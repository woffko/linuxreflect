//! Whole-disk backups and restores (spec §G.7, §H.1, §K S7).
//!
//! A whole-disk image imitates each partition on its own terms: filesystem
//! partitions through their used-block map, everything else (bios_grub, LVM
//! PV, LUKS, unknown) raw with zero suppression, swap by its first 4 KiB, and
//! the leading region — which carries the BIOS boot loader — raw up to the
//! spec's 16 MiB cap. Gaps and the backup GPT are not imaged; restore
//! regenerates the GPT for the target size.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use lr_blocksource::{BlockSource, DirectBlockSource, DirectBlockTarget, UsedChunks};
use lr_core::catalog::MemberKind;
use lr_core::{
    Consistency, Error, ImageId, ImageKind, Result, SnapshotOpts, SourceLayout, Support,
    discovery::discover_source,
};
use lr_crypto::nonce::NonceSeq;
use lr_format::{
    BlockEntry, BlockManifestHeader, ChainMember, ChunkOptions, ChunkState, DeltaEntry, DiskHeader,
    EXTRAS_IMAGE_METADATA, FORMAT_MAJOR, ImageWriter, MAX_LEADING_BYTES, MIN_READER, PtType,
    RegionKind, RegionRecord, SWAP_HEADER_BYTES, StreamId, Superblock, WriterKeys, flags, wire,
    write_chain_members, write_extras_record,
};
use lr_fsmap::provider_for;
use lr_snapshot::{BlockSnapshotProvider, offline_provider};

use crate::backup::{BadSectorPolicy, Compression, SourceState, now_unix, validate_chunk_size};
use crate::backup_plan::{BackupMode, ManifestEncoding, ResolvedBackupPlan};
use crate::keys;
use crate::restore::{RestoreReport, RestoreToken};

/// Per-region outcome of a whole-disk backup.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RegionReport {
    /// Partition index, or 0 for the leading region.
    pub index: u32,
    /// Region kind (`leading`, `partition-fs`, `partition-raw`, `swap`).
    pub kind: String,
    /// First LBA.
    pub start_lba: u64,
    /// Region length in bytes.
    pub size_bytes: u64,
    /// Consistency level for this region.
    pub consistency: Consistency,
    /// Filesystem type, when known.
    pub fs_type: String,
    /// Chunks stored for this region.
    pub stored_chunks: u64,
    /// Chunks recorded as zero.
    pub zero_chunks: u64,
    /// Chunks recorded as unreadable.
    pub bad_chunks: u64,
    /// `true` when a used-block map drove this region; `false` when it was
    /// imaged raw because no map was available (for example an image-file
    /// source, whose partitions have no device nodes).
    pub map_backed: bool,
}

/// What a whole-disk backup produced.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WholeDiskReport {
    /// Non-fatal notes, such as a destination that could not confirm the
    /// image reached stable storage.
    #[serde(default)]
    pub warnings: Vec<String>,
    /// Final image path inside the set.
    pub image_path: PathBuf,
    /// Image identifier.
    pub image_uuid: ImageId,
    /// Disk size in bytes.
    pub disk_size_bytes: u64,
    /// Partition table flavour.
    pub pt_type: String,
    /// Bytes of the final image file.
    pub image_bytes: u64,
    /// Bytes covered by the leading region.
    pub leading_bytes: u64,
    /// Regions, in disk order.
    pub regions: Vec<RegionReport>,
    /// Whether chunks are encrypted.
    pub encrypted: bool,
    /// The member's role in its chain (D-142).
    #[serde(default = "full_member")]
    pub member_kind: MemberKind,
    /// Position in the chain; 0 is the full.
    #[serde(default)]
    pub seq_in_chain: u32,
    /// Parent image UUID; zero for a full.
    #[serde(default)]
    pub parent_uuid: ImageId,
    /// Chunks of every region that changed since the parent (all of them
    /// for a full image).
    #[serde(default)]
    pub changed_chunks: u64,
    /// Chunks inherited unchanged from an ancestor.
    #[serde(default)]
    pub inherited_chunks: u64,
    /// What a tracked-freeze copy did (spec §E.7); `None` for an offline image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tracked: Option<lr_snapshot::TrackedSummary>,
}

const fn full_member() -> MemberKind {
    MemberKind::Full
}

impl WholeDiskReport {
    /// Total chunks stored across regions.
    #[must_use]
    pub fn stored_chunks(&self) -> u64 {
        self.regions.iter().map(|region| region.stored_chunks).sum()
    }
}

fn region_kind_name(kind: RegionKind) -> String {
    match kind {
        RegionKind::Leading => "leading",
        RegionKind::PartitionFs => "partition-fs",
        RegionKind::PartitionRaw => "partition-raw",
        RegionKind::Swap => "swap",
    }
    .to_owned()
}

/// Decide how one partition will be imaged (spec §G.7).
struct PartitionPlan {
    index: u32,
    start_lba: u64,
    size_bytes: u64,
    kind: RegionKind,
    fs_type: String,
    fs_uuid: String,
    fs_label: String,
    type_guid: String,
    partuuid: String,
    bootable: bool,
}

fn plan_partition(partition: &lr_core::PartitionLayout) -> PartitionPlan {
    let fs_type = partition.fs_type.clone().unwrap_or_default();
    let kind = if fs_type == "swap" {
        RegionKind::Swap
    } else if lr_fsmap::has_real_provider(&fs_type) {
        RegionKind::PartitionFs
    } else {
        RegionKind::PartitionRaw
    };
    PartitionPlan {
        index: partition.index,
        start_lba: partition.start_lba,
        size_bytes: partition.size_bytes,
        kind,
        fs_type,
        fs_uuid: partition.fs_uuid.clone().unwrap_or_default(),
        fs_label: partition.fs_label.clone().unwrap_or_default(),
        type_guid: partition.type_guid.clone().unwrap_or_default(),
        partuuid: partition.part_uuid.clone().unwrap_or_default(),
        bootable: partition.bootable,
    }
}

/// How `current` differs from `parent` in what a whole-disk chain relies on
/// (D-142): the disk's geometry, its partition table ([`table_bytes`]), and each
/// region's kind, number, place, type and PARTUUID. Contents may differ (a
/// filesystem re-created in place is a change of data, not of layout), and
/// so may the swap headers and each region's consistency.
pub(crate) fn layout_difference(parent: &DiskHeader, current: &DiskHeader) -> Option<String> {
    if parent.disk_size != current.disk_size {
        return Some(format!(
            "the disk has {} bytes, its parent {}",
            current.disk_size, parent.disk_size
        ));
    }
    if parent.logical_block_size != current.logical_block_size {
        return Some(format!(
            "the disk has {}-byte sectors, its parent {}",
            current.logical_block_size, parent.logical_block_size
        ));
    }
    if parent.pt_type != current.pt_type
        || table_bytes(parent.pt_type, &parent.pt_raw, parent.logical_block_size)
            != table_bytes(current.pt_type, &current.pt_raw, current.logical_block_size)
    {
        return Some("the partition table changed".to_owned());
    }
    if parent.regions.len() != current.regions.len() {
        return Some(format!(
            "the disk has {} regions, its parent {}",
            current.regions.len(),
            parent.regions.len()
        ));
    }
    for (old, new) in parent.regions.iter().zip(&current.regions) {
        if old.kind != new.kind
            || old.index != new.index
            || old.start_lba != new.start_lba
            || old.size_bytes != new.size_bytes
            || old.type_guid != new.type_guid
            || old.partuuid != new.partuuid
        {
            return Some(format!(
                "region {} ({}) at sector {} changed",
                new.index,
                region_kind_name(new.kind),
                new.start_lba
            ));
        }
    }
    None
}

/// The bytes of a captured partition table that describe the partitions:
/// the MBR's four entries and its signature (bytes 446..512), and for GPT the
/// GPT header and its entry array. The MBR boot code and the rest of the
/// boot area are a boot loader's data, imaged as the leading region (D-142).
fn table_bytes(pt_type: PtType, pt_raw: &[u8], lbs: u32) -> Vec<u8> {
    let slice = |start: usize, len: usize| {
        let end = start.saturating_add(len).min(pt_raw.len());
        pt_raw.get(start..end).unwrap_or(&[])
    };
    let mut bytes = slice(446, 66).to_vec();
    if pt_type == PtType::Gpt {
        let lbs = usize::try_from(lbs).unwrap_or(usize::MAX);
        let header = slice(lbs, 92);
        bytes.extend_from_slice(header);
        let field = |at: usize, len: usize| {
            header.get(at..at + len).map_or(0, |raw| {
                raw.iter()
                    .rev()
                    .fold(0u64, |value, byte| value << 8 | u64::from(*byte))
            })
        };
        let entries_lba = usize::try_from(field(72, 8)).unwrap_or(usize::MAX);
        let entries =
            usize::try_from(field(80, 4).saturating_mul(field(84, 4))).unwrap_or(usize::MAX);
        bytes.extend_from_slice(slice(entries_lba.saturating_mul(lbs), entries));
    }
    bytes
}

/// How a whole disk is read (spec §E, D-138, D-141).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Route {
    /// Every partition idle: the offline provider, with its exclusive claim.
    Offline,
    /// In use: copied live with tracked-freeze.
    Tracked,
}

/// Check the read-only preconditions shared by planning and whole-disk
/// execution, and choose how the disk is read.
///
/// An idle disk is read offline. A disk in use is copied live only by
/// tracked-freeze: when asked for by name, or by the automatic choice with
/// `--allow-freeze` when its preconditions hold (spec §E step 4; at the
/// backup stage also its write-tracking self test). No other live method
/// reads a whole disk; in particular, `allow_inconsistent` never permits a
/// live read of a disk and its partitions.
pub(crate) fn preflight(
    request: &crate::backup::BackupRequest,
    layout: &SourceLayout,
    stage: lr_snapshot::probe::Stage,
) -> Result<Route> {
    validate_chunk_size(request.chunk_size)?;
    if !layout.is_whole_disk() {
        return Err(Error::unsupported(
            "this source has no partition table; use a block backup instead",
        ));
    }
    let named = request
        .snapshot_provider
        .as_deref()
        .filter(|name| *name != "auto");
    // A tracked copy may read a disk that is in use (spec §E.7); its own
    // refusals run when it starts.
    if named == Some(lr_snapshot::tracked_freeze::ID) {
        return Ok(Route::Tracked);
    }
    let snapshot_opts = SnapshotOpts {
        provider: request.snapshot_provider.clone(),
        ..SnapshotOpts::default()
    };
    let Support::No(offline_refusal) = offline_provider().supports(layout, &snapshot_opts) else {
        return Ok(Route::Offline);
    };
    let mut options = vec![
        format!("offline read refused: {offline_refusal}"),
        "unmount every partition of the disk, then retry".to_owned(),
        "boot rescue media and run the statically linked CLI (offline)".to_owned(),
    ];
    if named.is_none() {
        if request.allow_freeze {
            let lbs = layout.device_facts.logical_block_size;
            let regions = layout_regions(
                layout,
                lbs,
                layout.device_facts.size_bytes,
                Consistency::Frozen,
            );
            match lr_snapshot::tracked_freeze::disk_support(
                &request.source,
                &tracked_specs(&regions, layout, lbs),
                &crate::backup::snapshot_opts(request),
                stage == lr_snapshot::probe::Stage::Backup,
            )? {
                Support::Yes => return Ok(Route::Tracked),
                Support::No(reason) => {
                    options.push(format!("tracked-freeze cannot copy it live: {reason}"));
                }
            }
        } else {
            options.push(
                "pass --allow-freeze to copy it live with tracked-freeze (ext4 on plain \
                 partitions; a short freeze at the end)"
                    .to_owned(),
            );
        }
    }
    Err(Error::no_consistent_method(options))
}

/// The regions of a whole disk, without reading it: the leading area, then
/// every partition in disk order. The numbers need not follow the disk
/// (partition 2 may come before 1), so regions are ordered by position and
/// keep their own numbers (R37). A swap region's header is read by the
/// backup.
fn layout_regions(
    layout: &SourceLayout,
    lbs: u32,
    disk_size: u64,
    consistency: Consistency,
) -> Vec<RegionRecord> {
    let mut regions: Vec<RegionRecord> = Vec::new();
    let first_partition_byte = layout
        .partitions
        .iter()
        .map(|partition| partition.start_lba * u64::from(lbs))
        .min()
        .unwrap_or(disk_size);
    let leading_bytes = first_partition_byte.min(MAX_LEADING_BYTES);
    if leading_bytes > 0 {
        let mut region = RegionRecord::new(RegionKind::Leading, 0, 0, leading_bytes);
        region.consistency = consistency;
        regions.push(region);
    }
    let mut plans: Vec<PartitionPlan> = layout
        .partitions
        .iter()
        .filter(|partition| partition.size_bytes > 0)
        .map(plan_partition)
        .collect();
    plans.sort_by_key(|plan| (plan.start_lba, plan.index));
    for plan in &plans {
        let mut region = RegionRecord::new(plan.kind, plan.index, plan.start_lba, plan.size_bytes);
        region.consistency = consistency;
        region.bootable = plan.bootable;
        region.type_guid = plan.type_guid.clone();
        region.partuuid = plan.partuuid.clone();
        region.fs_type = plan.fs_type.clone();
        region.fs_uuid = plan.fs_uuid.clone();
        region.fs_label = plan.fs_label.clone();
        regions.push(region);
    }
    regions
}

/// What a tracked copy tracks: every region with a manifest, in order.
fn tracked_specs(
    regions: &[RegionRecord],
    layout: &SourceLayout,
    lbs: u32,
) -> Vec<lr_snapshot::tracked_freeze::RegionSpec> {
    let sector = |bytes: u64| bytes / 512;
    regions
        .iter()
        .filter(|region| region.has_manifest())
        .map(|region| {
            let partition = layout.partitions.iter().find(|partition| {
                region.kind != RegionKind::Leading && partition.index == region.index
            });
            lr_snapshot::tracked_freeze::RegionSpec {
                start_sector: sector(region.start_lba * u64::from(lbs)),
                sectors: sector(region.size_bytes),
                partition: partition.and_then(|partition| partition.path.clone()),
                fs_type: region.fs_type.clone(),
                mountpoints: partition
                    .map(|partition| partition.mountpoints.clone())
                    .unwrap_or_default(),
            }
        })
        .collect()
}

/// Plan a whole-disk tracked copy without tracing or freezing (the backup
/// plan): the same regions and the same checks as the backup.
///
/// # Errors
/// The refusals the backup would return before it starts tracing.
pub(crate) fn plan_tracked(
    request: &crate::backup::BackupRequest,
    layout: &SourceLayout,
) -> Result<lr_snapshot::tracked_freeze::TrackedPlan> {
    let lbs = layout.device_facts.logical_block_size;
    let regions = layout_regions(
        layout,
        lbs,
        layout.device_facts.size_bytes,
        Consistency::Frozen,
    );
    lr_snapshot::tracked_freeze::plan_disk(
        &request.source,
        &tracked_specs(&regions, layout, lbs),
        &crate::backup::snapshot_opts(request),
    )
}

/// Back up a whole disk.
///
/// # Errors
/// Returns [`Error::Unsupported`] when the source is not a whole disk,
/// [`Error::NoConsistentMethod`] when a partition cannot be read offline, and
/// propagates I/O, AEAD and format errors.
pub fn backup_whole_disk(request: &crate::backup::BackupRequest) -> Result<WholeDiskReport> {
    let layout = discover_source(&request.source)?;
    backup_whole_disk_with_layout(request, &layout)
}

pub(crate) fn backup_whole_disk_with_layout(
    request: &crate::backup::BackupRequest,
    layout: &SourceLayout,
) -> Result<WholeDiskReport> {
    let tracked_mode =
        preflight(request, layout, lr_snapshot::probe::Stage::Backup)? == Route::Tracked;
    // Offline: the disk itself and every partition must be idle, and stay
    // idle: the snapshot holds the provider's exclusive claim on the disk
    // until the whole image is written (A2). Tracked: the copy is live, and
    // its consistency comes from tracking and the final freeze.
    let _claim = if tracked_mode {
        None
    } else {
        let snapshot_opts = SnapshotOpts {
            provider: request.snapshot_provider.clone(),
            ..SnapshotOpts::default()
        };
        Some(offline_provider().create(layout, &snapshot_opts)?)
    };
    let consistency = if tracked_mode {
        Consistency::Frozen
    } else {
        Consistency::Offline
    };

    let mut source = DirectBlockSource::open(&request.source)?;
    let disk_size = source.size_bytes();
    let lbs = source.logical_block_size();
    let mut buffer = source.buffer(request.chunk_size as usize)?;

    let mut regions = layout_regions(layout, lbs, disk_size, consistency);
    for region in regions
        .iter_mut()
        .filter(|region| region.kind == RegionKind::Swap)
    {
        let mut header = source.buffer(SWAP_HEADER_BYTES)?;
        let offset = region.start_lba * u64::from(lbs);
        let read = source.read_at(offset, &mut header, SWAP_HEADER_BYTES)?;
        if read != SWAP_HEADER_BYTES {
            return Err(Error::BadSector {
                offset,
                len: SWAP_HEADER_BYTES as u64,
            });
        }
        region.swap_header = header.as_slice().to_vec();
    }

    let disk_header = DiskHeader {
        disk_size,
        logical_block_size: lbs,
        pt_type: match &layout.partition_table {
            Some(table) => match table.kind {
                lr_core::PartitionTableKind::Gpt => PtType::Gpt,
                lr_core::PartitionTableKind::Mbr => PtType::Mbr,
                lr_core::PartitionTableKind::None => PtType::None,
            },
            None => PtType::None,
        },
        serial_wwid: layout
            .device_facts
            .wwid
            .clone()
            .or_else(|| layout.device_facts.serial.clone())
            .unwrap_or_default(),
        pt_raw: Vec::new(),
        regions,
    };
    let mut disk_header = disk_header;
    disk_header.pt_raw = read_pt_raw(&request.source, lbs, disk_header.pt_type)?;
    disk_header.validate()?;

    // The set lock and the chain (spec §D.3), before anything is traced: a
    // member whose parent describes another disk layout is refused first
    // (D-142).
    let destination = request.open_destination()?;
    let set = destination.open_set(&request.set_id)?;
    let lock = crate::backup::acquire_set_lock(&*destination, &set, request)?;
    let (set_root, spool_dir) = crate::backup::spool_location(&*destination, &set)?;
    let now = now_unix();
    let resolved_plan =
        ResolvedBackupPlan::resolve(request, BackupMode::Block, &*destination, &set, now)?;
    let parent = resolved_plan.parent();
    let delta = resolved_plan.manifest_encoding() == ManifestEncoding::BlockDelta;
    let member = u16::try_from(resolved_plan.seq_in_chain())
        .map_err(|_| Error::unsupported("chains longer than 65535 members are not supported"))?;
    // The parent's merged entries, every region with data in order, so the
    // regions below are compared with them positionally (spec §D.4).
    let mut parent_entries = match parent {
        Some(parent) => {
            crate::backup::check_parent_fits(
                &parent.superblock,
                request.chunk_size,
                disk_size,
                true,
            )?;
            let members =
                crate::chain::open_chain(&*destination, &set, &parent.files, &request.encryption)?;
            let mut walk = crate::chain::DiskWalk::new(members)?;
            if let Some(difference) = layout_difference(walk.disk(), &disk_header) {
                return Err(Error::unsupported(format!(
                    "{difference} since the parent image; start a new full chain"
                )));
            }
            let mut entries = crate::spool::scratch_file(&spool_dir)?;
            {
                let mut out = BufWriter::new(&mut entries);
                walk.walk(|_, _, state, _| crate::backup::entry_of(&state).write(&mut out))?;
                out.flush().map_err(Error::Io)?;
            }
            entries.rewind().map_err(Error::Io)?;
            Some(wire::Reader::new(BufReader::new(entries)))
        }
        None => None,
    };

    // Keys and superblock, exactly as for a block image. A member reuses its
    // parent's chain key (spec §G.4).
    let chain_id = resolved_plan.chain_id();
    let new_keys = match parent {
        Some(parent) => keys::member_chain_keys(
            &request.encryption,
            &parent.superblock,
            &chain_id,
            request.image_uuid.inner(),
        )?,
        None => keys::new_chain_keys(&request.encryption, &chain_id, request.image_uuid.inner())?,
    };
    let meta_key = *new_keys.keys.meta_key;
    let mac_key = new_keys.encrypted.then_some(&meta_key);
    let mut sb_flags = flags::WHOLE_DISK;
    if new_keys.encrypted {
        sb_flags |= flags::ENCRYPTED;
    }
    if matches!(request.compression, Compression::Zstd { .. }) {
        sb_flags |= flags::COMPRESSED;
    }
    if delta {
        sb_flags |= flags::DELTA_MANIFEST;
    }
    let mut superblock = Superblock {
        format_major: FORMAT_MAJOR,
        min_reader: MIN_READER,
        flags: sb_flags,
        image_kind: ImageKind::Block,
        consistency,
        image_uuid: request.image_uuid,
        chain_id,
        set_id: resolved_plan.set_id(),
        parent_uuid: resolved_plan.parent_uuid(),
        seq_in_chain: resolved_plan.seq_in_chain(),
        created_unix: now,
        source_size_bytes: disk_size,
        logical_block_size: lbs,
        chunk_size: request.chunk_size,
        kdf_id: u32::from(new_keys.encrypted),
        aead_id: request.aead.id(),
        kdf_salt: new_keys.kdf_salt,
        argon2_m_cost_kib: new_keys.params.m_cost_kib,
        argon2_t_cost: new_keys.params.t_cost,
        argon2_p_cost: new_keys.params.p_cost,
        wrap_nonce: new_keys.wrap_nonce,
        wrapped_chain_key: new_keys.wrapped_chain_key,
    };
    superblock.set_consistency(consistency);

    // Tracked: one copy over every region that has a manifest, in order.
    let mut tracked = if tracked_mode {
        let mut copy = lr_snapshot::tracked_freeze::track_disk(
            &request.source,
            tracked_specs(&disk_header.regions, layout, lbs),
            &crate::backup::snapshot_opts(request),
        )?;
        copy.bind(u64::from(request.chunk_size))?;
        Some(copy)
    } else {
        None
    };
    // Where each tracked region's entries start in the spool, and its place.
    let mut tracked_regions: Vec<TrackedRegionSpool> = Vec::new();
    let reads_before = source.read_stats();

    let image_name = format!(
        "{chain_id}/{:03}-{}-{}.lrimg",
        resolved_plan.seq_in_chain(),
        resolved_plan.file_tag(),
        request.image_uuid
    );
    let mut guard = crate::backup::TempGuard::new(std::sync::Arc::clone(&destination), set.clone());

    let writer_keys = WriterKeys {
        data_key: new_keys.keys.data_key.as_ref().map(|key| **key),
        meta_key,
        dedup_key: *new_keys.keys.dedup_key,
    };
    let options = ChunkOptions {
        kind: request.aead,
        level: match request.compression {
            Compression::None => 0,
            Compression::Zstd { level } => level,
        },
        compress: matches!(request.compression, Compression::Zstd { .. }),
    };

    let tmp = destination.create_tmp(&set, &image_name)?;

    let tmp_name = tmp.name.clone();

    guard.track_tmp(tmp_name.clone());

    let mut image_writer = ImageWriter::create(tmp.writer, &superblock, mac_key)?;
    let mut nonce_seq = NonceSeq::new();
    let mut reports: Vec<RegionReport> = Vec::new();

    let mut reporter = request.context.clone().reporter(disk_size)?;
    reporter.phase("regions");
    let mut spool_file = crate::spool::scratch_file(&spool_dir)?;
    let mut tracked_summary = None;
    let mut hook_warnings = Vec::new();
    let mut changed_chunks = 0u64;
    let mut inherited_chunks = 0u64;
    // Filesystems whose map came back incomplete (D-124).
    let mut map_warnings: Vec<String> = Vec::new();
    // Phase A: chunk records plus the spooled manifest.
    {
        let mut spool = BufWriter::new(&mut spool_file);
        disk_header.write(&mut spool)?;

        for region in &disk_header.regions {
            if !region.has_manifest() {
                reports.push(RegionReport {
                    index: region.index,
                    kind: region_kind_name(region.kind),
                    start_lba: region.start_lba,
                    size_bytes: region.size_bytes,
                    consistency: region.consistency,
                    fs_type: region.fs_type.clone(),
                    stored_chunks: 0,
                    zero_chunks: 0,
                    bad_chunks: 0,
                    map_backed: false,
                });
                continue;
            }
            // The manifest lives in the spool; its header is written before the
            // entries so the reader can stream it.
            let chunk_size = u64::from(request.chunk_size);
            let chunk_count = region.chunk_count(chunk_size)?;
            let header_offset = spool.stream_position().map_err(Error::Io)?;
            BlockManifestHeader {
                chunk_size: request.chunk_size,
                chunk_count,
                entry_count: chunk_count,
                used_extent_count: 1,
                used_bytes: region.size_bytes,
                fs_type: region.fs_type.clone(),
                fs_uuid: region.fs_uuid.clone(),
                label: region.fs_label.clone(),
            }
            .write(&mut spool, delta)?;
            let report_index = reports.len();
            if tracked.is_some() {
                tracked_regions.push(TrackedRegionSpool {
                    entries_start: spool.stream_position().map_err(Error::Io)?,
                    start_byte: region.start_lba * u64::from(lbs),
                    size_bytes: region.size_bytes,
                    report: report_index,
                    aside: delta.then(BTreeMap::new),
                });
            }

            let (regions_of_source, map_backed, incomplete) = match tracked.as_mut() {
                // A mounted ext4 is mapped live (spec §E.7 step 4).
                Some(copy)
                    if region.kind == RegionKind::PartitionFs && region.fs_type == "ext4" =>
                {
                    let index = tracked_regions.len() - 1;
                    let start = region.start_lba * u64::from(lbs);
                    let map = copy.used_map(index)?;
                    (
                        lr_fsmap::ExtentMap {
                            extents: map
                                .extents
                                .iter()
                                .map(|(first, last)| (first + start, last + start))
                                .collect(),
                            complete: map.complete,
                        },
                        true,
                        None,
                    )
                }
                _ => region_source_map(layout, region),
            };
            map_warnings.extend(incomplete);
            if !map_backed && region.kind == RegionKind::PartitionFs {
                tracing::warn!(
                    partition = region.index,
                    "no used-block map available; imaging the partition raw"
                );
            }
            // Chunk indices are positional *within the region*, so the plan is
            // built on region-relative offsets and shifted back when reading.
            let region_start = region.start_lba * u64::from(lbs);
            let region_map = lr_fsmap::ExtentMap {
                extents: regions_of_source
                    .extents
                    .iter()
                    .map(|(start, end)| (start - region_start, end - region_start))
                    .collect(),
                complete: regions_of_source.complete,
            };
            let mut plan = UsedChunks::new(&region_map, chunk_size, region.size_bytes)?;
            let mut stored_chunks = 0u64;
            let mut zero_chunks = 0u64;
            let mut bad_chunks = 0u64;
            let mut changed = 0u64;
            reporter.phase(&format!("region {}", region.index));
            reporter.report(region.start_lba * u64::from(lbs))?;
            // Every chunk of the region in order, compared with the parent's
            // merged state (none for a full image).
            let mut next_chunk = plan.next_chunk();
            for index in 0..chunk_count {
                let parent_state = match parent_entries.as_mut() {
                    Some(entries) => ChunkState::from(&BlockEntry::read(entries)?),
                    None => ChunkState::Unused,
                };
                let source_state = if next_chunk.is_some_and(|chunk| chunk.index == index) {
                    let chunk = next_chunk.take().expect("checked");
                    next_chunk = plan.next_chunk();
                    reporter.report(region_start + chunk.offset)?;
                    let absolute = lr_blocksource::ChunkPlan {
                        index: chunk.index,
                        offset: region_start + chunk.offset,
                        len: chunk.len,
                    };
                    match lr_blocksource::read_chunk(&mut source, &absolute, &mut buffer) {
                        Ok(bytes) => crate::backup::store_bytes(
                            &mut image_writer,
                            options,
                            &writer_keys,
                            &mut nonce_seq,
                            member,
                            bytes,
                            &parent_state,
                        )?,
                        Err(error @ Error::BadSector { .. }) => match request.on_bad_sector {
                            BadSectorPolicy::Abort => return Err(error),
                            BadSectorPolicy::Record => SourceState::BadSector(
                                BlockEntry::bad_sector(absolute.offset, absolute.len),
                            ),
                        },
                        Err(error) => return Err(error),
                    }
                } else if matches!(parent_state, ChunkState::Unused) {
                    SourceState::Unchanged
                } else {
                    SourceState::Missing
                };
                let entry = match source_state {
                    // Inherited: a full region manifest repeats the parent's
                    // entry, a delta leaves it out; either way no change.
                    SourceState::Unchanged if parent_entries.is_some() => {
                        inherited_chunks += 1;
                        if !delta {
                            crate::backup::entry_of(&parent_state).write(&mut spool)?;
                        }
                        continue;
                    }
                    // A full image: nothing is stored for this chunk.
                    SourceState::Unchanged => BlockEntry::unused(),
                    SourceState::Stored(entry) => {
                        stored_chunks += 1;
                        entry
                    }
                    SourceState::Zero => {
                        zero_chunks += 1;
                        BlockEntry::zero()
                    }
                    SourceState::BadSector(entry) => {
                        bad_chunks += 1;
                        entry
                    }
                    SourceState::Missing => BlockEntry::unused(),
                };
                changed += 1;
                if delta {
                    DeltaEntry {
                        chunk_no: index,
                        entry,
                    }
                    .write(&mut spool)?;
                } else {
                    entry.write(&mut spool)?;
                }
            }
            if delta {
                crate::backup::patch_entry_count(&mut spool, header_offset, changed)?;
            }
            changed_chunks += changed;
            reports.push(RegionReport {
                index: region.index,
                kind: region_kind_name(region.kind),
                start_lba: region.start_lba,
                size_bytes: region.size_bytes,
                consistency: region.consistency,
                fs_type: region.fs_type.clone(),
                stored_chunks,
                zero_chunks,
                bad_chunks,
                map_backed,
            });
        }
        if let Some(copy) = tracked.as_mut() {
            reporter.phase("converge");
            let first_pass = source.read_stats().since(reads_before);
            let summary = converge_disk(
                copy,
                &mut image_writer,
                options,
                &writer_keys,
                &mut nonce_seq,
                &mut source,
                &mut buffer,
                &mut spool,
                &mut tracked_regions,
                &mut reports,
                member,
                request,
                first_pass,
            )?;
            // The disk's partition table must be what the image describes.
            if read_pt_raw(&request.source, lbs, disk_header.pt_type)? != disk_header.pt_raw {
                return Err(Error::SourceChanged {
                    what: "the partition table changed during the backup".to_owned(),
                });
            }
            tracked_summary = Some(summary);
            hook_warnings.extend_from_slice(copy.warnings());
        }
        spool.flush().map_err(Error::Io)?;
    }

    // A delta region lists its chunks in order, so what a live member read
    // again is merged in rather than appended.
    if tracked_regions
        .iter()
        .any(|region| region.aside.as_ref().is_some_and(|aside| !aside.is_empty()))
    {
        let (merged, newly_changed) =
            merge_disk_spool(&mut spool_file, &tracked_regions, &mut reports, &spool_dir)?;
        spool_file = merged;
        changed_chunks += newly_changed;
        inherited_chunks = inherited_chunks.saturating_sub(newly_changed);
    }

    reporter.phase("manifest");
    // Phase B: copy the spooled manifest into the page stream.
    {
        let mut manifest = image_writer.page_stream(StreamId::Manifest, request.aead, meta_key);
        spool_file.rewind().map_err(Error::Io)?;
        let mut spool = BufReader::new(&mut spool_file);
        let mut chunk = vec![0u8; 64 * 1024];
        loop {
            let read = spool.read(&mut chunk).map_err(Error::Io)?;
            if read == 0 {
                break;
            }
            manifest.write(&chunk[..read])?;
        }
        manifest.finish()?;
    }
    drop(spool_file);

    // Extras: chain members and a small metadata record.
    {
        let mut extras = image_writer.page_stream(StreamId::Extras, request.aead, meta_key);
        let mut members: Vec<ChainMember> = parent
            .map(|parent| {
                parent
                    .prefix
                    .iter()
                    .map(|(index, image_uuid)| ChainMember {
                        index: *index,
                        image_uuid: *image_uuid,
                    })
                    .collect()
            })
            .unwrap_or_default();
        members.push(ChainMember {
            index: u8::try_from(resolved_plan.seq_in_chain()).unwrap_or(u8::MAX),
            image_uuid: request.image_uuid,
        });
        write_chain_members(&mut extras, &members)?;
        let mut metadata = format!(
            "source={}\ndisk_size={disk_size}\npt_type={}\n",
            request.source.display(),
            disk_header.pt_type.as_u8()
        );
        for region in &disk_header.regions {
            metadata.push_str(&format!(
                "region index={} kind={} start_lba={} size={}\n",
                region.index,
                region_kind_name(region.kind),
                region.start_lba,
                region.size_bytes
            ));
        }
        write_extras_record(&mut extras, EXTRAS_IMAGE_METADATA, metadata.as_bytes())?;
        extras.finish()?;
    }

    let (mut writer, _footer) = image_writer.finish(&meta_key, mac_key, request.aead)?;
    writer.flush().map_err(Error::Io)?;
    let image_bytes = writer.seek(SeekFrom::End(0)).map_err(Error::Io)?;
    drop(writer);
    // A holder that lost its lease stops before changing the set (R21).
    lock.verify()?;
    // A failed flush publishes nothing (R19); an unconfirmed one is reported.
    let durability = destination.publish_new(&set, &tmp_name, &image_name)?;
    guard.disarm();
    // The catalog, still under the lock (spec §D.3).
    let catalog_warning =
        crate::catalog::record_published(&*destination, &set, &request.set_name, &lock, now_unix());

    Ok(WholeDiskReport {
        warnings: durability
            .warning("the image")
            .into_iter()
            .chain(catalog_warning)
            .chain(map_warnings)
            .chain(hook_warnings)
            .collect(),
        member_kind: resolved_plan.member_kind(),
        seq_in_chain: resolved_plan.seq_in_chain(),
        parent_uuid: resolved_plan.parent_uuid(),
        changed_chunks,
        inherited_chunks,
        image_path: crate::backup::local_image_path(&set_root, &image_name),
        image_uuid: request.image_uuid,
        disk_size_bytes: disk_size,
        pt_type: match disk_header.pt_type {
            PtType::None => "none",
            PtType::Gpt => "gpt",
            PtType::Mbr => "mbr",
        }
        .to_owned(),
        image_bytes,
        leading_bytes: disk_header
            .regions
            .iter()
            .find(|region| region.kind == RegionKind::Leading)
            .map_or(0, |region| region.size_bytes),
        regions: reports,
        encrypted: new_keys.encrypted,
        tracked: tracked_summary,
    })
}

/// A tracked region's place in the spool and on the disk.
struct TrackedRegionSpool {
    entries_start: u64,
    start_byte: u64,
    size_bytes: u64,
    /// Index into the region reports.
    report: usize,
    /// For a delta region manifest, what the copy read again, newest per
    /// chunk; merged in chunk order once the copy ends ([`merge_disk_spool`]).
    /// `None` for a full region manifest, patched in place.
    aside: Option<BTreeMap<u64, BlockEntry>>,
}

/// Record what a tracked copy read again for chunk `index` of `region`.
fn record_region_entry(
    spool: &File,
    region: &mut TrackedRegionSpool,
    index: u64,
    entry: BlockEntry,
    report: &mut RegionReport,
) -> Result<()> {
    match region.aside.as_mut() {
        Some(aside) => {
            aside.insert(index, entry);
            Ok(())
        }
        None => patch_region_entry(spool, region, index, &entry, report),
    }
}

/// Rewrite a whole-disk manifest spool with what a live member read again
/// merged into its delta region manifests, in chunk order
/// ([`crate::backup::merge_delta_entries`]); full region manifests were
/// patched in place and are copied as they are. Returns the new spool and
/// how many inherited chunks became changes.
fn merge_disk_spool(
    spool: &mut File,
    regions: &[TrackedRegionSpool],
    reports: &mut [RegionReport],
    spool_dir: &Path,
) -> Result<(File, u64)> {
    spool.rewind().map_err(Error::Io)?;
    let mut input = wire::Reader::new(BufReader::new(&mut *spool));
    let disk = DiskHeader::read(&mut input)?;
    let mut newly_changed = 0u64;
    let mut merged = crate::spool::scratch_file(spool_dir)?;
    {
        let mut out = BufWriter::new(&mut merged);
        disk.write(&mut out)?;
        let mut tracked = regions.iter();
        let empty = BTreeMap::new();
        for _ in disk.regions.iter().filter(|region| region.has_manifest()) {
            let region = tracked
                .next()
                .ok_or_else(|| Error::corrupt("a region manifest without its tracked region"))?;
            let (header, delta) = BlockManifestHeader::read(&mut input)?;
            let header_offset = out.stream_position().map_err(Error::Io)?;
            header.write(&mut out, delta)?;
            if delta {
                let report = &mut reports[region.report];
                let mut counts = crate::backup::Counts {
                    stored: report.stored_chunks,
                    zero: report.zero_chunks,
                    bad: report.bad_chunks,
                    ..crate::backup::Counts::default()
                };
                let written = crate::backup::merge_delta_entries(
                    &mut input,
                    header.entry_count,
                    region.aside.as_ref().unwrap_or(&empty),
                    &mut counts,
                    &mut out,
                )?;
                report.stored_chunks = counts.stored;
                report.zero_chunks = counts.zero;
                report.bad_chunks = counts.bad;
                newly_changed += counts.changed;
                crate::backup::patch_entry_count(&mut out, header_offset, written)?;
            } else {
                for _ in 0..header.entry_count {
                    BlockEntry::read(&mut input)?.write(&mut out)?;
                }
            }
        }
        out.flush().map_err(Error::Io)?;
    }
    Ok((merged, newly_changed))
}

/// Replace chunk `index`'s entry of a tracked region and keep its report's
/// counts right; the superseded record stays unreferenced (spec §E.7).
fn patch_region_entry(
    spool: &File,
    region: &TrackedRegionSpool,
    index: u64,
    entry: &BlockEntry,
    report: &mut RegionReport,
) -> Result<()> {
    use std::os::unix::fs::FileExt as _;
    let at = region.entries_start + index * lr_format::ENTRY_LEN as u64;
    let mut old = [0u8; lr_format::ENTRY_LEN];
    spool.read_exact_at(&mut old, at).map_err(Error::Io)?;
    for (state, add) in [
        (BlockEntry::decode(&old)?.state, false),
        (entry.state, true),
    ] {
        let counter = match state {
            lr_format::STATE_STORED => &mut report.stored_chunks,
            lr_format::STATE_ZERO => &mut report.zero_chunks,
            lr_format::STATE_BAD_SECTOR => &mut report.bad_chunks,
            _ => continue,
        };
        *counter = if add {
            *counter + 1
        } else {
            counter.saturating_sub(1)
        };
    }
    spool.write_all_at(&entry.encode()?, at).map_err(Error::Io)
}

/// Drive a whole-disk tracked copy after the first pass (spec §E.7): the
/// same passes and final read as a partition's, over every region.
#[allow(clippy::too_many_arguments)]
fn converge_disk(
    copy: &mut lr_snapshot::TrackedCopy,
    writer: &mut ImageWriter<impl Write + Seek>,
    options: ChunkOptions,
    writer_keys: &WriterKeys,
    nonce_seq: &mut NonceSeq,
    source: &mut DirectBlockSource,
    buffer: &mut lr_unsafe::AlignedBuf,
    spool: &mut BufWriter<&mut File>,
    regions: &mut [TrackedRegionSpool],
    reports: &mut [RegionReport],
    member: u16,
    request: &crate::backup::BackupRequest,
    first_pass: lr_blocksource::ReadStats,
) -> Result<lr_snapshot::TrackedSummary> {
    use crate::backup::{chunk_plan_at, full_entry, store_bytes};
    use lr_format::ChunkState;
    spool.flush().map_err(Error::Io)?;
    let chunk_size = u64::from(request.chunk_size);
    // The rate is the reads' own (spec §E.7 step 5): the final read only
    // reads, while a pass also compresses, encrypts and writes.
    let mut pass = first_pass;
    let absolute = |region: &TrackedRegionSpool, index: u64| {
        let plan = chunk_plan_at(index, chunk_size, region.size_bytes);
        lr_blocksource::ChunkPlan {
            index,
            offset: region.start_byte + plan.offset,
            len: plan.len,
        }
    };
    while let Some(dirty) = copy.next_pass(pass.bytes, pass.time)? {
        let reads_before = source.read_stats();
        for group in dirty {
            let region = &mut regions[group.region];
            for index in group.chunks {
                let plan = absolute(region, index);
                let state = match lr_blocksource::read_chunk(source, &plan, buffer) {
                    Ok(read) => store_bytes(
                        writer,
                        options,
                        writer_keys,
                        nonce_seq,
                        member,
                        read,
                        &ChunkState::Unused,
                    )?,
                    Err(error @ Error::BadSector { .. }) => match request.on_bad_sector {
                        BadSectorPolicy::Abort => return Err(error),
                        BadSectorPolicy::Record => crate::backup::SourceState::BadSector(
                            BlockEntry::bad_sector(plan.offset, plan.len),
                        ),
                    },
                    Err(error) => return Err(error),
                };
                let report = region.report;
                record_region_entry(
                    spool.get_ref(),
                    region,
                    index,
                    full_entry(state),
                    &mut reports[report],
                )?;
            }
        }
        pass = source.read_stats().since(reads_before);
    }

    // The final read: buffers first, then nothing is logged or written
    // until the thaw.
    let alignment = source.alignment();
    let capacity = copy.pending_count().saturating_mul(2).saturating_add(8);
    let mut pool = Vec::with_capacity(capacity);
    for _ in 0..capacity {
        pool.push(
            lr_unsafe::AlignedBuf::new(request.chunk_size as usize, alignment)
                .map_err(Error::Io)?,
        );
    }
    let read_back = copy.final_read(|dirty| {
        let mut done = Vec::new();
        let mut slot = 0usize;
        for group in dirty {
            let region = &regions[group.region];
            for &index in &group.chunks {
                if slot == pool.len() {
                    pool.push(
                        lr_unsafe::AlignedBuf::new(request.chunk_size as usize, alignment)
                            .map_err(Error::Io)?,
                    );
                }
                let plan = absolute(region, index);
                let read = source.read_at(plan.offset, &mut pool[slot], plan.len as usize)?;
                if read != plan.len as usize {
                    return Err(Error::BadSector {
                        offset: plan.offset,
                        len: u64::from(plan.len),
                    });
                }
                done.push((group.region, index, slot, plan.len as usize));
                slot += 1;
            }
        }
        Ok(done)
    })?;
    for (region_index, index, slot, len) in read_back {
        let region = &mut regions[region_index];
        let state = store_bytes(
            writer,
            options,
            writer_keys,
            nonce_seq,
            member,
            &pool[slot].as_slice()[..len],
            &ChunkState::Unused,
        )?;
        let report = region.report;
        record_region_entry(
            spool.get_ref(),
            region,
            index,
            full_entry(state),
            &mut reports[report],
        )?;
    }
    copy.finish()
}

/// The used-byte ranges of one region, whether a real map was used, and the
/// warning for a filesystem whose map came back incomplete (D-124).
fn region_source_map(
    layout: &lr_core::SourceLayout,
    region: &RegionRecord,
) -> (lr_fsmap::ExtentMap, bool, Option<String>) {
    let start = region.start_lba * u64::from(layout.device_facts.logical_block_size);
    let end = start + region.size_bytes - 1;
    let whole = lr_fsmap::ExtentMap {
        extents: vec![(start, end)],
        complete: false,
    };
    match region.kind {
        RegionKind::Leading | RegionKind::PartitionRaw => (whole, false, None),
        RegionKind::PartitionFs => {
            let partition = layout
                .partitions
                .iter()
                .find(|partition| partition.index == region.index);
            let fs_type = partition
                .and_then(|partition| partition.fs_type.clone())
                .unwrap_or_else(|| lr_fsmap::RAW_FS_TYPE.to_owned());
            match partition.and_then(|partition| partition.path.clone()) {
                Some(path) if path.exists() => match provider_for(&fs_type).used_extents(&path) {
                    // The provider reports offsets relative to the partition,
                    // so they are shifted onto the disk here.
                    Ok(map) if map.complete => (
                        lr_fsmap::ExtentMap {
                            extents: map
                                .extents
                                .iter()
                                .map(|(first, last)| (first + start, last + start))
                                .collect(),
                            complete: true,
                        },
                        true,
                        None,
                    ),
                    Ok(_) => (
                        whole,
                        false,
                        crate::backup::incomplete_map_warning(
                            &fs_type,
                            &format!("partition {}", region.index),
                        ),
                    ),
                    Err(_) => (whole, false, None),
                },
                // An image file has no partition device nodes, so the map tools
                // cannot be pointed at the partition (spec §F).
                _ => (whole, false, None),
            }
        }
        RegionKind::Swap => (
            lr_fsmap::ExtentMap {
                extents: Vec::new(),
                complete: true,
            },
            false,
            None,
        ),
    }
}

fn read_pt_raw(source: &Path, lbs: u32, pt_type: PtType) -> Result<Vec<u8>> {
    if pt_type == PtType::None {
        return Ok(Vec::new());
    }
    let length = lr_format::PT_RAW_BYTES.min(usize::try_from(lbs).unwrap_or(512) * 2048);
    let mut file = File::open(source).map_err(Error::Io)?;
    let mut bytes = vec![0u8; length];
    let mut filled = 0usize;
    while filled < bytes.len() {
        match file.read(&mut bytes[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Error::Io(e)),
        }
    }
    bytes.truncate(filled);
    Ok(bytes)
}

/// Restore a whole-disk image onto the target that `apply` claimed.
///
/// Every write, including the swap headers and the regenerated GPT, goes
/// through that claim; the target is never reopened by path (A1, R05).
///
/// # Errors
/// Returns [`Error::TargetChanged`] when the target changed since `prepare`,
/// [`Error::NoSpace`] when it is smaller than the image's disk, and propagates
/// I/O and format errors.
pub(crate) fn restore_whole_disk(
    mut walk: crate::chain::DiskWalk,
    superblock: &Superblock,
    token: &RestoreToken,
    mut target: DirectBlockTarget,
    reporter: &mut crate::progress::Reporter,
) -> Result<RestoreReport> {
    let lbs = u64::from(superblock.logical_block_size);
    let chunk_size = u64::from(superblock.chunk_size);
    if target.size_bytes() < superblock.source_size_bytes {
        return Err(Error::NoSpace);
    }
    let mut buffer = target.buffer(chunk_size as usize)?;
    let mut zeros = target.buffer(chunk_size as usize)?;
    zeros.clear();
    // The newest member's view of the disk: its swap headers too.
    let disk_header = walk.disk().clone();

    let mut stored_chunks_written = 0u64;
    let mut zero_chunks_written = 0u64;
    let mut skipped_chunks = 0u64;
    let mut bytes_written = 0u64;

    for region in disk_header
        .regions
        .iter()
        .filter(|region| region.kind == RegionKind::Swap)
    {
        reporter.phase(&format!("region {}", region.index));
        write_swap(&mut target, region, lbs)?;
    }
    let mut current = None;
    walk.walk(|region, index, state, access| {
        if current != Some(region.index) {
            current = Some(region.index);
            reporter.phase(&format!("region {}", region.index));
        }
        let offset = region.start_lba * lbs + index * chunk_size;
        reporter.report(offset)?;
        let chunk_len = chunk_size.min(region.size_bytes - index * chunk_size) as usize;
        match state {
            ChunkState::Stored { .. } => {
                let plaintext = access.read(&state)?;
                if plaintext.len() != chunk_len {
                    return Err(Error::corrupt(format!(
                        "chunk {index} of region {} restored to {} bytes, expected {chunk_len}",
                        region.index,
                        plaintext.len()
                    )));
                }
                buffer.as_mut_slice()[..chunk_len].copy_from_slice(&plaintext);
                target.write_at(offset, &buffer, chunk_len)?;
                stored_chunks_written += 1;
                bytes_written += chunk_len as u64;
            }
            ChunkState::Zero => {
                target.write_at(offset, &zeros, chunk_len)?;
                zero_chunks_written += 1;
                bytes_written += chunk_len as u64;
            }
            ChunkState::Unused => skipped_chunks += 1,
            ChunkState::BadSector => {
                return Err(Error::BadSector {
                    offset,
                    len: chunk_len as u64,
                });
            }
        }
        Ok(())
    })?;

    // Regenerate the GPT for the target size (spec §H.1): the crate computes a
    // fresh backup LBA and rewrites both headers with valid CRCs.
    if disk_header.pt_type == PtType::Gpt {
        target.sync()?;
        regenerate_gpt(&target, &token.target_path, superblock.logical_block_size)?;
    }

    target.sync()?;
    Ok(RestoreReport {
        image: token.image.clone(),
        target: token.target_path.clone(),
        image_uuid: superblock.image_uuid,
        consistency: superblock.consistency,
        stored_chunks_written,
        zero_chunks_written,
        skipped_chunks,
        bytes_written,
    })
}

/// Fit the restored GPT to the target: move the backup header and entry
/// array to the target's last blocks and let the usable area end before
/// them, through the claimed target (`path` only names it in messages).
///
/// The entry array stays exactly as restored, so every partition keeps its
/// number and slot, and the entry count does not change. (The `gpt` crate
/// rewrote the whole table, which moved the used entries to the front, so
/// partition 5 of a table with a gap came back as partition 3, and shrank
/// the entry count to the number of partitions; R37.) The table's LBAs are
/// in the image's logical blocks, which `prepare` matched to the target's
/// (A14).
fn regenerate_gpt(target: &DirectBlockTarget, path: &Path, logical_block_size: u32) -> Result<()> {
    use std::os::unix::fs::FileExt;
    let fail = |what: String| {
        Error::corrupt(format!(
            "cannot fit the partition table to {}: {what}",
            path.display()
        ))
    };
    let lbs = u64::from(logical_block_size);
    let block = usize::try_from(lbs).map_err(|_| fail("block size".to_owned()))?;
    let file = target.buffered_handle()?;
    let last_lba = (target.size_bytes() / lbs)
        .checked_sub(1)
        .ok_or_else(|| fail("the target is empty".to_owned()))?;
    let field = |bytes: &[u8], at: usize| {
        u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap_or([0; 8]))
    };
    let field32 = |bytes: &[u8], at: usize| {
        u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap_or([0; 4]))
    };

    let mut primary = vec![0u8; block];
    file.read_exact_at(&mut primary, lbs).map_err(Error::Io)?;
    if &primary[0..8] != b"EFI PART" {
        return Err(fail("there is no GPT header in block 1".to_owned()));
    }
    let header_size = field32(&primary, 12) as usize;
    if !(92..=block).contains(&header_size) {
        return Err(fail(format!("the header claims {header_size} bytes")));
    }
    let mut unsealed = primary[..header_size].to_vec();
    unsealed[16..20].fill(0);
    if crc32fast::hash(&unsealed) != field32(&primary, 16) {
        return Err(fail("the header checksum does not match".to_owned()));
    }
    let entries_lba = field(&primary, 72);
    let entry_count = u64::from(field32(&primary, 80));
    let entry_size = u64::from(field32(&primary, 84));
    let entries_bytes = entry_count * entry_size;
    if entry_size < 128 || entries_bytes == 0 || entries_bytes > 16 * 1024 * 1024 {
        return Err(fail(format!(
            "{entry_count} entries of {entry_size} bytes is not a partition array"
        )));
    }
    let entries_blocks = entries_bytes.div_ceil(lbs);
    let mut entries = vec![0u8; usize::try_from(entries_blocks * lbs).unwrap_or(0)];
    file.read_exact_at(&mut entries, entries_lba * lbs)
        .map_err(Error::Io)?;
    let listed = usize::try_from(entries_bytes).unwrap_or(0);
    if crc32fast::hash(&entries[..listed]) != field32(&primary, 88) {
        return Err(fail(
            "the partition array checksum does not match".to_owned(),
        ));
    }
    let backup_entries_lba = last_lba
        .checked_sub(entries_blocks)
        .ok_or_else(|| fail("the target is too small".to_owned()))?;
    let last_usable = backup_entries_lba - 1;
    if last_usable < field(&primary, 48) {
        return Err(fail(
            "the target is smaller than the restored table".to_owned(),
        ));
    }

    let seal = |header: &mut Vec<u8>| {
        header[16..20].fill(0);
        let crc = crc32fast::hash(&header[..header_size]);
        header[16..20].copy_from_slice(&crc.to_le_bytes());
    };
    primary[32..40].copy_from_slice(&last_lba.to_le_bytes());
    primary[48..56].copy_from_slice(&last_usable.to_le_bytes());
    seal(&mut primary);
    let mut backup = primary.clone();
    backup[24..32].copy_from_slice(&last_lba.to_le_bytes());
    backup[32..40].copy_from_slice(&1u64.to_le_bytes());
    backup[72..80].copy_from_slice(&backup_entries_lba.to_le_bytes());
    seal(&mut backup);

    file.write_all_at(&entries, backup_entries_lba * lbs)
        .map_err(Error::Io)?;
    file.write_all_at(&backup, last_lba * lbs)
        .map_err(Error::Io)?;
    file.write_all_at(&primary, lbs).map_err(Error::Io)?;

    // The protective MBR is left as restored, boot code included.
    file.sync_all().map_err(Error::Io)
}

/// Recreate a swap region from its stored header.
///
/// The first 4 KiB of the source's swap area carry its signature, UUID,
/// label and size, and the region is restored at the image's own offset, so
/// writing that header back through the claimed whole-disk target recreates
/// the same swap area. `mkswap` on a partition node was used before, but the
/// node could still describe the target's *old* partition table and format
/// the wrong extent (R05).
fn write_swap(target: &mut DirectBlockTarget, region: &RegionRecord, lbs: u64) -> Result<()> {
    if region.swap_header.len() != SWAP_HEADER_BYTES {
        return Err(Error::corrupt(format!(
            "swap region {} has a {}-byte header, expected {SWAP_HEADER_BYTES}",
            region.index,
            region.swap_header.len()
        )));
    }
    let mut buffer = target.buffer(SWAP_HEADER_BYTES)?;
    buffer.as_mut_slice()[..SWAP_HEADER_BYTES].copy_from_slice(&region.swap_header);
    target.write_at(region.start_lba * lbs, &buffer, SWAP_HEADER_BYTES)
}
