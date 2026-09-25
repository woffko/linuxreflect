//! Whole-disk backups and restores (spec §G.7, §H.1, §K S7).
//!
//! A whole-disk image imitates each partition on its own terms: filesystem
//! partitions through their used-block map, everything else (bios_grub, LVM
//! PV, LUKS, unknown) raw with zero suppression, swap by its first 4 KiB, and
//! the leading region — which carries the BIOS boot loader — raw up to the
//! spec's 16 MiB cap. Gaps and the backup GPT are not imaged; restore
//! regenerates the GPT for the target size.

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use lr_blocksource::{BlockSource, DirectBlockSource, DirectBlockTarget, UsedChunks, is_all_zero};
use lr_core::{
    Consistency, Error, ImageId, ImageKind, Result, SnapshotOpts, Support,
    discovery::discover_source,
};
use lr_crypto::nonce::NonceSeq;
use lr_format::{
    BlockEntry, BlockManifestHeader, ChainMember, ChunkOptions, DiskHeader, EXTRAS_IMAGE_METADATA,
    FORMAT_MAJOR, ImageWriter, MAX_LEADING_BYTES, MIN_READER, PtType, RegionKind, RegionRecord,
    SWAP_HEADER_BYTES, StreamId, Superblock, WriterKeys, flags, wire, write_chain_members,
    write_extras_record,
};
use lr_fsmap::provider_for;
use lr_snapshot::{BlockSnapshotProvider, offline_provider};

use crate::backup::{BadSectorPolicy, Compression, now_unix, validate_chunk_size};
use crate::keys::{self, ImageKeys};
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

/// Back up a whole disk.
///
/// # Errors
/// Returns [`Error::Unsupported`] when the source is not a whole disk,
/// [`Error::NoConsistentMethod`] when a partition cannot be read offline, and
/// propagates I/O, AEAD and format errors.
pub fn backup_whole_disk(request: &crate::backup::BackupRequest) -> Result<WholeDiskReport> {
    if request.member_type != crate::backup::MemberType::Full || request.parent.is_some() {
        return Err(Error::unsupported(
            "whole-disk images are full images only; per-region chain support is not implemented yet",
        ));
    }
    validate_chunk_size(request.chunk_size)?;
    let layout = discover_source(&request.source)?;
    if !layout.is_whole_disk() {
        return Err(Error::unsupported(
            "this source has no partition table; use a block backup instead",
        ));
    }
    let snapshot_opts = SnapshotOpts {
        provider: request.snapshot_provider.clone(),
        ..SnapshotOpts::default()
    };
    let provider = offline_provider();
    if let Support::No(reason) = provider.supports(&layout, &snapshot_opts) {
        return Err(Error::no_consistent_method([
            format!("offline read refused: {reason}"),
            "unmount every partition of the disk, then retry".to_owned(),
            "boot rescue media and run the statically linked CLI (offline)".to_owned(),
        ]));
    }
    // The disk itself and every partition must be idle.
    provider.create(&layout, &snapshot_opts)?;

    let mut source = DirectBlockSource::open(&request.source)?;
    let disk_size = source.size_bytes();
    let lbs = source.logical_block_size();
    let mut buffer = source.buffer(request.chunk_size as usize)?;

    // Regions: the leading area, then every partition in index order.
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
        region.consistency = Consistency::Offline;
        regions.push(region);
    }
    let plans: Vec<PartitionPlan> = layout
        .partitions
        .iter()
        .filter(|partition| partition.size_bytes > 0)
        .map(plan_partition)
        .collect();
    for plan in &plans {
        let mut region = RegionRecord::new(plan.kind, plan.index, plan.start_lba, plan.size_bytes);
        region.consistency = Consistency::Offline;
        region.bootable = plan.bootable;
        region.type_guid = plan.type_guid.clone();
        region.partuuid = plan.partuuid.clone();
        region.fs_type = plan.fs_type.clone();
        region.fs_uuid = plan.fs_uuid.clone();
        region.fs_label = plan.fs_label.clone();
        if plan.kind == RegionKind::Swap {
            let mut header = source.buffer(SWAP_HEADER_BYTES)?;
            let read = source.read_at(
                plan.start_lba * u64::from(lbs),
                &mut header,
                SWAP_HEADER_BYTES,
            )?;
            if read != SWAP_HEADER_BYTES {
                return Err(Error::BadSector {
                    offset: plan.start_lba * u64::from(lbs),
                    len: SWAP_HEADER_BYTES as u64,
                });
            }
            region.swap_header = header.as_slice().to_vec();
        }
        regions.push(region);
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

    // Keys and superblock, exactly as for a block image.
    let new_keys = keys::new_chain_keys(
        &request.encryption,
        &request.chain_id,
        request.image_uuid.inner(),
    )?;
    let meta_key = *new_keys.keys.meta_key;
    let mac_key = new_keys.encrypted.then_some(&meta_key);
    let mut sb_flags = flags::WHOLE_DISK;
    if new_keys.encrypted {
        sb_flags |= flags::ENCRYPTED;
    }
    if matches!(request.compression, Compression::Zstd { .. }) {
        sb_flags |= flags::COMPRESSED;
    }
    let superblock = Superblock {
        format_major: FORMAT_MAJOR,
        min_reader: MIN_READER,
        flags: sb_flags,
        image_kind: ImageKind::Block,
        consistency: Consistency::Offline,
        image_uuid: request.image_uuid,
        chain_id: request.chain_id,
        set_id: request.set_id,
        parent_uuid: ImageId::ZERO,
        seq_in_chain: 0,
        created_unix: now_unix(),
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

    let destination = request.open_destination()?;
    let set = destination.open_set(&request.set_id)?;
    let _lock = crate::backup::acquire_set_lock(&*destination, &set, request)?;
    let (set_root, spool_dir) = crate::backup::spool_location(&*destination, &set)?;
    let image_name = format!("{}/000-full-{}.lrimg", request.chain_id, request.image_uuid);
    let spool_name = format!(
        "{}.000-full-{}.manifest.spool",
        request.chain_id, request.image_uuid
    );
    let spool_path = spool_dir.join(&spool_name);
    let mut guard = crate::backup::TempGuard::new(
        std::sync::Arc::clone(&destination),
        set.clone(),
        image_name.clone(),
        spool_path.clone(),
    );

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

    let mut image_writer = ImageWriter::create(
        destination.create_tmp(&set, &image_name)?,
        &superblock,
        mac_key,
    )?;
    let mut nonce_seq = NonceSeq::new();
    let mut reports: Vec<RegionReport> = Vec::new();

    let mut reporter = request.context.clone().reporter(disk_size)?;
    reporter.phase("regions");
    // Phase A: chunk records plus the spooled manifest.
    {
        let mut spool = BufWriter::new(File::create(&spool_path).map_err(Error::Io)?);
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
            .write(&mut spool, false)?;

            let (regions_of_source, map_backed) = region_source_map(&layout, region);
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
            let mut next_index = 0u64;
            let mut stored_chunks = 0u64;
            let mut zero_chunks = 0u64;
            let mut bad_chunks = 0u64;
            reporter.phase(&format!("region {}", region.index));
            reporter.report(region.start_lba * u64::from(lbs))?;
            while let Some(chunk) = plan.next_chunk() {
                reporter.report(region.start_lba * u64::from(lbs) + chunk.offset)?;
                while next_index < chunk.index {
                    BlockEntry::unused().write(&mut spool)?;
                    next_index += 1;
                }
                let absolute = lr_blocksource::ChunkPlan {
                    index: chunk.index,
                    offset: region_start + chunk.offset,
                    len: chunk.len,
                };
                let entry = match lr_blocksource::read_chunk(&mut source, &absolute, &mut buffer) {
                    Ok(bytes) => {
                        if is_all_zero(bytes) {
                            zero_chunks += 1;
                            BlockEntry::zero()
                        } else {
                            let reference = image_writer.append_chunk(
                                options,
                                &writer_keys,
                                ImageKind::Block,
                                &mut nonce_seq,
                                bytes,
                            )?;
                            stored_chunks += 1;
                            BlockEntry::stored(
                                0,
                                reference.hash,
                                reference.offset,
                                reference.stored_len,
                            )?
                        }
                    }
                    Err(error @ Error::BadSector { .. }) => match request.on_bad_sector {
                        BadSectorPolicy::Abort => return Err(error),
                        BadSectorPolicy::Record => {
                            bad_chunks += 1;
                            BlockEntry::bad_sector(absolute.offset, absolute.len)
                        }
                    },
                    Err(error) => return Err(error),
                };
                entry.write(&mut spool)?;
                next_index = chunk.index + 1;
            }
            while next_index < chunk_count {
                BlockEntry::unused().write(&mut spool)?;
                next_index += 1;
            }
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
        spool.flush().map_err(Error::Io)?;
        spool
            .into_inner()
            .map_err(|e| Error::Io(e.into_error()))?
            .sync_all()
            .map_err(Error::Io)?;
    }

    reporter.phase("manifest");
    // Phase B: copy the spooled manifest into the page stream.
    {
        let mut manifest = image_writer.page_stream(StreamId::Manifest, request.aead, meta_key);
        let mut spool = BufReader::new(File::open(&spool_path).map_err(Error::Io)?);
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
    let _ = std::fs::remove_file(&spool_path);

    // Extras: chain members and a small metadata record.
    {
        let mut extras = image_writer.page_stream(StreamId::Extras, request.aead, meta_key);
        write_chain_members(
            &mut extras,
            &[ChainMember {
                index: 0,
                image_uuid: request.image_uuid,
            }],
        )?;
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
    destination.finalize(&set, &image_name, &image_name)?;
    guard.disarm();

    Ok(WholeDiskReport {
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
        leading_bytes,
        regions: reports,
        encrypted: new_keys.encrypted,
    })
}

/// The used-byte ranges of one region, and whether a real map was used.
fn region_source_map(
    layout: &lr_core::SourceLayout,
    region: &RegionRecord,
) -> (lr_fsmap::ExtentMap, bool) {
    let start = region.start_lba * u64::from(layout.device_facts.logical_block_size);
    let end = start + region.size_bytes - 1;
    let whole = lr_fsmap::ExtentMap {
        extents: vec![(start, end)],
        complete: false,
    };
    match region.kind {
        RegionKind::Leading | RegionKind::PartitionRaw => (whole, false),
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
                    ),
                    Ok(_) | Err(_) => (whole, false),
                },
                // An image file has no partition device nodes, so the map tools
                // cannot be pointed at the partition (spec §F).
                _ => (whole, false),
            }
        }
        RegionKind::Swap => (
            lr_fsmap::ExtentMap {
                extents: Vec::new(),
                complete: true,
            },
            false,
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

/// Restore a whole-disk image.
///
/// # Errors
/// Returns [`Error::TargetChanged`] when the target changed since `prepare`,
/// [`Error::NoSpace`] when it is smaller than the image's disk, and propagates
/// I/O and format errors.
pub(crate) fn restore_whole_disk<R: std::io::Read + std::io::Seek>(
    reader: &mut lr_format::ImageReader<R>,
    chunks: &mut lr_format::ChunkReader,
    keys: &ImageKeys,
    superblock: &Superblock,
    token: &RestoreToken,
    reporter: &mut crate::progress::Reporter,
) -> Result<RestoreReport> {
    let kind = superblock.aead_kind()?;
    let lbs = u64::from(superblock.logical_block_size);
    let chunk_size = u64::from(superblock.chunk_size);
    let mut target = DirectBlockTarget::open(&token.target_path)?;
    if target.size_bytes() < superblock.source_size_bytes {
        return Err(Error::NoSpace);
    }
    let mut buffer = target.buffer(chunk_size as usize)?;
    let mut zeros = target.buffer(chunk_size as usize)?;
    zeros.clear();

    let manifest = reader.stream_reader(StreamId::Manifest, *keys.meta_key, kind)?;
    let mut wire = wire::Reader::new(manifest);
    let disk_header = DiskHeader::read(&mut wire)?;
    disk_header.validate()?;

    let mut stored_chunks_written = 0u64;
    let mut zero_chunks_written = 0u64;
    let mut skipped_chunks = 0u64;
    let mut bytes_written = 0u64;

    for region in &disk_header.regions {
        reporter.phase(&format!("region {}", region.index));
        reporter.report(region.start_lba * lbs)?;
        if region.kind == RegionKind::Swap {
            write_swap(&token.target_path, region, lbs)?;
            continue;
        }
        if !region.has_manifest() {
            continue;
        }
        let (header, delta) = BlockManifestHeader::read(&mut wire)?;
        if delta {
            return Err(Error::unsupported(
                "delta manifests arrive in Slice S9; this image needs its chain",
            ));
        }
        let expected = region.chunk_count(chunk_size)?;
        if header.chunk_count != expected {
            return Err(Error::corrupt(format!(
                "region {} declares {expected} chunks but its manifest has {}",
                region.index, header.chunk_count
            )));
        }
        let region_start = region.start_lba * lbs;
        for index in 0..header.entry_count {
            let entry = BlockEntry::read(&mut wire)?;
            let offset = region_start + index * chunk_size;
            let chunk_len = chunk_size.min(region.size_bytes - index * chunk_size) as usize;
            match entry.state {
                lr_format::STATE_STORED => {
                    let record = chunks.read_record(entry.offset)?;
                    let plaintext = lr_format::open_chunk(
                        kind,
                        keys.data_key.as_deref(),
                        &keys.dedup_key,
                        ImageKind::Block,
                        &entry.hash,
                        chunk_len,
                        &record,
                    )?;
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
                lr_format::STATE_ZERO => {
                    target.write_at(offset, &zeros, chunk_len)?;
                    zero_chunks_written += 1;
                    bytes_written += chunk_len as u64;
                }
                lr_format::STATE_UNUSED => skipped_chunks += 1,
                lr_format::STATE_BAD_SECTOR => {
                    return Err(Error::BadSector {
                        offset,
                        len: chunk_len as u64,
                    });
                }
                other => {
                    return Err(Error::corrupt(format!("unknown chunk state {other}")));
                }
            }
        }
    }

    // Regenerate the GPT for the target size (spec §H.1): the crate computes a
    // fresh backup LBA and rewrites both headers with valid CRCs.
    if disk_header.pt_type == PtType::Gpt {
        regenerate_gpt(&token.target_path)?;
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

/// Rewrite the primary and backup GPT for the current target size.
fn regenerate_gpt(target: &Path) -> Result<()> {
    let config = gpt::GptConfig::new()
        .writable(true)
        .only_valid_headers(false)
        .change_partition_count(true);
    let mut disk = config.open(target).map_err(|e| {
        Error::corrupt(format!(
            "cannot reopen {} to regenerate the partition table: {e}",
            target.display()
        ))
    })?;
    // `update_partitions` recomputes both headers for the *current* device
    // size, including the backup header's location; `write_inplace` alone would
    // keep the old backup LBA from the restored header.
    let partitions = disk.partitions().clone();
    disk.update_partitions(partitions)
        .map_err(|e| Error::corrupt(format!("cannot rebuild the partition table: {e}")))?;
    disk.write_inplace()
        .map_err(|e| Error::corrupt(format!("cannot write the regenerated GPT: {e}")))?;
    Ok(())
}

/// Recreate a swap region.
///
/// On a device with partition nodes this calls `mkswap -U <uuid> -L <label>`
/// (spec §G.7). On a plain image file there is no partition node to hand to
/// `mkswap`, so the stored 4 KiB header is written back and the caller is told
/// to verify it.
fn write_swap(target: &Path, region: &RegionRecord, lbs: u64) -> Result<()> {
    let offset = region.start_lba * lbs;
    let name = lr_core::sysfs::device_name(target).unwrap_or_default();
    let partition_node = if name.starts_with("loop") || name.starts_with("nvme") {
        PathBuf::from(format!("{}p{}", target.display(), region.index))
    } else {
        PathBuf::from(format!("{}{}", target.display(), region.index))
    };
    if partition_node.exists() {
        let mut command = std::process::Command::new("mkswap");
        if !region.fs_uuid.is_empty() {
            command.arg("-U").arg(&region.fs_uuid);
        }
        if !region.fs_label.is_empty() {
            command.arg("-L").arg(&region.fs_label);
        }
        let status = command.arg(&partition_node).status().map_err(Error::Io)?;
        if status.success() {
            return Ok(());
        }
        tracing::warn!(
            partition = %partition_node.display(),
            "mkswap failed; falling back to the stored swap header"
        );
    }
    if region.swap_header.is_empty() {
        return Err(Error::corrupt(format!(
            "swap region {} has no stored header",
            region.index
        )));
    }
    let mut buffer = lr_unsafe::AlignedBuf::new(SWAP_HEADER_BYTES, 4096).map_err(Error::Io)?;
    buffer.as_mut_slice()[..region.swap_header.len()].copy_from_slice(&region.swap_header);
    let mut target = DirectBlockTarget::open(target)?;
    target.write_at(offset, &buffer, region.swap_header.len())?;
    target.sync()?;
    tracing::warn!(
        region = region.index,
        "swap recreated from the stored header; verify it before activating"
    );
    Ok(())
}
