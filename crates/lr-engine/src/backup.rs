//! Full block-mode backup (spec §D.1, §G, §K S6).
//!
//! The image is written in the order the format requires — superblock, chunk
//! records, metadata pages, footer — while the manifest that describes the
//! chunks is spooled to a temporary file next to the image and copied into the
//! page stream afterwards. That keeps memory bounded (spec §G.2: 4 TB of
//! entries is 184 MB) without re-reading the source or re-hashing chunks.

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use lr_blocksource::{BlockSource, DirectBlockSource, UsedChunks, is_all_zero, read_chunk};
use lr_core::catalog::{MemberKind, MemberRecord};
use lr_core::{
    ChainId, Consistency, Error, Id, ImageId, ImageKind, Result, SetId, SnapshotOpts,
    discovery::discover_source,
};
use lr_crypto::aead::AeadKind;
use lr_crypto::nonce::NonceSeq;
use lr_format::{
    BlockEntry, BlockManifestHeader, CHUNK_OVERHEAD_ENCRYPTED, ChainMember, ChunkOptions,
    ChunkState, DeltaEntry, EXTRAS_IMAGE_METADATA, FORMAT_MAJOR, ImageWriter, MIN_READER, StreamId,
    Superblock, WriterKeys, flags, write_chain_members, write_extras_record,
};
use lr_fsmap::provider_for;
use lr_snapshot::offline_provider;
use lr_store::{Destination, DestinationOptions};

use crate::keys::{self, Encryption};
use crate::keystore::Passphrase;

/// How chunks are compressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    /// Store chunks as-is (zero chunks are still detected).
    None,
    /// Try zstd; a chunk that does not shrink is stored raw (spec §G.5).
    Zstd {
        /// zstd level, 1..=22 (`zstd:9` default in spec §J.2).
        level: i32,
    },
}

impl Default for Compression {
    fn default() -> Self {
        Self::Zstd {
            level: lr_format::DEFAULT_LEVEL,
        }
    }
}

/// What to do when a chunk cannot be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BadSectorPolicy {
    /// Fail the job (default).
    Abort,
    /// Record state 3 in the manifest and continue (spec §L.2).
    Record,
}

/// The kind of chain member a request asks for (spec §D.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MemberType {
    /// Sequence 0 of a new chain; carries every chunk.
    Full,
    /// A delta manifest over the previous member (spec §D.4).
    Incremental,
    /// A full manifest that reuses chunks stored in ancestors.
    Differential,
}

impl MemberType {
    /// The file-name component for this kind.
    #[must_use]
    pub const fn file_tag(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Incremental => "incr",
            Self::Differential => "diff",
        }
    }
}

/// Everything a backup needs.
pub struct BackupRequest {
    /// Device or image file to back up.
    pub source: PathBuf,
    /// Destination base directory.
    pub dest_root: PathBuf,
    /// Backup set name (the directory under the destination).
    pub set_name: String,
    /// Set identifier recorded in the superblock.
    pub set_id: SetId,
    /// Chain identifier; new chains get a fresh one.
    pub chain_id: ChainId,
    /// Identifier of this image.
    pub image_uuid: ImageId,
    /// Block-mode chunk size.
    pub chunk_size: u32,
    /// Compression settings.
    pub compression: Compression,
    /// Encryption settings.
    pub encryption: Encryption,
    /// AEAD algorithm recorded in the superblock.
    pub aead: AeadKind,
    /// Bad-sector handling.
    pub on_bad_sector: BadSectorPolicy,
    /// Optional `--snapshot <provider>` override.
    pub snapshot_provider: Option<String>,
    /// Allow the freeze provider (writers block for the whole read).
    pub allow_freeze: bool,
    /// Freeze timeout in seconds (default 300).
    pub freeze_timeout_secs: Option<u64>,
    /// Allow reading a mounted device as-is (image flagged inconsistent).
    pub allow_inconsistent: bool,
    /// LVM snapshot COW size override, e.g. `2G` or `25%`.
    pub lvm_cow_size: Option<String>,
    /// Extra grace before the freeze deadman fires (default 30 s).
    pub deadman_grace_secs: Option<u64>,
    /// Chain member type (spec §J.1 `--type`).
    pub member_type: MemberType,
    /// `--parent latest|<uuid>`; required in spirit for incrementals.
    pub parent: Option<String>,
    /// Break an expired set lock instead of failing (spec §D.3).
    pub break_stale_lock: bool,
    /// Start a new chain when the newest one already holds this many
    /// incrementals (spec §J.3); `None` or `Some(0)` means no limit.
    pub max_incrementals_per_chain: Option<u64>,
    /// Destination URI; empty means "use `dest_root`" (spec §J.1).
    pub dest: String,
    /// Options for reaching the destination (paths, not secrets).
    pub destination_options: DestinationOptions,
    /// Set-lock lease in seconds; the spec default is 300, tests shorten it.
    pub set_lock_ttl_secs: Option<u64>,
    /// Live progress and cooperative cancellation (spec §I).
    pub context: crate::progress::EngineContext,
}

impl BackupRequest {
    /// A request with the spec defaults.
    ///
    /// # Errors
    /// Propagates RNG failures while generating identifiers.
    pub fn new(
        source: impl Into<PathBuf>,
        dest_root: impl Into<PathBuf>,
        set_name: impl Into<String>,
        encryption: Encryption,
    ) -> Result<Self> {
        let dest_root = dest_root.into();
        let set_name = set_name.into();
        Ok(Self {
            source: source.into(),
            dest_root,
            destination_options: DestinationOptions::new(&set_name),
            dest: String::new(),
            set_name,
            set_id: SetId::new(Id::generate()?),
            chain_id: ChainId::new(Id::generate()?),
            image_uuid: ImageId::new(Id::generate()?),
            chunk_size: 1024 * 1024,
            compression: Compression::default(),
            encryption,
            aead: AeadKind::Aes256Gcm,
            on_bad_sector: BadSectorPolicy::Abort,
            snapshot_provider: None,
            allow_freeze: false,
            freeze_timeout_secs: None,
            allow_inconsistent: false,
            lvm_cow_size: None,
            deadman_grace_secs: None,
            member_type: MemberType::Full,
            parent: None,
            break_stale_lock: false,
            max_incrementals_per_chain: None,
            set_lock_ttl_secs: None,
            context: crate::progress::EngineContext::silent(),
        })
    }

    /// Convenience constructor for a passphrase-protected backup.
    ///
    /// # Errors
    /// See [`BackupRequest::new`].
    pub fn encrypted(
        source: impl Into<PathBuf>,
        dest_root: impl Into<PathBuf>,
        set_name: impl Into<String>,
        passphrase: Passphrase,
    ) -> Result<Self> {
        Self::new(
            source,
            dest_root,
            set_name,
            Encryption::Passphrase(passphrase),
        )
    }
}

impl BackupRequest {
    /// Open the destination this request names.
    ///
    /// # Errors
    /// Propagates URI parsing, connection and authentication errors.
    pub fn open_destination(&self) -> Result<std::sync::Arc<dyn Destination>> {
        let mut options = self.destination_options.clone();
        options.set_name.clone_from(&self.set_name);
        let dest = if self.dest.is_empty() {
            self.dest_root.to_string_lossy().into_owned()
        } else {
            self.dest.clone()
        };
        lr_store::open(&dest, &options)
    }

    /// A human-readable name for the destination, for reports.
    #[must_use]
    pub fn destination_label(&self) -> String {
        if self.dest.is_empty() {
            self.dest_root.to_string_lossy().into_owned()
        } else {
            self.dest.clone()
        }
    }

    /// The URI of one image on this destination, for reports.
    #[must_use]
    pub fn image_uri(&self, name: &str) -> String {
        format!(
            "{}/{}/{}",
            self.destination_label().trim_end_matches('/'),
            self.set_name,
            name
        )
    }
}

/// What a finished backup produced.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BackupReport {
    /// Final image path inside the set; absolute for a local destination and
    /// set-relative for a remote one.
    pub image_path: PathBuf,
    /// The image as a destination URI, for display.
    pub image_uri: String,
    /// Image identifier.
    pub image_uuid: ImageId,
    /// Chain identifier.
    pub chain_id: ChainId,
    /// Consistency level achieved.
    pub consistency: Consistency,
    /// Source size in bytes.
    pub source_size_bytes: u64,
    /// Chunk size used.
    pub chunk_size: u32,
    /// Total chunks in the image.
    pub total_chunks: u64,
    /// Chunks stored in this image.
    pub stored_chunks: u64,
    /// Chunks recorded as all zero.
    pub zero_chunks: u64,
    /// Chunks recorded as unreadable.
    pub bad_chunks: u64,
    /// Bytes covered by the used-block map, before chunk alignment.
    pub used_bytes: u64,
    /// Bytes actually read and imaged, after rounding extents outward to chunk
    /// boundaries (spec §G.2).
    pub imaged_bytes: u64,
    /// Bytes of the final image file.
    pub image_bytes: u64,
    /// Source filesystem type, or `raw`.
    pub fs_type: String,
    /// `false` when the whole device was imaged because no map exists.
    pub map_complete: bool,
    /// Whether chunks are encrypted.
    pub encrypted: bool,
    /// Chain member role.
    pub member_kind: MemberKind,
    /// Position in the chain; 0 is the full.
    pub seq_in_chain: u32,
    /// Parent image UUID; zero for a full.
    pub parent_uuid: ImageId,
    /// Chunks whose content changed since the parent.
    pub changed_chunks: u64,
    /// Chunks inherited unchanged from an ancestor.
    pub inherited_chunks: u64,
}

/// Delete the temporary image and spool unless the job succeeded.
pub(crate) struct TempGuard {
    dest: std::sync::Arc<dyn Destination>,
    set: lr_store::SetHandle,
    image_name: String,
    /// Local scratch file holding the spooled manifest.
    spool_path: PathBuf,
    armed: bool,
}

impl TempGuard {
    pub(crate) fn new(
        dest: std::sync::Arc<dyn Destination>,
        set: lr_store::SetHandle,
        image_name: String,
        spool_path: PathBuf,
    ) -> Self {
        Self {
            dest,
            set,
            image_name,
            spool_path,
            armed: true,
        }
    }

    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let _ = self
            .dest
            .delete(&self.set, &format!("{}.tmp", self.image_name));
        let _ = std::fs::remove_file(&self.spool_path);
    }
}

/// Back up `request.source` into one full block image.
///
/// # Errors
/// Returns [`Error::NoConsistentMethod`] when the source cannot be read
/// consistently, [`Error::Unsupported`] for whole-disk sources (Slice S7) and
/// unavailable capabilities, and propagates I/O, AEAD and format errors.
pub fn backup_block_full(request: &BackupRequest) -> Result<BackupReport> {
    backup_block_with(request, offline_provider())
}

/// Back up a source with an explicitly chosen block snapshot provider.
///
/// # Errors
/// Returns [`Error::NoConsistentMethod`] when the provider refuses the source,
/// and propagates I/O, AEAD and format errors.
pub fn backup_block_with(
    request: &BackupRequest,
    provider: &dyn lr_snapshot::BlockSnapshotProvider,
) -> Result<BackupReport> {
    validate_chunk_size(request.chunk_size)?;

    // 1. What is the source?
    let layout = discover_source(&request.source)?;
    if layout.is_whole_disk() {
        return Err(Error::unsupported(
            "this source is a whole disk; call `backup` so the partition table is imaged too",
        ));
    }
    request.context.phase("snapshot");
    let snapshot_opts = snapshot_opts(request);
    lr_snapshot::probe::confirm(provider, &layout, &snapshot_opts)?;
    let snapshot = provider.create(&layout, &snapshot_opts)?;

    // 2. Which blocks must be read?
    let fs_type = layout
        .fs
        .as_ref()
        .map(|facts| facts.fs_type.clone())
        .unwrap_or_else(|| lr_fsmap::RAW_FS_TYPE.to_owned());
    let map = provider_for(&fs_type).used_extents(&snapshot.block_path)?;

    // 3. Open the source for aligned reads.
    let mut source = DirectBlockSource::open(&snapshot.block_path)?;
    let device_size = source.size_bytes();
    let logical_block_size = source.logical_block_size();
    let mut buffer = source.buffer(request.chunk_size as usize)?;
    let mut plan = UsedChunks::new(&map, u64::from(request.chunk_size), device_size)?;
    let imaged_bytes = plan.planned_bytes();
    let mut reporter = request.context.clone().reporter(imaged_bytes)?;
    reporter.phase("scan");
    // `chunk_count` is the device's chunk count (the manifest's `chunk_count`);
    // the used-block map only decides which of them hold data.
    let chunk_count = plan.chunk_count();

    // 4. Destination, catalog and set lock: all of backup, catalog rebuild and
    //    `parent=latest` resolution run under the lock (spec §D.3).
    let destination = request.open_destination()?;
    let set = destination.open_set(&request.set_id)?;
    let _lock = acquire_set_lock(&*destination, &set, request)?;
    let now = now_unix();
    let parent = resolve_parent_chain(request, &*destination, &set, now)?;
    let set_id = parent
        .as_ref()
        .map(|parent| parent.set_id)
        .filter(|id| *id != SetId::ZERO)
        .unwrap_or(request.set_id);
    let chain_id = parent
        .as_ref()
        .map_or(request.chain_id, |parent| parent.chain_id);
    let seq_in_chain = parent
        .as_ref()
        .map_or(0, |parent| parent.member.seq_in_chain + 1);
    let parent_uuid = parent
        .as_ref()
        .map_or(ImageId::ZERO, |parent| parent.member.image_uuid);
    let member_kind = match (&parent, request.member_type) {
        (None, _) => MemberKind::Full,
        (Some(_), MemberType::Incremental) => MemberKind::Incremental,
        (Some(_), _) => MemberKind::Differential,
    };

    // 5. Keys and superblock. A member reuses the chain key of its parent, so
    //    the whole chain shares one `dedup_key` (spec §G.4).
    let new_keys = match &parent {
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
    let mut sb_flags = 0u64;
    if new_keys.encrypted {
        sb_flags |= flags::ENCRYPTED;
    }
    if matches!(request.compression, Compression::Zstd { .. }) {
        sb_flags |= flags::COMPRESSED;
    }
    if snapshot.consistency == lr_core::Consistency::None {
        sb_flags |= flags::INCONSISTENT;
    }
    if member_kind == MemberKind::Incremental {
        sb_flags |= flags::DELTA_MANIFEST;
    }
    let superblock = Superblock {
        format_major: FORMAT_MAJOR,
        min_reader: MIN_READER,
        flags: sb_flags,
        image_kind: ImageKind::Block,
        consistency: snapshot.consistency,
        image_uuid: request.image_uuid,
        chain_id,
        set_id,
        parent_uuid,
        seq_in_chain,
        created_unix: now,
        source_size_bytes: device_size,
        logical_block_size,
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

    // 6. Destination layout (spec §D.3): `<chain_id>/<seq>-<kind>-<uuid>.lrimg`.
    //    The manifest spool needs local scratch space; next to the image for a
    //    local destination, a temporary directory for a remote one.
    let (set_root, spool_dir) = spool_location(&*destination, &set)?;
    let chain_dir = chain_id.to_string();
    let base_name = format!(
        "{seq_in_chain:03}-{}-{}.lrimg",
        request.member_type.file_tag(),
        request.image_uuid
    );
    let image_name = format!("{chain_dir}/{base_name}");
    let spool_name = format!("{chain_dir}/.{base_name}.manifest.spool");
    let spool_path = if spool_dir == set_root {
        set_root.join(&spool_name)
    } else {
        spool_dir.join(spool_name.replace('/', "_"))
    };
    let mut guard = TempGuard::new(
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

    // 7. Phase A: chunk records plus a spooled manifest.
    let mut image_writer = ImageWriter::create(
        destination.create_tmp(&set, &image_name)?,
        &superblock,
        mac_key,
    )?;
    let mut nonce_seq = NonceSeq::new();
    let spool_path = spool_dir.join(spool_name.replace('/', "_"));
    let counts = {
        let mut spool = BufWriter::new(File::create(&spool_path).map_err(Error::Io)?);
        let header = BlockManifestHeader {
            chunk_size: request.chunk_size,
            chunk_count,
            entry_count: 0,
            used_extent_count: map.extents.len() as u64,
            used_bytes: map.covered_bytes(),
            fs_type: fs_type.clone(),
            fs_uuid: layout
                .fs
                .as_ref()
                .and_then(|facts| facts.uuid.clone())
                .unwrap_or_default(),
            label: layout
                .fs
                .as_ref()
                .and_then(|facts| facts.label.clone())
                .unwrap_or_default(),
        };
        let header_offset = spool.stream_position().map_err(Error::Io)?;
        let counts = match &parent {
            None => {
                header.write(&mut spool, false)?;
                let counts = write_full_entries(
                    &mut image_writer,
                    options,
                    &writer_keys,
                    &mut nonce_seq,
                    &snapshot,
                    &mut source,
                    &mut plan,
                    &mut buffer,
                    request,
                    chunk_count,
                    &mut reporter,
                    &mut spool,
                )?;
                patch_entry_count(&mut spool, header_offset, chunk_count)?;
                counts
            }
            Some(parent) => {
                let delta = member_kind == MemberKind::Incremental;
                header.write(&mut spool, delta)?;
                let member = u16::try_from(seq_in_chain).map_err(|_| {
                    Error::unsupported("chains longer than 65535 members are not supported")
                })?;
                let members = crate::chain::open_chain(
                    &*destination,
                    &set,
                    &parent.files,
                    &request.encryption,
                )?;
                let mut walk = crate::chain::ChainWalk::new(members)?;
                if walk.chunk_count() != chunk_count {
                    return Err(Error::unsupported(format!(
                        "the source has {chunk_count} chunks but the parent image has {}; \
                         start a new full chain",
                        walk.chunk_count()
                    )));
                }
                let mut counts = Counts::default();
                let mut next = plan.next_chunk();
                walk.walk(|index, parent_state, _| {
                    reporter.report(index * u64::from(request.chunk_size))?;
                    counts.visited += 1;
                    let source_state = if next.is_some_and(|chunk| chunk.index == index) {
                        let chunk = next.expect("checked");
                        next = plan.next_chunk();
                        store_chunk(
                            &mut image_writer,
                            options,
                            &writer_keys,
                            &mut nonce_seq,
                            member,
                            &snapshot,
                            &mut source,
                            &chunk,
                            &mut buffer,
                            &parent_state,
                            request.on_bad_sector,
                        )?
                    } else if matches!(parent_state, ChunkState::Unused) {
                        SourceState::Unchanged
                    } else {
                        SourceState::Missing
                    };
                    let entry = match source_state {
                        SourceState::Unchanged => {
                            counts.inherited += 1;
                            if !delta {
                                entry_of(&parent_state).write(&mut spool)?;
                            }
                            return Ok(());
                        }
                        SourceState::Stored(entry) => {
                            counts.stored += 1;
                            entry
                        }
                        SourceState::Zero => {
                            counts.zero += 1;
                            BlockEntry::zero()
                        }
                        SourceState::BadSector(entry) => {
                            counts.bad += 1;
                            entry
                        }
                        SourceState::Missing => BlockEntry::unused(),
                    };
                    counts.changed += 1;
                    if delta {
                        DeltaEntry {
                            chunk_no: index,
                            entry,
                        }
                        .write(&mut spool)?;
                    } else {
                        entry.write(&mut spool)?;
                    }
                    Ok(())
                })?;
                let entries = if delta { counts.changed } else { chunk_count };
                patch_entry_count(&mut spool, header_offset, entries)?;
                counts
            }
        };
        spool.flush().map_err(Error::Io)?;
        spool
            .into_inner()
            .map_err(|e| Error::Io(e.into_error()))?
            .sync_all()
            .map_err(Error::Io)?;
        counts
    };

    reporter.phase("manifest");
    // 8. Phase B: copy the spooled manifest into the page stream.
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

    // 9. Extras: the chain member list (this member's prefix) and metadata.
    {
        let mut extras = image_writer.page_stream(StreamId::Extras, request.aead, meta_key);
        let mut members: Vec<ChainMember> = parent
            .as_ref()
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
            index: u8::try_from(seq_in_chain).unwrap_or(u8::MAX),
            image_uuid: request.image_uuid,
        });
        write_chain_members(&mut extras, &members)?;
        let metadata = format!(
            "source={}\nconsistency={}\nfs_type={fs_type}\nkind={}\nseq={seq_in_chain}\n",
            request.source.display(),
            snapshot.consistency,
            request.member_type.file_tag()
        );
        write_extras_record(&mut extras, EXTRAS_IMAGE_METADATA, metadata.as_bytes())?;
        extras.finish()?;
    }

    reporter.phase("finalize");
    reporter.finish(imaged_bytes);
    // 10. Footer, then atomic finalize.
    let (mut writer, _footer) = image_writer.finish(&meta_key, mac_key, request.aead)?;
    writer.flush().map_err(Error::Io)?;
    let image_bytes = writer.seek(SeekFrom::End(0)).map_err(Error::Io)?;
    drop(writer);
    destination.finalize(&set, &image_name, &image_name)?;
    guard.disarm();

    // 11. Catalog update, still under the lock (spec §D.3).
    update_catalog(&*destination, &set, &request.set_name, now_unix())?;

    Ok(BackupReport {
        image_path: local_image_path(&set_root, &image_name),
        image_uri: request.image_uri(&image_name),
        image_uuid: request.image_uuid,
        chain_id,
        consistency: snapshot.consistency,
        source_size_bytes: device_size,
        chunk_size: request.chunk_size,
        total_chunks: chunk_count,
        stored_chunks: counts.stored,
        zero_chunks: counts.zero,
        bad_chunks: counts.bad,
        used_bytes: map.covered_bytes(),
        imaged_bytes,
        image_bytes,
        fs_type,
        map_complete: map.complete,
        encrypted: new_keys.encrypted,
        member_kind,
        seq_in_chain,
        parent_uuid,
        changed_chunks: counts.changed,
        inherited_chunks: counts.inherited,
    })
}

/// How long a set lock lease lasts; refreshed every `ttl/3` (spec §D.3).
pub(crate) const SET_LOCK_TTL_SECS: u64 = 300;

/// Take the set lock, optionally breaking an expired one.
///
/// # Errors
/// Returns [`Error::SetLocked`] when another owner holds the set.
pub(crate) fn acquire_set_lock(
    destination: &dyn Destination,
    set: &lr_store::SetHandle,
    request: &BackupRequest,
) -> Result<lr_store::SetLock> {
    acquire_set_lock_for(
        destination,
        set,
        request.set_lock_ttl_secs.unwrap_or(SET_LOCK_TTL_SECS),
        request.break_stale_lock,
    )
}

/// Take the set lock with explicit lease and stale-breaking options, for
/// callers that hold no [`BackupRequest`] (catalog rebuild, retention).
///
/// # Errors
/// Returns [`Error::SetLocked`] when another owner holds the set.
pub fn acquire_set_lock_for(
    destination: &dyn Destination,
    set: &lr_store::SetHandle,
    ttl_secs: u64,
    break_stale: bool,
) -> Result<lr_store::SetLock> {
    let owner = lr_store::LockOwner::local();
    let ttl = std::time::Duration::from_secs(ttl_secs);
    if break_stale {
        destination.lock_set_breaking_stale(set, &owner, ttl)
    } else {
        destination.lock_set(set, &owner, ttl)
    }
}

/// The image's local path when the destination is local, its set-relative name
/// otherwise (`image_uri` carries the full address either way).
pub(crate) fn local_image_path(set_root: &Path, image_name: &str) -> PathBuf {
    if set_root.as_os_str().is_empty() {
        PathBuf::from(image_name)
    } else {
        set_root.join(image_name)
    }
}

/// Where the image lives and where a short-lived manifest spool goes.
///
/// A local destination keeps the spool next to the image (same filesystem, so
/// the finalize rename is atomic); a remote one uses a temporary directory.
pub(crate) fn spool_location(
    destination: &dyn Destination,
    set: &lr_store::SetHandle,
) -> Result<(PathBuf, PathBuf)> {
    match lr_store::local_root(set) {
        Ok(root) => Ok((root.clone(), root)),
        Err(_) => {
            let _ = destination;
            let dir = std::env::temp_dir().join("linuxreflect-spool");
            std::fs::create_dir_all(&dir).map_err(Error::Io)?;
            // An empty set root marks a remote destination: there is no local
            // path for the image.
            Ok((PathBuf::new(), dir))
        }
    }
}

/// Rewrite the catalog from the superblocks and refresh the source labels.
fn update_catalog(
    destination: &dyn Destination,
    set: &lr_store::SetHandle,
    set_name: &str,
    now: u64,
) -> Result<()> {
    let mut loaded = crate::catalog::load(destination, set, set_name, now)?;
    loaded.catalog.updated_unix = now;
    crate::catalog::write_catalog(destination, set, &loaded.catalog)
}

/// The parent chain of an incremental or differential member.
pub(crate) struct ParentChain {
    /// The parent member, as the catalog recorded it.
    pub member: MemberRecord,
    /// Chain of the parent.
    pub chain_id: ChainId,
    /// Set the parent belongs to.
    pub set_id: SetId,
    /// Chain member list to write in extras, indexed by sequence.
    pub prefix: Vec<(u8, ImageId)>,
    /// Member files from the full up to and including the parent.
    pub files: Vec<crate::chain::ChainMemberFile>,
    /// The parent's superblock, for key reuse.
    pub superblock: Superblock,
}

/// Resolve `--type`/`--parent` against the validated catalog.
///
/// # Errors
/// Returns [`Error::Unsupported`] for an unknown or superseded parent, and
/// propagates catalog and I/O errors.
pub(crate) fn resolve_parent_chain(
    request: &BackupRequest,
    destination: &dyn Destination,
    set: &lr_store::SetHandle,
    now: u64,
) -> Result<Option<ParentChain>> {
    if request.member_type == MemberType::Full {
        if request.parent.is_some() {
            return Err(Error::unsupported(
                "a full image starts a new chain and has no --parent",
            ));
        }
        return Ok(None);
    }
    let limit = request
        .max_incrementals_per_chain
        .filter(|limit| *limit > 0);
    let loaded = crate::catalog::load(destination, set, &request.set_name, now)?;
    for warning in &loaded.warnings {
        tracing::warn!(%warning, "catalog");
    }
    let parent = crate::catalog::resolve_parent(
        &loaded.catalog,
        request.parent.as_deref().unwrap_or("latest"),
    )?;
    let chain = loaded
        .catalog
        .chains
        .iter()
        .find(|chain| chain.member(parent.image_uuid).is_some())
        .cloned()
        .ok_or_else(|| Error::corrupt("the parent's chain vanished from the catalog"))?;
    // A run that would exceed `max_incrementals_per_chain` starts a new chain
    // (spec §J.3): returning "no parent" makes this member a fresh full.
    if let Some(limit) = limit {
        let incrementals = chain
            .members
            .iter()
            .filter(|member| member.seq_in_chain > 0)
            .count() as u64;
        if incrementals >= limit {
            tracing::info!(
                chain = %chain.chain_id,
                incrementals,
                limit,
                "the chain is full; starting a new one"
            );
            return Ok(None);
        }
    }
    let mut records: Vec<MemberRecord> = chain
        .members
        .iter()
        .filter(|member| member.seq_in_chain <= parent.seq_in_chain)
        .cloned()
        .collect();
    records.sort_by_key(|member| member.seq_in_chain);
    let mut files = Vec::with_capacity(records.len());
    let mut prefix = Vec::with_capacity(records.len());
    for (index, member) in records.iter().enumerate() {
        let index = u8::try_from(index)
            .map_err(|_| Error::unsupported("chains longer than 255 members are not supported"))?;
        files.push(crate::chain::ChainMemberFile {
            file_name: member.file_name.clone(),
            seq_in_chain: member.seq_in_chain,
            image_uuid: member.image_uuid,
        });
        prefix.push((index, member.image_uuid));
    }
    let superblock = crate::chain::read_superblock(destination, set, &parent.file_name)?;
    Ok(Some(ParentChain {
        member: parent,
        chain_id: chain.chain_id,
        set_id: loaded.catalog.set_id,
        prefix,
        files,
        superblock,
    }))
}

/// Counters for one manifest pass.
#[derive(Default)]
struct Counts {
    stored: u64,
    zero: u64,
    bad: u64,
    changed: u64,
    inherited: u64,
    visited: u64,
}

/// What the source holds in one chunk, relative to its parent state.
enum SourceState {
    /// Identical to the parent; nothing needs storing.
    Unchanged,
    Stored(BlockEntry),
    Zero,
    BadSector(BlockEntry),
    /// The used-block map says the source has no data in this chunk.
    Missing,
}

/// Read one chunk and store it only when it differs from its parent state.
///
/// This is the positional scan-and-diff of spec §D.4: every used block is read
/// and hashed, but a chunk whose keyed hash matches the parent's is not stored
/// again. Pass [`ChunkState::Unused`] as `parent` for a full image, where
/// nothing can be inherited.
#[allow(clippy::too_many_arguments)]
fn store_chunk(
    writer: &mut ImageWriter<impl Write + Seek>,
    options: ChunkOptions,
    writer_keys: &WriterKeys,
    nonce_seq: &mut NonceSeq,
    member: u16,
    snapshot: &lr_snapshot::BlockSnapshot,
    source: &mut DirectBlockSource,
    chunk: &lr_blocksource::ChunkPlan,
    buffer: &mut lr_unsafe::AlignedBuf,
    parent: &ChunkState,
    on_bad_sector: BadSectorPolicy,
) -> Result<SourceState> {
    // A snapshot that overflowed or a freeze that timed out must abort the job
    // before more data is read (spec §E.2, §E.4).
    snapshot.check_health()?;
    match read_chunk(source, chunk, buffer) {
        Ok(bytes) => {
            if is_all_zero(bytes) {
                return Ok(if matches!(parent, ChunkState::Zero) {
                    SourceState::Unchanged
                } else {
                    SourceState::Zero
                });
            }
            let hash = lr_crypto::content_hash(&writer_keys.dedup_key, bytes);
            if let ChunkState::Stored {
                hash: parent_hash, ..
            } = parent
                && *parent_hash == hash
            {
                return Ok(SourceState::Unchanged);
            }
            let reference =
                writer.append_chunk(options, writer_keys, ImageKind::Block, nonce_seq, bytes)?;
            Ok(SourceState::Stored(BlockEntry::stored(
                member,
                reference.hash,
                reference.offset,
                reference.stored_len,
            )?))
        }
        Err(error @ Error::BadSector { .. }) => match on_bad_sector {
            BadSectorPolicy::Abort => Err(error),
            // A recorded bad sector is always retried: the read may succeed
            // now, and the state is a change either way.
            BadSectorPolicy::Record => Ok(SourceState::BadSector(BlockEntry::bad_sector(
                chunk.offset,
                chunk.len,
            ))),
        },
        Err(error) => Err(error),
    }
}

/// Write a full manifest: every chunk in order, holes filled with `unused`.
#[allow(clippy::too_many_arguments)]
fn write_full_entries(
    writer: &mut ImageWriter<impl Write + Seek>,
    options: ChunkOptions,
    writer_keys: &WriterKeys,
    nonce_seq: &mut NonceSeq,
    snapshot: &lr_snapshot::BlockSnapshot,
    source: &mut DirectBlockSource,
    plan: &mut UsedChunks,
    buffer: &mut lr_unsafe::AlignedBuf,
    request: &BackupRequest,
    chunk_count: u64,
    reporter: &mut crate::progress::Reporter,
    spool: &mut impl Write,
) -> Result<Counts> {
    let mut counts = Counts::default();
    let mut next_index = 0u64;
    while let Some(chunk) = plan.next_chunk() {
        reporter.report(chunk.offset)?;
        while next_index < chunk.index {
            BlockEntry::unused().write(spool)?;
            next_index += 1;
        }
        let state = store_chunk(
            writer,
            options,
            writer_keys,
            nonce_seq,
            0,
            snapshot,
            source,
            &chunk,
            buffer,
            &ChunkState::Unused,
            request.on_bad_sector,
        )?;
        let entry = match state {
            SourceState::Stored(entry) => {
                counts.stored += 1;
                entry
            }
            SourceState::Zero => {
                counts.zero += 1;
                BlockEntry::zero()
            }
            SourceState::BadSector(entry) => {
                counts.bad += 1;
                entry
            }
            SourceState::Unchanged | SourceState::Missing => BlockEntry::unused(),
        };
        entry.write(spool)?;
        next_index = chunk.index + 1;
        counts.visited += 1;
    }
    while next_index < chunk_count {
        BlockEntry::unused().write(spool)?;
        next_index += 1;
    }
    Ok(counts)
}

/// Patch a spooled manifest header's `entry_count` field in place.
///
/// The incremental pass only learns how many chunks changed after walking the
/// parent, and re-reading the source to count first would defeat scan-and-diff.
fn patch_entry_count(
    spool: &mut BufWriter<File>,
    header_offset: u64,
    entry_count: u64,
) -> Result<()> {
    // Layout: ver u16, kind u8, reserved u8, chunk_size u32, chunk_count u64,
    // then entry_count u64.
    const ENTRY_COUNT_OFFSET: u64 = 2 + 1 + 1 + 4 + 8;
    spool.flush().map_err(Error::Io)?;
    let end = spool.stream_position().map_err(Error::Io)?;
    spool
        .seek(SeekFrom::Start(header_offset + ENTRY_COUNT_OFFSET))
        .map_err(Error::Io)?;
    spool
        .write_all(&entry_count.to_le_bytes())
        .map_err(Error::Io)?;
    spool.seek(SeekFrom::Start(end)).map_err(Error::Io)?;
    Ok(())
}

/// Convert a resolved parent state back into a manifest entry.
fn entry_of(state: &ChunkState) -> BlockEntry {
    match state {
        ChunkState::Stored {
            member,
            hash,
            offset,
            stored_len,
        } => BlockEntry::stored(*member, *hash, *offset, *stored_len)
            .unwrap_or_else(|_| BlockEntry::unused()),
        ChunkState::Zero => BlockEntry::zero(),
        ChunkState::Unused => BlockEntry::unused(),
        // A recorded bad sector is always re-read (`is_change` returns true),
        // so a differential never inherits one.
        ChunkState::BadSector => BlockEntry::bad_sector(0, 0),
    }
}

pub(crate) fn validate_chunk_size(chunk_size: u32) -> Result<()> {
    if !chunk_size.is_power_of_two()
        || !(lr_format::MIN_CHUNK_SIZE..=lr_format::MAX_CHUNK_SIZE).contains(&chunk_size)
    {
        return Err(Error::unsupported(format!(
            "chunk size {chunk_size} must be a power of two between {} and {}",
            lr_format::MIN_CHUNK_SIZE,
            lr_format::MAX_CHUNK_SIZE
        )));
    }
    Ok(())
}

/// Snapshot options derived from a backup request (spec §E).
pub(crate) fn snapshot_opts(request: &BackupRequest) -> SnapshotOpts {
    SnapshotOpts {
        provider: request.snapshot_provider.clone(),
        allow_freeze: request.allow_freeze,
        freeze_timeout_secs: request.freeze_timeout_secs,
        allow_inconsistent: request.allow_inconsistent,
        lvm_cow_size: request.lvm_cow_size.clone(),
        deadman_grace_secs: request.deadman_grace_secs,
        // The freeze provider proves the destination is on another filesystem.
        // A remote destination is never on the frozen filesystem.
        destination: request.dest.is_empty().then(|| request.dest_root.clone()),
        destination_remote: !request.dest.is_empty(),
    }
}

/// The report of whichever imaging mode ran.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ImageReport {
    /// A partition, logical volume or image file.
    Block(BackupReport),
    /// A whole disk with its partition table.
    WholeDisk(crate::whole_disk::WholeDiskReport),
    /// Btrfs subvolumes streamed with `btrfs send` (spec §E.1).
    Stream(crate::stream::StreamReport),
    /// A directory tree in file mode (spec §D.1, Slice S12).
    File(crate::file::FileReport),
}

/// Back up a source, choosing whole-disk or block mode from its layout.
///
/// # Errors
/// Propagates the errors of the chosen mode.
pub fn backup_image(request: &BackupRequest) -> Result<ImageReport> {
    let layout = discover_source(&request.source)?;
    if layout.device_facts.size_bytes == 0 {
        // A missing device, a detached loop device or an unreadable size would
        // otherwise produce a successful image with no content at all.
        return Err(Error::unsupported(format!(
            "{} reports a size of 0 bytes; is the source still present?",
            request.source.display()
        )));
    }
    if layout.is_whole_disk() {
        return Ok(ImageReport::WholeDisk(
            crate::whole_disk::backup_whole_disk(request)?,
        ));
    }
    let plan = lr_snapshot::probe::probe(&layout, &snapshot_opts(request))?;
    if plan.image_kind == ImageKind::Stream {
        return Ok(ImageReport::Stream(crate::stream::backup_stream(request)?));
    }
    let provider = lr_snapshot::probe::block_provider(&plan.provider)?;
    Ok(ImageReport::Block(backup_block_with(request, provider)?))
}

/// Minimum image overhead for a chunk count, used by tests and diagnostics.
#[must_use]
pub fn minimum_image_bytes(chunk_count: u64) -> u64 {
    lr_format::SB_SIZE as u64
        + chunk_count * CHUNK_OVERHEAD_ENCRYPTED as u64
        + lr_format::FOOTER_SIZE as u64
}

/// Seconds since the Unix epoch.
#[must_use]
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Path helper used by tests and the CLI.
#[must_use]
pub fn chain_dir(root: &Path, chain_id: &ChainId) -> PathBuf {
    root.join(chain_id.to_string())
}

#[cfg(test)]
mod tests {
    use super::{BackupRequest, Compression, backup_block_full, validate_chunk_size};
    use crate::keys::Encryption;
    use crate::keystore::Passphrase;

    #[test]
    fn chunk_size_validation_follows_the_spec() {
        assert!(validate_chunk_size(256 * 1024).is_ok());
        assert!(validate_chunk_size(1024 * 1024).is_ok());
        assert!(validate_chunk_size(4 * 1024 * 1024).is_ok());
        assert!(validate_chunk_size(1000).is_err());
        assert!(validate_chunk_size(128 * 1024).is_err());
        assert!(validate_chunk_size(8 * 1024 * 1024).is_err());
    }

    #[test]
    fn requests_default_to_one_mib_chunks_and_zstd_nine() {
        let request = BackupRequest::new(
            "/dev/loop-none",
            "/tmp/out",
            "set",
            Encryption::Passphrase(Passphrase::new(b"pw".to_vec())),
        )
        .expect("request");
        assert_eq!(request.chunk_size, 1024 * 1024);
        assert_eq!(
            request.compression,
            Compression::Zstd {
                level: lr_format::DEFAULT_LEVEL
            }
        );
        assert!(matches!(
            request.on_bad_sector,
            super::BadSectorPolicy::Abort
        ));
    }

    #[test]
    fn a_missing_source_is_reported() {
        let request = BackupRequest::new(
            "/nonexistent/lr-source",
            "/tmp/out",
            "set",
            Encryption::NoEncrypt,
        )
        .expect("request");
        assert!(backup_block_full(&request).is_err());
    }
}
