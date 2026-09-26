//! File mode: content-defined chunks per file over a directory tree
//! (spec §D.1 `File`, §G.7, §K S12).
//!
//! A file image holds a manifest of `{path, mode, uid, gid, mtime, size,
//! xattrs, acl, hardlink_group, chunks[]}` records plus a hash index that maps
//! every chunk hash to the member and offset that stores it. Because the
//! references are content hashes, an incremental member only has to store the
//! chunks of the files that changed: entries whose metadata and content are
//! unchanged keep pointing at the chunks their ancestor stored.
//!
//! Sparse regions are recorded as `(offset, length)` pairs and restored with
//! `FALLOC_FL_PUNCH_HOLE`, so a sparse source stays sparse. Zero chunks are
//! ordinary stored chunks (a compressed zero chunk is tiny and repeats dedupe),
//! which keeps the reader free of a special "how long is a zero chunk" case.

use std::collections::{BTreeMap, HashMap};
use std::io::{Cursor, Read, Seek, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use fastcdc::v2020::{Normalization, StreamCDC};
use lr_core::catalog::MemberKind;
use lr_core::{
    ChainId, Consistency, Error, ImageId, ImageKind, Result, SetId, discovery::discover_source,
};
use lr_crypto::nonce::NonceSeq;
use lr_format::{
    BlockEntry, CdcParams, ChainMember, ChunkOptions, EXTRAS_IMAGE_METADATA, FORMAT_MAJOR,
    FileEntry, FileRecord, ImageWriter, MIN_READER, StreamId, Superblock, WriterKeys, flags,
    read_extras_record, read_manifest, write_cdc_params, write_chain_members, write_extras_record,
    write_record,
};

use crate::backup::{
    BackupRequest, Compression, MemberType, TempGuard, acquire_set_lock, now_unix,
    resolve_parent_chain,
};
use crate::keys::{self, Encryption};
use crate::tree::{self, WalkOptions};

/// Minimum file chunk size (spec §D, the stream/file CDC parameters).
pub const CDC_MIN: u32 = 16 * 1024;
/// Target file chunk size (spec §D).
pub const CDC_AVG: u32 = 64 * 1024;
/// Maximum file chunk size (spec §D).
pub const CDC_MAX: u32 = 256 * 1024;

/// A source directory resolved for walking, optionally through a snapshot.
struct FileSnapshot {
    /// Directory to walk.
    root: PathBuf,
    /// Consistency the walk provides.
    consistency: Consistency,
    /// Read-only snapshot to release when the image is final.
    _guard: Option<lr_snapshot::TreeSnapshot>,
}

/// Resolve the source root, snapshotting a Btrfs directory when asked.
///
/// `--snapshot btrfs` (or `auto` on a Btrfs source) takes a read-only snapshot
/// of the subvolume holding the directory and walks that instead, so the image
/// reflects one instant. Any other provider is refused with a clear error: a
/// directory cannot be frozen or taken offline per file.
fn snapshot_source(
    request: &BackupRequest,
    options: &FileBackupOptions,
) -> Result<Option<FileSnapshot>> {
    let source = request.source.canonicalize().map_err(Error::Io)?;
    let Some(mount) = lr_snapshot::btrfs::mount_of_path(&source)? else {
        return Ok(None);
    };
    let requested = request.snapshot_provider.as_deref();
    match requested {
        Some("none") => return Ok(None),
        Some("btrfs") | None if mount.fstype == "btrfs" => {}
        Some("btrfs") => {
            return Err(Error::unsupported(format!(
                "{} is on {}, not Btrfs; file mode cannot snapshot it",
                source.display(),
                mount.fstype
            )));
        }
        Some(other) if mount.fstype == "btrfs" => {
            return Err(Error::unsupported(format!(
                "file mode snapshots a source with `btrfs`, not `{other}`"
            )));
        }
        Some(_) | None => return Ok(None),
    }
    if mount.device.is_empty() {
        return Err(Error::unsupported(format!(
            "{} has no backing device to snapshot",
            source.display()
        )));
    }
    let layout = discover_source(Path::new(&mount.device))?;
    let opts = lr_snapshot::TreeSnapshotOpts {
        set_name: request.set_name.clone(),
        image_uuid: *request.image_uuid.inner(),
        incremental: lr_snapshot::btrfs::Incremental::Never,
        parent_image: None,
        mount_root: PathBuf::from(lr_snapshot::btrfs::DEFAULT_MOUNT_ROOT),
        general: crate::backup::snapshot_opts(request),
    };
    request.context.phase("snapshot");
    let snapshot = lr_snapshot::btrfs::provider().create(&layout, &opts)?;
    let root = snapshot
        .subvolumes
        .iter()
        .filter_map(|subvol| {
            source
                .strip_prefix(&subvol.mount_target)
                .ok()
                .map(|relative| subvol.snapshot_path.join(relative))
        })
        .find(|candidate| candidate.is_dir())
        .ok_or_else(|| {
            Error::unsupported(format!(
                "no snapshot of {} covers {}",
                mount.device,
                source.display()
            ))
        })?;
    if !options.xattrs {
        tracing::debug!("the btrfs snapshot still carries xattrs");
    }
    Ok(Some(FileSnapshot {
        root,
        consistency: Consistency::PointInTime,
        _guard: Some(snapshot),
    }))
}

/// How a file backup walks the source.
#[derive(Debug, Clone)]
pub struct FileBackupOptions {
    /// Do not descend into other filesystems (spec §K S12).
    pub one_file_system: bool,
    /// Absolute paths to skip; defaults to the spec's pseudo-filesystems.
    pub excludes: Vec<PathBuf>,
    /// Read extended attributes (POSIX ACLs included).
    pub xattrs: bool,
    /// Walk this path instead of `request.source` (a read-only snapshot).
    pub source_override: Option<PathBuf>,
    /// Consistency of the walk; `PerFile` unless the source is a snapshot.
    pub consistency: Consistency,
}

impl Default for FileBackupOptions {
    fn default() -> Self {
        Self {
            one_file_system: false,
            excludes: WalkOptions::with_default_excludes().excludes,
            xattrs: true,
            source_override: None,
            consistency: Consistency::PerFile,
        }
    }
}

/// What a file backup produced.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FileReport {
    /// Final image path inside the set.
    pub image_path: PathBuf,
    /// Image identifier.
    pub image_uuid: ImageId,
    /// Chain identifier.
    pub chain_id: ChainId,
    /// Consistency level achieved.
    pub consistency: Consistency,
    /// Backed-up root.
    pub root: String,
    /// Regular files in the image.
    pub files: u64,
    /// Directories.
    pub directories: u64,
    /// Symbolic links.
    pub symlinks: u64,
    /// Hard links (content stored once with its group's first file).
    pub hardlinks: u64,
    /// Device nodes, FIFOs and sockets.
    pub specials: u64,
    /// Files whose content was inherited from an ancestor unchanged.
    pub unchanged_files: u64,
    /// Total logical bytes of regular files.
    pub total_bytes: u64,
    /// Bytes of regular-file content newly chunked in this image.
    pub chunked_bytes: u64,
    /// Chunks stored in this image.
    pub stored_chunks: u64,
    /// Chunk references that reused an in-image duplicate.
    pub deduplicated_chunks: u64,
    /// Bytes of the final image file.
    pub image_bytes: u64,
    /// Whether chunks are encrypted.
    pub encrypted: bool,
    /// Chain member role.
    pub member_kind: MemberKind,
    /// Position in the chain; 0 is the full.
    pub seq_in_chain: u32,
    /// Parent image UUID; zero for a full.
    pub parent_uuid: ImageId,
    /// Non-fatal notes from the walk.
    pub warnings: Vec<String>,
}

/// Back up a directory tree in File mode (spec §D.1, §K S12).
///
/// # Errors
/// Returns [`Error::Unsupported`] when the source is not a directory and
/// propagates walk, chunking, AEAD and format errors.
pub fn backup_file(request: &BackupRequest, options: &FileBackupOptions) -> Result<FileReport> {
    // A Btrfs source can be snapshotted first, which turns per-file consistency
    // into a point-in-time view (spec §D.2, §K S12).
    let snapshot = match options.source_override.clone() {
        Some(root) => Some(FileSnapshot {
            root,
            consistency: options.consistency,
            _guard: None,
        }),
        None => snapshot_source(request, options)?,
    };
    let walk_root = snapshot
        .as_ref()
        .map_or_else(|| request.source.clone(), |snapshot| snapshot.root.clone());
    let consistency = snapshot
        .as_ref()
        .map_or(options.consistency, |snapshot| snapshot.consistency);

    // The set lock comes first so a refused parent never wastes a walk.
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

    // The base state an incremental/differential compares against: the newest
    // member of the parent chain.
    let mut base: HashMap<Vec<u8>, FileEntry> = HashMap::new();
    if let Some(parent) = &parent {
        let mut members =
            crate::chain::open_chain(&*destination, &set, &parent.files, &request.encryption)?;
        // A differential depends on the chain's full member only (spec §D.3),
        // so it compares against the full; an incremental compares against the
        // newest member.
        let against_full = request.member_type == MemberType::Differential;
        let reference = if against_full {
            members.first_mut()
        } else {
            members.last_mut()
        };
        if let Some(reference) = reference {
            for record in read_records(reference)? {
                base.insert(record.entry.path.clone(), record.entry);
            }
        }
    }

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
    if consistency == Consistency::None {
        sb_flags |= flags::INCONSISTENT;
    }
    let walk = tree::walk(
        &walk_root,
        &WalkOptions {
            one_file_system: options.one_file_system,
            excludes: options.excludes.clone(),
            xattrs: options.xattrs,
        },
    )?;
    let superblock = Superblock {
        format_major: FORMAT_MAJOR,
        min_reader: MIN_READER,
        flags: sb_flags,
        image_kind: ImageKind::File,
        consistency,
        image_uuid: request.image_uuid,
        chain_id,
        set_id,
        parent_uuid,
        seq_in_chain,
        created_unix: now,
        source_size_bytes: walk.total_bytes,
        logical_block_size: 4096,
        // For File images this is the maximum CDC chunk size; the exact
        // parameters live in the CDC_PARAMS extras record (like Stream).
        chunk_size: CDC_MAX,
        kdf_id: u32::from(new_keys.encrypted),
        aead_id: request.aead.id(),
        kdf_salt: new_keys.kdf_salt,
        argon2_m_cost_kib: new_keys.params.m_cost_kib,
        argon2_t_cost: new_keys.params.t_cost,
        argon2_p_cost: new_keys.params.p_cost,
        wrap_nonce: new_keys.wrap_nonce,
        wrapped_chain_key: new_keys.wrapped_chain_key,
    };

    let (set_root, spool_dir) = crate::backup::spool_location(&*destination, &set)?;
    let chain_dir = chain_id.to_string();
    let base_name = format!(
        "{seq_in_chain:03}-{}-{}.lrimg",
        request.member_type.file_tag(),
        request.image_uuid
    );
    let image_name = format!("{chain_dir}/{base_name}");
    let spool_path = spool_dir.join(format!("{chain_dir}.{base_name}.file.spool"));
    let mut guard = TempGuard::new(
        std::sync::Arc::clone(&destination),
        set.clone(),
        image_name.clone(),
        spool_path,
    );

    let writer_keys = WriterKeys {
        data_key: new_keys.keys.data_key.as_ref().map(|key| **key),
        meta_key,
        dedup_key: *new_keys.keys.dedup_key,
    };
    let chunk_options = ChunkOptions {
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
    let mut reporter = request.context.clone().reporter(walk.total_bytes)?;
    reporter.phase("files");

    // Every chunk this image stores, keyed by its content hash; entries whose
    // content is unchanged are inherited from the base instead.
    let mut index: BTreeMap<[u8; 32], BlockEntry> = BTreeMap::new();
    let mut records: Vec<FileRecord> = Vec::with_capacity(walk.entries.len());
    let mut counts = [0u64; 5];
    let mut unchanged_files = 0u64;
    let mut chunked_bytes = 0u64;
    let mut stored_chunks = 0u64;
    let mut deduplicated_chunks = 0u64;
    let mut seen_content = 0u64;

    for walked in &walk.entries {
        let mut entry = walked.entry.clone();
        match entry.file_kind {
            lr_format::FILE_KIND_DIRECTORY => counts[1] += 1,
            lr_format::FILE_KIND_SYMLINK => counts[2] += 1,
            lr_format::FILE_KIND_HARDLINK => counts[3] += 1,
            lr_format::FILE_KIND_SPECIAL => counts[4] += 1,
            _ => counts[0] += 1,
        }
        if entry.file_kind == lr_format::FILE_KIND_REGULAR {
            let inherited = base
                .get(&entry.path)
                .filter(|previous| unchanged(previous, &entry))
                .cloned();
            match inherited {
                Some(previous) => {
                    // The chunk references stay valid: they point at the same
                    // chain members, whose indices do not change.
                    entry = FileEntry {
                        chunk_refs_total: previous.chunk_refs_total,
                        chunk_refs_here: previous.chunk_refs_here,
                        ..entry
                    };
                    unchanged_files += 1;
                    seen_content += entry.size;
                    reporter.report(seen_content)?;
                }
                None => {
                    let hashes = chunk_file(
                        &mut image_writer,
                        &writer_keys,
                        chunk_options,
                        &mut nonce_seq,
                        &walk_root.join(std::ffi::OsStr::from_bytes(&entry.path)),
                        &mut index,
                        &mut stored_chunks,
                        &mut deduplicated_chunks,
                        &mut reporter,
                        seen_content,
                        seq_in_chain,
                    )?;
                    seen_content += entry.size;
                    chunked_bytes += entry.size;
                    entry.chunk_refs_total = hashes.len() as u64;
                    entry.chunk_refs_here = hashes;
                }
            }
        } else if entry.file_kind == lr_format::FILE_KIND_HARDLINK {
            // A hard link has no content of its own; its group's first file
            // carries it. Nothing to chunk.
        }
        records.push(FileRecord {
            entry,
            holes: walked.holes.clone(),
        });
    }

    {
        let mut manifest = image_writer.page_stream(StreamId::Manifest, request.aead, meta_key);
        for record in &records {
            write_record(&mut manifest, record)?;
        }
        manifest.finish()?;
    }
    {
        let mut hash_index = image_writer.page_stream(StreamId::HashIndex, request.aead, meta_key);
        for entry in index.values() {
            entry.write(&mut hash_index)?;
        }
        hash_index.finish()?;
    }
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
        write_cdc_params(
            &mut extras,
            CdcParams {
                min_size: CDC_MIN,
                avg_size: CDC_AVG,
                max_size: CDC_MAX,
                normalization: 1,
            },
        )?;
        let mut metadata = format!(
            "source={}\nconsistency={}\nmode=file\nroot={}\none_file_system={}\nxattrs={}\n",
            request.source.display(),
            consistency,
            walk_root.display(),
            options.one_file_system,
            options.xattrs
        );
        for exclude in &options.excludes {
            metadata.push_str(&format!("exclude={}\n", exclude.display()));
        }
        write_extras_record(&mut extras, EXTRAS_IMAGE_METADATA, metadata.as_bytes())?;
        extras.finish()?;
    }

    reporter.phase("finalize");
    reporter.finish(walk.total_bytes);
    let (mut writer, _footer) = image_writer.finish(&meta_key, mac_key, request.aead)?;
    writer.flush().map_err(Error::Io)?;
    let image_bytes = writer.seek(std::io::SeekFrom::End(0)).map_err(Error::Io)?;
    drop(writer);
    destination.finalize(&set, &image_name, &image_name)?;
    guard.disarm();
    drop(snapshot);

    {
        let mut loaded = crate::catalog::load(&*destination, &set, &request.set_name, now_unix())?;
        loaded.catalog.updated_unix = now_unix();
        crate::catalog::write_catalog(&*destination, &set, &loaded.catalog)?;
    }

    let mut warnings = walk.warnings;
    if consistency == Consistency::PerFile {
        warnings.push(
            "file mode without a tree snapshot is consistently per file, not point-in-time \
             (spec §D.2)"
                .to_owned(),
        );
    }

    Ok(FileReport {
        image_path: crate::backup::local_image_path(&set_root, &image_name),
        image_uuid: request.image_uuid,
        chain_id,
        consistency,
        root: walk_root.display().to_string(),
        files: counts[0],
        directories: counts[1],
        symlinks: counts[2],
        hardlinks: counts[3],
        specials: counts[4],
        unchanged_files,
        total_bytes: walk.total_bytes,
        chunked_bytes,
        stored_chunks,
        deduplicated_chunks,
        image_bytes,
        encrypted: new_keys.encrypted,
        member_kind,
        seq_in_chain,
        parent_uuid,
        warnings,
    })
}

/// True when a base entry and a fresh walk describe identical metadata.
fn unchanged(previous: &FileEntry, fresh: &FileEntry) -> bool {
    previous.file_kind == fresh.file_kind
        && previous.mode == fresh.mode
        && previous.uid == fresh.uid
        && previous.gid == fresh.gid
        && previous.mtime_sec == fresh.mtime_sec
        && previous.mtime_nsec == fresh.mtime_nsec
        && previous.size == fresh.size
        && previous.rdev == fresh.rdev
        && previous.hardlink_group == fresh.hardlink_group
        && previous.link_target == fresh.link_target
        && previous.xattrs == fresh.xattrs
        && previous.acl == fresh.acl
}

/// Chunk one regular file and return its content hashes in order.
#[allow(clippy::too_many_arguments)]
fn chunk_file<W: Write + Seek>(
    writer: &mut ImageWriter<W>,
    writer_keys: &WriterKeys,
    options: ChunkOptions,
    nonce_seq: &mut NonceSeq,
    path: &Path,
    index: &mut BTreeMap<[u8; 32], BlockEntry>,
    stored_chunks: &mut u64,
    deduplicated_chunks: &mut u64,
    reporter: &mut crate::progress::Reporter,
    processed: u64,
    seq_in_chain: u32,
) -> Result<Vec<[u8; 32]>> {
    let file = tree::open_nofollow(path)?;
    let reader: Box<dyn Read> = Box::new(file);
    let chunker = StreamCDC::with_level(
        reader,
        CDC_MIN as usize,
        CDC_AVG as usize,
        CDC_MAX as usize,
        Normalization::Level1,
    );
    let member = u16::try_from(seq_in_chain).unwrap_or(u16::MAX);
    let mut hashes = Vec::new();
    let mut reported = processed;
    for chunk in chunker {
        let chunk = chunk.map_err(|error| {
            Error::corrupt(format!("chunking {} failed: {error}", path.display()))
        })?;
        reported += chunk.length as u64;
        reporter.report(reported)?;
        let hash = lr_crypto::content_hash(&writer_keys.dedup_key, &chunk.data);
        hashes.push(hash);
        if index.contains_key(&hash) {
            *deduplicated_chunks += 1;
            continue;
        }
        let reference = writer.append_chunk(
            options,
            writer_keys,
            ImageKind::File,
            nonce_seq,
            &chunk.data,
        )?;
        *stored_chunks += 1;
        let entry = BlockEntry::stored(
            member,
            reference.hash,
            reference.offset,
            reference.stored_len,
        )?;
        index.insert(hash, entry);
    }
    Ok(hashes)
}

/// What `restore_file` needs.
pub struct FileRestoreRequest {
    /// Destination URI the images live on.
    pub dest: String,
    /// Set name inside the destination.
    pub set: String,
    /// Images in chain order; each is applied on top of the previous.
    pub images: Vec<String>,
    /// How to reach the destination (paths, not secrets).
    pub destination_options: lr_store::DestinationOptions,
    /// Existing directory to restore into.
    pub target: PathBuf,
    /// How to unlock the images.
    pub encryption: Encryption,
    /// Must be true; the write is refused otherwise.
    pub confirm: bool,
    /// Allow applying images flagged inconsistent.
    pub accept_inconsistent: bool,
    /// Allow restoring into a directory that already has entries.
    pub merge: bool,
    /// Live progress and cooperative cancellation (spec §I).
    pub context: crate::progress::EngineContext,
}

/// What a file restore produced.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FileRestoreReport {
    /// Directory that was written.
    pub target: PathBuf,
    /// Images applied, in order.
    pub images: Vec<String>,
    /// Regular files written.
    pub files: u64,
    /// Directories created.
    pub directories: u64,
    /// Symbolic links recreated.
    pub symlinks: u64,
    /// Hard links recreated.
    pub hardlinks: u64,
    /// Device nodes, FIFOs and sockets recreated.
    pub specials: u64,
    /// Content bytes written.
    pub restored_bytes: u64,
    /// Non-fatal notes.
    pub warnings: Vec<String>,
}

/// Restore a file-mode chain into an existing directory (spec §H.1).
///
/// # Errors
/// Returns [`Error::Unsupported`] without `--confirm` or when the target is a
/// non-empty directory in non-merge mode, and propagates chain, decryption and
/// filesystem errors.
pub fn restore_file(request: &FileRestoreRequest) -> Result<FileRestoreReport> {
    if !request.confirm {
        return Err(Error::unsupported(
            "restore apply requires --confirm; nothing has been written",
        ));
    }
    if request.images.is_empty() {
        return Err(Error::unsupported("no images to restore"));
    }
    let destination = lr_store::open(&request.dest, &request.destination_options)?;
    let set = destination.open_set(&SetId::ZERO)?;
    let files = request
        .images
        .iter()
        .map(|name| {
            let member = crate::chain::read_superblock(&*destination, &set, name)?;
            Ok(crate::chain::ChainMemberFile {
                file_name: name.clone(),
                seq_in_chain: member.seq_in_chain,
                image_uuid: member.image_uuid,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut members = crate::chain::open_chain(&*destination, &set, &files, &request.encryption)?;
    if members
        .iter()
        .any(|member| member.superblock.image_kind != ImageKind::File)
    {
        return Err(Error::unsupported(
            "this is not a file-mode chain; file restore needs File images",
        ));
    }
    if members
        .iter()
        .any(|member| member.superblock.consistency == Consistency::None)
        && !request.accept_inconsistent
    {
        return Err(Error::unsupported(
            "an image is flagged inconsistent; pass --accept-inconsistent to restore it",
        ));
    }

    // Every member's manifest lists the whole tree at its backup time, so the
    // newest member alone is the state being restored; earlier members only
    // contribute the chunks it references. Merging all manifests would bring
    // back files deleted before the newest backup (D-108).
    let newest = members
        .iter()
        .map(|member| member.seq_in_chain)
        .max()
        .unwrap_or_default();
    let mut final_entries: BTreeMap<Vec<u8>, FileRecord> = BTreeMap::new();
    let mut hash_index: HashMap<[u8; 32], BlockEntry> = HashMap::new();
    for member in &mut members {
        if member.seq_in_chain == newest {
            let bytes = member.stream_bytes(StreamId::Manifest)?;
            for record in read_manifest(&bytes)? {
                final_entries.insert(record.entry.path.clone(), record);
            }
        }
        let bytes = member.stream_bytes(StreamId::HashIndex)?;
        let mut cursor = Cursor::new(bytes.as_slice());
        while (cursor.position() as usize) < bytes.len() {
            let mut wire = lr_format::wire::Reader::new(&mut cursor);
            let entry = BlockEntry::read(&mut wire)?;
            if entry.state == lr_format::manifest::STATE_STORED {
                hash_index.insert(entry.hash, entry);
            }
        }
    }

    // Hard-link groups resolve to the group's content-bearing path.
    let mut group_paths: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    for record in final_entries.values() {
        if record.entry.file_kind == lr_format::FILE_KIND_REGULAR
            && record.entry.hardlink_group != 0
        {
            group_paths
                .entry(record.entry.hardlink_group)
                .or_insert_with(|| record.entry.path.clone());
        }
    }
    let hardlink_targets: BTreeMap<u32, PathBuf> = group_paths
        .iter()
        .map(|(group, path)| {
            (
                *group,
                request.target.join(std::ffi::OsStr::from_bytes(path)),
            )
        })
        .collect();

    prepare_target(&request.target, request.merge)?;

    let total_bytes: u64 = final_entries
        .values()
        .filter(|record| {
            matches!(
                record.entry.file_kind,
                lr_format::FILE_KIND_REGULAR | lr_format::FILE_KIND_HARDLINK
            )
        })
        .map(|record| record.entry.size)
        .sum();
    let mut reporter = request.context.clone().reporter(total_bytes)?;
    reporter.phase("restore");

    let mut ordered: Vec<&FileRecord> = final_entries.values().collect();
    ordered.sort_by_key(|record| {
        let kind_rank = match record.entry.file_kind {
            lr_format::FILE_KIND_DIRECTORY => 0,
            lr_format::FILE_KIND_REGULAR => 1,
            lr_format::FILE_KIND_SPECIAL | lr_format::FILE_KIND_SYMLINK => 2,
            _ => 3,
        };
        (kind_rank, record.entry.path.clone())
    });

    let mut counts = [0u64; 5];
    let mut restored_bytes = 0u64;
    let mut warnings = Vec::new();
    for record in &ordered {
        match record.entry.file_kind {
            lr_format::FILE_KIND_DIRECTORY => counts[1] += 1,
            lr_format::FILE_KIND_SYMLINK => counts[2] += 1,
            lr_format::FILE_KIND_HARDLINK => counts[3] += 1,
            lr_format::FILE_KIND_SPECIAL => counts[4] += 1,
            _ => counts[0] += 1,
        }
        let mut content = |file: &mut std::fs::File| -> Result<()> {
            let mut offset = 0u64;
            for hash in &record.entry.chunk_refs_here {
                let entry = hash_index.get(hash).ok_or_else(|| {
                    Error::corrupt(format!(
                        "{} references a chunk no member stores",
                        String::from_utf8_lossy(&record.entry.path)
                    ))
                })?;
                let member = members.get_mut(entry.member as usize).ok_or_else(|| {
                    Error::corrupt(format!(
                        "a chunk of {} names chain member {}, which does not exist",
                        String::from_utf8_lossy(&record.entry.path),
                        entry.member
                    ))
                })?;
                let plaintext = member.chunk_plaintext(entry, CDC_MAX as usize)?;
                write_skipping_holes(file, offset, &plaintext, &record.holes)?;
                offset += plaintext.len() as u64;
                restored_bytes += plaintext.len() as u64;
            }
            reporter.report(restored_bytes)?;
            Ok(())
        };
        tree::restore_entry(
            &request.target,
            &record.entry,
            &record.holes,
            &hardlink_targets,
            &mut content,
        )?;
    }

    // Metadata after content, directories deepest first so writing children
    // cannot bump a directory's mtime.
    let entries: Vec<FileEntry> = final_entries
        .values()
        .map(|record| record.entry.clone())
        .collect();
    for entry in tree::deepest_first(&entries) {
        let path = request
            .target
            .join(std::ffi::OsStr::from_bytes(&entry.path));
        if let Err(error) = tree::apply_metadata(&path, entry) {
            if entry.file_kind == lr_format::FILE_KIND_SPECIAL {
                warnings.push(format!(
                    "{}: {}",
                    String::from_utf8_lossy(&entry.path),
                    error
                ));
                continue;
            }
            return Err(error);
        }
    }

    Ok(FileRestoreReport {
        target: request.target.clone(),
        images: request.images.clone(),
        files: counts[0],
        directories: counts[1],
        symlinks: counts[2],
        hardlinks: counts[3],
        specials: counts[4],
        restored_bytes,
        warnings,
    })
}

/// Write `bytes` at `offset`, leaving the recorded sparse regions as holes.
///
/// The backup chunked the whole logical file (holes read as zeros), so the
/// content stream contains the hole bytes; seeking over them instead of writing
/// keeps the restored file sparse without needing a hole-aware chunker.
fn write_skipping_holes(
    file: &mut std::fs::File,
    offset: u64,
    bytes: &[u8],
    holes: &[(u64, u64)],
) -> Result<()> {
    use std::io::{Seek, SeekFrom};
    if holes.is_empty() || bytes.is_empty() {
        return file.write_all(bytes).map_err(Error::Io);
    }
    let end = offset + bytes.len() as u64;
    let mut position = offset;
    let mut index = 0usize;
    while position < end {
        // Advance to the first hole that can overlap the remaining bytes.
        while index < holes.len() && holes[index].0 + holes[index].1 <= position {
            index += 1;
        }
        match holes.get(index) {
            Some((hole_start, hole_len)) if *hole_start < end => {
                let hole_end = hole_start + hole_len;
                if position < *hole_start {
                    let write_end = (*hole_start).min(end);
                    let from = (position - offset) as usize;
                    let to = (write_end - offset) as usize;
                    file.write_all(&bytes[from..to]).map_err(Error::Io)?;
                    position = write_end;
                    continue;
                }
                // Inside the hole: seek past it without allocating.
                position = hole_end.min(end);
                file.seek(SeekFrom::Start(position)).map_err(Error::Io)?;
            }
            _ => {
                let from = (position - offset) as usize;
                file.write_all(&bytes[from..]).map_err(Error::Io)?;
                position = end;
            }
        }
    }
    Ok(())
}

fn prepare_target(target: &Path, merge: bool) -> Result<()> {
    match std::fs::metadata(target) {
        Ok(metadata) if !metadata.is_dir() => {
            return Err(Error::unsupported(format!(
                "{} is not a directory",
                target.display()
            )));
        }
        Ok(_) => {
            if !merge {
                let mut entries = std::fs::read_dir(target).map_err(Error::Io)?;
                if entries.next().is_some() {
                    return Err(Error::unsupported(format!(
                        "{} is not empty; pass --merge to restore into it anyway",
                        target.display()
                    )));
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(target).map_err(Error::Io)?;
        }
        Err(error) => return Err(Error::Io(error)),
    }
    Ok(())
}

/// Read one member's manifest records.
///
/// # Errors
/// Returns [`Error::Corrupt`] for a damaged manifest.
pub fn read_records(member: &mut crate::chain::OpenMember) -> Result<Vec<FileRecord>> {
    let bytes = member.stream_bytes(StreamId::Manifest)?;
    read_manifest(&bytes)
}

/// The consistency and source recorded in a file image's extras.
///
/// # Errors
/// Returns [`Error::Corrupt`] when the metadata record is missing.
pub fn read_file_metadata(
    member: &mut crate::chain::OpenMember,
) -> Result<HashMap<String, String>> {
    let extras = member.stream_bytes(StreamId::Extras)?;
    let mut cursor = Cursor::new(extras.as_slice());
    let mut metadata = HashMap::new();
    while (cursor.position() as usize) < extras.len() {
        let mut wire = lr_format::wire::Reader::new(&mut cursor);
        let (kind, payload) = read_extras_record(&mut wire)?;
        if kind == EXTRAS_IMAGE_METADATA {
            for line in String::from_utf8_lossy(&payload).lines() {
                if let Some((key, value)) = line.split_once('=') {
                    metadata.insert(key.to_owned(), value.to_owned());
                }
            }
        }
    }
    Ok(metadata)
}
