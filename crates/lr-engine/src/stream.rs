//! Btrfs Stream mode: `btrfs send` streams, chunked and deduplicated
//! (spec §E.1, §G, §K S8).
//!
//! A stream image does not hold filesystem blocks; it holds the bytes of one
//! `btrfs send` stream per mounted subvolume, cut into content-defined chunks
//! (spec §D: fastcdc v2020, 16 KiB / 64 KiB / 256 KiB, normalization level 1).
//! Because the boundaries follow the data, an unchanged region of a later
//! incremental send produces the same chunk hashes, and the per-image hash
//! index (stream 2) makes those repeats cheap to detect.
//!
//! Restore is the inverse: recreate the filesystem with the recorded UUID and
//! label, replay each image's subvolume sections through `btrfs receive` in
//! dependency order, then keep only the final subvolume of each path, rename
//! it to the original name and restore the default subvolume (spec §H.1).

use std::collections::BTreeMap;
use std::io::{Cursor, Read, Seek, Write};
use std::path::{Path, PathBuf};

use fastcdc::v2020::{Normalization, StreamCDC};
use lr_core::catalog::MemberKind;
use lr_core::{
    ChainId, Consistency, Error, Id, ImageId, ImageKind, Result, SetId, discovery::discover_source,
};
use lr_crypto::aead::AeadKind;
use lr_crypto::nonce::NonceSeq;
use lr_format::{
    BlockEntry, CdcParams, ChainMember, ChunkOptions, EXTRAS_BTRFS_LAYOUT, EXTRAS_FSTAB,
    EXTRAS_IMAGE_METADATA, FORMAT_MAJOR, ImageReader, ImageWriter, MIN_READER, StreamId,
    StreamSection, Superblock, WriterKeys, flags, open_chunk, wire, write_cdc_params,
    write_chain_members, write_extras_record,
};
use lr_snapshot::btrfs::{self, TreeSnapshotOpts};
use lr_store::Destination;

use crate::backup::{
    BackupRequest, MemberType, TempGuard, acquire_set_lock, now_unix, resolve_parent_chain,
};
use crate::keys::{self, Encryption};

/// Minimum stream chunk size (spec §D).
pub const CDC_MIN: u32 = 16 * 1024;
/// Target stream chunk size (spec §D).
pub const CDC_AVG: u32 = 64 * 1024;
/// Maximum stream chunk size (spec §D).
pub const CDC_MAX: u32 = 256 * 1024;

/// How many bytes of send stream one subvolume contributed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SubvolumeReport {
    /// Path relative to the top-level subvolume.
    pub subvol_path: String,
    /// Subvolume id.
    pub subvolid: u64,
    /// Bytes in the `btrfs send` stream.
    pub send_stream_bytes: u64,
    /// Chunks this subvolume contributed.
    pub chunks: u64,
    /// Chunks stored (after dedup).
    pub stored_chunks: u64,
    /// Parent snapshot UUID for an incremental send.
    pub parent_snapshot_uuid: Option<Id>,
}

/// What a stream backup produced.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StreamReport {
    /// Final image path inside the set.
    pub image_path: PathBuf,
    /// Image identifier.
    pub image_uuid: ImageId,
    /// Chain identifier.
    pub chain_id: ChainId,
    /// Consistency level achieved.
    pub consistency: Consistency,
    /// Filesystem UUID of the source.
    pub fs_uuid: String,
    /// Filesystem label.
    pub label: String,
    /// Default subvolume id of the source.
    pub default_subvolid: u64,
    /// One entry per subvolume.
    pub subvolumes: Vec<SubvolumeReport>,
    /// Total chunks in the image.
    pub total_chunks: u64,
    /// Chunks stored after deduplication.
    pub stored_chunks: u64,
    /// Chunks whose content repeated inside this image.
    pub deduplicated_chunks: u64,
    /// Total bytes of send streams.
    pub send_stream_bytes: u64,
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
}

/// One send stream to chunk, with the manifest metadata for it.
pub struct StreamInput<'a> {
    /// Path relative to the top-level subvolume.
    pub subvol_path: String,
    /// Subvolume id.
    pub subvolid: u64,
    /// Parent snapshot UUID for an incremental send.
    pub parent_snapshot_uuid: Option<Id>,
    /// The send stream.
    pub reader: Box<dyn Read + 'a>,
}

/// Result of chunking the send streams of one image.
struct ChunkedStreams {
    sections: Vec<(StreamSection, Vec<BlockEntry>)>,
    index: Vec<([u8; 32], BlockEntry)>,
    reports: Vec<SubvolumeReport>,
    total_chunks: u64,
    stored_chunks: u64,
    deduplicated_chunks: u64,
    send_stream_bytes: u64,
}

/// Cut every send stream into CDC chunks and append the stored ones.
///
/// Chunks whose content already appeared in this image reuse the stored copy;
/// the hash index records every distinct hash once, sorted, which is what a
/// later chain lookup binary-searches.
fn chunk_streams<W: Write + Seek>(
    writer: &mut ImageWriter<W>,
    writer_keys: &WriterKeys,
    options: ChunkOptions,
    nonce_seq: &mut NonceSeq,
    inputs: Vec<StreamInput<'_>>,
    reporter: &mut crate::progress::Reporter,
) -> Result<ChunkedStreams> {
    let mut sections = Vec::with_capacity(inputs.len());
    let mut index: Vec<([u8; 32], BlockEntry)> = Vec::new();
    let mut seen: BTreeMap<[u8; 32], BlockEntry> = BTreeMap::new();
    let mut reports = Vec::with_capacity(inputs.len());
    let mut total_chunks = 0u64;
    let mut stored_chunks = 0u64;
    let mut deduplicated_chunks = 0u64;
    let mut send_stream_bytes = 0u64;

    for input in inputs {
        let StreamInput {
            subvol_path,
            subvolid,
            parent_snapshot_uuid,
            reader,
        } = input;
        let mut entries = Vec::new();
        let mut section_bytes = 0u64;
        let mut section_stored = 0u64;
        let chunker = StreamCDC::with_level(
            reader,
            CDC_MIN as usize,
            CDC_AVG as usize,
            CDC_MAX as usize,
            Normalization::Level1,
        );
        for chunk in chunker {
            let chunk = chunk.map_err(|error| {
                Error::corrupt(format!("chunking a send stream failed: {error}"))
            })?;
            reporter.report(send_stream_bytes + section_bytes)?;
            total_chunks += 1;
            section_bytes += chunk.length as u64;
            let hash = lr_crypto::content_hash(&writer_keys.dedup_key, &chunk.data);
            let entry = match seen.get(&hash) {
                Some(existing) => {
                    deduplicated_chunks += 1;
                    *existing
                }
                None => {
                    let reference = writer.append_chunk(
                        options,
                        writer_keys,
                        ImageKind::Stream,
                        nonce_seq,
                        &chunk.data,
                    )?;
                    stored_chunks += 1;
                    section_stored += 1;
                    let entry = BlockEntry::stored(
                        0,
                        reference.hash,
                        reference.offset,
                        reference.stored_len,
                    )?;
                    seen.insert(hash, entry);
                    index.push((hash, entry));
                    entry
                }
            };
            entries.push(entry);
        }
        send_stream_bytes += section_bytes;
        reports.push(SubvolumeReport {
            subvol_path: subvol_path.clone(),
            subvolid,
            send_stream_bytes: section_bytes,
            chunks: entries.len() as u64,
            stored_chunks: section_stored,
            parent_snapshot_uuid,
        });
        sections.push((
            StreamSection {
                subvolid,
                send_stream_bytes: section_bytes,
                parent_snapshot_uuid,
                subvol_path,
                entry_count: entries.len() as u64,
            },
            entries,
        ));
    }

    index.sort_by_key(|(hash, _)| *hash);
    Ok(ChunkedStreams {
        sections,
        index,
        reports,
        total_chunks,
        stored_chunks,
        deduplicated_chunks,
        send_stream_bytes,
    })
}

/// Back up a Btrfs filesystem in Stream mode (spec §E.1, §K S8).
///
/// # Errors
/// Returns [`Error::Unsupported`] when the source is not a mounted Btrfs
/// filesystem, [`Error::StreamParentMissing`] when a required parent snapshot
/// is gone, and propagates snapshot, chunking, AEAD and format errors.
pub fn backup_stream(request: &BackupRequest) -> Result<StreamReport> {
    if request.member_type == MemberType::Differential {
        return Err(Error::unsupported(
            "btrfs Stream images are incremental or full; a differential would need the \
             chain's first snapshot, which is not kept",
        ));
    }
    let layout = discover_source(&request.source)?;

    // The catalog and the set lock come first so a refused parent never leaves
    // a snapshot behind.
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
    let member_kind = if parent.is_none() {
        MemberKind::Full
    } else {
        MemberKind::Incremental
    };

    let tree_opts = TreeSnapshotOpts {
        set_name: request.set_name.clone(),
        image_uuid: *request.image_uuid.inner(),
        // A `--type full` starts a new chain and must not reuse the previous
        // snapshot as a send parent.
        incremental: if request.member_type == MemberType::Full {
            btrfs::Incremental::Never
        } else {
            btrfs::Incremental::Auto
        },
        mount_root: PathBuf::from(btrfs::DEFAULT_MOUNT_ROOT),
        general: crate::backup::snapshot_opts(request),
    };
    request.context.phase("snapshot");
    let mut snapshot = btrfs::provider().create(&layout, &tree_opts)?;
    let mut reporter = request.context.clone().reporter(0)?;
    reporter.phase("stream");

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
    if matches!(request.compression, crate::backup::Compression::Zstd { .. }) {
        sb_flags |= flags::COMPRESSED;
    }
    if snapshot.consistency == Consistency::None {
        sb_flags |= flags::INCONSISTENT;
    }
    let all_full = snapshot
        .subvolumes
        .iter()
        .all(|subvol| subvol.parent_snapshot.is_none());
    let superblock = Superblock {
        format_major: FORMAT_MAJOR,
        min_reader: MIN_READER,
        flags: sb_flags,
        image_kind: ImageKind::Stream,
        consistency: snapshot.consistency,
        image_uuid: request.image_uuid,
        chain_id,
        set_id,
        parent_uuid,
        seq_in_chain,
        created_unix: now,
        source_size_bytes: layout.device_facts.size_bytes,
        logical_block_size: 512,
        // For Stream images the superblock's `chunk_size` is the *maximum* CDC
        // chunk size, which is the only value that is meaningful without
        // variable-length records; the exact parameters live in the
        // `CDC_PARAMS` extras record.
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
    let mode = if all_full { "full" } else { "incr" };
    let base_name = format!(
        "{seq_in_chain:03}-{}-{}.lrimg",
        request.member_type.file_tag(),
        request.image_uuid
    );
    let image_name = format!("{chain_dir}/{base_name}");
    // A stream image is built in the manifest page stream directly, so the
    // guard only needs a scratch path it can remove on failure.
    let spool_path = spool_dir.join(format!("{chain_dir}.{base_name}.stream.spool"));
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
    let options = ChunkOptions {
        kind: request.aead,
        level: match request.compression {
            crate::backup::Compression::None => 0,
            crate::backup::Compression::Zstd { level } => level,
        },
        compress: matches!(request.compression, crate::backup::Compression::Zstd { .. }),
    };

    let mut image_writer = ImageWriter::create(
        destination.create_tmp(&set, &image_name)?,
        &superblock,
        mac_key,
    )?;
    let mut nonce_seq = NonceSeq::new();

    // Phase A: chunk every send stream, keeping the send handles so a failure
    // inside `btrfs send` is reported instead of silently truncating a stream.
    let mut inputs = Vec::with_capacity(snapshot.subvolumes.len());
    let mut streams = Vec::with_capacity(snapshot.subvolumes.len());
    for subvol in &snapshot.subvolumes {
        let stream = snapshot.send(subvol)?;
        streams.push(stream.clone());
        inputs.push(StreamInput {
            subvol_path: subvol.subvol_path.clone(),
            subvolid: subvol.subvolid,
            parent_snapshot_uuid: subvol.parent_snapshot_uuid,
            reader: Box::new(stream),
        });
    }
    let chunked = chunk_streams(
        &mut image_writer,
        &writer_keys,
        options,
        &mut nonce_seq,
        inputs,
        &mut reporter,
    )?;
    for stream in streams {
        stream.finish()?;
    }

    // Phase B: the manifest stream, one section per subvolume.
    {
        let mut manifest = image_writer.page_stream(StreamId::Manifest, request.aead, meta_key);
        for (section, entries) in &chunked.sections {
            section.write(&mut manifest)?;
            for entry in entries {
                entry.write(&mut manifest)?;
            }
        }
        manifest.finish()?;
    }

    // Phase C: the hash index, sorted by hash (spec §G.6 stream 2).
    {
        let mut index = image_writer.page_stream(StreamId::HashIndex, request.aead, meta_key);
        for (_, entry) in &chunked.index {
            entry.write(&mut index)?;
        }
        index.finish()?;
    }

    // Phase D: extras — chain members, CDC parameters, Btrfs layout, fstab.
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
        let metadata = format!(
            "source={}\nconsistency={}\nfs_type=btrfs\nmode={mode}\n",
            request.source.display(),
            snapshot.consistency
        );
        write_extras_record(&mut extras, EXTRAS_IMAGE_METADATA, metadata.as_bytes())?;
        write_extras_record(
            &mut extras,
            EXTRAS_BTRFS_LAYOUT,
            stream_layout(&snapshot, &chunked.reports).as_bytes(),
        )?;
        if let Some(fstab) = read_fstab() {
            write_extras_record(&mut extras, EXTRAS_FSTAB, fstab.as_bytes())?;
        }
        extras.finish()?;
    }

    reporter.phase("finalize");
    reporter.finish(chunked.send_stream_bytes);
    let (mut writer, _footer) = image_writer.finish(&meta_key, mac_key, request.aead)?;
    writer.flush().map_err(Error::Io)?;
    let image_bytes = writer.seek(std::io::SeekFrom::End(0)).map_err(Error::Io)?;
    drop(writer);
    destination.finalize(&set, &image_name, &image_name)?;
    guard.disarm();

    // The image is durable, so the snapshots it streamed may now be recorded
    // as the set's parent and the older ones deleted (spec §E.1).
    snapshot.commit()?;

    // The catalog write still happens under the set lock (spec §D.3).
    {
        let mut loaded = crate::catalog::load(&*destination, &set, &request.set_name, now_unix())?;
        loaded.catalog.updated_unix = now_unix();
        crate::catalog::write_catalog(&*destination, &set, &loaded.catalog)?;
    }

    Ok(StreamReport {
        image_path: crate::backup::local_image_path(&set_root, &image_name),
        image_uuid: request.image_uuid,
        chain_id: request.chain_id,
        consistency: snapshot.consistency,
        fs_uuid: snapshot.fs_uuid.clone(),
        label: snapshot.label.clone(),
        default_subvolid: snapshot.default_subvolid,
        subvolumes: chunked.reports,
        total_chunks: chunked.total_chunks,
        stored_chunks: chunked.stored_chunks,
        deduplicated_chunks: chunked.deduplicated_chunks,
        send_stream_bytes: chunked.send_stream_bytes,
        image_bytes,
        encrypted: new_keys.encrypted,
        member_kind,
        seq_in_chain,
        parent_uuid,
    })
}

/// The Btrfs layout extras record (spec §G.6 extras kind 4).
///
/// Line-oriented, so a reader can ignore fields it does not know:
/// `fs_uuid=`, `label=`, `default_subvolid=`, `default_subvol_path=`,
/// `mount_options=`, then `subvol=<path>\t<subvolid>` per subvolume.
#[must_use]
pub fn stream_layout(
    snapshot: &lr_snapshot::TreeSnapshot,
    subvolumes: &[SubvolumeReport],
) -> String {
    let default_path = subvolumes
        .iter()
        .find(|subvol| subvol.subvolid == snapshot.default_subvolid)
        .map_or_else(|| "-".to_owned(), |subvol| subvol.subvol_path.clone());
    let mut text = String::new();
    text.push_str(&format!("fs_uuid={}\n", snapshot.fs_uuid));
    text.push_str(&format!("label={}\n", snapshot.label));
    text.push_str(&format!("default_subvolid={}\n", snapshot.default_subvolid));
    text.push_str(&format!("default_subvol_path={default_path}\n"));
    text.push_str(&format!("mount_options={}\n", snapshot.mount_options));
    for subvol in subvolumes {
        text.push_str(&format!(
            "subvol={}\t{}\n",
            subvol.subvol_path, subvol.subvolid
        ));
    }
    text
}

/// Parsed Btrfs layout extras.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StreamLayout {
    /// Filesystem UUID to recreate.
    pub fs_uuid: String,
    /// Filesystem label.
    pub label: String,
    /// Default subvolume id on the source.
    pub default_subvolid: u64,
    /// Path of the default subvolume, `-` when it is the top level.
    pub default_subvol_path: String,
    /// Mount options of the source.
    pub mount_options: String,
    /// `subvol_path` → subvolid.
    pub subvolumes: Vec<(String, u64)>,
}

/// Parse the Btrfs layout extras record.
///
/// # Errors
/// Returns [`Error::Corrupt`] when `fs_uuid` is missing.
pub fn parse_stream_layout(text: &str) -> Result<StreamLayout> {
    let mut layout = StreamLayout::default();
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("fs_uuid=") {
            layout.fs_uuid = value.to_owned();
        } else if let Some(value) = line.strip_prefix("label=") {
            layout.label = value.to_owned();
        } else if let Some(value) = line.strip_prefix("default_subvolid=") {
            layout.default_subvolid = value.parse().unwrap_or(0);
        } else if let Some(value) = line.strip_prefix("default_subvol_path=") {
            layout.default_subvol_path = value.to_owned();
        } else if let Some(value) = line.strip_prefix("mount_options=") {
            layout.mount_options = value.to_owned();
        } else if let Some(value) = line.strip_prefix("subvol=")
            && let Some((path, id)) = value.split_once('\t')
        {
            layout
                .subvolumes
                .push((path.to_owned(), id.parse().unwrap_or(0)));
        }
    }
    if layout.fs_uuid.is_empty() {
        return Err(Error::corrupt(
            "the Btrfs layout record has no filesystem UUID",
        ));
    }
    Ok(layout)
}

/// Read a whole metadata page stream into memory.
///
/// Manifest section lists and extras are bounded by the image's chunk count
/// (46 B per chunk) and are needed before the chunk pass starts; chunk records
/// themselves are still read one at a time.
fn read_page_stream<R: Read + Seek>(
    reader: &mut ImageReader<R>,
    stream: StreamId,
    meta_key: [u8; 32],
    kind: AeadKind,
) -> Result<Vec<u8>> {
    let mut sink = Vec::new();
    let mut buffer = vec![0u8; 64 * 1024];
    let mut page = reader.stream_reader(stream, meta_key, kind)?;
    loop {
        let read = page.read_bytes_partial(&mut buffer)?;
        if read == 0 {
            break;
        }
        sink.extend_from_slice(&buffer[..read]);
    }
    Ok(sink)
}

fn read_fstab() -> Option<String> {
    let path =
        std::env::var_os("LR_FSTAB").map_or_else(|| PathBuf::from("/etc/fstab"), PathBuf::from);
    std::fs::read_to_string(path).ok()
}

/// One subvolume section read back from an image.
#[derive(Debug, Clone)]
pub struct ImageSection {
    /// Section header.
    pub section: StreamSection,
    /// Chunk entries in stream order.
    pub entries: Vec<BlockEntry>,
}

/// Everything one image contributes to a stream restore.
#[derive(Debug, Clone)]
pub struct ImageContents {
    /// Set-relative image name.
    pub image: String,
    /// Image UUID.
    pub image_uuid: ImageId,
    /// Consistency recorded in the image.
    pub consistency: Consistency,
    /// Layout extras.
    pub layout: StreamLayout,
    /// Subvolume sections in manifest order.
    pub sections: Vec<ImageSection>,
}

/// Read a stream image's manifest and layout extras without touching chunks.
///
/// # Errors
/// Returns [`Error::Unsupported`] for a non-stream image, and propagates
/// authentication, decryption and parsing errors.
pub fn read_stream_image(
    destination: &dyn Destination,
    set: &lr_store::SetHandle,
    image: &str,
    encryption: &Encryption,
) -> Result<ImageContents> {
    let mut reader = ImageReader::open(destination.open_ro(set, image)?)?;
    let keys = keys::unlock_image(encryption, reader.superblock())?;
    let meta_key = reader
        .superblock()
        .is_encrypted()
        .then_some(&*keys.meta_key);
    reader.authenticate(meta_key)?;
    let superblock = reader.superblock().clone();
    if superblock.image_kind != ImageKind::Stream {
        return Err(Error::unsupported(format!(
            "this is a {:?} image, not a stream image",
            superblock.image_kind
        )));
    }
    let kind = superblock.aead_kind()?;

    // The manifest is small next to the chunk data (46 B per chunk), so the
    // whole section list is parsed up front; chunk records are streamed later.
    let manifest = read_page_stream(&mut reader, StreamId::Manifest, *keys.meta_key, kind)?;
    let mut cursor = Cursor::new(manifest.as_slice());
    let mut sections = Vec::new();
    while (cursor.position() as usize) < manifest.len() {
        let mut wire = wire::Reader::new(&mut cursor);
        let section = StreamSection::read(&mut wire)?;
        let mut entries = Vec::with_capacity(section.entry_count.min(1 << 20) as usize);
        for _ in 0..section.entry_count {
            entries.push(BlockEntry::read(&mut wire)?);
        }
        sections.push(ImageSection { section, entries });
    }

    let extras = read_page_stream(&mut reader, StreamId::Extras, *keys.meta_key, kind)?;
    let mut layout = None;
    let mut cursor = Cursor::new(extras.as_slice());
    while (cursor.position() as usize) < extras.len() {
        let mut wire = wire::Reader::new(&mut cursor);
        let (kind, payload) = lr_format::read_extras_record(&mut wire)?;
        if kind == EXTRAS_BTRFS_LAYOUT {
            layout = Some(parse_stream_layout(&String::from_utf8_lossy(&payload))?);
        }
    }
    let layout =
        layout.ok_or_else(|| Error::corrupt("the image carries no Btrfs layout record"))?;

    Ok(ImageContents {
        image: image.to_owned(),
        image_uuid: superblock.image_uuid,
        consistency: superblock.consistency,
        layout,
        sections,
    })
}

/// What `restore_stream` needs.
pub struct StreamRestoreRequest {
    /// Destination URI the images live on.
    pub dest: String,
    /// Set name inside the destination.
    pub set: String,
    /// Images in chain order; each one is applied on top of the previous.
    pub images: Vec<String>,
    /// How to reach the destination (paths, not secrets).
    pub destination_options: lr_store::DestinationOptions,
    /// Target device to format and receive into.
    pub target: PathBuf,
    /// How to unlock the images.
    pub encryption: Encryption,
    /// Private directory for the received filesystem's mount point.
    pub mount_root: PathBuf,
    /// Must be true; the write is refused otherwise.
    pub confirm: bool,
    /// Allow applying images flagged inconsistent.
    pub accept_inconsistent: bool,
    /// Live progress and cooperative cancellation (spec §I).
    pub context: crate::progress::EngineContext,
}

/// What a stream restore produced.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StreamRestoreReport {
    /// Target that was written.
    pub target: PathBuf,
    /// Images that were applied, in order (set-relative names).
    pub images: Vec<String>,
    /// Filesystem UUID that was recreated.
    pub fs_uuid: String,
    /// Filesystem label.
    pub label: String,
    /// Subvolume paths that were restored.
    pub subvolumes: Vec<String>,
    /// Default subvolume path that was set, when there was one.
    pub default_subvolume: Option<String>,
    /// Total send-stream bytes received.
    pub received_bytes: u64,
    /// Non-fatal notes.
    pub warnings: Vec<String>,
}

/// Recreate a Btrfs filesystem from one or more stream images (spec §H.1).
///
/// # Errors
/// Returns [`Error::Unsupported`] without `confirm`, [`Error::TargetBusy`] or
/// [`Error::NoSpace`]-style failures from `mkfs`, and propagates receive errors.
pub fn restore_stream(request: &StreamRestoreRequest) -> Result<StreamRestoreReport> {
    if !request.confirm {
        return Err(Error::unsupported(
            "restore apply requires --confirm; nothing has been written",
        ));
    }
    if request.images.is_empty() {
        return Err(Error::unsupported("no images to restore"));
    }
    let destination = lr_store::open(&request.dest, &request.destination_options)?;
    let set = destination.open_set(&lr_core::SetId::ZERO)?;
    let contents = request
        .images
        .iter()
        .map(|image| read_stream_image(&*destination, &set, image, &request.encryption))
        .collect::<Result<Vec<_>>>()?;
    if contents
        .iter()
        .any(|content| content.consistency == Consistency::None)
        && !request.accept_inconsistent
    {
        return Err(Error::unsupported(
            "an image is flagged inconsistent; pass --accept-inconsistent to restore it",
        ));
    }
    let total = contents
        .iter()
        .flat_map(|content| &content.sections)
        .map(|section| section.section.send_stream_bytes)
        .sum();
    let mut reporter = request.context.clone().reporter(total)?;
    reporter.phase("receive");
    let first = &contents[0];
    for content in &contents[1..] {
        if content.layout.fs_uuid != first.layout.fs_uuid {
            return Err(Error::corrupt(format!(
                "{} belongs to filesystem {}, expected {}",
                content.image, content.layout.fs_uuid, first.layout.fs_uuid
            )));
        }
    }

    // A fresh filesystem with the source's UUID and label.
    btrfs::create_filesystem(&request.target, &first.layout.fs_uuid, &first.layout.label)?;
    let mountpoint = request.mount_root.join(format!(
        "restore-{}",
        &first.layout.fs_uuid[..8.min(first.layout.fs_uuid.len())]
    ));
    std::fs::create_dir_all(&mountpoint).map_err(Error::Io)?;
    let mounted = MountGuard::mount(&request.target, &mountpoint)?;

    let mut warnings = Vec::new();
    if !first.layout.mount_options.is_empty() {
        warnings.push(format!(
            "the source mounted this filesystem with '{}'; keep its `subvol=` entries in /etc/fstab in mind on the restored system",
            first.layout.mount_options
        ));
    }

    // Receive every section in order; the last subvolume of each source path
    // is the final state.
    let mut created: BTreeMap<String, Vec<PathBuf>> = BTreeMap::new();
    let mut received_bytes = 0u64;
    for content in &contents {
        let reader = ImageReader::open(destination.open_ro(&set, &content.image)?)?;
        let keys = keys::unlock_image(&request.encryption, reader.superblock())?;
        let kind = reader.superblock().aead_kind()?;
        let mut chunks = reader.chunk_reader_with(destination.open_ro(&set, &content.image)?);
        for section in &content.sections {
            let parent = dirname_of(&section.section.subvol_path);
            let parent_dir = mounted.path().join(&parent);
            std::fs::create_dir_all(&parent_dir).map_err(Error::Io)?;
            let mut stream = ChunkStream {
                chunks: &mut chunks,
                entries: section.entries.clone(),
                index: 0,
                buffer: Vec::new(),
                offset: 0,
                kind,
                data_key: keys.data_key.as_deref(),
                dedup_key: &keys.dedup_key,
            };
            let name = btrfs::receive_top_level(&parent_dir, &mut stream)?;
            received_bytes += section.section.send_stream_bytes;
            reporter.report(received_bytes)?;
            created
                .entry(section.section.subvol_path.clone())
                .or_default()
                .push(parent_dir.join(&name));
        }
    }

    // Keep only the final subvolume of each path and give it its real name.
    let mut restored = Vec::new();
    for (subvol_path, paths) in &created {
        for stale in &paths[..paths.len() - 1] {
            let _ = std::process::Command::new("btrfs")
                .args(["subvolume", "delete"])
                .arg(stale)
                .output();
        }
        let Some(last) = paths.last() else {
            continue;
        };
        let final_path = mounted.path().join(subvol_path.trim_matches('/'));
        if last != &final_path {
            std::fs::create_dir_all(final_path.parent().unwrap_or(mounted.path()))
                .map_err(Error::Io)?;
            std::fs::rename(last, &final_path).map_err(Error::Io)?;
        }
        restored.push(subvol_path.clone());
    }

    // Recreate the source's default subvolume by path, because received
    // subvolumes get new ids.
    let mut default_subvolume = None;
    let default_path = first
        .layout
        .default_subvol_path
        .trim_matches('/')
        .to_owned();
    if !default_path.is_empty()
        && default_path != "-"
        && mounted.path().join(&default_path).exists()
        && let Some(id) = btrfs::subvolume_id(&mounted.path().join(&default_path))?
    {
        btrfs::set_default(mounted.path(), id)?;
        default_subvolume = Some(format!("/{default_path}"));
    }

    reporter.finish(received_bytes);
    drop(mounted);
    Ok(StreamRestoreReport {
        target: request.target.clone(),
        images: request.images.clone(),
        fs_uuid: first.layout.fs_uuid.clone(),
        label: first.layout.label.clone(),
        subvolumes: restored,
        default_subvolume,
        received_bytes,
        warnings,
    })
}

/// A chunk list presented as one byte stream, for `btrfs receive`.
struct ChunkStream<'a> {
    chunks: &'a mut lr_format::ChunkReader,
    entries: Vec<BlockEntry>,
    index: usize,
    buffer: Vec<u8>,
    offset: usize,
    kind: AeadKind,
    data_key: Option<&'a [u8; 32]>,
    dedup_key: &'a [u8; 32],
}

impl Read for ChunkStream<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        while self.offset >= self.buffer.len() {
            let Some(entry) = self.entries.get(self.index) else {
                return Ok(0);
            };
            self.index += 1;
            let record = self
                .chunks
                .read_record(entry.offset)
                .map_err(std::io::Error::other)?;
            let plaintext = open_chunk(
                self.kind,
                self.data_key,
                self.dedup_key,
                ImageKind::Stream,
                &entry.hash,
                CDC_MAX as usize,
                &record,
            )
            .map_err(std::io::Error::other)?;
            self.buffer = plaintext;
            self.offset = 0;
        }
        let available = &self.buffer[self.offset..];
        let take = available.len().min(buf.len());
        buf[..take].copy_from_slice(&available[..take]);
        self.offset += take;
        Ok(take)
    }
}

/// Mount a device privately and unmount it on drop.
struct MountGuard {
    mountpoint: PathBuf,
}

impl MountGuard {
    fn mount(device: &Path, mountpoint: &Path) -> Result<Self> {
        let status = std::process::Command::new("mount")
            .args(["-t", "btrfs", "-o", "subvolid=5"])
            .arg(device)
            .arg(mountpoint)
            .status()
            .map_err(Error::Io)?;
        if !status.success() {
            return Err(Error::unsupported(format!(
                "mounting the restored filesystem at {} failed",
                mountpoint.display()
            )));
        }
        Ok(Self {
            mountpoint: mountpoint.to_path_buf(),
        })
    }

    fn path(&self) -> &Path {
        &self.mountpoint
    }
}

impl Drop for MountGuard {
    fn drop(&mut self) {
        let _ = std::process::Command::new("umount")
            .arg(&self.mountpoint)
            .output();
        let _ = std::fs::remove_dir(&self.mountpoint);
    }
}

fn dirname_of(subvol_path: &str) -> String {
    let trimmed = subvol_path.trim_matches('/');
    match trimmed.rsplit_once('/') {
        Some((parent, _)) => parent.to_owned(),
        None => String::new(),
    }
}

/// The set identifier a stream request will use.
#[must_use]
pub fn set_id_of(request: &BackupRequest) -> SetId {
    request.set_id
}

#[cfg(test)]
mod tests {
    use super::{
        CDC_MAX, CDC_MIN, StreamInput, SubvolumeReport, chunk_streams, parse_stream_layout,
    };
    use lr_core::Id;
    use lr_crypto::aead::AeadKind;
    use lr_crypto::nonce::NonceSeq;
    use lr_format::{ChunkOptions, ImageWriter, Superblock, WriterKeys};
    use std::io::Cursor;

    fn writer_keys() -> WriterKeys {
        WriterKeys {
            data_key: None,
            meta_key: [0x11; 32],
            dedup_key: [0x22; 32],
        }
    }

    fn superblock() -> Superblock {
        Superblock {
            format_major: lr_format::FORMAT_MAJOR,
            min_reader: lr_format::MIN_READER,
            flags: 0,
            image_kind: lr_core::ImageKind::Stream,
            consistency: lr_core::Consistency::PointInTime,
            image_uuid: lr_core::ImageId::new(Id::from_bytes([9u8; 16])),
            chain_id: lr_core::ChainId::new(Id::from_bytes([8u8; 16])),
            set_id: lr_core::SetId::new(Id::from_bytes([7u8; 16])),
            parent_uuid: lr_core::ImageId::ZERO,
            seq_in_chain: 0,
            created_unix: 1,
            source_size_bytes: 1 << 20,
            logical_block_size: 512,
            chunk_size: CDC_MAX,
            kdf_id: 0,
            aead_id: lr_crypto::AEAD_ID_AES_256_GCM,
            kdf_salt: [0u8; 16],
            argon2_m_cost_kib: 0,
            argon2_t_cost: 0,
            argon2_p_cost: 0,
            wrap_nonce: [0u8; 12],
            wrapped_chain_key: [0u8; 48],
        }
    }

    fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed | 1;
        (0..len)
            .map(|_| {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                (state >> 33) as u8
            })
            .collect()
    }

    fn run(inputs: Vec<StreamInput<'_>>, path: &std::path::Path) -> super::ChunkedStreams {
        let file = std::fs::File::create(path).expect("create");
        let mut writer = ImageWriter::create(file, &superblock(), None).expect("image writer");
        let context = crate::progress::EngineContext::silent();
        let mut reporter = context.reporter(0).expect("reporter");
        chunk_streams(
            &mut writer,
            &writer_keys(),
            ChunkOptions {
                kind: AeadKind::Aes256Gcm,
                level: 0,
                compress: false,
            },
            &mut NonceSeq::new(),
            inputs,
            &mut reporter,
        )
        .expect("chunk")
    }

    #[test]
    fn chunking_is_deterministic_and_bounded() {
        let data = pseudo_random(600 * 1024, 42);
        let dir = tempfile::tempdir().expect("tempdir");
        let mut first = None;
        for _ in 0..2 {
            let outcome = run(
                vec![StreamInput {
                    subvol_path: "/@".to_owned(),
                    subvolid: 256,
                    parent_snapshot_uuid: None,
                    reader: Box::new(Cursor::new(data.clone())),
                }],
                &dir.path().join("one.lrimg"),
            );
            let lengths: Vec<u32> = outcome.sections[0]
                .1
                .iter()
                .map(|entry| entry.stored_len)
                .collect();
            assert_eq!(outcome.total_chunks, outcome.sections[0].1.len() as u64);
            assert!(outcome.sections[0].1.len() > 4, "several chunks expected");
            if let Some(previous) = &first {
                assert_eq!(*previous, lengths, "boundaries must be deterministic");
            }
            first = Some(lengths);
        }
        assert_eq!(CDC_MIN, 16 * 1024);
        assert_eq!(CDC_MAX, 256 * 1024);
    }

    #[test]
    fn identical_subvolumes_are_stored_once() {
        // Two subvolumes with the same bytes: the chunker runs from the start
        // of each one, so the second subvolume produces the same boundaries and
        // every one of its chunks reuses the stored copy.
        let data = pseudo_random(300 * 1024, 7);
        let dir = tempfile::tempdir().expect("tempdir");
        let outcome = run(
            vec![
                StreamInput {
                    subvol_path: "/@".to_owned(),
                    subvolid: 256,
                    parent_snapshot_uuid: None,
                    reader: Box::new(Cursor::new(data.clone())),
                },
                StreamInput {
                    subvol_path: "/@home".to_owned(),
                    subvolid: 257,
                    parent_snapshot_uuid: None,
                    reader: Box::new(Cursor::new(data)),
                },
            ],
            &dir.path().join("dedup.lrimg"),
        );
        let first = outcome.sections[0].1.len() as u64;
        assert!(first > 1, "several chunks expected");
        assert_eq!(outcome.deduplicated_chunks, first);
        assert_eq!(outcome.stored_chunks, first);
        assert_eq!(
            outcome.stored_chunks + outcome.deduplicated_chunks,
            outcome.total_chunks
        );
        assert_eq!(outcome.reports[1].stored_chunks, 0);
        // The hash index holds every distinct hash exactly once, sorted.
        let hashes: Vec<[u8; 32]> = outcome.index.iter().map(|(hash, _)| *hash).collect();
        assert_eq!(hashes.len() as u64, first);
        let mut sorted = hashes.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted, hashes);
    }

    #[test]
    fn two_subvolumes_share_one_index() {
        let dir = tempfile::tempdir().expect("tempdir");
        let outcome = run(
            vec![
                StreamInput {
                    subvol_path: "/@".to_owned(),
                    subvolid: 256,
                    parent_snapshot_uuid: None,
                    reader: Box::new(Cursor::new(vec![1u8; 200 * 1024])),
                },
                StreamInput {
                    subvol_path: "/@home".to_owned(),
                    subvolid: 257,
                    parent_snapshot_uuid: None,
                    reader: Box::new(Cursor::new(vec![2u8; 200 * 1024])),
                },
            ],
            &dir.path().join("two.lrimg"),
        );
        assert_eq!(outcome.sections.len(), 2);
        assert_eq!(outcome.reports.len(), 2);
        assert_eq!(outcome.reports[1].subvol_path, "/@home");
        assert!(
            outcome
                .reports
                .iter()
                .all(|report| report.send_stream_bytes > 0)
        );
    }

    #[test]
    fn the_layout_record_round_trips() {
        let text = "fs_uuid=abc\nlabel=L\ndefault_subvolid=256\ndefault_subvol_path=/@\nmount_options=rw,subvol=/@\nsubvol=/@\t256\nsubvol=/home/u1\t257\n";
        let layout = parse_stream_layout(text).expect("parse");
        assert_eq!(layout.fs_uuid, "abc");
        assert_eq!(layout.label, "L");
        assert_eq!(layout.default_subvolid, 256);
        assert_eq!(layout.default_subvol_path, "/@");
        assert_eq!(layout.subvolumes.len(), 2);
        assert!(parse_stream_layout("label=x").is_err());
    }

    #[test]
    fn subvolume_reports_serialize() {
        let report = SubvolumeReport {
            subvol_path: "/@".to_owned(),
            subvolid: 256,
            send_stream_bytes: 10,
            chunks: 2,
            stored_chunks: 2,
            parent_snapshot_uuid: None,
        };
        let json = serde_json::to_string(&report).expect("serialize");
        assert!(json.contains("\"subvol_path\":\"/@\""));
    }
}
