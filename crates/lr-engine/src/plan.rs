//! The validated restore plan (remediation plan block 2.3).
//!
//! What a restore would write is checked from the manifests before a token is
//! issued and before any target is touched, and `verify` uses the same checks,
//! so an image that verifies can be restored and one that cannot be restored
//! is refused up front.

use std::borrow::Borrow;

use lr_core::{Error, Result};
use lr_format::{ChunkState, Superblock};

/// The merged state of a block chain, counted without reading payloads.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BlockSummary {
    /// Chunks whose payload is stored in some member.
    pub stored: u64,
    /// Chunks recorded as zeros.
    pub zero: u64,
    /// Chunks the filesystem did not use.
    pub unused: u64,
    /// Chunks the source could not read (`--on-bad-sector record`).
    pub bad: u64,
    /// Byte offset of the first unreadable chunk.
    pub first_bad: Option<u64>,
}

/// Walk a block chain's merged manifest without reading payloads. The walk
/// validates the chain links, the geometry, every entry's range and the
/// complete consumption of every manifest.
///
/// # Errors
/// Returns [`Error::Corrupt`] for a malformed chain or manifest.
pub(crate) fn block_chain(
    members: Vec<crate::chain::OpenMember>,
    superblock: &Superblock,
) -> Result<BlockSummary> {
    let chunk_size = u64::from(superblock.chunk_size);
    let mut walk = crate::chain::ChainWalk::new(members)?;
    if walk.chunk_size() != superblock.chunk_size
        || walk.chunk_count() != superblock.source_size_bytes.div_ceil(chunk_size)
    {
        return Err(Error::corrupt(
            "the chain's chunk geometry does not match the image superblock",
        ));
    }
    let mut summary = BlockSummary::default();
    walk.walk(|index, state, _access| {
        match state {
            ChunkState::Stored { .. } => summary.stored += 1,
            ChunkState::Zero => summary.zero += 1,
            ChunkState::Unused => summary.unused += 1,
            ChunkState::BadSector => {
                summary.bad += 1;
                summary.first_bad.get_or_insert(index * chunk_size);
            }
        }
        Ok(())
    })?;
    Ok(summary)
}

/// Read a whole-disk image's manifest completely without reading payloads
/// (R24): the disk header must agree with the superblock and keep its
/// regions on the disk, every region manifest must be a full manifest with
/// exactly one valid entry per chunk, and nothing may follow the last one.
///
/// # Errors
/// Returns [`Error::Corrupt`] naming the first violation.
pub(crate) fn whole_disk<R: std::io::Read + std::io::Seek>(
    reader: &mut lr_format::ImageReader<R>,
    meta_key: &[u8; 32],
    superblock: &Superblock,
) -> Result<BlockSummary> {
    use lr_format::disk::DiskHeader;
    use lr_format::{BlockEntry, BlockManifestHeader, StreamId, wire};
    let chunk_size = u64::from(superblock.chunk_size);
    let lbs = u64::from(superblock.logical_block_size);
    let stream = reader.stream_reader(StreamId::Manifest, *meta_key, superblock.aead_kind()?)?;
    let mut wire = wire::Reader::new(stream);
    let disk = DiskHeader::read(&mut wire)?;
    disk.validate()?;
    disk.validate_geometry(superblock.source_size_bytes, superblock.logical_block_size)?;
    let mut summary = BlockSummary::default();
    for region in disk.regions.iter().filter(|region| region.has_manifest()) {
        let (header, delta) = BlockManifestHeader::read(&mut wire)?;
        if delta {
            return Err(Error::corrupt(format!(
                "region {} has a delta manifest; a whole-disk image carries full manifests",
                region.index
            )));
        }
        if u64::from(header.chunk_size) != chunk_size {
            return Err(Error::corrupt(format!(
                "region {} declares {}-byte chunks, the image {chunk_size}",
                region.index, header.chunk_size
            )));
        }
        let expected = region.chunk_count(chunk_size)?;
        if header.chunk_count != expected || header.entry_count != expected {
            return Err(Error::corrupt(format!(
                "region {} needs {expected} entries, its manifest declares {} chunks and {} \
                 entries",
                region.index, header.chunk_count, header.entry_count
            )));
        }
        let region_start = region.start_lba * lbs;
        for index in 0..expected {
            let entry = BlockEntry::read(&mut wire)?;
            match ChunkState::from(&entry) {
                ChunkState::Stored { .. } => summary.stored += 1,
                ChunkState::Zero => summary.zero += 1,
                ChunkState::Unused => summary.unused += 1,
                ChunkState::BadSector => {
                    summary.bad += 1;
                    summary
                        .first_bad
                        .get_or_insert(region_start + index * chunk_size);
                }
            }
        }
    }
    // Complete consumption: the last region manifest ends the stream.
    if wire.u8().is_ok() {
        return Err(Error::corrupt(
            "the whole-disk manifest continues after its last region",
        ));
    }
    Ok(summary)
}

/// The structural checks a file tree passes before it is restored or called
/// restorable (R25): plain paths below directories of the image (R06), hole
/// maps only on regular files, sorted, non-empty and inside the file, and a
/// file carrying every hard-link group a link names.
///
/// # Errors
/// Returns [`Error::Corrupt`] naming the first violation.
pub(crate) fn file_tree<K, V>(records: &std::collections::BTreeMap<K, V>) -> Result<()>
where
    K: Ord + Borrow<[u8]>,
    V: Borrow<lr_format::FileRecord>,
{
    crate::file::validate_tree_records(records)?;
    let name = |path: &[u8]| String::from_utf8_lossy(path).into_owned();
    let mut groups = std::collections::HashSet::new();
    for record in records.values() {
        let record: &lr_format::FileRecord = record.borrow();
        let entry = &record.entry;
        if !record.holes.is_empty() && entry.file_kind != lr_format::FILE_KIND_REGULAR {
            return Err(Error::corrupt(format!(
                "{} records holes but is not a regular file",
                name(&entry.path)
            )));
        }
        let mut end = 0u64;
        for &(offset, len) in &record.holes {
            let hole_end = offset.checked_add(len);
            if len == 0 || offset < end || hole_end.is_none_or(|hole_end| hole_end > entry.size) {
                return Err(Error::corrupt(format!(
                    "{} records the hole {offset}+{len}, which is empty, out of order or past \
                     its {}-byte size",
                    name(&entry.path),
                    entry.size
                )));
            }
            end = offset + len;
        }
        if entry.file_kind == lr_format::FILE_KIND_REGULAR && entry.hardlink_group != 0 {
            groups.insert(entry.hardlink_group);
        }
    }
    for record in records.values() {
        let record: &lr_format::FileRecord = record.borrow();
        let entry = &record.entry;
        if entry.file_kind == lr_format::FILE_KIND_HARDLINK
            && !groups.contains(&entry.hardlink_group)
        {
            return Err(Error::corrupt(format!(
                "{} is a hard link to group {}, which no file of the image carries",
                name(&entry.path),
                entry.hardlink_group
            )));
        }
    }
    Ok(())
}

/// Check one decoded chunk of a file at `position` against its recorded
/// holes: a hole must hold zeros, or the restore, which leaves holes
/// unwritten, would lose data (R25).
///
/// # Errors
/// Returns [`Error::Corrupt`] when a hole covers non-zero content.
pub(crate) fn holes_hold_zeros(
    path: &[u8],
    holes: &[(u64, u64)],
    position: u64,
    plaintext: &[u8],
) -> Result<()> {
    let end = position + plaintext.len() as u64;
    for &(offset, len) in holes {
        let from = offset.max(position);
        let to = (offset + len).min(end);
        if from >= to {
            continue;
        }
        let slice = &plaintext[(from - position) as usize..(to - position) as usize];
        if slice.iter().any(|byte| *byte != 0) {
            return Err(Error::corrupt(format!(
                "{} records a hole at {offset}+{len} over data",
                String::from_utf8_lossy(path)
            )));
        }
    }
    Ok(())
}

/// The message for an image that records unreadable source chunks (R26).
#[must_use]
pub fn bad_sector_message(bad: u64, first: Option<u64>) -> String {
    format!(
        "the image records {bad} chunk(s) its source could not read (bad sectors{}); those \
         regions were never backed up, so the image cannot be restored completely",
        first.map_or_else(String::new, |offset| format!(
            ", the first at byte {offset}"
        ))
    )
}

/// Refuse a restore of an image with recorded bad sectors, before any
/// target write (R26).
///
/// # Errors
/// Returns [`Error::Unsupported`] naming the count and the first offset.
pub(crate) fn refuse_bad_sectors(summary: &BlockSummary) -> Result<()> {
    if summary.bad == 0 {
        return Ok(());
    }
    Err(Error::unsupported(format!(
        "{}; it is refused before the target is touched",
        bad_sector_message(summary.bad, summary.first_bad)
    )))
}

#[cfg(test)]
mod tests {
    use crate::keys::Encryption;
    use crate::restore::{PrepareRequest, prepare_restore};
    use lr_core::{ChainId, Consistency, Id, ImageId, ImageKind, SetId};
    use lr_crypto::AeadKind;
    use lr_crypto::nonce::NonceSeq;
    use lr_format::disk::{DiskHeader, PtType, RegionKind, RegionRecord};
    use lr_format::{
        BlockEntry, BlockManifestHeader, ImageWriter, StreamId, Superblock, WriterKeys, flags,
    };

    const CHUNK: u32 = 256 * 1024;
    const DISK: u64 = 4 * 1024 * 1024;
    const REGION_START_LBA: u64 = 2048;
    const REGION_BYTES: u64 = 4 * CHUNK as u64;

    /// How a crafted whole-disk image departs from a well-formed one.
    #[derive(Clone, Copy, Default)]
    struct Flaw {
        /// Entries written beyond (or, negative, short of) the chunk count.
        extra_entries: i64,
        /// Mark the region manifest as a delta manifest.
        delta: bool,
        /// Logical block size the disk header claims, when not 512.
        header_lbs: Option<u32>,
        /// Let the region run past the end of the disk.
        past_the_end: bool,
    }

    fn whole_disk_superblock() -> Superblock {
        Superblock {
            format_major: lr_format::FORMAT_MAJOR,
            min_reader: lr_format::MIN_READER,
            flags: flags::WHOLE_DISK,
            image_kind: ImageKind::Block,
            consistency: Consistency::Offline,
            image_uuid: ImageId::new(Id::from_bytes([0xD1; 16])),
            chain_id: ChainId::new(Id::from_bytes([0xD2; 16])),
            set_id: SetId::new(Id::from_bytes([0xD3; 16])),
            parent_uuid: ImageId::ZERO,
            seq_in_chain: 0,
            created_unix: 10,
            source_size_bytes: DISK,
            logical_block_size: 512,
            chunk_size: CHUNK,
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

    fn write_whole_disk(path: &std::path::Path, flaw: Flaw) {
        let superblock = whole_disk_superblock();
        let derived = crate::keys::unlock_image(&Encryption::NoEncrypt, &superblock).expect("keys");
        let _keys = WriterKeys {
            data_key: None,
            meta_key: *derived.meta_key,
            dedup_key: *derived.dedup_key,
        };
        let file = std::fs::File::create(path).expect("create");
        let mut writer = ImageWriter::create(file, &superblock, None).expect("writer");
        let _nonce = NonceSeq::new();
        let header_lbs = flaw.header_lbs.unwrap_or(512);
        // The region starts 1 MiB into the disk in the header's own sectors.
        let start_lba = REGION_START_LBA * 512 / u64::from(header_lbs);
        let mut region = RegionRecord::new(RegionKind::PartitionRaw, 1, start_lba, REGION_BYTES);
        region.consistency = Consistency::Offline;
        let header = DiskHeader {
            disk_size: DISK,
            logical_block_size: header_lbs,
            pt_type: PtType::None,
            serial_wwid: String::new(),
            pt_raw: Vec::new(),
            regions: vec![region.clone()],
        };
        let chunk_count = region.chunk_count(u64::from(CHUNK)).expect("count");
        let entries =
            u64::try_from(i64::try_from(chunk_count).expect("count") + flaw.extra_entries)
                .expect("entries");
        {
            let mut manifest =
                writer.page_stream(StreamId::Manifest, AeadKind::Aes256Gcm, *derived.meta_key);
            // The writer refuses a region past the disk, so that one is
            // patched into the encoded header.
            let mut encoded = Vec::new();
            header.write(&mut encoded).expect("disk header");
            if flaw.past_the_end {
                let mut placed = start_lba.to_le_bytes().to_vec();
                placed.extend_from_slice(&REGION_BYTES.to_le_bytes());
                let at = encoded
                    .windows(placed.len())
                    .position(|window| window == placed)
                    .expect("region fields")
                    + 8;
                encoded[at..at + 8].copy_from_slice(&DISK.to_le_bytes());
            }
            lr_format::wire::put_bytes(&mut manifest, &encoded).expect("disk header");
            BlockManifestHeader {
                chunk_size: CHUNK,
                chunk_count,
                entry_count: entries,
                used_extent_count: 1,
                used_bytes: region.size_bytes,
                fs_type: String::new(),
                fs_uuid: String::new(),
                label: String::new(),
            }
            .write(&mut manifest, flaw.delta)
            .expect("region header");
            for index in 0..entries {
                if flaw.delta {
                    lr_format::DeltaEntry {
                        chunk_no: index,
                        entry: BlockEntry::zero(),
                    }
                    .write(&mut manifest)
                    .expect("delta entry");
                } else {
                    BlockEntry::zero().write(&mut manifest).expect("entry");
                }
            }
            manifest.finish().expect("finish manifest");
        }
        let (mut file, _footer) = writer
            .finish(&[0u8; 32], None, AeadKind::Aes256Gcm)
            .expect("finish");
        use std::io::Write;
        file.flush().expect("flush");
    }

    /// Prepare a restore of a crafted image onto a sentinel-filled file.
    fn prepare(flaw: Flaw) -> (lr_core::Result<crate::restore::RestorePlan>, bool) {
        let set = tempfile::Builder::new()
            .prefix("set")
            .tempdir()
            .expect("set");
        std::fs::create_dir(set.path().join("chain")).expect("chain");
        let image = set.path().join("chain/000-full.lrimg");
        write_whole_disk(&image, flaw);
        let targets = tempfile::tempdir().expect("targets");
        let target = targets.path().join("disk.img");
        let sentinel = vec![0x5Au8; DISK as usize];
        std::fs::write(&target, &sentinel).expect("target");
        let outcome = prepare_restore(&PrepareRequest::from_path(
            &image,
            &target,
            Encryption::NoEncrypt,
        ));
        let untouched = std::fs::read(&target).expect("target") == sentinel;
        (outcome, untouched)
    }

    /// Malformed whole-disk manifests are refused at `prepare`, before any
    /// token exists or the target is touched (R24).
    #[test]
    fn malformed_whole_disk_manifests_are_refused_before_writing() {
        let (outcome, untouched) = prepare(Flaw::default());
        outcome.expect("a well-formed image is accepted");
        assert!(untouched);
        for (what, flaw) in [
            (
                "a short full manifest",
                Flaw {
                    extra_entries: -1,
                    ..Flaw::default()
                },
            ),
            (
                "a long full manifest",
                Flaw {
                    extra_entries: 3,
                    ..Flaw::default()
                },
            ),
            (
                "a delta manifest",
                Flaw {
                    delta: true,
                    ..Flaw::default()
                },
            ),
            (
                "a conflicting sector size",
                Flaw {
                    header_lbs: Some(4096),
                    ..Flaw::default()
                },
            ),
            (
                "a region past the end of the disk",
                Flaw {
                    past_the_end: true,
                    ..Flaw::default()
                },
            ),
        ] {
            let (outcome, untouched) = prepare(flaw);
            assert!(outcome.is_err(), "{what} was accepted");
            assert!(untouched, "{what}: the target was written");
        }
    }

    // --- File images (R25) ---

    use lr_format::{ChainMember, ChunkOptions, FileEntry, FileRecord};

    fn file_entry(path: &str, kind: u8, size: u64, refs: Vec<[u8; 32]>, group: u32) -> FileEntry {
        FileEntry {
            file_kind: kind,
            mode: if kind == lr_format::FILE_KIND_DIRECTORY {
                0o040_755
            } else {
                0o100_644
            },
            uid: 0,
            gid: 0,
            mtime_sec: 1,
            mtime_nsec: 0,
            size,
            rdev: 0,
            hardlink_group: group,
            link_target: Vec::new(),
            path: path.as_bytes().to_vec(),
            xattrs: Vec::new(),
            acl: Vec::new(),
            chunk_refs_total: refs.len() as u64,
            chunk_refs_here: refs,
        }
    }

    /// A file image whose `data` file holds `chunks` and records `size` and
    /// `holes`; `extra` records are added as they are.
    fn write_file_image(
        path: &std::path::Path,
        chunks: &[&[u8]],
        size: u64,
        holes: Vec<(u64, u64)>,
        extra: Vec<FileRecord>,
    ) {
        let superblock = Superblock {
            image_kind: ImageKind::File,
            flags: 0,
            source_size_bytes: size,
            logical_block_size: 4096,
            chunk_size: crate::file::CDC_MAX,
            ..whole_disk_superblock()
        };
        let derived = crate::keys::unlock_image(&Encryption::NoEncrypt, &superblock).expect("keys");
        let keys = WriterKeys {
            data_key: None,
            meta_key: *derived.meta_key,
            dedup_key: *derived.dedup_key,
        };
        let file = std::fs::File::create(path).expect("create");
        let mut writer = ImageWriter::create(file, &superblock, None).expect("writer");
        let mut nonce = NonceSeq::new();
        let mut index = Vec::new();
        let mut refs = Vec::new();
        for chunk in chunks {
            let reference = writer
                .append_chunk(
                    ChunkOptions {
                        kind: AeadKind::Aes256Gcm,
                        level: 0,
                        compress: false,
                    },
                    &keys,
                    ImageKind::File,
                    &mut nonce,
                    chunk,
                )
                .expect("chunk");
            refs.push(reference.hash);
            index.push(
                BlockEntry::stored(0, reference.hash, reference.offset, reference.stored_len)
                    .expect("entry"),
            );
        }
        let mut records = vec![
            FileRecord {
                entry: file_entry("", lr_format::FILE_KIND_DIRECTORY, 0, Vec::new(), 0),
                holes: Vec::new(),
            },
            FileRecord {
                entry: file_entry("data", lr_format::FILE_KIND_REGULAR, size, refs, 0),
                holes,
            },
        ];
        records.extend(extra);
        {
            let mut manifest =
                writer.page_stream(StreamId::Manifest, AeadKind::Aes256Gcm, *derived.meta_key);
            for record in &records {
                lr_format::write_record(&mut manifest, record).expect("record");
            }
            manifest.finish().expect("manifest");
        }
        {
            let mut hash_index =
                writer.page_stream(StreamId::HashIndex, AeadKind::Aes256Gcm, *derived.meta_key);
            for entry in &index {
                entry.write(&mut hash_index).expect("index");
            }
            hash_index.finish().expect("index");
        }
        {
            let mut extras =
                writer.page_stream(StreamId::Extras, AeadKind::Aes256Gcm, *derived.meta_key);
            lr_format::write_chain_members(
                &mut extras,
                &[ChainMember {
                    index: 0,
                    image_uuid: superblock.image_uuid,
                }],
            )
            .expect("members");
            extras.finish().expect("extras");
        }
        let (mut file, _footer) = writer
            .finish(&[0u8; 32], None, AeadKind::Aes256Gcm)
            .expect("finish");
        use std::io::Write;
        file.flush().expect("flush");
    }

    fn verify_file_image(
        chunks: &[&[u8]],
        size: u64,
        holes: Vec<(u64, u64)>,
        extra: Vec<FileRecord>,
    ) -> lr_core::Result<crate::verify::VerifyReport> {
        let set = tempfile::Builder::new()
            .prefix("set")
            .tempdir()
            .expect("set");
        std::fs::create_dir(set.path().join("chain")).expect("chain");
        let image = set.path().join("chain/000-full.lrimg");
        write_file_image(&image, chunks, size, holes, extra);
        crate::verify::verify_image(&crate::verify::VerifyRequest {
            image: image.display().to_string(),
            encryption: Encryption::NoEncrypt,
            chain: true,
            destination_options: lr_store::DestinationOptions::default(),
            context: crate::progress::EngineContext::silent(),
        })
    }

    /// File images that are well framed but cannot be restored as recorded
    /// fail verification (R25).
    #[test]
    fn file_images_that_cannot_be_restored_fail_verification() {
        let data: &[u8] = &[0x11; 8192];
        let mut sparse = vec![0x22u8; 4096];
        sparse.extend_from_slice(&[0u8; 4096]);
        verify_file_image(&[data], 8192, Vec::new(), Vec::new()).expect("a sound image");
        verify_file_image(&[&sparse], 8192, vec![(4096, 4096)], Vec::new())
            .expect("a hole over zeros");
        let orphan = FileRecord {
            entry: file_entry("link", lr_format::FILE_KIND_HARDLINK, 8192, Vec::new(), 7),
            holes: Vec::new(),
        };
        for (what, outcome) in [
            (
                "a size its chunks do not hold",
                verify_file_image(&[data], 9000, Vec::new(), Vec::new()),
            ),
            (
                "a hole past the end",
                verify_file_image(&[data], 8192, vec![(8000, 4096)], Vec::new()),
            ),
            (
                "a hole over data",
                verify_file_image(&[data], 8192, vec![(0, 4096)], Vec::new()),
            ),
            (
                "a hard link to no file",
                verify_file_image(&[data], 8192, Vec::new(), vec![orphan]),
            ),
        ] {
            assert!(outcome.is_err(), "{what} verified: {outcome:?}");
        }
    }

    // --- Stream images (R25) ---

    /// A stream image with one stored chunk, with or without its Btrfs
    /// layout record.
    fn write_stream_image(path: &std::path::Path, with_layout: bool) {
        let superblock = Superblock {
            image_kind: ImageKind::Stream,
            flags: 0,
            source_size_bytes: 4096,
            logical_block_size: 4096,
            chunk_size: crate::file::CDC_MAX,
            ..whole_disk_superblock()
        };
        let derived = crate::keys::unlock_image(&Encryption::NoEncrypt, &superblock).expect("keys");
        let keys = WriterKeys {
            data_key: None,
            meta_key: *derived.meta_key,
            dedup_key: *derived.dedup_key,
        };
        let file = std::fs::File::create(path).expect("create");
        let mut writer = ImageWriter::create(file, &superblock, None).expect("writer");
        let mut nonce = NonceSeq::new();
        let reference = writer
            .append_chunk(
                ChunkOptions {
                    kind: AeadKind::Aes256Gcm,
                    level: 0,
                    compress: false,
                },
                &keys,
                ImageKind::Stream,
                &mut nonce,
                &[0x33; 4096],
            )
            .expect("chunk");
        {
            let mut manifest =
                writer.page_stream(StreamId::Manifest, AeadKind::Aes256Gcm, *derived.meta_key);
            lr_format::StreamSection {
                subvolid: 256,
                send_stream_bytes: 4096,
                parent_snapshot_uuid: None,
                subvol_path: "/@".to_owned(),
                entry_count: 1,
            }
            .write(&mut manifest)
            .expect("section");
            BlockEntry::stored(0, reference.hash, reference.offset, reference.stored_len)
                .expect("entry")
                .write(&mut manifest)
                .expect("entry");
            manifest.finish().expect("manifest");
        }
        {
            let mut extras =
                writer.page_stream(StreamId::Extras, AeadKind::Aes256Gcm, *derived.meta_key);
            lr_format::write_chain_members(
                &mut extras,
                &[ChainMember {
                    index: 0,
                    image_uuid: superblock.image_uuid,
                }],
            )
            .expect("members");
            if with_layout {
                lr_format::write_extras_record(
                    &mut extras,
                    lr_format::EXTRAS_BTRFS_LAYOUT,
                    b"fs_uuid=00000000-0000-0000-0000-000000000001\nlabel=\n\
                      default_subvolid=256\ndefault_subvol_path=/@\nmount_options=\n\
                      subvol=/@\t256\n",
                )
                .expect("layout");
            }
            extras.finish().expect("extras");
        }
        let (mut file, _footer) = writer
            .finish(&[0u8; 32], None, AeadKind::Aes256Gcm)
            .expect("finish");
        use std::io::Write;
        file.flush().expect("flush");
    }

    /// A stream image without the Btrfs layout record a restore needs fails
    /// verification instead of failing at restore time (R25).
    #[test]
    fn a_stream_image_without_its_layout_fails_verification() {
        for with_layout in [true, false] {
            let set = tempfile::Builder::new()
                .prefix("set")
                .tempdir()
                .expect("set");
            std::fs::create_dir(set.path().join("chain")).expect("chain");
            let image = set.path().join("chain/000-full.lrimg");
            write_stream_image(&image, with_layout);
            let outcome = crate::verify::verify_image(&crate::verify::VerifyRequest {
                image: image.display().to_string(),
                encryption: Encryption::NoEncrypt,
                chain: true,
                destination_options: lr_store::DestinationOptions::default(),
                context: crate::progress::EngineContext::silent(),
            });
            if with_layout {
                outcome.expect("a complete stream image verifies");
            } else {
                let error = outcome.expect_err("the layout is missing");
                assert!(error.to_string().contains("layout"), "{error}");
            }
        }
    }

    /// Payload corruption and cancellation both stop a public Stream restore
    /// before it reaches `mkfs.btrfs` or creates a mountpoint.
    #[test]
    fn stream_restore_preverifies_payload_before_formatting() {
        use std::io::{Read, Seek, SeekFrom, Write};

        let work = tempfile::tempdir().expect("work directory");
        let set = work.path().join("set");
        std::fs::create_dir_all(set.join("chain")).expect("chain directory");
        let image = set.join("chain/000-full.lrimg");
        write_stream_image(&image, true);

        let payload_offset = lr_format::SB_SIZE as u64 + lr_format::CHUNK_HEADER_LEN as u64;
        let mut image_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&image)
            .expect("open stream image");
        image_file
            .seek(SeekFrom::Start(payload_offset))
            .expect("seek payload");
        let mut original = [0u8; 1];
        image_file
            .read_exact(&mut original)
            .expect("read payload byte");
        image_file
            .seek(SeekFrom::Start(payload_offset))
            .expect("rewind payload");
        image_file
            .write_all(&[original[0] ^ 0xFF])
            .expect("corrupt payload");
        image_file.sync_all().expect("sync corruption");

        let target = work.path().join("target.img");
        let target_bytes = vec![0xA5; 4 * 1024 * 1024];
        std::fs::write(&target, &target_bytes).expect("create sentinel target");
        let mount_root = work.path().join("mount-root");
        let request = |context| crate::stream::StreamRestoreRequest {
            dest: work.path().to_string_lossy().into_owned(),
            set: "set".to_owned(),
            images: vec!["chain/000-full.lrimg".to_owned()],
            destination_options: lr_store::DestinationOptions::new("set"),
            target: target.clone(),
            encryption: Encryption::NoEncrypt,
            mount_root: mount_root.clone(),
            confirm: true,
            accept_inconsistent: false,
            context,
        };

        let error =
            crate::stream::restore_stream(&request(crate::progress::EngineContext::silent()))
                .expect_err("corrupt Stream payload must fail before formatting");
        let message = format!("{error}");
        assert!(
            matches!(&error, lr_core::Error::Corrupt { .. }),
            "expected payload corruption, got {message}"
        );
        assert!(
            message.contains("chunk") || message.contains("payload"),
            "expected a payload-specific error, got {message}"
        );
        assert_eq!(
            std::fs::read(&target).expect("sentinel remains"),
            target_bytes
        );
        assert!(
            !mount_root.exists(),
            "verification did not create a mountpoint"
        );

        let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let context = crate::progress::EngineContext {
            progress: Some(std::sync::Arc::new(CancelOnStreamContent(
                cancelled.clone(),
            ))),
            cancel: Some(cancelled),
        };
        let error = crate::stream::restore_stream(&request(context))
            .expect_err("cancellation during payload verification stops formatting");
        assert!(matches!(error, lr_core::Error::Cancelled), "{error}");
        assert_eq!(
            std::fs::read(&target).expect("sentinel remains after cancellation"),
            target_bytes
        );
        assert!(
            !mount_root.exists(),
            "cancellation did not create a mountpoint"
        );
    }

    struct CancelOnStreamContent(std::sync::Arc<std::sync::atomic::AtomicBool>);

    impl crate::progress::ProgressSink for CancelOnStreamContent {
        fn phase(&self, name: &str) {
            if name == "content" {
                self.0.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }

        fn bytes(&self, _done: u64, _total: u64) {}
    }
}
