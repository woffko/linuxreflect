//! The validated restore plan (remediation plan block 2.3).
//!
//! What a restore would write is checked from the manifests before a token is
//! issued and before any target is touched, and `verify` uses the same checks,
//! so an image that verifies can be restored and one that cannot be restored
//! is refused up front.

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
}
