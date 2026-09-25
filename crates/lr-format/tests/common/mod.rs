//! Shared helpers for the `lr-format` integration tests.
//!
//! Each integration test is its own crate, so any helper this file offers may
//! be unused in some of them; that is expected, not dead code.
#![allow(dead_code, unreachable_pub)]

use std::io::Cursor;

use lr_core::{Consistency, Id, ImageId, ImageKind};
use lr_crypto::aead::AeadKind;
use lr_crypto::nonce::NonceSeq;
use lr_crypto::page::StreamId;
use lr_format::{
    BlockEntry, BlockManifestHeader, ChainMember, ImageWriter, Superblock, WriterKeys, flags,
    write_chain_members, write_extras_record,
};

/// Deterministic test keys.
pub const META_KEY: [u8; 32] = [0x44; 32];
/// Deterministic chunk key.
pub const DATA_KEY: [u8; 32] = [0x33; 32];
/// Deterministic content-hash key.
pub const DEDUP_KEY: [u8; 32] = [0x22; 32];

/// A chunk plaintext that compresses well.
#[must_use]
pub fn chunk_plaintext(index: u64, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| ((index as usize + i) % 251) as u8)
        .collect()
}

/// Everything a test needs to inspect the image it built.
pub struct TestImage {
    /// The whole file.
    pub bytes: Vec<u8>,
    /// The superblock used.
    pub superblock: Superblock,
    /// Manifest header written into stream 1.
    pub manifest: BlockManifestHeader,
    /// Manifest entries, in chunk order.
    pub entries: Vec<BlockEntry>,
    /// Plaintext of each chunk.
    pub chunks: Vec<Vec<u8>>,
}

/// Build a complete encrypted block image in memory.
///
/// `chunk_len` is the payload size of each chunk (kept small so tests are
/// fast); the recorded `chunk_size` is the smallest value the spec allows.
pub fn build_image(chunk_count: usize, chunk_len: usize, page_len: Option<usize>) -> TestImage {
    let chunk_size = lr_format::MIN_CHUNK_SIZE;
    let superblock = test_superblock(chunk_size, chunk_count as u64);
    let keys = WriterKeys {
        data_key: Some(DATA_KEY),
        meta_key: META_KEY,
        dedup_key: DEDUP_KEY,
    };
    let kind = AeadKind::Aes256Gcm;

    let cursor = Cursor::new(Vec::new());
    let mut writer =
        ImageWriter::create(cursor, &superblock, Some(&META_KEY)).expect("create image writer");

    let mut nonce_seq = NonceSeq::new();
    let mut chunks = Vec::with_capacity(chunk_count);
    let mut entries = Vec::with_capacity(chunk_count);
    for index in 0..chunk_count as u64 {
        let plaintext = chunk_plaintext(index, chunk_len);
        let reference = writer
            .append_chunk(
                lr_format::ChunkOptions {
                    kind,
                    level: 9,
                    compress: true,
                },
                &keys,
                ImageKind::Block,
                &mut nonce_seq,
                &plaintext,
            )
            .expect("append chunk");
        entries.push(
            BlockEntry::stored(0, reference.hash, reference.offset, reference.stored_len)
                .expect("stored entry"),
        );
        chunks.push(plaintext);
    }

    let manifest = BlockManifestHeader {
        chunk_size,
        chunk_count: chunk_count as u64,
        entry_count: chunk_count as u64,
        used_extent_count: 1,
        used_bytes: (chunk_count * chunk_len) as u64,
        fs_type: "ext4".to_owned(),
        fs_uuid: "11111111-2222-3333-4444-555555555555".to_owned(),
        label: "ROOT".to_owned(),
    };

    {
        let mut stream = match page_len {
            Some(page_len) => {
                writer.page_stream_with_page_len(StreamId::Manifest, kind, META_KEY, page_len)
            }
            None => writer.page_stream(StreamId::Manifest, kind, META_KEY),
        };
        manifest.write(&mut stream, false).expect("manifest header");
        for entry in &entries {
            entry.write(&mut stream).expect("manifest entry");
        }
        stream.finish().expect("finish manifest");
    }

    {
        let mut stream = writer.page_stream(StreamId::Extras, kind, META_KEY);
        write_chain_members(
            &mut stream,
            &[ChainMember {
                index: 0,
                image_uuid: superblock.image_uuid,
            }],
        )
        .expect("chain members");
        write_extras_record(
            &mut stream,
            lr_format::EXTRAS_FSTAB,
            b"/dev/sda1 / ext4 defaults 0 1\n",
        )
        .expect("fstab");
        stream.finish().expect("finish extras");
    }

    let (cursor, _footer) = writer
        .finish(&META_KEY, Some(&META_KEY), kind)
        .expect("finish image");
    TestImage {
        bytes: cursor.into_inner(),
        superblock,
        manifest,
        entries,
        chunks,
    }
}

/// A valid superblock for tests.
#[must_use]
pub fn test_superblock(chunk_size: u32, chunk_count: u64) -> Superblock {
    Superblock {
        format_major: lr_format::FORMAT_MAJOR,
        min_reader: lr_format::MIN_READER,
        flags: flags::ENCRYPTED,
        image_kind: ImageKind::Block,
        consistency: Consistency::Offline,
        image_uuid: ImageId::new(Id::from_bytes([0x01; 16])),
        chain_id: lr_core::ChainId::new(Id::from_bytes([0x02; 16])),
        set_id: lr_core::SetId::new(Id::from_bytes([0x03; 16])),
        parent_uuid: ImageId::ZERO,
        seq_in_chain: 0,
        created_unix: 1_800_000_000,
        source_size_bytes: u64::from(chunk_size) * chunk_count,
        logical_block_size: 512,
        chunk_size,
        kdf_id: 1,
        aead_id: AeadKind::Aes256Gcm.id(),
        kdf_salt: [0x04; 16],
        argon2_m_cost_kib: 256 * 1024,
        argon2_t_cost: 3,
        argon2_p_cost: 4,
        wrap_nonce: [0x05; 12],
        wrapped_chain_key: [0x06; 48],
    }
}

/// Build an image whose manifest stream is produced by a caller-supplied
/// closure, so tests can write delta or stream manifests.
pub fn build_custom_image(
    superblock: &Superblock,
    manifest: impl FnOnce(&mut lr_format::PageStream<'_>) -> lr_core::Result<()>,
) -> Vec<u8> {
    let kind = AeadKind::Aes256Gcm;
    let cursor = Cursor::new(Vec::new());
    let mut writer =
        ImageWriter::create(cursor, superblock, Some(&META_KEY)).expect("create image writer");
    {
        let mut stream = writer.page_stream(StreamId::Manifest, kind, META_KEY);
        manifest(&mut stream).expect("write manifest");
        stream.finish().expect("finish manifest");
    }
    {
        let mut stream = writer.page_stream(StreamId::Extras, kind, META_KEY);
        write_extras_record(
            &mut stream,
            lr_format::EXTRAS_FSTAB,
            b"/dev/sda1 / ext4 defaults\n",
        )
        .expect("fstab");
        stream.finish().expect("finish extras");
    }
    let (cursor, _footer) = writer
        .finish(&META_KEY, Some(&META_KEY), kind)
        .expect("finish image");
    cursor.into_inner()
}
