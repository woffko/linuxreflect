//! Chunk record codec (spec §G.5, `docs/format-lrimg-v1.md` §2).
//!
//! ```text
//! [ magic u16 = 0xC4C7 ][ stored_len u32 ][ flags u8 ][ nonce 12 ]
//! [ payload ][ tag 16 (only when flags.bit1 is set) ]
//! ```
//!
//! The associated data binds the chunk to its manifest entry: it is
//! `keyed_BLAKE3(dedup_key, plaintext) ‖ image_kind`. The hash itself lives in
//! the manifest, so a reader can only decrypt a chunk whose manifest entry it
//! already trusts.

use lr_core::{Error, ImageKind, Result};
use lr_crypto::aead::{AeadKind, NONCE_LEN, TAG_LEN, open_in_place, seal_in_place};
use lr_crypto::hash::content_hash;
use lr_crypto::nonce::NonceSeq;

use crate::compress;
use crate::sb::MAX_CHUNK_SIZE;
use crate::wire;

/// Chunk record magic, little-endian on disk.
pub const CHUNK_MAGIC: u16 = 0xC4C7;

/// Payload is a zstd frame.
pub const CHUNK_FLAG_ZSTD: u8 = 0x01;

/// Payload is AEAD ciphertext with a trailing tag.
pub const CHUNK_FLAG_ENCRYPTED: u8 = 0x02;

/// Flags this version understands.
pub const CHUNK_FLAGS_KNOWN: u8 = CHUNK_FLAG_ZSTD | CHUNK_FLAG_ENCRYPTED;

/// Bytes before the payload.
pub const CHUNK_HEADER_LEN: usize = 2 + 4 + 1 + NONCE_LEN;

/// Bytes after the payload when the record is encrypted.
pub const CHUNK_TAG_LEN: usize = TAG_LEN;

/// Total overhead of an encrypted record.
pub const CHUNK_OVERHEAD_ENCRYPTED: usize = CHUNK_HEADER_LEN + CHUNK_TAG_LEN;

/// Total overhead of an unencrypted record.
pub const CHUNK_OVERHEAD_PLAIN: usize = CHUNK_HEADER_LEN;

/// Largest accepted `stored_len`, bounding allocations on corrupt input.
pub const MAX_STORED_LEN: usize = MAX_CHUNK_SIZE as usize + 64 * 1024;

/// A decoded chunk record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkRecord {
    /// Record flags, see [`CHUNK_FLAG_ZSTD`] and [`CHUNK_FLAG_ENCRYPTED`].
    pub flags: u8,
    /// Nonce used for this record.
    pub nonce: [u8; NONCE_LEN],
    /// Stored payload: ciphertext when encrypted, otherwise the (possibly
    /// compressed) plaintext.
    pub payload: Vec<u8>,
    /// Authentication tag, present exactly when the record is encrypted.
    pub tag: Option<[u8; TAG_LEN]>,
}

impl ChunkRecord {
    /// `true` when the payload is encrypted.
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        self.flags & CHUNK_FLAG_ENCRYPTED != 0
    }

    /// `true` when the payload is a zstd frame.
    #[must_use]
    pub const fn is_compressed(&self) -> bool {
        self.flags & CHUNK_FLAG_ZSTD != 0
    }

    /// Total on-disk length of this record.
    #[must_use]
    pub fn total_len(&self) -> usize {
        CHUNK_HEADER_LEN + self.payload.len() + usize::from(self.is_encrypted()) * CHUNK_TAG_LEN
    }
}

/// Encode a chunk record.
///
/// # Errors
/// Returns [`Error::Unsupported`] when the payload does not fit in a `u32`.
pub fn encode(record: &ChunkRecord) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(record.total_len());
    let mut header = Vec::with_capacity(CHUNK_HEADER_LEN);
    write_header(&mut header, record)?;
    out.extend_from_slice(&header);
    out.extend_from_slice(&record.payload);
    if let Some(tag) = record.tag {
        out.extend_from_slice(&tag);
    }
    Ok(out)
}

fn write_header(out: &mut Vec<u8>, record: &ChunkRecord) -> Result<()> {
    wire::put_u16(out, CHUNK_MAGIC)?;
    wire::put_u32(out, record.payload.len() as u32)?;
    wire::put_u8(out, record.flags)?;
    wire::put_bytes(out, &record.nonce)?;
    Ok(())
}

/// The fixed part of a chunk record, without reading the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkHeader {
    /// Record flags.
    pub flags: u8,
    /// Stored payload length.
    pub stored_len: u32,
    /// Nonce.
    pub nonce: [u8; NONCE_LEN],
}

impl ChunkHeader {
    /// `true` when a tag follows the payload.
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        self.flags & CHUNK_FLAG_ENCRYPTED != 0
    }

    /// Total on-disk length of the record this header describes.
    #[must_use]
    pub fn total_len(&self) -> usize {
        CHUNK_HEADER_LEN
            + self.stored_len as usize
            + usize::from(self.is_encrypted()) * CHUNK_TAG_LEN
    }
}

/// Decode only the fixed header of a chunk record.
///
/// This is what a structural scan uses, so verification never allocates a
/// payload buffer.
///
/// # Errors
/// Returns [`Error::Corrupt`] for a bad magic, unknown flags, or an
/// implausible `stored_len`.
pub fn decode_header(bytes: &[u8]) -> Result<ChunkHeader> {
    if bytes.len() < CHUNK_HEADER_LEN {
        return Err(Error::corrupt("chunk record shorter than its header"));
    }
    let magic = wire::slice_u16(bytes)?;
    if magic != CHUNK_MAGIC {
        return Err(Error::corrupt(format!(
            "chunk magic 0x{magic:04X} is not 0x{CHUNK_MAGIC:04X}"
        )));
    }
    let stored_len = wire::slice_u32(&bytes[2..])?;
    if stored_len as usize > MAX_STORED_LEN {
        return Err(Error::corrupt(format!(
            "chunk stored_len {stored_len} exceeds {MAX_STORED_LEN}"
        )));
    }
    let flags = bytes[6];
    if flags & !CHUNK_FLAGS_KNOWN != 0 {
        return Err(Error::corrupt(format!("unknown chunk flags 0x{flags:02X}")));
    }
    let nonce: [u8; NONCE_LEN] = bytes[7..7 + NONCE_LEN]
        .try_into()
        .map_err(|_| Error::corrupt("chunk nonce"))?;
    Ok(ChunkHeader {
        flags,
        stored_len,
        nonce,
    })
}

/// Decode one chunk record from the front of `bytes`.
///
/// # Errors
/// Returns [`Error::Corrupt`] for a malformed header or a record that is
/// longer than the available bytes.
pub fn decode(bytes: &[u8]) -> Result<ChunkRecord> {
    let header = decode_header(bytes)?;
    let stored_len = header.stored_len as usize;
    let total = header.total_len();
    if bytes.len() < total {
        return Err(Error::corrupt(format!(
            "chunk record declares {stored_len} bytes but only {} are available",
            bytes.len()
        )));
    }
    let payload = bytes[CHUNK_HEADER_LEN..CHUNK_HEADER_LEN + stored_len].to_vec();
    let tag = if header.is_encrypted() {
        Some(
            bytes[CHUNK_HEADER_LEN + stored_len..total]
                .try_into()
                .map_err(|_| Error::corrupt("chunk tag"))?,
        )
    } else {
        None
    };
    Ok(ChunkRecord {
        flags: header.flags,
        nonce: header.nonce,
        payload,
        tag,
    })
}

/// The associated data that binds a chunk to its manifest entry.
#[must_use]
pub fn chunk_ad(plaintext_hash: &[u8; 32], image_kind: ImageKind) -> [u8; 33] {
    let mut ad = [0u8; 33];
    ad[..32].copy_from_slice(plaintext_hash);
    ad[32] = image_kind.as_u8();
    ad
}

/// Per-chunk codec options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkOptions {
    /// AEAD algorithm from the superblock.
    pub kind: AeadKind,
    /// zstd level used when compression is enabled.
    pub level: i32,
    /// `--compress`: try zstd, keeping it only when it shrinks the chunk.
    pub compress: bool,
}

impl Default for ChunkOptions {
    fn default() -> Self {
        Self {
            kind: AeadKind::Aes256Gcm,
            level: crate::compress::DEFAULT_LEVEL,
            compress: true,
        }
    }
}

/// Compress, encrypt and frame one chunk.
///
/// Returns the record bytes and the keyed content hash that must be stored in
/// the manifest. Pass `key = None` for `--no-encrypt` images; the hash is
/// computed in both cases.
///
/// # Errors
/// Propagates compression and AEAD failures, and the nonce counter state.
pub fn seal_chunk(
    options: ChunkOptions,
    key: Option<&[u8; 32]>,
    dedup_key: &[u8; 32],
    image_kind: ImageKind,
    nonce_seq: &mut NonceSeq,
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 32])> {
    let ChunkOptions {
        kind,
        level,
        compress: compress_enabled,
    } = options;
    let hash = content_hash(dedup_key, plaintext);

    let (mut payload, compressed) = if compress_enabled {
        compress::compress_if_smaller(plaintext, level)?
    } else {
        (plaintext.to_vec(), false)
    };

    let mut flags = 0u8;
    if compressed {
        flags |= CHUNK_FLAG_ZSTD;
    }

    let (nonce, tag) = match key {
        Some(key) => {
            let nonce = nonce_seq.next_nonce()?;
            let ad = chunk_ad(&hash, image_kind);
            let tag = seal_in_place(kind, key, &nonce, &ad, &mut payload)?;
            flags |= CHUNK_FLAG_ENCRYPTED;
            (nonce, Some(tag))
        }
        None => ([0u8; NONCE_LEN], None),
    };

    let record = ChunkRecord {
        flags,
        nonce,
        payload,
        tag,
    };
    Ok((encode(&record)?, hash))
}

/// Decode, decrypt, decompress and verify one chunk.
///
/// `expected_hash` comes from the manifest; passing a wrong value makes
/// decryption fail rather than returning unauthenticated plaintext.
///
/// # Errors
/// Returns [`Error::Corrupt`] for a malformed record or a hash mismatch and
/// [`Error::Aead`] when authentication fails.
pub fn open_chunk(
    kind: AeadKind,
    key: Option<&[u8; 32]>,
    dedup_key: &[u8; 32],
    image_kind: ImageKind,
    expected_hash: &[u8; 32],
    max_plaintext: usize,
    bytes: &[u8],
) -> Result<Vec<u8>> {
    let record = decode(bytes)?;
    let mut payload = record.payload.clone();

    if record.is_encrypted() {
        let key = key.ok_or_else(|| Error::corrupt("encrypted chunk without a key"))?;
        let tag = record
            .tag
            .ok_or_else(|| Error::corrupt("encrypted chunk without a tag"))?;
        let ad = chunk_ad(expected_hash, image_kind);
        open_in_place(kind, key, &record.nonce, &ad, &mut payload, &tag)?;
    }

    let plaintext = if record.is_compressed() {
        compress::decompress(&payload, max_plaintext)?
    } else {
        payload
    };

    if plaintext.len() > max_plaintext {
        return Err(Error::corrupt(format!(
            "chunk plaintext is {} bytes, limit {max_plaintext}",
            plaintext.len()
        )));
    }
    let recomputed = content_hash(dedup_key, &plaintext);
    if &recomputed != expected_hash {
        return Err(Error::corrupt(
            "chunk content hash does not match the manifest",
        ));
    }
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::ChunkOptions;
    use super::{
        CHUNK_FLAG_ENCRYPTED, CHUNK_FLAG_ZSTD, CHUNK_HEADER_LEN, ChunkRecord, decode, encode,
        open_chunk, seal_chunk,
    };
    use lr_core::ImageKind;
    use lr_crypto::aead::AeadKind;
    use lr_crypto::hash::content_hash;
    use lr_crypto::nonce::NonceSeq;

    const DATA_KEY: [u8; 32] = [0x21; 32];
    const DEDUP_KEY: [u8; 32] = [0x22; 32];

    #[test]
    fn round_trips_encrypted_and_compressed() {
        let plaintext = vec![0x5au8; 4096];
        for kind in [AeadKind::Aes256Gcm, AeadKind::ChaCha20Poly1305] {
            let mut seq = NonceSeq::new();
            let (bytes, hash) = seal_chunk(
                ChunkOptions {
                    kind,
                    level: 9,
                    compress: true,
                },
                Some(&DATA_KEY),
                &DEDUP_KEY,
                ImageKind::Block,
                &mut seq,
                &plaintext,
            )
            .expect("seal");
            assert_eq!(hash, content_hash(&DEDUP_KEY, &plaintext));
            let record = decode(&bytes).expect("decode");
            assert!(record.is_encrypted() && record.is_compressed());
            assert_eq!(record.total_len(), bytes.len());
            assert!(
                record.payload.len() < plaintext.len(),
                "zstd must shrink this"
            );

            let opened = open_chunk(
                kind,
                Some(&DATA_KEY),
                &DEDUP_KEY,
                ImageKind::Block,
                &hash,
                plaintext.len(),
                &bytes,
            )
            .expect("open");
            assert_eq!(opened, plaintext);
        }
    }

    #[test]
    fn unencrypted_records_have_no_tag() {
        let plaintext = b"raw payload".to_vec();
        let mut seq = NonceSeq::new();
        let (bytes, hash) = seal_chunk(
            ChunkOptions {
                kind: AeadKind::Aes256Gcm,
                level: 9,
                compress: false,
            },
            None,
            &DEDUP_KEY,
            ImageKind::Block,
            &mut seq,
            &plaintext,
        )
        .expect("seal");
        let record = decode(&bytes).expect("decode");
        assert!(!record.is_encrypted());
        assert!(record.tag.is_none());
        assert_eq!(bytes.len(), CHUNK_HEADER_LEN + plaintext.len());
        assert_eq!(
            open_chunk(
                AeadKind::Aes256Gcm,
                None,
                &DEDUP_KEY,
                ImageKind::Block,
                &hash,
                plaintext.len(),
                &bytes
            )
            .expect("open"),
            plaintext
        );
    }

    #[test]
    fn a_wrong_manifest_hash_fails_authentication() {
        let plaintext = vec![7u8; 256];
        let mut seq = NonceSeq::new();
        let (bytes, _hash) = seal_chunk(
            ChunkOptions::default(),
            Some(&DATA_KEY),
            &DEDUP_KEY,
            ImageKind::Block,
            &mut seq,
            &plaintext,
        )
        .expect("seal");
        let wrong = [0xEEu8; 32];
        assert!(
            open_chunk(
                AeadKind::Aes256Gcm,
                Some(&DATA_KEY),
                &DEDUP_KEY,
                ImageKind::Block,
                &wrong,
                plaintext.len(),
                &bytes
            )
            .is_err()
        );
    }

    #[test]
    fn corrupt_records_are_rejected() {
        let mut record = ChunkRecord {
            flags: CHUNK_FLAG_ENCRYPTED,
            nonce: [0u8; 12],
            payload: vec![0u8; 8],
            tag: Some([0u8; 16]),
        };
        assert!(decode(&encode(&record).expect("encode")).is_ok());

        let encoded = encode(&record).expect("encode");
        let mut bad_magic = encoded.clone();
        bad_magic[0] ^= 0xff;
        assert!(decode(&bad_magic).is_err());

        let mut bad_flags = encoded.clone();
        bad_flags[6] = 0x80;
        assert!(decode(&bad_flags).is_err());

        let mut too_long = encoded[..CHUNK_HEADER_LEN].to_vec();
        too_long[2..6].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode(&too_long).is_err());

        let truncated = &encoded[..encoded.len() - 1];
        assert!(decode(truncated).is_err());

        record.flags = CHUNK_FLAG_ZSTD;
        record.tag = None;
        assert!(decode(&encode(&record).expect("encode")).is_ok());
    }
}
