//! Metadata-page codec (spec §G.6).
//!
//! ```text
//! [ page_magic u16 = 0x9A6E ][ len u32 ][ nonce 12 ][ ciphertext ][ tag 16 ]
//! ```
//!
//! `len` is the ciphertext length; the tag always follows it. Pages are
//! encrypted with the image's `meta_key` and the associated data is
//! `stream_id u8 || page_no u64` (little-endian), so a page cannot be moved
//! between streams or renumbered.

use lr_core::{Error, Result};

use crate::aead::{AeadKind, TAG_LEN, open_in_place, seal_in_place};
use crate::nonce::{NONCE_LEN, NonceSeq};

/// Page magic, little-endian on disk.
pub const PAGE_MAGIC: u16 = 0x9A6E;

/// Fixed part of a page record before the ciphertext.
pub const PAGE_HEADER_LEN: usize = 2 + 4 + NONCE_LEN;

/// Total per-page overhead.
pub const PAGE_OVERHEAD: usize = PAGE_HEADER_LEN + TAG_LEN;

/// Largest accepted page payload, to bound allocations on corrupt input.
pub const MAX_PAGE_LEN: usize = 4 * 1024 * 1024;

/// Page streams (spec §G.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamId {
    /// Manifests (block, stream or file).
    Manifest = 1,
    /// Hash index used by stream and file images.
    HashIndex = 2,
    /// Extras: partition tables, `fstab`, Btrfs layout.
    Extras = 3,
    /// Overflow page table when it does not fit in the footer.
    PageTable = 4,
}

impl StreamId {
    /// On-disk discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parse an on-disk discriminant.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] for unknown stream ids; §G.8 forbids
    /// repurposing ids, so an unknown one means a newer writer.
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Manifest),
            2 => Ok(Self::HashIndex),
            3 => Ok(Self::Extras),
            4 => Ok(Self::PageTable),
            other => Err(Error::corrupt(format!("unknown page stream {other}"))),
        }
    }
}

fn page_ad(stream: StreamId, page_no: u64) -> [u8; 9] {
    let mut ad = [0u8; 9];
    ad[0] = stream.as_u8();
    ad[1..].copy_from_slice(&page_no.to_le_bytes());
    ad
}

/// Encode one page, appending it to `out`.
///
/// A fresh nonce is taken from `nonce_seq`; the caller must keep one sequence
/// per key.
///
/// # Errors
/// Returns [`Error::Unsupported`] when the payload exceeds [`MAX_PAGE_LEN`],
/// or propagates AEAD failures.
pub fn seal_page(
    kind: AeadKind,
    meta_key: &[u8; 32],
    stream: StreamId,
    page_no: u64,
    plaintext: &[u8],
    nonce_seq: &mut NonceSeq,
    out: &mut Vec<u8>,
) -> Result<()> {
    if plaintext.len() > MAX_PAGE_LEN {
        return Err(Error::unsupported(format!(
            "page payload {} exceeds {MAX_PAGE_LEN} bytes",
            plaintext.len()
        )));
    }
    let nonce = nonce_seq.next_nonce()?;
    let ad = page_ad(stream, page_no);
    let mut buf = plaintext.to_vec();
    let tag = seal_in_place(kind, meta_key, &nonce, &ad, &mut buf)?;

    out.reserve(PAGE_OVERHEAD + buf.len());
    out.extend_from_slice(&PAGE_MAGIC.to_le_bytes());
    out.extend_from_slice(&(buf.len() as u32).to_le_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&buf);
    out.extend_from_slice(&tag);
    Ok(())
}

/// Decode one page record and return its plaintext.
///
/// # Errors
/// Returns [`Error::Corrupt`] for a wrong magic, an implausible length, or a
/// record that is not exactly as long as its header claims, and
/// [`Error::Aead`] when authentication fails (wrong key, stream, page number,
/// or a modified byte).
pub fn open_page(
    kind: AeadKind,
    meta_key: &[u8; 32],
    stream: StreamId,
    page_no: u64,
    record: &[u8],
) -> Result<Vec<u8>> {
    if record.len() < PAGE_OVERHEAD {
        return Err(Error::corrupt("page record shorter than its overhead"));
    }
    let magic = u16::from_le_bytes([record[0], record[1]]);
    if magic != PAGE_MAGIC {
        return Err(Error::corrupt(format!(
            "page magic 0x{magic:04X} is not 0x{PAGE_MAGIC:04X}"
        )));
    }
    let len = u32::from_le_bytes([record[2], record[3], record[4], record[5]]) as usize;
    if len > MAX_PAGE_LEN {
        return Err(Error::corrupt(format!(
            "page length {len} exceeds {MAX_PAGE_LEN}"
        )));
    }
    if record.len() != PAGE_OVERHEAD + len {
        return Err(Error::corrupt(format!(
            "page record is {} bytes but declares {len} plus overhead",
            record.len()
        )));
    }
    let nonce: [u8; NONCE_LEN] = record[PAGE_HEADER_LEN - NONCE_LEN..PAGE_HEADER_LEN]
        .try_into()
        .map_err(|_| Error::corrupt("page nonce"))?;
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&record[PAGE_HEADER_LEN + len..]);
    let ad = page_ad(stream, page_no);
    let mut buf = record[PAGE_HEADER_LEN..PAGE_HEADER_LEN + len].to_vec();
    open_in_place(kind, meta_key, &nonce, &ad, &mut buf, &tag)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::{MAX_PAGE_LEN, StreamId, open_page, seal_page};
    use crate::aead::AeadKind;
    use crate::nonce::NonceSeq;

    const META_KEY: [u8; 32] = [0x5cu8; 32];

    #[test]
    fn stream_ids_round_trip() {
        for stream in [
            StreamId::Manifest,
            StreamId::HashIndex,
            StreamId::Extras,
            StreamId::PageTable,
        ] {
            assert_eq!(StreamId::from_u8(stream.as_u8()).expect("known"), stream);
        }
        assert!(StreamId::from_u8(9).is_err());
    }

    #[test]
    fn page_round_trip_for_both_ciphers() {
        for kind in [AeadKind::Aes256Gcm, AeadKind::ChaCha20Poly1305] {
            let mut seq = NonceSeq::new();
            let mut record = Vec::new();
            seal_page(
                kind,
                &META_KEY,
                StreamId::Manifest,
                0,
                b"manifest page",
                &mut seq,
                &mut record,
            )
            .expect("seal");
            let plaintext =
                open_page(kind, &META_KEY, StreamId::Manifest, 0, &record).expect("open");
            assert_eq!(plaintext, b"manifest page");
        }
    }

    #[test]
    fn moving_a_page_to_another_stream_or_number_fails() {
        let mut seq = NonceSeq::new();
        let mut record = Vec::new();
        seal_page(
            AeadKind::Aes256Gcm,
            &META_KEY,
            StreamId::Manifest,
            7,
            b"data",
            &mut seq,
            &mut record,
        )
        .expect("seal");
        assert!(
            open_page(
                AeadKind::Aes256Gcm,
                &META_KEY,
                StreamId::HashIndex,
                7,
                &record
            )
            .is_err()
        );
        assert!(
            open_page(
                AeadKind::Aes256Gcm,
                &META_KEY,
                StreamId::Manifest,
                8,
                &record
            )
            .is_err()
        );
    }

    #[test]
    fn corrupt_records_are_rejected() {
        let mut seq = NonceSeq::new();
        let mut record = Vec::new();
        seal_page(
            AeadKind::Aes256Gcm,
            &META_KEY,
            StreamId::Extras,
            0,
            b"extras",
            &mut seq,
            &mut record,
        )
        .expect("seal");

        let mut short = record.clone();
        short.truncate(3);
        assert!(open_page(AeadKind::Aes256Gcm, &META_KEY, StreamId::Extras, 0, &short).is_err());

        let mut bad_magic = record.clone();
        bad_magic[0] ^= 0xff;
        assert!(
            open_page(
                AeadKind::Aes256Gcm,
                &META_KEY,
                StreamId::Extras,
                0,
                &bad_magic
            )
            .is_err()
        );

        let mut bad_tag = record.clone();
        let last = bad_tag.len() - 1;
        bad_tag[last] ^= 0x01;
        assert!(
            open_page(
                AeadKind::Aes256Gcm,
                &META_KEY,
                StreamId::Extras,
                0,
                &bad_tag
            )
            .is_err()
        );

        let mut truncated_len = record.clone();
        truncated_len[2] = 0xfe;
        assert!(
            open_page(
                AeadKind::Aes256Gcm,
                &META_KEY,
                StreamId::Extras,
                0,
                &truncated_len
            )
            .is_err()
        );
    }

    #[test]
    fn oversized_pages_are_refused_on_write() {
        let mut seq = NonceSeq::new();
        let mut record = Vec::new();
        let oversized = vec![0u8; MAX_PAGE_LEN + 1];
        assert!(
            seal_page(
                AeadKind::Aes256Gcm,
                &META_KEY,
                StreamId::Manifest,
                0,
                &oversized,
                &mut seq,
                &mut record
            )
            .is_err()
        );
    }
}
