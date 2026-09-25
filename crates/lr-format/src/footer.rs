//! Footer codec and page table (spec §G.6, `docs/format-lrimg-v1.md` §4).

use lr_core::{Error, Result};
use lr_crypto::mac::{mac32, unkeyed_mac32, verify_mac32};
use lr_crypto::page::StreamId;

use crate::sb::SUPERBLOCK_COPY_LEN;

/// Size of the footer.
pub const FOOTER_SIZE: usize = 4096;

/// Footer magic (`"LRFOOT\x01"` plus one reserved zero byte).
pub const FOOTER_MAGIC: [u8; 8] = [0x4C, 0x52, 0x46, 0x4F, 0x4F, 0x54, 0x01, 0x00];

/// Superblock copy offset inside the footer.
pub const SUPERBLOCK_COPY_OFFSET: usize = 32;

/// Offset of the inline page table.
pub const PAGE_TABLE_OFFSET: usize = 1056;

/// Number of inline page-table slots.
pub const INLINE_PAGE_TABLE_SLOTS: usize = 120;

/// Size of one page-table slot.
pub const PAGE_ENTRY_SIZE: usize = 13;

/// Offset of `footer_hash`.
pub const FOOTER_HASH_OFFSET: usize = 2624;

/// Offset of `footer_mac`.
pub const FOOTER_MAC_OFFSET: usize = 2656;

/// Footer flag: the real page table is stored in stream 4.
pub const FLAG_PAGE_TABLE_IN_STREAM4: u32 = 1 << 0;

/// One metadata-page extent referenced by the footer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageEntry {
    /// Which page stream this page belongs to.
    pub stream: StreamId,
    /// Absolute file offset of the page record.
    pub offset: u64,
    /// Ciphertext length declared by the page record.
    pub len: u32,
}

/// The `.lrimg` footer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Footer {
    /// Number of chunk records in the file.
    pub total_chunks: u64,
    /// Offset where chunk records end and metadata pages begin.
    pub data_end_offset: u64,
    /// Page table; may be longer than [`INLINE_PAGE_TABLE_SLOTS`], in which
    /// case it is stored in stream 4.
    pub page_table: Vec<PageEntry>,
    /// Footer flags.
    pub flags: u32,
}

impl Footer {
    /// Encode the footer, computing `footer_hash` and `footer_mac`.
    ///
    /// `superblock_copy` is the first [`SUPERBLOCK_COPY_LEN`] bytes of the
    /// superblock.
    ///
    /// # Errors
    /// Returns [`Error::Unsupported`] when the page table does not fit inline
    /// and [`FLAG_PAGE_TABLE_IN_STREAM4`] is not set, and propagates I/O-free
    /// encoding errors.
    pub fn encode(
        &self,
        superblock_copy: &[u8],
        meta_key: Option<&[u8; 32]>,
    ) -> Result<[u8; FOOTER_SIZE]> {
        if superblock_copy.len() != SUPERBLOCK_COPY_LEN {
            return Err(Error::corrupt(format!(
                "superblock copy must be {SUPERBLOCK_COPY_LEN} bytes"
            )));
        }
        let inline = self.flags & FLAG_PAGE_TABLE_IN_STREAM4 == 0;
        if inline && self.page_table.len() > INLINE_PAGE_TABLE_SLOTS {
            return Err(Error::unsupported(format!(
                "page table has {} entries; {} slots fit inline",
                self.page_table.len(),
                INLINE_PAGE_TABLE_SLOTS
            )));
        }
        if !inline {
            if self.page_table.is_empty() {
                return Err(Error::corrupt(
                    "stream-4 page table flag with an empty table",
                ));
            }
            if self.page_table.len() > INLINE_PAGE_TABLE_SLOTS {
                return Err(Error::unsupported(
                    "stream-4 page table is itself too large to describe inline",
                ));
            }
        }

        let mut bytes = [0u8; FOOTER_SIZE];
        bytes[0..8].copy_from_slice(&FOOTER_MAGIC);
        bytes[8..16].copy_from_slice(&self.total_chunks.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.data_end_offset.to_le_bytes());
        bytes[24..26].copy_from_slice(&(self.page_table.len() as u16).to_le_bytes());
        bytes[26..28].copy_from_slice(&(INLINE_PAGE_TABLE_SLOTS as u16).to_le_bytes());
        bytes[28..32].copy_from_slice(&self.flags.to_le_bytes());
        bytes[SUPERBLOCK_COPY_OFFSET..SUPERBLOCK_COPY_OFFSET + SUPERBLOCK_COPY_LEN]
            .copy_from_slice(superblock_copy);
        for (index, entry) in self.page_table.iter().enumerate() {
            let at = PAGE_TABLE_OFFSET + index * PAGE_ENTRY_SIZE;
            bytes[at] = entry.stream.as_u8();
            bytes[at + 1..at + 9].copy_from_slice(&entry.offset.to_le_bytes());
            bytes[at + 9..at + 13].copy_from_slice(&entry.len.to_le_bytes());
        }

        let hash = unkeyed_mac32(&bytes[..FOOTER_HASH_OFFSET]);
        bytes[FOOTER_HASH_OFFSET..FOOTER_HASH_OFFSET + 32].copy_from_slice(&hash);
        let key = crate::sb::Superblock::authentication_key(meta_key);
        let mac = mac32(&key, &bytes[..FOOTER_MAC_OFFSET]);
        bytes[FOOTER_MAC_OFFSET..FOOTER_MAC_OFFSET + 32].copy_from_slice(&mac);
        Ok(bytes)
    }

    /// Decode a footer, verifying `footer_hash` and that `superblock_copy`
    /// matches the actual superblock prefix.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] for a bad magic, a bad hash, a page table
    /// that does not fit its declared count, or a superblock copy mismatch.
    pub fn decode(bytes: &[u8; FOOTER_SIZE], superblock_prefix: &[u8]) -> Result<Self> {
        if bytes[0..8] != FOOTER_MAGIC {
            return Err(Error::corrupt("footer magic does not match LRFOOT"));
        }
        let expected = unkeyed_mac32(&bytes[..FOOTER_HASH_OFFSET]);
        if bytes[FOOTER_HASH_OFFSET..FOOTER_HASH_OFFSET + 32] != expected {
            return Err(Error::corrupt("footer hash mismatch"));
        }
        if superblock_prefix.len() != SUPERBLOCK_COPY_LEN {
            return Err(Error::corrupt("superblock prefix has the wrong length"));
        }
        if bytes[SUPERBLOCK_COPY_OFFSET..SUPERBLOCK_COPY_OFFSET + SUPERBLOCK_COPY_LEN]
            != *superblock_prefix
        {
            return Err(Error::corrupt(
                "footer superblock copy does not match the superblock",
            ));
        }

        let count = usize::from(u16::from_le_bytes([bytes[24], bytes[25]]));
        let slots = usize::from(u16::from_le_bytes([bytes[26], bytes[27]]));
        if slots != INLINE_PAGE_TABLE_SLOTS {
            return Err(Error::corrupt(format!(
                "footer declares {slots} inline slots, expected {INLINE_PAGE_TABLE_SLOTS}"
            )));
        }
        if count > INLINE_PAGE_TABLE_SLOTS {
            return Err(Error::corrupt(format!(
                "footer declares {count} page-table entries, at most {INLINE_PAGE_TABLE_SLOTS} fit"
            )));
        }
        let flags = u32::from_le_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]);
        if flags & !FLAG_PAGE_TABLE_IN_STREAM4 != 0 {
            return Err(Error::corrupt(format!(
                "unknown footer flags 0x{flags:08X}"
            )));
        }

        let mut page_table = Vec::with_capacity(count);
        for index in 0..count {
            let at = PAGE_TABLE_OFFSET + index * PAGE_ENTRY_SIZE;
            page_table.push(PageEntry {
                stream: StreamId::from_u8(bytes[at])?,
                offset: u64::from_le_bytes(
                    bytes[at + 1..at + 9]
                        .try_into()
                        .map_err(|_| Error::corrupt("page table offset"))?,
                ),
                len: u32::from_le_bytes(
                    bytes[at + 9..at + 13]
                        .try_into()
                        .map_err(|_| Error::corrupt("page table length"))?,
                ),
            });
        }

        Ok(Self {
            total_chunks: u64::from_le_bytes(
                bytes[8..16]
                    .try_into()
                    .map_err(|_| Error::corrupt("total_chunks"))?,
            ),
            data_end_offset: u64::from_le_bytes(
                bytes[16..24]
                    .try_into()
                    .map_err(|_| Error::corrupt("data_end_offset"))?,
            ),
            page_table,
            flags,
        })
    }

    /// Verify `footer_mac`.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] when the MAC does not match.
    pub fn verify_mac(&self, bytes: &[u8; FOOTER_SIZE], meta_key: Option<&[u8; 32]>) -> Result<()> {
        let stored: [u8; 32] = bytes[FOOTER_MAC_OFFSET..FOOTER_MAC_OFFSET + 32]
            .try_into()
            .map_err(|_| Error::corrupt("footer_mac"))?;
        let key = crate::sb::Superblock::authentication_key(meta_key);
        if verify_mac32(&key, &bytes[..FOOTER_MAC_OFFSET], &stored) {
            Ok(())
        } else {
            Err(Error::corrupt("footer MAC mismatch"))
        }
    }

    /// `true` when the page table lives in stream 4.
    #[must_use]
    pub const fn page_table_in_stream4(&self) -> bool {
        self.flags & FLAG_PAGE_TABLE_IN_STREAM4 != 0
    }

    /// Total number of metadata pages, including the stream-4 table when used.
    #[must_use]
    pub fn page_count(&self) -> usize {
        self.page_table.len()
    }

    /// Entries of one stream, in file order.
    #[must_use]
    pub fn entries_for(&self, stream: StreamId) -> Vec<PageEntry> {
        self.page_table
            .iter()
            .copied()
            .filter(|entry| entry.stream == stream)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FLAG_PAGE_TABLE_IN_STREAM4, FOOTER_SIZE, Footer, INLINE_PAGE_TABLE_SLOTS, PageEntry,
    };
    use crate::sb::SUPERBLOCK_COPY_LEN;
    use lr_crypto::page::StreamId;

    fn prefix() -> Vec<u8> {
        (0..SUPERBLOCK_COPY_LEN).map(|i| (i % 251) as u8).collect()
    }

    fn sample() -> Footer {
        Footer {
            total_chunks: 12,
            data_end_offset: 4096 + 12 * 1024,
            flags: 0,
            page_table: vec![
                PageEntry {
                    stream: StreamId::Manifest,
                    offset: 20_000,
                    len: 1024,
                },
                PageEntry {
                    stream: StreamId::Extras,
                    offset: 21_024,
                    len: 64,
                },
            ],
        }
    }

    #[test]
    fn layout_matches_the_normative_offsets() {
        let bytes = sample()
            .encode(&prefix(), Some(&[0xAB; 32]))
            .expect("encode");
        assert_eq!(&bytes[0..8], &super::FOOTER_MAGIC);
        assert_eq!(&bytes[8..16], &12u64.to_le_bytes());
        assert_eq!(&bytes[24..26], &2u16.to_le_bytes(), "page table count");
        assert_eq!(&bytes[26..28], &120u16.to_le_bytes(), "slots");
        assert_eq!(&bytes[32..32 + SUPERBLOCK_COPY_LEN], &prefix()[..]);
        assert_eq!(bytes[1056], 1, "first entry is stream 1");
        assert_eq!(&bytes[1057..1065], &20_000u64.to_le_bytes());
        assert_eq!(&bytes[1065..1069], &1024u32.to_le_bytes());
        assert_ne!(&bytes[2624..2656], &[0u8; 32], "footer_hash");
        assert_ne!(&bytes[2656..2688], &[0u8; 32], "footer_mac");
        assert_eq!(&bytes[2688..], &vec![0u8; FOOTER_SIZE - 2688][..]);
    }

    #[test]
    fn round_trips() {
        let key = [0x11u8; 32];
        let bytes = sample().encode(&prefix(), Some(&key)).expect("encode");
        let decoded = Footer::decode(&bytes, &prefix()).expect("decode");
        assert_eq!(decoded, sample());
        decoded.verify_mac(&bytes, Some(&key)).expect("mac");
    }

    #[test]
    fn entries_for_filters_by_stream() {
        let footer = sample();
        assert_eq!(footer.entries_for(StreamId::Manifest).len(), 1);
        assert_eq!(footer.entries_for(StreamId::HashIndex).len(), 0);
    }

    #[test]
    fn bad_magic_and_hash_are_rejected() {
        let mut bytes = sample().encode(&prefix(), None).expect("encode");
        bytes[0] ^= 0xff;
        assert!(Footer::decode(&bytes, &prefix()).is_err());

        let mut bytes = sample().encode(&prefix(), None).expect("encode");
        bytes[16] ^= 0x01;
        assert!(Footer::decode(&bytes, &prefix()).is_err());
    }

    #[test]
    fn a_mismatched_superblock_copy_is_rejected() {
        let bytes = sample().encode(&prefix(), None).expect("encode");
        let mut other = prefix();
        other[0] ^= 0x01;
        assert!(Footer::decode(&bytes, &other).is_err());
    }

    #[test]
    fn tampering_with_a_mac_covered_field_is_caught() {
        let key = [0x11u8; 32];
        let mut bytes = sample().encode(&prefix(), Some(&key)).expect("encode");
        bytes[20] ^= 0x01; // data_end_offset
        let fixed = lr_crypto::mac::unkeyed_mac32(&bytes[..2624]);
        bytes[2624..2656].copy_from_slice(&fixed);
        let decoded = Footer::decode(&bytes, &prefix()).expect("hash is valid again");
        assert!(decoded.verify_mac(&bytes, Some(&key)).is_err());
    }

    #[test]
    fn too_many_entries_need_the_stream4_flag() {
        let mut footer = sample();
        footer.page_table = (0..=INLINE_PAGE_TABLE_SLOTS)
            .map(|i| PageEntry {
                stream: StreamId::Manifest,
                offset: i as u64,
                len: 16,
            })
            .collect();
        assert!(footer.encode(&prefix(), None).is_err());
        footer.flags |= FLAG_PAGE_TABLE_IN_STREAM4;
        // Still too large: the stream-4 table itself must fit inline.
        assert!(footer.encode(&prefix(), None).is_err());
        footer.page_table.truncate(INLINE_PAGE_TABLE_SLOTS);
        assert!(footer.encode(&prefix(), None).is_ok());
    }
}
