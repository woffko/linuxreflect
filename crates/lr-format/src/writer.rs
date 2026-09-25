//! The image writer: superblock, chunk records, metadata pages and footer
//! (spec §G.1, `docs/format-lrimg-v1.md`).
//!
//! An `ImageWriter` owns the file until [`ImageWriter::finish`], which appends
//! the footer and returns the [`Footer`] that was written. Nothing is left
//! dangling: a file without a valid footer is never restorable, and a crash
//! simply leaves an unusable `.tmp` (spec §L.1).

use std::io::{Seek, SeekFrom, Write};

use lr_core::{ImageKind, Result};
use lr_crypto::aead::AeadKind;
use lr_crypto::nonce::NonceSeq;
use lr_crypto::page::{PAGE_OVERHEAD, StreamId};

use crate::chunk::{self, ChunkOptions};
use crate::footer::{
    FLAG_PAGE_TABLE_IN_STREAM4, FOOTER_SIZE, Footer, INLINE_PAGE_TABLE_SLOTS, PAGE_ENTRY_SIZE,
    PageEntry,
};
use crate::sb::{SB_SIZE, Superblock};
use crate::stream::{PageSink, PageStream};

/// Keys the writer needs. `data_key` is `None` for `--no-encrypt` images,
/// whose chunks are stored in the clear; pages are still authenticated because
/// the metadata path always uses `meta_key`.
#[derive(Clone)]
pub struct WriterKeys {
    /// Chunk payload key; `None` for unencrypted images.
    pub data_key: Option<[u8; 32]>,
    /// Metadata and header authentication key.
    pub meta_key: [u8; 32],
    /// Content-hash key.
    pub dedup_key: [u8; 32],
}

/// Where a chunk landed in the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkRef {
    /// Absolute offset of the chunk record.
    pub offset: u64,
    /// Stored payload length.
    pub stored_len: u32,
    /// Keyed content hash of the plaintext.
    pub hash: [u8; 32],
}

/// Writes one `.lrimg` file.
pub struct ImageWriter<W: Write + Seek> {
    writer: W,
    position: u64,
    superblock_bytes: [u8; SB_SIZE],
    page_table: Vec<PageEntry>,
    data_end_offset: Option<u64>,
    total_chunks: u64,
}

impl<W: Write + Seek> ImageWriter<W> {
    /// Write the superblock and prepare for chunk records.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] when the superblock fields are invalid, and
    /// propagates I/O errors.
    pub fn create(
        mut writer: W,
        superblock: &Superblock,
        meta_key: Option<&[u8; 32]>,
    ) -> Result<Self> {
        let superblock_bytes = superblock.encode(meta_key)?;
        writer.seek(SeekFrom::Start(0))?;
        writer.write_all(&superblock_bytes)?;
        Ok(Self {
            writer,
            position: SB_SIZE as u64,
            superblock_bytes,
            page_table: Vec::new(),
            data_end_offset: None,
            total_chunks: 0,
        })
    }

    /// Current write offset.
    #[must_use]
    pub const fn position(&self) -> u64 {
        self.position
    }

    /// Number of chunk records written.
    #[must_use]
    pub const fn total_chunks(&self) -> u64 {
        self.total_chunks
    }

    /// Offset where chunk records end; `None` until the first page is written.
    #[must_use]
    pub const fn data_end_offset(&self) -> Option<u64> {
        self.data_end_offset
    }

    /// Append an already-sealed chunk record.
    ///
    /// Returns `(offset, total_record_len)`.
    ///
    /// # Errors
    /// Propagates I/O errors.
    pub fn append_record(&mut self, record: &[u8]) -> Result<(u64, u32)> {
        let offset = self.position;
        let total_len = u32::try_from(record.len())
            .map_err(|_| lr_core::Error::unsupported("chunk record larger than 4 GiB"))?;
        self.writer.write_all(record)?;
        self.position += record.len() as u64;
        self.total_chunks += 1;
        Ok((offset, total_len))
    }

    /// Seal a chunk and append it.
    ///
    /// # Errors
    /// Propagates compression, AEAD, nonce and I/O errors.
    pub fn append_chunk(
        &mut self,
        options: ChunkOptions,
        keys: &WriterKeys,
        image_kind: ImageKind,
        nonce_seq: &mut NonceSeq,
        plaintext: &[u8],
    ) -> Result<ChunkRef> {
        let (record, hash) = chunk::seal_chunk(
            options,
            keys.data_key.as_ref(),
            &keys.dedup_key,
            image_kind,
            nonce_seq,
            plaintext,
        )?;
        let header = chunk::decode_header(&record)?;
        let stored_len = header.stored_len;
        let (offset, _total) = self.append_record(&record)?;
        Ok(ChunkRef {
            offset,
            stored_len,
            hash,
        })
    }

    /// Begin a metadata page stream.
    pub fn page_stream<'a>(
        &'a mut self,
        stream: StreamId,
        kind: AeadKind,
        meta_key: [u8; 32],
    ) -> PageStream<'a> {
        PageStream::new(self, stream, kind, meta_key)
    }

    /// Begin a metadata page stream with an explicit page payload size.
    ///
    /// Smaller pages are useful for tests and for images whose metadata is
    /// tiny; production images use [`crate::stream::DEFAULT_PAGE_LEN`].
    pub fn page_stream_with_page_len<'a>(
        &'a mut self,
        stream: StreamId,
        kind: AeadKind,
        meta_key: [u8; 32],
        page_len: usize,
    ) -> PageStream<'a> {
        PageStream::with_page_len(self, stream, kind, meta_key, page_len)
    }

    /// Append the page table (if it overflowed) and the footer.
    ///
    /// Metadata pages are always keyed, even in an unencrypted image (the key
    /// is derived from the chain key either way), while the footer MAC is keyed
    /// only for encrypted images — the two therefore take different keys. A
    /// first version passed only the MAC key to both, so an unencrypted image
    /// with more than [`INLINE_PAGE_TABLE_SLOTS`] pages could not be written at
    /// all (found by the 16 TB scaling test, D-096).
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] when no metadata page was ever written, and
    /// propagates AEAD and I/O errors.
    pub fn finish(
        mut self,
        page_key: &[u8; 32],
        mac_key: Option<&[u8; 32]>,
        kind: AeadKind,
    ) -> Result<(W, Footer)> {
        let data_end_offset = self
            .data_end_offset
            .ok_or_else(|| lr_core::Error::corrupt("image has no metadata pages"))?;

        let mut flags = 0u32;
        if self.page_table.len() > INLINE_PAGE_TABLE_SLOTS {
            let serialized = serialize_table(&self.page_table);
            let before = self.page_table.len();
            {
                let mut stream = PageStream::new(&mut self, StreamId::PageTable, kind, *page_key);
                stream.write(&serialized)?;
                stream.finish()?;
            }
            self.page_table = self.page_table.split_off(before);
            flags |= FLAG_PAGE_TABLE_IN_STREAM4;
        }

        let footer = Footer {
            total_chunks: self.total_chunks,
            data_end_offset,
            page_table: self.page_table.clone(),
            flags,
        };
        let superblock_copy = &self.superblock_bytes[..crate::sb::SUPERBLOCK_COPY_LEN];
        let footer_bytes = footer.encode(superblock_copy, mac_key)?;
        self.writer.seek(SeekFrom::Start(self.position))?;
        self.writer.write_all(&footer_bytes)?;
        self.writer.flush()?;
        Ok((self.writer, footer))
    }

    /// Give back the underlying writer without writing a footer.
    #[must_use]
    pub fn into_inner(self) -> W {
        self.writer
    }
}

impl<W: Write + Seek> PageSink for ImageWriter<W> {
    fn write_page(&mut self, stream: StreamId, _page_no: u64, page: &[u8]) -> Result<()> {
        if self.data_end_offset.is_none() {
            self.data_end_offset = Some(self.position);
        }
        let len = page.len().saturating_sub(PAGE_OVERHEAD);
        self.page_table.push(PageEntry {
            stream,
            offset: self.position,
            len: u32::try_from(len).map_err(|_| lr_core::Error::unsupported("page too large"))?,
        });
        self.writer.write_all(page)?;
        self.position += page.len() as u64;
        Ok(())
    }
}

/// Serialize a page table exactly as it appears in the footer or stream 4.
#[must_use]
pub fn serialize_table(table: &[PageEntry]) -> Vec<u8> {
    let mut out = Vec::with_capacity(table.len() * PAGE_ENTRY_SIZE);
    for entry in table {
        out.push(entry.stream.as_u8());
        out.extend_from_slice(&entry.offset.to_le_bytes());
        out.extend_from_slice(&entry.len.to_le_bytes());
    }
    out
}

/// Parse a serialized page table.
///
/// # Errors
/// Returns [`Error::Corrupt`] when the length is not a multiple of
/// [`PAGE_ENTRY_SIZE`] or a stream id is unknown.
pub fn parse_table(bytes: &[u8]) -> Result<Vec<PageEntry>> {
    if !bytes.len().is_multiple_of(PAGE_ENTRY_SIZE) {
        return Err(lr_core::Error::corrupt(format!(
            "page table length {} is not a multiple of {PAGE_ENTRY_SIZE}",
            bytes.len()
        )));
    }
    let mut table = Vec::with_capacity(bytes.len() / PAGE_ENTRY_SIZE);
    for entry in bytes.chunks_exact(PAGE_ENTRY_SIZE) {
        table.push(PageEntry {
            stream: StreamId::from_u8(entry[0])?,
            offset: u64::from_le_bytes(
                entry[1..9]
                    .try_into()
                    .map_err(|_| lr_core::Error::corrupt("entry offset"))?,
            ),
            len: u32::from_le_bytes(
                entry[9..13]
                    .try_into()
                    .map_err(|_| lr_core::Error::corrupt("entry len"))?,
            ),
        });
    }
    Ok(table)
}

/// The footer size, re-exported for callers that size buffers.
pub const FOOTER_BYTES: usize = FOOTER_SIZE;

#[cfg(test)]
mod tests {
    use super::{WriterKeys, parse_table, serialize_table};
    use crate::footer::PageEntry;
    use lr_crypto::page::StreamId;

    #[test]
    fn page_table_serialization_round_trips() {
        let table = vec![
            PageEntry {
                stream: StreamId::Manifest,
                offset: 4096,
                len: 1024,
            },
            PageEntry {
                stream: StreamId::HashIndex,
                offset: 5120,
                len: 2048,
            },
            PageEntry {
                stream: StreamId::PageTable,
                offset: 7168,
                len: 13,
            },
        ];
        let bytes = serialize_table(&table);
        assert_eq!(bytes.len(), table.len() * 13);
        assert_eq!(parse_table(&bytes).expect("parse"), table);
    }

    #[test]
    fn a_misaligned_page_table_is_rejected() {
        assert!(parse_table(&[1, 2, 3]).is_err());
    }

    #[test]
    fn writer_keys_can_be_cloned_for_two_streams() {
        let keys = WriterKeys {
            data_key: Some([1u8; 32]),
            meta_key: [2u8; 32],
            dedup_key: [3u8; 32],
        };
        let copy = keys.clone();
        assert_eq!(copy.meta_key, keys.meta_key);
    }
}
