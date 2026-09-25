//! The image reader: structural validation, key-based authentication and page
//! stream access (spec §G.6, §G.8, `docs/format-lrimg-v1.md`).
//!
//! [`ImageReader::open`] performs only checks that need no key: magic numbers,
//! the unkeyed `sb_hash`/`footer_hash`, field ranges, and every offset and
//! length against the real file size. [`ImageReader::authenticate`] then
//! verifies `sb_mac`/`footer_mac` before any flag or offset may be trusted.

use std::io::{Read, Seek, SeekFrom};

use lr_core::{Error, Result};
use lr_crypto::aead::AeadKind;
use lr_crypto::page::{PAGE_OVERHEAD, StreamId};

use crate::chunk::{CHUNK_OVERHEAD_PLAIN, decode_header};
use crate::footer::FOOTER_SIZE;
use crate::sb::SB_SIZE;
use crate::stream::PageStreamReader;
use crate::writer::parse_table;

/// Upper bound on a page table, so a hostile footer cannot request a huge
/// allocation: 8 MiB covers roughly 645 000 pages, far beyond any real image.
pub const MAX_PAGE_TABLE_BYTES: usize = 8 * 1024 * 1024;

/// Reads one `.lrimg` file.
pub struct ImageReader<R: Read + Seek> {
    reader: R,
    file_len: u64,
    superblock_bytes: [u8; SB_SIZE],
    superblock: crate::sb::Superblock,
    footer_bytes: [u8; FOOTER_SIZE],
    footer: crate::footer::Footer,
}

impl<R: Read + Seek> ImageReader<R> {
    /// Open an image and run every key-independent check.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] for a missing/short file, a bad magic, a bad
    /// unkeyed hash, an out-of-range field, or metadata that points outside
    /// the file.
    pub fn open(mut reader: R) -> Result<Self> {
        reader.seek(SeekFrom::End(0))?;
        let file_len = reader.stream_position()?;
        if file_len < (SB_SIZE + FOOTER_SIZE) as u64 {
            return Err(Error::corrupt(format!(
                "file is {file_len} bytes; a .lrimg needs at least {}",
                SB_SIZE + FOOTER_SIZE
            )));
        }

        let mut superblock_bytes = [0u8; SB_SIZE];
        reader.seek(SeekFrom::Start(0))?;
        reader.read_exact(&mut superblock_bytes)?;
        let superblock = crate::sb::Superblock::decode(&superblock_bytes)?;

        let mut footer_bytes = [0u8; FOOTER_SIZE];
        reader.seek(SeekFrom::Start(file_len - FOOTER_SIZE as u64))?;
        reader.read_exact(&mut footer_bytes)?;
        let footer = crate::footer::Footer::decode(
            &footer_bytes,
            &superblock_bytes[..crate::sb::SUPERBLOCK_COPY_LEN],
        )?;

        validate_layout(&superblock, &footer, file_len)?;

        Ok(Self {
            reader,
            file_len,
            superblock_bytes,
            superblock,
            footer_bytes,
            footer,
        })
    }

    /// The decoded superblock.
    #[must_use]
    pub const fn superblock(&self) -> &crate::sb::Superblock {
        &self.superblock
    }

    /// The decoded footer.
    #[must_use]
    pub const fn footer(&self) -> &crate::footer::Footer {
        &self.footer
    }

    /// Size of the underlying file.
    #[must_use]
    pub const fn file_len(&self) -> u64 {
        self.file_len
    }

    /// Verify `sb_mac` and `footer_mac`.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] when either MAC fails, which means the header
    /// was modified after the image was written.
    pub fn authenticate(&self, meta_key: Option<&[u8; 32]>) -> Result<()> {
        self.superblock
            .verify_mac(&self.superblock_bytes, meta_key)?;
        self.footer.verify_mac(&self.footer_bytes, meta_key)?;
        Ok(())
    }

    /// Resolve the full page table, following the stream-4 indirection.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] when the stream-4 table is malformed and
    /// [`Error::Aead`] when it does not authenticate.
    pub fn page_table(
        &mut self,
        meta_key: &[u8; 32],
        kind: AeadKind,
    ) -> Result<Vec<crate::footer::PageEntry>> {
        if !self.footer.page_table_in_stream4() {
            return Ok(self.footer.page_table.clone());
        }
        let entries = self.footer.entries_for(StreamId::PageTable);
        let mut stream = PageStreamReader::new(
            &mut self.reader,
            kind,
            *meta_key,
            StreamId::PageTable,
            entries,
            self.file_len,
        )?;
        let mut bytes = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            match stream.read_bytes_partial(&mut buf)? {
                0 => break,
                read => {
                    if bytes.len() + read > MAX_PAGE_TABLE_BYTES {
                        return Err(Error::corrupt("page table exceeds the accepted size"));
                    }
                    bytes.extend_from_slice(&buf[..read]);
                }
            }
        }
        parse_table(&bytes)
    }

    /// Open one page stream for sequential reading.
    ///
    /// # Errors
    /// Propagates page-table resolution and extent validation errors.
    pub fn stream_reader(
        &mut self,
        stream: StreamId,
        meta_key: [u8; 32],
        kind: AeadKind,
    ) -> Result<PageStreamReader<'_, R>> {
        let table = self.page_table(&meta_key, kind)?;
        let entries = table
            .into_iter()
            .filter(|entry| entry.stream == stream)
            .collect::<Vec<_>>();
        PageStreamReader::new(
            &mut self.reader,
            kind,
            meta_key,
            stream,
            entries,
            self.file_len,
        )
    }

    /// Read the raw bytes of one chunk record.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] when the extent lies outside the chunk
    /// region, and propagates I/O errors.
    pub fn read_chunk_bytes(&mut self, offset: u64, total_len: usize) -> Result<Vec<u8>> {
        let data_end = self.footer.data_end_offset;
        let end = offset
            .checked_add(total_len as u64)
            .ok_or_else(|| Error::corrupt("chunk extent overflows"))?;
        if offset < SB_SIZE as u64 || end > data_end {
            return Err(Error::corrupt(format!(
                "chunk extent {offset}..{end} lies outside the chunk region"
            )));
        }
        let mut bytes = vec![0u8; total_len];
        self.reader.seek(SeekFrom::Start(offset))?;
        self.reader.read_exact(&mut bytes)?;
        Ok(bytes)
    }

    /// Read a complete chunk record starting at `offset`.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] for a malformed header or an extent outside
    /// the chunk region.
    pub fn read_chunk_record(&mut self, offset: u64) -> Result<Vec<u8>> {
        let header = self.read_chunk_bytes(offset, crate::chunk::CHUNK_HEADER_LEN)?;
        let decoded = decode_header(&header)?;
        self.read_chunk_bytes(offset, decoded.total_len())
    }

    /// Walk every chunk record header, counting records.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] for a malformed record or a count that does
    /// not match the footer.
    pub fn scan_chunk_headers(&mut self) -> Result<u64> {
        let mut offset = SB_SIZE as u64;
        let data_end = self.footer.data_end_offset;
        let mut count = 0u64;
        let mut header = [0u8; crate::chunk::CHUNK_HEADER_LEN];
        while offset < data_end {
            if offset + crate::chunk::CHUNK_HEADER_LEN as u64 > data_end {
                return Err(Error::corrupt(
                    "truncated chunk header at the end of the region",
                ));
            }
            self.reader.seek(SeekFrom::Start(offset))?;
            self.reader.read_exact(&mut header)?;
            let decoded = decode_header(&header)?;
            let total = decoded.total_len() as u64;
            if offset + total > data_end {
                return Err(Error::corrupt("chunk record overruns the chunk region"));
            }
            offset += total;
            count += 1;
        }
        if offset != data_end {
            return Err(Error::corrupt(
                "chunk records do not end at data_end_offset",
            ));
        }
        if count != self.footer.total_chunks {
            return Err(Error::corrupt(format!(
                "footer declares {} chunks but {count} were found",
                self.footer.total_chunks
            )));
        }
        Ok(count)
    }
}

/// Reads chunk records through a second file handle.
///
/// A restore streams the manifest and reads chunk records at the same time;
/// with one handle those two readers would fight over the file offset, so
/// [`ImageReader::chunk_reader`] duplicates the descriptor instead of
/// buffering the manifest in memory.
pub struct ChunkReader {
    reader: Box<dyn lr_core::io::ReadSeek + Send>,
    data_end_offset: u64,
    chunk_region_start: u64,
}

impl ChunkReader {
    /// Build a chunk reader over an independent handle to the same image.
    ///
    /// The format layer is generic over the handle so a destination can hand
    /// out a second reader (a `dup`ed descriptor locally, a ranged SFTP handle
    /// remotely) while a metadata page stream stays open.
    #[must_use]
    pub fn new(reader: Box<dyn lr_core::io::ReadSeek + Send>, data_end_offset: u64) -> Self {
        Self {
            reader,
            data_end_offset,
            chunk_region_start: SB_SIZE as u64,
        }
    }

    /// End of the chunk region.
    #[must_use]
    pub const fn data_end_offset(&self) -> u64 {
        self.data_end_offset
    }

    /// Read one complete chunk record at `offset`.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] when the extent lies outside the chunk
    /// region and propagates I/O errors.
    pub fn read_record(&mut self, offset: u64) -> Result<Vec<u8>> {
        let header = self.read_bytes(offset, crate::chunk::CHUNK_HEADER_LEN)?;
        let decoded = decode_header(&header)?;
        self.read_bytes(offset, decoded.total_len())
    }

    fn read_bytes(&mut self, offset: u64, len: usize) -> Result<Vec<u8>> {
        let end = offset
            .checked_add(len as u64)
            .ok_or_else(|| Error::corrupt("chunk extent overflows"))?;
        if offset < self.chunk_region_start || end > self.data_end_offset {
            return Err(Error::corrupt(format!(
                "chunk extent {offset}..{end} lies outside the chunk region"
            )));
        }
        let mut bytes = vec![0u8; len];
        self.reader.seek(SeekFrom::Start(offset))?;
        self.reader.read_exact(&mut bytes)?;
        Ok(bytes)
    }
}

impl<R: Read + Seek> ImageReader<R> {
    /// A second handle for reading chunk records while a page stream is open.
    ///
    /// `reader` must be an independent handle to the same image, because a
    /// restore reads the manifest page stream and chunk records at the same
    /// time and one file offset cannot serve both.
    #[must_use]
    pub fn chunk_reader_with(&self, reader: Box<dyn lr_core::io::ReadSeek + Send>) -> ChunkReader {
        ChunkReader::new(reader, self.footer.data_end_offset)
    }
}

impl ImageReader<std::fs::File> {
    /// A second handle for reading chunk records while a page stream is open.
    ///
    /// # Errors
    /// Propagates `dup(2)` failures.
    pub fn chunk_reader(&self) -> Result<ChunkReader> {
        let duplicate = self.reader.try_clone().map_err(Error::Io)?;
        Ok(self.chunk_reader_with(Box::new(duplicate)))
    }
}

/// Check that the footer describes a file that can possibly exist.
fn validate_layout(
    superblock: &crate::sb::Superblock,
    footer: &crate::footer::Footer,
    file_len: u64,
) -> Result<()> {
    let chunk_region_start = SB_SIZE as u64;
    let pages_end = file_len - FOOTER_SIZE as u64;
    if footer.data_end_offset < chunk_region_start || footer.data_end_offset > pages_end {
        return Err(Error::corrupt(format!(
            "data_end_offset {} is outside {chunk_region_start}..={pages_end}",
            footer.data_end_offset
        )));
    }
    let chunk_region = footer.data_end_offset - chunk_region_start;
    let minimum_chunk_bytes = footer.total_chunks * CHUNK_OVERHEAD_PLAIN as u64;
    if minimum_chunk_bytes > chunk_region {
        return Err(Error::corrupt(format!(
            "{} chunks cannot fit in {chunk_region} bytes",
            footer.total_chunks
        )));
    }
    for entry in &footer.page_table {
        if entry.len as usize > lr_crypto::page::MAX_PAGE_LEN {
            return Err(Error::corrupt("page length exceeds the accepted maximum"));
        }
        let end = entry
            .offset
            .checked_add(entry.len as u64 + PAGE_OVERHEAD as u64)
            .ok_or_else(|| Error::corrupt("page extent overflows"))?;
        if entry.offset < footer.data_end_offset || end > pages_end {
            return Err(Error::corrupt(format!(
                "page extent {}..{} lies outside the metadata region",
                entry.offset, end
            )));
        }
    }
    if superblock.chunk_size == 0 {
        return Err(Error::corrupt("chunk_size must not be zero"));
    }
    Ok(())
}
