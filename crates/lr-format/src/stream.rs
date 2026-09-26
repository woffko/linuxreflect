//! Page streams: the metadata carrier of an image (spec §G.6, §G.2).
//!
//! A page stream is a logical byte stream split into 1 MiB pages. Both the
//! writer and the reader treat page boundaries as invisible, so manifests stay
//! parseable by structure rather than by position, and nothing beyond one page
//! is ever held in memory.

use std::io::{Read, Seek, SeekFrom};

use lr_core::{Error, Result};
use lr_crypto::aead::AeadKind;
use lr_crypto::nonce::NonceSeq;
use lr_crypto::page::{MAX_PAGE_LEN, PAGE_OVERHEAD, StreamId, open_page, seal_page};

use crate::footer::PageEntry;
use crate::wire::ByteSink;

/// Default page payload size (spec §G.2).
pub const DEFAULT_PAGE_LEN: usize = 1024 * 1024;

/// Where sealed pages go.
pub trait PageSink {
    /// Receive one sealed page record.
    ///
    /// # Errors
    /// Implementation defined.
    fn write_page(&mut self, stream: StreamId, page_no: u64, page: &[u8]) -> Result<()>;

    /// The image's single metadata nonce counter (spec §G.4).
    ///
    /// Every page stream of an image is sealed under the same `meta_key`, so
    /// all of them must draw from this one counter; a counter per stream
    /// repeated nonces across streams (R01, D-110).
    fn meta_nonces(&mut self) -> &mut NonceSeq;
}

/// Buffers writes into page-sized payloads and seals them.
pub struct PageStream<'a> {
    sink: &'a mut dyn PageSink,
    stream: StreamId,
    kind: AeadKind,
    meta_key: [u8; 32],
    page_len: usize,
    buf: Vec<u8>,
    page_no: u64,
    pages: u64,
}

impl<'a> PageStream<'a> {
    /// Create a writer for one stream.
    pub fn new(
        sink: &'a mut dyn PageSink,
        stream: StreamId,
        kind: AeadKind,
        meta_key: [u8; 32],
    ) -> Self {
        Self::with_page_len(sink, stream, kind, meta_key, DEFAULT_PAGE_LEN)
    }

    /// Create a writer with an explicit page payload size.
    ///
    /// # Errors
    /// Panics only if `page_len` is zero or exceeds [`MAX_PAGE_LEN`], which is
    /// a programming error; callers use [`DEFAULT_PAGE_LEN`].
    pub fn with_page_len(
        sink: &'a mut dyn PageSink,
        stream: StreamId,
        kind: AeadKind,
        meta_key: [u8; 32],
        page_len: usize,
    ) -> Self {
        assert!(
            page_len > 0 && page_len <= MAX_PAGE_LEN,
            "page length must be in 1..={MAX_PAGE_LEN}"
        );
        Self {
            sink,
            stream,
            kind,
            meta_key,
            page_len,
            buf: Vec::with_capacity(page_len),
            page_no: 0,
            pages: 0,
        }
    }

    /// Buffered write; full pages are sealed and handed to the sink.
    ///
    /// # Errors
    /// Propagates AEAD and sink errors.
    pub fn write(&mut self, mut bytes: &[u8]) -> Result<()> {
        while !bytes.is_empty() {
            let space = self.page_len - self.buf.len();
            let take = space.min(bytes.len());
            self.buf.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.buf.len() == self.page_len {
                self.flush_page()?;
            }
        }
        Ok(())
    }

    /// Seal any trailing partial page.
    ///
    /// # Errors
    /// Propagates AEAD and sink errors.
    pub fn finish(&mut self) -> Result<()> {
        self.flush_page()
    }

    /// Number of pages emitted so far.
    #[must_use]
    pub const fn pages(&self) -> u64 {
        self.pages
    }

    /// Bytes currently buffered but not yet sealed.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    fn flush_page(&mut self) -> Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let mut page = Vec::with_capacity(PAGE_OVERHEAD + self.buf.len());
        seal_page(
            self.kind,
            &self.meta_key,
            self.stream,
            self.page_no,
            &self.buf,
            self.sink.meta_nonces(),
            &mut page,
        )?;
        self.sink.write_page(self.stream, self.page_no, &page)?;
        self.page_no += 1;
        self.pages += 1;
        self.buf.clear();
        Ok(())
    }
}

impl ByteSink for PageStream<'_> {
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.write(bytes)
    }
}

/// Reads a page stream back, decrypting one page at a time.
pub struct PageStreamReader<'a, R: Read + Seek> {
    reader: &'a mut R,
    kind: AeadKind,
    meta_key: [u8; 32],
    stream: StreamId,
    entries: Vec<PageEntry>,
    index: usize,
    buf: Vec<u8>,
    pos: usize,
}

impl<'a, R: Read + Seek> PageStreamReader<'a, R> {
    /// Build a reader over the entries of one stream.
    ///
    /// Entries are validated against `file_len` before any read happens.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] when an entry points outside the file or its
    /// declared length exceeds [`MAX_PAGE_LEN`].
    pub fn new(
        reader: &'a mut R,
        kind: AeadKind,
        meta_key: [u8; 32],
        stream: StreamId,
        entries: impl IntoIterator<Item = PageEntry>,
        file_len: u64,
    ) -> Result<Self> {
        let mut filtered: Vec<PageEntry> = entries.into_iter().collect();
        for entry in &filtered {
            if entry.len as usize > MAX_PAGE_LEN {
                return Err(Error::corrupt(format!(
                    "page length {} exceeds {MAX_PAGE_LEN}",
                    entry.len
                )));
            }
            let end = entry
                .offset
                .checked_add(entry.len as u64 + PAGE_OVERHEAD as u64)
                .ok_or_else(|| Error::corrupt("page extent overflows"))?;
            if end > file_len {
                return Err(Error::corrupt(format!(
                    "page extent {}..{} lies outside the {file_len}-byte file",
                    entry.offset, end
                )));
            }
        }
        filtered.sort_by_key(|entry| entry.offset);
        Ok(Self {
            reader,
            kind,
            meta_key,
            stream,
            entries: filtered,
            index: 0,
            buf: Vec::new(),
            pos: 0,
        })
    }

    /// Number of pages this stream consists of.
    #[must_use]
    pub fn page_count(&self) -> usize {
        self.entries.len()
    }

    /// Read up to `out.len()` bytes, returning 0 at the end of the stream.
    ///
    /// # Errors
    /// Propagates decryption and I/O errors.
    pub fn read_bytes_partial(&mut self, out: &mut [u8]) -> Result<usize> {
        if self.pos >= self.buf.len() && !self.load_next()? {
            return Ok(0);
        }
        let take = out.len().min(self.buf.len() - self.pos);
        out[..take].copy_from_slice(&self.buf[self.pos..self.pos + take]);
        self.pos += take;
        Ok(take)
    }

    fn load_next(&mut self) -> Result<bool> {
        if self.index >= self.entries.len() {
            return Ok(false);
        }
        let entry = self.entries[self.index];
        self.index += 1;
        let total = entry.len as usize + PAGE_OVERHEAD;
        self.reader.seek(SeekFrom::Start(entry.offset))?;
        let mut raw = vec![0u8; total];
        self.reader.read_exact(&mut raw).map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                Error::corrupt("page record is truncated")
            } else {
                Error::Io(e)
            }
        })?;
        // The page number is the position within its own stream.
        self.buf = open_page(
            self.kind,
            &self.meta_key,
            self.stream,
            (self.index - 1) as u64,
            &raw,
        )?;
        self.pos = 0;
        Ok(true)
    }
}

impl<R: Read + Seek> crate::wire::ByteSource for PageStreamReader<'_, R> {
    fn read_bytes(&mut self, out: &mut [u8]) -> Result<()> {
        let mut written = 0;
        while written < out.len() {
            if self.pos >= self.buf.len() && !self.load_next()? {
                return Err(Error::corrupt("page stream ended early"));
            }
            let take = (out.len() - written).min(self.buf.len() - self.pos);
            out[written..written + take].copy_from_slice(&self.buf[self.pos..self.pos + take]);
            self.pos += take;
            written += take;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{PageSink, PageStream, PageStreamReader};
    use crate::footer::PageEntry;
    use crate::wire::{ByteSource, Reader};
    use lr_core::Result;
    use lr_crypto::aead::AeadKind;
    use lr_crypto::nonce::NonceSeq;
    use lr_crypto::page::StreamId;
    use std::io::Cursor;

    const META_KEY: [u8; 32] = [0x33; 32];

    struct MemorySink {
        pages: Vec<(StreamId, u64, Vec<u8>)>,
        nonces: NonceSeq,
    }

    impl Default for MemorySink {
        fn default() -> Self {
            Self {
                pages: Vec::new(),
                nonces: NonceSeq::new(),
            }
        }
    }

    impl PageSink for MemorySink {
        fn write_page(&mut self, stream: StreamId, page_no: u64, page: &[u8]) -> Result<()> {
            self.pages.push((stream, page_no, page.to_vec()));
            Ok(())
        }

        fn meta_nonces(&mut self) -> &mut NonceSeq {
            &mut self.nonces
        }
    }

    fn build(data: &[u8], page_len: usize, stream: StreamId) -> (MemorySink, Vec<u8>) {
        let mut sink = MemorySink::default();
        {
            let mut writer = PageStream::with_page_len(
                &mut sink,
                stream,
                AeadKind::Aes256Gcm,
                META_KEY,
                page_len,
            );
            for chunk in data.chunks(7) {
                writer.write(chunk).expect("write");
            }
            writer.finish().expect("finish");
        }

        // Lay the sealed pages out in a buffer exactly as the container would.
        let mut file = vec![0u8; 4096];
        let mut entries = Vec::new();
        for (stream, _page_no, page) in &sink.pages {
            let offset = file.len() as u64;
            file.extend_from_slice(page);
            let len = page.len() - lr_crypto::page::PAGE_OVERHEAD;
            entries.push(PageEntry {
                stream: *stream,
                offset,
                len: len as u32,
            });
        }
        let mut table = Vec::new();
        for entry in entries {
            table.extend_from_slice(&[entry.stream.as_u8()]);
            table.extend_from_slice(&entry.offset.to_le_bytes());
            table.extend_from_slice(&entry.len.to_le_bytes());
        }
        (sink, table)
    }

    #[test]
    fn splits_and_reassembles_across_page_boundaries() {
        let data: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let (sink, table) = build(&data, 1024, StreamId::Manifest);
        assert_eq!(sink.pages.len(), 5, "5000 bytes at 1024 per page");

        // Reconstruct the page table for reading.
        let mut file = vec![0u8; 4096];
        let mut entries = Vec::new();
        for (stream, _no, page) in &sink.pages {
            let offset = file.len() as u64;
            file.extend_from_slice(page);
            entries.push(PageEntry {
                stream: *stream,
                offset,
                len: (page.len() - lr_crypto::page::PAGE_OVERHEAD) as u32,
            });
        }
        drop(table);
        // The generated table must describe the same pages.
        let mut cursor = Cursor::new(&file);
        let mut reader = PageStreamReader::new(
            &mut cursor,
            AeadKind::Aes256Gcm,
            META_KEY,
            StreamId::Manifest,
            entries,
            file.len() as u64,
        )
        .expect("reader");
        let mut out = vec![0u8; data.len()];
        reader.read_bytes(&mut out).expect("read");
        assert_eq!(out, data);
    }

    #[test]
    fn typed_writes_round_trip_through_the_stream() {
        let mut sink = MemorySink::default();
        {
            let mut writer = PageStream::with_page_len(
                &mut sink,
                StreamId::Extras,
                AeadKind::Aes256Gcm,
                META_KEY,
                64,
            );
            crate::wire::put_u32(&mut writer, 0xAABB_CCDD).expect("u32");
            crate::wire::put_u16_prefixed(&mut writer, b"hello").expect("string");
            writer.finish().expect("finish");
        }
        let mut file = vec![0u8; 16];
        let mut entries = Vec::new();
        for (stream, _no, page) in &sink.pages {
            let offset = file.len() as u64;
            file.extend_from_slice(page);
            entries.push(PageEntry {
                stream: *stream,
                offset,
                len: (page.len() - lr_crypto::page::PAGE_OVERHEAD) as u32,
            });
        }
        let mut cursor = Cursor::new(&file);
        let reader = PageStreamReader::new(
            &mut cursor,
            AeadKind::Aes256Gcm,
            META_KEY,
            StreamId::Extras,
            entries,
            file.len() as u64,
        )
        .expect("reader");
        let mut wire = Reader::new(reader);
        assert_eq!(wire.u32().expect("u32"), 0xAABB_CCDD);
        assert_eq!(wire.u16_prefixed().expect("string"), b"hello");
    }

    #[test]
    fn an_entry_outside_the_file_is_refused() {
        let file = vec![0u8; 32];
        let mut cursor = Cursor::new(&file);
        let result = PageStreamReader::new(
            &mut cursor,
            AeadKind::Aes256Gcm,
            META_KEY,
            StreamId::Manifest,
            vec![PageEntry {
                stream: StreamId::Manifest,
                offset: 4096,
                len: 128,
            }],
            file.len() as u64,
        );
        assert!(result.is_err());
    }
}
