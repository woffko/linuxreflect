//! Structural and authentication verification of an image (spec §G.8).
//!
//! This is the part of `verify` that slice S4 can already provide: everything
//! that can be checked without the manifest, namely magic numbers, hashes,
//! MACs, chunk-record framing and every metadata page tag. Recomputing chunk
//! content hashes against the manifest belongs to S11.

use std::io::{Read, Seek};

use lr_core::Result;
use lr_crypto::page::StreamId;

use crate::reader::ImageReader;

/// What a structural verification found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// File size.
    pub file_len: u64,
    /// End of the chunk region.
    pub data_end_offset: u64,
    /// Number of chunk records.
    pub chunks: u64,
    /// Pages per stream that were decrypted successfully.
    pub pages: Vec<(StreamId, usize)>,
}

impl VerifyReport {
    /// Total number of metadata pages verified.
    #[must_use]
    pub fn total_pages(&self) -> usize {
        self.pages.iter().map(|(_, count)| count).sum()
    }
}

/// Verify structure, MACs and every page tag.
///
/// `meta_key` is the image's metadata key; pass `encrypted = false` for
/// `--no-encrypt` images so the header MACs are checked with the fixed public
/// key (the pages still use `meta_key`, which those images derive from their
/// public chain key).
///
/// # Errors
/// Returns [`Error::Corrupt`](lr_core::Error::Corrupt) for any structural or
/// authentication failure and [`Error::Aead`](lr_core::Error::Aead) when a
/// page fails to decrypt.
pub fn verify_structure<R: Read + Seek>(
    reader: R,
    meta_key: [u8; 32],
    encrypted: bool,
) -> Result<VerifyReport> {
    let mut image = ImageReader::open(reader)?;
    let kind = image.superblock().aead_kind()?;
    image.authenticate(if encrypted { Some(&meta_key) } else { None })?;

    let chunks = image.scan_chunk_headers()?;
    let table = image.page_table(&meta_key, kind)?;

    let mut pages = Vec::new();
    for stream in [
        StreamId::Manifest,
        StreamId::HashIndex,
        StreamId::Extras,
        StreamId::PageTable,
    ] {
        let count = table.iter().filter(|entry| entry.stream == stream).count();
        if count == 0 {
            continue;
        }
        let mut stream_reader = image.stream_reader(stream, meta_key, kind)?;
        let mut buf = vec![0u8; 64 * 1024];
        // Decrypt every page of the stream; open_page checks each tag, and
        // decoding the whole stream also proves the pages are contiguous.
        loop {
            if stream_reader.read_bytes_partial(&mut buf)? == 0 {
                break;
            }
        }
        pages.push((stream, count));
    }

    Ok(VerifyReport {
        file_len: image.file_len(),
        data_end_offset: image.footer().data_end_offset,
        chunks,
        pages,
    })
}
