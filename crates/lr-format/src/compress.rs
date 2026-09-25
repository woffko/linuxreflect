//! zstd compression with the "only if it helps" rule (spec §G.5 bit0 `zstd`).
//!
//! A chunk that does not shrink is stored raw, which keeps the reader's
//! decompression surface minimal and avoids spending CPU on incompressible
//! data.

use lr_core::{Error, Result};

/// Compression level used by default (`zstd:9` in spec §J.2).
pub const DEFAULT_LEVEL: i32 = 9;

/// Smallest level the spec allows in config.
pub const MIN_LEVEL: i32 = 1;

/// Largest level the spec allows in config.
pub const MAX_LEVEL: i32 = 22;

/// Compress `data` at `level`.
///
/// # Errors
/// Returns [`Error::Unsupported`] for an out-of-range level and propagates
/// zstd failures as [`Error::Io`].
pub fn compress(data: &[u8], level: i32) -> Result<Vec<u8>> {
    if !(MIN_LEVEL..=MAX_LEVEL).contains(&level) {
        return Err(Error::unsupported(format!("zstd level {level}")));
    }
    zstd::bulk::compress(data, level).map_err(Error::Io)
}

/// Decompress `data`, refusing to produce more than `max_output` bytes.
///
/// # Errors
/// Returns [`Error::Corrupt`] when the frame is invalid or expands beyond
/// `max_output`, which bounds memory on hostile input.
pub fn decompress(data: &[u8], max_output: usize) -> Result<Vec<u8>> {
    let out = zstd::bulk::decompress(data, max_output).map_err(Error::Io)?;
    if out.len() > max_output {
        return Err(Error::corrupt(format!(
            "zstd frame expands to {} bytes, limit {max_output}",
            out.len()
        )));
    }
    Ok(out)
}

/// Compress only when the result is strictly smaller than the input.
///
/// Returns `(bytes, was_compressed)`.
///
/// # Errors
/// See [`compress`].
pub fn compress_if_smaller(data: &[u8], level: i32) -> Result<(Vec<u8>, bool)> {
    let compressed = compress(data, level)?;
    if compressed.len() < data.len() {
        Ok((compressed, true))
    } else {
        Ok((data.to_vec(), false))
    }
}

#[cfg(test)]
mod tests {
    use super::{compress, compress_if_smaller, decompress};

    #[test]
    fn compresses_repetitive_data() {
        let data = vec![0x41u8; 64 * 1024];
        let (stored, compressed) = compress_if_smaller(&data, 9).expect("compress");
        assert!(compressed);
        assert!(stored.len() < data.len());
        assert_eq!(decompress(&stored, data.len()).expect("decompress"), data);
    }

    #[test]
    fn keeps_incompressible_data_raw() {
        // 8 KiB of hashed counters: no structure for zstd to exploit.
        let mut data = Vec::with_capacity(8192);
        let mut counter = 0u64;
        while data.len() < 8192 {
            data.extend_from_slice(&lr_crypto::hash::unkeyed_hash(&counter.to_le_bytes()));
            counter += 1;
        }
        let (stored, compressed) = compress_if_smaller(&data, 9).expect("compress");
        assert!(!compressed, "incompressible data must be stored raw");
        assert_eq!(stored, data);
    }

    #[test]
    fn rejects_absurd_levels() {
        assert!(compress(b"data", 0).is_err());
        assert!(compress(b"data", 23).is_err());
    }

    #[test]
    fn refuses_to_expand_beyond_the_limit() {
        let data = vec![0x7fu8; 128 * 1024];
        let compressed = compress(&data, 9).expect("compress");
        assert!(decompress(&compressed, 1024).is_err());
    }
}
