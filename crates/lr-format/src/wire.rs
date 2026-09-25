//! Little-endian wire helpers shared by every `.lrimg` structure.
//!
//! Writing goes through [`ByteSink`] and reading through [`ByteSource`], which
//! keeps typed [`lr_core::Error`] values all the way to the caller: a corrupt
//! page is [`lr_core::Error::Corrupt`], not a flattened I/O error.

use std::io::{Read, Write};

use lr_core::{Error, Id, Result};

/// A byte sink that reports typed errors.
pub trait ByteSink {
    /// Write every byte or fail.
    ///
    /// # Errors
    /// Implementation defined.
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()>;
}

impl<W: Write + ?Sized> ByteSink for W {
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.write_all(bytes).map_err(Error::Io)
    }
}

/// A byte source that reports typed errors.
pub trait ByteSource {
    /// Fill `buf` completely or fail.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] when the source ends early.
    fn read_bytes(&mut self, buf: &mut [u8]) -> Result<()>;
}

impl<R: Read + ?Sized> ByteSource for R {
    fn read_bytes(&mut self, buf: &mut [u8]) -> Result<()> {
        match self.read_exact(buf) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                Err(Error::corrupt("unexpected end of image data"))
            }
            Err(e) => Err(Error::Io(e)),
        }
    }
}

/// Append a `u8`.
///
/// # Errors
/// Propagates sink errors.
pub fn put_u8(out: &mut impl ByteSink, value: u8) -> Result<()> {
    out.write_bytes(&[value])
}

/// Append a little-endian `u16`.
///
/// # Errors
/// Propagates sink errors.
pub fn put_u16(out: &mut impl ByteSink, value: u16) -> Result<()> {
    out.write_bytes(&value.to_le_bytes())
}

/// Append a little-endian `u32`.
///
/// # Errors
/// Propagates sink errors.
pub fn put_u32(out: &mut impl ByteSink, value: u32) -> Result<()> {
    out.write_bytes(&value.to_le_bytes())
}

/// Append a little-endian `u64`.
///
/// # Errors
/// Propagates sink errors.
pub fn put_u64(out: &mut impl ByteSink, value: u64) -> Result<()> {
    out.write_bytes(&value.to_le_bytes())
}

/// Append a little-endian `i64`.
///
/// # Errors
/// Propagates sink errors.
pub fn put_i64(out: &mut impl ByteSink, value: i64) -> Result<()> {
    out.write_bytes(&value.to_le_bytes())
}

/// Append a 16-byte identifier.
///
/// # Errors
/// Propagates sink errors.
pub fn put_id(out: &mut impl ByteSink, value: &Id) -> Result<()> {
    out.write_bytes(value.as_bytes())
}

/// Append raw bytes.
///
/// # Errors
/// Propagates sink errors.
pub fn put_bytes(out: &mut impl ByteSink, bytes: &[u8]) -> Result<()> {
    out.write_bytes(bytes)
}

/// Append a length-prefixed byte string (`u16` length).
///
/// # Errors
/// Returns [`Error::Unsupported`] when the value does not fit in a `u16`, and
/// propagates sink errors.
pub fn put_u16_prefixed(out: &mut impl ByteSink, bytes: &[u8]) -> Result<()> {
    let len = u16::try_from(bytes.len())
        .map_err(|_| Error::unsupported("string longer than 65535 bytes"))?;
    put_u16(out, len)?;
    put_bytes(out, bytes)
}

/// Append a length-prefixed byte string (`u32` length).
///
/// # Errors
/// Returns [`Error::Unsupported`] when the value does not fit in a `u32`, and
/// propagates sink errors.
pub fn put_u32_prefixed(out: &mut impl ByteSink, bytes: &[u8]) -> Result<()> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| Error::unsupported("string longer than 4294967295 bytes"))?;
    put_u32(out, len)?;
    put_bytes(out, bytes)
}

/// Sequential, bounds-checked reader over any byte source.
pub struct Reader<S: ByteSource> {
    inner: S,
}

impl<S: ByteSource> Reader<S> {
    /// Wrap a byte source.
    pub fn new(inner: S) -> Self {
        Self { inner }
    }

    /// Unwrap the byte source.
    pub fn into_inner(self) -> S {
        self.inner
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut buf = [0u8; N];
        self.inner.read_bytes(&mut buf)?;
        Ok(buf)
    }

    /// Read a `u8`.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] at end of input.
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.read_array::<1>()?[0])
    }

    /// Read a little-endian `u16`.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] at end of input.
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.read_array()?))
    }

    /// Read a little-endian `u32`.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] at end of input.
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    /// Read a little-endian `u64`.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] at end of input.
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.read_array()?))
    }

    /// Read a little-endian `i64`.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] at end of input.
    pub fn i64(&mut self) -> Result<i64> {
        Ok(i64::from_le_bytes(self.read_array()?))
    }

    /// Read exactly `len` bytes into a fresh vector.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] at end of input.
    pub fn bytes(&mut self, len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        self.read_into(&mut buf)?;
        Ok(buf)
    }

    /// Fill an existing buffer.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] at end of input.
    pub fn read_into(&mut self, buf: &mut [u8]) -> Result<()> {
        self.inner.read_bytes(buf)
    }

    /// Read a fixed-size array.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] at end of input.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.read_array()
    }

    /// Read a 16-byte identifier.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] at end of input.
    pub fn id(&mut self) -> Result<Id> {
        Ok(Id::from_bytes(self.read_array()?))
    }

    /// Read a `u16`-length-prefixed byte string.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] at end of input.
    pub fn u16_prefixed(&mut self) -> Result<Vec<u8>> {
        let len = usize::from(self.u16()?);
        self.bytes(len)
    }

    /// Read a `u32`-length-prefixed byte string.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] at end of input.
    pub fn u32_prefixed(&mut self) -> Result<Vec<u8>> {
        let len = self.u32()? as usize;
        self.bytes(len)
    }
}

/// Read a little-endian `u16` from a slice.
///
/// # Errors
/// Returns [`Error::Corrupt`] when the slice is too short.
pub fn slice_u16(bytes: &[u8]) -> Result<u16> {
    let array: [u8; 2] = bytes
        .get(..2)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| Error::corrupt("slice shorter than 2 bytes"))?;
    Ok(u16::from_le_bytes(array))
}

/// Read a little-endian `u32` from a slice.
///
/// # Errors
/// Returns [`Error::Corrupt`] when the slice is too short.
pub fn slice_u32(bytes: &[u8]) -> Result<u32> {
    let array: [u8; 4] = bytes
        .get(..4)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| Error::corrupt("slice shorter than 4 bytes"))?;
    Ok(u32::from_le_bytes(array))
}

/// Read a little-endian `u64` from a slice.
///
/// # Errors
/// Returns [`Error::Corrupt`] when the slice is too short.
pub fn slice_u64(bytes: &[u8]) -> Result<u64> {
    let array: [u8; 8] = bytes
        .get(..8)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| Error::corrupt("slice shorter than 8 bytes"))?;
    Ok(u64::from_le_bytes(array))
}

#[cfg(test)]
mod tests {
    use super::{Reader, put_u16_prefixed, put_u32, put_u64};
    use std::io::Cursor;

    #[test]
    fn round_trips_through_a_reader() {
        let mut buf = Vec::new();
        put_u32(&mut buf, 0xDEAD_BEEF).expect("write");
        put_u64(&mut buf, u64::MAX).expect("write");
        put_u16_prefixed(&mut buf, b"label").expect("write");

        let mut reader = Reader::new(Cursor::new(buf));
        assert_eq!(reader.u32().expect("read"), 0xDEAD_BEEF);
        assert_eq!(reader.u64().expect("read"), u64::MAX);
        assert_eq!(reader.u16_prefixed().expect("read"), b"label");
    }

    #[test]
    fn truncation_is_an_error_not_a_panic() {
        let mut reader = Reader::new(Cursor::new(vec![0u8, 1, 2]));
        assert!(reader.u32().is_err());
    }
}
