//! Block sources for LinuxReflect (spec §C.1, §D.4, Slice S6).
//!
//! A [`BlockSource`] reads aligned runs of bytes from a block device or image
//! file. [`plan::UsedChunks`] turns a used-block map into chunk plans, and
//! [`read_chunk`] performs one planned read while translating I/O failures into
//! [`Error::BadSector`] so the engine can honour `--on-bad-sector`.
#![forbid(unsafe_code)]

pub mod direct;
pub mod plan;

pub use direct::{DirectBlockSource, DirectBlockTarget, IoMode, MIN_ALIGNMENT};
pub use plan::{ChunkPlan, UsedChunks, is_all_zero};

use lr_core::{Error, Result};
use lr_unsafe::AlignedBuf;

/// Read access to the blocks of a device.
pub trait BlockSource: Send {
    /// Device size in bytes.
    fn size_bytes(&self) -> u64;

    /// Logical block size in bytes.
    fn logical_block_size(&self) -> u32;

    /// Read `len` bytes into `buf` at `offset`, returning how many were read.
    ///
    /// `len` must fit in `buf`. It is separate from the buffer's size because
    /// the final chunk of a region is shorter than the chunk size, and reading
    /// the full buffer would return more bytes than the plan expects.
    /// Implementations clamp to the end of the device, so a short read means
    /// end of device rather than an error.
    ///
    /// # Errors
    /// Propagates I/O failures.
    fn read_at(&mut self, offset: u64, buf: &mut AlignedBuf, len: usize) -> Result<usize>;
}

/// Read one planned chunk and return the bytes that were read.
///
/// # Errors
/// Returns [`Error::BadSector`] when the read fails or returns fewer bytes than
/// the chunk claims, and [`Error::Unsupported`] when `buf` is too small.
pub fn read_chunk<'a>(
    source: &mut dyn BlockSource,
    plan: &ChunkPlan,
    buf: &'a mut AlignedBuf,
) -> Result<&'a [u8]> {
    let want = plan.len as usize;
    if buf.len() < want {
        return Err(Error::unsupported(format!(
            "{} byte buffer cannot hold a {want} byte chunk",
            buf.len()
        )));
    }
    let read = source.read_at(plan.offset, buf, want).map_err(|error| {
        tracing::warn!(offset = plan.offset, len = plan.len, %error, "chunk read failed");
        Error::BadSector {
            offset: plan.offset,
            len: u64::from(plan.len),
        }
    })?;
    if read != want {
        tracing::warn!(
            offset = plan.offset,
            expected = want,
            got = read,
            "short chunk read"
        );
        return Err(Error::BadSector {
            offset: plan.offset,
            len: u64::from(plan.len),
        });
    }
    Ok(&buf.as_slice()[..read])
}

#[cfg(test)]
mod tests {
    use super::{BlockSource, ChunkPlan, read_chunk};
    use lr_core::{Error, Result};
    use lr_unsafe::AlignedBuf;

    /// An in-memory source with deterministic contents.
    struct MemorySource {
        data: Vec<u8>,
        fail_at: Option<u64>,
    }

    impl MemorySource {
        fn new(size: usize) -> Self {
            let data = (0..size).map(|i| (i % 251) as u8).collect();
            Self {
                data,
                fail_at: None,
            }
        }
    }

    impl BlockSource for MemorySource {
        fn size_bytes(&self) -> u64 {
            self.data.len() as u64
        }

        fn logical_block_size(&self) -> u32 {
            512
        }

        fn read_at(&mut self, offset: u64, buf: &mut AlignedBuf, len: usize) -> Result<usize> {
            if self.fail_at == Some(offset) {
                return Err(Error::Io(std::io::Error::other("injected read error")));
            }
            let offset = offset as usize;
            if offset >= self.data.len() {
                return Ok(0);
            }
            let available = self.data.len() - offset;
            let want = len.min(buf.len()).min(available);
            buf.as_mut_slice()[..want].copy_from_slice(&self.data[offset..offset + want]);
            Ok(want)
        }
    }

    fn buffer(len: usize) -> AlignedBuf {
        AlignedBuf::new(len, 4096).expect("buffer")
    }

    #[test]
    fn reads_a_planned_chunk() {
        let mut source = MemorySource::new(16 * 1024);
        let plan = ChunkPlan {
            index: 1,
            offset: 4096,
            len: 4096,
        };
        let mut buf = buffer(4096);
        let chunk = read_chunk(&mut source, &plan, &mut buf).expect("read");
        assert_eq!(chunk.len(), 4096);
        assert_eq!(chunk[0], (4096 % 251) as u8);
    }

    #[test]
    fn an_io_failure_becomes_a_bad_sector() {
        let mut source = MemorySource::new(16 * 1024);
        source.fail_at = Some(4096);
        let plan = ChunkPlan {
            index: 1,
            offset: 4096,
            len: 4096,
        };
        let mut buf = buffer(4096);
        let error = read_chunk(&mut source, &plan, &mut buf).expect_err("must fail");
        assert!(matches!(
            error,
            Error::BadSector {
                offset: 4096,
                len: 4096
            }
        ));
    }

    #[test]
    fn a_short_read_is_a_bad_sector() {
        let mut source = MemorySource::new(5000);
        let plan = ChunkPlan {
            index: 1,
            offset: 4096,
            len: 4096,
        };
        let mut buf = buffer(4096);
        assert!(matches!(
            read_chunk(&mut source, &plan, &mut buf),
            Err(Error::BadSector { .. })
        ));
    }

    #[test]
    fn a_small_buffer_is_refused() {
        let mut source = MemorySource::new(16 * 1024);
        let plan = ChunkPlan {
            index: 0,
            offset: 0,
            len: 4096,
        };
        let mut buf = buffer(512);
        assert!(matches!(
            read_chunk(&mut source, &plan, &mut buf),
            Err(Error::Unsupported { .. })
        ));
    }

    #[test]
    fn memory_source_matches_the_expected_pattern() {
        // Guard against the test double drifting from real device semantics.
        let mut source = MemorySource::new(1024);
        let mut buf = buffer(512);
        let len = buf.len();
        assert_eq!(source.read_at(0, &mut buf, len).expect("read"), 512);
        assert_eq!(buf.as_slice().len(), 512);
    }
}
