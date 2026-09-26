//! `O_DIRECT` block sources and targets.
//!
//! Block mode reads and writes whole chunks with `direct` I/O so that a chunk
//! never passes through the page cache: a backup must not evict the running
//! system's cached data, and a restore must not leave the target's cache
//! holding data that was never flushed. Buffered mode exists for tests and for
//! filesystems that cannot do `O_DIRECT`; the engine never selects it
//! implicitly (spec §L.1: no silent downgrade).

use std::fs::File;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::fs::FileExt;
use std::path::Path;

use lr_core::{Error, Result};
use lr_unsafe::AlignedBuf;

/// Smallest alignment Linux block devices accept for `O_DIRECT`.
pub const MIN_ALIGNMENT: usize = 4096;

/// How a source or target talks to its device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoMode {
    /// `O_DIRECT`; required for production backups and restores.
    Direct,
    /// Buffered I/O; explicit opt-in for tests and unsupported filesystems.
    Buffered,
}

fn device_size(path: &Path) -> Result<u64> {
    match lr_unsafe::block_device_size_bytes(path) {
        Ok(size) => Ok(size),
        Err(_) => std::fs::metadata(path).map_err(Error::Io).map(|m| m.len()),
    }
}

fn alignment_for(path: &Path) -> usize {
    let lbs = lr_unsafe::block_device_logical_sector_size(path).unwrap_or(512) as usize;
    lbs.max(MIN_ALIGNMENT)
}

/// A busy device is reported as [`Error::TargetBusy`], anything else as
/// the caller's error.
fn busy_or(
    path: &Path,
    error: std::io::Error,
    other: impl FnOnce(std::io::Error) -> Error,
) -> Error {
    if error.kind() == std::io::ErrorKind::ResourceBusy {
        Error::TargetBusy {
            holder: format!(
                "{} is in use: it is mounted (possibly in another mount namespace), \
                 held by another device, or claimed by another program",
                path.display()
            ),
        }
    } else {
        other(error)
    }
}

/// Open the same device again through `/proc/self/fd`, without `O_DIRECT`.
///
/// The new description refers to the open device, not to whatever the path
/// names now, so a renamed or replaced node cannot redirect the write.
fn reopen_buffered(fd: std::os::fd::RawFd, write: bool) -> Result<File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(write)
        .open(format!("/proc/self/fd/{fd}"))
        .map_err(Error::Io)
}

fn open_direct(path: &Path, write: bool) -> Result<OwnedFd> {
    lr_unsafe::open_o_direct(path, write).map_err(|e| {
        Error::unsupported(format!(
            "O_DIRECT on {}: {e}; this device or filesystem cannot be used for block I/O",
            path.display()
        ))
    })
}

/// A chunk-aligned reader.
pub struct DirectBlockSource {
    handle: Handle,
    size_bytes: u64,
    logical_block_size: u32,
    alignment: usize,
}

enum Handle {
    Direct(OwnedFd),
    Buffered(File),
}

impl DirectBlockSource {
    /// Open a device or file read-only with `O_DIRECT`.
    ///
    /// # Errors
    /// Returns [`Error::Unsupported`] when the path cannot be opened with
    /// `O_DIRECT`, and [`Error::Io`] for other failures.
    pub fn open(path: &Path) -> Result<Self> {
        let fd = open_direct(path, false)?;
        Self::finish(Handle::Direct(fd), path)
    }

    /// Open a device or file read-only without `O_DIRECT`.
    ///
    /// # Errors
    /// Propagates I/O errors.
    pub fn open_buffered(path: &Path) -> Result<Self> {
        let file = File::open(path).map_err(Error::Io)?;
        Self::finish(Handle::Buffered(file), path)
    }

    fn finish(handle: Handle, path: &Path) -> Result<Self> {
        Ok(Self {
            handle,
            size_bytes: device_size(path)?,
            logical_block_size: lr_unsafe::block_device_logical_sector_size(path).unwrap_or(512),
            alignment: alignment_for(path),
        })
    }

    /// Alignment required for buffers used with this source.
    #[must_use]
    pub const fn alignment(&self) -> usize {
        self.alignment
    }

    /// Allocate a buffer suitable for this source.
    ///
    /// # Errors
    /// Propagates allocation failures.
    pub fn buffer(&self, len: usize) -> Result<AlignedBuf> {
        AlignedBuf::new(len, self.alignment).map_err(Error::Io)
    }

    /// `true` when the source uses `O_DIRECT`.
    #[must_use]
    pub const fn is_direct(&self) -> bool {
        matches!(self.handle, Handle::Direct(_))
    }
}

impl crate::BlockSource for DirectBlockSource {
    fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    fn logical_block_size(&self) -> u32 {
        self.logical_block_size
    }

    fn read_at(&mut self, offset: u64, buf: &mut AlignedBuf, len: usize) -> Result<usize> {
        if offset >= self.size_bytes {
            return Ok(0);
        }
        let available = self.size_bytes - offset;
        let want = len
            .min(buf.len())
            .min(usize::try_from(available).unwrap_or(usize::MAX));
        if want == 0 {
            return Ok(0);
        }
        if buf.alignment() < self.alignment {
            return Err(Error::unsupported(format!(
                "unaligned direct read of {want} bytes (alignment {}, sector {})",
                self.alignment, self.logical_block_size
            )));
        }
        // `O_DIRECT` also rejects a *length* that is not a multiple of the
        // device alignment. The last chunk of a partition is often shorter than
        // that (its end is not 4 KiB-aligned), and there is nothing to pad with
        // past the end of the device, so that one read is buffered instead
        // (D-097). The data is identical; only the transfer mode differs.
        if matches!(self.handle, Handle::Direct(_)) && !want.is_multiple_of(self.alignment) {
            tracing::debug!(offset, want, "reading an unaligned tail without O_DIRECT");
            let Handle::Direct(fd) = &self.handle else {
                unreachable!("checked above")
            };
            let file = reopen_buffered(fd.as_raw_fd(), false)?;
            return file
                .read_at(&mut buf.as_mut_slice()[..want], offset)
                .map_err(Error::Io);
        }
        match &self.handle {
            Handle::Direct(fd) => lr_unsafe::pread_into(fd, buf, want, offset).map_err(Error::Io),
            Handle::Buffered(file) => file
                .read_at(&mut buf.as_mut_slice()[..want], offset)
                .map_err(Error::Io),
        }
    }
}

/// A chunk-aligned writer used by restore.
pub struct DirectBlockTarget {
    handle: Handle,
    size_bytes: u64,
    logical_block_size: u32,
    alignment: usize,
}

impl DirectBlockTarget {
    /// Claim a device or file exclusively and open it read-write with
    /// `O_DIRECT`.
    ///
    /// The claim (`O_EXCL`) is held until the target is dropped: a device
    /// that is mounted anywhere, in any mount namespace, is refused, and
    /// nothing can mount it while the restore writes (A1).
    ///
    /// # Errors
    /// Returns [`Error::TargetBusy`] when the device is in use,
    /// [`Error::Unsupported`] when it cannot be opened with `O_DIRECT`, and
    /// [`Error::Io`] for other failures.
    pub fn open(path: &Path) -> Result<Self> {
        let fd = lr_unsafe::open_block_exclusive(path, true, true).map_err(|error| {
            busy_or(path, error, |error| {
                Error::unsupported(format!(
                    "O_DIRECT on {}: {error}; this device or filesystem cannot be used for \
                     block I/O",
                    path.display()
                ))
            })
        })?;
        Self::finish(Handle::Direct(fd), path)
    }

    /// Claim a device or file exclusively and open it read-write without
    /// `O_DIRECT`.
    ///
    /// # Errors
    /// Returns [`Error::TargetBusy`] when the device is in use and propagates
    /// other I/O errors.
    pub fn open_buffered(path: &Path) -> Result<Self> {
        let fd = lr_unsafe::open_block_exclusive(path, true, false)
            .map_err(|error| busy_or(path, error, Error::Io))?;
        Self::finish(Handle::Buffered(File::from(fd)), path)
    }

    /// Device number (`st_rdev`) of the claimed target, read from the open
    /// descriptor, so it names the device this target will write.
    ///
    /// # Errors
    /// Propagates `fstat` failures.
    pub fn device_id(&self) -> Result<u64> {
        use std::os::unix::fs::MetadataExt;
        let fd = match &self.handle {
            Handle::Direct(fd) => fd.try_clone(),
            Handle::Buffered(file) => file.as_fd().try_clone_to_owned(),
        }
        .map_err(Error::Io)?;
        Ok(File::from(fd).metadata().map_err(Error::Io)?.rdev())
    }

    /// A buffered read-write handle on the same claimed device, for writers
    /// such as the GPT crate that need a `File` (see [`reopen_buffered`]).
    ///
    /// # Errors
    /// Propagates the reopen failure.
    pub fn buffered_handle(&self) -> Result<File> {
        match &self.handle {
            Handle::Direct(fd) => reopen_buffered(fd.as_raw_fd(), true),
            Handle::Buffered(file) => file.try_clone().map_err(Error::Io),
        }
    }

    fn finish(handle: Handle, path: &Path) -> Result<Self> {
        Ok(Self {
            handle,
            size_bytes: device_size(path)?,
            logical_block_size: lr_unsafe::block_device_logical_sector_size(path).unwrap_or(512),
            alignment: alignment_for(path),
        })
    }

    /// Target size in bytes.
    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    /// Alignment required for buffers used with this target.
    #[must_use]
    pub const fn alignment(&self) -> usize {
        self.alignment
    }

    /// Allocate a buffer of `len` zeroed bytes suitable for this target.
    ///
    /// # Errors
    /// Propagates allocation failures.
    pub fn buffer(&self, len: usize) -> Result<AlignedBuf> {
        AlignedBuf::new(len, self.alignment).map_err(Error::Io)
    }

    /// Write `len` bytes from the front of `buf` at `offset`.
    ///
    /// `len` may be shorter than the buffer, which is how the final short
    /// chunk of a restore is written without a second allocation.
    ///
    /// # Errors
    /// Returns [`Error::NoSpace`] past the end of the target,
    /// [`Error::Unsupported`] for an unaligned direct write, and
    /// [`Error::Io`] for write failures.
    pub fn write_at(&mut self, offset: u64, buf: &AlignedBuf, len: usize) -> Result<()> {
        if len == 0 {
            return Ok(());
        }
        if len > buf.len() {
            return Err(Error::unsupported(format!(
                "{len} bytes requested from a {}-byte buffer",
                buf.len()
            )));
        }
        if offset + len as u64 > self.size_bytes {
            return Err(Error::NoSpace);
        }
        match &self.handle {
            Handle::Direct(fd) => {
                if buf.alignment() < self.alignment {
                    return Err(Error::unsupported(format!(
                        "unaligned direct write of {len} bytes (alignment {}, sector {})",
                        self.alignment, self.logical_block_size
                    )));
                }
                if !len.is_multiple_of(self.alignment) {
                    // The same end-of-partition case as the reader: padding the
                    // write would clobber the bytes after the chunk, so the
                    // unaligned tail is written buffered (D-097).
                    tracing::debug!(offset, len, "writing an unaligned tail without O_DIRECT");
                    let file = reopen_buffered(fd.as_raw_fd(), true)?;
                    return file
                        .write_all_at(&buf.as_slice()[..len], offset)
                        .map_err(Error::Io);
                }
                lr_unsafe::pwrite_all(fd, buf, len, offset).map_err(Error::Io)
            }
            Handle::Buffered(file) => file
                .write_all_at(&buf.as_slice()[..len], offset)
                .map_err(Error::Io),
        }
    }

    /// Flush the target to stable storage.
    ///
    /// # Errors
    /// Propagates `fsync` failures.
    pub fn sync(&mut self) -> Result<()> {
        match &self.handle {
            Handle::Direct(fd) => lr_unsafe::fsync(fd).map_err(Error::Io),
            Handle::Buffered(file) => file.sync_all().map_err(Error::Io),
        }
    }

    /// Raw descriptor, for callers that need `ioctl`/`fstat` on the target.
    #[must_use]
    pub fn raw_fd(&self) -> Option<std::os::fd::RawFd> {
        match &self.handle {
            Handle::Direct(fd) => Some(fd.as_raw_fd()),
            Handle::Buffered(file) => Some(file.as_raw_fd()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DirectBlockSource, DirectBlockTarget, IoMode};
    use crate::BlockSource;

    fn scratch(dir: &std::path::Path, name: &str, size: u64) -> std::path::PathBuf {
        let path = dir.join(name);
        let file = std::fs::File::create(&path).expect("create");
        file.set_len(size).expect("size");
        drop(file);
        path
    }

    #[test]
    fn an_alignment_is_at_least_a_page() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = scratch(dir.path(), "dev.img", 64 * 1024);
        let source = DirectBlockSource::open_buffered(&path).expect("open");
        assert!(source.alignment() >= super::MIN_ALIGNMENT);
        assert_eq!(source.size_bytes(), 64 * 1024);
        assert_eq!(source.logical_block_size(), 512);
    }

    #[test]
    fn buffered_round_trip_through_a_target() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = scratch(dir.path(), "dev.img", 16 * 1024);
        let mut target = DirectBlockTarget::open_buffered(&path).expect("open target");
        let mut data = target.buffer(4096).expect("buffer");
        data.as_mut_slice().fill(0xab);
        target.write_at(4096, &data, 4096).expect("write");
        target.sync().expect("sync");
        drop(target);

        let mut source = DirectBlockSource::open_buffered(&path).expect("open source");
        let mut read = source.buffer(4096).expect("buffer");
        let len = read.len();
        let got = source.read_at(4096, &mut read, len).expect("read");
        assert_eq!(got, 4096);
        assert!(read.as_slice().iter().all(|byte| *byte == 0xab));
        let len = read.len();
        assert_eq!(source.read_at(16 * 1024, &mut read, len).expect("eof"), 0);
    }

    #[test]
    fn a_write_past_the_end_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = scratch(dir.path(), "dev.img", 8192);
        let mut target = DirectBlockTarget::open_buffered(&path).expect("open");
        let buffer = target.buffer(8192).expect("buffer");
        assert!(matches!(
            target.write_at(1, &buffer, 8192),
            Err(lr_core::Error::NoSpace)
        ));
        assert!(matches!(
            target.write_at(0, &buffer, 9000),
            Err(lr_core::Error::Unsupported { .. })
        ));
    }

    #[test]
    fn io_mode_is_explicit() {
        assert_ne!(IoMode::Direct, IoMode::Buffered);
    }

    #[test]
    fn the_direct_path_reports_its_own_failures() {
        // /dev/null cannot be read with O_DIRECT; the error must be typed.
        let error = match DirectBlockSource::open(std::path::Path::new("/dev/null")) {
            Err(error) => error,
            Ok(source) => panic!(
                "unexpectedly opened /dev/null (direct: {})",
                source.is_direct()
            ),
        };
        assert!(
            matches!(
                error,
                lr_core::Error::Unsupported { .. } | lr_core::Error::Io(_)
            ),
            "{error}"
        );
    }
}
