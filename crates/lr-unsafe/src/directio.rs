//! Positioned reads and writes for `O_DIRECT` file descriptors.
//!
//! `pread`/`pwrite` never touch the file offset, which keeps concurrent chunk
//! reads and restores independent of each other. Every call takes an
//! [`AlignedBuf`] so the alignment requirement of the file descriptor cannot be
//! violated by a caller.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};

use crate::aligned::AlignedBuf;

/// Read `len` bytes into the front of `buf` at `offset`.
///
/// `len` may be shorter than the buffer, which is how the final short chunk of
/// a device is read without allocating a second buffer. Returns the number of
/// bytes read, which is short only at end of file.
///
/// # Errors
/// Returns [`io::ErrorKind::InvalidInput`] when `len` exceeds the buffer, and
/// propagates `pread(2)` failures.
pub fn pread_into(
    fd: &OwnedFd,
    buf: &mut AlignedBuf,
    len: usize,
    offset: u64,
) -> io::Result<usize> {
    if len > buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{len} bytes requested from a {}-byte buffer", buf.len()),
        ));
    }
    // SAFETY: `pread` writes at most `len` bytes into a buffer that owns `len`
    // initialized bytes; the descriptor stays open for the call.
    let read = unsafe {
        libc::pread(
            fd.as_raw_fd(),
            buf.as_mut_slice().as_mut_ptr().cast(),
            len,
            offset as libc::off_t,
        )
    };
    if read < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(read as usize)
}

/// Write `len` bytes from the front of `buf` at `offset`, retrying short writes.
///
/// # Errors
/// Returns [`io::ErrorKind::InvalidInput`] when `len` exceeds the buffer, and
/// propagates `pwrite(2)` failures.
pub fn pwrite_all(fd: &OwnedFd, buf: &AlignedBuf, len: usize, offset: u64) -> io::Result<()> {
    if len > buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{len} bytes requested from a {}-byte buffer", buf.len()),
        ));
    }
    let mut written = 0usize;
    while written < len {
        let slice = &buf.as_slice()[written..len];
        // SAFETY: the pointer and length come from an owned buffer, and the
        // descriptor stays open for the call.
        let n = unsafe {
            libc::pwrite(
                fd.as_raw_fd(),
                slice.as_ptr().cast(),
                slice.len(),
                (offset + written as u64) as libc::off_t,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "pwrite wrote no bytes",
            ));
        }
        written += n as usize;
    }
    Ok(())
}

/// `fsync(2)` a descriptor.
///
/// # Errors
/// Propagates `fsync(2)` failures.
pub fn fsync(fd: &OwnedFd) -> io::Result<()> {
    // SAFETY: `fsync` only inspects the descriptor.
    if unsafe { libc::fsync(fd.as_raw_fd()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
