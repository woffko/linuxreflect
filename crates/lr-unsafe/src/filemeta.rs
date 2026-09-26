//! File-mode plumbing (spec §K S12): sparse detection, extended attributes,
//! device nodes and timestamp/ownership changes that never follow a symlink.
//!
//! This module is split out of `lib.rs` because file mode needs a wider set of
//! syscalls than block mode. Every entry point here is a thin, safe wrapper
//! around one libc call; the `SAFETY:` comments state the invariants.

use std::ffi::CString;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// The next offset with data at or after `offset`, or `None` at end of file.
///
/// `SEEK_DATA` is how file mode detects sparse regions (spec §F, §K S12).
///
/// # Errors
/// Returns the raw `lseek` error, except that `ENXIO` (past the last data
/// extent) becomes `Ok(None)`. `EINVAL` or `ENOTSUP` from a file that does
/// not support the call is an error, never "no more data": the caller must
/// then treat the whole file as data (R03).
pub fn seek_data(fd: &impl AsRawFd, offset: u64) -> io::Result<Option<u64>> {
    seek(fd, offset, libc::SEEK_DATA)
}

/// The next offset at or after `offset` that is a hole, or `None` at EOF.
///
/// # Errors
/// Returns the raw `lseek` error, except that `ENXIO` becomes `Ok(None)`.
pub fn seek_hole(fd: &impl AsRawFd, offset: u64) -> io::Result<Option<u64>> {
    seek(fd, offset, libc::SEEK_HOLE)
}

fn seek(fd: &impl AsRawFd, offset: u64, whence: libc::c_int) -> io::Result<Option<u64>> {
    let raw = fd.as_raw_fd();
    // SAFETY: `raw` is a valid descriptor owned by the caller for the duration
    // of the call, and `lseek` has no memory arguments.
    let result = unsafe { libc::lseek(raw, i64::try_from(offset).unwrap_or(i64::MAX), whence) };
    if result >= 0 {
        return Ok(Some(result as u64));
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        // Only ENXIO means "past the last data extent". An unsupported call
        // (EINVAL, ENOTSUP) carries no hole information at all; reporting it
        // as `None` made the caller record the rest of the file as a hole.
        Some(libc::ENXIO) => Ok(None),
        _ => Err(error),
    }
}

/// List the extended attribute names of a path, never following symlinks.
///
/// # Errors
/// Returns the raw `llistxattr` error.
pub fn list_xattrs(path: &Path) -> io::Result<Vec<Vec<u8>>> {
    let path = c_path(path)?;
    loop {
        // SAFETY: `path` is a valid NUL-terminated C string; a null buffer with
        // size 0 asks only for the required length.
        let size = unsafe { libc::llistxattr(path.as_ptr(), std::ptr::null_mut(), 0) };
        if size < 0 {
            return Err(io::Error::last_os_error());
        }
        if size == 0 {
            return Ok(Vec::new());
        }
        let mut buffer = vec![0u8; size as usize];
        // SAFETY: `buffer` is writable for exactly the size passed.
        let written = unsafe {
            libc::llistxattr(
                path.as_ptr(),
                buffer.as_mut_ptr().cast::<libc::c_char>(),
                buffer.len(),
            )
        };
        if written < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ERANGE) {
                continue;
            }
            return Err(error);
        }
        buffer.truncate(written as usize);
        return Ok(buffer
            .split(|byte| *byte == 0)
            .filter(|name| !name.is_empty())
            .map(<[u8]>::to_vec)
            .collect());
    }
}

/// Read one extended attribute of a path, never following symlinks.
///
/// # Errors
/// Returns the raw `lgetxattr` error.
pub fn get_xattr(path: &Path, name: &[u8]) -> io::Result<Vec<u8>> {
    let path_c = c_path(path)?;
    let name_c = c_bytes(name)?;
    loop {
        // SAFETY: both pointers are valid NUL-terminated C strings.
        let size =
            unsafe { libc::lgetxattr(path_c.as_ptr(), name_c.as_ptr(), std::ptr::null_mut(), 0) };
        if size < 0 {
            return Err(io::Error::last_os_error());
        }
        if size == 0 {
            return Ok(Vec::new());
        }
        let mut buffer = vec![0u8; size as usize];
        // SAFETY: `buffer` is writable for exactly the size passed.
        let written = unsafe {
            libc::lgetxattr(
                path_c.as_ptr(),
                name_c.as_ptr(),
                buffer.as_mut_ptr().cast::<libc::c_void>(),
                buffer.len(),
            )
        };
        if written < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ERANGE) {
                continue;
            }
            return Err(error);
        }
        buffer.truncate(written as usize);
        return Ok(buffer);
    }
}

/// Write one extended attribute of a path, never following symlinks.
///
/// # Errors
/// Returns the raw `lsetxattr` error.
pub fn set_xattr(path: &Path, name: &[u8], value: &[u8]) -> io::Result<()> {
    let path_c = c_path(path)?;
    let name_c = c_bytes(name)?;
    // SAFETY: the pointers are valid for the lengths passed, and `value` is
    // only read.
    let result = unsafe {
        libc::lsetxattr(
            path_c.as_ptr(),
            name_c.as_ptr(),
            value.as_ptr().cast::<libc::c_void>(),
            value.len(),
            0,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Create a filesystem object at `path` (device node, FIFO or socket).
///
/// # Errors
/// Returns the raw `mknod` error, including `EPERM` when not privileged.
pub fn mknod(path: &Path, mode: u32, device: u64) -> io::Result<()> {
    let path_c = c_path(path)?;
    // SAFETY: `path_c` is a valid NUL-terminated C string; `mknod` has no
    // pointer output.
    let result = unsafe { libc::mknod(path_c.as_ptr(), mode as libc::mode_t, device) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Change the owner of a path without following a final symlink.
///
/// # Errors
/// Returns the raw `lchown` error.
pub fn lchown(path: &Path, uid: u32, gid: u32) -> io::Result<()> {
    let path_c = c_path(path)?;
    // SAFETY: `path_c` is a valid NUL-terminated C string.
    let result = unsafe { libc::lchown(path_c.as_ptr(), uid, gid) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Set atime and mtime of a path without following a final symlink.
///
/// # Errors
/// Returns the raw `utimensat` error.
pub fn set_times_nofollow(
    path: &Path,
    atime_sec: i64,
    atime_nsec: u32,
    mtime_sec: i64,
    mtime_nsec: u32,
) -> io::Result<()> {
    let path_c = c_path(path)?;
    let times = [
        libc::timespec {
            tv_sec: atime_sec,
            tv_nsec: i64::from(atime_nsec),
        },
        libc::timespec {
            tv_sec: mtime_sec,
            tv_nsec: i64::from(mtime_nsec),
        },
    ];
    // SAFETY: `path_c` is a valid C string and `times` is a 2-element array as
    // required by `utimensat`. `AT_SYMLINK_NOFOLLOW` makes the call set the
    // link's own timestamps instead of the target's.
    let result = unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            path_c.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Deallocate a byte range inside a file, turning it into a hole.
///
/// Used by file-mode restore to recreate sparse files. A filesystem that does
/// not support hole punching reports `EOPNOTSUPP`/`EINVAL`; callers treat that
/// as "the file is simply fully allocated", which is still correct.
///
/// # Errors
/// Returns the raw `fallocate` error.
pub fn punch_hole(fd: &impl AsRawFd, offset: u64, len: u64) -> io::Result<()> {
    let raw = fd.as_raw_fd();
    // SAFETY: `raw` is a valid descriptor owned by the caller; `fallocate` has
    // no pointer arguments.
    let result = unsafe {
        libc::fallocate(
            raw,
            libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
            i64::try_from(offset).unwrap_or(i64::MAX),
            i64::try_from(len).unwrap_or(i64::MAX),
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Free and total bytes of the filesystem holding `path`.
///
/// File-mode restores go into an existing filesystem, so the space check is
/// "free bytes >= content bytes" rather than a device size comparison.
///
/// # Errors
/// Returns the raw `statvfs` error, and an error when a count does not fit in
/// `u64`.
pub fn statvfs_bytes(path: &Path) -> io::Result<(u64, u64)> {
    let path_c = c_path(path)?;
    // SAFETY: `path_c` is a valid C string and `stat` is a zeroed struct that
    // `statvfs` fills in completely.
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: both pointers are valid for the duration of the call.
    let result = unsafe { libc::statvfs(path_c.as_ptr(), &mut stat) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    let fragment = if stat.f_frsize == 0 {
        stat.f_bsize
    } else {
        stat.f_frsize
    };
    let fragment = u128::from(fragment);
    let free = (stat.f_bavail as u128)
        .checked_mul(fragment)
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(|| io::Error::other("statvfs free bytes overflow"))?;
    let total = (stat.f_blocks as u128)
        .checked_mul(fragment)
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(|| io::Error::other("statvfs total bytes overflow"))?;
    Ok((free, total))
}

/// True when `punch_hole`'s failure means "unsupported on this filesystem".
#[must_use]
pub fn punch_hole_unsupported(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EOPNOTSUPP | libc::ENOSYS | libc::EINVAL)
    )
}

fn c_path(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes().to_vec())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))
}

fn c_bytes(value: &[u8]) -> io::Result<CString> {
    CString::new(value)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "value contains a NUL byte"))
}

#[cfg(test)]
mod tests {
    use super::{
        get_xattr, list_xattrs, mknod, punch_hole, seek_data, seek_hole, set_times_nofollow,
        set_xattr, statvfs_bytes,
    };
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    #[test]
    fn sparse_files_report_their_holes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sparse.bin");
        let file = std::fs::File::create(&path).expect("create");
        file.set_len(4 * 1024 * 1024).expect("size");
        drop(file);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .open(&path)
            .expect("open");
        // A freshly sized file is one big hole, so seeking to data reaches EOF.
        assert_eq!(seek_hole(&file, 0).expect("hole"), Some(0));
        assert_eq!(seek_data(&file, 0).expect("data"), None);
    }

    #[test]
    fn an_unsupported_seek_is_an_error_not_the_end_of_data() {
        // procfs files are seq_files, whose lseek refuses SEEK_DATA with
        // EINVAL although they have content (R03).
        let file = std::fs::File::open("/proc/self/status").expect("open procfs");
        let error = seek_data(&file, 0).expect_err("SEEK_DATA is unsupported on procfs");
        assert_eq!(error.raw_os_error(), Some(libc::EINVAL), "{error}");
        let error = seek_hole(&file, 0).expect_err("SEEK_HOLE is unsupported on procfs");
        assert_eq!(error.raw_os_error(), Some(libc::EINVAL), "{error}");
    }

    #[test]
    fn attributes_round_trip_and_missing_names_fail() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("xattr.bin");
        std::fs::write(&path, b"hello").expect("write");
        set_xattr(&path, b"user.lrtest", b"value").expect("setxattr");
        assert_eq!(
            get_xattr(&path, b"user.lrtest").expect("getxattr"),
            b"value"
        );
        let names = list_xattrs(&path).expect("listxattr");
        assert!(names.iter().any(|name| name == b"user.lrtest"));
        assert!(get_xattr(&path, b"user.absent").is_err());
    }

    #[test]
    fn symlink_timestamps_are_set_on_the_link_itself() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("target");
        std::fs::write(&target, b"data").expect("write");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink("target", &link).expect("symlink");
        set_times_nofollow(&link, 1_600_000_000, 0, 1_600_000_000, 0).expect("utimensat");
        let link_time = std::fs::symlink_metadata(&link).expect("stat").mtime();
        let target_time = std::fs::metadata(&target).expect("stat").mtime();
        assert_eq!(link_time, 1_600_000_000, "the link's own time changed");
        assert_ne!(
            target_time, 1_600_000_000,
            "the target must not have been touched"
        );
    }

    #[test]
    fn filesystem_space_is_reported() {
        let (free, total) = statvfs_bytes(Path::new("/")).expect("statvfs");
        assert!(total > 0);
        assert!(free <= total);
    }

    #[test]
    fn device_nodes_can_be_created_when_privileged() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("null");
        let mode = libc::S_IFCHR | 0o666;
        match mknod(&path, mode, libc::makedev(1, 3)) {
            Ok(()) => {
                let metadata = std::fs::symlink_metadata(&path).expect("stat");
                assert_eq!(metadata.rdev(), libc::makedev(1, 3));
            }
            Err(error) => {
                lr_testkit::report_unavailable(&format!("mknod needs privileges: {error}"));
            }
        }
    }

    #[test]
    fn timestamps_and_hole_punching_are_best_effort() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("time.bin");
        std::fs::write(&path, b"0123456789").expect("write");
        set_times_nofollow(&path, 1_600_000_000, 0, 1_600_000_000, 0).expect("utimensat");
        let metadata = std::fs::metadata(&path).expect("stat");
        assert_eq!(metadata.mtime(), 1_600_000_000);

        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open");
        match punch_hole(&file, 0, 4) {
            Ok(()) => {
                // Only the punched range reads back as zeros; the tail is
                // untouched, which is what a sparse file must look like.
                let bytes = std::fs::read(&path).expect("read");
                assert_eq!(bytes, vec![0, 0, 0, 0, b'4', b'5', b'6', b'7', b'8', b'9']);
            }
            Err(error) if super::punch_hole_unsupported(&error) => {
                eprintln!("hole punching unsupported here: {error}");
            }
            Err(error) => panic!("punch_hole failed: {error}"),
        }
    }
}
