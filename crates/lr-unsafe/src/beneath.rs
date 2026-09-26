//! Path resolution confined beneath a pinned directory (R06, R14).
//!
//! A restore writes an image's paths below an approved directory, and a
//! file-mode backup reads a live tree below its root. Joining path strings and
//! calling path-based syscalls lets a symlink in any ancestor, planted in the
//! image, already present in a merge target, or swapped in while a live walk
//! runs, redirect the operation outside that directory.
//!
//! [`open_dir_beneath`] resolves a relative directory path from a pinned
//! directory descriptor with `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)`,
//! falling back on kernels older than 5.6 to a walk that opens one component
//! at a time with `O_NOFOLLOW`. [`entry_path`] then names one entry of that
//! directory as `/proc/self/fd/<dir>/<name>`: the kernel resolves the magic
//! link to exactly the pinned directory, and `name` is a single component, so
//! a syscall that does not follow its final component cannot leave the
//! directory.

use std::ffi::{CString, OsStr};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// `struct open_how` of `openat2(2)`; `libc::open_how` cannot be built
/// outside its crate.
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// Open a directory, following the path as given, as the pinned root of a
/// confined walk.
///
/// # Errors
/// Returns the raw `open` error; `ENOTDIR` when the path is not a directory.
pub fn open_root(path: &Path) -> io::Result<OwnedFd> {
    let cpath = c_path(path.as_os_str())?;
    // SAFETY: `cpath` is a valid NUL-terminated C string and the flags take no
    // mode argument; the returned descriptor is wrapped immediately.
    let fd = unsafe {
        libc::open(
            cpath.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a freshly opened descriptor owned by us.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Split `relative` into its normal components, refusing anything else.
///
/// # Errors
/// Returns `InvalidInput` for an absolute path, `.`, `..` or an empty
/// component.
pub fn normal_components(relative: &Path) -> io::Result<Vec<&OsStr>> {
    // Byte-wise: `Path::components` silently drops `.` segments and
    // repeated separators, which would hide a malformed manifest path.
    let bytes = relative.as_os_str().as_bytes();
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    bytes
        .split(|byte| *byte == b'/')
        .map(|name| match name {
            b"" | b"." | b".." => Err(invalid(relative)),
            name => Ok(OsStr::from_bytes(name)),
        })
        .collect()
}

fn invalid(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "{} is not a plain relative path below the root",
            path.display()
        ),
    )
}

/// Open the directory `relative` beneath `root` without following any
/// symlink, as an `O_PATH` descriptor. An empty path opens `root` itself.
///
/// # Errors
/// Returns `InvalidInput` for a path that is not plain and relative, `ELOOP`
/// or `ENOTDIR` when a component is a symlink or not a directory, `EXDEV`
/// when resolution would leave `root`, and other raw errors.
pub fn open_dir_beneath(root: &impl AsRawFd, relative: &Path) -> io::Result<OwnedFd> {
    let components = normal_components(relative)?;
    if components.is_empty() {
        return reopen_path(root.as_raw_fd(), c".");
    }
    let cpath = c_path(relative.as_os_str())?;
    let how = OpenHow {
        flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS,
    };
    // SAFETY: `root` is a valid descriptor for the duration of the call,
    // `cpath` is NUL-terminated, and `how` is a live `open_how` whose size is
    // passed alongside it.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root.as_raw_fd(),
            cpath.as_ptr(),
            std::ptr::from_ref(&how),
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd >= 0 {
        // SAFETY: `fd` is a freshly opened descriptor owned by us.
        return Ok(unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) });
    }
    let error = io::Error::last_os_error();
    if !matches!(error.raw_os_error(), Some(libc::ENOSYS | libc::EPERM)) {
        return Err(error);
    }
    // No openat2 (Linux < 5.6, or a seccomp filter): one component at a time,
    // each opened with O_NOFOLLOW so a symlink fails with ELOOP/ENOTDIR.
    let mut current = reopen_path(root.as_raw_fd(), c".")?;
    for component in components {
        let name = c_path(component)?;
        current = reopen_path(current.as_raw_fd(), &name)?;
    }
    Ok(current)
}

fn reopen_path(dir: libc::c_int, name: &std::ffi::CStr) -> io::Result<OwnedFd> {
    // SAFETY: `dir` is a valid descriptor, `name` is NUL-terminated, and the
    // flags take no mode argument.
    let fd = unsafe {
        libc::openat(
            dir,
            name.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a freshly opened descriptor owned by us.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The path of `name` inside the pinned directory `dir`.
///
/// Only syscalls that do not follow their final component may use it for an
/// entry that could be a symlink.
///
/// # Errors
/// Returns `InvalidInput` when `name` is not one plain component.
pub fn entry_path(dir: &impl AsRawFd, name: &OsStr) -> io::Result<PathBuf> {
    if name.is_empty() || name == "." || name == ".." || name.as_bytes().contains(&b'/') {
        return Err(invalid(Path::new(name)));
    }
    Ok(PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd())).join(name))
}

/// The path of the pinned directory `dir` itself, for calls on the directory.
#[must_use]
pub fn self_path(dir: &impl AsRawFd) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}/.", dir.as_raw_fd()))
}

/// The path of an open object (any type) that follows to exactly that
/// object, for the few calls that always follow, such as `chmod`.
#[must_use]
pub fn object_path(object: &impl AsRawFd) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", object.as_raw_fd()))
}

fn c_path(value: &OsStr) -> io::Result<CString> {
    CString::new(value.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))
}

#[cfg(test)]
mod tests {
    use super::{entry_path, normal_components, open_dir_beneath, open_root};
    use std::ffi::OsStr;
    use std::path::Path;

    #[test]
    fn only_plain_relative_paths_are_accepted() {
        assert_eq!(normal_components(Path::new("a/b")).expect("plain").len(), 2);
        assert!(normal_components(Path::new("")).expect("empty").is_empty());
        for bad in ["/etc", "../x", "a/../b", "a/./b", "a//b", "a/", "."] {
            assert!(normal_components(Path::new(bad)).is_err(), "{bad}");
        }
        assert!(entry_path(&std::io::stdin(), OsStr::new("a/b")).is_err());
        assert!(entry_path(&std::io::stdin(), OsStr::new("..")).is_err());
    }

    #[test]
    fn a_symlinked_ancestor_is_not_followed() {
        let outside = tempfile::tempdir().expect("outside");
        let root = tempfile::tempdir().expect("root");
        std::fs::create_dir(root.path().join("real")).expect("dir");
        std::os::unix::fs::symlink(outside.path(), root.path().join("link")).expect("symlink");
        let pinned = open_root(root.path()).expect("root");
        assert!(open_dir_beneath(&pinned, Path::new("real")).is_ok());
        let error = open_dir_beneath(&pinned, Path::new("link")).expect_err("a symlink");
        assert!(
            matches!(
                error.raw_os_error(),
                Some(libc::ELOOP | libc::ENOTDIR | libc::EXDEV)
            ),
            "{error}"
        );
        assert!(open_dir_beneath(&pinned, Path::new("../x")).is_err());
    }

    #[test]
    fn entries_of_a_pinned_directory_stay_in_it() {
        let root = tempfile::tempdir().expect("root");
        std::fs::create_dir(root.path().join("dir")).expect("dir");
        let pinned = open_root(root.path()).expect("root");
        let dir = open_dir_beneath(&pinned, Path::new("dir")).expect("dir");
        std::fs::write(entry_path(&dir, OsStr::new("file")).expect("path"), b"x").expect("write");
        assert_eq!(
            std::fs::read(root.path().join("dir/file")).expect("read"),
            b"x"
        );
        // Renaming the directory does not move later writes: they follow the
        // pinned descriptor, not the name.
        std::fs::rename(root.path().join("dir"), root.path().join("moved")).expect("rename");
        std::fs::create_dir(root.path().join("dir")).expect("new dir");
        std::fs::write(entry_path(&dir, OsStr::new("second")).expect("path"), b"y").expect("write");
        assert!(root.path().join("moved/second").exists());
        assert!(!root.path().join("dir/second").exists());
    }
}
