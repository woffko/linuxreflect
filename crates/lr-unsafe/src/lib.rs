//! Raw Linux plumbing for LinuxReflect.
//!
//! This is the **only** crate in the workspace permitted to contain `unsafe`
//! code (`unsafe_code` is `forbid` everywhere else). It exposes a small,
//! auditable surface of block-device ioctls and process syscalls.
//!
//! Every public item here must be justified by a spec requirement:
//!
//! * `BLKGETSIZE64`, `BLKSSZGET` — device geometry (spec §B, §C).
//! * `FIFREEZE` / `FITHAW` — freeze provider (spec §E.4).
//! * `pidfd_open` — polkit peer identity hardening (spec §I).
//! * `SEEK_DATA`/`SEEK_HOLE`, xattrs, `mknod`, `utimensat`, hole punching —
//!   file mode (spec §K S12).
#![deny(unsafe_op_in_unsafe_fn)]

pub mod aligned;
pub mod directio;
pub mod filemeta;

pub use aligned::AlignedBuf;
pub use directio::{fsync, pread_into, pwrite_all};

use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// `_IOC` encoding constants, mirroring `include/uapi/asm-generic/ioctl.h`.
mod ioc {
    pub(crate) const NRBITS: u32 = 8;
    pub(crate) const TYPEBITS: u32 = 8;
    pub(crate) const SIZEBITS: u32 = 14;

    pub(crate) const NRSHIFT: u32 = 0;
    pub(crate) const TYPESHIFT: u32 = NRSHIFT + NRBITS;
    pub(crate) const SIZESHIFT: u32 = TYPESHIFT + TYPEBITS;
    pub(crate) const DIRSHIFT: u32 = SIZESHIFT + SIZEBITS;

    pub(crate) const NONE: u32 = 0;
    pub(crate) const WRITE: u32 = 1;
    pub(crate) const READ: u32 = 2;

    pub(crate) const IOR: u32 = READ;
    pub(crate) const IOWR: u32 = READ | WRITE;

    /// Encode a `_IOC` request number at compile time.
    pub(crate) const fn encode(dir: u32, ty: u32, nr: u32, size: u32) -> libc::c_ulong {
        ((dir << DIRSHIFT) | (ty << TYPESHIFT) | (nr << NRSHIFT) | (size << SIZESHIFT))
            as libc::c_ulong
    }
}

/// `BLKGETSIZE64`, `_IOR(0x12, 114, size_t)`.
pub const BLKGETSIZE64: libc::c_ulong =
    ioc::encode(ioc::IOR, 0x12, 114, std::mem::size_of::<u64>() as u32);

/// `BLKSSZGET`, `_IO(0x12, 104)` — logical sector size as `c_int`.
pub const BLKSSZGET: libc::c_ulong = ioc::encode(ioc::NONE, 0x12, 104, 0);

/// `BLKPBSZGET`, `_IO(0x12, 123)` — physical sector size as `c_int`.
pub const BLKPBSZGET: libc::c_ulong = ioc::encode(ioc::NONE, 0x12, 123, 0);

/// `FIFREEZE`, `_IOWR('X', 119, int)` — freeze a mounted filesystem.
pub const FIFREEZE: libc::c_ulong = ioc::encode(
    ioc::IOWR,
    b'X' as u32,
    119,
    std::mem::size_of::<libc::c_int>() as u32,
);

/// `FITHAW`, `_IOWR('X', 120, int)` — thaw a mounted filesystem.
pub const FITHAW: libc::c_ulong = ioc::encode(
    ioc::IOWR,
    b'X' as u32,
    120,
    std::mem::size_of::<libc::c_int>() as u32,
);

fn last_os_error() -> io::Error {
    io::Error::last_os_error()
}

/// Return the size in bytes of a block device via `BLKGETSIZE64`.
pub fn block_device_size_bytes(dev: &std::path::Path) -> io::Result<u64> {
    let file = File::open(dev)?;
    let fd = file.as_raw_fd();
    let mut size: u64 = 0;
    // SAFETY: `fd` is a valid open descriptor for the lifetime of `file`, and
    // `BLKGETSIZE64` writes exactly one `u64` into the pointed-to buffer.
    // `as _` because glibc types the request as `c_ulong` and musl as `c_int`;
    // the value is the same bit pattern either way.
    let rc = unsafe { libc::ioctl(fd, BLKGETSIZE64 as _, &mut size) };
    if rc < 0 {
        return Err(last_os_error());
    }
    Ok(size)
}

/// Return the logical sector size in bytes of a block device via `BLKSSZGET`.
pub fn block_device_logical_sector_size(dev: &std::path::Path) -> io::Result<u32> {
    let file = File::open(dev)?;
    let fd = file.as_raw_fd();
    let mut size: libc::c_int = 0;
    // SAFETY: `fd` is valid and `BLKSSZGET` writes exactly one `c_int`.
    let rc = unsafe { libc::ioctl(fd, BLKSSZGET as _, &mut size) };
    if rc < 0 {
        return Err(last_os_error());
    }
    Ok(u32::try_from(size).unwrap_or(0))
}

/// Return the physical sector size in bytes of a block device via `BLKPBSZGET`.
pub fn block_device_physical_sector_size(dev: &std::path::Path) -> io::Result<u32> {
    let file = File::open(dev)?;
    let fd = file.as_raw_fd();
    let mut size: libc::c_int = 0;
    // SAFETY: `fd` is valid and `BLKPBSZGET` writes exactly one `c_int`.
    let rc = unsafe { libc::ioctl(fd, BLKPBSZGET as _, &mut size) };
    if rc < 0 {
        return Err(last_os_error());
    }
    Ok(u32::try_from(size).unwrap_or(0))
}

/// Freeze the filesystem mounted at an open directory descriptor (`FIFREEZE`).
///
/// The caller keeps ownership of `dir`; the ioctl does not take a reference.
pub fn freeze_fs(dir: &OwnedFd) -> io::Result<()> {
    // SAFETY: `FIFREEZE` takes an `int` argument and a valid directory fd; no
    // memory is written through the argument.
    let rc = unsafe { libc::ioctl(dir.as_raw_fd(), FIFREEZE as _, 0 as libc::c_int) };
    if rc < 0 { Err(last_os_error()) } else { Ok(()) }
}

/// Thaw the filesystem mounted at an open directory descriptor (`FITHAW`).
pub fn thaw_fs(dir: &OwnedFd) -> io::Result<()> {
    // SAFETY: see `freeze_fs`.
    let rc = unsafe { libc::ioctl(dir.as_raw_fd(), FITHAW as _, 0 as libc::c_int) };
    if rc < 0 { Err(last_os_error()) } else { Ok(()) }
}

/// Probe whether the running kernel supports `FIFREEZE`/`FITHAW`.
///
/// This is deliberately non-destructive: `FITHAW` on an *unfrozen* filesystem
/// returns `EINVAL` when the ioctl exists and `ENOTTY` when it does not.
pub fn fs_freeze_supported(dir: &OwnedFd) -> bool {
    match thaw_fs(dir) {
        Ok(()) => true,
        Err(e) => e.raw_os_error() != Some(libc::ENOTTY),
    }
}

/// Open a directory read-only for freeze probing.
pub fn open_dir_readonly(path: &std::path::Path) -> io::Result<OwnedFd> {
    let file = File::open(path)?;
    Ok(OwnedFd::from(file))
}

/// Open a file with `O_DIRECT`, returning an error when unsupported.
pub fn open_o_direct(path: &std::path::Path, write: bool) -> io::Result<OwnedFd> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let cpath = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let mut flags = libc::O_DIRECT | libc::O_CLOEXEC;
    flags |= if write { libc::O_RDWR } else { libc::O_RDONLY };
    // SAFETY: `cpath` is a valid NUL-terminated C string, `flags` is a valid
    // open(2) flag set, and the returned descriptor is immediately wrapped.
    let fd = unsafe { libc::open(cpath.as_ptr(), flags) };
    if fd < 0 {
        return Err(last_os_error());
    }
    // SAFETY: `fd` is a freshly opened descriptor owned by us.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Open a process file descriptor via `pidfd_open(2)`.
///
/// Returns `Ok(None)` when the kernel does not implement `pidfd_open`
/// (`ENOSYS`); other errors are propagated.
pub fn pidfd_open(pid: u32) -> io::Result<Option<OwnedFd>> {
    // SAFETY: `pidfd_open` takes two scalar arguments and returns a new fd.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0 as libc::c_uint) };
    if fd < 0 {
        let err = last_os_error();
        if err.raw_os_error() == Some(libc::ENOSYS) {
            return Ok(None);
        }
        return Err(err);
    }
    // SAFETY: `fd` is a fresh descriptor owned by us.
    Ok(Some(unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) }))
}

/// Open a file read-only, refusing to follow a final symlink.
///
/// `O_NOFOLLOW` is what makes the passphrase-file checks meaningful (spec
/// §L.1): a symlink in a world-writable directory must not be able to redirect
/// a root daemon to another file.
///
/// # Errors
/// Propagates `open(2)` failures, including `ELOOP` for a symlink.
pub fn open_readonly_nofollow(path: &std::path::Path) -> io::Result<OwnedFd> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let cpath = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    // SAFETY: `cpath` is a valid NUL-terminated string and the flags are a
    // valid `open(2)` set; the returned descriptor is wrapped immediately.
    let fd = unsafe {
        libc::open(
            cpath.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a freshly opened descriptor owned by us.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `st_mode` of an open descriptor.
///
/// # Errors
/// Propagates `fstat(2)` failures.
pub fn fd_mode(fd: &OwnedFd) -> io::Result<u32> {
    // SAFETY: `fstat` fills a plain struct; zeroed is a valid initial value.
    let stat = unsafe {
        let mut stat: libc::stat = std::mem::zeroed();
        if libc::fstat(fd.as_raw_fd(), &mut stat) < 0 {
            return Err(io::Error::last_os_error());
        }
        stat
    };
    Ok(stat.st_mode)
}

/// `true` when the descriptor refers to a regular file.
///
/// # Errors
/// Propagates `fstat(2)` failures.
pub fn fd_is_regular_file(fd: &OwnedFd) -> io::Result<bool> {
    let mode = fd_mode(fd)?;
    Ok(mode & libc::S_IFMT == libc::S_IFREG)
}

/// Create a file exclusively with mode 0600.
///
/// `O_CREAT | O_EXCL` with an explicit mode avoids the window in which a file
/// created with the process umask is world-readable before it is chmodded.
///
/// # Errors
/// Returns `EEXIST` when the file already exists, so the caller can retry the
/// read instead of truncating someone else's secret.
pub fn create_private(path: &std::path::Path) -> io::Result<OwnedFd> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let cpath = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    // SAFETY: `cpath` is a valid NUL-terminated string; mode 0600 is passed
    // explicitly so the umask cannot widen it.
    let fd = unsafe {
        libc::open(
            cpath.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a freshly opened descriptor owned by us.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Effective user id.
pub fn effective_uid() -> u32 {
    // SAFETY: `geteuid` takes no arguments and cannot fail.
    unsafe { libc::geteuid() }
}

/// Read a sysfs attribute as a trimmed UTF-8 string.
pub fn read_sysfs_string(path: &std::path::Path) -> io::Result<String> {
    Ok(std::fs::read_to_string(path)?.trim().to_owned())
}

/// Read a sysfs attribute as a `u64`, tolerating surrounding whitespace.
pub fn read_sysfs_u64(path: &std::path::Path) -> io::Result<u64> {
    let raw = read_sysfs_string(path)?;
    raw.parse::<u64>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Adopt a file descriptor that was inherited from a parent process.
///
/// systemd's socket activation passes listening sockets as descriptors 3, 4,
/// ... with `FD_CLOEXEC` cleared so they survive `exec`. Adoption takes
/// ownership, so the descriptor is closed when the returned value is dropped,
/// and `FD_CLOEXEC` is set again so no further child inherits it.
///
/// # Errors
/// Returns the `fcntl` error when the flag cannot be set.
pub fn adopt_fd(fd: std::os::fd::RawFd) -> io::Result<OwnedFd> {
    // SAFETY: the caller guarantees that `fd` is an open descriptor this
    // process owns (systemd passes it exactly once) and that nothing else
    // closes it; taking ownership here makes that explicit and gives the
    // descriptor a single owner for the rest of the process lifetime.
    let owned = unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd) };
    // Re-arm close-on-exec; the flag was cleared by whoever passed the fd on.
    // SAFETY: `owned` is a live descriptor and `F_GETFD`/`F_SETFD` do not
    // change ownership.
    unsafe {
        let flags = libc::fcntl(owned.as_raw_fd(), libc::F_GETFD);
        if flags == -1
            || libc::fcntl(owned.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) == -1
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(owned)
}

#[cfg(test)]
mod tests {
    use super::{BLKGETSIZE64, BLKSSZGET, FIFREEZE, FITHAW, ioc};

    #[test]
    fn ioctl_numbers_match_linux_uapi() {
        assert_eq!(BLKGETSIZE64, 0x8008_1272);
        assert_eq!(BLKSSZGET, 0x1268);
        assert_eq!(FIFREEZE, 0xC004_5877);
        assert_eq!(FITHAW, 0xC004_5878);
        assert_eq!(ioc::encode(ioc::NONE, 0x12, 104, 0), 0x1268);
    }

    #[test]
    fn thaw_on_unfrozen_tmp_reports_supported() {
        let dir = std::env::temp_dir();
        let fd = super::open_dir_readonly(&dir).expect("open temp dir");
        assert!(
            super::fs_freeze_supported(&fd),
            "FITHAW must exist on modern Linux"
        );
    }

    #[test]
    fn nofollow_open_refuses_symlinks() {
        let dir = std::env::temp_dir().join(format!("lr-nofollow-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let target = dir.join("target");
        std::fs::write(&target, b"secret").expect("write");
        // An explicit mode: what `write` creates depends on the umask.
        std::fs::set_permissions(&target, std::os::unix::fs::PermissionsExt::from_mode(0o640))
            .expect("chmod");
        let link = dir.join("link");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        let direct = super::open_readonly_nofollow(&target).expect("open regular file");
        assert!(super::fd_is_regular_file(&direct).expect("fstat"));
        let mode = super::fd_mode(&direct).expect("fstat") & 0o777;
        assert_eq!(mode, 0o640, "unexpected mode {mode:o}");

        let error = super::open_readonly_nofollow(&link).expect_err("symlink must be refused");
        assert_eq!(error.raw_os_error(), Some(libc::ELOOP));

        let directory = super::open_readonly_nofollow(&dir).expect("open directory");
        assert!(!super::fd_is_regular_file(&directory).expect("fstat"));

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn private_files_are_created_0600_and_never_truncated() {
        let path = std::env::temp_dir().join(format!("lr-private-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let fd = super::create_private(&path).expect("create");
        assert_eq!(super::fd_mode(&fd).expect("fstat") & 0o777, 0o600);
        drop(fd);
        assert!(super::create_private(&path).is_err(), "O_EXCL must refuse");
        std::fs::remove_file(&path).expect("cleanup");
    }

    #[test]
    fn effective_uid_is_plausible() {
        assert!(super::effective_uid() < u32::MAX);
    }

    #[test]
    fn pidfd_open_self_succeeds() {
        let pid = std::process::id();
        match super::pidfd_open(pid) {
            Ok(Some(_fd)) => {}
            Ok(None) => {
                lr_testkit::report_unavailable("pidfd_open is not implemented by this kernel")
            }
            Err(e) => panic!("pidfd_open(self) failed: {e}"),
        }
    }
}
