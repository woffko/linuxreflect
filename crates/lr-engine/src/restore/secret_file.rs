//! Private token material in a runtime directory shared with the daemon socket.

use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use lr_core::{Error, Result};

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn pinned(directory: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()))
}

fn open_dir(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
}

/// Traverse through pinned directory descriptors, rejecting symlinks and
/// untrusted ancestors. Existing permissions (including socket group access)
/// are never changed. A sticky ancestor owned by root or this user is permitted;
/// the final directory must be owned by this effective UID and not writable
/// by other users. Only missing directories are created, with mode 0700.
pub(super) fn directory(path: &Path) -> io::Result<File> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let uid = lr_unsafe::effective_uid();
    let mut current = open_dir(Path::new("/"))?;
    for component in absolute.components() {
        let name = match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => name,
            _ => return Err(invalid("token directory must not contain parent traversal")),
        };
        let metadata = current.metadata()?;
        let trusted_owner = metadata.uid() == 0 || metadata.uid() == uid;
        let sticky_trusted = trusted_owner && metadata.mode() & 0o1000 != 0;
        if !trusted_owner || (metadata.mode() & 0o022 != 0 && !sticky_trusted) {
            return Err(invalid("untrusted token directory ancestor"));
        }
        let next = pinned(&current).join(name);
        current = match open_dir(&next) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match DirBuilder::new().mode(0o700).create(&next) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error),
                }
                open_dir(&next)?
            }
            Err(error) => return Err(error),
        };
    }
    let metadata = current.metadata()?;
    if metadata.uid() != uid || metadata.mode() & 0o022 != 0 {
        return Err(invalid(
            "token directory must be owned by the effective user and not writable by others",
        ));
    }
    Ok(current)
}

fn read(path: &Path) -> io::Result<[u8; 32]> {
    // NONBLOCK prevents a malicious FIFO from hanging before the fstat check.
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != lr_unsafe::effective_uid()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.len() != 32
    {
        return Err(invalid(
            "token key must be an owned, mode-0600 regular file of exactly 32 bytes",
        ));
    }
    let mut bytes = [0; 32];
    file.read_exact(&mut bytes)?;
    if file.read(&mut [0])? != 0 {
        return Err(invalid("token key changed size while reading"));
    }
    Ok(bytes)
}

pub(super) fn load(path: &Path) -> Result<[u8; 32]> {
    let name = path
        .file_name()
        .ok_or_else(|| invalid("missing token key filename"))?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let directory = directory(parent)?;
    let directory_path = pinned(&directory);
    let final_path = directory_path.join(name);
    match read(&final_path) {
        Ok(secret) => return Ok(secret),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(Error::Io(error)),
    }
    // Publish only a complete key. persist_noclobber atomically installs it
    // without replacing a concurrent winner; all callers read the winner.
    let secret: [u8; 32] = lr_crypto::rand::random_bytes()?;
    let mut temporary = tempfile::NamedTempFile::new_in(&directory_path)?;
    temporary.write_all(&secret)?;
    temporary.as_file().sync_all()?;
    match temporary.persist_noclobber(&final_path) {
        Ok(_) => directory.sync_all()?,
        Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(Error::Io(error.error)),
    }
    read(&final_path).map_err(Error::Io)
}

#[cfg(test)]
mod tests {
    /// A 0700 directory whatever the umask: under umask 002 a plain temporary
    /// directory is group-writable, which the loader rightly refuses.
    fn private_dir() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt as _;
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }

    use super::*;
    use std::os::unix::fs::{FileTypeExt, PermissionsExt, symlink};

    #[test]
    fn preserves_socket_directory_and_existing_key() {
        let dir = private_dir();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
        let socket =
            std::os::unix::net::UnixListener::bind(dir.path().join("daemon.sock")).unwrap();
        let path = dir.path().join("token.key");
        let first = load(&path).unwrap();
        assert!(first == load(&path).unwrap());
        assert_eq!(dir.path().metadata().unwrap().mode() & 0o777, 0o750);
        assert_eq!(path.metadata().unwrap().mode() & 0o777, 0o600);
        assert!(std::os::unix::net::UnixStream::connect(dir.path().join("daemon.sock")).is_ok());
        drop(socket);
    }

    #[test]
    fn concurrent_creators_share_one_complete_key() {
        let dir = private_dir();
        let path = dir.path().join("token.key");
        let barrier = std::sync::Barrier::new(12);
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..12)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        load(&path).unwrap()
                    })
                })
                .collect();
            let expected = handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect::<Vec<_>>();
            assert!(expected.iter().all(|key| key == &expected[0]));
        });
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn rejects_symlinks_and_does_not_touch_probe() {
        let dir = private_dir();
        let original = dir.path().join("original");
        load(&original).unwrap();
        let before = std::fs::read(&original).unwrap();
        symlink(&original, dir.path().join("token.key")).unwrap();
        symlink(&original, dir.path().join(".probe")).unwrap();
        assert!(load(&dir.path().join("token.key")).is_err());
        load(&dir.path().join("another.key")).unwrap();
        assert!(std::fs::read(&original).unwrap() == before);
        let alias = dir.path().join("alias");
        symlink(dir.path(), &alias).unwrap();
        assert!(load(&alias.join("another.key")).is_err());
    }

    #[test]
    fn rejects_bad_modes_sizes_and_directory_without_replacing_them() {
        let dir = private_dir();
        let path = dir.path().join("token.key");
        load(&path).unwrap();
        for mode in [0o644, 0o660, 0o400] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(load(&path).is_err());
            assert_eq!(path.metadata().unwrap().mode() & 0o777, mode);
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        for len in [0, 31, 33, 4096] {
            std::fs::write(&path, vec![0; len]).unwrap();
            assert!(load(&path).is_err());
            assert_eq!(path.metadata().unwrap().len(), len as u64);
        }
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(load(&path).is_err());
    }

    #[test]
    fn rejects_writable_parent_without_chmod() {
        let dir = private_dir();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(load(&dir.path().join("token.key")).is_err());
        assert_eq!(dir.path().metadata().unwrap().mode() & 0o777, 0o770);
        assert!(!dir.path().join("token.key").exists());
    }

    #[test]
    fn rejects_fifo_without_waiting_for_a_writer() {
        let dir = private_dir();
        let path = dir.path().join("token.key");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        assert!(load(&path).is_err());
        assert!(path.symlink_metadata().unwrap().file_type().is_fifo());
    }

    #[test]
    fn owned_sticky_ancestor_is_safe_but_plain_writable_ancestor_is_not() {
        let ancestor = private_dir();
        let private = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(ancestor.path())
            .unwrap();
        std::fs::set_permissions(ancestor.path(), std::fs::Permissions::from_mode(0o1777)).unwrap();
        let path = private.path().join("token.key");
        load(&path).unwrap();
        std::fs::set_permissions(ancestor.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(load(&path).is_err());
    }

    #[test]
    #[ignore = "requires root, LR_ROOT_TESTS=1, setpriv and python3"]
    fn socket_group_can_connect_after_key_creation_but_cannot_read_key() {
        assert_eq!(std::env::var("LR_ROOT_TESTS").as_deref(), Ok("1"));
        assert_eq!(lr_unsafe::effective_uid(), 0);
        // Only this test's temporary socket/directory/key are changed.
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        let peer = 65534;
        std::os::unix::fs::chown(dir.path(), Some(0), Some(peer)).unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
        let socket_path = dir.path().join("daemon.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
        std::os::unix::fs::chown(&socket_path, Some(0), Some(peer)).unwrap();
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o660)).unwrap();
        let key_path = dir.path().join("token.key");
        load(&key_path).unwrap();
        let status = std::process::Command::new("setpriv")
            .args(["--reuid=65534", "--regid=65534", "--clear-groups", "python3", "-c",
                "import socket,sys; s=socket.socket(socket.AF_UNIX); s.settimeout(2); s.connect(sys.argv[1]); s.close()\ntry:\n open(sys.argv[2], 'rb').close()\nexcept PermissionError:\n sys.exit(0)\nraise SystemExit('peer could open the token key')"])
            .arg(&socket_path).arg(&key_path).status().unwrap();
        assert!(
            status.success(),
            "socket group must connect without key access"
        );
        assert_eq!(dir.path().metadata().unwrap().mode() & 0o777, 0o750);
        // A key owned by the peer is rejected even when its mode is private.
        std::os::unix::fs::chown(&key_path, Some(peer), Some(peer)).unwrap();
        assert!(load(&key_path).is_err());
        drop(listener);
    }
}
