//! Files a client names in a request: a passphrase file, an SSH identity or
//! a `known_hosts` file (A4).
//!
//! The daemon runs as root, so opening such a path on a client's behalf
//! would let any user of the session make it use a file only root may read:
//! root's SSH key for a server the client chooses, or a root-only file as a
//! passphrase. Every named file must therefore be a regular file owned by
//! the caller (root may name any file), opened without following a final
//! symbolic link. For requests that finish within the call, the file stays
//! pinned by its descriptor, so the path cannot be swapped after the check.

use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use lr_core::{Error, Result};

use crate::auth::Action;

/// Descriptors of the files a request named, open for as long as the
/// request uses them.
#[derive(Debug, Default)]
pub struct ClientFiles {
    held: Vec<OwnedFd>,
    /// `(pinned path, name the client gave)`, to name files in messages.
    names: Vec<(String, String)>,
}

impl ClientFiles {
    /// Nothing pinned yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Check that `path` may be read for `uid` and keep it open. Returns a
    /// `/proc/self/fd` path to the pinned file, valid while `self` lives, or
    /// `None` for an empty path.
    ///
    /// # Errors
    /// Returns [`Error::Denied`] when the file cannot be opened, is not a
    /// regular file, or belongs to another user.
    pub fn pin(&mut self, uid: u32, path: &str) -> Result<Option<PathBuf>> {
        let Some(fd) = open_for(uid, path)? else {
            return Ok(None);
        };
        let pinned = PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()));
        self.held.push(fd);
        self.names
            .push((pinned.display().to_string(), path.to_owned()));
        Ok(Some(pinned))
    }

    /// `error` with every pinned path replaced by the name the client gave,
    /// so a message names the client's file.
    #[must_use]
    pub fn named(&self, error: Error) -> Error {
        let name = |text: String| {
            self.names
                .iter()
                .fold(text, |text, (pinned, given)| text.replace(pinned, given))
        };
        match error {
            Error::Io(io) => Error::Io(std::io::Error::new(io.kind(), name(io.to_string()))),
            Error::NetworkTimeout(what) => Error::NetworkTimeout(name(what)),
            Error::SetLocked { owner } => Error::SetLocked { owner: name(owner) },
            Error::TargetBusy { holder } => Error::TargetBusy {
                holder: name(holder),
            },
            Error::Corrupt { what } => Error::Corrupt { what: name(what) },
            Error::Denied { action, reason } => Error::Denied {
                action,
                reason: name(reason),
            },
            Error::Unsupported { cap } => Error::Unsupported { cap: name(cap) },
            other => other,
        }
    }

    /// Read a passphrase file named by the client, with the checks of
    /// [`ClientFiles::pin`] and those of any passphrase file.
    ///
    /// # Errors
    /// As [`ClientFiles::pin`], and the passphrase-file errors.
    pub fn passphrase(uid: u32, path: &str) -> Result<Option<lr_engine::keystore::Passphrase>> {
        let Some(fd) = open_for(uid, path)? else {
            return Ok(None);
        };
        lr_engine::keystore::read_passphrase(fd, Path::new(path)).map(Some)
    }
}

/// Check the named files of a request whose paths are used later (restore
/// tokens keep them): each must be readable for `uid` now.
///
/// # Errors
/// As [`ClientFiles::pin`].
pub fn check(uid: u32, paths: &[&str]) -> Result<()> {
    for path in paths {
        open_for(uid, path)?;
    }
    Ok(())
}

/// Refuse `insecure_ignore_host_key` unless the daemon runs in development
/// mode: it turns off the only protection against an impostor server.
///
/// # Errors
/// Returns [`Error::Denied`] outside development mode.
pub fn check_host_key_policy(insecure_ignore_host_key: bool, dev_mode: bool) -> Result<()> {
    if insecure_ignore_host_key && !dev_mode {
        return Err(Error::denied(
            Action::DiskRead.id(),
            "insecure_ignore_host_key is only honoured by a daemon in development mode",
        ));
    }
    Ok(())
}

fn open_for(uid: u32, path: &str) -> Result<Option<OwnedFd>> {
    if path.is_empty() {
        return Ok(None);
    }
    let denied = |reason: String| Error::denied(Action::DiskRead.id(), reason);
    let fd = lr_unsafe::open_readonly_nofollow(Path::new(path))
        .map_err(|error| denied(format!("cannot open {path}: {error}")))?;
    let file = std::fs::File::from(fd);
    let metadata = file.metadata().map_err(Error::Io)?;
    if !metadata.is_file() {
        return Err(denied(format!("{path} is not a regular file")));
    }
    if uid != 0 && metadata.uid() != uid {
        return Err(denied(format!(
            "{path} belongs to uid {}, not to the caller (uid {uid}); the daemon reads \
             only the caller's own files",
            metadata.uid()
        )));
    }
    Ok(Some(OwnedFd::from(file)))
}

#[cfg(test)]
mod tests {
    use super::{ClientFiles, check, check_host_key_policy};

    #[test]
    fn a_file_of_another_user_is_refused() {
        // /etc/hostname belongs to root on every test host.
        let uid = 4242;
        let error = ClientFiles::new()
            .pin(uid, "/etc/hostname")
            .expect_err("root's file");
        assert!(error.to_string().contains("belongs to uid 0"), "{error}");
        assert!(check(uid, &["", "/etc/hostname"]).is_err());
        assert!(
            ClientFiles::new().pin(0, "/etc/hostname").is_ok(),
            "root may name any file"
        );
    }

    #[test]
    fn the_callers_own_file_is_pinned() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("known_hosts");
        std::fs::write(&path, "nas.local ssh-ed25519 AAAA\n").expect("write");
        let mut files = ClientFiles::new();
        let pinned = files
            .pin(lr_unsafe::effective_uid(), &path.display().to_string())
            .expect("own file")
            .expect("a path");
        // The pinned path keeps reading the checked file after the name
        // changes.
        std::fs::rename(&path, dir.path().join("moved")).expect("rename");
        std::fs::write(&path, "swapped\n").expect("swap");
        assert_eq!(
            std::fs::read_to_string(&pinned).expect("read pinned"),
            "nas.local ssh-ed25519 AAAA\n"
        );
        assert!(files.pin(0, "").expect("empty").is_none());
        let error = files.named(lr_core::Error::unsupported(format!(
            "{} has mode 644",
            pinned.display()
        )));
        assert!(
            error.to_string().contains(&path.display().to_string()),
            "{error}"
        );
    }

    #[test]
    fn a_symlink_or_directory_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let link = dir.path().join("id");
        std::os::unix::fs::symlink("/etc/hostname", &link).expect("symlink");
        let uid = lr_unsafe::effective_uid();
        assert!(
            ClientFiles::new()
                .pin(uid, &link.display().to_string())
                .is_err()
        );
        assert!(
            ClientFiles::new()
                .pin(uid, &dir.path().display().to_string())
                .is_err()
        );
    }

    #[test]
    fn ignoring_host_keys_needs_development_mode() {
        assert!(check_host_key_policy(true, false).is_err());
        assert!(check_host_key_policy(true, true).is_ok());
        assert!(check_host_key_policy(false, false).is_ok());
    }
}
