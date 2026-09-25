//! The daemon's listening socket (spec §I).
//!
//! The socket is either inherited from systemd socket activation
//! (`LISTEN_FDS`, `LISTEN_PID` matching this process) or created here: the
//! directory is private, the file is group-owned by `linuxreflect` and mode
//! 0660 so members of that group may talk to the daemon. When the group cannot
//! be established the socket falls back to 0600 root-only with a warning
//! rather than being left world-accessible.

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use lr_core::{Error, Result};
use tokio::net::UnixListener;

/// Where the socket lives by default.
pub const DEFAULT_SOCKET: &str = "/run/linuxreflect/daemon.sock";
/// The group that may talk to the daemon.
pub const DEFAULT_GROUP: &str = "linuxreflect";

/// How the listener was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Inherited from systemd socket activation.
    Inherited,
    /// Created by the daemon.
    Bound,
}

/// Number of sockets passed by systemd, when this process is the one it
/// started.
#[must_use]
pub fn inherited_fd_count() -> Option<u32> {
    let pid: u32 = std::env::var("LISTEN_PID").ok()?.parse().ok()?;
    if pid != std::process::id() {
        return None;
    }
    let count: u32 = std::env::var("LISTEN_FDS").ok()?.parse().ok()?;
    (count > 0).then_some(count)
}

/// Take the first inherited socket (descriptor 3).
///
/// # Errors
/// Returns the `fcntl`/conversion error when descriptor 3 is not a listener.
pub async fn adopt_inherited() -> io::Result<UnixListener> {
    let owned = lr_unsafe::adopt_fd(3)?;
    let listener = std::os::unix::net::UnixListener::from(owned);
    listener.set_nonblocking(true)?;
    UnixListener::from_std(listener)
}

/// Acquire the listening socket.
///
/// # Errors
/// Returns [`Error::TargetBusy`] when another daemon already listens on the
/// path, and propagates socket and permission errors.
pub async fn listen(
    path: &Path,
    group: Option<&str>,
    create_group: bool,
    mode_override: Option<u32>,
) -> Result<(UnixListener, Origin)> {
    let group = group.map(|name| (name.to_owned(), group_id(name, create_group)));
    if inherited_fd_count().is_some() {
        // systemd made the socket (SocketMode/SocketGroup), but its parent
        // directory is ours to keep reachable: a 0660 group socket inside a
        // 0700 root directory would be unreachable for the very group the
        // socket names (spec §I).
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(Error::Io)?;
            let (mode, gid) = directory_access(mode_override, group.as_ref());
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(mode));
            if let Some(gid) = gid
                && let Err(error) = std::os::unix::fs::chown(parent, Some(0), Some(gid))
            {
                tracing::warn!(%error, "cannot change the socket directory group");
            }
        }
        tracing::info!("using the socket passed by systemd");
        return Ok((
            adopt_inherited().await.map_err(Error::Io)?,
            Origin::Inherited,
        ));
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(Error::Io)?;
    }
    if let Some(parent) = path.parent() {
        // The directory must grant exactly the access the socket grants, or the
        // socket mode would be unreachable for the users it is meant for.
        let (mode, gid) = directory_access(mode_override, group.as_ref());
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(mode));
        if let Some(gid) = gid
            && let Err(error) = std::os::unix::fs::chown(parent, Some(0), Some(gid))
        {
            tracing::warn!(%error, "cannot change the socket directory group");
        }
    }
    if path.exists() {
        match std::os::unix::net::UnixStream::connect(path) {
            Ok(_) => {
                return Err(Error::TargetBusy {
                    holder: format!("another daemon on {}", path.display()),
                });
            }
            Err(_) => {
                // A leftover socket file from a crashed daemon.
                std::fs::remove_file(path).map_err(Error::Io)?;
            }
        }
    }
    let listener = std::os::unix::net::UnixListener::bind(path).map_err(Error::Io)?;
    listener.set_nonblocking(true).map_err(Error::Io)?;

    let mut mode = mode_override.unwrap_or(0o600);
    if mode_override.is_none()
        && let Some((name, gid)) = group.as_ref()
    {
        match gid {
            Some(gid) => {
                if let Err(error) = std::os::unix::fs::chown(path, Some(0), Some(*gid)) {
                    tracing::warn!(%error, "cannot change the socket group");
                } else {
                    mode = 0o660;
                }
            }
            None => tracing::warn!(
                name,
                "group does not exist; the socket stays root-only (0600)"
            ),
        }
    }
    if let Some(mode) = mode_override {
        tracing::warn!(
            mode = format_args!("{mode:o}"),
            "the socket mode was overridden"
        );
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(Error::Io)?;
    Ok((
        UnixListener::from_std(listener).map_err(Error::Io)?,
        Origin::Bound,
    ))
}

/// The directory access that matches the socket access.
///
/// A `0660` socket in a `0700` directory is unreachable for the group it names,
/// so the directory follows the socket: group access implies a group-traversable
/// directory, other-user access a world-traversable one, and a root-only socket
/// a root-only directory.
fn directory_access(
    mode_override: Option<u32>,
    group: Option<&(String, Option<u32>)>,
) -> (u32, Option<u32>) {
    let socket_mode = mode_override.unwrap_or_else(|| {
        if group.is_some_and(|(_, gid)| gid.is_some()) {
            0o660
        } else {
            0o600
        }
    });
    let gid = group.and_then(|(_, gid)| *gid);
    if socket_mode & 0o007 != 0 {
        (0o755, gid)
    } else if socket_mode & 0o070 != 0 {
        (0o750, gid)
    } else {
        (0o700, gid)
    }
}

/// Resolve a group name, creating the group when asked and possible.
fn group_id(name: &str, create: bool) -> Option<u32> {
    if let Some(gid) = lookup_group(name) {
        return Some(gid);
    }
    if !create {
        return None;
    }
    tracing::info!(name, "creating the socket group");
    let status = std::process::Command::new("groupadd")
        .args(["-r", name])
        .status()
        .ok()?;
    if !status.success() {
        tracing::warn!(name, "groupadd failed");
        return None;
    }
    lookup_group(name)
}

/// Look a group up in the system database.
#[must_use]
pub fn lookup_group(name: &str) -> Option<u32> {
    nix::unistd::Group::from_name(name)
        .ok()
        .flatten()
        .map(|group| group.gid.as_raw())
}

/// The default socket path.
#[must_use]
pub fn default_path() -> PathBuf {
    PathBuf::from(DEFAULT_SOCKET)
}

#[cfg(test)]
mod tests {
    use super::{Origin, directory_access, inherited_fd_count, listen, lookup_group};
    use std::os::unix::fs::PermissionsExt;

    fn mode_of(path: &std::path::Path) -> u32 {
        std::fs::metadata(path).expect("stat").permissions().mode() & 0o777
    }

    #[test]
    fn inherited_sockets_are_only_taken_when_systemd_started_us() {
        // The test harness does not set LISTEN_*; if it did, the pid would not
        // match, which is exactly what the check protects against.
        assert_eq!(inherited_fd_count(), None);
    }

    #[test]
    fn directory_access_follows_the_socket_mode() {
        // Root-only: nothing else may even reach the socket.
        assert_eq!(directory_access(None, None), (0o700, None));
        // A missing group degrades to root-only, so the directory does too.
        let missing = ("nope".to_owned(), None);
        assert_eq!(directory_access(None, Some(&missing)), (0o700, None));
        // Group access implies a group-traversable directory.
        let group = ("somegroup".to_owned(), Some(7));
        assert_eq!(directory_access(None, Some(&group)), (0o750, Some(7)));
        // World access implies a world-traversable directory.
        assert_eq!(directory_access(Some(0o666), None), (0o755, None));
        assert_eq!(directory_access(Some(0o660), None), (0o750, None));
        assert_eq!(directory_access(Some(0o600), None), (0o700, None));
    }

    #[tokio::test]
    async fn a_socket_is_bound_privately_and_never_twice() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("daemon.sock");
        let (listener, origin) = listen(&path, None, false, None).await.expect("bind");
        assert_eq!(origin, Origin::Bound);
        assert!(path.exists());
        assert_eq!(mode_of(&path), 0o600, "no group means root-only");
        assert_eq!(
            mode_of(dir.path()),
            0o700,
            "a root-only socket lives in a root-only directory"
        );
        drop(listener);

        // The first listener is gone, so a second bind succeeds; while it is
        // alive it must refuse.
        let (first, _) = listen(&path, None, false, None).await.expect("rebind");
        let error = listen(&path, None, false, None)
            .await
            .expect_err("must refuse");
        assert!(
            matches!(error, lr_core::Error::TargetBusy { .. }),
            "{error}"
        );
        drop(first);
        let (_second, _) = listen(&path, None, false, None)
            .await
            .expect("rebind after drop");
    }

    #[tokio::test]
    async fn a_missing_group_degrades_to_root_only() {
        assert_eq!(lookup_group("linuxreflect-not-a-group"), None);
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("daemon.sock");
        let (_listener, _origin) = listen(&path, Some("linuxreflect-not-a-group"), false, None)
            .await
            .expect("bind");
        assert_eq!(mode_of(&path), 0o600);
        assert_eq!(mode_of(dir.path()), 0o700);
    }

    #[tokio::test]
    async fn an_explicit_mode_is_honoured() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("daemon.sock");
        let (_listener, _origin) = listen(&path, None, false, Some(0o666)).await.expect("bind");
        assert_eq!(mode_of(&path), 0o666);
        assert_eq!(
            mode_of(dir.path()),
            0o755,
            "a world-accessible socket needs a traversable directory"
        );
    }

    #[tokio::test]
    async fn an_explicit_mode_wins_over_the_group() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("daemon.sock");
        let (_listener, _origin) = listen(&path, Some("root"), false, Some(0o666))
            .await
            .expect("bind");
        assert_eq!(
            mode_of(&path),
            0o666,
            "an explicit mode is applied verbatim"
        );
    }

    #[tokio::test]
    async fn an_existing_group_is_applied_when_permitted() {
        // Without root the chown fails and the mode stays 0600; the point is
        // that a known group never makes the socket world-accessible, and that
        // the directory never ends up more permissive than the socket.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("daemon.sock");
        let (_listener, _origin) = listen(&path, Some("root"), false, None)
            .await
            .expect("bind");
        let socket_mode = mode_of(&path);
        assert!(matches!(socket_mode, 0o600 | 0o660), "mode {socket_mode:o}");
        let dir_mode = mode_of(dir.path());
        assert!(matches!(dir_mode, 0o700 | 0o750), "dir mode {dir_mode:o}");
        if socket_mode == 0o660 {
            assert_eq!(dir_mode, 0o750, "a group socket needs group traversal");
        }
    }
}
