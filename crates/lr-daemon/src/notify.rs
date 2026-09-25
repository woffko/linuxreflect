//! `sd_notify` without a dependency (spec §I: `Type=notify`).
//!
//! systemd hands the daemon a datagram socket path in `NOTIFY_SOCKET`; writing
//! `READY=1`, `STATUS=…` or `WATCHDOG=1` to it is the whole protocol, so it is
//! implemented directly instead of pulling in a crate.

use std::io;
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;

/// Path systemd passes to the service, when it uses `Type=notify`.
#[must_use]
pub fn socket_path() -> Option<PathBuf> {
    std::env::var_os("NOTIFY_SOCKET")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

/// Send one notification.
///
/// Returns `Ok(false)` when systemd did not ask for notifications (the
/// variable is unset), so callers can stay silent under a plain shell.
///
/// # Errors
/// Propagates datagram errors when a socket path is configured.
pub fn send(message: &str) -> io::Result<bool> {
    let Some(path) = socket_path() else {
        return Ok(false);
    };
    send_to(&path.to_string_lossy(), message)?;
    Ok(true)
}

/// The watchdog interval systemd configured, if any.
#[must_use]
pub fn watchdog_interval() -> Option<std::time::Duration> {
    watchdog_from(std::env::var("WATCHDOG_USEC").ok().as_deref())
}

/// Send one notification to an explicit socket path.
///
/// `path` is either a filesystem path or (`@`-prefixed) an abstract name, as
/// systemd writes them. Kept separate from [`send`] so the protocol can be
/// tested without mutating the process environment.
///
/// # Errors
/// Propagates datagram errors.
pub fn send_to(path: &str, message: &str) -> io::Result<()> {
    let socket = UnixDatagram::unbound()?;
    match path.strip_prefix('@') {
        Some(name) => {
            use std::os::linux::net::SocketAddrExt;
            let address = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?;
            socket.send_to_addr(message.as_bytes(), &address)?;
        }
        None => {
            socket.send_to(message.as_bytes(), path)?;
        }
    }
    Ok(())
}

/// The watchdog interval for an explicit `WATCHDOG_USEC` value.
#[must_use]
pub fn watchdog_from(usec: Option<&str>) -> Option<std::time::Duration> {
    let usec: u64 = usec?.parse().ok()?;
    (usec > 0).then(|| std::time::Duration::from_micros(usec / 2))
}

#[cfg(test)]
mod tests {
    use super::{send, send_to, socket_path, watchdog_from};

    #[test]
    fn notifications_are_optional() {
        if std::env::var_os("NOTIFY_SOCKET").is_none() {
            assert_eq!(socket_path(), None);
            assert!(!send("READY=1").expect("no systemd is not an error"));
        }
    }

    #[test]
    fn notifications_reach_a_listening_socket() {
        let dir = tempfile::tempdir_in("/tmp/opencode").expect("tempdir");
        let path = dir.path().join("notify.sock");
        let listener = std::os::unix::net::UnixDatagram::bind(&path).expect("bind");
        send_to(&path.to_string_lossy(), "READY=1").expect("send");
        let mut buffer = [0u8; 64];
        let read = listener.recv(&mut buffer).expect("recv");
        assert_eq!(&buffer[..read], b"READY=1");
    }

    #[test]
    fn abstract_names_are_supported() {
        // systemd's default is an abstract socket; the name is `@`-prefixed.
        use std::os::linux::net::SocketAddrExt;
        let name = format!("lr-notify-test-{}", std::process::id());
        let address =
            std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes()).expect("address");
        let listener = std::os::unix::net::UnixDatagram::bind_addr(&address).expect("bind");
        send_to(&format!("@{name}"), "WATCHDOG=1").expect("send");
        let mut buffer = [0u8; 32];
        let read = listener.recv(&mut buffer).expect("recv");
        assert_eq!(&buffer[..read], b"WATCHDOG=1");
    }

    #[test]
    fn the_watchdog_interval_is_half_the_configured_one() {
        assert_eq!(
            watchdog_from(Some("1000000")),
            Some(std::time::Duration::from_millis(500))
        );
        assert_eq!(watchdog_from(Some("0")), None);
        assert_eq!(watchdog_from(Some("nonsense")), None);
        assert_eq!(watchdog_from(None), None);
    }
}
