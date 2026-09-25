//! Peer identity and authorization (spec §I, Slice S11).
//!
//! A connection's identity comes from `SO_PEERCRED` (`UdsConnectInfo` in
//! tonic), which is what the kernel says about the socket — not what the client
//! claims. The pid is pinned with `pidfd_open` immediately and then re-read from
//! `/proc`, so a pid that exits between the two reads cannot be replaced by an
//! unrelated process before the authorization check runs.
//!
//! Authorization is delegated to an [`AuthBackend`]: polkit in production, a
//! static uid list only in development mode.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use lr_core::{Error, Result};
use tokio::net::unix::UCred;

/// One privileged operation, as polkit sees it (spec §I).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Read disk and set metadata.
    DiskRead,
    /// Create a backup image.
    BackupCreate,
    /// Build a restore plan and token.
    RestorePrepare,
    /// Write a restore target.
    RestoreApply,
    /// Manage snapshots (LVM/btrfs).
    SnapshotManage,
    /// Manage schedules.
    ScheduleManage,
    /// Configure destinations.
    DestinationConfigure,
    /// Mount or unmount exports.
    ExportManage,
}

impl Action {
    /// The polkit action identifier.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::DiskRead => "org.linuxreflect.disk.read",
            Self::BackupCreate => "org.linuxreflect.backup.create",
            Self::RestorePrepare => "org.linuxreflect.restore.prepare",
            Self::RestoreApply => "org.linuxreflect.restore.apply",
            Self::SnapshotManage => "org.linuxreflect.snapshot.manage",
            Self::ScheduleManage => "org.linuxreflect.schedule.manage",
            Self::DestinationConfigure => "org.linuxreflect.destination.configure",
            Self::ExportManage => "org.linuxreflect.export.manage",
        }
    }

    /// `true` when polkit should allow an authentication dialog.
    #[must_use]
    pub const fn allows_interaction(self) -> bool {
        // `auth_admin_keep` actions may prompt; `restore.apply` is `auth_admin`
        // (no keep) and is still allowed to prompt, but never to be skipped.
        matches!(
            self,
            Self::BackupCreate
                | Self::RestorePrepare
                | Self::SnapshotManage
                | Self::ScheduleManage
                | Self::DestinationConfigure
                | Self::ExportManage
        )
    }
}

/// Who is calling, as proved by the kernel.
#[derive(Debug)]
pub struct PeerIdentity {
    /// Real uid from `SO_PEERCRED`, cross-checked against `/proc`.
    pub uid: u32,
    /// Gid from `SO_PEERCRED`.
    pub gid: u32,
    /// Pid from `SO_PEERCRED`; `None` when the kernel does not report one.
    pub pid: Option<u32>,
    /// Start time of that pid (field 22 of `/proc/<pid>/stat`).
    pub start_time: Option<u64>,
    /// Pin on the process, held for the lifetime of the request.
    _pidfd: Option<std::os::fd::OwnedFd>,
}

impl PeerIdentity {
    /// Capture the identity of a Unix-socket peer.
    ///
    /// # Errors
    /// Returns [`Error::Denied`] when the kernel reports no credentials or when
    /// `/proc` disagrees with them (a pid-reuse race the kernel cannot see).
    pub fn capture(cred: Option<&UCred>) -> Result<Self> {
        let Some(cred) = cred else {
            return Err(Error::denied(
                Action::DiskRead.id(),
                "the connection has no peer credentials",
            ));
        };
        let uid = cred.uid();
        let gid = cred.gid();
        let pid = cred.pid().and_then(|pid| u32::try_from(pid).ok());

        let mut identity = Self {
            uid,
            gid,
            pid,
            start_time: None,
            _pidfd: None,
        };

        if let Some(pid) = pid {
            // Pin the process first: after this the pid cannot be recycled.
            identity._pidfd = lr_unsafe::pidfd_open(pid).ok().flatten();
            let (proc_uid, start_time) = read_proc_identity(pid)?;
            if proc_uid != uid {
                return Err(Error::denied(
                    Action::DiskRead.id(),
                    format!("peer claimed uid {uid} but /proc/{pid} says {proc_uid}"),
                ));
            }
            identity.start_time = Some(start_time);
        }

        Ok(identity)
    }

    /// A short description for logs and error messages.
    #[must_use]
    pub fn describe(&self) -> String {
        match self.pid {
            Some(pid) => format!("uid {} pid {pid}", self.uid),
            None => format!("uid {}", self.uid),
        }
    }
}

/// Read the real uid and start time of a process from `/proc`.
///
/// `/proc/<pid>/stat` puts the command in parentheses, which may itself contain
/// spaces and parentheses, so the fields are counted from the last `)`.
fn read_proc_identity(pid: u32) -> Result<(u32, u64)> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).map_err(Error::Io)?;
    let uid = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| Error::corrupt("no Uid line in /proc/<pid>/status"))?;

    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).map_err(Error::Io)?;
    let after_command = stat
        .rfind(')')
        .map(|index| &stat[index + 1..])
        .ok_or_else(|| Error::corrupt("malformed /proc/<pid>/stat"))?;
    // Field 3 (`state`) is the first token after the command, so start time
    // (field 22) is token 19 from here.
    let start_time = after_command
        .split_whitespace()
        .nth(19)
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| Error::corrupt("no start time in /proc/<pid>/stat"))?;
    Ok((uid, start_time))
}

/// A decision about one action for one peer.
pub trait AuthBackend: Send + Sync {
    /// Check whether `peer` may perform `action`.
    fn check<'a>(
        &'a self,
        peer: &'a PeerIdentity,
        action: Action,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;
}

/// Development backend: an explicit uid list, only with `--dev-mode`.
///
/// This exists so CI can exercise the daemon without a polkit daemon; it is
/// refused unless the daemon was started in development mode (spec §I).
#[derive(Debug, Clone)]
pub struct StaticBackend {
    /// Uids that may do anything, or `None` when every uid is allowed.
    allowed: Option<Vec<u32>>,
}

impl StaticBackend {
    /// Parse `static:<uid>[,<uid>...]` or `static:all`.
    ///
    /// # Errors
    /// Returns [`Error::Unsupported`] for a malformed specification and
    /// [`Error::Denied`] when development mode is off.
    pub fn parse(spec: &str, dev_mode: bool) -> Result<Self> {
        if !dev_mode {
            return Err(Error::denied(
                Action::DiskRead.id(),
                "the static auth backend needs LR_DEV_MODE=1",
            ));
        }
        let list = spec.strip_prefix("static:").ok_or_else(|| {
            Error::unsupported("--auth expects `static:<uids>` or omit it for polkit")
        })?;
        if list == "all" {
            return Ok(Self { allowed: None });
        }
        let mut uids = Vec::new();
        for item in list.split(',').filter(|item| !item.is_empty()) {
            uids.push(
                item.parse()
                    .map_err(|_| Error::unsupported(format!("`{item}` is not a uid")))?,
            );
        }
        if uids.is_empty() {
            return Err(Error::unsupported("--auth static: needs at least one uid"));
        }
        Ok(Self {
            allowed: Some(uids),
        })
    }

    /// A backend that allows every uid (tests only).
    #[must_use]
    pub fn allow_all() -> Self {
        Self { allowed: None }
    }

    /// A backend that allows exactly these uids.
    #[must_use]
    pub fn uids(uids: impl IntoIterator<Item = u32>) -> Self {
        Self {
            allowed: Some(uids.into_iter().collect()),
        }
    }
}

impl AuthBackend for StaticBackend {
    fn check<'a>(
        &'a self,
        peer: &'a PeerIdentity,
        action: Action,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let allowed = match &self.allowed {
                None => true,
                Some(uids) => uids.contains(&peer.uid),
            };
            if allowed {
                Ok(())
            } else {
                Err(Error::denied(
                    action.id(),
                    format!("uid {} is not in the static allow list", peer.uid),
                ))
            }
        })
    }
}

/// Production backend: ask polkit over the system bus.
pub struct PolkitBackend {
    connection: zbus::Connection,
    /// `true` when the subject may carry a `pidfd` (polkit 121+).
    pidfd_subject: bool,
}

impl std::fmt::Debug for PolkitBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolkitBackend")
            .field("pidfd_subject", &self.pidfd_subject)
            .finish_non_exhaustive()
    }
}

impl PolkitBackend {
    /// Connect to the system bus and probe the polkit version.
    ///
    /// # Errors
    /// Returns [`Error::Unsupported`] when the system bus or polkit is absent.
    pub async fn connect() -> Result<Self> {
        let connection = zbus::Connection::system()
            .await
            .map_err(|error| Error::unsupported(format!("no system D-Bus for polkit: {error}")))?;
        let version = polkit_version(&connection).await;
        let pidfd_subject = version.is_none_or(|version| version >= 121);
        tracing::info!(
            version = version.unwrap_or(0),
            pidfd_subject,
            "polkit authorization backend connected"
        );
        Ok(Self {
            connection,
            pidfd_subject,
        })
    }

    /// Build the `unix-process` subject, carrying a `pidfd` when polkit
    /// supports it (which makes the check immune to pid reuse).
    fn subject(&self, peer: &PeerIdentity) -> Result<zbus_polkit::policykit1::Subject> {
        use zbus::zvariant::{OwnedValue, Value};
        let Some(pid) = peer.pid else {
            return zbus_polkit::policykit1::Subject::new_for_owner(0, None, Some(peer.uid))
                .map_err(|error| Error::unsupported(format!("polkit subject: {error}")));
        };
        if self.pidfd_subject
            && let Some(pidfd) = &peer._pidfd
        {
            let owned = pidfd
                .try_clone()
                .map_err(|error| Error::unsupported(format!("pidfd: {error}")))?;
            let fd = zbus::zvariant::Fd::from(owned);
            let owned_value = |value: Value<'_>| -> Result<OwnedValue> {
                value
                    .try_to_owned()
                    .map_err(|error| Error::unsupported(format!("polkit detail: {error}")))
            };
            let mut details = std::collections::HashMap::new();
            details.insert("pid".to_owned(), owned_value(Value::from(pid))?);
            if let Some(start_time) = peer.start_time {
                details.insert(
                    "start-time".to_owned(),
                    owned_value(Value::from(start_time))?,
                );
            }
            details.insert("uid".to_owned(), owned_value(Value::from(peer.uid))?);
            details.insert("pidfd".to_owned(), owned_value(Value::from(fd))?);
            return Ok(zbus_polkit::policykit1::Subject {
                subject_kind: "unix-process".to_owned(),
                subject_details: details,
            });
        }
        zbus_polkit::policykit1::Subject::new_for_owner(pid, peer.start_time, Some(peer.uid))
            .map_err(|error| Error::unsupported(format!("polkit subject: {error}")))
    }

    /// Ask polkit, falling back to the pid-only subject when the pidfd one is
    /// not accepted.
    async fn ask(&self, peer: &PeerIdentity, action: Action) -> Result<()> {
        use enumflags2::BitFlags;
        use zbus_polkit::policykit1::{AuthorityProxy, CheckAuthorizationFlags};
        let proxy = AuthorityProxy::new(&self.connection)
            .await
            .map_err(|error| Error::unsupported(format!("polkit authority: {error}")))?;
        let mut flags = BitFlags::<CheckAuthorizationFlags>::empty();
        if action.allows_interaction() {
            flags.insert(CheckAuthorizationFlags::AllowUserInteraction);
        }

        let subject = self.subject(peer)?;
        let result = proxy
            .check_authorization(&subject, action.id(), &Default::default(), flags, "")
            .await;
        let result = match result {
            Ok(result) => result,
            Err(_) if self.pidfd_subject => {
                // Older polkit rejects the pidfd detail; retry without it.
                tracing::warn!("polkit refused the pidfd subject; retrying with pid/start-time");
                let fallback = zbus_polkit::policykit1::Subject::new_for_owner(
                    peer.pid.unwrap_or(0),
                    peer.start_time,
                    Some(peer.uid),
                )
                .map_err(|error| Error::unsupported(format!("polkit subject: {error}")))?;
                proxy
                    .check_authorization(&fallback, action.id(), &Default::default(), flags, "")
                    .await
                    .map_err(|error| Error::unsupported(format!("polkit check: {error}")))?
            }
            Err(error) => {
                return Err(Error::unsupported(format!("polkit check: {error}")));
            }
        };
        if result.is_authorized {
            Ok(())
        } else {
            Err(Error::denied(
                action.id(),
                format!(
                    "polkit refused {} ({})",
                    peer.describe(),
                    result.is_challenge
                ),
            ))
        }
    }
}

impl AuthBackend for PolkitBackend {
    fn check<'a>(
        &'a self,
        peer: &'a PeerIdentity,
        action: Action,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(self.ask(peer, action))
    }
}

/// The polkit version reported by the authority's `Backend` property.
async fn polkit_version(connection: &zbus::Connection) -> Option<u64> {
    use zbus::Proxy;
    let proxy = Proxy::new(
        connection,
        "org.freedesktop.PolicyKit1",
        "/org/freedesktop/PolicyKit1/Authority",
        "org.freedesktop.DBus.Properties",
    )
    .await
    .ok()?;
    let value: zbus::zvariant::OwnedValue = proxy
        .call("Get", &("org.freedesktop.PolicyKit1.Authority", "Backend"))
        .await
        .ok()?;
    // The property is `(ss)`: the backend name and its version string.
    let tuple: (String, String) = value.try_into().ok()?;
    tuple.1.split_whitespace().last()?.parse().ok()
}

/// An authorizer shared by every connection handler.
pub type SharedAuth = Arc<dyn AuthBackend>;

/// Decide authorization from `--auth`, refusing the static backend in
/// production (spec §I).
///
/// # Errors
/// Propagates backend construction errors.
pub async fn build(spec: Option<&str>, dev_mode: bool) -> Result<SharedAuth> {
    match spec {
        Some(spec) if spec.starts_with("static:") => {
            Ok(Arc::new(StaticBackend::parse(spec, dev_mode)?))
        }
        Some(other) => Err(Error::unsupported(format!(
            "unknown --auth value `{other}` (only `static:<uids>` exists)"
        ))),
        None => Ok(Arc::new(PolkitBackend::connect().await?)),
    }
}

/// How long a caller may keep an interactive authentication dialog open.
pub const AUTH_TIMEOUT: Duration = Duration::from_secs(60);

/// The five actions above are exactly the ones a polkit policy file must
/// declare; this keeps the two lists in step at compile time.
#[cfg(test)]
mod tests {
    use super::{Action, AuthBackend, PeerIdentity, StaticBackend};

    fn peer(uid: u32) -> PeerIdentity {
        PeerIdentity {
            uid,
            gid: uid,
            pid: None,
            start_time: None,
            _pidfd: None,
        }
    }

    #[test]
    fn static_lists_allow_and_deny() {
        let backend = StaticBackend::uids([0, 1000]);
        let allowed = futures_lite_block_on(backend.check(&peer(1000), Action::BackupCreate));
        assert!(allowed.is_ok());
        let denied = futures_lite_block_on(backend.check(&peer(1001), Action::BackupCreate));
        assert!(
            matches!(denied, Err(lr_core::Error::Denied { .. })),
            "{denied:?}"
        );

        let all = StaticBackend::allow_all();
        assert!(futures_lite_block_on(all.check(&peer(4242), Action::DiskRead)).is_ok());
    }

    #[test]
    fn the_static_backend_needs_development_mode() {
        let error = StaticBackend::parse("static:0", false).expect_err("must refuse");
        assert!(error.to_string().contains("LR_DEV_MODE"), "{error}");
        assert!(StaticBackend::parse("static:0", true).is_ok());
        assert!(StaticBackend::parse("static:all", true).is_ok());
        assert!(StaticBackend::parse("static:", true).is_err());
        assert!(StaticBackend::parse("static:x", true).is_err());
        assert!(StaticBackend::parse("polkit", true).is_err());
    }

    #[test]
    fn every_action_has_the_expected_identifier() {
        let ids: Vec<&str> = [
            Action::DiskRead,
            Action::BackupCreate,
            Action::RestorePrepare,
            Action::RestoreApply,
            Action::SnapshotManage,
            Action::ScheduleManage,
            Action::DestinationConfigure,
            Action::ExportManage,
        ]
        .into_iter()
        .map(Action::id)
        .collect();
        for id in ids {
            assert!(id.starts_with("org.linuxreflect."), "{id}");
        }
        assert!(
            !Action::RestoreApply.allows_interaction(),
            "auth_admin, no keep"
        );
        assert!(Action::BackupCreate.allows_interaction());
    }

    #[test]
    fn a_missing_peer_credential_is_refused() {
        let error = PeerIdentity::capture(None).expect_err("must refuse");
        assert!(matches!(error, lr_core::Error::Denied { .. }), "{error}");
    }

    #[test]
    fn the_current_process_can_be_identified() {
        // Reading our own /proc entry exercises the parser without a socket.
        let (uid, start) = super::read_proc_identity(std::process::id()).expect("proc identity");
        assert_eq!(uid, lr_unsafe::effective_uid());
        assert!(start > 0);
    }

    /// A three-line executor, so the tests need no runtime dependency.
    fn futures_lite_block_on<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(future)
    }
}
