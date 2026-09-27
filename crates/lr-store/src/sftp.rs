//! SFTP destination (spec §C.1, §D.3, §B; Slice S10).
//!
//! The engine is synchronous, so this module owns a small tokio runtime and
//! `block_on`s one operation at a time; readers and writers handed to the codec
//! wrap a remote file the same way. Nothing is ever resumed: a `.tmp` file is
//! written once, fsynced when the server supports `fsync@openssh.com`, and
//! renamed into place, so a dropped connection leaves no finalised image and a
//! retry starts with a fresh image UUID (spec §G.4, §L.2).
//!
//! Host keys are verified against `known_hosts` before authentication; the
//! identity comes from `ssh-agent` when one is reachable, otherwise from the
//! configured key file. Passwords are never accepted (spec §L.1).

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lr_core::io::ReadSeek;
use lr_core::{Error, Result, SetId};
use russh::client::{self, Handle};
use russh::keys::agent::client::AgentClient;
use russh::keys::{PrivateKeyWithHashAlg, PublicKeyOrCertificate, load_secret_key};
use russh_sftp::client::error::Error as SftpError;
use russh_sftp::client::{RawSftpSession, SftpSession};
use russh_sftp::protocol::{FileAttributes, OpenFlags, Packet, StatusCode};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::runtime::Runtime;

use crate::known_hosts::HostKeyVerifier;
use crate::uri::DestinationUri;
use crate::{
    Destination, DestinationOptions, Durability, LockOwner, LockRecord, SetHandle, SetLock,
    TempFile, WriteSeekSync, now_unix,
};

/// Connection timeout for one operation.
pub const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);

/// How often a failed operation is retried before the job aborts.
pub const RETRY_ATTEMPTS: u32 = 5;
/// First backoff delay; doubled after every failed attempt.
pub const RETRY_BASE_DELAY: Duration = Duration::from_millis(250);
/// Longest backoff delay.
pub const RETRY_MAX_DELAY: Duration = Duration::from_secs(8);

/// Connection parameters for one server.
#[derive(Debug, Clone)]
pub struct SftpConfig {
    /// Host name or address.
    pub host: String,
    /// TCP port.
    pub port: u16,
    /// Login user; the current user when absent.
    pub user: Option<String>,
    /// Private key file.
    pub identity: Option<PathBuf>,
    /// `known_hosts` file.
    pub known_hosts: Option<PathBuf>,
    /// Skip host-key verification (tests only).
    pub insecure_ignore_host_key: bool,
    /// Directory on the server that holds the sets.
    pub root: String,
    /// Set name inside the root.
    pub set_name: String,
}

impl SftpConfig {
    /// Build a config from a parsed URI and options.
    ///
    /// # Errors
    /// Returns [`Error::Unsupported`] for a local URI or a missing user.
    pub fn from_uri(parsed: &DestinationUri, options: &DestinationOptions) -> Result<Self> {
        let DestinationUri::Sftp {
            user,
            host,
            port,
            path,
        } = parsed
        else {
            return Err(Error::unsupported("not an sftp destination"));
        };
        if options.set_name.is_empty() {
            return Err(Error::unsupported("an sftp destination needs a set name"));
        }
        Ok(Self {
            host: host.clone(),
            port: *port,
            user: user.clone(),
            identity: options.identity.clone(),
            known_hosts: options.known_hosts.clone(),
            insecure_ignore_host_key: options.insecure_ignore_host_key,
            root: path.trim_end_matches('/').to_owned(),
            set_name: options.set_name.clone(),
        })
    }

    /// The login user, defaulting to the current one.
    ///
    /// # Errors
    /// Returns [`Error::Unsupported`] when no user name can be determined.
    pub fn login_user(&self) -> Result<String> {
        if let Some(user) = &self.user {
            return Ok(user.clone());
        }
        for key in ["USER", "LOGNAME"] {
            if let Ok(value) = std::env::var(key)
                && !value.is_empty()
            {
                return Ok(value);
            }
        }
        Err(Error::unsupported(
            "no user name: write the destination as sftp://user@host/path",
        ))
    }

    /// Path of the set on the server (no trailing slash).
    #[must_use]
    pub fn set_path(&self) -> String {
        format!("{}/{}", self.root.trim_end_matches('/'), self.set_name)
    }

    /// Path of one file inside the set.
    #[must_use]
    pub fn file_path(&self, name: &str) -> String {
        format!("{}/{name}", self.set_path())
    }
}

/// An SFTP directory backend with a leased set lock.
pub struct SftpDestination {
    config: SftpConfig,
    runtime: Arc<Runtime>,
    session: Mutex<Option<Arc<Session>>>,
}

/// A boxed future produced by one remote operation.
type SftpFuture<T> = Pin<Box<dyn Future<Output = Result<T>> + Send>>;

/// A live connection.
struct Session {
    /// Keeps the SSH connection (and its channels) alive.
    _handle: Handle<ClientHandler>,
    sftp: Arc<SftpSession>,
    /// A second SFTP channel for the `@openssh.com` extensions the high-level
    /// session does not expose (`posix-rename`).
    raw: Arc<RawSftpSession>,
    /// Extensions the server announced, with their versions.
    extensions: std::collections::HashMap<String, String>,
}

impl Session {
    fn supports(&self, extension: &str) -> bool {
        self.extensions
            .get(extension)
            .is_some_and(|version| version == "1")
    }
}

/// The OpenSSH extension that renames over an existing file atomically.
const POSIX_RENAME: &str = "posix-rename@openssh.com";
/// The OpenSSH extension that flushes an open file to stable storage.
const FSYNC: &str = "fsync@openssh.com";

/// Verifies the server key while the handshake runs.
struct ClientHandler {
    verifier: HostKeyVerifier,
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        let public = key.public_key();
        let algorithm = public.algorithm().as_str().to_owned();
        let blob = public
            .to_openssh()
            .ok()
            .and_then(|text| text.split_whitespace().nth(1).map(str::to_owned))
            .unwrap_or_default();
        let trusted = self.verifier.verify(&algorithm, &blob);
        if !trusted {
            tracing::error!(algorithm, "the server key is not in known_hosts; refusing");
        }
        Ok(trusted)
    }
}

impl SftpDestination {
    /// Connect to `uri` as described by `options`.
    ///
    /// # Errors
    /// Returns [`Error::Unsupported`] for bad options and I/O or protocol
    /// errors for a refused connection or a rejected host key.
    pub fn connect(parsed: &DestinationUri, options: &DestinationOptions) -> Result<Self> {
        let config = SftpConfig::from_uri(parsed, options)?;
        let identity_mode = check_identity_permissions(config.identity.as_deref())?;
        let _ = identity_mode;
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .map_err(Error::Io)?,
        );
        let destination = Self {
            config,
            runtime,
            session: Mutex::new(None),
        };
        // Fail fast: a bad host key or key file must surface before any work.
        let _ = destination.session()?;
        Ok(destination)
    }

    /// The current connection, connecting and authenticating if needed.
    fn connection(&self) -> Result<Arc<Session>> {
        if let Some(session) = self
            .session
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            return Ok(Arc::clone(session));
        }
        let connected = Arc::new(self.runtime.block_on(connect_async(&self.config))?);
        *self
            .session
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::clone(&connected));
        Ok(connected)
    }

    /// The current SFTP session, connecting if needed.
    fn session(&self) -> Result<Arc<SftpSession>> {
        Ok(Arc::clone(&self.connection()?.sftp))
    }

    /// Forget the connection so the next operation reconnects.
    fn drop_connection(&self) {
        *self
            .session
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    /// One attempt of an operation that must not be blindly repeated; a
    /// transient failure drops the connection for the next attempt.
    fn once<T>(&self, operation: impl FnOnce(&Session) -> SftpFuture<T>) -> Result<T> {
        let connection = self.connection()?;
        let outcome = self.runtime.block_on(operation(&connection));
        if let Err(error) = &outcome
            && is_transient(error)
        {
            self.drop_connection();
        }
        outcome
    }

    fn retry() -> crate::publish::Retry {
        crate::publish::Retry {
            attempts: RETRY_ATTEMPTS,
            delay: RETRY_BASE_DELAY,
            max_delay: RETRY_MAX_DELAY,
        }
    }

    /// Run one remote operation with bounded retries.
    ///
    /// A transient failure drops the session so the next attempt reconnects;
    /// a final failure is returned to the caller, which aborts the job.
    fn run<T>(
        &self,
        label: &str,
        mut operation: impl FnMut(Arc<SftpSession>) -> SftpFuture<T>,
    ) -> Result<T> {
        self.run_with(label, |connection| operation(Arc::clone(&connection.sftp)))
    }

    /// [`Self::run`] for operations that need the whole connection.
    fn run_with<T>(
        &self,
        label: &str,
        mut operation: impl FnMut(&Session) -> SftpFuture<T>,
    ) -> Result<T> {
        let mut delay = RETRY_BASE_DELAY;
        let mut last = None;
        for attempt in 0..RETRY_ATTEMPTS {
            let session = match self.connection() {
                Ok(session) => session,
                Err(error) => {
                    last = Some(error);
                    std::thread::sleep(delay);
                    delay = (delay * 2).min(RETRY_MAX_DELAY);
                    continue;
                }
            };
            let future = operation(&session);
            match self.runtime.block_on(future) {
                Ok(value) => return Ok(value),
                Err(error) => {
                    let transient = is_transient(&error);
                    tracing::warn!(label, %error, transient, attempt, "sftp operation failed");
                    if !transient || attempt + 1 == RETRY_ATTEMPTS {
                        return Err(error);
                    }
                    self.drop_connection();
                    std::thread::sleep(delay);
                    delay = (delay * 2).min(RETRY_MAX_DELAY);
                    last = Some(error);
                }
            }
        }
        Err(last.unwrap_or_else(|| Error::NetworkTimeout(label.to_owned())))
    }

    /// The handle of this destination's set.
    fn handle(&self, set: &SetId) -> SetHandle {
        SetHandle {
            set_id: *set,
            // A URI, not a path: `local_root` must refuse it so no caller can
            // mistake a remote set for a local directory.
            path: format!(
                "sftp://{}/{}",
                self.config.host,
                self.config.set_path().trim_start_matches('/')
            ),
        }
    }

    /// Join a set-relative name onto the destination's set directory.
    fn path(&self, name: &str) -> String {
        self.config.file_path(name)
    }
}

/// Open an SFTP destination for the factory.
///
/// # Errors
/// See [`SftpDestination::connect`].
pub fn open(parsed: &DestinationUri, options: &DestinationOptions) -> Result<Arc<dyn Destination>> {
    Ok(Arc::new(SftpDestination::connect(parsed, options)?))
}

/// A private key must not be readable by anyone else.
fn check_identity_permissions(identity: Option<&Path>) -> Result<Option<u32>> {
    use std::os::unix::fs::PermissionsExt;
    let Some(path) = identity else {
        return Ok(None);
    };
    let mode = std::fs::metadata(path)
        .map_err(Error::Io)?
        .permissions()
        .mode()
        & 0o777;
    if mode & 0o077 != 0 {
        return Err(Error::unsupported(format!(
            "the identity file {} is mode {mode:o}; SSH keys must be private (0600)",
            path.display()
        )));
    }
    Ok(Some(mode))
}

/// Connect, authenticate and open the SFTP subsystem.
async fn connect_async(config: &SftpConfig) -> Result<Session> {
    let verifier = HostKeyVerifier::load(
        &config.host,
        config.port,
        config.known_hosts.as_deref(),
        config.insecure_ignore_host_key,
    )?;
    tracing::debug!(
        host = config.host,
        entries = verifier.explain(),
        "connecting"
    );

    let ssh_config = client::Config {
        inactivity_timeout: Some(OPERATION_TIMEOUT),
        keepalive_interval: Some(Duration::from_secs(15)),
        nodelay: true,
        ..client::Config::default()
    };
    let mut handle = client::connect(
        Arc::new(ssh_config),
        (config.host.as_str(), config.port),
        ClientHandler { verifier },
    )
    .await
    .map_err(|error| {
        Error::NetworkTimeout(format!("ssh handshake with {}: {error}", config.host))
    })?;

    let user = config.login_user()?;
    authenticate(&mut handle, config, &user).await?;

    let channel = handle
        .channel_open_session()
        .await
        .map_err(|error| Error::NetworkTimeout(format!("opening a session: {error}")))?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|error| {
            Error::unsupported(format!("the server has no sftp subsystem: {error}"))
        })?;
    let stream = channel.into_stream();
    let sftp = SftpSession::new(stream)
        .await
        .map_err(|error| sftp_error("sftp session", error))?;
    sftp.set_timeout(OPERATION_TIMEOUT.as_secs());

    let raw_channel = handle
        .channel_open_session()
        .await
        .map_err(|error| Error::NetworkTimeout(format!("opening a session: {error}")))?;
    raw_channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|error| {
            Error::unsupported(format!("the server has no sftp subsystem: {error}"))
        })?;
    let raw = RawSftpSession::new(raw_channel.into_stream());
    raw.set_timeout(OPERATION_TIMEOUT.as_secs());
    let version = raw
        .init()
        .await
        .map_err(|error| sftp_error("sftp session", error))?;
    Ok(Session {
        _handle: handle,
        sftp: Arc::new(sftp),
        raw: Arc::new(raw),
        extensions: version.extensions,
    })
}

/// Authenticate with `ssh-agent` first, then the identity file.
async fn authenticate(
    handle: &mut Handle<ClientHandler>,
    config: &SftpConfig,
    user: &str,
) -> Result<()> {
    if std::env::var_os("SSH_AUTH_SOCK").is_some() {
        match AgentClient::connect_env().await {
            Ok(mut agent) => {
                let identities = agent
                    .request_identities()
                    .await
                    .map_err(|error| Error::unsupported(format!("ssh-agent: {error}")))?;
                for identity in identities {
                    // Agent certificates need `authenticate_openssh_cert`;
                    // plain agent keys are what this slice supports.
                    let russh::keys::agent::AgentIdentity::PublicKey { key, .. } = identity else {
                        continue;
                    };
                    let result = handle
                        .authenticate_publickey_with(user, key, None, &mut agent)
                        .await
                        .map_err(|error| Error::unsupported(format!("ssh-agent auth: {error}")))?;
                    if matches!(result, client::AuthResult::Success) {
                        tracing::debug!(user, "authenticated with ssh-agent");
                        return Ok(());
                    }
                }
                tracing::debug!("ssh-agent offered no accepted identity");
            }
            Err(error) => tracing::warn!(%error, "SSH_AUTH_SOCK is unusable"),
        }
    }

    let Some(identity) = &config.identity else {
        return Err(Error::unsupported(
            "no identity: pass --identity or start an ssh-agent with a loaded key",
        ));
    };
    let key = load_secret_key(identity, None).map_err(|error| {
        Error::unsupported(format!(
            "cannot load the identity {}: {error}",
            identity.display()
        ))
    })?;
    let result = handle
        .authenticate_publickey(user, PrivateKeyWithHashAlg::new(Arc::new(key), None))
        .await
        .map_err(|error| Error::unsupported(format!("public-key auth: {error}")))?;
    if matches!(result, client::AuthResult::Success) {
        tracing::debug!(user, "authenticated with the identity file");
        return Ok(());
    }
    Err(Error::unsupported(format!(
        "the server refused the key for user '{user}'"
    )))
}

/// Map an SFTP failure, marking connection loss as retryable.
fn sftp_error(context: &str, error: SftpError) -> Error {
    match error {
        SftpError::Status(status)
            if matches!(
                status.status_code,
                StatusCode::ConnectionLost | StatusCode::NoConnection
            ) =>
        {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                format!("{context}: {}", status.error_message),
            ))
        }
        SftpError::Timeout => Error::NetworkTimeout(context.to_owned()),
        SftpError::Status(status) if status.status_code == StatusCode::NoSuchFile => {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!(
                    "{context}: {}: {}",
                    status.status_code, status.error_message
                ),
            ))
        }
        other => Error::corrupt(format!("{context}: {other}")),
    }
}

/// `true` when an error is worth retrying.
pub(crate) fn is_transient(error: &Error) -> bool {
    match error {
        Error::NetworkTimeout(_) => true,
        Error::Io(io) => matches!(
            io.kind(),
            std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::NotConnected
                | std::io::ErrorKind::WouldBlock
        ),
        other => {
            let text = other.to_string().to_lowercase();
            [
                "connection lost",
                "no connection",
                "timeout",
                "broken pipe",
                "reset by peer",
                "unexpected packet",
                "session closed",
            ]
            .iter()
            .any(|needle| text.contains(needle))
        }
    }
}

fn io_other(error: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(error.to_string())
}

/// A remote file open for writing.
struct SftpWriter {
    runtime: Arc<Runtime>,
    file: russh_sftp::client::fs::File,
}

impl std::io::Write for SftpWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.runtime
            .block_on(self.file.write(buf))
            .map_err(io_other)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.runtime.block_on(self.file.flush()).map_err(io_other)
    }
}

impl std::io::Seek for SftpWriter {
    fn seek(&mut self, position: std::io::SeekFrom) -> std::io::Result<u64> {
        self.runtime
            .block_on(self.file.seek(position))
            .map_err(io_other)
    }
}

impl WriteSeekSync for SftpWriter {
    fn sync_all(&mut self) -> std::io::Result<()> {
        // OpenSSH servers support `fsync@openssh.com`; others answer
        // pseudo-successfully, and the rename in `publish_new` still orders the
        // data after the metadata that matters.
        self.runtime
            .block_on(self.file.sync_all())
            .map_err(io_other)
    }
}

/// A remote file open for reading.
struct SftpReader {
    runtime: Arc<Runtime>,
    file: russh_sftp::client::fs::File,
}

impl std::io::Read for SftpReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.runtime.block_on(self.file.read(buf)).map_err(io_other)
    }
}

impl std::io::Seek for SftpReader {
    fn seek(&mut self, position: std::io::SeekFrom) -> std::io::Result<u64> {
        self.runtime
            .block_on(self.file.seek(position))
            .map_err(io_other)
    }
}

/// A held remote lease. SFTP offers no compare-and-swap, so the holder
/// re-reads the lock before every refresh and every [`SetLock::verify`] and
/// acts only while it still carries this acquisition's token (R21). A
/// replacement that lands between that read and the refresh's write is the
/// one window remote storage cannot close; the replacing holder's own
/// verification then sees the old token and stops instead.
struct RemoteLease {
    runtime: Arc<Runtime>,
    session: Arc<SftpSession>,
    path: String,
    record: LockRecord,
    ttl: Duration,
    /// When the lease was last written; monotonic, so it keeps counting
    /// while the process is paused.
    refreshed: Mutex<std::time::Instant>,
    lost: Mutex<Option<String>>,
    stop: std::sync::atomic::AtomicBool,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl RemoteLease {
    /// `Ok(())` while the lock still carries this holder's token.
    fn still_ours(&self) -> std::result::Result<(), String> {
        let bytes = self
            .runtime
            .block_on(self.session.read(&self.path))
            .map_err(|error| format!("the lock cannot be read: {error}"))?;
        let record: LockRecord = serde_json::from_slice(&bytes)
            .map_err(|error| format!("the lock is unreadable: {error}"))?;
        if record.token == self.record.token {
            Ok(())
        } else {
            Err(format!("the lock now belongs to {}", record.describe()))
        }
    }

    fn lose(&self, reason: String) {
        tracing::error!(path = %self.path, %reason, "remote set lock lease lost");
        self.lost
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_or_insert(reason);
    }

    fn refresh_loop(&self, interval: Duration) {
        use std::sync::atomic::Ordering;
        let slice = Duration::from_millis(50);
        loop {
            let mut waited = Duration::ZERO;
            while waited < interval {
                if self.stop.load(Ordering::SeqCst) {
                    return;
                }
                std::thread::sleep(slice.min(interval - waited));
                waited += slice;
            }
            if self.stop.load(Ordering::SeqCst) {
                return;
            }
            if let Err(reason) = self.still_ours() {
                self.lose(reason);
                return;
            }
            let now = now_unix();
            let payload = serde_json::to_vec(&LockRecord {
                created: now,
                ..self.record.clone()
            })
            .unwrap_or_default();
            // WRITE | TRUNCATE without CREATE: a removed lock is not revived.
            let written = self.runtime.block_on(async {
                let mut file = self
                    .session
                    .open_with_flags(&self.path, OpenFlags::WRITE | OpenFlags::TRUNCATE)
                    .await
                    .map_err(|error| error.to_string())?;
                file.write_all(&payload)
                    .await
                    .map_err(|error| error.to_string())?;
                file.shutdown().await.map_err(|error| error.to_string())
            });
            if let Err(error) = written {
                self.lose(format!("refreshing it failed: {error}"));
                return;
            }
            *self
                .refreshed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = std::time::Instant::now();
        }
    }

    /// See [`SetLock::verify`].
    fn verify(&self, display: &str) -> Result<()> {
        if let Some(reason) = self
            .lost
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
        {
            return Err(crate::lease_lost(display, &reason));
        }
        self.still_ours()
            .map_err(|reason| crate::lease_lost(display, &reason))?;
        let refreshed = *self
            .refreshed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !self.ttl.is_zero() && refreshed.elapsed() > self.ttl {
            return Err(crate::lease_lost(
                display,
                "it expired while the job was not running, and another job may have broken it",
            ));
        }
        Ok(())
    }
}

/// Stops the refresher and releases the remote lock on drop.
struct RemoteLeaseGuard(Arc<RemoteLease>);

impl Drop for RemoteLeaseGuard {
    fn drop(&mut self) {
        let lease = &self.0;
        lease.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(thread) = lease
            .thread
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            let _ = thread.join();
        }
        // Remove only a lock that is still ours.
        if lease.still_ours().is_ok() {
            let _ = lease
                .runtime
                .block_on(lease.session.remove_file(&lease.path));
        }
    }
}

impl Destination for SftpDestination {
    fn open_set(&self, set: &SetId) -> Result<SetHandle> {
        let path = self.config.set_path();
        self.run("mkdir", |session| {
            let path = path.clone();
            Box::pin(async move {
                mkdir_all(&session, &path)
                    .await
                    .map_err(|error| sftp_error("mkdir", error))
            })
        })?;
        Ok(self.handle(set))
    }

    fn open_existing_set(&self, set: &SetId) -> Result<SetHandle> {
        let path = self.config.set_path();
        let is_dir = self.run("stat", |session| {
            let path = path.clone();
            Box::pin(async move {
                match session.metadata(&path).await {
                    Ok(metadata) => Ok(Some(metadata.is_dir())),
                    Err(error) => match sftp_error("stat", error) {
                        Error::Io(io) if io.kind() == std::io::ErrorKind::NotFound => Ok(None),
                        other => Err(other),
                    },
                }
            })
        })?;
        match is_dir {
            Some(true) => Ok(self.handle(set)),
            Some(false) => Err(Error::unsupported(format!("{path} is not a directory"))),
            None => Err(crate::no_such_set(
                &self.config.set_name,
                &format!("sftp://{}{}", self.config.host, self.config.root),
            )),
        }
    }

    fn lock_set(&self, set: &SetHandle, owner: &LockOwner, ttl: Duration) -> Result<SetLock> {
        self.acquire_lock(set, owner, ttl, false)
    }

    fn lock_set_breaking_stale(
        &self,
        set: &SetHandle,
        owner: &LockOwner,
        ttl: Duration,
    ) -> Result<SetLock> {
        self.acquire_lock(set, owner, ttl, true)
    }

    fn create_tmp(&self, set: &SetHandle, final_name: &str) -> Result<TempFile> {
        let _ = set;
        let name = crate::temp_name(final_name)?;
        let path = self.path(&name);
        // A name may contain `/` (spec §D.3's `<chain_id>/<file>`); its
        // directory has to exist before the file can be created.
        if let Some((parent, _)) = path.rsplit_once('/') {
            let parent = format!("{parent}/");
            self.run("mkdir", |session| {
                let parent = parent.clone();
                Box::pin(async move {
                    mkdir_all(&session, &parent)
                        .await
                        .map_err(|error| sftp_error("mkdir", error))
                })
            })?;
        }
        let session = self.session()?;
        // Exclusive create: a name planted on the server is never reused.
        let file = self
            .runtime
            .block_on(session.open_with_flags(
                &path,
                OpenFlags::CREATE | OpenFlags::WRITE | OpenFlags::EXCLUDE,
            ))
            .map_err(|error| sftp_error("create", error))?;
        Ok(TempFile {
            name,
            writer: Box::new(SftpWriter {
                runtime: Arc::clone(&self.runtime),
                file,
            }),
        })
    }

    fn publish_new(&self, set: &SetHandle, tmp: &str, final_name: &str) -> Result<Durability> {
        let _ = set;
        crate::publish::publish_new_with(
            self,
            &self.path(tmp),
            &self.path(final_name),
            Self::retry(),
        )
    }

    fn replace(&self, set: &SetHandle, tmp: &str, final_name: &str) -> Result<Durability> {
        let _ = set;
        crate::publish::replace_with(self, &self.path(tmp), &self.path(final_name), Self::retry())
    }

    fn open_ro(&self, set: &SetHandle, name: &str) -> Result<Box<dyn ReadSeek + Send>> {
        let _ = set;
        let path = self.path(name);
        let session = self.session()?;
        let file = self
            .runtime
            .block_on(session.open(&path))
            .map_err(|error| sftp_error("open", error))?;
        Ok(Box::new(SftpReader {
            runtime: Arc::clone(&self.runtime),
            file,
        }))
    }

    fn list(&self, set: &SetHandle) -> Result<Vec<String>> {
        let _ = set;
        let root = self.config.set_path();
        self.run("list", |session| {
            let root = root.clone();
            Box::pin(async move {
                let mut found = Vec::new();
                let root = root.trim_end_matches('/').to_owned();
                let mut queue = vec![(root.clone(), String::new())];
                while let Some((directory, prefix)) = queue.pop() {
                    let entries = session
                        .read_dir(&directory)
                        .await
                        .map_err(|error| sftp_error("read_dir", error))?;
                    for entry in entries {
                        let name = entry.file_name();
                        if name == "." || name == ".." {
                            continue;
                        }
                        let relative = format!("{prefix}{name}");
                        let child = format!("{directory}/{name}");
                        if entry.metadata().is_dir() {
                            queue.push((child, format!("{relative}/")));
                        } else if !relative.ends_with(".tmp") {
                            found.push(relative);
                        }
                    }
                }
                found.sort();
                Ok(found)
            })
        })
    }

    fn list_set_names(&self) -> Result<Vec<String>> {
        let root = self.config.root.trim_end_matches('/').to_owned();
        self.run("list sets", |session| {
            let root = root.clone();
            Box::pin(async move {
                let mut names = Vec::new();
                let entries = session
                    .read_dir(&root)
                    .await
                    .map_err(|error| sftp_error("read_dir", error))?;
                for entry in entries {
                    let name = entry.file_name();
                    if name == "." || name == ".." || !entry.metadata().is_dir() {
                        continue;
                    }
                    // Depth-first until the first image: a set is a
                    // directory holding at least one `.lrimg`.
                    let mut queue = vec![format!("{root}/{name}")];
                    let mut found = false;
                    while let Some(directory) = queue.pop() {
                        let children = session
                            .read_dir(&directory)
                            .await
                            .map_err(|error| sftp_error("read_dir", error))?;
                        for child in children {
                            let child_name = child.file_name();
                            if child_name == "." || child_name == ".." {
                                continue;
                            }
                            if child.metadata().is_dir() {
                                queue.push(format!("{directory}/{child_name}"));
                            } else if child_name.ends_with(".lrimg") {
                                found = true;
                                break;
                            }
                        }
                        if found {
                            break;
                        }
                    }
                    if found {
                        names.push(name);
                    }
                }
                names.sort();
                Ok(names)
            })
        })
    }

    fn delete(&self, set: &SetHandle, name: &str) -> Result<()> {
        let _ = set;
        let path = self.path(name);
        self.run("delete", |session| {
            let path = path.clone();
            Box::pin(async move {
                session
                    .remove_file(&path)
                    .await
                    .map_err(|error| sftp_error("delete", error))
            })
        })
    }
}

impl SftpDestination {
    /// Take the remote set lock (spec §D.3: exclusive create).
    fn acquire_lock(
        &self,
        set: &SetHandle,
        owner: &LockOwner,
        ttl: Duration,
        break_stale: bool,
    ) -> Result<SetLock> {
        let _ = set;
        let path = self.path("set.lock");
        let record = LockRecord {
            owner: owner.clone(),
            created: now_unix(),
            ttl_secs: ttl.as_secs(),
            token: lr_core::Id::generate().map_err(Error::Io)?.to_string(),
        };
        let payload = serde_json::to_vec(&record)
            .map_err(|error| Error::corrupt(format!("set lock record: {error}")))?;
        let session = self.session()?;

        for _ in 0..2 {
            let opened = self.runtime.block_on(session.open_with_flags(
                &path,
                OpenFlags::CREATE | OpenFlags::WRITE | OpenFlags::EXCLUDE,
            ));
            match opened {
                Ok(mut file) => {
                    let written = self.runtime.block_on(async {
                        file.write_all(&payload).await.map_err(io_other)?;
                        file.flush().await.map_err(io_other)?;
                        file.sync_all().await.map_err(io_other)?;
                        let _ = file.close().await;
                        Ok::<(), std::io::Error>(())
                    });
                    written.map_err(Error::Io)?;
                    let lease = self.start_lease(Arc::clone(&session), path.clone(), record, ttl);
                    let check = {
                        let lease = Arc::clone(&lease);
                        let path = path.clone();
                        move || lease.verify(&path)
                    };
                    return Ok(SetLock::with_check(path, RemoteLeaseGuard(lease), check));
                }
                Err(error) => {
                    let existing = self
                        .runtime
                        .block_on(session.read(&path))
                        .ok()
                        .and_then(|bytes| serde_json::from_slice::<LockRecord>(&bytes).ok());
                    match existing {
                        Some(existing) if existing.is_stale(now_unix()) && break_stale => {
                            self.runtime
                                .block_on(session.remove_file(&path))
                                .map_err(|error| sftp_error("remove stale lock", error))?;
                            continue;
                        }
                        Some(existing) => {
                            return Err(Error::SetLocked {
                                owner: existing.describe(),
                            });
                        }
                        None => {
                            return Err(Error::SetLocked {
                                owner: format!("unreadable {path} ({error})"),
                            });
                        }
                    }
                }
            }
        }
        Err(Error::SetLocked {
            owner: format!("the lock at {path} keeps being replaced"),
        })
    }

    /// Keep the lease fresh until the lock is dropped.
    fn start_lease(
        &self,
        session: Arc<SftpSession>,
        path: String,
        record: LockRecord,
        ttl: Duration,
    ) -> Arc<RemoteLease> {
        let lease = Arc::new(RemoteLease {
            runtime: Arc::clone(&self.runtime),
            session,
            path,
            refreshed: Mutex::new(std::time::Instant::now()),
            record,
            ttl,
            lost: Mutex::new(None),
            stop: std::sync::atomic::AtomicBool::new(false),
            thread: Mutex::new(None),
        });
        // A zero lease never expires, so there is nothing to refresh.
        if !ttl.is_zero() {
            let interval = (ttl / 3).max(Duration::from_millis(250));
            let refresher = Arc::clone(&lease);
            let thread = std::thread::Builder::new()
                .name("lr-sftp-lock".to_owned())
                .spawn(move || refresher.refresh_loop(interval))
                .ok();
            *lease
                .thread
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = thread;
        }
        lease
    }
}

impl crate::publish::RemoteOps for SftpDestination {
    fn size(&self, path: &str) -> Result<Option<u64>> {
        let path = path.to_owned();
        self.run("stat", |session| {
            let path = path.clone();
            Box::pin(async move {
                match session.metadata(&path).await {
                    Ok(metadata) => Ok(Some(metadata.size.unwrap_or(0))),
                    Err(error) => match sftp_error("stat", error) {
                        Error::Io(io) if io.kind() == std::io::ErrorKind::NotFound => Ok(None),
                        other => Err(other),
                    },
                }
            })
        })
    }

    fn sync(&self, path: &str) -> Result<bool> {
        let path = path.to_owned();
        self.run_with("fsync", |connection| {
            let supported = connection.supports(FSYNC);
            let raw = Arc::clone(&connection.raw);
            let path = path.clone();
            Box::pin(async move {
                if !supported {
                    return Ok(false);
                }
                let handle = raw
                    .open(&path, OpenFlags::READ, FileAttributes::default())
                    .await
                    .map_err(|error| sftp_error("open for fsync", error))?
                    .handle;
                let synced = raw
                    .fsync(handle.as_str())
                    .await
                    .map_err(|error| sftp_error("fsync", error));
                let _ = raw.close(handle).await;
                synced.map(|_| true)
            })
        })
    }

    fn rename(&self, from: &str, to: &str) -> Result<()> {
        let (from, to) = (from.to_owned(), to.to_owned());
        self.once(|connection| {
            let sftp = Arc::clone(&connection.sftp);
            Box::pin(async move {
                // Plain SSH_FXP_RENAME refuses to replace an existing file.
                sftp.rename(&from, &to)
                    .await
                    .map_err(|error| sftp_error("rename", error))
            })
        })
    }

    fn rename_over(&self, from: &str, to: &str) -> Result<bool> {
        let (from, to) = (from.to_owned(), to.to_owned());
        self.once(|connection| {
            let supported = connection.supports(POSIX_RENAME);
            let raw = Arc::clone(&connection.raw);
            Box::pin(async move {
                if !supported {
                    return Ok(false);
                }
                posix_rename(&raw, &from, &to)
                    .await
                    .map(|()| true)
                    .map_err(|error| sftp_error("posix-rename", error))
            })
        })
    }

    fn remove(&self, path: &str) -> Result<()> {
        let path = path.to_owned();
        self.run("delete", |session| {
            let path = path.clone();
            Box::pin(async move {
                session
                    .remove_file(&path)
                    .await
                    .map_err(|error| sftp_error("delete", error))
            })
        })
    }
}

/// `posix-rename@openssh.com`: rename over an existing file atomically.
async fn posix_rename(
    raw: &RawSftpSession,
    from: &str,
    to: &str,
) -> std::result::Result<(), SftpError> {
    let mut data = Vec::with_capacity(8 + from.len() + to.len());
    for text in [from, to] {
        let length = u32::try_from(text.len())
            .map_err(|_| SftpError::UnexpectedBehavior("path too long".to_owned()))?;
        data.extend_from_slice(&length.to_be_bytes());
        data.extend_from_slice(text.as_bytes());
    }
    match raw.extended(POSIX_RENAME, data).await? {
        Packet::Status(status) if status.status_code == StatusCode::Ok => Ok(()),
        Packet::Status(status) => Err(SftpError::Status(status)),
        _ => Err(SftpError::UnexpectedPacket),
    }
}

/// Recursively create a directory (`mkdir -p`).
async fn mkdir_all(session: &SftpSession, path: &str) -> std::result::Result<(), SftpError> {
    let mut current = String::new();
    for component in path.split('/').filter(|part| !part.is_empty()) {
        current.push('/');
        current.push_str(component);
        // `create_dir` reports "already exists" as a generic failure, so ask
        // whether it is really there before treating the error as fatal.
        if session.metadata(&current).await.is_ok() {
            continue;
        }
        if let Err(error) = session.create_dir(&current).await {
            if session.metadata(&current).await.is_ok() {
                continue;
            }
            return Err(error);
        }
    }
    Ok(())
}
