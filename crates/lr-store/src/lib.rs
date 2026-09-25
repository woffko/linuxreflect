//! Backup destinations (spec §C.1, §D.3, Slice S6 subset).
//!
//! Slice S6 implements the local destination only: plain directories with
//! `fsync` + `rename` finalisation. Mounted network paths and SFTP, together
//! with the set lock, arrive with Slice S10; [`Destination::lock_set`] already
//! exists so the trait shape matches spec §C.1, and the local backend refuses
//! it with a clear error until then.
#![forbid(unsafe_code)]

pub mod known_hosts;
pub mod local;
pub mod sftp;
pub mod uri;

pub use local::LocalDestination;
pub use uri::{DestinationUri, ImageLocation};

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use lr_core::{Error, Result, SetId};

// One definition of these traits lives in `lr-core` so the format codec and
// the destinations agree on what a boxed reader is.
pub use lr_core::io::{ReadSeek, WriteSeekSync};

/// A resolved backup set on one destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetHandle {
    /// Set identifier.
    pub set_id: SetId,
    /// Where the set lives on the destination (a path or remote URL).
    pub path: String,
}

/// Who holds a set lock (spec §D.3).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LockOwner {
    /// Stable identifier of the host running the job.
    pub host_id: String,
    /// Process id of the daemon or client holding the lock.
    pub pid: u32,
}

impl LockOwner {
    /// The owner of the current process (`machine-id`, or the hostname).
    #[must_use]
    pub fn local() -> Self {
        Self {
            host_id: machine_id(),
            pid: std::process::id(),
        }
    }
}

/// The machine identifier, falling back to the host name.
#[must_use]
pub fn machine_id() -> String {
    for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
        if let Ok(text) = std::fs::read_to_string(path) {
            let id = text.trim();
            if !id.is_empty() {
                return id.to_owned();
            }
        }
    }
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|name| name.trim().to_owned())
        .unwrap_or_else(|_| "unknown-host".to_owned())
}

/// On-disk content of a set lock (spec §D.3).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LockRecord {
    /// Owner of the lock.
    #[serde(flatten)]
    pub owner: LockOwner,
    /// Creation time, seconds since the Unix epoch.
    pub created: u64,
    /// Lease duration in seconds; the lock is stale after `created + ttl`.
    pub ttl_secs: u64,
}

impl LockRecord {
    /// `true` when the lease has expired at `now`.
    #[must_use]
    pub const fn is_stale(&self, now: u64) -> bool {
        // A zero ttl means "no expiry" and is never stale.
        self.ttl_secs != 0 && now > self.created.saturating_add(self.ttl_secs)
    }

    /// Human-readable owner for [`lr_core::Error::SetLocked`].
    #[must_use]
    pub fn describe(&self) -> String {
        format!(
            "{} pid {} since {} (ttl {}s)",
            self.owner.host_id, self.owner.pid, self.created, self.ttl_secs
        )
    }
}

/// A held set lock. Dropping it releases the lock.
pub struct SetLock {
    /// Path or URL of the lock file, for diagnostics.
    pub path: String,
    /// Ownership token; dropping it releases the lock.
    release: Option<Box<dyn Send + Sync>>,
}

impl Drop for SetLock {
    fn drop(&mut self) {
        // Releasing the lock must not depend on field drop order.
        drop(self.release.take());
    }
}

impl SetLock {
    /// Build a lock, keeping `release` alive until the lock is dropped.
    pub fn new(path: impl Into<String>, release: impl Send + Sync + 'static) -> Self {
        Self {
            path: path.into(),
            release: Some(Box::new(release)),
        }
    }
}

impl std::fmt::Debug for SetLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SetLock").field("path", &self.path).finish()
    }
}

/// How to open a destination.
#[derive(Debug, Clone, Default)]
pub struct DestinationOptions {
    /// Set name inside the destination; also the directory name.
    pub set_name: String,
    /// Private key for an SFTP server (never a secret in argv; a path).
    pub identity: Option<PathBuf>,
    /// `known_hosts` file to verify the SFTP server against.
    pub known_hosts: Option<PathBuf>,
    /// Skip host-key verification. Tests only; the CLI warns loudly.
    pub insecure_ignore_host_key: bool,
}

impl DestinationOptions {
    /// Options for one set name.
    #[must_use]
    pub fn new(set_name: impl Into<String>) -> Self {
        Self {
            set_name: set_name.into(),
            ..Self::default()
        }
    }
}

/// Open the destination a URI names (spec §J.1).
///
/// # Errors
/// Returns [`Error::Unsupported`] for an unknown scheme or an SFTP option this
/// build cannot honour, and propagates connection errors.
pub fn open(uri: &str, options: &DestinationOptions) -> Result<std::sync::Arc<dyn Destination>> {
    let parsed = uri::parse(uri)?;
    let destination: std::sync::Arc<dyn Destination> = match parsed {
        DestinationUri::Local { path } => {
            std::sync::Arc::new(LocalDestination::new(path, options.set_name.clone()))
        }
        DestinationUri::Sftp { .. } => sftp::open(&parsed, options)?,
    };
    Ok(destination)
}

/// What a local destination path is mounted as (spec §J.2's mounted paths).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalMountFacts {
    /// `true` when the path is itself a mount point.
    pub is_mount: bool,
    /// Filesystem type recorded for the mount, when known.
    pub fs_type: Option<String>,
    /// Mount source (for example `nas.local:/export` or `//nas/share`).
    pub source: Option<String>,
}

/// Inspect the mount table for a local destination path.
///
/// # Errors
/// Propagates I/O errors while reading `/proc/self/mounts`.
pub fn local_mount_facts(path: &Path) -> Result<LocalMountFacts> {
    let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let text = std::fs::read_to_string(mounts_path()).map_err(Error::Io)?;
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let (Some(source), Some(target), Some(fs_type)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let target = PathBuf::from(target.replace("\\040", " "));
        if target == canonical {
            return Ok(LocalMountFacts {
                is_mount: true,
                fs_type: Some(fs_type.to_owned()),
                source: Some(source.to_owned()),
            });
        }
    }
    Ok(LocalMountFacts {
        is_mount: false,
        fs_type: None,
        source: None,
    })
}

fn mounts_path() -> PathBuf {
    std::env::var_os("LR_MOUNTS").map_or_else(|| PathBuf::from("/proc/self/mounts"), PathBuf::from)
}

/// Somewhere backup images can be written.
///
/// `name` arguments are paths relative to the set and may contain `/`
/// (spec §D.3 uses `<chain_id>/<seq>-<kind>-<uuid>.lrimg`); implementations
/// create intermediate directories and must reject `..` components.
pub trait Destination: Send + Sync {
    /// Open a set, creating its directory when it does not exist yet.
    ///
    /// # Errors
    /// Propagates I/O errors.
    fn open_set(&self, set: &SetId) -> Result<SetHandle>;

    /// Take the set lock (spec §D.3).
    ///
    /// # Errors
    /// Returns [`lr_core::Error::Unsupported`] on backends that do not
    /// implement locking yet, and [`lr_core::Error::SetLocked`] when another
    /// owner holds it.
    fn lock_set(&self, set: &SetHandle, owner: &LockOwner, ttl: Duration) -> Result<SetLock>;

    /// Take the lock, first removing one whose lease has expired.
    ///
    /// This is what `--break-stale-lock` calls. Backends that cannot inspect
    /// the lock file keep the safe default and refuse instead.
    ///
    /// # Errors
    /// See [`Destination::lock_set`].
    fn lock_set_breaking_stale(
        &self,
        set: &SetHandle,
        owner: &LockOwner,
        ttl: Duration,
    ) -> Result<SetLock> {
        let _ = (set, owner, ttl);
        Err(lr_core::Error::unsupported(
            "breaking a stale lock is not supported by this destination",
        ))
    }

    /// Create a temporary file inside the set.
    ///
    /// # Errors
    /// Propagates I/O errors.
    fn create_tmp(&self, set: &SetHandle, name: &str) -> Result<Box<dyn WriteSeekSync + Send>>;

    /// Flush and rename a temporary file into place (spec §L.1).
    ///
    /// # Errors
    /// Propagates I/O errors.
    fn finalize(&self, set: &SetHandle, tmp: &str, final_name: &str) -> Result<()>;

    /// Open an existing file read-only.
    ///
    /// # Errors
    /// Propagates I/O errors.
    fn open_ro(&self, set: &SetHandle, name: &str) -> Result<Box<dyn ReadSeek + Send>>;

    /// List every file in the set, relative to the set root.
    ///
    /// # Errors
    /// Propagates I/O errors.
    fn list(&self, set: &SetHandle) -> Result<Vec<String>>;

    /// Delete one file from the set.
    ///
    /// # Errors
    /// Propagates I/O errors.
    fn delete(&self, set: &SetHandle, name: &str) -> Result<()>;
}

/// Read a whole file through a destination handle, for small metadata files.
///
/// # Errors
/// Propagates I/O errors.
pub fn read_to_vec(destination: &dyn Destination, set: &SetHandle, name: &str) -> Result<Vec<u8>> {
    let mut reader = destination.open_ro(set, name)?;
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).map_err(lr_core::Error::Io)?;
    Ok(bytes)
}

/// Rewind a destination writer to the start, for callers that re-read a `tmp`.
///
/// # Errors
/// Propagates I/O errors.
pub fn rewind(writer: &mut dyn WriteSeekSync) -> Result<()> {
    writer.rewind().map_err(lr_core::Error::Io)
}

/// The root directory of a set described by a handle.
///
/// # Errors
/// Returns [`lr_core::Error::Unsupported`] for handles that do not carry a
/// local path.
pub fn local_root(handle: &SetHandle) -> Result<PathBuf> {
    if handle.path.contains("://") {
        return Err(lr_core::Error::unsupported(format!(
            "{} is not a local set",
            handle.path
        )));
    }
    Ok(PathBuf::from(&handle.path))
}

/// Seconds since the Unix epoch, used for lock leases.
#[must_use]
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
