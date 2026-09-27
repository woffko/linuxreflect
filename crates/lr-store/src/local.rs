//! Local-directory destination (spec §D.3, §L.1).
//!
//! Images are written to `<root>/<set-name>/<chain_id>/<seq>-<kind>-<uuid>.lrimg`
//! through a `.tmp` file that is fsynced and renamed into place, so a crash can
//! never leave a partial file that looks complete.
//!
//! The root daemon may write into a directory that other users can write too.
//! Below the destination root nothing is reached by joining path strings: the
//! set directory and every directory under it are opened from the pinned root
//! without following symlinks ([`lr_unsafe::beneath`]), and each file is named
//! as one component of its pinned directory (R07). A planted symlink is
//! refused, never followed.

use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::OwnedFd;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use lr_core::{Error, Result, SetId};

use crate::{
    Destination, Durability, LockOwner, LockRecord, ReadSeek, SetHandle, SetLock, TempFile,
    now_unix,
};

/// `O_NOFOLLOW`: fail instead of opening a symlink.
const O_NOFOLLOW: i32 = 0o400_000;

/// Suffix of in-progress files.
pub const TMP_SUFFIX: &str = ".tmp";
/// Name of the set lock file (spec §D.3).
pub const LOCK_FILE: &str = "set.lock";

/// A destination that stores sets under a local directory.
#[derive(Debug, Clone)]
pub struct LocalDestination {
    root: PathBuf,
    set_name: String,
}

impl LocalDestination {
    /// Create a destination for one set name under `root`.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>, set_name: impl Into<String>) -> Self {
        Self {
            root: root.into(),
            set_name: set_name.into(),
        }
    }

    /// Directory of the set, whether or not it exists yet.
    #[must_use]
    pub fn set_dir(&self) -> PathBuf {
        self.root.join(&self.set_name)
    }

    /// The pinned set directory, reached from the root without following a
    /// symlink. `create` makes it when it is missing.
    fn set_fd(&self, create: bool) -> Result<OwnedFd> {
        lr_core::validate_set_name(&self.set_name)?;
        if create {
            std::fs::create_dir_all(&self.root).map_err(Error::Io)?;
        }
        let root = lr_unsafe::beneath::open_root(&self.root).map_err(Error::Io)?;
        let name = OsStr::new(&self.set_name);
        if create {
            mkdir_in(&root, name)?;
        }
        lr_unsafe::beneath::open_dir_beneath(&root, Path::new(name))
            .map_err(|error| refused(&self.set_dir(), &error))
    }

    /// The pinned directory holding `name` and the entry path of `name` in
    /// it. `create` makes missing intermediate directories.
    fn entry(&self, name: &str, create: bool) -> Result<(OwnedFd, PathBuf)> {
        let components = lr_unsafe::beneath::normal_components(Path::new(name)).map_err(|_| {
            Error::unsupported(format!(
                "destination name '{name}' must be a plain relative path"
            ))
        })?;
        let Some((file, directories)) = components.split_last() else {
            return Err(Error::unsupported("empty destination name"));
        };
        let mut dir = self.set_fd(create)?;
        for component in directories {
            if create {
                mkdir_in(&dir, component)?;
            }
            dir = lr_unsafe::beneath::open_dir_beneath(&dir, Path::new(component))
                .map_err(|error| refused(&self.set_dir().join(name), &error))?;
        }
        let path = lr_unsafe::beneath::entry_path(&dir, file).map_err(Error::Io)?;
        Ok((dir, path))
    }

    /// fsync `tmp`, rename it to `final_name` (replacing it only when
    /// `replace`), then fsync the directory so the rename itself is durable
    /// (spec §L.1: finalize = fsync + rename).
    fn publish(&self, tmp: &str, final_name: &str, replace: bool) -> Result<Durability> {
        let (_tmp_dir, tmp_path) = self.entry(tmp, false)?;
        let (final_dir, final_path) = self.entry(final_name, true)?;
        open_nofollow(&tmp_path)
            .and_then(|file| file.sync_all())
            .map_err(Error::Io)?;
        // Neither rename follows a symlink at either name.
        if replace {
            std::fs::rename(&tmp_path, &final_path).map_err(Error::Io)?;
        } else {
            lr_unsafe::rename_noreplace(&tmp_path, &final_path).map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    Error::unsupported(format!(
                        "{final_name} already exists; a published image is never replaced"
                    ))
                } else {
                    Error::Io(error)
                }
            })?;
        }
        File::open(lr_unsafe::beneath::self_path(&final_dir))
            .and_then(|dir| dir.sync_all())
            .map_err(Error::Io)?;
        Ok(Durability::Synced)
    }

    /// Path of the set lock file.
    #[must_use]
    pub fn lock_path(&self) -> PathBuf {
        self.set_dir().join(LOCK_FILE)
    }

    /// `true` when the lock file's lease has expired.
    ///
    /// # Errors
    /// Propagates I/O errors other than "does not exist".
    pub fn lock_is_stale(&self) -> Result<bool> {
        match read_lock(&self.lock_path())? {
            Some(record) => Ok(record.is_stale(now_unix())),
            None => Ok(false),
        }
    }

    /// Take the lock, optionally breaking an expired one first.
    ///
    /// The holder keeps the lock file open with an exclusive `flock` for as
    /// long as it holds the lock. A process that is alive, even paused past
    /// its lease, keeps that `flock`, so nobody on this host can break its
    /// lock; the kernel drops the `flock` when the process dies. Holders on
    /// other hosts sharing the destination are fenced by the lease token
    /// instead ([`SetLock::verify`], R21).
    fn acquire(
        &self,
        set: &SetHandle,
        owner: &LockOwner,
        ttl: Duration,
        break_stale: bool,
    ) -> Result<SetLock> {
        let _ = set;
        let (dir, path) = self.entry(LOCK_FILE, true)?;
        let dir = Arc::new(dir);
        let record = LockRecord {
            owner: owner.clone(),
            created: now_unix(),
            ttl_secs: ttl.as_secs(),
            token: lr_core::Id::generate().map_err(Error::Io)?.to_string(),
        };
        loop {
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .custom_flags(O_NOFOLLOW)
                .open(&path)
            {
                Ok(mut file) => {
                    lock_exclusive(&file)?;
                    file.write_all(&serde_json::to_vec(&record).map_err(lock_serialize)?)
                        .map_err(Error::Io)?;
                    file.sync_all().map_err(Error::Io)?;
                    let display = self.lock_path().to_string_lossy().into_owned();
                    let lease = Arc::new(Lease::new(Arc::clone(&dir), path, file, record, ttl)?);
                    lease.start()?;
                    let check = {
                        let lease = Arc::clone(&lease);
                        let display = display.clone();
                        move || lease.verify(&display)
                    };
                    return Ok(SetLock::with_check(display, LeaseGuard(lease), check));
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    match read_lock(&path)? {
                        Some(existing) if existing.is_stale(now_unix()) && break_stale => {
                            let file = open_nofollow(&path).map_err(Error::Io)?;
                            match file.try_lock() {
                                Ok(()) => {
                                    std::fs::remove_file(&path).map_err(Error::Io)?;
                                    // The lock is gone now, so the next
                                    // attempt creates it.
                                    continue;
                                }
                                Err(std::fs::TryLockError::WouldBlock) => {
                                    return Err(Error::SetLocked {
                                        owner: format!(
                                            "{}; its lease looks expired, but its process is \
                                             still alive on this host, so it is not broken",
                                            existing.describe()
                                        ),
                                    });
                                }
                                Err(std::fs::TryLockError::Error(error)) => {
                                    return Err(Error::Io(error));
                                }
                            }
                        }
                        Some(existing) => {
                            return Err(Error::SetLocked {
                                owner: existing.describe(),
                            });
                        }
                        None => {
                            return Err(Error::SetLocked {
                                owner: format!("unreadable {}", path.display()),
                            });
                        }
                    }
                }
                Err(error) => return Err(Error::Io(error)),
            }
        }
    }
}

fn lock_serialize(error: serde_json::Error) -> Error {
    Error::corrupt(format!("set lock record: {error}"))
}

/// Read the lock file; `Ok(None)` when it does not exist.
fn read_lock(path: &Path) -> Result<Option<LockRecord>> {
    let read = open_nofollow(path).and_then(|mut file| {
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut file, &mut bytes).map(|_| bytes)
    });
    match read {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes).ok()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(Error::Io(error)),
    }
}

/// Take an exclusive `flock` on a freshly created lock file.
fn lock_exclusive(file: &File) -> Result<()> {
    match file.try_lock() {
        Ok(()) => Ok(()),
        Err(std::fs::TryLockError::WouldBlock) => Err(Error::SetLocked {
            owner: "a process that opened the new lock file first".to_owned(),
        }),
        Err(std::fs::TryLockError::Error(error)) => Err(Error::Io(error)),
    }
}

/// A held lease: the lock file this holder created, kept open and flocked,
/// and refreshed until the lock is dropped.
struct Lease {
    /// The pinned set directory; `path` names the lock file inside it and is
    /// valid only while this descriptor is open.
    _dir: Arc<OwnedFd>,
    path: PathBuf,
    /// The lock file this holder created. Refreshes write into this inode,
    /// never through the path, so they cannot touch a replacement.
    file: File,
    ttl: Duration,
    /// When the lease was last written; monotonic, so it keeps counting
    /// while the process is paused.
    refreshed: Mutex<std::time::Instant>,
    /// Why the lease was lost, once it is.
    lost: Mutex<Option<String>>,
    stop: AtomicBool,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    record: LockRecord,
}

impl Lease {
    fn new(
        dir: Arc<OwnedFd>,
        path: PathBuf,
        file: File,
        record: LockRecord,
        ttl: Duration,
    ) -> Result<Self> {
        Ok(Self {
            _dir: dir,
            path,
            file,
            ttl,
            refreshed: Mutex::new(std::time::Instant::now()),
            lost: Mutex::new(None),
            stop: AtomicBool::new(false),
            thread: Mutex::new(None),
            record,
        })
    }

    /// Start refreshing; a zero lease never expires and needs none.
    fn start(self: &Arc<Self>) -> Result<()> {
        if self.ttl.is_zero() {
            return Ok(());
        }
        let interval = (self.ttl / 3).max(Duration::from_millis(250));
        let lease = Arc::clone(self);
        let thread = std::thread::Builder::new()
            .name("lr-set-lock".to_owned())
            .spawn(move || lease.refresh_loop(interval))
            .map_err(Error::Io)?;
        *self.thread.lock().unwrap_or_else(PoisonError::into_inner) = Some(thread);
        Ok(())
    }

    /// `Ok(())` while the path still names the file this holder created.
    fn still_ours(&self) -> std::result::Result<(), String> {
        let at_path = std::fs::symlink_metadata(&self.path)
            .map_err(|error| format!("the lock file is gone: {error}"))?;
        let ours = self.file.metadata().map_err(|error| error.to_string())?;
        if (at_path.dev(), at_path.ino()) == (ours.dev(), ours.ino()) {
            Ok(())
        } else {
            Err("the lock file was replaced by another holder".to_owned())
        }
    }

    fn lose(&self, reason: String) {
        tracing::error!(path = %self.path.display(), %reason, "set lock lease lost");
        self.lost
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_or_insert(reason);
    }

    /// Refresh the lease until asked to stop or until it is lost.
    ///
    /// The sleep is chopped into short slices so `Drop` never waits for a
    /// whole refresh interval.
    fn refresh_loop(&self, interval: Duration) {
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
            let refreshed = LockRecord {
                created: now,
                ..self.record.clone()
            };
            let written = serde_json::to_vec(&refreshed)
                .map_err(std::io::Error::other)
                .and_then(|bytes| {
                    self.file.set_len(0)?;
                    self.file.write_all_at(&bytes, 0)
                });
            if let Err(error) = written {
                self.lose(format!("refreshing it failed: {error}"));
                return;
            }
            *self
                .refreshed
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = std::time::Instant::now();
        }
    }

    /// See [`SetLock::verify`].
    fn verify(&self, display: &str) -> Result<()> {
        if let Some(reason) = self
            .lost
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
        {
            return Err(crate::lease_lost(display, &reason));
        }
        self.still_ours()
            .map_err(|reason| crate::lease_lost(display, &reason))?;
        let refreshed = *self
            .refreshed
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if !self.ttl.is_zero() && refreshed.elapsed() > self.ttl {
            return Err(crate::lease_lost(
                display,
                "it expired while the job was not running, and another job may have broken it",
            ));
        }
        Ok(())
    }
}

/// Stops the refresher and releases the lock when the [`SetLock`] is
/// dropped.
struct LeaseGuard(Arc<Lease>);

impl Drop for LeaseGuard {
    fn drop(&mut self) {
        let lease = &self.0;
        lease.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = lease
            .thread
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            let _ = thread.join();
        }
        // Only remove a lock that is still ours: another holder may have
        // replaced it while this process was busy.
        if lease.still_ours().is_ok() {
            let _ = std::fs::remove_file(&lease.path);
        }
    }
}

impl Destination for LocalDestination {
    fn open_set(&self, set: &SetId) -> Result<SetHandle> {
        // Without a valid name the set directory would be the destination
        // root or somewhere outside it (R02, D-115), and a symlink in its
        // place would lead elsewhere (R07).
        drop(self.set_fd(true)?);
        Ok(SetHandle {
            set_id: *set,
            path: self.set_dir().to_string_lossy().into_owned(),
        })
    }

    fn open_existing_set(&self, set: &SetId) -> Result<SetHandle> {
        match self.set_fd(false) {
            Ok(dir) => drop(dir),
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(crate::no_such_set(
                    &self.set_name,
                    &self.root.display().to_string(),
                ));
            }
            Err(error) => return Err(error),
        }
        Ok(SetHandle {
            set_id: *set,
            path: self.set_dir().to_string_lossy().into_owned(),
        })
    }

    fn lock_set(&self, set: &SetHandle, owner: &LockOwner, ttl: Duration) -> Result<SetLock> {
        self.acquire(set, owner, ttl, false)
    }

    fn lock_set_breaking_stale(
        &self,
        set: &SetHandle,
        owner: &LockOwner,
        ttl: Duration,
    ) -> Result<SetLock> {
        self.acquire(set, owner, ttl, true)
    }

    fn create_tmp(&self, set: &SetHandle, final_name: &str) -> Result<TempFile> {
        let _ = set;
        let name = crate::temp_name(final_name)?;
        let (_dir, path) = self.entry(&name, true)?;
        // `create_new` is `O_CREAT | O_EXCL`, which also fails on a symlink.
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .read(true)
            .custom_flags(O_NOFOLLOW)
            .open(&path)
            .map_err(Error::Io)?;
        Ok(TempFile {
            name,
            writer: Box::new(file),
        })
    }

    fn publish_new(&self, set: &SetHandle, tmp: &str, final_name: &str) -> Result<Durability> {
        let _ = set;
        self.publish(tmp, final_name, false)
    }

    fn replace(&self, set: &SetHandle, tmp: &str, final_name: &str) -> Result<Durability> {
        let _ = set;
        self.publish(tmp, final_name, true)
    }

    fn open_ro(&self, set: &SetHandle, name: &str) -> Result<Box<dyn ReadSeek + Send>> {
        let _ = set;
        let (_dir, path) = self.entry(name, false)?;
        let file = open_nofollow(&path).map_err(Error::Io)?;
        Ok(Box::new(file))
    }

    fn list(&self, set: &SetHandle) -> Result<Vec<String>> {
        let _ = set;
        let dir = match self.set_fd(false) {
            Ok(dir) => dir,
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Vec::new());
            }
            Err(error) => return Err(error),
        };
        let mut found = Vec::new();
        collect_beneath(&dir, "", &mut found)?;
        found.sort();
        Ok(found)
    }

    fn delete(&self, set: &SetHandle, name: &str) -> Result<()> {
        let _ = set;
        let (_dir, path) = self.entry(name, false)?;
        // `unlink` does not follow its final component.
        std::fs::remove_file(path).map_err(Error::Io)
    }

    fn list_set_names(&self) -> Result<Vec<String>> {
        let entries = match std::fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(Error::Io(e)),
        };
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry.map_err(Error::Io)?;
            // `file_type` does not follow symlinks: a link is never a set.
            if !entry.file_type().map_err(Error::Io)?.is_dir() {
                continue;
            }
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            let mut files = Vec::new();
            let dir = entry.path();
            collect_files(&dir, &dir, &mut files)?;
            if files.iter().any(|file| file.ends_with(".lrimg")) {
                names.push(name);
            }
        }
        names.sort();
        Ok(names)
    }
}

/// Every regular file below the pinned `dir`, entering subdirectories only
/// through their own pinned descriptors, so a directory swapped for a symlink
/// while the listing runs is refused rather than listed.
fn collect_beneath(dir: &OwnedFd, prefix: &str, found: &mut Vec<String>) -> Result<()> {
    let entries = std::fs::read_dir(lr_unsafe::beneath::self_path(dir)).map_err(Error::Io)?;
    for entry in entries {
        let entry = entry.map_err(Error::Io)?;
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let file_type = entry.file_type().map_err(Error::Io)?;
        if file_type.is_dir() {
            let sub = lr_unsafe::beneath::open_dir_beneath(dir, Path::new(&name))
                .map_err(|error| refused(Path::new(&format!("{prefix}{name}")), &error))?;
            collect_beneath(&sub, &format!("{prefix}{name}/"), found)?;
        } else if file_type.is_file() {
            found.push(format!("{prefix}{name}"));
        }
    }
    Ok(())
}

/// Create the directory `name` in `dir` unless it exists; `mkdir` does not
/// follow a symlink in its place, and opening it afterwards refuses one.
fn mkdir_in(dir: &OwnedFd, name: &OsStr) -> Result<()> {
    let path = lr_unsafe::beneath::entry_path(dir, name).map_err(Error::Io)?;
    match std::fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(Error::Io(error)),
    }
}

/// Open a file read-only, refusing a symlink.
fn open_nofollow(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
}

/// The error for a directory that is a symlink or otherwise unusable.
fn refused(path: &Path, error: &std::io::Error) -> Error {
    if error.kind() == std::io::ErrorKind::NotFound {
        return Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{}: {error}", path.display()),
        ));
    }
    Error::unsupported(format!(
        "{} cannot be reached without following a symlink or is not a directory \
         ({error}); refusing to use it",
        path.display()
    ))
}

fn collect_files(root: &Path, at: &Path, found: &mut Vec<String>) -> Result<()> {
    let entries = match std::fs::read_dir(at) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(Error::Io(e)),
    };
    for entry in entries {
        let entry = entry.map_err(Error::Io)?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(Error::Io)?;
        if file_type.is_dir() {
            collect_files(root, &path, found)?;
        } else if file_type.is_file()
            && let Ok(relative) = path.strip_prefix(root)
        {
            found.push(relative.to_string_lossy().into_owned());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{LocalDestination, TMP_SUFFIX};
    use crate::{Destination, LockOwner, LockRecord, local_root, read_to_vec};
    use lr_core::{Id, SetId};
    use std::io::Write;
    use std::time::Duration;

    fn destination(dir: &tempfile::TempDir) -> (LocalDestination, SetId) {
        let destination = LocalDestination::new(dir.path(), "laptop-root");
        let set_id = SetId::new(Id::from_bytes([0x11; 16]));
        (destination, set_id)
    }

    #[test]
    fn set_names_are_listed_without_creating_anything() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        std::fs::create_dir_all(root.join("laptop/chain-1")).expect("set");
        std::fs::write(root.join("laptop/chain-1/000-full-a.lrimg"), b"x").expect("image");
        std::fs::create_dir_all(root.join("empty")).expect("empty set");
        std::fs::write(root.join("notes.txt"), b"x").expect("file");
        std::fs::create_dir_all(root.join("server")).expect("set");
        std::fs::write(root.join("server/000-full-b.lrimg"), b"x").expect("image");
        let destination = LocalDestination::new(root, "unused");
        assert_eq!(
            destination.list_set_names().expect("list"),
            ["laptop", "server"]
        );
        assert!(
            !root.join("unused").exists(),
            "listing must not create a set"
        );
        let missing = LocalDestination::new(root.join("absent"), "unused");
        assert!(missing.list_set_names().expect("missing root").is_empty());
        assert!(!root.join("absent").exists());
    }

    #[test]
    fn set_directories_are_created_on_open() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (destination, set_id) = destination(&dir);
        let handle = destination.open_set(&set_id).expect("open set");
        assert!(std::path::Path::new(&handle.path).is_dir());
        assert!(handle.path.ends_with("laptop-root"));
        assert_eq!(local_root(&handle).expect("local"), destination.set_dir());
    }

    #[test]
    fn tmp_write_publish_then_read_back() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (destination, set_id) = destination(&dir);
        let set = destination.open_set(&set_id).expect("open set");
        let name = "chain-1/000-full-image.lrimg";

        let mut tmp = destination.create_tmp(&set, name).expect("tmp");
        tmp.writer.write_all(b"image bytes").expect("write");
        tmp.writer.sync_all().expect("fsync");
        drop(tmp.writer);
        assert!(
            tmp.name.starts_with(name) && tmp.name.ends_with(TMP_SUFFIX),
            "{}",
            tmp.name
        );
        let tmp_path = format!("{}/{}", set.path, tmp.name);
        assert!(
            std::path::Path::new(&tmp_path).exists(),
            "the temporary file exists before finalize"
        );

        destination
            .publish_new(&set, &tmp.name, name)
            .expect("publish");
        assert!(
            !std::path::Path::new(&tmp_path).exists(),
            "the temporary file is gone after publication"
        );
        let mut again = destination.create_tmp(&set, name).expect("tmp");
        again.writer.write_all(b"other bytes").expect("write");
        let error = destination
            .publish_new(&set, &again.name, name)
            .expect_err("a published image is never replaced");
        assert!(error.to_string().contains("never replaced"), "{error}");
        destination.delete(&set, &again.name).expect("discard");
        assert_eq!(
            read_to_vec(&destination, &set, name).expect("read"),
            b"image bytes"
        );

        let listing = destination.list(&set).expect("list");
        assert_eq!(listing, vec![name.to_owned()]);
    }

    #[test]
    fn listing_walks_chain_directories() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (destination, set_id) = destination(&dir);
        let set = destination.open_set(&set_id).expect("open set");
        for name in ["a/1.lrimg", "a/2.lrimg", "b/1.lrimg"] {
            let mut tmp = destination.create_tmp(&set, name).expect("tmp");
            tmp.writer.write_all(b"x").expect("write");
            destination
                .publish_new(&set, &tmp.name, name)
                .expect("finalize");
        }
        assert_eq!(
            destination.list(&set).expect("list"),
            vec!["a/1.lrimg", "a/2.lrimg", "b/1.lrimg"]
        );
    }

    #[test]
    fn delete_removes_one_image() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (destination, set_id) = destination(&dir);
        let set = destination.open_set(&set_id).expect("open set");
        let mut tmp = destination.create_tmp(&set, "a/1.lrimg").expect("tmp");
        tmp.writer.write_all(b"x").expect("write");
        destination
            .publish_new(&set, &tmp.name, "a/1.lrimg")
            .expect("finalize");

        destination.delete(&set, "a/1.lrimg").expect("delete");
        assert!(destination.list(&set).expect("list").is_empty());
        assert!(destination.delete(&set, "a/1.lrimg").is_err());
    }

    #[test]
    fn path_traversal_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (destination, set_id) = destination(&dir);
        let set = destination.open_set(&set_id).expect("open set");
        for name in ["../escape", "/etc/passwd", "a/../../escape"] {
            assert!(
                destination.create_tmp(&set, name).is_err(),
                "{name} must be refused"
            );
            assert!(
                destination.open_ro(&set, name).is_err(),
                "{name} must be refused"
            );
            assert!(
                destination.delete(&set, name).is_err(),
                "{name} must be refused"
            );
        }
    }

    #[test]
    fn publishing_a_missing_tmp_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (destination, set_id) = destination(&dir);
        let set = destination.open_set(&set_id).expect("open set");
        assert!(destination.publish_new(&set, "nope", "nope").is_err());
    }

    /// A writer of the destination directory plants symlinks where the
    /// root daemon will write, delete or look for its set (R07). Nothing
    /// may follow them.
    #[test]
    fn planted_symlinks_are_never_followed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&outside).expect("outside");
        std::fs::write(outside.join("victim.lrimg"), b"SENTINEL").expect("sentinel");
        let root = dir.path().join("dest");
        std::fs::create_dir_all(&root).expect("root");

        // A set directory that is a symlink is refused, not followed.
        std::os::unix::fs::symlink(&outside, root.join("linked")).expect("set link");
        let linked = LocalDestination::new(&root, "linked");
        assert!(
            linked
                .open_set(&SetId::new(Id::from_bytes([1; 16])))
                .is_err(),
            "a symlinked set directory must be refused"
        );

        let destination = LocalDestination::new(&root, "laptop-root");
        let set = destination
            .open_set(&SetId::new(Id::from_bytes([1; 16])))
            .expect("open set");
        let set_dir = destination.set_dir();
        // A chain directory that is a symlink is neither written through
        // nor used for deleting.
        std::os::unix::fs::symlink(&outside, set_dir.join("chain")).expect("chain link");
        assert!(
            destination.delete(&set, "chain/victim.lrimg").is_err(),
            "a delete through a symlinked directory must be refused"
        );
        assert!(destination.open_ro(&set, "chain/victim.lrimg").is_err());
        assert!(destination.list(&set).expect("list").is_empty());
        assert_eq!(
            std::fs::read(outside.join("victim.lrimg")).expect("sentinel"),
            b"SENTINEL"
        );
        assert_eq!(
            std::fs::read_dir(&outside).expect("outside").count(),
            1,
            "nothing is created outside the set"
        );
    }

    fn owner(pid: u32) -> LockOwner {
        LockOwner {
            host_id: "test-host".to_owned(),
            pid,
        }
    }

    #[test]
    fn the_lock_is_exclusive_and_released_on_drop() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (destination, set_id) = destination(&dir);
        let set = destination.open_set(&set_id).expect("open set");
        let ttl = Duration::from_secs(60);

        let first = destination
            .lock_set(&set, &owner(1), ttl)
            .expect("first lock");
        let error = destination
            .lock_set(&set, &owner(2), ttl)
            .expect_err("second lock must fail");
        match error {
            lr_core::Error::SetLocked { owner } => assert!(owner.contains("test-host"), "{owner}"),
            other => panic!("expected SetLocked, got {other}"),
        }

        drop(first);
        assert!(!destination.lock_path().exists(), "drop releases the lock");
        destination
            .lock_set(&set, &owner(2), ttl)
            .expect("lock after release");
    }

    #[test]
    fn a_stale_lock_is_broken_only_when_asked() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (destination, set_id) = destination(&dir);
        let set = destination.open_set(&set_id).expect("open set");
        let stale = LockRecord {
            owner: owner(1),
            created: 1_000,
            ttl_secs: 1,
            ..LockRecord::default()
        };
        std::fs::write(
            destination.lock_path(),
            serde_json::to_vec(&stale).expect("serialize"),
        )
        .expect("write lock");
        assert!(destination.lock_is_stale().expect("staleness"));

        let error = destination
            .lock_set(&set, &owner(2), Duration::from_secs(60))
            .expect_err("a stale lock still blocks without the flag");
        assert!(matches!(error, lr_core::Error::SetLocked { .. }), "{error}");

        destination
            .lock_set_breaking_stale(&set, &owner(2), Duration::from_secs(60))
            .expect("stale lock is broken on request");
    }

    /// A holder paused past its lease still lives; on its own host nobody
    /// may break its lock, however stale the record looks (R21).
    #[test]
    fn a_live_holder_is_never_broken_on_its_host() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (destination, set_id) = destination(&dir);
        let set = destination.open_set(&set_id).expect("open set");
        let holder = destination
            .lock_set(&set, &owner(1), Duration::ZERO)
            .expect("lock");
        holder.verify().expect("a fresh lease is held");
        // As if the holder had been paused and its lease had run out.
        let stale = LockRecord {
            owner: owner(1),
            created: 1_000,
            ttl_secs: 1,
            ..LockRecord::default()
        };
        std::fs::write(
            destination.lock_path(),
            serde_json::to_vec(&stale).expect("serialize"),
        )
        .expect("age the record");
        assert!(destination.lock_is_stale().expect("staleness"));
        let breaker = destination.lock_set_breaking_stale(&set, &owner(2), Duration::from_secs(60));
        assert!(
            breaker.is_err(),
            "a lock whose holder is alive on this host must not be broken"
        );
        drop(breaker);
        drop(holder);
    }

    /// A holder whose lock was broken and replaced elsewhere (another host
    /// sharing the destination) never writes over the new owner's record,
    /// and learns that it lost the lease (R21).
    #[test]
    fn a_replaced_lock_is_never_overwritten_by_its_old_holder() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (destination, set_id) = destination(&dir);
        let set = destination.open_set(&set_id).expect("open set");
        let holder = destination
            .lock_set(&set, &owner(1), Duration::from_secs(1))
            .expect("lock");
        let replacement = LockRecord {
            owner: owner(2),
            created: crate::now_unix(),
            ttl_secs: 60,
            ..LockRecord::default()
        };
        std::fs::remove_file(destination.lock_path()).expect("break");
        std::fs::write(
            destination.lock_path(),
            serde_json::to_vec(&replacement).expect("serialize"),
        )
        .expect("replace");
        // Several refresh intervals of the old holder.
        std::thread::sleep(Duration::from_millis(1200));
        let on_disk: LockRecord =
            serde_json::from_slice(&std::fs::read(destination.lock_path()).expect("read"))
                .expect("record");
        assert_eq!(on_disk.owner, owner(2), "the new owner's record survives");
        let error = holder.verify().expect_err("the old holder lost its lease");
        assert!(error.to_string().contains("lost"), "{error}");
        drop(holder);
        assert!(
            destination.lock_path().exists(),
            "dropping the old holder leaves the new owner's lock alone"
        );
    }

    #[test]
    fn a_live_lease_is_refreshed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (destination, set_id) = destination(&dir);
        let set = destination.open_set(&set_id).expect("open set");
        let _lock = destination
            .lock_set(&set, &owner(1), Duration::from_secs(1))
            .expect("lock");

        std::thread::sleep(Duration::from_millis(1500));
        assert!(
            !destination.lock_is_stale().expect("staleness"),
            "the refresher must extend the lease"
        );
    }

    #[test]
    fn a_zero_ttl_never_expires() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (destination, set_id) = destination(&dir);
        let set = destination.open_set(&set_id).expect("open set");
        let _lock = destination
            .lock_set(&set, &owner(1), Duration::ZERO)
            .expect("lock");
        std::thread::sleep(Duration::from_millis(1200));
        assert!(!destination.lock_is_stale().expect("staleness"));
    }
}
