//! Local-directory destination (spec §D.3, §L.1).
//!
//! Images are written to `<root>/<set-name>/<chain_id>/<seq>-<kind>-<uuid>.lrimg`
//! through a `.tmp` file that is fsynced and renamed into place, so a crash can
//! never leave a partial file that looks complete.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use lr_core::{Error, Result, SetId};

use crate::{
    Destination, LockOwner, LockRecord, ReadSeek, SetHandle, SetLock, WriteSeekSync, now_unix,
};

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

    fn resolve(&self, handle: &SetHandle, name: &str) -> Result<PathBuf> {
        let root = crate::local_root(handle)?;
        let relative = Path::new(name);
        if relative.is_absolute() {
            return Err(Error::unsupported(format!(
                "destination name '{name}' must be relative"
            )));
        }
        for component in relative.components() {
            match component {
                Component::Normal(_) => {}
                other => {
                    return Err(Error::unsupported(format!(
                        "destination name '{name}' contains {other:?}"
                    )));
                }
            }
        }
        Ok(root.join(relative))
    }

    fn create_parents(path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(Error::Io)?;
        }
        Ok(())
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
    fn acquire(
        &self,
        set: &SetHandle,
        owner: &LockOwner,
        ttl: Duration,
        break_stale: bool,
    ) -> Result<SetLock> {
        let path = self.resolve(set, LOCK_FILE)?;
        Self::create_parents(&path)?;
        let record = LockRecord {
            owner: owner.clone(),
            created: now_unix(),
            ttl_secs: ttl.as_secs(),
        };
        loop {
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut file) => {
                    file.write_all(&serde_json::to_vec(&record).map_err(lock_serialize)?)
                        .map_err(Error::Io)?;
                    file.sync_all().map_err(Error::Io)?;
                    drop(file);
                    let guard = RefreshGuard::start(path.clone(), record.clone(), ttl)?;
                    return Ok(SetLock::new(path.to_string_lossy().into_owned(), guard));
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    match read_lock(&path)? {
                        Some(existing) if existing.is_stale(now_unix()) && break_stale => {
                            std::fs::remove_file(&path).map_err(Error::Io)?;
                            // The lock is gone now, so the next attempt creates it.
                            continue;
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
    match std::fs::read(path) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes).ok()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(Error::Io(error)),
    }
}

/// Keeps a set lock's lease fresh until it is dropped, then releases it.
struct RefreshGuard {
    path: PathBuf,
    owner: LockOwner,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl RefreshGuard {
    fn start(path: PathBuf, record: LockRecord, ttl: Duration) -> Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let owner = record.owner.clone();
        // A zero lease never expires, so there is nothing to refresh.
        if ttl.is_zero() {
            return Ok(Self {
                path,
                owner,
                stop,
                thread: None,
            });
        }
        let interval = (ttl / 3).max(Duration::from_millis(250));
        let thread_stop = Arc::clone(&stop);
        let thread_path = path.clone();
        let thread = std::thread::Builder::new()
            .name("lr-set-lock".to_owned())
            .spawn(move || refresh_loop(&thread_path, &record, interval, &thread_stop))
            .map_err(Error::Io)?;
        Ok(Self {
            path,
            owner,
            stop,
            thread: Some(thread),
        })
    }
}

/// Refresh the lease until asked to stop.
///
/// The sleep is chopped into short slices so `Drop` never waits for a whole
/// refresh interval.
fn refresh_loop(path: &Path, record: &LockRecord, interval: Duration, stop: &AtomicBool) {
    let slice = Duration::from_millis(50);
    loop {
        let mut waited = Duration::ZERO;
        while waited < interval {
            if stop.load(Ordering::SeqCst) {
                return;
            }
            std::thread::sleep(slice.min(interval - waited));
            waited += slice;
        }
        if stop.load(Ordering::SeqCst) {
            return;
        }
        let mut refreshed = record.clone();
        refreshed.created = now_unix();
        if std::fs::write(path, serde_json::to_vec(&refreshed).unwrap_or_default()).is_err() {
            return;
        }
    }
}

impl Drop for RefreshGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        // Only remove a lock that is still ours: a stale-breaker may have
        // replaced it while this process was busy.
        if let Ok(Some(record)) = read_lock(&self.path)
            && record.owner == self.owner
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

impl Destination for LocalDestination {
    fn open_set(&self, set: &SetId) -> Result<SetHandle> {
        // Without a valid name the set directory would be the destination
        // root or somewhere outside it (R02, D-115).
        lr_core::validate_set_name(&self.set_name)?;
        let dir = self.set_dir();
        std::fs::create_dir_all(&dir).map_err(Error::Io)?;
        Ok(SetHandle {
            set_id: *set,
            path: dir.to_string_lossy().into_owned(),
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

    fn create_tmp(&self, set: &SetHandle, name: &str) -> Result<Box<dyn WriteSeekSync + Send>> {
        let path = self.resolve(set, &format!("{name}{TMP_SUFFIX}"))?;
        Self::create_parents(&path)?;
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .read(true)
            .open(&path)
            .map_err(Error::Io)?;
        Ok(Box::new(file))
    }

    fn finalize(&self, set: &SetHandle, tmp: &str, final_name: &str) -> Result<()> {
        let tmp_path = self.resolve(set, &format!("{tmp}{TMP_SUFFIX}"))?;
        let final_path = self.resolve(set, final_name)?;
        Self::create_parents(&final_path)?;
        // fsync the data before the rename, then fsync the directory so the
        // rename itself is durable (spec §L.1: finalize = fsync + rename).
        if let Ok(file) = File::open(&tmp_path) {
            file.sync_all().map_err(Error::Io)?;
        }
        std::fs::rename(&tmp_path, &final_path).map_err(Error::Io)?;
        if let Some(parent) = final_path.parent()
            && let Ok(dir) = File::open(parent)
        {
            dir.sync_all().map_err(Error::Io)?;
        }
        Ok(())
    }

    fn open_ro(&self, set: &SetHandle, name: &str) -> Result<Box<dyn ReadSeek + Send>> {
        let path = self.resolve(set, name)?;
        let file = File::open(path).map_err(Error::Io)?;
        Ok(Box::new(file))
    }

    fn list(&self, set: &SetHandle) -> Result<Vec<String>> {
        let root = crate::local_root(set)?;
        let mut found = Vec::new();
        collect_files(&root, &root, &mut found)?;
        found.sort();
        Ok(found)
    }

    fn delete(&self, set: &SetHandle, name: &str) -> Result<()> {
        let path = self.resolve(set, name)?;
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
    fn tmp_write_finalize_then_read_back() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (destination, set_id) = destination(&dir);
        let set = destination.open_set(&set_id).expect("open set");
        let name = "chain-1/000-full-image.lrimg";

        {
            let mut writer = destination.create_tmp(&set, name).expect("tmp");
            writer.write_all(b"image bytes").expect("write");
            writer.sync_all().expect("fsync");
        }
        assert!(
            std::path::Path::new(&format!("{}/{name}{TMP_SUFFIX}", set.path)).exists(),
            "the temporary file exists before finalize"
        );

        destination.finalize(&set, name, name).expect("finalize");
        assert!(
            !std::path::Path::new(&format!("{}/{name}{TMP_SUFFIX}", set.path)).exists(),
            "the temporary file is gone after finalize"
        );
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
            let mut writer = destination.create_tmp(&set, name).expect("tmp");
            writer.write_all(b"x").expect("write");
            destination.finalize(&set, name, name).expect("finalize");
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
        let mut writer = destination.create_tmp(&set, "a/1.lrimg").expect("tmp");
        writer.write_all(b"x").expect("write");
        destination
            .finalize(&set, "a/1.lrimg", "a/1.lrimg")
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
    fn finalizing_a_missing_tmp_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (destination, set_id) = destination(&dir);
        let set = destination.open_set(&set_id).expect("open set");
        assert!(destination.finalize(&set, "nope", "nope").is_err());
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
