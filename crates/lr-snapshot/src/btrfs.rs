//! Btrfs tree snapshots and send streams (spec §E.1, Slice S8b).
//!
//! A Btrfs source is imaged in Stream mode. The filesystem's mounted
//! subvolumes are snapshotted read-only into `.linuxreflect/<set>/<image>` on
//! the filesystem itself, then each snapshot is streamed through
//! `btrfs send`; the engine content-defined chunks that byte stream.
//!
//! Incrementals use `btrfs send -p <previous snapshot>`. The previous snapshot
//! of a set is recorded in `.linuxreflect/<set>/latest`, and older snapshots
//! are deleted only after a new image is complete — deleting a parent while a
//! send still needs it would be a silent data-loss bug (spec §E.1).

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};

use lr_core::{Consistency, Error, Id, Result, SnapshotOpts, SourceLayout, Support};

/// Directory, below the top-level subvolume, that holds snapshots and state.
pub const STATE_DIR: &str = ".linuxreflect";
/// Where the top-level subvolume is mounted by default.
pub const DEFAULT_MOUNT_ROOT: &str = "/run/linuxreflect";
/// The always-present top-level (FS_TREE) subvolume id.
pub const TOP_LEVEL_SUBVOLID: u64 = 5;

/// Whether an incremental send is wanted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Incremental {
    /// Use the recorded parent when it still exists, otherwise go full.
    Auto,
    /// Require a parent; refuse with `E_STREAM_PARENT_MISSING` when it is gone.
    Require,
    /// Always produce a full stream.
    Never,
}

/// What the provider needs beyond the generic [`SnapshotOpts`].
#[derive(Debug, Clone)]
pub struct TreeSnapshotOpts {
    /// Backup set name; snapshots live below `.linuxreflect/<set_name>/`.
    pub set_name: String,
    /// Image identifier, used as the snapshot directory name.
    pub image_uuid: Id,
    /// Incremental policy.
    pub incremental: Incremental,
    /// Where the top-level subvolume is mounted.
    pub mount_root: PathBuf,
    /// Generic snapshot options (destination, opt-ins).
    pub general: SnapshotOpts,
}

impl TreeSnapshotOpts {
    /// Options with a private mount root and no incrementals.
    #[must_use]
    pub fn new(set_name: impl Into<String>, image_uuid: Id) -> Self {
        Self {
            set_name: set_name.into(),
            image_uuid,
            incremental: Incremental::Auto,
            mount_root: PathBuf::from(DEFAULT_MOUNT_ROOT),
            general: SnapshotOpts::default(),
        }
    }
}

/// One mounted subvolume of the source filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountedSubvol {
    /// Where the subvolume is mounted in the running system.
    pub target: PathBuf,
    /// Backing device as reported by `findmnt`.
    pub source: String,
    /// Path relative to the top-level subvolume.
    pub subvol_path: String,
    /// Subvolume id.
    pub subvolid: u64,
    /// Mount options as reported by `findmnt`.
    pub options: String,
}

/// One read-only snapshot taken for this image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubvolSnapshot {
    /// Mount target in the running system (informational).
    pub mount_target: PathBuf,
    /// Path relative to the top-level subvolume.
    pub subvol_path: String,
    /// Subvolume id of the source.
    pub subvolid: u64,
    /// Absolute path of the read-only snapshot.
    pub snapshot_path: PathBuf,
    /// Snapshot used as the `-p` parent, if any.
    pub parent_snapshot: Option<PathBuf>,
    /// Btrfs UUID of the parent snapshot, when it could be read.
    pub parent_snapshot_uuid: Option<Id>,
}

/// A set of read-only snapshots plus the state needed to release them.
pub struct TreeSnapshot {
    /// Filesystem UUID of the source.
    pub fs_uuid: String,
    /// Filesystem label.
    pub label: String,
    /// Default subvolume id (restored with `btrfs subvolume set-default`).
    pub default_subvolid: u64,
    /// Mount options of the filesystem, as recorded by `findmnt`.
    pub mount_options: String,
    /// Consistency level this snapshot provides.
    pub consistency: Consistency,
    /// One entry per snapshot taken.
    pub subvolumes: Vec<SubvolSnapshot>,
    /// Top-level mount point; unmounted when the snapshot is dropped.
    mountpoint: PathBuf,
    /// Top-level path used to build snapshot paths.
    top: PathBuf,
    /// State directory of this set.
    set_dir: PathBuf,
    /// `true` once the image is complete and retention has run.
    committed: bool,
}

impl TreeSnapshot {
    /// Byte stream of `btrfs send [-p parent]` for one snapshot.
    ///
    /// # Errors
    /// Returns [`Error::Unsupported`] when `btrfs` cannot be started.
    pub fn send(&self, snapshot: &SubvolSnapshot) -> Result<SendStream> {
        let mut command = Command::new("btrfs");
        command.args(["send"]);
        if let Some(parent) = &snapshot.parent_snapshot {
            command.arg("-p").arg(parent);
        }
        command
            .arg(&snapshot.snapshot_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().map_err(|error| {
            Error::unsupported(format!("btrfs send could not be started: {error}"))
        })?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| Error::unsupported("btrfs send produced no stdout pipe"))?;
        Ok(SendStream {
            inner: std::sync::Arc::new(std::sync::Mutex::new(SendInner {
                child: Some(child),
                stdout,
            })),
        })
    }

    /// Record this image as the set's latest and delete older snapshots.
    ///
    /// Called only after the image file is final so a failed job never
    /// invalidates the parent of a previous successful image.
    ///
    /// # Errors
    /// Propagates I/O errors while writing `latest` or deleting snapshots.
    pub fn commit(&mut self) -> Result<()> {
        // `latest` records a snapshot's *own* UUID: that is what the next
        // incremental must name as its parent, not the UUID of the parent this
        // snapshot had.
        let mut latest = Vec::with_capacity(self.subvolumes.len());
        for snapshot in &self.subvolumes {
            let own_uuid = subvolume_uuid(&snapshot.snapshot_path)?;
            latest.push((
                escape_path(&snapshot.subvol_path).to_owned(),
                snapshot.clone(),
                own_uuid,
            ));
        }
        write_latest(&self.set_dir, &latest)?;

        // Retention: keep the snapshots of this image, drop the rest. The
        // parent of *this* image is not needed any more either: the next
        // incremental uses this image's snapshots.
        let keep = self.image_prefix();
        prune_image_dirs(&self.set_dir, &keep)?;
        self.committed = true;
        Ok(())
    }

    /// Top-level subvolume mount point; `.linuxreflect` lives below it.
    #[must_use]
    pub fn top_level(&self) -> &Path {
        &self.top
    }

    fn image_prefix(&self) -> String {
        self.subvolumes
            .first()
            .and_then(|snapshot| snapshot.snapshot_path.parent())
            .and_then(|parent| parent.file_name())
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default()
    }
}

impl Drop for TreeSnapshot {
    fn drop(&mut self) {
        if !self.committed {
            // A failed job removes its own snapshots; the recorded parent of
            // the previous image is untouched, so a retry still works.
            for snapshot in &self.subvolumes {
                let _ = run_ok(
                    "btrfs",
                    &["subvolume", "delete", &path_text(&snapshot.snapshot_path)],
                );
            }
            if let Some(parent) = self
                .subvolumes
                .first()
                .and_then(|s| s.snapshot_path.parent())
            {
                let _ = std::fs::remove_dir(parent);
            }
        }
        // The private top-level mount is always released.
        let _ = run_ok("umount", &[&path_text(&self.mountpoint)]);
        let _ = std::fs::remove_dir(&self.mountpoint);
    }
}

/// A `btrfs send` process whose stdout is the send stream.
///
/// Cheap to clone: the chunker takes one handle as its `Read` and the caller
/// keeps another to call [`SendStream::finish`] once the chunker is done, so
/// the exit status is never lost.
#[derive(Clone)]
pub struct SendStream {
    inner: std::sync::Arc<std::sync::Mutex<SendInner>>,
}

struct SendInner {
    child: Option<Child>,
    stdout: ChildStdout,
}

impl SendStream {
    /// Wait for `btrfs send` to exit and report a non-zero status.
    ///
    /// # Errors
    /// Returns the stderr text when the send failed.
    pub fn finish(&self) -> Result<()> {
        let mut inner = self.lock();
        let Some(mut child) = inner.child.take() else {
            return Ok(());
        };
        drop(inner);
        let status = child.wait().map_err(Error::Io)?;
        if status.success() {
            return Ok(());
        }
        let mut stderr = String::new();
        if let Some(mut pipe) = child.stderr.take() {
            let _ = pipe.read_to_string(&mut stderr);
        }
        Err(Error::corrupt(format!(
            "btrfs send failed: {}",
            stderr.trim()
        )))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, SendInner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Read for SendStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.lock().stdout.read(buf)
    }
}

impl Drop for SendStream {
    fn drop(&mut self) {
        if std::sync::Arc::strong_count(&self.inner) != 1 {
            return;
        }
        if let Some(mut child) = self.lock().child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// The Btrfs tree snapshot provider (spec §E.1).
#[derive(Debug, Default)]
pub struct BtrfsProvider;

/// The process-wide Btrfs provider.
#[must_use]
pub fn provider() -> &'static BtrfsProvider {
    static PROVIDER: BtrfsProvider = BtrfsProvider;
    &PROVIDER
}

impl BtrfsProvider {
    /// Provider identifier.
    #[must_use]
    pub const fn id(&self) -> &'static str {
        "btrfs"
    }

    /// Whether this source can be imaged in Stream mode.
    #[must_use]
    pub fn supports(&self, src: &SourceLayout, _opts: &SnapshotOpts) -> Support {
        let Some(fs) = &src.fs else {
            return Support::No("the source has no recognisable filesystem".to_owned());
        };
        if fs.fs_type != "btrfs" {
            return Support::No(format!("the source filesystem is {}", fs.fs_type));
        }
        if fs.uuid.is_none() {
            return Support::No("the btrfs filesystem UUID could not be read".to_owned());
        }
        if src.mountpoints.is_empty() {
            return Support::No(
                "the btrfs filesystem is not mounted; mount it (or a subvolume of it) first"
                    .to_owned(),
            );
        }
        Support::Yes
    }

    /// Snapshot every mounted subvolume of the source.
    ///
    /// # Errors
    /// Returns [`Support::No`]-derived [`Error::NoConsistentMethod`] reasons as
    /// [`Error::Unsupported`], and [`Error::StreamParentMissing`] when an
    /// incremental was required but its parent is gone.
    pub fn create(&self, src: &SourceLayout, opts: &TreeSnapshotOpts) -> Result<TreeSnapshot> {
        // The set name becomes a directory whose other entries are pruned on
        // commit; `..` would make that the top level itself (R02, D-115).
        // Refuse before anything is mounted.
        lr_core::validate_set_name(&opts.set_name)?;
        match self.supports(src, &opts.general) {
            Support::Yes => {}
            Support::No(reason) => {
                return Err(Error::unsupported(format!("btrfs provider: {reason}")));
            }
        }
        let fs_uuid = src
            .fs
            .as_ref()
            .and_then(|fs| fs.uuid.clone())
            .ok_or_else(|| Error::unsupported("btrfs provider: no filesystem UUID"))?;
        let label = src
            .fs
            .as_ref()
            .and_then(|fs| fs.label.clone())
            .unwrap_or_default();

        // 1. Mount the top-level subvolume read-write. Snapshots are created by
        //    that filesystem itself, so a read-only mount cannot be used here
        //    (spec §E.1 says `ro`; D-028 records the deviation and why).
        let mountpoint = opts
            .mount_root
            .join(format!("btrfs-{}", &fs_uuid[..8.min(fs_uuid.len())]));
        mount_top_level(&src.device, &mountpoint)?;
        let top = mountpoint.clone();
        let set_dir = top.join(STATE_DIR).join(&opts.set_name);
        std::fs::create_dir_all(&set_dir).map_err(Error::Io)?;
        let image_dir = set_dir.join(opts.image_uuid.to_string());
        std::fs::create_dir_all(&image_dir).map_err(Error::Io)?;

        // 2. Which subvolumes are mounted? (spec §E.1)
        let mounted = self.mounted_subvolumes(&fs_uuid)?;
        if mounted.is_empty() {
            let _ = run_ok("umount", &[&path_text(&mountpoint)]);
            let _ = std::fs::remove_dir(&mountpoint);
            return Err(Error::unsupported(
                "btrfs provider: no mounted subvolume of this filesystem; mount a subvolume \
                 (not the top level) and retry",
            ));
        }

        // 3. Snapshot each one, reusing the recorded parent when it exists.
        let mount_options = mounted
            .first()
            .map(|entry| entry.options.clone())
            .unwrap_or_default();
        let latest = read_latest(&set_dir)?;
        let mut subvolumes = Vec::with_capacity(mounted.len());
        for subvol in mounted {
            let escaped = escape_path(&subvol.subvol_path);
            let snapshot_path =
                image_dir.join(snapshot_name(&subvol.subvol_path, &opts.image_uuid));
            let source_path = if subvol.subvol_path == "/" {
                top.clone()
            } else {
                top.join(subvol.subvol_path.trim_start_matches('/'))
            };
            run(
                "btrfs",
                &[
                    "subvolume",
                    "snapshot",
                    "-r",
                    &path_text(&source_path),
                    &path_text(&snapshot_path),
                ],
            )?;

            let (parent_snapshot, parent_snapshot_uuid) = if opts.incremental == Incremental::Never
            {
                (None, None)
            } else {
                match latest.get(&escaped) {
                    Some(previous) if previous.snapshot_path.exists() => (
                        Some(previous.snapshot_path.clone()),
                        previous.parent_snapshot_uuid,
                    ),
                    _ if opts.incremental == Incremental::Require => {
                        return Err(Error::stream_parent_missing(&subvol.subvol_path));
                    }
                    _ => (None, None),
                }
            };
            let parent_snapshot_uuid = match &parent_snapshot {
                Some(path) => subvolume_uuid(path)?.or(parent_snapshot_uuid),
                None => None,
            };

            subvolumes.push(SubvolSnapshot {
                mount_target: subvol.target,
                subvol_path: subvol.subvol_path,
                subvolid: subvol.subvolid,
                snapshot_path,
                parent_snapshot,
                parent_snapshot_uuid,
            });
        }

        let default_subvolid = default_subvolid(&top).unwrap_or(TOP_LEVEL_SUBVOLID);
        Ok(TreeSnapshot {
            fs_uuid,
            label,
            default_subvolid,
            mount_options,
            consistency: Consistency::PointInTime,
            subvolumes,
            mountpoint,
            top,
            set_dir,
            committed: false,
        })
    }

    /// Mounted subvolumes of `fs_uuid`, top level excluded.
    ///
    /// # Errors
    /// Returns [`Error::Unsupported`] when `findmnt` cannot be run.
    pub fn mounted_subvolumes(&self, fs_uuid: &str) -> Result<Vec<MountedSubvol>> {
        let output = Command::new("findmnt")
            // `-o ...UUID` is required: without it findmnt omits `uuid`
            // entirely, and a filesystem cannot be identified by its mounts.
            .args(["-J", "-o", "TARGET,SOURCE,FSTYPE,UUID,OPTIONS", "-t", "btrfs"])
            .output()
            .map_err(|error| Error::unsupported(format!("findmnt could not be run: {error}")))?;
        if !output.status.success() {
            return Err(Error::unsupported(format!(
                "findmnt failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        parse_mounted_subvolumes(&output.stdout, fs_uuid)
    }
}

/// The mount entry that holds a path, as `findmnt -T` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathMount {
    /// Mount target.
    pub target: PathBuf,
    /// Backing source, with any `[subvol]` suffix removed.
    pub device: String,
    /// Filesystem type.
    pub fstype: String,
    /// Filesystem UUID, when findmnt reports one.
    pub fs_uuid: Option<String>,
    /// Mount options.
    pub options: String,
}

/// Find the mount holding `path`, for file-mode snapshots.
///
/// # Errors
/// Returns [`Error::Unsupported`] when `findmnt` cannot be run, and
/// [`Error::Corrupt`] when its output cannot be read.
pub fn mount_of_path(path: &Path) -> Result<Option<PathMount>> {
    let output = Command::new("findmnt")
        .args([
            "-J",
            "-T",
            &path.display().to_string(),
            "-o",
            "TARGET,SOURCE,FSTYPE,UUID,OPTIONS",
        ])
        .output()
        .map_err(|error| Error::unsupported(format!("findmnt could not be run: {error}")))?;
    if !output.status.success() {
        return Ok(None);
    }
    let json: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| Error::corrupt(format!("findmnt output: {error}")))?;
    let Some(entry) = json
        .get("filesystems")
        .and_then(|value| value.as_array())
        .and_then(|array| array.first())
    else {
        return Ok(None);
    };
    let string = |key: &str| -> Option<String> {
        entry
            .get(key)
            .and_then(|value| value.as_str())
            .map(str::to_owned)
    };
    let Some(target) = string("target") else {
        return Ok(None);
    };
    let source = string("source").unwrap_or_default();
    // `findmnt` reports a subvolume mount as `/dev/sda1[/@]`.
    let device = source.split('[').next().unwrap_or_default().to_owned();
    Ok(Some(PathMount {
        target: PathBuf::from(target),
        device,
        fstype: string("fstype").unwrap_or_default(),
        fs_uuid: string("uuid").filter(|uuid| !uuid.is_empty()),
        options: string("options").unwrap_or_default(),
    }))
}

/// Parse `findmnt -J -t btrfs` output, keeping the subvolumes of one UUID.
///
/// # Errors
/// Returns [`Error::Corrupt`] when the JSON cannot be parsed.
pub fn parse_mounted_subvolumes(json: &[u8], fs_uuid: &str) -> Result<Vec<MountedSubvol>> {
    #[derive(serde::Deserialize)]
    struct Filesystems {
        #[serde(default)]
        filesystems: Vec<Entry>,
    }
    #[derive(serde::Deserialize)]
    struct Entry {
        target: String,
        #[serde(default)]
        source: String,
        #[serde(default)]
        options: Option<String>,
        #[serde(default)]
        uuid: Option<String>,
        #[serde(default)]
        children: Vec<Entry>,
    }
    let parsed: Filesystems = serde_json::from_slice(json)
        .map_err(|error| Error::corrupt(format!("findmnt output is not valid JSON: {error}")))?;
    let mut flat = Vec::new();
    fn walk(entries: Vec<Entry>, into: &mut Vec<Entry>) {
        for mut entry in entries {
            let children = std::mem::take(&mut entry.children);
            into.push(entry);
            walk(children, into);
        }
    }
    walk(parsed.filesystems, &mut flat);

    let mut found = BTreeMap::new();
    for entry in flat {
        if entry.uuid.as_deref() != Some(fs_uuid) {
            continue;
        }
        let (subvol_path, subvolid) = parse_subvol_options(entry.options.as_deref().unwrap_or(""));
        if subvolid == Some(TOP_LEVEL_SUBVOLID) {
            continue;
        }
        let subvol_path = subvol_path.unwrap_or_else(|| "/".to_owned());
        let subvolid = subvolid.unwrap_or(0);
        found.entry(subvol_path.clone()).or_insert(MountedSubvol {
            target: PathBuf::from(entry.target),
            source: entry.source,
            subvol_path,
            subvolid,
            options: entry.options.unwrap_or_default(),
        });
    }
    Ok(found.into_values().collect())
}

/// Read `subvol=` and `subvolid=` from a mount options string.
#[must_use]
pub fn parse_subvol_options(options: &str) -> (Option<String>, Option<u64>) {
    let mut path = None;
    let mut id = None;
    for option in options.split(',') {
        if let Some(value) = option.strip_prefix("subvol=") {
            path = Some(value.to_owned());
        } else if let Some(value) = option.strip_prefix("subvolid=") {
            id = value.parse().ok();
        }
    }
    (path, id)
}

/// Escape a subvolume path so it is one directory name.
///
/// `/` maps to `FS_TREE`, and `%` and `/` are percent-encoded so distinct
/// paths can never collide.
#[must_use]
pub fn escape_path(subvol_path: &str) -> String {
    let trimmed = subvol_path.trim_matches('/');
    if trimmed.is_empty() {
        return "FS_TREE".to_owned();
    }
    trimmed.replace('%', "%25").replace('/', "%2F")
}

/// A snapshot name unique to one image.
///
/// `btrfs send` names the stream after the snapshot's last path component, so
/// two images of the same subvolume must not use the same name: an incremental
/// received next to its parent would otherwise fail with `File exists`. The
/// image identifier suffix keeps the names distinct and bounded in length.
#[must_use]
pub fn snapshot_name(subvol_path: &str, image_uuid: &Id) -> String {
    let escaped = escape_path(subvol_path);
    let suffix = image_uuid.to_string();
    let suffix = &suffix[..8.min(suffix.len())];
    let room = 200usize.saturating_sub(suffix.len() + 1);
    if escaped.len() > room {
        format!("{}.{suffix}", &escaped[..room])
    } else {
        format!("{escaped}.{suffix}")
    }
}

fn latest_path(set_dir: &Path) -> PathBuf {
    set_dir.join("latest")
}

/// Read `.linuxreflect/<set>/latest` into escaped-path → previous snapshot.
fn read_latest(set_dir: &Path) -> Result<BTreeMap<String, SubvolSnapshot>> {
    let path = latest_path(set_dir);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(error) => return Err(Error::Io(error)),
    };
    let mut map = BTreeMap::new();
    for line in text.lines() {
        // `<escaped>\t<subvol_path>\t<subvolid>\t<snapshot_path>\t<parent_uuid>`
        let mut fields = line.split('\t');
        let (Some(escaped), Some(subvol_path), Some(subvolid), Some(snapshot)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let parent_snapshot_uuid = fields
            .next()
            .filter(|value| !value.is_empty() && *value != "-")
            .and_then(|value| value.parse().ok());
        map.insert(
            escaped.to_owned(),
            SubvolSnapshot {
                mount_target: PathBuf::new(),
                subvol_path: subvol_path.to_owned(),
                subvolid: subvolid.parse().unwrap_or(0),
                snapshot_path: PathBuf::from(snapshot),
                parent_snapshot: None,
                parent_snapshot_uuid,
            },
        );
    }
    Ok(map)
}

fn write_latest(set_dir: &Path, latest: &[(String, SubvolSnapshot, Option<Id>)]) -> Result<()> {
    let mut text = String::new();
    for (escaped, snapshot, own_uuid) in latest {
        let uuid = own_uuid
            .map(|id| id.to_string())
            .unwrap_or_else(|| "-".to_owned());
        text.push_str(&format!(
            "{escaped}\t{}\t{}\t{}\t{uuid}\n",
            snapshot.subvol_path,
            snapshot.subvolid,
            snapshot.snapshot_path.display()
        ));
    }
    std::fs::write(latest_path(set_dir), text).map_err(Error::Io)
}

fn mount_top_level(device: &Path, mountpoint: &Path) -> Result<()> {
    std::fs::create_dir_all(mountpoint).map_err(Error::Io)?;
    match run(
        "mount",
        &[
            "-t",
            "btrfs",
            "-o",
            "subvolid=5",
            &path_text(device),
            &path_text(mountpoint),
        ],
    ) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = std::fs::remove_dir(mountpoint);
            Err(error)
        }
    }
}

fn default_subvolid(top: &Path) -> Option<u64> {
    let output = Command::new("btrfs")
        .args(["subvolume", "get-default", &path_text(top)])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_default_subvolid(&String::from_utf8_lossy(&output.stdout))
}

/// Parse `btrfs subvolume get-default`: `ID <id> gen <n> ... path <path>`.
#[must_use]
pub fn parse_default_subvolid(text: &str) -> Option<u64> {
    let mut tokens = text.split_whitespace();
    if tokens.next()? != "ID" {
        return None;
    }
    tokens.next()?.parse().ok()
}

fn subvolume_uuid(path: &Path) -> Result<Option<Id>> {
    let output = Command::new("btrfs")
        .args(["subvolume", "show", &path_text(path)])
        .output()
        .map_err(Error::Io)?;
    if !output.status.success() {
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        if let Some(value) = line.trim().strip_prefix("UUID:") {
            return Ok(value.trim().parse().ok());
        }
    }
    Ok(None)
}

/// Delete the snapshots of every earlier image of this set.
///
/// Only this provider's own layout is touched (R02): a directory directly in
/// `set_dir` whose name is an image UUID, and within it only the subvolumes
/// directly inside, each removed with `btrfs subvolume delete`. Nothing is
/// followed through a symlink, nothing is removed recursively, and an image
/// directory is removed only once it is empty. Anything else in `set_dir`
/// is left alone.
fn prune_image_dirs(set_dir: &Path, keep: &str) -> Result<()> {
    let set_meta = std::fs::symlink_metadata(set_dir).map_err(Error::Io)?;
    if !set_meta.is_dir() {
        return Err(Error::unsupported(format!(
            "{} is not a directory; snapshots are not pruned",
            set_dir.display()
        )));
    }
    for entry in std::fs::read_dir(set_dir).map_err(Error::Io)? {
        let entry = entry.map_err(Error::Io)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name == keep || !is_image_dir_name(name) {
            continue;
        }
        // `file_type` does not follow symlinks.
        if !entry.file_type().map_err(Error::Io)?.is_dir() {
            continue;
        }
        let image_dir = entry.path();
        let Ok(children) = std::fs::read_dir(&image_dir) else {
            continue;
        };
        for child in children.flatten() {
            if child.file_type().is_ok_and(|kind| kind.is_dir()) {
                let _ = run_ok("btrfs", &["subvolume", "delete", &path_text(&child.path())]);
            }
        }
        let _ = std::fs::remove_dir(&image_dir);
    }
    Ok(())
}

/// Whether `name` is an image directory this provider creates: an image
/// UUID in its canonical text form.
fn is_image_dir_name(name: &str) -> bool {
    name.parse::<Id>().is_ok_and(|id| id.to_string() == name)
}

fn run(program: &str, args: &[&str]) -> Result<()> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| Error::unsupported(format!("{program} could not be run: {error}")))?;
    if output.status.success() {
        return Ok(());
    }
    Err(Error::corrupt(format!(
        "{program} {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}

fn run_ok(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .output()
        .is_ok_and(|output| output.status.success())
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Create a fresh Btrfs filesystem for a Stream restore (spec §H.1).
///
/// # Errors
/// Returns [`Error::Unsupported`] when `mkfs.btrfs` is missing and
/// [`Error::Corrupt`] when it fails.
pub fn create_filesystem(device: &Path, fs_uuid: &str, label: &str) -> Result<()> {
    let mut args = vec!["-f".to_owned(), "-U".to_owned(), fs_uuid.to_owned()];
    if !label.is_empty() {
        args.push("-L".to_owned());
        args.push(label.to_owned());
    }
    args.push(path_text(device));
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    run("mkfs.btrfs", &borrowed)
}

/// Run `btrfs receive` in `top`, feeding it `input`.
///
/// Returns the name of the subvolume the receiver created. `btrfs receive`
/// reports it as `At subvol <name>` (full) or `At snapshot <name>`
/// (incremental) on stderr; parsing it is how the caller learns where the
/// received subvolume landed, since the stream may choose a new name for an
/// incremental.
///
/// # Errors
/// Returns [`Error::Corrupt`] when the receive fails, with its stderr.
pub fn receive_top_level(top: &Path, input: &mut dyn Read) -> Result<String> {
    let mut child = Command::new("btrfs")
        .arg("receive")
        .arg(top)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            Error::unsupported(format!("btrfs receive could not be started: {error}"))
        })?;
    let written = {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| Error::unsupported("btrfs receive produced no stdin pipe"))?;
        std::io::copy(input, &mut stdin).map_err(Error::Io)?
    };
    let output = child.wait_with_output().map_err(Error::Io)?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() {
        return Err(Error::corrupt(format!(
            "btrfs receive failed: {}",
            stderr.trim()
        )));
    }
    // Which stream carries the progress line depends on the btrfs-progs
    // version, so both are searched.
    let name = [stdout.as_ref(), stderr.as_ref()]
        .into_iter()
        .flat_map(str::lines)
        .filter_map(|line| {
            let line = line.strip_prefix("At ")?;
            line.strip_prefix("subvol ")
                .or_else(|| line.strip_prefix("snapshot "))
        })
        .map(str::trim)
        .next_back()
        .ok_or_else(|| {
            Error::corrupt(format!(
                "btrfs receive reported no received subvolume after {written} input bytes; stdout: {:?} stderr: {:?}",
                stdout.trim(),
                stderr.trim()
            ))
        })?;
    Ok(name.rsplit('/').next().unwrap_or(name).to_owned())
}

/// The id of a subvolume by path.
///
/// # Errors
/// Propagates I/O errors; `Ok(None)` when the id cannot be determined.
pub fn subvolume_id(path: &Path) -> Result<Option<u64>> {
    let output = Command::new("btrfs")
        .args(["subvolume", "show", &path_text(path)])
        .output()
        .map_err(Error::Io)?;
    if !output.status.success() {
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("Subvolume ID:") {
            return Ok(value.trim().parse().ok());
        }
    }
    Ok(None)
}

/// Set the default subvolume of a freshly received filesystem.
///
/// # Errors
/// Propagates `btrfs subvolume set-default` failures.
pub fn set_default(top: &Path, subvolid: u64) -> Result<()> {
    run(
        "btrfs",
        &[
            "subvolume",
            "set-default",
            &subvolid.to_string(),
            &path_text(top),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::{
        Incremental, TOP_LEVEL_SUBVOLID, TreeSnapshotOpts, escape_path, parse_mounted_subvolumes,
        parse_subvol_options,
    };
    use crate::test_layout::offline;
    use lr_core::{Id, SourceLayout, Support};

    fn btrfs_layout() -> SourceLayout {
        let mut layout = offline("/dev/lr-btrfs");
        if let Some(fs) = layout.fs.as_mut() {
            fs.fs_type = "btrfs".to_owned();
            fs.uuid = Some("11111111-2222-3333-4444-555555555555".to_owned());
        }
        layout
    }

    #[test]
    fn subvolume_paths_are_escaped_without_collisions() {
        assert_eq!(escape_path("/"), "FS_TREE");
        assert_eq!(escape_path("/@"), "@");
        assert_eq!(escape_path("/home/user"), "home%2Fuser");
        assert_eq!(escape_path("/home_user"), "home_user");
        assert_eq!(escape_path("/a%b"), "a%25b");
        assert_ne!(escape_path("/a/b"), escape_path("/a_b"));
    }

    #[test]
    fn snapshot_names_are_unique_per_image_and_bounded() {
        let first = Id::from_bytes([1u8; 16]);
        let second = Id::from_bytes([2u8; 16]);
        let name = super::snapshot_name("/@", &first);
        assert_ne!(name, super::snapshot_name("/@", &second));
        assert!(name.starts_with("@."), "{name}");
        let deep = format!("/{}", "x".repeat(400));
        assert!(super::snapshot_name(&deep, &first).len() <= 200);
    }

    #[test]
    fn a_set_name_that_leaves_the_state_directory_is_refused_before_mounting() {
        // The fixture device does not exist: had the name been accepted, the
        // provider would fail later at `mount`, with a different error.
        let provider = super::BtrfsProvider;
        for name in ["..", ".", "a/b", ""] {
            let mut opts = TreeSnapshotOpts::new(name, Id::from_bytes([9u8; 16]));
            opts.mount_root = std::path::PathBuf::from("/nonexistent-lr-test");
            let Err(error) = provider.create(&btrfs_layout(), &opts) else {
                panic!("{name:?}: an invalid set name must be refused");
            };
            assert!(
                error.to_string().contains("invalid set name"),
                "{name:?}: {error}"
            );
        }
    }

    #[test]
    fn only_image_uuid_directories_are_pruned() {
        let dir = tempfile::tempdir().expect("tempdir");
        let set_dir = dir.path();
        let keep = Id::from_bytes([1u8; 16]).to_string();
        let old = Id::from_bytes([0xabu8; 16]).to_string();
        for name in [keep.as_str(), old.as_str(), "@home", "not-a-uuid"] {
            std::fs::create_dir(set_dir.join(name)).expect("dir");
            std::fs::write(set_dir.join(name).join("file"), b"data").expect("file");
        }
        std::fs::write(set_dir.join("latest"), b"").expect("latest");
        super::prune_image_dirs(set_dir, &keep).expect("prune");
        // Plain files are never deleted: only subvolumes are, by `btrfs`.
        for name in [keep.as_str(), old.as_str(), "@home", "not-a-uuid"] {
            assert!(set_dir.join(name).join("file").exists(), "{name}");
        }
        assert!(super::is_image_dir_name(&old));
        assert!(!super::is_image_dir_name("@home"));
        assert!(!super::is_image_dir_name(".."));
        assert!(!super::is_image_dir_name(&old.to_uppercase()));
    }

    #[test]
    fn mount_options_are_parsed() {
        let (path, id) = parse_subvol_options("rw,relatime,subvolid=256,subvol=/@");
        assert_eq!(path.as_deref(), Some("/@"));
        assert_eq!(id, Some(256));
        assert_eq!(parse_subvol_options("rw,ssd"), (None, None));
    }

    #[test]
    fn findmnt_json_keeps_only_this_filesystem_and_skips_the_top_level() {
        let json = br#"{
          "filesystems": [
            { "target": "/", "source": "/dev/sda2", "uuid": "11111111-2222-3333-4444-555555555555",
              "options": "rw,relatime,subvolid=256,subvol=/@",
              "children": [ { "target": "/home", "source": "/dev/sda2",
                              "uuid": "11111111-2222-3333-4444-555555555555",
                              "options": "rw,relatime,subvolid=257,subvol=/@home" } ] },
            { "target": "/mnt/other", "source": "/dev/sdb1", "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
              "options": "rw,subvolid=5,subvol=/" },
            { "target": "/var", "source": "/dev/sda2", "uuid": "11111111-2222-3333-4444-555555555555",
              "options": "rw,subvolid=5,subvol=/" }
          ]
        }"#;
        let found =
            parse_mounted_subvolumes(json, "11111111-2222-3333-4444-555555555555").expect("parse");
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].subvol_path, "/@");
        assert_eq!(found[0].subvolid, 256);
        assert_eq!(found[1].subvol_path, "/@home");
        assert!(found.iter().all(|s| s.subvolid != TOP_LEVEL_SUBVOLID));
    }

    #[test]
    fn invalid_findmnt_json_is_rejected() {
        assert!(parse_mounted_subvolumes(b"not json", "x").is_err());
    }

    #[test]
    fn a_non_btrfs_source_is_refused() {
        let layout = offline("/dev/lr-ext4");
        let provider = super::provider();
        match provider.supports(&layout, &lr_core::SnapshotOpts::default()) {
            Support::No(reason) => assert!(reason.contains("ext4"), "{reason}"),
            Support::Yes => panic!("must refuse ext4"),
        }
    }

    #[test]
    fn an_unmounted_btrfs_source_is_refused() {
        let layout = btrfs_layout();
        match super::provider().supports(&layout, &lr_core::SnapshotOpts::default()) {
            Support::No(reason) => assert!(reason.contains("not mounted"), "{reason}"),
            Support::Yes => panic!("must refuse an unmounted btrfs"),
        }
    }

    #[test]
    fn tree_options_default_to_auto_incrementals() {
        let opts = TreeSnapshotOpts::new("set", Id::from_bytes([7u8; 16]));
        assert_eq!(opts.incremental, Incremental::Auto);
        assert_eq!(
            opts.mount_root,
            std::path::PathBuf::from("/run/linuxreflect")
        );
    }
}
