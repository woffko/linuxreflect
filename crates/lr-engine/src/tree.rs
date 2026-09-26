//! File-mode tree walking and restoring (spec §D.1 `File`, §G.7, §K S12).
//!
//! A walk records the metadata of every entry and the sparse layout of regular
//! files; the content is chunked by [`crate::file`]. Restoration recreates the
//! entries in a target directory, including ownership, permissions, timestamps,
//! extended attributes (POSIX ACLs are xattrs), hard links and device nodes.
//!
//! The walk deliberately never follows a symbolic link. It pins the source
//! root with a descriptor, reaches every directory beneath it without
//! following symlinks, and names each entry as one component of its pinned
//! directory; a regular file's identity is recorded from the descriptor its
//! sparse map is read from, and the content pass reopens it the same way and
//! refuses a different file (R14). A symlink planted in any ancestor while
//! the walk runs cannot redirect the backup outside the source tree.

use std::collections::{BTreeMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use lr_core::{Error, Result};
use lr_format::file_manifest::{
    FILE_KIND_DIRECTORY, FILE_KIND_HARDLINK, FILE_KIND_REGULAR, FILE_KIND_SPECIAL,
    FILE_KIND_SYMLINK, FileEntry, Xattr,
};

/// `O_NOFOLLOW`: fail instead of opening a symbolic link.
const O_NOFOLLOW: i32 = 0o400000;

/// Paths a file-mode walk never enters unless they are the source itself.
pub const DEFAULT_EXCLUDES: [&str; 5] = ["/proc", "/sys", "/dev", "/run", "/tmp"];

/// How a walk treats the tree.
#[derive(Debug, Clone)]
pub struct WalkOptions {
    /// Do not descend into directories on another filesystem (spec §K S12).
    pub one_file_system: bool,
    /// Absolute paths to skip, compared after canonicalization.
    pub excludes: Vec<PathBuf>,
    /// Read extended attributes (and therefore POSIX ACLs).
    pub xattrs: bool,
}

impl Default for WalkOptions {
    fn default() -> Self {
        Self::with_default_excludes()
    }
}

impl WalkOptions {
    /// The spec §K S12 defaults plus `--one-file-system`.
    #[must_use]
    pub fn with_default_excludes_one_file_system() -> Self {
        Self {
            one_file_system: true,
            ..Self::with_default_excludes()
        }
    }

    /// The spec §K S12 defaults: no cross-filesystem descent, pseudo-filesystems
    /// excluded, xattrs read.
    #[must_use]
    pub fn with_default_excludes() -> Self {
        Self {
            one_file_system: false,
            excludes: DEFAULT_EXCLUDES
                .iter()
                .map(PathBuf::from)
                .filter(|path| path.exists())
                .collect(),
            xattrs: true,
        }
    }
}

/// One walked entry, with the content still to be chunked.
#[derive(Debug, Clone)]
pub struct WalkedEntry {
    /// Metadata, without chunk references.
    pub entry: FileEntry,
    /// Sparse regions of a regular file as `(offset, length)`.
    pub holes: Vec<(u64, u64)>,
    /// `(st_dev, st_ino)` of a regular file, from the descriptor the walk
    /// read it through; the content pass must find the same file.
    pub identity: Option<(u64, u64)>,
}

/// The result of a walk.
#[derive(Debug, Clone, Default)]
pub struct WalkedTree {
    /// Entries in walk order: a directory precedes its children.
    pub entries: Vec<WalkedEntry>,
    /// Sum of regular-file sizes.
    pub total_bytes: u64,
    /// Non-fatal notes, e.g. a file that shrank while it was being read.
    pub warnings: Vec<String>,
    /// The walked root, pinned for the content pass.
    root: Option<std::sync::Arc<std::os::fd::OwnedFd>>,
}

impl WalkedTree {
    /// Close the pinned root. A walk of a snapshot must release it before
    /// the snapshot is unmounted, or the unmount fails as busy.
    pub fn release_root(&mut self) {
        self.root = None;
    }

    /// Open a regular file the walk recorded, beneath the pinned root and
    /// without following symlinks, and check that it is still that file.
    ///
    /// # Errors
    /// Refuses an entry whose path now crosses a symlink or names another
    /// file (it was replaced while the backup ran; retry the backup), and
    /// propagates other I/O errors.
    pub fn open_file(&self, walked: &WalkedEntry) -> Result<File> {
        let root = self
            .root
            .as_ref()
            .ok_or_else(|| Error::unsupported("this walk has no pinned root"))?;
        let relative = Path::new(std::ffi::OsStr::from_bytes(&walked.entry.path));
        let (parent, name) = split_parent(relative)?;
        let replaced = |why: String| {
            Error::unsupported(format!(
                "{} was replaced while the backup ran ({why}); nothing was read from it, \
                 retry the backup",
                relative.display()
            ))
        };
        let parent = lr_unsafe::beneath::open_dir_beneath(root.as_ref(), parent)
            .map_err(|error| replaced(error.to_string()))?;
        let path = lr_unsafe::beneath::entry_path(&parent, name).map_err(Error::Io)?;
        let file = open_nofollow(&path).map_err(|error| replaced(error.to_string()))?;
        let metadata = file.metadata().map_err(Error::Io)?;
        if Some((metadata.dev(), metadata.ino())) != walked.identity {
            return Err(replaced("it is a different file now".to_owned()));
        }
        Ok(file)
    }
}

/// Walk `root` and record every entry below it, including the root itself.
///
/// The root is recorded with an empty path, so restoring a tree can also apply
/// the root directory's own mode, owner and timestamp.
///
/// # Errors
/// Returns [`Error::Unsupported`] when the root is not a directory and
/// propagates filesystem and xattr errors.
pub fn walk(root: &Path, options: &WalkOptions) -> Result<WalkedTree> {
    let root = root
        .canonicalize()
        .map_err(|error| Error::unsupported(format!("{}: {error}", root.display())))?;
    let root_metadata = std::fs::symlink_metadata(&root).map_err(Error::Io)?;
    if !root_metadata.is_dir() {
        return Err(Error::unsupported(format!(
            "{} is not a directory; file mode backs up directory trees",
            root.display()
        )));
    }
    let excludes: HashSet<PathBuf> = options
        .excludes
        .iter()
        .filter_map(|path| path.canonicalize().ok())
        .collect();
    if excludes.contains(&root) {
        return Err(Error::unsupported(format!(
            "{} is excluded from file-mode backups",
            root.display()
        )));
    }

    // Everything below is reached through this descriptor, never by name.
    let pinned = lr_unsafe::beneath::open_root(&root).map_err(Error::Io)?;
    let pinned_metadata = File::from(pinned.try_clone().map_err(Error::Io)?)
        .metadata()
        .map_err(Error::Io)?;
    if (pinned_metadata.dev(), pinned_metadata.ino()) != (root_metadata.dev(), root_metadata.ino())
    {
        return Err(Error::unsupported(format!(
            "{} changed while the backup started; retry",
            root.display()
        )));
    }
    let root_device = root_metadata.dev();
    let mut tree = WalkedTree::default();
    let mut hardlinks: BTreeMap<(u64, u64), u32> = BTreeMap::new();

    record(
        Path::new(""),
        &lr_unsafe::beneath::self_path(&pinned),
        options,
        &mut hardlinks,
        &mut tree,
    )?;

    let mut stack: Vec<PathBuf> = vec![PathBuf::new()];
    while let Some(directory) = stack.pop() {
        let dir = lr_unsafe::beneath::open_dir_beneath(&pinned, &directory).map_err(|error| {
            Error::unsupported(format!(
                "{}: the directory cannot be reached without following a symlink (it was \
                 replaced while the backup ran?): {error}",
                root.join(&directory).display()
            ))
        })?;
        let mut names = Vec::new();
        for entry in std::fs::read_dir(lr_unsafe::beneath::object_path(&dir)).map_err(Error::Io)? {
            names.push(entry.map_err(Error::Io)?.file_name());
        }
        // Deterministic order keeps two walks of the same tree identical.
        names.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        for name in names {
            let relative = directory.join(&name);
            if excludes.contains(&root.join(&relative)) {
                continue;
            }
            let path = lr_unsafe::beneath::entry_path(&dir, &name).map_err(Error::Io)?;
            let metadata = std::fs::symlink_metadata(&path).map_err(Error::Io)?;
            record(&relative, &path, options, &mut hardlinks, &mut tree)?;
            // A mount point is recorded, its contents are not, with
            // `--one-file-system`.
            if metadata.is_dir() && !(options.one_file_system && metadata.dev() != root_device) {
                stack.push(relative);
            }
        }
    }
    tree.root = Some(std::sync::Arc::new(pinned));
    Ok(tree)
}

/// Record the entry `relative`, reached as `path` (one component of its
/// pinned parent directory, see [`lr_unsafe::beneath`]).
fn record(
    relative: &Path,
    path: &Path,
    options: &WalkOptions,
    hardlinks: &mut BTreeMap<(u64, u64), u32>,
    tree: &mut WalkedTree,
) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path).map_err(Error::Io)?;
    let kind = metadata.file_type();
    let file_kind = if kind.is_dir() {
        FILE_KIND_DIRECTORY
    } else if kind.is_symlink() {
        FILE_KIND_SYMLINK
    } else if kind.is_file() {
        FILE_KIND_REGULAR
    } else {
        FILE_KIND_SPECIAL
    };

    let mut entry = FileEntry {
        file_kind,
        mode: metadata.mode(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        mtime_sec: metadata.mtime(),
        mtime_nsec: metadata.mtime_nsec() as u32,
        size: metadata.size(),
        rdev: metadata.rdev(),
        hardlink_group: 0,
        link_target: Vec::new(),
        path: relative.as_os_str().as_bytes().to_vec(),
        xattrs: Vec::new(),
        acl: Vec::new(),
        chunk_refs_total: 0,
        chunk_refs_here: Vec::new(),
    };
    let mut holes = Vec::new();
    let mut identity = None;
    let total_bytes = &mut tree.total_bytes;
    let warnings = &mut tree.warnings;

    match file_kind {
        FILE_KIND_SYMLINK => {
            entry.link_target = std::fs::read_link(path)
                .map_err(Error::Io)?
                .as_os_str()
                .as_bytes()
                .to_vec();
            entry.size = 0;
        }
        FILE_KIND_REGULAR if metadata.nlink() > 1 => {
            let key = (metadata.dev(), metadata.ino());
            match hardlinks.get(&key) {
                Some(group) => {
                    entry.file_kind = FILE_KIND_HARDLINK;
                    entry.hardlink_group = *group;
                    entry.size = 0;
                }
                None => {
                    let group = u32::try_from(hardlinks.len() + 1).unwrap_or(u32::MAX);
                    hardlinks.insert(key, group);
                    entry.hardlink_group = group;
                    *total_bytes += metadata.size();
                    holes = sparse_holes(path, &metadata, warnings)?;
                    identity = Some(key);
                }
            }
        }
        FILE_KIND_REGULAR => {
            *total_bytes += metadata.size();
            holes = sparse_holes(path, &metadata, warnings)?;
            identity = Some((metadata.dev(), metadata.ino()));
        }
        _ => {}
    }

    if options.xattrs {
        let (acl, xattrs) = read_xattrs(path)?;
        entry.acl = acl;
        entry.xattrs = xattrs;
    }

    tree.entries.push(WalkedEntry {
        entry,
        holes,
        identity,
    });
    Ok(())
}

/// Sparse regions of `path`, using `SEEK_DATA`/`SEEK_HOLE` (spec §F).
///
/// A filesystem without hole support reports one data region covering the whole
/// file, so the result is simply empty.
fn sparse_holes(
    path: &Path,
    metadata: &std::fs::Metadata,
    warnings: &mut Vec<String>,
) -> Result<Vec<(u64, u64)>> {
    let size = metadata.size();
    if size == 0 {
        return Ok(Vec::new());
    }
    let file = open_nofollow(path)?;
    // The map must describe the file whose metadata was recorded (R14).
    let opened = file.metadata().map_err(Error::Io)?;
    if (opened.dev(), opened.ino()) != (metadata.dev(), metadata.ino()) {
        return Err(Error::unsupported(format!(
            "{} was replaced while the backup ran; retry the backup",
            path.display()
        )));
    }
    Ok(holes_from(
        size,
        |offset| lr_unsafe::filemeta::seek_data(&file, offset),
        |offset| lr_unsafe::filemeta::seek_hole(&file, offset),
        |error| {
            warnings.push(format!(
                "{}: cannot inspect sparse regions: {error}",
                path.display()
            ));
        },
    ))
}

/// The hole map of a file of `size` bytes, from its `SEEK_DATA` and
/// `SEEK_HOLE` answers.
///
/// `Ok(None)` means `ENXIO`, "no data at or after this offset", and only
/// that ends the walk with a trailing hole. Any error means there is no hole
/// information: the whole file is then data (an empty map), so every byte is
/// stored (R03). `EINVAL` and `ENOTSUP` are the normal answer of a filesystem
/// without hole support and are not reported; other errors are.
fn holes_from(
    size: u64,
    mut seek_data: impl FnMut(u64) -> std::io::Result<Option<u64>>,
    mut seek_hole: impl FnMut(u64) -> std::io::Result<Option<u64>>,
    mut warn: impl FnMut(&std::io::Error),
) -> Vec<(u64, u64)> {
    let mut no_information = |error: &std::io::Error| {
        if !matches!(error.raw_os_error(), Some(libc::EINVAL | libc::ENOTSUP)) {
            warn(error);
        }
        Vec::new()
    };
    let mut holes = Vec::new();
    let mut position = 0u64;
    while position < size {
        match seek_data(position) {
            Ok(Some(data)) if data > position => {
                holes.push((position, data.min(size) - position));
                position = data;
            }
            Ok(Some(_)) => {}
            Ok(None) => {
                holes.push((position, size - position));
                break;
            }
            Err(error) => return no_information(&error),
        }
        if position >= size {
            break;
        }
        match seek_hole(position) {
            Ok(Some(hole)) if hole > position => position = hole,
            // A hole at the data offset contradicts the previous answer;
            // stop trusting the map rather than loop.
            Ok(Some(_)) => {
                return no_information(&std::io::Error::other("SEEK_HOLE and SEEK_DATA disagree"));
            }
            Ok(None) => break,
            Err(error) => return no_information(&error),
        }
    }
    holes
}

/// Open a regular file for reading, refusing to follow a symbolic link.
///
/// # Errors
/// Returns [`Error::Io`] for anything but a regular file or a refused symlink.
pub fn open_nofollow(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(Error::Io)?;
    let metadata = file.metadata().map_err(Error::Io)?;
    if !metadata.is_file() {
        return Err(Error::unsupported(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    Ok(file)
}

/// Read the extended attributes of a path, splitting out the access ACL.
fn read_xattrs(path: &Path) -> Result<(Vec<u8>, Vec<Xattr>)> {
    let mut acl = Vec::new();
    let mut xattrs = Vec::new();
    let names = match lr_unsafe::filemeta::list_xattrs(path) {
        Ok(names) => names,
        Err(error) if error.kind() == io::ErrorKind::Unsupported => return Ok((acl, xattrs)),
        Err(error) => {
            // Filesystems without xattr support answer ENOTSUP; anything else
            // is worth reporting but never fatal for a backup.
            if matches!(error.raw_os_error(), Some(libc::EOPNOTSUPP)) {
                return Ok((acl, xattrs));
            }
            return Err(Error::Io(error));
        }
    };
    for name in names {
        let value = match lr_unsafe::filemeta::get_xattr(path, &name) {
            Ok(value) => value,
            Err(error) => {
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ENODATA | libc::EOPNOTSUPP | libc::EPERM | libc::EACCES)
                ) {
                    continue;
                }
                return Err(Error::Io(error));
            }
        };
        if name == b"system.posix_acl_access" {
            acl = value;
        } else {
            xattrs.push(Xattr { name, value });
        }
    }
    xattrs.sort_by(|a, b| a.name.cmp(&b.name));
    Ok((acl, xattrs))
}

/// The restore root, pinned by a descriptor (R06).
///
/// Every restored entry is created, replaced and given its metadata through
/// a directory resolved beneath this root without following symlinks, and
/// then as a single name inside that directory. Neither a path in the image
/// nor a symlink already present in a `--merge` target can make a restore
/// write outside the approved directory.
pub struct RestoreRoot {
    fd: std::os::fd::OwnedFd,
}

/// One entry below the root: its pinned parent directory and the path that
/// names the entry inside it (valid while the entry is alive).
struct Entry {
    _parent: std::os::fd::OwnedFd,
    path: PathBuf,
}

impl RestoreRoot {
    /// Pin the directory at `path`.
    ///
    /// # Errors
    /// Returns [`Error::Io`] when it cannot be opened as a directory.
    pub fn open(path: &Path) -> Result<Self> {
        Ok(Self {
            fd: lr_unsafe::beneath::open_root(path).map_err(Error::Io)?,
        })
    }

    /// The entry `relative`; its parent directories must already exist.
    fn entry(&self, relative: &Path) -> Result<Entry> {
        let (parent, name) = split_parent(relative)?;
        let parent = lr_unsafe::beneath::open_dir_beneath(&self.fd, parent).map_err(|error| {
            Error::unsupported(format!(
                "{}: the parent directory cannot be reached inside the restore root without \
                 following a symlink: {error}",
                relative.display()
            ))
        })?;
        let path = lr_unsafe::beneath::entry_path(&parent, name).map_err(Error::Io)?;
        Ok(Entry {
            _parent: parent,
            path,
        })
    }

    /// Create any missing ancestors of `relative` (mode 0700; the manifest's
    /// own directory entries set the final metadata).
    fn ensure_parent(&self, relative: &Path) -> Result<()> {
        let (parent, _) = split_parent(relative)?;
        self.ensure_dirs(parent, 0o700)
    }

    /// The directory `relative` below the root, created (with `mode`) where
    /// it is missing, and pinned.
    ///
    /// # Errors
    /// Refuses a path that is not plain and relative, or that crosses a
    /// symlink or a non-directory, and propagates `mkdir` errors.
    pub fn dir(&self, relative: &Path, mode: u32) -> Result<PinnedDir> {
        self.ensure_dirs(relative, mode)?;
        let fd = lr_unsafe::beneath::open_dir_beneath(&self.fd, relative).map_err(|error| {
            Error::unsupported(format!(
                "{} cannot be reached inside the restore root without following a symlink: \
                 {error}",
                relative.display()
            ))
        })?;
        Ok(PinnedDir { fd })
    }

    fn ensure_dirs(&self, relative: &Path, mode: u32) -> Result<()> {
        let components = lr_unsafe::beneath::normal_components(relative).map_err(Error::Io)?;
        let mut prefix = PathBuf::new();
        for component in components {
            let entry = self.entry(&prefix.join(component))?;
            match std::fs::symlink_metadata(&entry.path) {
                Ok(metadata) if metadata.is_dir() => {}
                Ok(_) => {
                    return Err(Error::unsupported(format!(
                        "{} exists in the restore root and is not a directory",
                        prefix.join(component).display()
                    )));
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    std::fs::DirBuilder::new()
                        .mode(mode)
                        .create(&entry.path)
                        .map_err(Error::Io)?;
                }
                Err(error) => return Err(Error::Io(error)),
            }
            prefix.push(component);
        }
        Ok(())
    }
}

/// A directory below a [`RestoreRoot`], pinned by a descriptor.
pub struct PinnedDir {
    fd: std::os::fd::OwnedFd,
}

impl PinnedDir {
    /// The path of `name` in this directory, for this process.
    ///
    /// # Errors
    /// Refuses a `name` that is not one plain component.
    pub fn entry(&self, name: &std::ffi::OsStr) -> Result<PathBuf> {
        lr_unsafe::beneath::entry_path(&self.fd, name).map_err(Error::Io)
    }

    /// The path of this directory for a child process: children inherit no
    /// descriptors, so it goes through this process's `/proc/<pid>/fd`.
    #[must_use]
    pub fn for_child(&self) -> PathBuf {
        use std::os::fd::AsRawFd;
        PathBuf::from(format!(
            "/proc/{}/fd/{}/.",
            std::process::id(),
            self.fd.as_raw_fd()
        ))
    }

    /// The path of `name` in this directory for a child process.
    ///
    /// # Errors
    /// Refuses a `name` that is not one plain component.
    pub fn child_entry(&self, name: &std::ffi::OsStr) -> Result<PathBuf> {
        use std::os::fd::AsRawFd;
        // Checks that `name` is one plain component.
        self.entry(name)?;
        Ok(PathBuf::from(format!(
            "/proc/{}/fd/{}",
            std::process::id(),
            self.fd.as_raw_fd()
        ))
        .join(name))
    }
}

/// Split a relative path into its parent and final name.
fn split_parent(relative: &Path) -> Result<(&Path, &std::ffi::OsStr)> {
    let name = relative
        .file_name()
        .ok_or_else(|| Error::corrupt(format!("{} has no final name", relative.display())))?;
    Ok((relative.parent().unwrap_or(Path::new("")), name))
}

/// Restore an entry below `root` (the restore root).
///
/// `content` is called at most once for a regular file and must write the file
/// body in chunk order; `holes` are punched before the content is written.
/// `hardlink_targets` maps a hard-link group to the relative path restored
/// first for it.
///
/// # Errors
/// Propagates filesystem errors, including `EPERM` from `mknod` when not
/// privileged and an attempt to recreate a device node, and refuses an entry
/// whose parent cannot be reached without following a symlink.
pub fn restore_entry(
    root: &RestoreRoot,
    entry: &FileEntry,
    holes: &[(u64, u64)],
    hardlink_targets: &BTreeMap<u32, PathBuf>,
    content: &mut dyn FnMut(&mut File) -> Result<()>,
) -> Result<()> {
    let relative = PathBuf::from(std::ffi::OsStr::from_bytes(&entry.path));
    if relative.as_os_str().is_empty() {
        // The restore root itself: only its metadata is applied.
        return apply_metadata(root, entry);
    }
    root.ensure_parent(&relative)?;
    let target = root.entry(&relative)?;
    let path = &target.path;

    match entry.file_kind {
        FILE_KIND_DIRECTORY => match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => {
                remove_existing(path)?;
                std::fs::create_dir(path).map_err(Error::Io)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                std::fs::create_dir(path).map_err(Error::Io)?;
            }
            Err(error) => return Err(Error::Io(error)),
        },
        FILE_KIND_SYMLINK => {
            remove_existing(path)?;
            let link = PathBuf::from(std::ffi::OsStr::from_bytes(&entry.link_target));
            std::os::unix::fs::symlink(&link, path).map_err(Error::Io)?;
        }
        FILE_KIND_HARDLINK => {
            let first = hardlink_targets.get(&entry.hardlink_group).ok_or_else(|| {
                Error::corrupt(format!(
                    "{} is a hard link to a file the images never restored",
                    String::from_utf8_lossy(&entry.path)
                ))
            })?;
            let first = root.entry(first)?;
            remove_existing(path)?;
            // linkat(2) without AT_SYMLINK_FOLLOW links the entry itself.
            std::fs::hard_link(&first.path, path).map_err(Error::Io)?;
        }
        FILE_KIND_SPECIAL => {
            remove_existing(path)?;
            lr_unsafe::filemeta::mknod(path, entry.mode, entry.rdev).map_err(|error| {
                Error::unsupported(format!(
                    "cannot recreate {}: {error} (device nodes need root)",
                    String::from_utf8_lossy(&entry.path)
                ))
            })?;
        }
        _ => {
            remove_existing(path)?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .custom_flags(O_NOFOLLOW)
                .mode(0o600)
                .open(path)
                .map_err(Error::Io)?;
            if !holes.is_empty() {
                push_holes(&file, holes);
            }
            content(&mut file)?;
            file.set_len(entry.size).map_err(Error::Io)?;
        }
    }
    Ok(())
}

/// Apply ownership, mode, timestamps and xattrs, deepest directories last.
///
/// Directory timestamps are applied only after their contents exist, so writing
/// children does not bump the mtime of a directory that was just restored.
/// Every call acts on the entry itself inside its pinned parent: ownership,
/// times and xattrs never follow a final symlink, and the mode is set through
/// a descriptor of the verified non-symlink entry.
///
/// # Errors
/// Propagates `chown`/`chmod`/`utimensat` errors, except that a failure to
/// restore ownership of a symlink is reported as unsupported only when it is
/// `EPERM` (an unprivileged restore).
pub fn apply_metadata(root: &RestoreRoot, entry: &FileEntry) -> Result<()> {
    let relative = PathBuf::from(std::ffi::OsStr::from_bytes(&entry.path));
    let (_pinned, path) = if relative.as_os_str().is_empty() {
        (None, lr_unsafe::beneath::self_path(&root.fd))
    } else {
        let target = root.entry(&relative)?;
        let path = target.path.clone();
        (Some(target), path)
    };
    if let Some(error) = set_owner(&path, entry) {
        return Err(error);
    }
    if entry.file_kind != FILE_KIND_SYMLINK {
        // chmod(2) follows symlinks, so it goes through a descriptor of the
        // entry after checking that the entry is not one.
        let object = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | O_NOFOLLOW)
            .open(&path)
            .map_err(Error::Io)?;
        if object
            .metadata()
            .map_err(Error::Io)?
            .file_type()
            .is_symlink()
        {
            return Err(Error::unsupported(format!(
                "{} became a symlink during the restore",
                String::from_utf8_lossy(&entry.path)
            )));
        }
        std::fs::set_permissions(
            lr_unsafe::beneath::object_path(&object),
            std::fs::Permissions::from_mode(entry.mode & 0o7777),
        )
        .map_err(Error::Io)?;
    }
    let _ = lr_unsafe::filemeta::set_times_nofollow(
        &path,
        entry.mtime_sec,
        entry.mtime_nsec,
        entry.mtime_sec,
        entry.mtime_nsec,
    );
    if !entry.acl.is_empty() {
        let _ = lr_unsafe::filemeta::set_xattr(&path, b"system.posix_acl_access", &entry.acl);
    }
    for xattr in &entry.xattrs {
        if let Err(error) = lr_unsafe::filemeta::set_xattr(&path, &xattr.name, &xattr.value) {
            if matches!(
                error.raw_os_error(),
                Some(libc::EPERM | libc::EACCES | libc::EOPNOTSUPP)
            ) {
                continue;
            }
            return Err(Error::Io(error));
        }
    }
    Ok(())
}

fn set_owner(path: &Path, entry: &FileEntry) -> Option<Error> {
    match lr_unsafe::filemeta::lchown(path, entry.uid, entry.gid) {
        Ok(()) => None,
        Err(error) if error.raw_os_error() == Some(libc::EPERM) => None,
        Err(error) => Some(Error::Io(error)),
    }
}

fn push_holes(file: &File, holes: &[(u64, u64)]) {
    for (offset, len) in holes {
        if let Err(error) = lr_unsafe::filemeta::punch_hole(file, *offset, *len)
            && !lr_unsafe::filemeta::punch_hole_unsupported(&error)
        {
            // Losing sparseness is not a correctness problem: the content is
            // written explicitly and the file still compares equal.
            tracing::debug!(%error, "cannot punch a hole");
        }
    }
}

/// Remove an entry without following it: `remove_dir_all` does not follow
/// symlinks, and `remove_file` unlinks a symlink itself.
fn remove_existing(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => std::fs::remove_dir_all(path).map_err(Error::Io),
        Ok(_) => std::fs::remove_file(path).map_err(Error::Io),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Error::Io(error)),
    }
}

/// Sort entries so directories come after their contents, for metadata passes.
#[must_use]
pub fn deepest_first(entries: &[FileEntry]) -> Vec<&FileEntry> {
    let mut sorted: Vec<&FileEntry> = entries.iter().collect();
    sorted.sort_by(|a, b| {
        let depth = |entry: &FileEntry| entry.path.iter().filter(|byte| **byte == b'/').count();
        depth(b).cmp(&depth(a)).then_with(|| b.path.cmp(&a.path))
    });
    sorted
}

#[cfg(test)]
mod tests {
    use super::{WalkOptions, deepest_first, restore_entry, walk};
    use lr_format::file_manifest::{
        FILE_KIND_DIRECTORY, FILE_KIND_HARDLINK, FILE_KIND_REGULAR, FILE_KIND_SPECIAL,
        FILE_KIND_SYMLINK, FileEntry,
    };
    use std::collections::BTreeMap;
    use std::io::Write;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};

    fn temp() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn errno(code: i32) -> std::io::Error {
        std::io::Error::from_raw_os_error(code)
    }

    #[test]
    fn unsupported_hole_queries_mean_the_whole_file_is_data() {
        // R03: a filesystem that answers EINVAL or ENOTSUP has no hole
        // information, so nothing may be recorded as a hole and the whole
        // file is stored.
        for code in [libc::EINVAL, libc::ENOTSUP] {
            let mut warned = 0;
            let holes = super::holes_from(
                8192,
                |_| Err(errno(code)),
                |_| Ok(Some(8192)),
                |_| warned += 1,
            );
            assert!(holes.is_empty(), "errno {code}: {holes:?}");
            assert_eq!(warned, 0, "an unsupported call is not a warning");

            let holes = super::holes_from(
                8192,
                |offset| Ok(Some(offset)),
                |_| Err(errno(code)),
                |_| {},
            );
            assert!(holes.is_empty(), "errno {code} from SEEK_HOLE: {holes:?}");
        }
        let mut warned = 0;
        let holes = super::holes_from(
            8192,
            |_| Err(errno(libc::EIO)),
            |_| Ok(None),
            |_| {
                warned += 1;
            },
        );
        assert!(holes.is_empty());
        assert_eq!(warned, 1, "an unexpected error is reported");
    }

    #[test]
    fn genuine_holes_are_still_mapped() {
        // All hole: ENXIO at offset 0.
        let holes = super::holes_from(4096, |_| Ok(None), |_| Ok(Some(0)), |_| {});
        assert_eq!(holes, vec![(0, 4096)]);
        // Hole, data, trailing hole.
        let holes = super::holes_from(
            12288,
            |offset| Ok((offset < 8192).then_some(4096.max(offset))),
            |offset| Ok(Some(if offset < 8192 { 8192 } else { 12288 })),
            |_| {},
        );
        assert_eq!(holes, vec![(0, 4096), (8192, 4096)]);
        // A contradictory answer stops trusting the map instead of looping.
        let holes = super::holes_from(
            4096,
            |offset| Ok(Some(offset)),
            |offset| Ok(Some(offset)),
            |_| {},
        );
        assert!(holes.is_empty());
    }

    fn entry_for<'a>(tree: &'a super::WalkedTree, path: &str) -> &'a super::WalkedEntry {
        tree.entries
            .iter()
            .find(|walked| walked.entry.path == path.as_bytes())
            .unwrap_or_else(|| panic!("{path} was not walked"))
    }

    #[test]
    fn a_tree_records_metadata_and_sparseness() {
        let dir = temp();
        let root = dir.path().join("source");
        std::fs::create_dir_all(root.join("sub/deeper")).expect("dirs");
        std::fs::write(root.join("sub/hello.txt"), b"hello world").expect("file");
        std::fs::hard_link(root.join("sub/hello.txt"), root.join("sub/link.txt")).expect("hard");
        std::os::unix::fs::symlink("hello.txt", root.join("sub/sym")).expect("symlink");
        let sparse = std::fs::File::create(root.join("sparse.bin")).expect("sparse");
        sparse.set_len(8 * 1024 * 1024).expect("size");
        drop(sparse);

        let options = WalkOptions {
            excludes: Vec::new(),
            ..WalkOptions::with_default_excludes()
        };
        let tree = walk(&root, &options).expect("walk");

        let root_entry = entry_for(&tree, "");
        assert_eq!(root_entry.entry.file_kind, FILE_KIND_DIRECTORY);

        let directory = entry_for(&tree, "sub");
        assert_eq!(directory.entry.file_kind, FILE_KIND_DIRECTORY);

        let file = entry_for(&tree, "sub/hello.txt");
        assert_eq!(file.entry.file_kind, FILE_KIND_REGULAR);
        assert_eq!(file.entry.size, 11);
        assert_ne!(file.entry.hardlink_group, 0);

        let link = entry_for(&tree, "sub/link.txt");
        assert_eq!(link.entry.file_kind, FILE_KIND_HARDLINK);
        assert_eq!(link.entry.hardlink_group, file.entry.hardlink_group);

        let symlink = entry_for(&tree, "sub/sym");
        assert_eq!(symlink.entry.file_kind, FILE_KIND_SYMLINK);
        assert_eq!(symlink.entry.link_target, b"hello.txt");

        let sparse = entry_for(&tree, "sparse.bin");
        assert_eq!(sparse.holes, vec![(0, 8 * 1024 * 1024)]);
        assert!(tree.total_bytes >= 11);
    }

    #[test]
    fn exclude_paths_are_not_walked() {
        let dir = temp();
        let root = dir.path().join("source");
        std::fs::create_dir_all(root.join("keep")).expect("dirs");
        std::fs::create_dir_all(root.join("skip")).expect("dirs");
        std::fs::write(root.join("keep/file"), b"a").expect("file");
        std::fs::write(root.join("skip/file"), b"b").expect("file");
        let options = WalkOptions {
            excludes: vec![root.join("skip").canonicalize().expect("canonical")],
            ..WalkOptions::with_default_excludes()
        };
        let tree = walk(&root, &options).expect("walk");
        assert!(tree.entries.iter().any(|e| e.entry.path == b"keep/file"));
        assert!(!tree.entries.iter().any(|e| e.entry.path == b"skip/file"));
        assert!(!tree.entries.iter().any(|e| e.entry.path == b"skip"));
    }

    #[test]
    fn a_restore_recreates_the_tree() {
        let dir = temp();
        let root = dir.path().join("source");
        let target = dir.path().join("target");
        std::fs::create_dir_all(root.join("sub")).expect("dirs");
        std::fs::write(root.join("sub/file.bin"), b"payload").expect("file");
        std::os::unix::fs::symlink("file.bin", root.join("sub/sym")).expect("symlink");
        let options = WalkOptions {
            excludes: Vec::new(),
            ..WalkOptions::with_default_excludes()
        };
        let tree = walk(&root, &options).expect("walk");
        std::fs::create_dir_all(&target).expect("target");
        let pinned = super::RestoreRoot::open(&target).expect("pin the target");

        let mut hardlinks: BTreeMap<u32, PathBuf> = BTreeMap::new();
        for walked in &tree.entries {
            if walked.entry.file_kind == FILE_KIND_HARDLINK
                && !hardlinks.contains_key(&walked.entry.hardlink_group)
            {
                continue;
            }
            let mut write =
                |file: &mut std::fs::File| file.write_all(b"payload").map_err(lr_core::Error::Io);
            restore_entry(
                &pinned,
                &walked.entry,
                &walked.holes,
                &hardlinks,
                &mut write,
            )
            .expect("restore");
            if walked.entry.file_kind == FILE_KIND_REGULAR {
                hardlinks.insert(
                    walked.entry.hardlink_group,
                    PathBuf::from(std::ffi::OsStr::from_bytes(&walked.entry.path)),
                );
            }
        }
        assert_eq!(
            std::fs::read(target.join("sub/file.bin")).expect("read"),
            b"payload"
        );
        assert_eq!(
            std::fs::read_link(target.join("sub/sym")).expect("readlink"),
            Path::new("file.bin")
        );
    }

    fn crafted(path: &str, file_kind: u8) -> FileEntry {
        FileEntry {
            file_kind,
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime_sec: 0,
            mtime_nsec: 0,
            size: 0,
            rdev: 0,
            hardlink_group: 0,
            link_target: Vec::new(),
            path: path.as_bytes().to_vec(),
            xattrs: Vec::new(),
            acl: Vec::new(),
            chunk_refs_total: 0,
            chunk_refs_here: Vec::new(),
        }
    }

    /// Crafted entries that try to leave the restore root are refused, and a
    /// sentinel outside it is untouched (R06).
    #[test]
    fn crafted_entries_cannot_leave_the_restore_root() {
        let dir = temp();
        let target = dir.path().join("target");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&target).expect("target");
        std::fs::create_dir_all(&outside).expect("outside");
        std::fs::write(outside.join("sentinel"), b"untouched").expect("sentinel");
        let pinned = super::RestoreRoot::open(&target).expect("pin");
        let hardlinks = BTreeMap::new();
        let mut write =
            |file: &mut std::fs::File| file.write_all(b"evil").map_err(lr_core::Error::Io);

        let absolute = format!("{}/sentinel", outside.display());
        for path in [
            "../outside/sentinel",
            absolute.as_str(),
            "a/../../outside/sentinel",
        ] {
            let entry = crafted(path, FILE_KIND_REGULAR);
            assert!(
                restore_entry(&pinned, &entry, &[], &hardlinks, &mut write).is_err(),
                "{path} must be refused"
            );
        }

        // A symlink restored by the image, then an entry below it.
        let mut link = crafted("link", FILE_KIND_SYMLINK);
        link.link_target = outside.as_os_str().as_bytes().to_vec();
        restore_entry(&pinned, &link, &[], &hardlinks, &mut write).expect("the symlink itself");
        let below = crafted("link/sentinel", FILE_KIND_REGULAR);
        assert!(
            restore_entry(&pinned, &below, &[], &hardlinks, &mut write).is_err(),
            "an entry below a symlink must be refused"
        );
        assert!(super::apply_metadata(&pinned, &below).is_err());

        assert_eq!(
            std::fs::read(outside.join("sentinel")).expect("sentinel"),
            b"untouched"
        );
        assert_eq!(std::fs::read_dir(&outside).expect("outside").count(), 1);
    }

    /// An ancestor swapped for a symlink, or a file swapped for another one,
    /// between the walk and the content pass is refused, and the content
    /// pass never reads the file outside the source (R14).
    #[test]
    fn the_content_pass_refuses_a_swapped_ancestor_or_file() {
        let dir = temp();
        let root = dir.path().join("source");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(root.join("sub")).expect("dirs");
        std::fs::write(root.join("sub/file"), b"walked").expect("file");
        std::fs::write(root.join("other"), b"walked").expect("file");
        std::fs::create_dir_all(&outside).expect("outside");
        std::fs::write(outside.join("file"), b"SECRET").expect("sentinel");
        let options = WalkOptions {
            excludes: Vec::new(),
            ..WalkOptions::with_default_excludes()
        };
        let tree = walk(&root, &options).expect("walk");
        let sub_file = entry_for(&tree, "sub/file").clone();
        let other = entry_for(&tree, "other").clone();
        assert!(tree.open_file(&sub_file).is_ok(), "unchanged files open");

        // The injected pause: the tree changes between walk and content.
        std::fs::rename(root.join("sub"), dir.path().join("moved")).expect("move");
        std::os::unix::fs::symlink(&outside, root.join("sub")).expect("symlink");
        // An atomic replacement, as editors do: the new file exists before
        // the old one goes, so it cannot reuse the old inode number.
        std::fs::write(root.join("other.new"), b"replacement").expect("new");
        std::fs::rename(root.join("other.new"), root.join("other")).expect("replace");

        // Opening by path with only a final O_NOFOLLOW, as the content pass
        // did before, reads the file outside the source.
        let mut leaked = String::new();
        std::io::Read::read_to_string(
            &mut super::open_nofollow(&root.join("sub/file")).expect("old open"),
            &mut leaked,
        )
        .expect("read");
        assert_eq!(leaked, "SECRET");

        let error = tree.open_file(&sub_file).expect_err("a symlinked ancestor");
        assert!(error.to_string().contains("was replaced"), "{error}");
        let error = tree.open_file(&other).expect_err("a different file");
        assert!(error.to_string().contains("different file"), "{error}");
    }

    #[test]
    fn deepest_first_puts_children_before_parents() {
        let entry = |path: &str| FileEntry {
            file_kind: FILE_KIND_DIRECTORY,
            mode: 0o755,
            uid: 0,
            gid: 0,
            mtime_sec: 0,
            mtime_nsec: 0,
            size: 0,
            rdev: 0,
            hardlink_group: 0,
            link_target: Vec::new(),
            path: path.as_bytes().to_vec(),
            xattrs: Vec::new(),
            acl: Vec::new(),
            chunk_refs_total: 0,
            chunk_refs_here: Vec::new(),
        };
        let entries = vec![entry("a"), entry("a/b"), entry("a/b/c")];
        let sorted = deepest_first(&entries);
        assert_eq!(sorted[0].path, b"a/b/c");
        assert_eq!(sorted[2].path, b"a");
    }

    #[test]
    fn special_files_are_recognised() {
        let dir = temp();
        let fifo = dir.path().join("pipe");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo");
        assert!(status.success());
        assert_eq!(
            std::fs::symlink_metadata(&fifo).expect("stat").mode() & 0o170000,
            libc::S_IFIFO
        );
        let options = WalkOptions {
            excludes: Vec::new(),
            ..WalkOptions::with_default_excludes()
        };
        let tree = walk(dir.path(), &options).expect("walk");
        let walked = entry_for(&tree, "pipe");
        assert_eq!(walked.entry.file_kind, FILE_KIND_SPECIAL);
    }
}
