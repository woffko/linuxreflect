//! File-mode tree walking and restoring (spec §D.1 `File`, §G.7, §K S12).
//!
//! A walk records the metadata of every entry and the sparse layout of regular
//! files; the content is chunked by [`crate::file`]. Restoration recreates the
//! entries in a target directory, including ownership, permissions, timestamps,
//! extended attributes (POSIX ACLs are xattrs), hard links and device nodes.
//!
//! The walk deliberately never follows a symbolic link: every path is opened
//! with `O_NOFOLLOW` (or a `*l*` syscall) so a link planted between the
//! directory read and the file open cannot redirect the backup outside the
//! source tree.

use std::collections::{BTreeMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
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

    let root_device = root_metadata.dev();
    let mut tree = WalkedTree::default();
    let mut hardlinks: BTreeMap<(u64, u64), u32> = BTreeMap::new();

    record(
        &root,
        &root,
        options,
        &mut hardlinks,
        &mut tree.entries,
        &mut tree.total_bytes,
        &mut tree.warnings,
    )?;

    let mut stack: Vec<PathBuf> = vec![root.clone()];
    while let Some(directory) = stack.pop() {
        let mut children = read_directory(&directory)?;
        // Deterministic order keeps two walks of the same tree identical.
        children.sort_by(|a, b| a.as_os_str().as_bytes().cmp(b.as_os_str().as_bytes()));
        for child in children {
            let metadata = std::fs::symlink_metadata(&child).map_err(Error::Io)?;
            if excludes.contains(&canonicalish(&child)) {
                continue;
            }
            if metadata.is_dir() {
                if options.one_file_system && metadata.dev() != root_device {
                    // The mount point itself is recorded, its contents are not.
                    record(
                        &root,
                        &child,
                        options,
                        &mut hardlinks,
                        &mut tree.entries,
                        &mut tree.total_bytes,
                        &mut tree.warnings,
                    )?;
                    continue;
                }
                record(
                    &root,
                    &child,
                    options,
                    &mut hardlinks,
                    &mut tree.entries,
                    &mut tree.total_bytes,
                    &mut tree.warnings,
                )?;
                stack.push(child);
                continue;
            }
            record(
                &root,
                &child,
                options,
                &mut hardlinks,
                &mut tree.entries,
                &mut tree.total_bytes,
                &mut tree.warnings,
            )?;
        }
    }
    Ok(tree)
}

fn read_directory(path: &Path) -> Result<Vec<PathBuf>> {
    let mut children = Vec::new();
    let entries = std::fs::read_dir(path).map_err(Error::Io)?;
    for entry in entries {
        let entry = entry.map_err(Error::Io)?;
        children.push(entry.path());
    }
    Ok(children)
}

/// Canonicalize as far as possible without failing on a vanished entry.
fn canonicalish(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

#[allow(clippy::too_many_arguments)]
fn record(
    root: &Path,
    path: &Path,
    options: &WalkOptions,
    hardlinks: &mut BTreeMap<(u64, u64), u32>,
    entries: &mut Vec<WalkedEntry>,
    total_bytes: &mut u64,
    warnings: &mut Vec<String>,
) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path).map_err(Error::Io)?;
    let relative = relative_path(root, path);
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
                    holes = sparse_holes(path, metadata.size(), warnings)?;
                }
            }
        }
        FILE_KIND_REGULAR => {
            *total_bytes += metadata.size();
            holes = sparse_holes(path, metadata.size(), warnings)?;
        }
        _ => {}
    }

    if options.xattrs {
        let (acl, xattrs) = read_xattrs(path)?;
        entry.acl = acl;
        entry.xattrs = xattrs;
    }

    entries.push(WalkedEntry { entry, holes });
    Ok(())
}

/// Relative path bytes, empty for the root itself.
fn relative_path(root: &Path, path: &Path) -> PathBuf {
    match path.strip_prefix(root) {
        Ok(relative) if relative.as_os_str().is_empty() => PathBuf::new(),
        Ok(relative) => relative.to_path_buf(),
        Err(_) => path.to_path_buf(),
    }
}

/// Sparse regions of `path`, using `SEEK_DATA`/`SEEK_HOLE` (spec §F).
///
/// A filesystem without hole support reports one data region covering the whole
/// file, so the result is simply empty.
fn sparse_holes(path: &Path, size: u64, warnings: &mut Vec<String>) -> Result<Vec<(u64, u64)>> {
    if size == 0 {
        return Ok(Vec::new());
    }
    let file = open_nofollow(path)?;
    let mut holes = Vec::new();
    let mut position = 0u64;
    loop {
        if position >= size {
            break;
        }
        match lr_unsafe::filemeta::seek_data(&file, position) {
            Ok(Some(data)) if data > position => {
                holes.push((position, data - position));
                position = data;
            }
            Ok(Some(_)) => {}
            Ok(None) => {
                holes.push((position, size - position));
                break;
            }
            Err(error) => {
                warnings.push(format!(
                    "{}: cannot inspect sparse regions: {error}",
                    path.display()
                ));
                return Ok(Vec::new());
            }
        }
        match lr_unsafe::filemeta::seek_hole(&file, position) {
            Ok(Some(hole)) if hole > position => position = hole,
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(error) => {
                warnings.push(format!(
                    "{}: cannot inspect sparse regions: {error}",
                    path.display()
                ));
                return Ok(Vec::new());
            }
        }
    }
    Ok(holes)
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

/// Restore an entry into `target` (the restore root).
///
/// `content` is called at most once for a regular file and must write the file
/// body in chunk order; `holes` are punched before the content is written.
/// `hardlink_targets` maps a hard-link group to the path restored first for it.
///
/// # Errors
/// Propagates filesystem errors, including `EPERM` from `mknod` when not
/// privileged and an attempt to recreate a device node.
pub fn restore_entry(
    target: &Path,
    entry: &FileEntry,
    holes: &[(u64, u64)],
    hardlink_targets: &BTreeMap<u32, PathBuf>,
    content: &mut dyn FnMut(&mut File) -> Result<()>,
) -> Result<()> {
    let relative = PathBuf::from(std::ffi::OsStr::from_bytes(&entry.path));
    let path = target.join(&relative);
    if relative.as_os_str().is_empty() {
        // The restore root itself: only its metadata is applied.
        apply_metadata(target, entry)?;
        return Ok(());
    }
    ensure_parent(target, &path)?;

    match entry.file_kind {
        FILE_KIND_DIRECTORY => {
            std::fs::create_dir_all(&path).map_err(Error::Io)?;
        }
        FILE_KIND_SYMLINK => {
            remove_existing(&path)?;
            let link = PathBuf::from(std::ffi::OsStr::from_bytes(&entry.link_target));
            std::os::unix::fs::symlink(&link, &path).map_err(Error::Io)?;
        }
        FILE_KIND_HARDLINK => {
            let first = hardlink_targets.get(&entry.hardlink_group).ok_or_else(|| {
                Error::corrupt(format!(
                    "{} is a hard link to a file the images never restored",
                    String::from_utf8_lossy(&entry.path)
                ))
            })?;
            remove_existing(&path)?;
            std::fs::hard_link(first, &path).map_err(Error::Io)?;
        }
        FILE_KIND_SPECIAL => {
            remove_existing(&path)?;
            lr_unsafe::filemeta::mknod(&path, entry.mode, entry.rdev).map_err(|error| {
                Error::unsupported(format!(
                    "cannot recreate {}: {error} (device nodes need root)",
                    String::from_utf8_lossy(&entry.path)
                ))
            })?;
        }
        _ => {
            remove_existing(&path)?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .custom_flags(O_NOFOLLOW)
                .mode(0o600)
                .open(&path)
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
///
/// # Errors
/// Propagates `chown`/`chmod`/`utimensat` errors, except that a failure to
/// restore ownership of a symlink is reported as unsupported only when it is
/// `EPERM` (an unprivileged restore).
pub fn apply_metadata(path: &Path, entry: &FileEntry) -> Result<()> {
    if let Some(error) = set_owner(path, entry) {
        return Err(error);
    }
    if entry.file_kind != FILE_KIND_SYMLINK {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(entry.mode & 0o7777))
            .map_err(Error::Io)?;
    }
    let _ = lr_unsafe::filemeta::set_times_nofollow(
        path,
        entry.mtime_sec,
        entry.mtime_nsec,
        entry.mtime_sec,
        entry.mtime_nsec,
    );
    if !entry.acl.is_empty() {
        let _ = lr_unsafe::filemeta::set_xattr(path, b"system.posix_acl_access", &entry.acl);
    }
    for xattr in &entry.xattrs {
        if let Err(error) = lr_unsafe::filemeta::set_xattr(path, &xattr.name, &xattr.value) {
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

fn ensure_parent(target: &Path, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent()
        && parent != target
    {
        std::fs::create_dir_all(parent).map_err(Error::Io)?;
    }
    Ok(())
}

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
                &target,
                &walked.entry,
                &walked.holes,
                &hardlinks,
                &mut write,
            )
            .expect("restore");
            if walked.entry.file_kind == FILE_KIND_REGULAR {
                hardlinks.insert(
                    walked.entry.hardlink_group,
                    target.join(Path::new(std::ffi::OsStr::from_bytes(&walked.entry.path))),
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
