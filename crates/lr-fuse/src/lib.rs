//! Read-only FUSE view of a file-mode image (spec §B, §K S12).
//!
//! The view exists so a backup can be inspected and verified without restoring
//! it: the spec's acceptance criterion is that `sha256sum` over the mounted
//! tree equals the checksum of the source file. Nothing here can write — every
//! mutating operation returns `EROFS`/`ENOSYS` — and the mount is created with
//! `MountOption::RO`.

use std::collections::{BTreeMap, HashMap};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use fuser::{
    Config, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo,
    LockOwner, MountOption, OpenFlags, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, ReplyOpen,
    ReplyXattr, Request,
};
use lr_core::{Error, Result};
use lr_engine::chain::OpenMember;
use lr_engine::file::read_records;
use lr_format::file_manifest::{
    FILE_KIND_DIRECTORY, FILE_KIND_HARDLINK, FILE_KIND_SPECIAL, FILE_KIND_SYMLINK, FileEntry,
};
use lr_format::{BlockEntry, StreamId};

/// Attribute cache lifetime; short, because a mount is read-only anyway.
pub const TTL: Duration = Duration::from_secs(1);

/// What `mount` needs.
pub struct FuseRequest {
    /// Destination URI the images live on.
    pub dest: String,
    /// Set name inside the destination.
    pub set: String,
    /// Images in chain order (`oldest` first).
    pub images: Vec<String>,
    /// How to reach the destination (paths, not secrets).
    pub destination_options: lr_store::DestinationOptions,
    /// How to unlock the images.
    pub encryption: lr_engine::Encryption,
    /// Directory to mount on.
    pub mountpoint: PathBuf,
}

/// Mount the image read-only and block until it is unmounted.
///
/// # Errors
/// Returns [`Error::Unsupported`] for a non-file chain and propagates mount and
/// image errors.
pub fn mount(request: &FuseRequest) -> Result<()> {
    let filesystem = ImageView::open(request)?;
    let config = mount_config();
    fuser::mount(filesystem, &request.mountpoint, &config)
        .map_err(|error| Error::unsupported(format!("mounting failed: {error}")))
}

/// Mount in a background thread; the returned session unmounts on drop.
///
/// # Errors
/// Returns [`Error::Unsupported`] for a non-file chain and mount errors.
pub fn spawn(request: &FuseRequest) -> Result<fuser::BackgroundSession> {
    let filesystem = ImageView::open(request)?;
    let config = mount_config();
    fuser::spawn_mount(filesystem, &request.mountpoint, &config)
        .map_err(|error| Error::unsupported(format!("mounting failed: {error}")))
}

fn mount_config() -> Config {
    let mut config = Config::default();
    config.mount_options = vec![
        MountOption::RO,
        MountOption::FSName("linuxreflect".to_owned()),
        MountOption::NoDev,
        MountOption::NoSuid,
        MountOption::DefaultPermissions,
    ];
    config.acl = fuser::SessionACL::Owner;
    config
}

/// One node of the in-memory tree.
struct Node {
    ino: u64,
    parent: u64,
    entry: FileEntry,
    /// Child name bytes → inode, sorted by name for a stable `readdir`.
    children: BTreeMap<Vec<u8>, u64>,
    /// Chunk references resolved on demand (regular files only).
    chunks: Vec<[u8; 32]>,
    /// Hard-link count: a shared inode counts every name.
    links: u32,
}

/// The mounted view: the tree plus everything needed to read chunk data.
struct ImageView {
    nodes: Vec<Node>,
    hash_index: HashMap<[u8; 32], BlockEntry>,
    members: Mutex<Vec<OpenMember>>,
    /// Whole-file content cache, keyed by inode.
    content: Mutex<HashMap<u64, Arc<Vec<u8>>>>,
}

impl ImageView {
    fn open(request: &FuseRequest) -> Result<Self> {
        let destination = lr_store::open(&request.dest, &request.destination_options)?;
        let set = destination.open_set(&lr_core::SetId::ZERO)?;
        let files = request
            .images
            .iter()
            .map(|name| {
                let member = lr_engine::chain::read_superblock(&*destination, &set, name)?;
                Ok(lr_engine::chain::ChainMemberFile {
                    file_name: name.clone(),
                    seq_in_chain: member.seq_in_chain,
                    image_uuid: member.image_uuid,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let mut members =
            lr_engine::chain::open_chain(&*destination, &set, &files, &request.encryption)?;
        // The newest member's manifest is the whole tree at its backup time;
        // older members only store chunks it references (D-108).
        let newest = members
            .iter()
            .map(|member| member.seq_in_chain)
            .max()
            .unwrap_or_default();
        let mut records: BTreeMap<Vec<u8>, (FileEntry, Vec<[u8; 32]>)> = BTreeMap::new();
        let mut hash_index = HashMap::new();
        for member in &mut members {
            if member.seq_in_chain == newest {
                for record in read_records(member)? {
                    records.insert(
                        record.entry.path.clone(),
                        (record.entry.clone(), record.entry.chunk_refs_here.clone()),
                    );
                }
            }
            let bytes = member.stream_bytes(StreamId::HashIndex)?;
            let mut cursor = std::io::Cursor::new(bytes.as_slice());
            while (cursor.position() as usize) < bytes.len() {
                let mut wire = lr_format::wire::Reader::new(&mut cursor);
                let entry = BlockEntry::read(&mut wire)?;
                if entry.state == lr_format::manifest::STATE_STORED {
                    hash_index.insert(entry.hash, entry);
                }
            }
        }

        let mut nodes = vec![Node {
            ino: 1,
            parent: 1,
            entry: root_entry(&records),
            children: BTreeMap::new(),
            chunks: Vec::new(),
            links: 1,
        }];
        let mut index: HashMap<Vec<u8>, u64> = HashMap::new();
        index.insert(Vec::new(), 1);
        // Parents come before children in the manifest, so one pass suffices;
        // `create_dir_all` semantics are not needed because a directory entry
        // always precedes the entries below it.
        let mut hardlinks: Vec<(Vec<u8>, u32)> = Vec::new();
        for (path, (entry, chunks)) in &records {
            if path.is_empty() {
                continue;
            }
            if entry.file_kind == FILE_KIND_HARDLINK {
                // A hard link shares the regular file's inode, and the regular
                // file may come later in the manifest, so the name is attached
                // once every node exists.
                hardlinks.push((path.clone(), entry.hardlink_group));
                continue;
            }
            let ino = nodes.len() as u64 + 1;
            let parent_path = parent_of(path);
            let parent = *index.get(&parent_path).ok_or_else(|| {
                Error::corrupt(format!(
                    "{} has no parent entry in the image",
                    String::from_utf8_lossy(path)
                ))
            })?;
            index.insert(path.clone(), ino);
            nodes.push(Node {
                ino,
                parent,
                entry: entry.clone(),
                children: BTreeMap::new(),
                chunks: chunks.clone(),
                links: 1,
            });
            if let Some(parent_node) = nodes.get_mut((parent - 1) as usize) {
                parent_node.children.insert(file_name_of(path), ino);
            }
        }
        let mut group_ino: HashMap<u32, u64> = HashMap::new();
        for (path, (entry, _)) in &records {
            if entry.file_kind != FILE_KIND_HARDLINK
                && entry.hardlink_group != 0
                && let Some(ino) = index.get(path)
            {
                group_ino.insert(entry.hardlink_group, *ino);
            }
        }
        for (path, group) in hardlinks {
            let target = *group_ino.get(&group).ok_or_else(|| {
                Error::corrupt(format!(
                    "{} is a hard link to a file the image does not contain",
                    String::from_utf8_lossy(&path)
                ))
            })?;
            let parent_path = parent_of(&path);
            let parent = *index.get(&parent_path).ok_or_else(|| {
                Error::corrupt(format!(
                    "{} has no parent entry in the image",
                    String::from_utf8_lossy(&path)
                ))
            })?;
            if let Some(node) = nodes.get_mut((target - 1) as usize) {
                node.links += 1;
            }
            if let Some(parent_node) = nodes.get_mut((parent - 1) as usize) {
                parent_node.children.insert(file_name_of(&path), target);
            }
        }
        Ok(Self {
            nodes,
            hash_index,
            members: Mutex::new(members),
            content: Mutex::new(HashMap::new()),
        })
    }

    fn node(&self, ino: u64) -> Option<&Node> {
        (ino >= 1)
            .then(|| self.nodes.get((ino - 1) as usize))
            .flatten()
    }

    fn attr(&self, node: &Node) -> FileAttr {
        let entry = &node.entry;
        let kind = match entry.file_kind {
            FILE_KIND_DIRECTORY => FileType::Directory,
            FILE_KIND_SYMLINK => FileType::Symlink,
            FILE_KIND_SPECIAL => match entry.mode & 0o170000 {
                0o010000 => FileType::NamedPipe,
                0o020000 => FileType::CharDevice,
                0o060000 => FileType::BlockDevice,
                0o140000 => FileType::Socket,
                _ => FileType::RegularFile,
            },
            _ => FileType::RegularFile,
        };
        let mtime = SystemTime::UNIX_EPOCH
            + Duration::new(
                entry.mtime_sec.max(0) as u64,
                entry.mtime_nsec.min(999_999_999),
            );
        FileAttr {
            ino: INodeNo(node.ino),
            size: entry.size,
            blocks: entry.size.div_ceil(512),
            atime: mtime,
            mtime,
            ctime: mtime,
            crtime: mtime,
            kind,
            perm: (entry.mode & 0o7777) as u16,
            nlink: if entry.file_kind == FILE_KIND_DIRECTORY {
                2
            } else {
                node.links
            },
            uid: entry.uid,
            gid: entry.gid,
            rdev: entry.rdev as u32,
            blksize: 4096,
            flags: 0,
        }
    }

    /// The whole content of a regular file, decoded from the chain once.
    fn content_of(&self, ino: u64) -> Result<Arc<Vec<u8>>> {
        if let Some(cached) = self.content.lock().expect("content lock").get(&ino) {
            return Ok(Arc::clone(cached));
        }
        let node = self
            .node(ino)
            .ok_or_else(|| Error::corrupt(format!("inode {ino} does not exist")))?;
        let mut bytes = Vec::with_capacity(node.entry.size as usize);
        let mut members = self.members.lock().expect("member lock");
        for hash in &node.chunks {
            let entry = self.hash_index.get(hash).ok_or_else(|| {
                Error::corrupt(format!(
                    "{} references a chunk no member stores",
                    String::from_utf8_lossy(&node.entry.path)
                ))
            })?;
            let member = members.get_mut(entry.member as usize).ok_or_else(|| {
                Error::corrupt(format!(
                    "a chunk names chain member {}, which does not exist",
                    entry.member
                ))
            })?;
            bytes.extend_from_slice(&member.chunk_plaintext(entry, 512 * 1024)?);
        }
        bytes.truncate(node.entry.size as usize);
        let bytes = Arc::new(bytes);
        self.content
            .lock()
            .expect("content lock")
            .insert(ino, Arc::clone(&bytes));
        Ok(bytes)
    }
}

fn root_entry(records: &BTreeMap<Vec<u8>, (FileEntry, Vec<[u8; 32]>)>) -> FileEntry {
    records.get(&Vec::new()).map_or_else(
        || FileEntry {
            file_kind: FILE_KIND_DIRECTORY,
            mode: 0o040755,
            uid: 0,
            gid: 0,
            mtime_sec: 0,
            mtime_nsec: 0,
            size: 0,
            rdev: 0,
            hardlink_group: 0,
            link_target: Vec::new(),
            path: Vec::new(),
            xattrs: Vec::new(),
            acl: Vec::new(),
            chunk_refs_total: 0,
            chunk_refs_here: Vec::new(),
        },
        |(entry, _)| entry.clone(),
    )
}

fn parent_of(path: &[u8]) -> Vec<u8> {
    match path.iter().rposition(|byte| *byte == b'/') {
        Some(index) => path[..index].to_vec(),
        None => Vec::new(),
    }
}

fn file_name_of(path: &[u8]) -> Vec<u8> {
    match path.iter().rposition(|byte| *byte == b'/') {
        Some(index) => path[index + 1..].to_vec(),
        None => path.to_vec(),
    }
}

impl Filesystem for ImageView {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        use std::os::unix::ffi::OsStrExt;
        let Some(node) = self.node(parent.0) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let Some(ino) = node.children.get(name.as_bytes()) else {
            reply.error(Errno::ENOENT);
            return;
        };
        match self.node(*ino) {
            Some(child) => reply.entry(&TTL, &self.attr(child), Generation(0)),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match self.node(ino.0) {
            Some(node) => reply.attr(&TTL, &self.attr(node)),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        match self.node(ino.0) {
            Some(node) if node.entry.file_kind == FILE_KIND_SYMLINK => {
                reply.data(&node.entry.link_target);
            }
            Some(_) => reply.error(Errno::EINVAL),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        use fuser::OpenAccMode;
        if flags.acc_mode() != OpenAccMode::O_RDONLY {
            // The view is read-only by contract; the mount is also `RO`.
            reply.error(Errno::EROFS);
            return;
        }
        match self.node(ino.0) {
            Some(node) if node.entry.file_kind == FILE_KIND_DIRECTORY => {
                reply.error(Errno::EISDIR);
            }
            Some(_) => reply.opened(FileHandle(0), FopenFlags::empty()),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        match self.content_of(ino.0) {
            Ok(bytes) => {
                let start = (offset as usize).min(bytes.len());
                let end = start.saturating_add(size as usize).min(bytes.len());
                reply.data(&bytes[start..end]);
            }
            Err(error) => {
                tracing::warn!(%error, "read from the image view failed");
                reply.error(Errno::EIO);
            }
        }
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: LockOwner,
        reply: fuser::ReplyEmpty,
    ) {
        // Nothing is buffered: every read goes to the image.
        reply.ok();
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: fuser::ReplyEmpty,
    ) {
        reply.ok();
    }

    fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        match self.node(ino.0) {
            Some(node) if node.entry.file_kind == FILE_KIND_DIRECTORY => {
                reply.opened(FileHandle(0), FopenFlags::empty());
            }
            Some(_) => reply.error(Errno::ENOTDIR),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn releasedir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _flags: OpenFlags,
        reply: fuser::ReplyEmpty,
    ) {
        reply.ok();
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let Some(node) = self.node(ino.0) else {
            reply.error(Errno::ENOENT);
            return;
        };
        if node.entry.file_kind != FILE_KIND_DIRECTORY {
            reply.error(Errno::ENOTDIR);
            return;
        }
        let mut entries: Vec<(u64, FileType, Vec<u8>)> = vec![
            (node.ino, FileType::Directory, b".".to_vec()),
            (node.parent, FileType::Directory, b"..".to_vec()),
        ];
        for (name, child_ino) in &node.children {
            if let Some(child) = self.node(*child_ino) {
                entries.push((*child_ino, self.attr(child).kind, name.clone()));
            }
        }
        for (index, (child_ino, kind, name)) in entries.iter().enumerate().skip(offset as usize) {
            let full = reply.add(
                INodeNo(*child_ino),
                (index + 1) as u64,
                *kind,
                OsStr::from_bytes(name),
            );
            if full {
                break;
            }
        }
        reply.ok();
    }

    fn listxattr(&self, _req: &Request, ino: INodeNo, size: u32, reply: ReplyXattr) {
        let Some(node) = self.node(ino.0) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let mut names = Vec::new();
        if !node.entry.acl.is_empty() {
            names.extend_from_slice(b"system.posix_acl_access\0");
        }
        for xattr in &node.entry.xattrs {
            names.extend_from_slice(&xattr.name);
            names.push(0);
        }
        reply_xattr(reply, &names, size);
    }

    fn getxattr(&self, _req: &Request, ino: INodeNo, name: &OsStr, size: u32, reply: ReplyXattr) {
        use std::os::unix::ffi::OsStrExt;
        let Some(node) = self.node(ino.0) else {
            reply.error(Errno::ENOENT);
            return;
        };
        if name.as_bytes() == b"system.posix_acl_access" {
            reply_xattr(reply, &node.entry.acl, size);
            return;
        }
        match node
            .entry
            .xattrs
            .iter()
            .find(|xattr| xattr.name == name.as_bytes())
        {
            Some(xattr) => reply_xattr(reply, &xattr.value, size),
            None => reply.error(Errno::ENODATA),
        }
    }
}

fn reply_xattr(reply: ReplyXattr, value: &[u8], size: u32) {
    if size == 0 {
        match u32::try_from(value.len()) {
            Ok(len) => reply.size(len),
            Err(_) => reply.error(Errno::ERANGE),
        }
    } else if value.len() <= size as usize {
        reply.data(value);
    } else {
        reply.error(Errno::ERANGE);
    }
}
