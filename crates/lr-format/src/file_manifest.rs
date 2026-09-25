//! File-mode manifest records (spec §G.7, `docs/format-lrimg-v1.md` §5.4).
//!
//! A file entry keeps a fixed-size header so a reader can index it cheaply,
//! and pushes its ordered chunk references into the stream: the header carries
//! `chunk_refs_total`, the first section carries as many 32-byte hashes as fit,
//! and continuation sections carry the rest. A 1 TB file therefore never
//! produces a single multi-hundred-megabyte record.

use lr_core::{Error, Result};

use crate::manifest::{
    MANIFEST_VER, SECTION_FILE_CONTINUATION, SECTION_FILE_ENTRY, SECTION_FILE_HOLES,
};
use crate::wire::{self, ByteSink, ByteSource, Reader};

/// A regular file.
pub const FILE_KIND_REGULAR: u8 = 1;
/// A directory.
pub const FILE_KIND_DIRECTORY: u8 = 2;
/// A symbolic link.
pub const FILE_KIND_SYMLINK: u8 = 3;
/// A hard link to a previously recorded file (same `hardlink_group`).
pub const FILE_KIND_HARDLINK: u8 = 4;
/// A device node, FIFO or socket.
pub const FILE_KIND_SPECIAL: u8 = 5;

/// One extended attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xattr {
    /// Attribute name.
    pub name: Vec<u8>,
    /// Attribute value.
    pub value: Vec<u8>,
}

/// One file-system entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    /// One of the `FILE_KIND_*` constants.
    pub file_kind: u8,
    /// Permission and type bits.
    pub mode: u32,
    /// Owner uid.
    pub uid: u32,
    /// Owner gid.
    pub gid: u32,
    /// Modification time, seconds since the epoch.
    pub mtime_sec: i64,
    /// Modification time, nanoseconds.
    pub mtime_nsec: u32,
    /// File size in bytes.
    pub size: u64,
    /// Device number (`st_rdev`) for device nodes, 0 otherwise.
    pub rdev: u64,
    /// Hard-link group; 0 means "not part of a group".
    pub hardlink_group: u32,
    /// Symlink target, empty for other kinds.
    pub link_target: Vec<u8>,
    /// Path relative to the restore root.
    pub path: Vec<u8>,
    /// Extended attributes.
    pub xattrs: Vec<Xattr>,
    /// Raw POSIX ACL blob.
    pub acl: Vec<u8>,
    /// Total chunk references for this file, across all sections.
    pub chunk_refs_total: u64,
    /// Chunk references carried by this first section.
    pub chunk_refs_here: Vec<[u8; 32]>,
}

impl FileEntry {
    /// Write this entry as a section 4 record.
    ///
    /// # Errors
    /// Returns [`Error::Unsupported`] for oversized fields and propagates sink
    /// errors.
    pub fn write(&self, out: &mut impl ByteSink) -> Result<()> {
        if self.file_kind < FILE_KIND_REGULAR || self.file_kind > FILE_KIND_SPECIAL {
            return Err(Error::corrupt(format!(
                "unknown file kind {}",
                self.file_kind
            )));
        }
        wire::put_u16(out, MANIFEST_VER)?;
        wire::put_u8(out, SECTION_FILE_ENTRY)?;
        wire::put_u8(out, 0)?;
        wire::put_u64(out, self.chunk_refs_total)?;
        wire::put_u8(out, self.file_kind)?;
        wire::put_u32(out, self.mode)?;
        wire::put_u32(out, self.uid)?;
        wire::put_u32(out, self.gid)?;
        wire::put_i64(out, self.mtime_sec)?;
        wire::put_u32(out, self.mtime_nsec)?;
        wire::put_u64(out, self.size)?;
        wire::put_u64(out, self.rdev)?;
        wire::put_u32(out, self.hardlink_group)?;
        wire::put_u32_prefixed(out, &self.link_target)?;
        wire::put_u16_prefixed(out, &self.path)?;
        wire::put_u32(out, u32::try_from(self.xattrs.len()).unwrap_or(u32::MAX))?;
        wire::put_u32_prefixed(out, &self.acl)?;
        wire::put_u64(out, self.chunk_refs_here.len() as u64)?;
        for xattr in &self.xattrs {
            wire::put_u16_prefixed(out, &xattr.name)?;
            wire::put_u16_prefixed(out, &xattr.value)?;
        }
        for hash in &self.chunk_refs_here {
            out.write_bytes(hash)?;
        }
        Ok(())
    }

    /// Read a section 4 record, header included.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] for a wrong version or section kind, invalid
    /// UTF-8-independent field sizes, or truncation.
    pub fn read<S: ByteSource>(reader: &mut Reader<S>) -> Result<Self> {
        let ver = reader.u16()?;
        if ver != MANIFEST_VER {
            return Err(Error::corrupt(format!("manifest version {ver}")));
        }
        let kind = reader.u8()?;
        if kind != SECTION_FILE_ENTRY {
            return Err(Error::corrupt(format!("expected a file entry, got {kind}")));
        }
        let _reserved = reader.u8()?;
        Self::read_body(reader)
    }

    /// Read the fields after the four-byte section header.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] for an unknown file kind or truncation.
    pub fn read_body<S: ByteSource>(reader: &mut Reader<S>) -> Result<Self> {
        let chunk_refs_total = reader.u64()?;
        let file_kind = reader.u8()?;
        if !(FILE_KIND_REGULAR..=FILE_KIND_SPECIAL).contains(&file_kind) {
            return Err(Error::corrupt(format!("unknown file kind {file_kind}")));
        }
        let mode = reader.u32()?;
        let uid = reader.u32()?;
        let gid = reader.u32()?;
        let mtime_sec = reader.i64()?;
        let mtime_nsec = reader.u32()?;
        let size = reader.u64()?;
        let rdev = reader.u64()?;
        let hardlink_group = reader.u32()?;
        let link_target = reader.u32_prefixed()?;
        let path = reader.u16_prefixed()?;
        let xattr_count = reader.u32()? as usize;
        let acl = reader.u32_prefixed()?;
        let refs_here = reader.u64()? as usize;
        let mut xattrs = Vec::with_capacity(xattr_count.min(1024));
        for _ in 0..xattr_count {
            xattrs.push(Xattr {
                name: reader.u16_prefixed()?,
                value: reader.u16_prefixed()?,
            });
        }
        let mut chunk_refs_here = Vec::with_capacity(refs_here.min(1 << 20));
        for _ in 0..refs_here {
            chunk_refs_here.push(reader.array::<32>()?);
        }
        if refs_here as u64 > chunk_refs_total {
            return Err(Error::corrupt(
                "file entry carries more references than it declares",
            ));
        }
        Ok(Self {
            file_kind,
            mode,
            uid,
            gid,
            mtime_sec,
            mtime_nsec,
            size,
            rdev,
            hardlink_group,
            link_target,
            path,
            xattrs,
            acl,
            chunk_refs_total,
            chunk_refs_here,
        })
    }
}

/// One file-manifest record: the entry plus the sparse regions of its file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRecord {
    /// Metadata and chunk references.
    pub entry: FileEntry,
    /// Sparse regions as `(offset, length)`; empty when the file is dense.
    pub holes: Vec<(u64, u64)>,
}

/// Write one record: the entry, its continuations and its hole section.
///
/// # Errors
/// Returns [`Error::Unsupported`] for oversized fields and propagates sink
/// errors.
pub fn write_record(out: &mut impl ByteSink, record: &FileRecord) -> Result<()> {
    let refs = &record.entry.chunk_refs_here;
    let total = record.entry.chunk_refs_total;
    if refs.len() as u64 > total {
        return Err(Error::corrupt(
            "a file entry carries more references than it declares",
        ));
    }
    record.entry.write(out)?;
    let mut written = refs.len();
    let mut index = refs.len();
    while (written as u64) < total {
        let end = (index + FILE_REFS_PER_SECTION).min(refs.len());
        if end <= index {
            return Err(Error::corrupt(
                "a file entry declares more references than it carries",
            ));
        }
        write_continuation(out, &refs[index..end])?;
        written += end - index;
        index = end;
    }
    if !record.holes.is_empty() {
        write_holes(out, &record.holes)?;
    }
    Ok(())
}

/// How many chunk references one file-entry section carries inline.
///
/// Larger file bodies continue in `SECTION_FILE_CONTINUATION` sections, so one
/// section never grows with the file size (spec §G.7).
pub const FILE_REFS_PER_SECTION: usize = 4096;

/// Parse a whole file manifest into records.
///
/// The buffer is what [`crate::stream::PageStream`] produced for
/// [`crate::StreamId::Manifest`]; it is already in memory because it is small
/// next to the file contents.
///
/// # Errors
/// Returns [`Error::Corrupt`] for an unknown section kind, a hole section that
/// does not follow an entry, or truncated data.
pub fn read_manifest(bytes: &[u8]) -> Result<Vec<FileRecord>> {
    let mut records: Vec<FileRecord> = Vec::new();
    let mut cursor = std::io::Cursor::new(bytes);
    while (cursor.position() as usize) < bytes.len() {
        let mut reader = Reader::new(&mut cursor);
        let ver = reader.u16()?;
        if ver != MANIFEST_VER {
            return Err(Error::corrupt(format!("manifest version {ver}")));
        }
        let kind = reader.u8()?;
        let _reserved = reader.u8()?;
        match kind {
            SECTION_FILE_ENTRY => {
                let entry = FileEntry::read_body(&mut reader)?;
                let mut refs = entry.chunk_refs_here.clone();
                while (refs.len() as u64) < entry.chunk_refs_total {
                    let ver = reader.u16()?;
                    if ver != MANIFEST_VER {
                        return Err(Error::corrupt(format!("manifest version {ver}")));
                    }
                    let kind = reader.u8()?;
                    if kind != SECTION_FILE_CONTINUATION {
                        return Err(Error::corrupt(format!(
                            "expected a continuation, got {kind}"
                        )));
                    }
                    let _reserved = reader.u8()?;
                    let count = reader.u64()? as usize;
                    if count == 0 {
                        return Err(Error::corrupt("an empty continuation section"));
                    }
                    for _ in 0..count {
                        refs.push(reader.array::<32>()?);
                    }
                }
                if refs.len() as u64 > entry.chunk_refs_total {
                    return Err(Error::corrupt(
                        "continuations carry more references than the entry declares",
                    ));
                }
                records.push(FileRecord {
                    entry: FileEntry {
                        chunk_refs_here: refs,
                        ..entry
                    },
                    holes: Vec::new(),
                });
            }
            SECTION_FILE_HOLES => {
                let count = reader.u64()? as usize;
                let record = records
                    .last_mut()
                    .ok_or_else(|| Error::corrupt("a hole section without a file entry"))?;
                for _ in 0..count {
                    let offset = reader.u64()?;
                    let len = reader.u64()?;
                    record.holes.push((offset, len));
                }
            }
            other => {
                return Err(Error::corrupt(format!(
                    "unknown file manifest section {other}"
                )));
            }
        }
    }
    Ok(records)
}

/// Write a continuation section holding the remaining chunk references.
///
/// # Errors
/// Propagates sink errors.
pub fn write_continuation(out: &mut impl ByteSink, hashes: &[[u8; 32]]) -> Result<()> {
    wire::put_u16(out, MANIFEST_VER)?;
    wire::put_u8(out, SECTION_FILE_CONTINUATION)?;
    wire::put_u8(out, 0)?;
    wire::put_u64(out, hashes.len() as u64)?;
    for hash in hashes {
        out.write_bytes(hash)?;
    }
    Ok(())
}

/// Read a continuation section.
///
/// # Errors
/// Returns [`Error::Corrupt`] for a wrong version or section kind.
pub fn read_continuation<S: ByteSource>(reader: &mut Reader<S>) -> Result<Vec<[u8; 32]>> {
    let ver = reader.u16()?;
    if ver != MANIFEST_VER {
        return Err(Error::corrupt(format!("manifest version {ver}")));
    }
    let kind = reader.u8()?;
    if kind != SECTION_FILE_CONTINUATION {
        return Err(Error::corrupt(format!(
            "expected a continuation, got {kind}"
        )));
    }
    let _reserved = reader.u8()?;
    let count = reader.u64()? as usize;
    let mut hashes = Vec::with_capacity(count.min(1 << 20));
    for _ in 0..count {
        hashes.push(reader.array::<32>()?);
    }
    Ok(hashes)
}

/// Read a file entry plus every continuation that follows it.
///
/// # Errors
/// Returns [`Error::Corrupt`] when the continuations do not add up to
/// `chunk_refs_total`.
pub fn read_entry_with_continuations<S: ByteSource>(
    reader: &mut Reader<S>,
) -> Result<(FileEntry, Vec<[u8; 32]>)> {
    let entry = FileEntry::read(reader)?;
    let mut refs = entry.chunk_refs_here.clone();
    while (refs.len() as u64) < entry.chunk_refs_total {
        refs.extend(read_continuation(reader)?);
    }
    if refs.len() as u64 > entry.chunk_refs_total {
        return Err(Error::corrupt(
            "continuations carry more chunk references than the entry declares",
        ));
    }
    Ok((entry, refs))
}

/// Write the sparse regions of the file entry that precedes this section.
///
/// # Errors
/// Propagates sink errors.
pub fn write_holes(out: &mut impl ByteSink, holes: &[(u64, u64)]) -> Result<()> {
    wire::put_u16(out, MANIFEST_VER)?;
    wire::put_u8(out, SECTION_FILE_HOLES)?;
    wire::put_u8(out, 0)?;
    wire::put_u64(out, holes.len() as u64)?;
    for (offset, len) in holes {
        wire::put_u64(out, *offset)?;
        wire::put_u64(out, *len)?;
    }
    Ok(())
}

/// Read a sparse-region section.
///
/// # Errors
/// Returns [`Error::Corrupt`] for a wrong version or section kind.
pub fn read_holes<S: ByteSource>(reader: &mut Reader<S>) -> Result<Vec<(u64, u64)>> {
    let ver = reader.u16()?;
    if ver != MANIFEST_VER {
        return Err(Error::corrupt(format!("manifest version {ver}")));
    }
    let kind = reader.u8()?;
    if kind != SECTION_FILE_HOLES {
        return Err(Error::corrupt(format!(
            "expected a hole section, got {kind}"
        )));
    }
    let _reserved = reader.u8()?;
    let count = reader.u64()? as usize;
    let mut holes = Vec::with_capacity(count.min(1 << 20));
    for _ in 0..count {
        let offset = reader.u64()?;
        let len = reader.u64()?;
        holes.push((offset, len));
    }
    Ok(holes)
}

#[cfg(test)]
mod tests {
    use super::{
        FILE_KIND_REGULAR, FILE_KIND_SYMLINK, FileEntry, Xattr, read_continuation,
        read_entry_with_continuations, read_holes, write_continuation, write_holes,
    };
    use crate::wire::Reader;
    use std::io::Cursor;

    fn sample(refs: usize) -> FileEntry {
        FileEntry {
            file_kind: FILE_KIND_REGULAR,
            mode: 0o644,
            uid: 1000,
            gid: 1000,
            mtime_sec: 1_800_000_000,
            mtime_nsec: 123_456_789,
            size: 12_345_678,
            rdev: 0,
            hardlink_group: 0,
            link_target: Vec::new(),
            path: b"home/user/file.bin".to_vec(),
            xattrs: vec![Xattr {
                name: b"user.comment".to_vec(),
                value: b"hello".to_vec(),
            }],
            acl: vec![1, 2, 3, 4],
            chunk_refs_total: refs as u64,
            chunk_refs_here: (0..refs.min(2)).map(|i| [i as u8; 32]).collect(),
        }
    }

    #[test]
    fn a_small_file_entry_round_trips() {
        let entry = sample(2);
        let mut bytes = Vec::new();
        entry.write(&mut bytes).expect("write");
        let mut reader = Reader::new(Cursor::new(bytes));
        let (decoded, refs) = read_entry_with_continuations(&mut reader).expect("read");
        assert_eq!(decoded, entry);
        assert_eq!(refs, entry.chunk_refs_here);
    }

    #[test]
    fn large_files_use_continuations() {
        let mut entry = sample(2);
        entry.chunk_refs_total = 5;
        let mut bytes = Vec::new();
        entry.write(&mut bytes).expect("write");
        write_continuation(&mut bytes, &[[0xAA; 32], [0xBB; 32], [0xCC; 32]])
            .expect("continuation");

        let mut reader = Reader::new(Cursor::new(bytes));
        let (decoded, refs) = read_entry_with_continuations(&mut reader).expect("read");
        assert_eq!(decoded.chunk_refs_total, 5);
        assert_eq!(refs.len(), 5);
        assert_eq!(refs[2], [0xAA; 32]);
        assert_eq!(refs[4], [0xCC; 32]);
    }

    #[test]
    fn a_short_file_is_rejected() {
        let mut entry = sample(1);
        entry.chunk_refs_total = 4;
        let mut bytes = Vec::new();
        entry.write(&mut bytes).expect("write");
        write_continuation(&mut bytes, &[[0xAA; 32]]).expect("continuation");
        let mut reader = Reader::new(Cursor::new(bytes));
        assert!(read_entry_with_continuations(&mut reader).is_err());
    }

    #[test]
    fn symlinks_round_trip() {
        let entry = FileEntry {
            file_kind: FILE_KIND_SYMLINK,
            link_target: b"../target".to_vec(),
            chunk_refs_total: 0,
            chunk_refs_here: Vec::new(),
            ..sample(0)
        };
        let mut bytes = Vec::new();
        entry.write(&mut bytes).expect("write");
        let mut reader = Reader::new(Cursor::new(bytes));
        let (decoded, refs) = read_entry_with_continuations(&mut reader).expect("read");
        assert_eq!(decoded, entry);
        assert!(refs.is_empty());
    }

    #[test]
    fn records_round_trip_with_continuations_and_holes() {
        let mut entry = sample(2);
        entry.chunk_refs_total = 5000;
        entry.chunk_refs_here = (0..5000u32).map(|i| [(i % 251) as u8; 32]).collect();
        let record = super::FileRecord {
            entry: entry.clone(),
            holes: vec![(0, 4096), (1 << 20, 1 << 19)],
        };
        let mut bytes: Vec<u8> = Vec::new();
        super::write_record(&mut bytes, &record).expect("write");
        let parsed = super::read_manifest(&bytes).expect("read");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].entry.chunk_refs_here.len(), 5000);
        assert_eq!(parsed[0].entry, entry);
        assert_eq!(parsed[0].holes, record.holes);
    }

    #[test]
    fn several_records_parse_in_order() {
        let mut bytes: Vec<u8> = Vec::new();
        for index in 0..3u8 {
            let mut entry = sample(1);
            entry.path = vec![b'a' + index];
            let record = super::FileRecord {
                entry,
                holes: Vec::new(),
            };
            super::write_record(&mut bytes, &record).expect("write");
        }
        let parsed = super::read_manifest(&bytes).expect("read");
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[2].entry.path, b"c");
    }

    #[test]
    fn hole_sections_round_trip() {
        let holes = vec![(0u64, 4096u64), (1 << 20, 1 << 19)];
        let mut bytes = Vec::new();
        write_holes(&mut bytes, &holes).expect("write");
        let mut reader = Reader::new(Cursor::new(bytes));
        assert_eq!(read_holes(&mut reader).expect("read"), holes);
    }

    #[test]
    fn unknown_file_kinds_are_refused() {
        let mut entry = sample(0);
        entry.file_kind = 9;
        let mut bytes = Vec::new();
        assert!(entry.write(&mut bytes).is_err());

        entry.file_kind = FILE_KIND_REGULAR;
        let mut bytes = Vec::new();
        entry.write(&mut bytes).expect("write");
        bytes[5] = 9; // section kind byte is at 2; file kind sits later
        let mut reader = Reader::new(Cursor::new(bytes.clone()));
        assert!(read_continuation(&mut reader).is_err());
    }
}
