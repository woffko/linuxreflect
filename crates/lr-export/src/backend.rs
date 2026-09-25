//! Byte-addressable read-only views of what an export serves (spec §K S13).
//!
//! Two backends exist: a plain file (used by the protocol tests and by
//! `export mount --raw`), and an `.lrimg` chain. The image backend builds a
//! sparse index of *stored* chunks by walking the chain once, so a read is a
//! binary search plus one chunk decode instead of a full manifest scan; chunks
//! that are unused or recorded as zero are served without touching the image.

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Mutex;

use lr_core::{Error, ImageKind, Result};
use lr_engine::chain::{ChainWalk, OpenMember};
use lr_format::manifest::ChunkState;
use lr_format::{BlockEntry, BlockManifestHeader, StreamId, wire};

/// A read-only, randomly addressable block device.
pub trait BlockBackend: Send + Sync {
    /// Export size in bytes.
    fn size_bytes(&self) -> u64;
    /// Logical block size the export advertises.
    fn block_size(&self) -> u32 {
        512
    }
    /// Fill `buffer` from `offset`.
    ///
    /// # Errors
    /// Returns the backend's error; the NBD layer turns it into an error reply.
    fn read_at(&self, offset: u64, buffer: &mut [u8]) -> Result<()>;
}

/// A plain file served verbatim.
pub struct FileBackend {
    file: Mutex<std::fs::File>,
    size: u64,
}

impl FileBackend {
    /// Open a file read-only.
    ///
    /// # Errors
    /// Returns the underlying I/O error.
    pub fn open(path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path).map_err(Error::Io)?;
        let size = file.metadata().map_err(Error::Io)?.len();
        Ok(Self {
            file: Mutex::new(file),
            size,
        })
    }
}

impl BlockBackend for FileBackend {
    fn size_bytes(&self) -> u64 {
        self.size
    }

    fn read_at(&self, offset: u64, buffer: &mut [u8]) -> Result<()> {
        let mut file = self.file.lock().expect("file lock");
        file.seek(SeekFrom::Start(offset)).map_err(Error::Io)?;
        file.read_exact(buffer).map_err(Error::Io)
    }
}

/// One chunk of the merged chain state, as the export needs it.
#[derive(Debug, Clone)]
enum ChunkSlot {
    /// The chunk is all zeroes.
    Zero,
    /// The chunk is unreadable and was recorded as a bad sector.
    BadSector,
    /// The chunk lives in a member.
    Stored {
        /// Chain member index.
        member: u16,
        /// Keyed content hash.
        hash: [u8; 32],
        /// Absolute offset of the chunk record.
        offset: u64,
        /// Stored payload length.
        stored_len: u32,
    },
}

/// A read-only view of a block image chain.
pub struct ImageBackend {
    size: u64,
    chunk_size: u64,
    chunk_count: u64,
    /// Only the chunks that are not plain zeroes; a missing chunk is zero.
    slots: BTreeMap<u64, ChunkSlot>,
    members: Mutex<Vec<OpenMember>>,
    /// The last decoded chunk, so a sequential read does not decode twice.
    cache: Mutex<Option<(u64, Vec<u8>)>>,
    /// Filesystem type recorded in the manifest, when there is one.
    fs_type: String,
    fs_uuid: String,
    label: String,
}

impl ImageBackend {
    /// Open a block image chain for export.
    ///
    /// # Errors
    /// Returns [`Error::Unsupported`] for image kinds that are not `Block`, and
    /// propagates destination, chain and format errors.
    pub fn open(
        dest: &str,
        images: &[String],
        options: &lr_store::DestinationOptions,
        encryption: &lr_engine::keys::Encryption,
    ) -> Result<Self> {
        let destination = lr_store::open(dest, options)?;
        let set = destination.open_set(&lr_core::SetId::ZERO)?;
        let files = images
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
        if files.is_empty() {
            return Err(Error::unsupported("the export has no images"));
        }
        let head = lr_engine::chain::read_superblock(&*destination, &set, &files[0].file_name)?;
        if head.image_kind != ImageKind::Block {
            return Err(Error::unsupported(format!(
                "block export needs a Block image; this is {:?}",
                head.image_kind
            )));
        }
        if head.is_whole_disk() {
            return Err(Error::unsupported(
                "whole-disk export is not part of Slice S13; export one partition image",
            ));
        }

        // One set of handles for the index walk, one for decoding.
        let walk_members = lr_engine::chain::open_chain(&*destination, &set, &files, encryption)?;
        let mut walk = ChainWalk::new(walk_members)?;
        let chunk_size = u64::from(walk.chunk_size());
        let chunk_count = walk.chunk_count();
        let mut slots = BTreeMap::new();
        walk.walk(|number, state, _access| {
            let slot = match state {
                ChunkState::Unused => return Ok(()),
                ChunkState::Zero => ChunkSlot::Zero,
                ChunkState::BadSector => ChunkSlot::BadSector,
                ChunkState::Stored {
                    member,
                    hash,
                    offset,
                    stored_len,
                } => ChunkSlot::Stored {
                    member,
                    hash,
                    offset,
                    stored_len,
                },
            };
            slots.insert(number, slot);
            Ok(())
        })?;

        // The manifest header carries the filesystem facts a mount needs.
        let mut read_members =
            lr_engine::chain::open_chain(&*destination, &set, &files, encryption)?;
        let manifest = read_members[0].stream_bytes(StreamId::Manifest)?;
        let mut cursor = std::io::Cursor::new(manifest.as_slice());
        let mut reader = wire::Reader::new(&mut cursor);
        let (header, _delta) = BlockManifestHeader::read(&mut reader)?;

        let size = head.source_size_bytes;
        if u64::from(header.chunk_size) != chunk_size {
            return Err(Error::corrupt(
                "the manifest and the superblock disagree about the chunk size",
            ));
        }
        Ok(Self {
            size,
            chunk_size,
            chunk_count,
            slots,
            members: Mutex::new(read_members),
            cache: Mutex::new(None),
            fs_type: header.fs_type.clone(),
            fs_uuid: header.fs_uuid.clone(),
            label: header.label.clone(),
        })
    }

    /// Filesystem type recorded in the manifest (`ext4`, `xfs`, …).
    #[must_use]
    pub fn fs_type(&self) -> &str {
        &self.fs_type
    }

    /// Filesystem UUID recorded in the manifest.
    #[must_use]
    pub fn fs_uuid(&self) -> &str {
        &self.fs_uuid
    }

    /// Filesystem label recorded in the manifest.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Chunks the image stores (`0` for an all-hole image would be surprising).
    #[must_use]
    pub fn stored_chunks(&self) -> usize {
        self.slots
            .values()
            .filter(|slot| matches!(slot, ChunkSlot::Stored { .. }))
            .count()
    }

    fn chunk(&self, number: u64) -> Result<Vec<u8>> {
        if let Some((cached, bytes)) = self.cache.lock().expect("cache lock").as_ref()
            && *cached == number
        {
            return Ok(bytes.clone());
        }
        let length = self.chunk_length(number);
        let bytes = match self.slots.get(&number) {
            None | Some(ChunkSlot::Zero) => vec![0u8; length],
            Some(ChunkSlot::BadSector) => {
                return Err(Error::BadSector {
                    offset: number * self.chunk_size,
                    len: self.chunk_size,
                });
            }
            Some(ChunkSlot::Stored {
                member,
                hash,
                offset,
                stored_len,
            }) => {
                let entry = BlockEntry::stored(*member, *hash, *offset, *stored_len)?;
                let mut members = self.members.lock().expect("member lock");
                let owner = members.get_mut(usize::from(*member)).ok_or_else(|| {
                    Error::corrupt(format!("chunk points at member {member}, which is missing"))
                })?;
                let mut plaintext =
                    owner.chunk_plaintext(&entry, usize::try_from(self.chunk_size).unwrap_or(0))?;
                plaintext.resize(length, 0);
                plaintext
            }
        };
        *self.cache.lock().expect("cache lock") = Some((number, bytes.clone()));
        Ok(bytes)
    }

    fn chunk_length(&self, number: u64) -> usize {
        let start = number.saturating_mul(self.chunk_size);
        let remaining = self.size.saturating_sub(start);
        usize::try_from(remaining.min(self.chunk_size)).unwrap_or(0)
    }
}

impl BlockBackend for ImageBackend {
    fn size_bytes(&self) -> u64 {
        self.size
    }

    fn block_size(&self) -> u32 {
        4096
    }

    fn read_at(&self, offset: u64, buffer: &mut [u8]) -> Result<()> {
        let end = offset
            .checked_add(buffer.len() as u64)
            .ok_or_else(|| Error::corrupt("read past the address space"))?;
        if end > self.size {
            return Err(Error::corrupt(format!(
                "read of {} bytes at {offset} is past the {}-byte export",
                buffer.len(),
                self.size
            )));
        }
        let mut position = offset;
        let mut filled = 0usize;
        while filled < buffer.len() {
            let number = position / self.chunk_size;
            if number >= self.chunk_count {
                // Past the manifest but inside the device: zeroes.
                buffer[filled..].fill(0);
                break;
            }
            let chunk = self.chunk(number)?;
            let within = usize::try_from(position % self.chunk_size).unwrap_or(0);
            let available = chunk.len().saturating_sub(within);
            let take = available.min(buffer.len() - filled);
            if take == 0 {
                buffer[filled] = 0;
                filled += 1;
                position += 1;
                continue;
            }
            buffer[filled..filled + take].copy_from_slice(&chunk[within..within + take]);
            filled += take;
            position += take as u64;
        }
        Ok(())
    }
}

/// Write a sparse file for the protocol tests.
///
/// # Errors
/// Returns the underlying I/O error.
pub fn write_sparse(path: &Path, size: u64) -> Result<()> {
    let file = std::fs::File::create(path).map_err(Error::Io)?;
    file.set_len(size).map_err(Error::Io)?;
    Ok(())
}

/// Convenience for tests: a file backend with a known pattern.
///
/// # Errors
/// Returns the underlying I/O error.
pub fn patterned_file(path: &Path, size: u64) -> Result<FileBackend> {
    let mut file = std::fs::File::create(path).map_err(Error::Io)?;
    let block: Vec<u8> = (0..4096).map(|index| (index % 251) as u8).collect();
    let mut written = 0u64;
    while written < size {
        let take = block
            .len()
            .min(usize::try_from(size - written).unwrap_or(0));
        file.write_all(&block[..take]).map_err(Error::Io)?;
        written += take as u64;
    }
    file.sync_all().map_err(Error::Io)?;
    drop(file);
    FileBackend::open(path)
}

#[cfg(test)]
mod tests {
    use super::{BlockBackend, FileBackend, patterned_file, write_sparse};

    #[test]
    fn a_file_backend_reads_its_bytes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("raw.bin");
        let backend = patterned_file(&path, 64 * 1024).expect("backend");
        assert_eq!(backend.size_bytes(), 64 * 1024);
        let mut buffer = vec![0u8; 16];
        backend.read_at(4096, &mut buffer).expect("read");
        assert_eq!(buffer[0], 0);
        assert_eq!(buffer[1], 1);
        // Past the end is an error, not silence.
        assert!(backend.read_at(64 * 1024, &mut buffer).is_err());
    }

    #[test]
    fn a_sparse_file_reads_as_zeroes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sparse.bin");
        write_sparse(&path, 1024 * 1024).expect("write");
        let backend = FileBackend::open(&path).expect("backend");
        let mut buffer = vec![0xFFu8; 512];
        backend.read_at(4096, &mut buffer).expect("read");
        assert!(buffer.iter().all(|byte| *byte == 0));
    }
}
