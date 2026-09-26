//! Chain members: opening, validating and streaming the merged chunk state
//! (spec §D.3, §D.4, §G.7, Slice S9).
//!
//! A chain member's manifest describes either every chunk (full and
//! differential) or only the chunks that changed (incremental). The state of a
//! chunk is therefore the entry from the *last* member that mentions it, and a
//! reader can walk all chunks in order while keeping one cursor per member —
//! memory stays O(number of members), not O(chunk count) (spec §G.2).

use std::io::{Read, Seek};

use lr_core::catalog::MemberKind;
use lr_core::io::ReadSeek;
use lr_core::{ChainId, Error, ImageId, ImageKind, Result};
use lr_crypto::aead::AeadKind;
use lr_format::{
    BlockEntry, BlockManifestHeader, ChunkReader, ChunkState, DeltaEntry, ImageReader,
    PageStreamReader, StreamId, Superblock, open_chunk, wire,
};
use lr_store::{Destination, SetHandle};

use crate::keys::{self, Encryption, ImageKeys};

/// One member of a chain, by its name inside the set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainMemberFile {
    /// Member file name relative to the set (for diagnostics and the catalog).
    pub file_name: String,
    /// Sequence in the chain; 0 is the full.
    pub seq_in_chain: u32,
    /// Member UUID.
    pub image_uuid: ImageId,
}

/// One opened and unlocked chain member.
pub struct OpenMember {
    /// File name relative to the set.
    pub file_name: String,
    /// Sequence in the chain.
    pub seq_in_chain: u32,
    /// Member UUID.
    pub image_uuid: ImageId,
    /// Member role.
    pub kind: MemberKind,
    /// Superblock.
    pub superblock: Superblock,
    /// Handle used for the manifest page streams.
    reader: ImageReader<Box<dyn ReadSeek + Send>>,
    /// Independent handle used for chunk records; a restore reads both at once.
    chunks: ChunkReader,
    keys: ImageKeys,
}

impl OpenMember {
    /// Read a whole metadata page stream into memory.
    ///
    /// # Errors
    /// Returns the authentication/decryption error of the stream, or a read
    /// error from the member file.
    pub fn stream_bytes(&mut self, stream: StreamId) -> Result<Vec<u8>> {
        let kind = self.superblock.aead_kind()?;
        let mut sink = Vec::new();
        let mut buffer = vec![0u8; 64 * 1024];
        let mut page = self
            .reader
            .stream_reader(stream, *self.keys.meta_key, kind)?;
        loop {
            let read = page.read_bytes_partial(&mut buffer)?;
            if read == 0 {
                break;
            }
            sink.extend_from_slice(&buffer[..read]);
        }
        Ok(sink)
    }

    /// Decrypt and decompress the chunk a manifest entry points at.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] when the stored payload does not hash to the
    /// manifest's expected value.
    pub fn chunk_plaintext(&mut self, entry: &BlockEntry, max_plaintext: usize) -> Result<Vec<u8>> {
        let kind = self.superblock.aead_kind()?;
        let data_key = if self.superblock.is_encrypted() {
            Some(
                &**self
                    .keys
                    .data_key
                    .as_ref()
                    .ok_or_else(|| Error::corrupt("the member has no data key"))?,
            )
        } else {
            None
        };
        let bytes = self.chunks.read_record(entry.offset)?;
        open_chunk(
            kind,
            data_key,
            &self.keys.dedup_key,
            self.superblock.image_kind,
            &entry.hash,
            max_plaintext,
            &bytes,
        )
    }
}

/// Open and unlock every member of a chain, deriving the KEK once.
///
/// Spec §G.4 wraps one chain key into every member; deriving Argon2id per
/// member would make a restore of a long chain needlessly expensive, so the
/// chain key is taken from the first member and reused. Each member gets two
/// independent destination handles: one for metadata pages and one for chunk
/// records, because a restore reads both at the same time.
///
/// # Errors
/// Returns [`Error::Aead`] for a wrong passphrase, [`Error::Unsupported`] for
/// members of another chain, and propagates destination, I/O and format errors.
pub fn open_chain(
    destination: &dyn Destination,
    set: &SetHandle,
    files: &[ChainMemberFile],
    encryption: &Encryption,
) -> Result<Vec<OpenMember>> {
    if files.is_empty() {
        return Err(Error::unsupported("the chain has no members"));
    }
    let mut readers = Vec::with_capacity(files.len());
    for file in files {
        readers.push(ImageReader::open(
            destination.open_ro(set, &file.file_name)?,
        )?);
    }
    let first = readers[0].superblock().clone();
    let (chain_key, encrypted) = keys::chain_key_of(encryption, &first)?;
    let chain_id: ChainId = first.chain_id;

    let mut members = Vec::with_capacity(files.len());
    for (file, reader) in files.iter().zip(readers) {
        let superblock = reader.superblock().clone();
        if superblock.chain_id != chain_id {
            return Err(Error::corrupt(format!(
                "{} belongs to chain {}, expected {chain_id}",
                file.file_name, superblock.chain_id
            )));
        }
        let member_keys =
            keys::unlock_with_chain_key(&chain_key, &chain_id, &superblock, encrypted)?;
        let mac_key = encrypted.then_some(&*member_keys.meta_key);
        reader.authenticate(mac_key)?;
        let chunks = reader.chunk_reader_with(destination.open_ro(set, &file.file_name)?);
        members.push(OpenMember {
            file_name: file.file_name.clone(),
            seq_in_chain: superblock.seq_in_chain,
            image_uuid: superblock.image_uuid,
            kind: member_kind(&superblock),
            superblock,
            reader,
            chunks,
            keys: member_keys,
        });
    }
    Ok(members)
}

/// The role of a member, from its sequence and delta flag.
#[must_use]
pub fn member_kind(superblock: &Superblock) -> MemberKind {
    if superblock.seq_in_chain == 0 {
        MemberKind::Full
    } else if superblock.image_kind == lr_core::ImageKind::Stream
        || superblock.flags & lr_format::flags::DELTA_MANIFEST != 0
    {
        // A stream member is a `btrfs send` stream, never a block delta
        // manifest: every member after the full is incremental by definition.
        MemberKind::Incremental
    } else {
        MemberKind::Differential
    }
}

/// Whether a source chunk differs from the state its parent chain recorded.
///
/// * a stored chunk with the same keyed hash is unchanged;
/// * `Zero`, `Unused` and `Stored` are different states and a move between
///   them is a change;
/// * a recorded bad sector is always retried: the sector may read now.
#[must_use]
pub fn is_change(source: &ChunkState, parent: &ChunkState) -> bool {
    match (source, parent) {
        (ChunkState::Stored { hash: left, .. }, ChunkState::Stored { hash: right, .. }) => {
            left != right
        }
        (ChunkState::Zero, ChunkState::Zero) | (ChunkState::Unused, ChunkState::Unused) => false,
        _ => true,
    }
}

/// The merged state of every chunk of a chain.
pub struct ChainWalk {
    members: Vec<OpenMember>,
    chunk_count: u64,
    chunk_size: u32,
}

impl ChainWalk {
    /// Validate a chain and read its base manifest header.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] when the sequence has gaps, the chain links
    /// are broken, or the members disagree about chunking or source size.
    pub fn new(mut members: Vec<OpenMember>) -> Result<Self> {
        if members.is_empty() {
            return Err(Error::unsupported("the chain has no members"));
        }
        members.sort_by_key(|member| member.seq_in_chain);
        let first = &members[0];
        if first.seq_in_chain != 0 || first.kind != MemberKind::Full {
            return Err(Error::corrupt(format!(
                "chain {} does not start with a full member",
                first.superblock.chain_id
            )));
        }
        for (index, member) in members.iter().enumerate() {
            let expected = u32::try_from(index).unwrap_or(u32::MAX);
            if member.seq_in_chain != expected {
                return Err(Error::corrupt(format!(
                    "chain {} has a gap at sequence {}",
                    first.superblock.chain_id, expected
                )));
            }
            if member.seq_in_chain > 0 {
                let previous = &members[index - 1];
                if member.superblock.parent_uuid != previous.image_uuid {
                    return Err(Error::corrupt(format!(
                        "{} does not link to {}",
                        member.file_name, previous.file_name
                    )));
                }
            }
            for (what, same) in [
                (
                    "chunk size",
                    member.superblock.chunk_size == first.superblock.chunk_size,
                ),
                (
                    "source size",
                    member.superblock.source_size_bytes == first.superblock.source_size_bytes,
                ),
                (
                    "image kind",
                    member.superblock.image_kind == first.superblock.image_kind,
                ),
                ("set", member.superblock.set_id == first.superblock.set_id),
            ] {
                if !same {
                    return Err(Error::corrupt(format!(
                        "{} disagrees about the {what}",
                        member.file_name
                    )));
                }
            }
        }

        let chunk_size = first.superblock.chunk_size;
        let chunk_count = {
            let mut member = members.remove(0);
            let kind = member.superblock.aead_kind()?;
            let meta_key = *member.keys.meta_key;
            let stream = member
                .reader
                .stream_reader(StreamId::Manifest, meta_key, kind)?;
            let mut wire = wire::Reader::new(stream);
            let (header, _delta) = BlockManifestHeader::read(&mut wire)?;
            members.insert(0, member);
            header.chunk_count
        };

        Ok(Self {
            members,
            chunk_count,
            chunk_size,
        })
    }

    /// Chunks in the image.
    #[must_use]
    pub const fn chunk_count(&self) -> u64 {
        self.chunk_count
    }

    /// Chunk size in bytes.
    #[must_use]
    pub const fn chunk_size(&self) -> u32 {
        self.chunk_size
    }

    /// The opened members, in sequence order.
    #[must_use]
    pub fn members(&self) -> &[OpenMember] {
        &self.members
    }

    /// Walk every chunk in order, handing the merged state to `visit`.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] when a manifest is short, a delta entry is
    /// out of order or out of range, or a member disagrees about the chunk
    /// count.
    pub fn walk<F>(&mut self, mut visit: F) -> Result<()>
    where
        F: FnMut(u64, ChunkState, &mut ChunkAccess<'_>) -> Result<()>,
    {
        let members = &mut self.members;
        let chunk_count = self.chunk_count;
        let image_kind = members[0].superblock.image_kind;
        let aead = members[0].superblock.aead_kind()?;
        let max_plaintext = if image_kind == ImageKind::Block || members[0].kind.has_full_manifest()
        {
            // Block chunks are exactly one chunk-sized plaintext (the final
            // chunk may be shorter); stream chunks are bounded by CDC's max.
            usize::try_from(self.chunk_size).unwrap_or(usize::MAX)
        } else {
            usize::try_from(self.chunk_size).unwrap_or(usize::MAX)
        };

        // Split each member borrow into its independent fields: the manifest
        // cursors borrow the metadata handle, the access list borrows the chunk
        // handle. They must all live for the whole walk.
        let mut cursors: Vec<Cursor<'_, Box<dyn ReadSeek + Send>>> =
            Vec::with_capacity(members.len());
        let mut chunk_readers: Vec<&mut ChunkReader> = Vec::with_capacity(members.len());
        let mut access_keys: Vec<MemberAccessKeys> = Vec::with_capacity(members.len());
        let mut file_names: Vec<String> = Vec::with_capacity(members.len());
        for member in members.iter_mut() {
            file_names.push(member.file_name.clone());
            let kind = member.superblock.aead_kind()?;
            let meta_key = *member.keys.meta_key;
            access_keys.push(MemberAccessKeys {
                data_key: member.keys.data_key.as_ref().map(|key| **key),
                dedup_key: *member.keys.dedup_key,
            });
            let delta = member.kind == MemberKind::Incremental;
            let stream = member
                .reader
                .stream_reader(StreamId::Manifest, meta_key, kind)?;
            cursors.push(Cursor::open(stream, delta, member.file_name.clone())?);
            chunk_readers.push(&mut member.chunks);
        }
        for (cursor, file_name) in cursors.iter().zip(file_names.iter()) {
            if cursor.chunk_count != chunk_count {
                return Err(Error::corrupt(format!(
                    "{file_name} declares {} chunks, expected {chunk_count}",
                    cursor.chunk_count
                )));
            }
            if cursor.chunk_size != self.chunk_size {
                return Err(Error::corrupt(format!(
                    "{file_name} declares a chunk size of {}, expected {}",
                    cursor.chunk_size, self.chunk_size
                )));
            }
        }

        let mut access = ChunkAccess {
            readers: chunk_readers,
            keys: &access_keys,
            aead,
            image_kind,
            max_plaintext,
        };

        for index in 0..chunk_count {
            let mut state = ChunkState::Unused;
            for cursor in &mut cursors {
                state = cursor.state_at(index, state)?;
            }
            visit(index, state, &mut access)?;
        }
        for cursor in &cursors {
            if let Some(pending) = &cursor.pending {
                return Err(Error::corrupt(format!(
                    "{} has a delta entry for chunk {} outside the image",
                    cursor.file_name, pending.chunk_no
                )));
            }
            if cursor.remaining != 0 {
                return Err(Error::corrupt(format!(
                    "{} has {} unused manifest entries",
                    cursor.file_name, cursor.remaining
                )));
            }
        }
        if !cursors[0].is_full {
            return Err(Error::corrupt("the base manifest is not a full manifest"));
        }
        Ok(())
    }
}

/// A cursor over one member's manifest.
struct Cursor<'a, R: Read + Seek> {
    wire: wire::Reader<PageStreamReader<'a, R>>,
    is_full: bool,
    file_name: String,
    chunk_count: u64,
    chunk_size: u32,
    remaining: u64,
    pending: Option<DeltaEntry>,
}

impl<'a, R: Read + Seek> Cursor<'a, R> {
    fn open(stream: PageStreamReader<'a, R>, delta: bool, file_name: String) -> Result<Self> {
        let mut wire = wire::Reader::new(stream);
        let (header, header_delta) = BlockManifestHeader::read(&mut wire)?;
        if header_delta != delta {
            return Err(Error::corrupt(format!(
                "{file_name}: the manifest kind disagrees with the superblock"
            )));
        }
        let mut cursor = Self {
            wire,
            is_full: !delta,
            file_name,
            chunk_count: header.chunk_count,
            chunk_size: header.chunk_size,
            remaining: header.entry_count,
            pending: None,
        };
        if delta {
            cursor.pending = cursor.read_delta()?;
        }
        Ok(cursor)
    }

    fn read_delta(&mut self) -> Result<Option<DeltaEntry>> {
        if self.remaining == 0 {
            return Ok(None);
        }
        let entry = DeltaEntry::read(&mut self.wire)?;
        self.remaining -= 1;
        Ok(Some(entry))
    }

    /// The state this member records for `index`, given the state so far.
    fn state_at(&mut self, index: u64, current: ChunkState) -> Result<ChunkState> {
        if self.is_full {
            if self.remaining == 0 {
                return Err(Error::corrupt(format!(
                    "{} ends before chunk {index}",
                    self.file_name
                )));
            }
            let entry = BlockEntry::read(&mut self.wire)?;
            self.remaining -= 1;
            return Ok(ChunkState::from(&entry));
        }
        match &self.pending {
            Some(_) => {}
            None => return Ok(current),
        }
        let pending = self.pending.take().expect("checked");
        if pending.chunk_no < index {
            return Err(Error::corrupt(format!(
                "{} has an out-of-order delta entry for chunk {}",
                self.file_name, pending.chunk_no
            )));
        }
        if pending.chunk_no > index {
            self.pending = Some(pending);
            return Ok(current);
        }
        self.pending = self.read_delta()?;
        Ok(ChunkState::from(&pending.entry))
    }
}

/// Chunk payload access across the members of a chain.
pub struct ChunkAccess<'a> {
    readers: Vec<&'a mut ChunkReader>,
    keys: &'a [MemberAccessKeys],
    aead: AeadKind,
    image_kind: ImageKind,
    max_plaintext: usize,
}

struct MemberAccessKeys {
    data_key: Option<[u8; 32]>,
    dedup_key: [u8; 32],
}

impl ChunkAccess<'_> {
    /// Read and verify the payload a stored chunk refers to.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] for a member index outside the chain or a
    /// hash mismatch, [`Error::Aead`] for a failed decryption, and propagates
    /// I/O errors.
    pub fn read(&mut self, state: &ChunkState) -> Result<Vec<u8>> {
        let ChunkState::Stored {
            member,
            hash,
            offset,
            ..
        } = state
        else {
            return Err(Error::corrupt("only stored chunks have a payload"));
        };
        let index = usize::from(*member);
        let reader = self
            .readers
            .get_mut(index)
            .ok_or_else(|| Error::corrupt(format!("chunk points at member {index}")))?;
        let keys = self
            .keys
            .get(index)
            .ok_or_else(|| Error::corrupt(format!("chunk points at member {index}")))?;
        let record = reader.read_record(*offset)?;
        open_chunk(
            self.aead,
            keys.data_key.as_ref(),
            &keys.dedup_key,
            self.image_kind,
            hash,
            self.max_plaintext,
            &record,
        )
    }
}

/// Order a chain's members, from its full up to and including `image_name`.
///
/// Restoring an older member never reads newer ones, so the chain is cut at
/// `image_name` itself.
///
/// # Errors
/// Returns [`Error::Corrupt`] when the members are incomplete, and propagates
/// destination and format errors.
pub fn resolve_chain(
    destination: &dyn Destination,
    set: &SetHandle,
    image_name: &str,
) -> Result<Vec<ChainMemberFile>> {
    let target = read_superblock(destination, set, image_name)?;
    let mut candidates = Vec::new();
    for name in destination.list(set)? {
        if !name.ends_with(".lrimg") {
            continue;
        }
        let Ok(candidate) = read_superblock(destination, set, &name) else {
            continue;
        };
        if candidate.chain_id != target.chain_id || candidate.seq_in_chain > target.seq_in_chain {
            continue;
        }
        candidates.push(ChainMemberFile {
            file_name: name,
            seq_in_chain: candidate.seq_in_chain,
            image_uuid: candidate.image_uuid,
        });
    }
    candidates.sort_by_key(|member| member.seq_in_chain);
    for (index, member) in candidates.iter().enumerate() {
        let expected = u32::try_from(index).unwrap_or(u32::MAX);
        if member.seq_in_chain != expected {
            return Err(Error::corrupt(format!(
                "the chain of {image_name} is incomplete: no member at sequence {expected}"
            )));
        }
    }
    if candidates.is_empty() {
        return Err(Error::corrupt(format!(
            "no chain members found for {image_name}"
        )));
    }
    Ok(candidates)
}

/// Read only a member's superblock (no keys required).
///
/// # Errors
/// Propagates destination and format errors.
pub fn read_superblock(
    destination: &dyn Destination,
    set: &SetHandle,
    name: &str,
) -> Result<Superblock> {
    let mut reader = destination.open_ro(set, name)?;
    let mut bytes = [0u8; lr_format::SB_SIZE];
    reader.read_exact(&mut bytes).map_err(Error::Io)?;
    Superblock::decode(&bytes)
}

#[cfg(test)]
mod tests {
    use super::{ChainMemberFile, ChainWalk, is_change, open_chain};
    use crate::keys::Encryption;
    use lr_core::catalog::MemberKind;
    use lr_core::{ChainId, Consistency, Id, ImageId, ImageKind, SetId};
    use lr_crypto::aead::AeadKind;
    use lr_crypto::nonce::NonceSeq;
    use lr_format::{
        BlockEntry, BlockManifestHeader, ChunkOptions, ChunkState, DeltaEntry, ImageWriter,
        StreamId, Superblock, WriterKeys, flags,
    };
    use lr_store::{Destination, LocalDestination, SetHandle};
    use std::path::Path;

    const CHUNK: u32 = 256 * 1024;

    /// One cell of the test's per-member chunk table.
    #[derive(Clone, Copy)]
    enum Cell<'a> {
        /// The member stores this payload.
        Stored(&'a [u8]),
        /// The member records the chunk as zero.
        Zero,
        /// The member records the chunk as unused.
        Unused,
        /// A delta manifest carries no entry for this chunk.
        Inherit,
    }

    /// Keys an unencrypted member derives from the public chain key.
    fn member_keys(superblock: &Superblock) -> crate::keys::ImageKeys {
        crate::keys::unlock_image(&Encryption::NoEncrypt, superblock).expect("keys")
    }

    fn dedup_key(superblock: &Superblock) -> [u8; 32] {
        *member_keys(superblock).dedup_key
    }

    fn hash_of(superblock: &Superblock, payload: &[u8]) -> [u8; 32] {
        lr_crypto::content_hash(&dedup_key(superblock), payload)
    }

    fn state_hash(state: &ChunkState) -> Option<[u8; 32]> {
        match state {
            ChunkState::Stored { hash, .. } => Some(*hash),
            _ => None,
        }
    }

    fn stored(superblock: &Superblock, payload: &[u8]) -> ChunkState {
        ChunkState::Stored {
            member: u16::try_from(superblock.seq_in_chain).expect("seq"),
            hash: hash_of(superblock, payload),
            offset: 0,
            stored_len: payload.len() as u32,
        }
    }

    fn superblock(seq: u32, parent: u8, uuid: u8, delta: bool) -> Superblock {
        Superblock {
            format_major: lr_format::FORMAT_MAJOR,
            min_reader: lr_format::MIN_READER,
            flags: if delta { flags::DELTA_MANIFEST } else { 0 },
            image_kind: ImageKind::Block,
            consistency: Consistency::Offline,
            image_uuid: ImageId::new(Id::from_bytes([uuid; 16])),
            chain_id: ChainId::new(Id::from_bytes([0xC1; 16])),
            set_id: SetId::new(Id::from_bytes([0xC2; 16])),
            parent_uuid: if seq == 0 {
                ImageId::ZERO
            } else {
                ImageId::new(Id::from_bytes([parent; 16]))
            },
            seq_in_chain: seq,
            created_unix: 10 + u64::from(seq),
            source_size_bytes: u64::from(CHUNK) * 4,
            logical_block_size: 512,
            chunk_size: CHUNK,
            kdf_id: 0,
            aead_id: lr_crypto::AEAD_ID_AES_256_GCM,
            kdf_salt: [0u8; 16],
            argon2_m_cost_kib: 0,
            argon2_t_cost: 0,
            argon2_p_cost: 0,
            wrap_nonce: [0u8; 12],
            wrapped_chain_key: [0u8; 48],
        }
    }

    /// Write a member image. A full manifest carries every cell; a delta
    /// manifest carries only the cells that are not `Inherit`.
    fn write_image(path: &Path, superblock: &Superblock, cells: &[Cell<'_>]) {
        let derived = member_keys(superblock);
        let keys = WriterKeys {
            data_key: None,
            meta_key: *derived.meta_key,
            dedup_key: *derived.dedup_key,
        };
        let file = std::fs::File::create(path).expect("create");
        let mut writer = ImageWriter::create(file, superblock, None).expect("writer");
        let mut nonce = NonceSeq::new();
        let mut entries: Vec<Option<BlockEntry>> = Vec::with_capacity(cells.len());
        for cell in cells {
            match cell {
                Cell::Stored(payload) => {
                    let reference = writer
                        .append_chunk(
                            ChunkOptions {
                                kind: AeadKind::Aes256Gcm,
                                level: 0,
                                compress: false,
                            },
                            &keys,
                            ImageKind::Block,
                            &mut nonce,
                            payload,
                        )
                        .expect("chunk");
                    entries.push(Some(
                        BlockEntry::stored(
                            u16::try_from(superblock.seq_in_chain).expect("seq"),
                            reference.hash,
                            reference.offset,
                            reference.stored_len,
                        )
                        .expect("stored entry"),
                    ));
                }
                Cell::Zero => entries.push(Some(BlockEntry::zero())),
                Cell::Unused => entries.push(Some(BlockEntry::unused())),
                Cell::Inherit => entries.push(None),
            }
        }
        let delta = superblock.flags & flags::DELTA_MANIFEST != 0;
        assert!(
            !delta || entries.iter().any(Option::is_none),
            "a delta member must inherit something"
        );
        let present = entries.iter().filter(|entry| entry.is_some()).count() as u64;
        {
            let mut manifest =
                writer.page_stream(StreamId::Manifest, AeadKind::Aes256Gcm, *derived.meta_key);
            BlockManifestHeader {
                chunk_size: CHUNK,
                chunk_count: cells.len() as u64,
                entry_count: present,
                used_extent_count: 0,
                used_bytes: 0,
                fs_type: "ext4".to_owned(),
                fs_uuid: String::new(),
                label: String::new(),
            }
            .write(&mut manifest, delta)
            .expect("header");
            for (index, entry) in entries.iter().enumerate() {
                let Some(entry) = entry else { continue };
                if delta {
                    DeltaEntry {
                        chunk_no: index as u64,
                        entry: *entry,
                    }
                    .write(&mut manifest)
                    .expect("delta");
                } else {
                    entry.write(&mut manifest).expect("entry");
                }
            }
            manifest.finish().expect("finish manifest");
        }
        let (mut file, _footer) = writer
            .finish(&[0u8; 32], None, AeadKind::Aes256Gcm)
            .expect("finish");
        use std::io::Write;
        file.flush().expect("flush");
    }

    /// A temporary directory whose name is a valid set name (D-115).
    fn set_dir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("set")
            .tempdir()
            .expect("tempdir")
    }

    /// A destination whose set root is `dir` itself, so a member's name is its
    /// file name; `dir` comes from [`set_dir`].
    fn destination_for(dir: &Path) -> (LocalDestination, SetHandle) {
        let name = dir
            .file_name()
            .and_then(|name| name.to_str())
            .expect("set directory name");
        let destination = LocalDestination::new(dir.parent().expect("parent"), name);
        let set = destination
            .open_set(&lr_core::SetId::ZERO)
            .expect("open set");
        (destination, set)
    }

    /// A chain of three members:
    /// 0: [aaaa, zero, unused, aaaa]
    /// 1: inherits 0 and 1, stores bbbb, marks 3 unused
    /// 2: inherits 0 and 2, stores bbbb at 1 and aaaa at 3
    fn chain(dir: &Path) -> Vec<ChainMemberFile> {
        write_image(
            &dir.join("000-full.lrimg"),
            &superblock(0, 0, 0xA1, false),
            &[
                Cell::Stored(b"aaaa"),
                Cell::Zero,
                Cell::Unused,
                Cell::Stored(b"aaaa"),
            ],
        );
        write_image(
            &dir.join("001-incr.lrimg"),
            &superblock(1, 0xA1, 0xA2, true),
            &[
                Cell::Inherit,
                Cell::Inherit,
                Cell::Stored(b"bbbb"),
                Cell::Unused,
            ],
        );
        write_image(
            &dir.join("002-incr.lrimg"),
            &superblock(2, 0xA2, 0xA3, true),
            &[
                Cell::Inherit,
                Cell::Stored(b"bbbb"),
                Cell::Inherit,
                Cell::Stored(b"aaaa"),
            ],
        );
        vec![
            ChainMemberFile {
                file_name: "000-full.lrimg".to_owned(),
                seq_in_chain: 0,
                image_uuid: ImageId::new(Id::from_bytes([0xA1; 16])),
            },
            ChainMemberFile {
                file_name: "001-incr.lrimg".to_owned(),
                seq_in_chain: 1,
                image_uuid: ImageId::new(Id::from_bytes([0xA2; 16])),
            },
            ChainMemberFile {
                file_name: "002-incr.lrimg".to_owned(),
                seq_in_chain: 2,
                image_uuid: ImageId::new(Id::from_bytes([0xA3; 16])),
            },
        ]
    }

    fn merged(dir: &Path) -> Vec<ChunkState> {
        let files = chain(dir);
        let (destination, set) = destination_for(dir);
        let members = open_chain(&destination, &set, &files, &Encryption::NoEncrypt).expect("open");
        let mut walk = ChainWalk::new(members).expect("walk");
        assert_eq!(walk.chunk_count(), 4);
        let mut seen = Vec::new();
        walk.walk(|_, state, _| {
            seen.push(state);
            Ok(())
        })
        .expect("walk");
        seen
    }

    #[test]
    fn the_merged_state_is_the_last_mention_in_sequence_order() {
        let dir = set_dir();
        let seen = merged(dir.path());
        let full = superblock(0, 0, 0xA1, false);
        assert_eq!(
            state_hash(&seen[0]),
            Some(hash_of(&full, b"aaaa")),
            "0: inherited from the full"
        );
        assert!(
            matches!(seen[0], ChunkState::Stored { member: 0, .. }),
            "0: the full stores it"
        );
        assert_eq!(state_hash(&seen[1]), Some(hash_of(&full, b"bbbb")));
        assert!(
            matches!(seen[1], ChunkState::Stored { member: 2, .. }),
            "1: the newest member stores it"
        );
        assert_eq!(
            state_hash(&seen[2]),
            Some(hash_of(&full, b"bbbb")),
            "2: unchanged since member 1"
        );
        assert!(
            matches!(seen[2], ChunkState::Stored { member: 1, .. }),
            "2: still the member that last changed it"
        );
        assert_eq!(
            state_hash(&seen[3]),
            Some(hash_of(&full, b"aaaa")),
            "3: restored by member 2"
        );

        let files = chain(dir.path());
        let (destination, set) = destination_for(dir.path());
        let members = open_chain(&destination, &set, &files, &Encryption::NoEncrypt).expect("open");
        assert_eq!(members[0].kind, MemberKind::Full);
        assert_eq!(members[1].kind, MemberKind::Incremental);
        assert_eq!(members[2].kind, MemberKind::Incremental);
    }

    #[test]
    fn payloads_come_from_the_member_that_stores_them() {
        let dir = set_dir();
        let files = chain(dir.path());
        let (destination, set) = destination_for(dir.path());
        let members = open_chain(&destination, &set, &files, &Encryption::NoEncrypt).expect("open");
        let mut walk = ChainWalk::new(members).expect("walk");
        let mut payloads = Vec::new();
        walk.walk(|_, state, access| {
            if matches!(state, ChunkState::Stored { .. }) {
                payloads.push(access.read(&state)?);
            }
            Ok(())
        })
        .expect("walk");
        assert_eq!(payloads.len(), 4, "{payloads:?}");
        assert_eq!(payloads[0], b"aaaa");
        assert_eq!(payloads[1], b"bbbb");
        assert_eq!(payloads[2], b"bbbb");
        assert_eq!(payloads[3], b"aaaa");
    }

    #[test]
    fn a_chain_with_a_gap_is_refused() {
        let dir = set_dir();
        let mut files = chain(dir.path());
        files.remove(1);
        let (destination, set) = destination_for(dir.path());
        let members = open_chain(&destination, &set, &files, &Encryption::NoEncrypt).expect("open");
        let error = ChainWalk::new(members).err().expect("must refuse");
        assert!(error.to_string().contains("gap"), "{error}");
    }

    #[test]
    fn a_broken_link_is_refused() {
        let dir = set_dir();
        let files = chain(dir.path());
        write_image(
            &dir.path().join("001-incr.lrimg"),
            &superblock(1, 0x99, 0xA2, true),
            &[Cell::Inherit, Cell::Unused, Cell::Unused, Cell::Unused],
        );
        let (destination, set) = destination_for(dir.path());
        let members = open_chain(&destination, &set, &files, &Encryption::NoEncrypt).expect("open");
        let error = ChainWalk::new(members).err().expect("must refuse");
        assert!(error.to_string().contains("does not link"), "{error}");
    }

    #[test]
    fn change_detection_follows_the_state_table() {
        let full = superblock(0, 0, 0xA1, false);
        assert!(!is_change(&stored(&full, b"aaaa"), &stored(&full, b"aaaa")));
        assert!(is_change(&stored(&full, b"aaaa"), &stored(&full, b"bbbb")));
        assert!(!is_change(&ChunkState::Zero, &ChunkState::Zero));
        assert!(!is_change(&ChunkState::Unused, &ChunkState::Unused));
        assert!(is_change(&stored(&full, b"aaaa"), &ChunkState::Unused));
        assert!(is_change(&ChunkState::Zero, &ChunkState::Unused));
        assert!(is_change(&ChunkState::BadSector, &ChunkState::BadSector));
    }
}
