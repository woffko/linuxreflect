//! Block, stream and delta manifests (spec §G.2, §G.7,
//! `docs/format-lrimg-v1.md` §5).
//!
//! Manifest entries are 46 bytes: `hash 32 ‖ member/state u16 ‖ offset u64 ‖
//! stored_len u32`. The two-bit `state` is packed into the top of the member
//! field because a member index never needs more than 14 bits and the spec's
//! own capacity arithmetic (4 M entries ≈ 184 MB for 4 TB) assumes 46 bytes.

use lr_core::{Error, Id, Result};

use crate::wire::{self, ByteSink, ByteSource, Reader};

/// Manifest schema version.
pub const MANIFEST_VER: u16 = 1;

/// Section kinds inside the manifest stream.
pub const SECTION_BLOCK_FULL: u8 = 1;
/// Delta block manifest: only changed chunks, each with its chunk number.
pub const SECTION_BLOCK_DELTA: u8 = 2;
/// One subvolume of a stream image.
pub const SECTION_STREAM_SUBVOL: u8 = 3;
/// One file entry of a file image.
pub const SECTION_FILE_ENTRY: u8 = 4;
/// More chunk references for the preceding file entry.
pub const SECTION_FILE_CONTINUATION: u8 = 5;
/// Sparse regions of the file entry that precedes it (spec §K S12).
pub const SECTION_FILE_HOLES: u8 = 6;

/// Chunk states (spec §G.7).
pub const STATE_UNUSED: u8 = 0;
/// All-zero chunk that is not stored.
pub const STATE_ZERO: u8 = 1;
/// Chunk payload is stored somewhere in the chain.
pub const STATE_STORED: u8 = 2;
/// Unreadable region; recorded, never silently zero-filled.
pub const STATE_BAD_SECTOR: u8 = 3;

/// Largest member index that fits in 14 bits.
pub const MAX_MEMBER: u16 = 0x3FFF;

/// Encoded size of a full-manifest entry.
pub const ENTRY_LEN: usize = 46;

/// Extra prefix on a delta entry: the absolute chunk number.
pub const DELTA_CHUNK_NO_LEN: usize = 8;

/// Encoded size of a delta-manifest entry.
pub const DELTA_ENTRY_LEN: usize = ENTRY_LEN + DELTA_CHUNK_NO_LEN;

/// Header of a block manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockManifestHeader {
    /// Chunk size in bytes.
    pub chunk_size: u32,
    /// Total chunks in the image.
    pub chunk_count: u64,
    /// Entries in this manifest.
    pub entry_count: u64,
    /// Number of used extents in the source summary.
    pub used_extent_count: u64,
    /// Total used bytes in the source summary.
    pub used_bytes: u64,
    /// Source filesystem type.
    pub fs_type: String,
    /// Source filesystem UUID.
    pub fs_uuid: String,
    /// Source filesystem label.
    pub label: String,
}

impl BlockManifestHeader {
    /// Serialize the common header plus the block fields.
    ///
    /// # Errors
    /// Propagates sink errors and rejects strings over 65535 bytes.
    pub fn write(&self, out: &mut impl ByteSink, delta: bool) -> Result<()> {
        wire::put_u16(out, MANIFEST_VER)?;
        wire::put_u8(
            out,
            if delta {
                SECTION_BLOCK_DELTA
            } else {
                SECTION_BLOCK_FULL
            },
        )?;
        wire::put_u8(out, 0)?;
        wire::put_u32(out, self.chunk_size)?;
        wire::put_u64(out, self.chunk_count)?;
        wire::put_u64(out, self.entry_count)?;
        wire::put_u64(out, self.used_extent_count)?;
        wire::put_u64(out, self.used_bytes)?;
        wire::put_u16_prefixed(out, self.fs_type.as_bytes())?;
        wire::put_u16_prefixed(out, self.fs_uuid.as_bytes())?;
        wire::put_u16_prefixed(out, self.label.as_bytes())?;
        wire::put_u16(out, 0)?; // reserved
        Ok(())
    }

    /// Parse a block manifest header.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] for a wrong version or section kind and for
    /// malformed strings.
    pub fn read<S: ByteSource>(reader: &mut Reader<S>) -> Result<(Self, bool)> {
        let ver = reader.u16()?;
        if ver != MANIFEST_VER {
            return Err(Error::corrupt(format!("manifest version {ver}")));
        }
        let kind = reader.u8()?;
        let delta = match kind {
            SECTION_BLOCK_FULL => false,
            SECTION_BLOCK_DELTA => true,
            other => {
                return Err(Error::corrupt(format!(
                    "expected a block manifest, got {other}"
                )));
            }
        };
        let _reserved = reader.u8()?;
        let chunk_size = reader.u32()?;
        let chunk_count = reader.u64()?;
        let entry_count = reader.u64()?;
        let used_extent_count = reader.u64()?;
        let used_bytes = reader.u64()?;
        let fs_type = utf8(reader.u16_prefixed()?, "fs_type")?;
        let fs_uuid = utf8(reader.u16_prefixed()?, "fs_uuid")?;
        let label = utf8(reader.u16_prefixed()?, "label")?;
        let _reserved = reader.u16()?;
        Ok((
            Self {
                chunk_size,
                chunk_count,
                entry_count,
                used_extent_count,
                used_bytes,
                fs_type,
                fs_uuid,
                label,
            },
            delta,
        ))
    }
}

fn utf8(bytes: Vec<u8>, what: &str) -> Result<String> {
    String::from_utf8(bytes).map_err(|_| Error::corrupt(format!("{what} is not valid UTF-8")))
}

/// One chunk's state as recorded in a manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockEntry {
    /// One of the `STATE_*` constants.
    pub state: u8,
    /// Chain member index holding the payload; 0 when nothing is stored.
    pub member: u16,
    /// Keyed content hash of the chunk plaintext.
    pub hash: [u8; 32],
    /// Absolute file offset of the chunk record.
    pub offset: u64,
    /// Stored payload length.
    pub stored_len: u32,
}

impl BlockEntry {
    /// A chunk that is not stored (unused/hole).
    #[must_use]
    pub const fn unused() -> Self {
        Self {
            state: STATE_UNUSED,
            member: 0,
            hash: [0u8; 32],
            offset: 0,
            stored_len: 0,
        }
    }

    /// An all-zero chunk that is not stored.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            state: STATE_ZERO,
            member: 0,
            hash: [0u8; 32],
            offset: 0,
            stored_len: 0,
        }
    }

    /// A stored chunk.
    ///
    /// # Errors
    /// Returns [`Error::Unsupported`] when the member index does not fit in
    /// 14 bits.
    pub fn stored(member: u16, hash: [u8; 32], offset: u64, stored_len: u32) -> Result<Self> {
        if member > MAX_MEMBER {
            return Err(Error::unsupported(format!(
                "chain member index {member} exceeds {MAX_MEMBER}"
            )));
        }
        Ok(Self {
            state: STATE_STORED,
            member,
            hash,
            offset,
            stored_len,
        })
    }

    /// A recorded bad sector.
    #[must_use]
    pub const fn bad_sector(offset: u64, len: u32) -> Self {
        Self {
            state: STATE_BAD_SECTOR,
            member: 0,
            hash: [0u8; 32],
            offset,
            stored_len: len,
        }
    }

    /// `true` when the payload lives in the file.
    #[must_use]
    pub const fn is_stored(&self) -> bool {
        self.state == STATE_STORED
    }

    /// Encode to 46 bytes.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] for an unknown state or an oversized member.
    pub fn encode(&self) -> Result<[u8; ENTRY_LEN]> {
        if self.state > STATE_BAD_SECTOR {
            return Err(Error::corrupt(format!(
                "unknown chunk state {}",
                self.state
            )));
        }
        if self.member > MAX_MEMBER {
            return Err(Error::corrupt(format!(
                "member index {} too large",
                self.member
            )));
        }
        let mut out = [0u8; ENTRY_LEN];
        out[..32].copy_from_slice(&self.hash);
        let packed = (self.member & MAX_MEMBER) | (u16::from(self.state) << 14);
        out[32..34].copy_from_slice(&packed.to_le_bytes());
        out[34..42].copy_from_slice(&self.offset.to_le_bytes());
        out[42..46].copy_from_slice(&self.stored_len.to_le_bytes());
        Ok(out)
    }

    /// Decode from 46 bytes.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] for an unknown state.
    pub fn decode(bytes: &[u8; ENTRY_LEN]) -> Result<Self> {
        let packed = wire::slice_u16(&bytes[32..])?;
        let state = (packed >> 14) as u8;
        if state > STATE_BAD_SECTOR {
            return Err(Error::corrupt(format!("unknown chunk state {state}")));
        }
        Ok(Self {
            state,
            member: packed & MAX_MEMBER,
            hash: bytes[..32]
                .try_into()
                .map_err(|_| Error::corrupt("entry hash"))?,
            offset: wire::slice_u64(&bytes[34..])?,
            stored_len: wire::slice_u32(&bytes[42..])?,
        })
    }

    /// Write this entry into a manifest stream.
    ///
    /// # Errors
    /// Propagates sink and encoding errors.
    pub fn write(&self, out: &mut impl ByteSink) -> Result<()> {
        out.write_bytes(&self.encode()?)
    }

    /// Read one entry from a manifest stream.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] at end of input.
    pub fn read<S: ByteSource>(reader: &mut Reader<S>) -> Result<Self> {
        let bytes: [u8; ENTRY_LEN] = reader.array()?;
        Self::decode(&bytes)
    }
}

/// A delta entry: an absolute chunk number plus a full entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeltaEntry {
    /// Chunk number this entry replaces.
    pub chunk_no: u64,
    /// The new state of that chunk.
    pub entry: BlockEntry,
}

impl DeltaEntry {
    /// Write this delta entry.
    ///
    /// # Errors
    /// Propagates sink and encoding errors.
    pub fn write(&self, out: &mut impl ByteSink) -> Result<()> {
        wire::put_u64(out, self.chunk_no)?;
        self.entry.write(out)
    }

    /// Read one delta entry.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] at end of input.
    pub fn read<S: ByteSource>(reader: &mut Reader<S>) -> Result<Self> {
        let chunk_no = reader.u64()?;
        Ok(Self {
            chunk_no,
            entry: BlockEntry::read(reader)?,
        })
    }
}

/// Resolved state of one chunk after applying a delta on top of its parent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkState {
    /// Nothing is stored and the chunk is not known to be zero.
    Unused,
    /// The chunk is entirely zero.
    Zero,
    /// The payload is stored in the file.
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
    /// A recorded bad sector.
    BadSector,
}

impl From<&BlockEntry> for ChunkState {
    fn from(entry: &BlockEntry) -> Self {
        match entry.state {
            STATE_STORED => Self::Stored {
                member: entry.member,
                hash: entry.hash,
                offset: entry.offset,
                stored_len: entry.stored_len,
            },
            STATE_ZERO => Self::Zero,
            STATE_BAD_SECTOR => Self::BadSector,
            _ => Self::Unused,
        }
    }
}

/// Apply delta entries to a parent state vector.
///
/// The engine streams this for real images; the vector form is what the
/// scan-and-diff tests and small images use.
///
/// # Errors
/// Returns [`Error::Corrupt`] when a delta entry points past the parent.
pub fn apply_delta(parent: &mut [ChunkState], delta: &[DeltaEntry]) -> Result<()> {
    for entry in delta {
        let index = usize::try_from(entry.chunk_no)
            .map_err(|_| Error::corrupt("delta chunk number does not fit in usize"))?;
        let slot = parent.get_mut(index).ok_or_else(|| {
            Error::corrupt(format!("delta chunk {} is out of range", entry.chunk_no))
        })?;
        *slot = ChunkState::from(&entry.entry);
    }
    Ok(())
}

/// One subvolume section of a stream image manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamSection {
    /// Subvolume id.
    pub subvolid: u64,
    /// Bytes in the `btrfs send` stream.
    pub send_stream_bytes: u64,
    /// Parent snapshot UUID for an incremental send.
    pub parent_snapshot_uuid: Option<Id>,
    /// Subvolume path.
    pub subvol_path: String,
    /// Number of chunk entries that follow.
    pub entry_count: u64,
}

impl StreamSection {
    /// Write the section header (entries follow separately).
    ///
    /// # Errors
    /// Propagates sink errors.
    pub fn write(&self, out: &mut impl ByteSink) -> Result<()> {
        wire::put_u16(out, MANIFEST_VER)?;
        wire::put_u8(out, SECTION_STREAM_SUBVOL)?;
        wire::put_u8(out, 0)?;
        wire::put_u64(out, self.subvolid)?;
        wire::put_u64(out, self.send_stream_bytes)?;
        wire::put_u64(out, self.entry_count)?;
        match &self.parent_snapshot_uuid {
            Some(id) => {
                wire::put_u8(out, 1)?;
                wire::put_id(out, id)?;
            }
            None => {
                wire::put_u8(out, 0)?;
                wire::put_bytes(out, &[0u8; 16])?;
            }
        }
        wire::put_u16_prefixed(out, self.subvol_path.as_bytes())?;
        Ok(())
    }

    /// Read a stream section header.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] for a wrong version or section kind.
    pub fn read<S: ByteSource>(reader: &mut Reader<S>) -> Result<Self> {
        let ver = reader.u16()?;
        if ver != MANIFEST_VER {
            return Err(Error::corrupt(format!("manifest version {ver}")));
        }
        let kind = reader.u8()?;
        if kind != SECTION_STREAM_SUBVOL {
            return Err(Error::corrupt(format!(
                "expected a stream section, got {kind}"
            )));
        }
        let _reserved = reader.u8()?;
        let subvolid = reader.u64()?;
        let send_stream_bytes = reader.u64()?;
        let entry_count = reader.u64()?;
        let has_parent = reader.u8()?;
        let parent = reader.id()?;
        let parent_snapshot_uuid = match has_parent {
            0 => None,
            1 => Some(parent),
            other => {
                return Err(Error::corrupt(format!("has_parent flag {other}")));
            }
        };
        let subvol_path = utf8(reader.u16_prefixed()?, "subvol_path")?;
        Ok(Self {
            subvolid,
            send_stream_bytes,
            parent_snapshot_uuid,
            subvol_path,
            entry_count,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BlockEntry, BlockManifestHeader, ChunkState, DeltaEntry, ENTRY_LEN, STATE_ZERO,
        StreamSection, apply_delta,
    };
    use crate::wire::Reader;
    use lr_core::Id;
    use std::io::Cursor;

    fn entry(member: u16, seed: u8) -> BlockEntry {
        BlockEntry::stored(member, [seed; 32], 4096 + u64::from(seed), 1024).expect("stored")
    }

    #[test]
    fn entry_is_exactly_46_bytes_and_packs_state() {
        let encoded = entry(3, 0xAA).encode().expect("encode");
        assert_eq!(encoded.len(), ENTRY_LEN);
        assert_eq!(&encoded[..32], &[0xAA; 32]);
        let packed = u16::from_le_bytes([encoded[32], encoded[33]]);
        assert_eq!(packed & 0x3FFF, 3, "member index");
        assert_eq!(packed >> 14, 2, "state stored");
        assert_eq!(&encoded[34..42], &(4096u64 + 0xAA).to_le_bytes());
        assert_eq!(&encoded[42..46], &1024u32.to_le_bytes());

        let decoded = BlockEntry::decode(&encoded).expect("decode");
        assert_eq!(decoded, entry(3, 0xAA));
    }

    #[test]
    fn entry_round_trips_every_state() {
        for entry in [
            BlockEntry::unused(),
            BlockEntry::zero(),
            entry(1, 0x11),
            BlockEntry::bad_sector(8192, 512),
        ] {
            assert_eq!(
                BlockEntry::decode(&entry.encode().expect("encode")).expect("decode"),
                entry
            );
        }
    }

    #[test]
    fn oversized_member_indices_are_refused() {
        assert!(BlockEntry::stored(super::MAX_MEMBER + 1, [0; 32], 0, 1).is_err());
    }

    #[test]
    fn manifest_headers_round_trip() {
        let header = BlockManifestHeader {
            chunk_size: 1024 * 1024,
            chunk_count: 4_194_304,
            entry_count: 4_194_304,
            used_extent_count: 12,
            used_bytes: 64 * 1024 * 1024 * 1024,
            fs_type: "ext4".to_owned(),
            fs_uuid: "11111111-2222-3333-4444-555555555555".to_owned(),
            label: "ROOT".to_owned(),
        };
        let mut bytes = Vec::new();
        header.write(&mut bytes, false).expect("write");
        let mut reader = Reader::new(Cursor::new(bytes));
        let (decoded, delta) = BlockManifestHeader::read(&mut reader).expect("read");
        assert_eq!(decoded, header);
        assert!(!delta);
    }

    #[test]
    fn delta_manifest_header_is_marked() {
        let header = BlockManifestHeader {
            chunk_size: 1024 * 1024,
            chunk_count: 100,
            entry_count: 3,
            used_extent_count: 0,
            used_bytes: 0,
            fs_type: "ext4".to_owned(),
            fs_uuid: String::new(),
            label: String::new(),
        };
        let mut bytes = Vec::new();
        header.write(&mut bytes, true).expect("write");
        let mut reader = Reader::new(Cursor::new(bytes));
        let (_, delta) = BlockManifestHeader::read(&mut reader).expect("read");
        assert!(delta);
    }

    #[test]
    fn delta_entries_round_trip_and_merge() {
        let mut parent = vec![ChunkState::Unused; 5];
        parent[1] = ChunkState::Zero;
        let delta = vec![
            DeltaEntry {
                chunk_no: 3,
                entry: entry(2, 0x33),
            },
            DeltaEntry {
                chunk_no: 1,
                entry: BlockEntry {
                    state: STATE_ZERO,
                    ..BlockEntry::unused()
                },
            },
        ];
        let mut bytes = Vec::new();
        for entry in &delta {
            entry.write(&mut bytes).expect("write");
        }
        let mut reader = Reader::new(Cursor::new(bytes));
        let mut read_back = Vec::new();
        for _ in 0..delta.len() {
            read_back.push(DeltaEntry::read(&mut reader).expect("read"));
        }
        assert_eq!(read_back, delta);

        apply_delta(&mut parent, &read_back).expect("apply");
        assert_eq!(parent[1], ChunkState::Zero);
        assert!(matches!(parent[3], ChunkState::Stored { member: 2, .. }));
        assert_eq!(parent[4], ChunkState::Unused);
        assert!(
            apply_delta(
                &mut parent,
                &[DeltaEntry {
                    chunk_no: 9,
                    entry: entry(0, 0)
                }]
            )
            .is_err()
        );
    }

    #[test]
    fn stream_sections_round_trip() {
        let section = StreamSection {
            subvolid: 256,
            send_stream_bytes: 1024 * 1024,
            parent_snapshot_uuid: Some(Id::from_bytes([0x77; 16])),
            subvol_path: "@home".to_owned(),
            entry_count: 16,
        };
        let mut bytes = Vec::new();
        section.write(&mut bytes).expect("write");
        let mut reader = Reader::new(Cursor::new(bytes));
        assert_eq!(StreamSection::read(&mut reader).expect("read"), section);

        let no_parent = StreamSection {
            parent_snapshot_uuid: None,
            ..section
        };
        let mut bytes = Vec::new();
        no_parent.write(&mut bytes).expect("write");
        let mut reader = Reader::new(Cursor::new(bytes));
        assert_eq!(StreamSection::read(&mut reader).expect("read"), no_parent);
    }
}
