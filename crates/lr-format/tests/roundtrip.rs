//! Property-based round-trip tests for every codec (spec §K S4).

use lr_core::{Consistency, Id, ImageId, ImageKind};
use lr_crypto::aead::AeadKind;
use lr_crypto::page::StreamId;
use lr_format::{
    BlockEntry, ChunkRecord, DeltaEntry, FileEntry, PageEntry, Superblock, Xattr, flags,
    parse_table, serialize_table,
};
use proptest::prelude::*;

fn hash32() -> impl Strategy<Value = [u8; 32]> {
    proptest::array::uniform32(any::<u8>())
}

fn id16() -> impl Strategy<Value = [u8; 16]> {
    proptest::array::uniform16(any::<u8>())
}

fn stream_id() -> impl Strategy<Value = StreamId> {
    prop_oneof![
        Just(StreamId::Manifest),
        Just(StreamId::HashIndex),
        Just(StreamId::Extras),
        Just(StreamId::PageTable),
    ]
}

fn block_entry() -> impl Strategy<Value = BlockEntry> {
    (0u8..=3, 0u16..=0x3FFF, hash32(), any::<u64>(), any::<u32>()).prop_map(
        |(state, member, hash, offset, stored_len)| BlockEntry {
            state,
            member,
            hash,
            offset,
            stored_len,
        },
    )
}

fn chunk_record() -> impl Strategy<Value = ChunkRecord> {
    (
        any::<bool>(),
        any::<bool>(),
        proptest::array::uniform12(any::<u8>()),
        prop::collection::vec(any::<u8>(), 0..2048),
        proptest::array::uniform16(any::<u8>()),
    )
        .prop_map(|(encrypted, compressed, nonce, payload, tag)| ChunkRecord {
            flags: u8::from(compressed) | (u8::from(encrypted) << 1),
            nonce,
            payload,
            tag: encrypted.then_some(tag),
        })
}

fn page_entry() -> impl Strategy<Value = PageEntry> {
    (stream_id(), any::<u64>(), 0u32..=4_194_304).prop_map(|(stream, offset, len)| PageEntry {
        stream,
        offset,
        len,
    })
}

fn file_entry() -> impl Strategy<Value = FileEntry> {
    let metadata = (
        any::<u32>(),
        any::<u32>(),
        any::<u32>(),
        any::<i64>(),
        any::<u32>(),
        any::<u64>(),
        any::<u32>(),
    );
    (
        1u8..=5,
        metadata,
        prop::collection::vec(any::<u8>(), 0..32),
        prop::collection::vec(any::<u8>(), 1..32),
        prop::collection::vec(
            (
                prop::collection::vec(any::<u8>(), 0..16),
                prop::collection::vec(any::<u8>(), 0..16),
            ),
            0..3,
        ),
        prop::collection::vec(any::<u8>(), 0..16),
        prop::collection::vec(hash32(), 0..4),
    )
        .prop_map(
            |(file_kind, metadata, link_target, path, xattrs, acl, chunk_refs_here)| FileEntry {
                file_kind,
                mode: metadata.0,
                uid: metadata.1,
                gid: metadata.2,
                mtime_sec: metadata.3,
                mtime_nsec: metadata.4,
                size: metadata.5,
                rdev: 0,
                hardlink_group: metadata.6,
                link_target,
                path,
                xattrs: xattrs
                    .into_iter()
                    .map(|(name, value)| Xattr { name, value })
                    .collect(),
                acl,
                chunk_refs_total: chunk_refs_here.len() as u64,
                chunk_refs_here,
            },
        )
}

fn superblock() -> impl Strategy<Value = Superblock> {
    (
        prop_oneof![
            Just(256 * 1024u32),
            Just(1024 * 1024),
            Just(4 * 1024 * 1024)
        ],
        prop_oneof![Just(512u32), Just(4096)],
        any::<u64>(),
        any::<u32>(),
        any::<u64>(),
        prop_oneof![
            Just(ImageKind::Block),
            Just(ImageKind::Stream),
            Just(ImageKind::File)
        ],
        prop_oneof![
            Just(Consistency::PointInTime),
            Just(Consistency::Frozen),
            Just(Consistency::Offline),
            Just(Consistency::PerFile),
            Just(Consistency::None),
        ],
        id16(),
        id16(),
        id16(),
    )
        .prop_map(
            |(
                chunk_size,
                logical_block_size,
                raw_flags,
                seq_in_chain,
                created_unix,
                image_kind,
                consistency,
                image_uuid,
                chain_id,
                set_id,
            )| Superblock {
                format_major: lr_format::FORMAT_MAJOR,
                min_reader: lr_format::MIN_READER,
                flags: raw_flags | flags::ENCRYPTED,
                image_kind,
                consistency,
                image_uuid: ImageId::new(Id::from_bytes(image_uuid)),
                chain_id: lr_core::ChainId::new(Id::from_bytes(chain_id)),
                set_id: lr_core::SetId::new(Id::from_bytes(set_id)),
                parent_uuid: ImageId::new(Id::from_bytes(chain_id)),
                seq_in_chain,
                created_unix,
                source_size_bytes: 1 << 40,
                logical_block_size,
                chunk_size,
                kdf_id: 1,
                aead_id: AeadKind::Aes256Gcm.id(),
                kdf_salt: [0x04; 16],
                argon2_m_cost_kib: 256 * 1024,
                argon2_t_cost: 3,
                argon2_p_cost: 4,
                wrap_nonce: [0x05; 12],
                wrapped_chain_key: [0x06; 48],
            },
        )
}

proptest! {
    #[test]
    fn block_entries_round_trip(entry in block_entry()) {
        let encoded = entry.encode().expect("encode");
        prop_assert_eq!(encoded.len(), lr_format::ENTRY_LEN);
        prop_assert_eq!(BlockEntry::decode(&encoded).expect("decode"), entry);
    }

    #[test]
    fn delta_entries_round_trip(chunk_no in any::<u64>(), entry in block_entry()) {
        let delta = DeltaEntry { chunk_no, entry };
        let mut bytes = Vec::new();
        delta.write(&mut bytes).expect("write");
        prop_assert_eq!(bytes.len(), lr_format::DELTA_ENTRY_LEN);
        let mut reader = lr_format::wire::Reader::new(std::io::Cursor::new(bytes));
        prop_assert_eq!(DeltaEntry::read(&mut reader).expect("read"), delta);
    }

    #[test]
    fn chunk_records_round_trip(record in chunk_record()) {
        let encoded = lr_format::chunk::encode(&record).expect("encode");
        prop_assert_eq!(encoded.len(), record.total_len());
        prop_assert_eq!(lr_format::chunk::decode(&encoded).expect("decode"), record);
    }

    #[test]
    fn page_tables_round_trip(table in prop::collection::vec(page_entry(), 0..64)) {
        let bytes = serialize_table(&table);
        prop_assert_eq!(bytes.len(), table.len() * lr_format::PAGE_ENTRY_SIZE);
        prop_assert_eq!(parse_table(&bytes).expect("parse"), table);
    }

    #[test]
    fn file_entries_round_trip(entry in file_entry()) {
        let mut bytes = Vec::new();
        entry.write(&mut bytes).expect("write");
        let mut reader = lr_format::wire::Reader::new(std::io::Cursor::new(bytes));
        let (decoded, refs) =
            lr_format::read_entry_with_continuations(&mut reader).expect("read");
        prop_assert_eq!(&decoded, &entry);
        prop_assert_eq!(refs.len(), entry.chunk_refs_total as usize);
    }

    #[test]
    fn superblocks_round_trip(superblock in superblock()) {
        let key = [0x11u8; 32];
        let bytes = superblock.encode(Some(&key)).expect("encode");
        let decoded = Superblock::decode(&bytes).expect("decode");
        prop_assert_eq!(&decoded, &superblock);
        decoded.verify_mac(&bytes, Some(&key)).expect("mac");
    }
}
