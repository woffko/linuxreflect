//! Delta-manifest tests (spec §D.4, §G.2, §G.7).

mod common;

use std::io::Cursor;

use common::{META_KEY, build_custom_image, test_superblock};
use lr_crypto::aead::AeadKind;
use lr_crypto::page::StreamId;
use lr_format::{
    BlockEntry, BlockManifestHeader, ChunkState, DeltaEntry, ImageReader, STATE_STORED, STATE_ZERO,
    apply_delta,
};

const KIND: AeadKind = AeadKind::Aes256Gcm;

fn stored(member: u16, seed: u8, offset: u64) -> BlockEntry {
    BlockEntry::stored(member, [seed; 32], offset, 1024).expect("stored entry")
}

#[test]
fn apply_delta_overwrites_only_the_listed_chunks() {
    let mut parent = vec![
        ChunkState::Stored {
            member: 0,
            hash: [0x01; 32],
            offset: 4096,
            stored_len: 1024,
        },
        ChunkState::Zero,
        ChunkState::Stored {
            member: 0,
            hash: [0x02; 32],
            offset: 5120,
            stored_len: 1024,
        },
        ChunkState::Unused,
        ChunkState::Stored {
            member: 0,
            hash: [0x03; 32],
            offset: 6144,
            stored_len: 1024,
        },
    ];
    let delta = vec![
        DeltaEntry {
            chunk_no: 1,
            entry: stored(1, 0xAA, 7168),
        },
        DeltaEntry {
            chunk_no: 3,
            entry: BlockEntry::zero(),
        },
    ];

    apply_delta(&mut parent, &delta).expect("apply");

    assert!(matches!(
        parent[0],
        ChunkState::Stored { hash, .. } if hash == [0x01; 32]
    ));
    assert!(matches!(parent[1], ChunkState::Stored { member: 1, .. }));
    assert!(matches!(
        parent[2],
        ChunkState::Stored { hash, .. } if hash == [0x02; 32]
    ));
    assert_eq!(parent[3], ChunkState::Zero);
    assert!(matches!(
        parent[4],
        ChunkState::Stored { hash, .. } if hash == [0x03; 32]
    ));
}

#[test]
fn delta_entries_cannot_point_past_the_parent() {
    let mut parent = vec![ChunkState::Unused; 2];
    let delta = vec![DeltaEntry {
        chunk_no: 2,
        entry: stored(0, 0x11, 4096),
    }];
    assert!(apply_delta(&mut parent, &delta).is_err());
}

#[test]
fn a_delta_manifest_stores_only_changed_chunks() {
    // The parent image has five chunks; the delta changes two of them.
    let mut superblock = test_superblock(lr_format::MIN_CHUNK_SIZE, 5);
    superblock.flags |= lr_format::flags::DELTA_MANIFEST;
    let delta_entries = vec![
        DeltaEntry {
            chunk_no: 1,
            entry: stored(1, 0xB1, 8192),
        },
        DeltaEntry {
            chunk_no: 4,
            entry: BlockEntry::zero(),
        },
    ];

    let bytes = build_custom_image(&superblock, |stream| {
        let header = BlockManifestHeader {
            chunk_size: lr_format::MIN_CHUNK_SIZE,
            chunk_count: 5,
            entry_count: delta_entries.len() as u64,
            used_extent_count: 1,
            used_bytes: 4096,
            fs_type: "ext4".to_owned(),
            fs_uuid: String::new(),
            label: String::new(),
        };
        header.write(stream, true)?;
        for entry in &delta_entries {
            entry.write(stream)?;
        }
        Ok(())
    });

    let mut image = ImageReader::open(Cursor::new(&bytes[..])).expect("open");
    image.authenticate(Some(&META_KEY)).expect("macs");
    assert!(
        image.superblock().is_delta_manifest(),
        "the superblock flag must record a delta manifest"
    );

    let stream = image
        .stream_reader(StreamId::Manifest, META_KEY, KIND)
        .expect("manifest stream");
    let mut wire = lr_format::wire::Reader::new(stream);
    let (header, delta) = BlockManifestHeader::read(&mut wire).expect("header");
    assert!(delta);
    assert_eq!(header.chunk_count, 5);
    assert_eq!(header.entry_count, 2);

    let mut read_back = Vec::new();
    for _ in 0..header.entry_count {
        read_back.push(DeltaEntry::read(&mut wire).expect("delta entry"));
    }
    assert_eq!(read_back, delta_entries);

    // Only the changed chunk numbers appear; everything else inherits from the
    // parent state (spec §G.2).
    let changed: Vec<u64> = read_back.iter().map(|entry| entry.chunk_no).collect();
    assert_eq!(changed, vec![1, 4]);
    assert!(read_back[0].entry.is_stored());
    assert_eq!(read_back[1].entry.state, STATE_ZERO);
    assert_eq!(read_back[0].entry.state, STATE_STORED);
}

#[test]
fn a_delta_with_a_full_entry_count_is_still_readable() {
    // Guard against a writer that sets delta_manifest but writes a full
    // manifest: the header carries the truth for section_kind.
    let superblock = test_superblock(lr_format::MIN_CHUNK_SIZE, 2);
    let bytes = build_custom_image(&superblock, |stream| {
        let header = BlockManifestHeader {
            chunk_size: lr_format::MIN_CHUNK_SIZE,
            chunk_count: 2,
            entry_count: 2,
            used_extent_count: 1,
            used_bytes: 2048,
            fs_type: "xfs".to_owned(),
            fs_uuid: String::new(),
            label: String::new(),
        };
        header.write(stream, false)?;
        stored(0, 0x01, 4096).write(stream)?;
        BlockEntry::unused().write(stream)?;
        Ok(())
    });

    let mut image = ImageReader::open(Cursor::new(&bytes[..])).expect("open");
    let stream = image
        .stream_reader(StreamId::Manifest, META_KEY, KIND)
        .expect("manifest stream");
    let mut wire = lr_format::wire::Reader::new(stream);
    let (header, delta) = BlockManifestHeader::read(&mut wire).expect("header");
    assert!(!delta, "a full manifest stays a full manifest");
    assert_eq!(header.fs_type, "xfs");
    let first = BlockEntry::read(&mut wire).expect("entry");
    let second = BlockEntry::read(&mut wire).expect("entry");
    assert_eq!(first.state, STATE_STORED);
    assert_eq!(second.state, lr_format::STATE_UNUSED);
}
