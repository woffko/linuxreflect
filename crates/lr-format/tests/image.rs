//! End-to-end image tests: write, read back, tamper, truncate (spec §K S4).

mod common;

use std::io::Cursor;

use common::{DATA_KEY, DEDUP_KEY, META_KEY, build_image};
use lr_core::ImageKind;
use lr_crypto::aead::AeadKind;
use lr_crypto::page::{PAGE_OVERHEAD, StreamId};
use lr_format::{BlockEntry, BlockManifestHeader, ImageReader, open_chunk, verify_structure};

const KIND: AeadKind = AeadKind::Aes256Gcm;

fn reader(bytes: &[u8]) -> ImageReader<Cursor<&[u8]>> {
    ImageReader::open(Cursor::new(bytes)).expect("open image")
}

fn manifest_of(bytes: &[u8]) -> (BlockManifestHeader, Vec<BlockEntry>) {
    let mut image = reader(bytes);
    let stream = image
        .stream_reader(StreamId::Manifest, META_KEY, KIND)
        .expect("manifest stream");
    let mut wire = lr_format::wire::Reader::new(stream);
    let (header, delta) = BlockManifestHeader::read(&mut wire).expect("manifest header");
    assert!(!delta, "the fixture writes a full manifest");
    let mut entries = Vec::new();
    for _ in 0..header.entry_count {
        entries.push(BlockEntry::read(&mut wire).expect("entry"));
    }
    (header, entries)
}

#[test]
fn image_round_trips_and_verifies() {
    let image = build_image(8, 4096, None);

    let report = verify_structure(Cursor::new(&image.bytes), META_KEY, true).expect("verify");
    assert_eq!(report.chunks, 8);
    assert!(
        report.data_end_offset < image.bytes.len() as u64 - 4096,
        "metadata pages follow the chunk region"
    );
    assert!(report.data_end_offset >= 4096);
    assert!(report.total_pages() >= 2, "manifest and extras pages");

    let (header, entries) = manifest_of(&image.bytes);
    assert_eq!(header, image.manifest);
    assert_eq!(entries, image.entries);

    let mut image_reader = reader(&image.bytes);
    image_reader.authenticate(Some(&META_KEY)).expect("macs");
    for (index, entry) in entries.iter().enumerate() {
        assert!(entry.is_stored());
        let record = image_reader
            .read_chunk_record(entry.offset)
            .expect("chunk record");
        let plaintext = open_chunk(
            KIND,
            Some(&DATA_KEY),
            &DEDUP_KEY,
            ImageKind::Block,
            &entry.hash,
            image.chunks[index].len(),
            &record,
        )
        .expect("open chunk");
        assert_eq!(plaintext, image.chunks[index], "chunk {index}");
    }
}

#[test]
fn a_chunk_reader_can_come_from_any_handle() {
    // The engine opens a second handle through the destination, which may be a
    // local `dup` or a ranged remote reader; the codec must accept either.
    let image = build_image(4, 4096, None);
    let bytes = image.bytes.clone();
    let image_reader = reader(&bytes);
    let mut chunks = image_reader.chunk_reader_with(Box::new(Cursor::new(bytes.clone())));
    for (index, entry) in image.entries.iter().enumerate() {
        let record = chunks.read_record(entry.offset).expect("chunk record");
        let plaintext = open_chunk(
            KIND,
            Some(&DATA_KEY),
            &DEDUP_KEY,
            ImageKind::Block,
            &entry.hash,
            image.chunks[index].len(),
            &record,
        )
        .expect("open chunk");
        assert_eq!(plaintext, image.chunks[index], "chunk {index}");
    }
}

#[test]
fn tampered_flag_byte_is_rejected() {
    let image = build_image(4, 1024, None);
    let mut bytes = image.bytes.clone();
    bytes[16] ^= 0x01; // superblock flags
    assert!(
        ImageReader::open(Cursor::new(&bytes[..])).is_err(),
        "sb_hash must catch a modified flag byte"
    );
}

#[test]
fn an_attacker_who_repairs_every_unkeyed_hash_still_fails_the_macs() {
    let image = build_image(4, 1024, None);
    let mut bytes = image.bytes.clone();

    // Change a header field, then repair everything that is only a checksum:
    // sb_hash, the footer's superblock copy and footer_hash.
    bytes[166] ^= 0x01; // wrapped_chain_key
    let repaired_sb = lr_crypto::mac::unkeyed_mac32(&bytes[..1024]);
    bytes[1024..1056].copy_from_slice(&repaired_sb);

    let footer_at = bytes.len() - 4096;
    let prefix: Vec<u8> = bytes[..1024].to_vec();
    bytes[footer_at + 32..footer_at + 32 + 1024].copy_from_slice(&prefix);
    let repaired_footer = lr_crypto::mac::unkeyed_mac32(&bytes[footer_at..footer_at + 2624]);
    bytes[footer_at + 2624..footer_at + 2656].copy_from_slice(&repaired_footer);

    let image_reader = ImageReader::open(Cursor::new(&bytes[..]))
        .expect("the structure is coherent after the repairs");
    assert!(
        image_reader.authenticate(Some(&META_KEY)).is_err(),
        "sb_mac must catch a change that the checksums cannot"
    );
    assert!(
        image_reader.authenticate(Some(&[0x99; 32])).is_err(),
        "a wrong key must not verify either"
    );
    assert!(verify_structure(Cursor::new(&bytes[..]), META_KEY, true).is_err());
}

#[test]
fn truncation_is_rejected() {
    let image = build_image(4, 1024, None);

    let no_footer = &image.bytes[..image.bytes.len() - 4096];
    assert!(ImageReader::open(Cursor::new(no_footer)).is_err());

    let nearly_empty = &image.bytes[..2048];
    assert!(ImageReader::open(Cursor::new(nearly_empty)).is_err());

    let cut_middle = &image.bytes[..image.bytes.len() - 200];
    assert!(ImageReader::open(Cursor::new(cut_middle)).is_err());

    // A flipped footer MAC byte is not a structural problem: the file opens,
    // and authentication is what rejects it.
    let mut bytes = image.bytes.clone();
    let len = bytes.len();
    bytes[len - 4096 + 2656] ^= 0x01;
    let image_reader =
        ImageReader::open(Cursor::new(&bytes[..])).expect("footer_hash still matches");
    assert!(
        image_reader.authenticate(Some(&META_KEY)).is_err(),
        "footer_mac must catch the flipped byte"
    );
}

#[test]
fn a_modified_superblock_is_caught_by_the_footer_copy() {
    let image = build_image(4, 1024, None);
    let mut bytes = image.bytes.clone();
    bytes[26] ^= 0x01; // image_uuid
    let repaired = lr_crypto::mac::unkeyed_mac32(&bytes[..1024]);
    bytes[1024..1056].copy_from_slice(&repaired);
    assert!(
        ImageReader::open(Cursor::new(&bytes[..])).is_err(),
        "the footer's superblock copy must not match any more"
    );
}

#[test]
fn wrong_keys_are_rejected() {
    let image = build_image(4, 1024, None);

    let image_reader = reader(&image.bytes);
    assert!(image_reader.authenticate(Some(&[0x99; 32])).is_err());

    let mut wrong_key_image = reader(&image.bytes);
    let mut wrong_stream = wrong_key_image
        .stream_reader(StreamId::Manifest, [0x99; 32], KIND)
        .expect("stream handle");
    let mut probe = [0u8; 1];
    assert!(
        wrong_stream.read_bytes_partial(&mut probe).is_err(),
        "pages must not open under a wrong metadata key"
    );

    let mut image_reader = reader(&image.bytes);

    // A wrong content key fails chunk authentication, not just hashing.
    let entry = image.entries[0];
    let record = image_reader
        .read_chunk_record(entry.offset)
        .expect("chunk record");
    assert!(
        open_chunk(
            KIND,
            Some(&[0x77; 32]),
            &DEDUP_KEY,
            ImageKind::Block,
            &entry.hash,
            image.chunks[0].len(),
            &record,
        )
        .is_err()
    );
}

#[test]
fn a_corrupted_page_tag_is_detected() {
    let image = build_image(4, 1024, None);
    let footer = ImageReader::open(Cursor::new(&image.bytes[..]))
        .expect("open")
        .footer()
        .clone();
    let entry = footer
        .entries_for(StreamId::Manifest)
        .first()
        .copied()
        .expect("manifest page");
    let mut bytes = image.bytes.clone();
    let last_tag_byte = entry.offset as usize + PAGE_OVERHEAD + entry.len as usize - 1;
    bytes[last_tag_byte] ^= 0x01;
    assert!(verify_structure(Cursor::new(&bytes[..]), META_KEY, true).is_err());
}

#[test]
fn an_oversized_page_table_moves_to_stream_four() {
    // 400 entries do not fit in the 120 inline slots.
    let image = build_image(400, 256, Some(64));

    let image_reader = reader(&image.bytes);
    let footer = image_reader.footer();
    assert!(
        footer.page_table_in_stream4(),
        "the footer must point at the stream-4 table"
    );
    assert!(footer.page_table.len() < 120);

    let report = verify_structure(Cursor::new(&image.bytes[..]), META_KEY, true).expect("verify");
    assert_eq!(report.chunks, 400);

    let (header, entries) = manifest_of(&image.bytes);
    assert_eq!(header.entry_count, 400);
    assert_eq!(entries, image.entries);
}
