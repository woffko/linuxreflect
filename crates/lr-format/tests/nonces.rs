//! Nonce uniqueness across the metadata streams of one image (R01, D-110).
//!
//! Every metadata stream of an image is sealed under the same per-image
//! metadata key, so all of them share one nonce counter (spec §G.4). Each
//! stream used to start its own counter at zero instead, so
//! page 0 of the manifest and page 0 of the extras stream were sealed with the
//! same `(key, nonce)` pair. These tests read the nonces back out of a written
//! image and require every one of them to be distinct, for both AEADs.

mod common;

use lr_crypto::NONCE_LEN;
use lr_crypto::aead::AeadKind;
use lr_crypto::page::PAGE_HEADER_LEN;
use lr_format::footer::{FLAG_PAGE_TABLE_IN_STREAM4, Footer};
use lr_format::{ImageReader, ImageWriter, StreamId};
use std::collections::HashSet;
use std::io::Cursor;

use common::{META_KEY, test_superblock};

/// Write an image whose four metadata streams (manifest, hash index, extras
/// and, through overflow, the page table) each span several pages.
fn image_with_every_stream(kind: AeadKind) -> (Vec<u8>, Footer) {
    let mut superblock = test_superblock(1024 * 1024, 8);
    superblock.aead_id = kind.id();
    let cursor = Cursor::new(Vec::new());
    let mut writer =
        ImageWriter::create(cursor, &superblock, Some(&META_KEY)).expect("create writer");
    for (stream, fill) in [
        (StreamId::Manifest, 0x11u8),
        (StreamId::HashIndex, 0x22),
        (StreamId::Extras, 0x33),
    ] {
        let mut pages = writer.page_stream_with_page_len(stream, kind, META_KEY, 64);
        pages.write(&vec![fill; 64 * 60]).expect("write pages");
        pages.finish().expect("finish stream");
    }
    let (cursor, footer) = writer
        .finish(&META_KEY, Some(&META_KEY), kind)
        .expect("finish image");
    assert!(
        footer.flags & FLAG_PAGE_TABLE_IN_STREAM4 != 0,
        "the fixture must overflow into stream 4 so that it is covered too"
    );
    (cursor.into_inner(), footer)
}

fn page_nonces(bytes: &[u8], footer: &Footer, kind: AeadKind) -> Vec<(StreamId, [u8; NONCE_LEN])> {
    let mut reader = ImageReader::open(Cursor::new(bytes.to_vec())).expect("open image");
    let mut table = reader.page_table(&META_KEY, kind).expect("page table");
    // The stream-4 pages hold the table itself; the footer lists them.
    table.extend(footer.entries_for(StreamId::PageTable));
    table
        .iter()
        .map(|entry| {
            let start =
                usize::try_from(entry.offset).expect("offset") + PAGE_HEADER_LEN - NONCE_LEN;
            let nonce = bytes[start..start + NONCE_LEN].try_into().expect("nonce");
            (entry.stream, nonce)
        })
        .collect()
}

#[test]
fn every_metadata_page_of_an_image_has_its_own_nonce() {
    for kind in [AeadKind::Aes256Gcm, AeadKind::ChaCha20Poly1305] {
        let (bytes, footer) = image_with_every_stream(kind);
        let nonces = page_nonces(&bytes, &footer, kind);
        let streams: HashSet<StreamId> = nonces.iter().map(|(stream, _)| *stream).collect();
        assert_eq!(streams.len(), 4, "{kind:?}: all four streams are present");
        let mut seen = HashSet::new();
        for (stream, nonce) in &nonces {
            assert!(
                seen.insert(*nonce),
                "{kind:?}: nonce {nonce:02x?} of a {stream:?} page repeats under the same key"
            );
        }
    }
}

#[test]
fn reopening_a_stream_is_refused() {
    let superblock = test_superblock(1024 * 1024, 8);
    let cursor = Cursor::new(Vec::new());
    let mut writer =
        ImageWriter::create(cursor, &superblock, Some(&META_KEY)).expect("create writer");
    {
        let mut pages = writer.page_stream(StreamId::Extras, AeadKind::Aes256Gcm, META_KEY);
        pages.write(b"first").expect("write");
        pages.finish().expect("finish");
    }
    // A second writer for the same stream would restart at page 0, and a
    // reader could not tell its pages from the first writer's.
    let mut again = writer.page_stream(StreamId::Extras, AeadKind::Aes256Gcm, META_KEY);
    again.write(b"second").expect("buffered");
    let error = again
        .finish()
        .expect_err("a reopened stream must be refused");
    assert!(error.to_string().contains("Extras"), "{error}");
}

/// An image sealed the way writers before D-110 did it: every stream's nonce
/// counter starts at zero.
fn legacy_image(kind: AeadKind) -> Vec<u8> {
    use lr_crypto::nonce::NonceSeq;
    use lr_crypto::page::seal_page;
    use lr_format::stream::PageSink;

    let mut superblock = test_superblock(1024 * 1024, 8);
    superblock.aead_id = kind.id();
    let cursor = Cursor::new(Vec::new());
    let mut writer =
        ImageWriter::create(cursor, &superblock, Some(&META_KEY)).expect("create writer");
    for stream in [StreamId::Manifest, StreamId::Extras] {
        let mut seq = NonceSeq::new();
        let mut page = Vec::new();
        seal_page(kind, &META_KEY, stream, 0, b"legacy", &mut seq, &mut page).expect("seal");
        writer.write_page(stream, 0, &page).expect("write page");
    }
    let (cursor, _footer) = writer
        .finish(&META_KEY, Some(&META_KEY), kind)
        .expect("finish image");
    cursor.into_inner()
}

#[test]
fn images_from_before_the_fix_are_recognised() {
    for kind in [AeadKind::Aes256Gcm, AeadKind::ChaCha20Poly1305] {
        let legacy = legacy_image(kind);
        let mut reader = ImageReader::open(Cursor::new(legacy)).expect("open legacy");
        assert!(
            reader
                .has_repeated_page_nonces(&META_KEY, kind)
                .expect("inspect"),
            "{kind:?}: an old image must be flagged"
        );
        let report = lr_format::verify_structure(Cursor::new(legacy_image(kind)), META_KEY, true)
            .expect("an old image still verifies");
        assert!(report.repeated_page_nonces, "{kind:?}");

        let (current, _footer) = image_with_every_stream(kind);
        let mut reader = ImageReader::open(Cursor::new(current)).expect("open current");
        assert!(
            !reader
                .has_repeated_page_nonces(&META_KEY, kind)
                .expect("inspect"),
            "{kind:?}: a current image must not be flagged"
        );
    }
}
