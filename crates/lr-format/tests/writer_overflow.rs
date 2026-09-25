//! Regression tests for the image writer (spec §G.6, §K S17).
//!
//! The metadata page table lives in the footer while it fits in its 120 inline
//! slots and moves into a stream-4 page when it does not. That second path used
//! to demand a MAC key, so an *unencrypted* image with enough metadata pages
//! could not be written at all — which is exactly what a multi-TB disk produces
//! (found by the 16 TB scaling test, D-096).

mod common;

use lr_core::Consistency;
use lr_crypto::aead::AeadKind;
use lr_format::footer::FLAG_PAGE_TABLE_IN_STREAM4;
use lr_format::{ImageReader, ImageWriter, StreamId, flags};
use std::io::Cursor;

use common::{META_KEY, test_superblock};

#[test]
fn an_unencrypted_image_survives_a_page_table_overflow() {
    let mut superblock = test_superblock(1024 * 1024, 8);
    // The helper builds an encrypted superblock; this test is about the
    // unencrypted path, where the writer has no MAC key.
    superblock.flags &= !flags::ENCRYPTED;
    superblock.consistency = Consistency::Offline;
    // An unencrypted image records no KDF (the engine writes 0 as well).
    superblock.kdf_id = 0;

    let cursor = Cursor::new(Vec::new());
    let mut writer =
        ImageWriter::create(cursor, &superblock, None).expect("create an unencrypted writer");
    {
        // 64-byte pages: a few kilobytes of metadata overflow the footer.
        let mut stream =
            writer.page_stream_with_page_len(StreamId::Manifest, AeadKind::Aes256Gcm, META_KEY, 64);
        stream.write(&vec![0x11u8; 16 * 1024]).expect("write pages");
        stream.finish().expect("finish the stream");
    }
    let (cursor, footer) = writer
        .finish(&META_KEY, None, AeadKind::Aes256Gcm)
        .expect("an unencrypted image must finish");
    assert_ne!(
        footer.flags & FLAG_PAGE_TABLE_IN_STREAM4,
        0,
        "the page table was expected to overflow the footer"
    );

    // The image authenticates without a MAC key and its pages are readable
    // through the stream-4 page table.
    let bytes = cursor.into_inner();
    let mut reader = ImageReader::open(Cursor::new(bytes)).expect("open the image");
    reader
        .authenticate(None)
        .expect("unencrypted authentication");
    let mut page = reader
        .stream_reader(StreamId::Manifest, META_KEY, AeadKind::Aes256Gcm)
        .expect("a reader over the overflowed page table");
    let mut buffer = vec![0u8; 64];
    let read = page.read_bytes_partial(&mut buffer).expect("read a page");
    assert_eq!(read, 64);
    assert!(buffer.iter().all(|byte| *byte == 0x11));
}
