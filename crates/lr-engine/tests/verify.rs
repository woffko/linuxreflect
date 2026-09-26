//! Slice S11 acceptance test: `verify` names the offending chunk (spec §K S11).
//!
//! The source is the same unprivileged ext4 image the other tests use, so no
//! root is needed.

use std::path::{Path, PathBuf};
use std::process::Command;

use lr_engine::backup::{BackupRequest, Compression, MemberType};
use lr_engine::keys::Encryption;
use lr_engine::verify::{VerifyReport, VerifyRequest, verify_image};
use lr_engine::{ImageReport, backup_image};
use lr_store::DestinationOptions;

const DEVICE_SIZE: u64 = 64 * 1024 * 1024;
const CHUNK_SIZE: u32 = 256 * 1024;
const SET: &str = "verify-set";

fn have(program: &str) -> bool {
    Command::new("which")
        .arg(program)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn run(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn payload(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as u8
        })
        .collect()
}

fn source_image(dir: &Path) -> Option<PathBuf> {
    if !have("mkfs.ext4") || !have("debugfs") {
        lr_testkit::unavailable!(return None; "mkfs.ext4 or debugfs missing");
    }
    let source = dir.join("source.img");
    let file = std::fs::File::create(&source).expect("create");
    file.set_len(DEVICE_SIZE).expect("size");
    drop(file);
    if !run("mkfs.ext4", &["-F", "-q", &source.display().to_string()]) {
        lr_testkit::fixture_failed!("mkfs.ext4 failed");
    }
    let payload_file = dir.join("payload");
    std::fs::write(&payload_file, payload(1, 4 * 1024 * 1024)).expect("payload");
    let script = dir.join("debugfs.cmds");
    std::fs::write(&script, format!("write {} /blob\n", payload_file.display())).expect("script");
    run(
        "debugfs",
        &[
            "-w",
            "-f",
            &script.display().to_string(),
            &source.display().to_string(),
        ],
    );
    Some(source)
}

fn request(source: &Path, dest: &Path) -> BackupRequest {
    let mut request =
        BackupRequest::new(source, dest, SET, Encryption::NoEncrypt).expect("request");
    request.chunk_size = CHUNK_SIZE;
    request.compression = Compression::None;
    request
}

fn verify_request(image: &str, chain: bool) -> VerifyRequest {
    VerifyRequest {
        image: image.to_owned(),
        encryption: Encryption::NoEncrypt,
        chain,
        destination_options: DestinationOptions::new(SET),
        context: lr_engine::progress::EngineContext::silent(),
    }
}

fn backup(report: ImageReport) -> lr_engine::backup::BackupReport {
    match report {
        ImageReport::Block(report) => report,
        other => panic!("expected a block image, got {other:?}"),
    }
}

/// The first chunk record sits straight after the 4096-byte superblock; its
/// payload starts after the 19-byte record header.
fn first_chunk_payload() -> u64 {
    lr_format::SB_SIZE as u64 + 20
}

fn flip_byte(path: &Path, offset: u64) {
    use std::io::{Read, Seek, SeekFrom, Write};
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("open image");
    file.seek(SeekFrom::Start(offset)).expect("seek");
    let mut byte = [0u8; 1];
    file.read_exact(&mut byte).expect("read");
    byte[0] ^= 0x01;
    file.seek(SeekFrom::Start(offset)).expect("seek");
    file.write_all(&byte).expect("write");
    file.sync_all().expect("sync");
}

#[test]
fn a_verified_image_reports_its_content() {
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(source) = source_image(dir.path()) else {
        return;
    };
    let dest = dir.path().join("out");
    let report = backup(backup_image(&request(&source, &dest)).expect("backup"));
    let verified: VerifyReport =
        verify_image(&verify_request(&report.image_uri, false)).expect("verify");
    assert_eq!(verified.members, 1);
    assert!(verified.pages > 0, "pages are checked");
    assert!(verified.chunks > 0, "chunks are re-hashed");
    assert!(verified.bytes_checked > 0);
    // A current writer keeps metadata nonces apart (D-110).
    assert!(verified.warnings.is_empty(), "{:?}", verified.warnings);
}

#[test]
fn a_flipped_chunk_names_the_offender() {
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(source) = source_image(dir.path()) else {
        return;
    };
    let dest = dir.path().join("out");
    let report = backup(backup_image(&request(&source, &dest)).expect("backup"));
    assert!(report.stored_chunks > 0, "the fixture stores chunks");
    // Corrupt the payload, not the header: framing stays valid, only the
    // keyed hash of the plaintext can notice it.
    flip_byte(&report.image_path, first_chunk_payload());

    let error = verify_image(&verify_request(&report.image_uri, false))
        .expect_err("a flipped chunk byte must be caught");
    let text = error.to_string();
    assert!(
        text.contains("chunk 0"),
        "the report must name the chunk: {text}"
    );
    assert!(
        text.contains("hash") || text.contains("aead") || text.contains("decryption"),
        "the report must say what failed: {text}"
    );
}

#[test]
fn a_flipped_page_or_superblock_is_caught() {
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(source) = source_image(dir.path()) else {
        return;
    };
    let dest = dir.path().join("out");
    let report = backup(backup_image(&request(&source, &dest)).expect("backup"));

    // A page in the metadata region (just before the footer).
    let len = std::fs::metadata(&report.image_path).expect("stat").len();
    flip_byte(&report.image_path, len - 4096 - 64);
    let error = verify_image(&verify_request(&report.image_uri, false))
        .expect_err("a flipped page must be caught");
    assert!(
        error.to_string().contains("structure"),
        "page failure must name the member: {error}"
    );

    // And the superblock itself (the flags byte).
    let report = backup(backup_image(&request(&source, &dest)).expect("backup"));
    flip_byte(&report.image_path, 16);
    let error = verify_image(&verify_request(&report.image_uri, false))
        .expect_err("a flipped superblock must be caught");
    assert!(
        error.to_string().contains("superblock") || error.to_string().contains("checksum"),
        "{error}"
    );
}

#[test]
fn a_corrupt_chain_member_is_named() {
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(source) = source_image(dir.path()) else {
        return;
    };
    let dest = dir.path().join("out");
    let full = backup(backup_image(&request(&source, &dest)).expect("full"));
    // Change the source so the incremental stores at least one chunk.
    let payload_file = dir.path().join("payload2");
    std::fs::write(&payload_file, payload(2, 4 * 1024 * 1024)).expect("payload");
    let script = dir.path().join("debugfs2.cmds");
    std::fs::write(
        &script,
        format!("rm /blob\nwrite {} /blob\n", payload_file.display()),
    )
    .expect("script");
    run(
        "debugfs",
        &[
            "-w",
            "-f",
            &script.display().to_string(),
            &source.display().to_string(),
        ],
    );
    let mut incremental_request = request(&source, &dest);
    incremental_request.member_type = MemberType::Incremental;
    incremental_request.parent = Some("latest".to_owned());
    let incremental = backup(backup_image(&incremental_request).expect("incremental"));
    assert_eq!(incremental.seq_in_chain, 1);
    assert_ne!(incremental.image_uuid, full.image_uuid);

    flip_byte(&incremental.image_path, first_chunk_payload());

    let error = verify_image(&verify_request(&incremental.image_uri, true))
        .expect_err("a corrupt chain member must be caught");
    let text = error.to_string();
    let member = incremental
        .image_path
        .file_name()
        .expect("file name")
        .to_string_lossy()
        .into_owned();
    assert!(
        text.contains("chunk "),
        "the report must name the chunk: {text}"
    );
    assert!(
        text.contains(&member),
        "the report must name the member {member}: {text}"
    );
}
