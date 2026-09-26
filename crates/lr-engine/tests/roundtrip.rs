//! End-to-end block backup and restore on image files.
//!
//! A real ext4 filesystem is created in a sparse file and populated with
//! `debugfs`, which needs no root. The same flow as the loop-device acceptance
//! test then runs: map the used blocks, back up, restore into a second file and
//! compare the used regions byte for byte.

use std::path::{Path, PathBuf};
use std::process::Command;

use lr_engine::backup::{BackupRequest, Compression};
use lr_engine::keys::Encryption;
use lr_engine::keystore::Passphrase;
use lr_engine::restore::{ApplyRequest, PrepareRequest, apply_restore, prepare_restore};
use lr_engine::{backup_block_full, resolve_passphrase};

const CHUNK_SIZE: u32 = 256 * 1024;
const DEVICE_SIZE: u64 = 64 * 1024 * 1024;

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

fn sparse(path: &Path, size: u64) {
    let file = std::fs::File::create(path).expect("create image");
    file.set_len(size).expect("size image");
    drop(file);
}

/// Create an ext4 filesystem in `path` and write `files` into it with debugfs.
fn make_ext4(path: &Path, files: &[(String, Vec<u8>)]) -> bool {
    if !have("mkfs.ext4") || !have("debugfs") {
        lr_testkit::unavailable!(return false; "mkfs.ext4 or debugfs missing");
    }
    sparse(path, DEVICE_SIZE);
    if !run(
        "mkfs.ext4",
        &["-F", "-q", "-L", "ROOTFS", &path.display().to_string()],
    ) {
        lr_testkit::fixture_failed!("mkfs.ext4 failed");
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let mut commands = String::new();
    for (index, (name, contents)) in files.iter().enumerate() {
        let host = dir.path().join(format!("payload-{index}"));
        std::fs::write(&host, contents).expect("write payload");
        commands.push_str(&format!("write {} /{name}\n", host.display()));
    }
    commands.push_str("mkdir /adir\n");
    commands.push_str("ln /file0 /hardlink0\n");
    let script = dir.path().join("commands");
    std::fs::write(&script, commands).expect("write script");
    run(
        "debugfs",
        &[
            "-w",
            "-f",
            &script.display().to_string(),
            &path.display().to_string(),
        ],
    )
}

fn payload(index: usize, len: usize) -> Vec<u8> {
    (0..len)
        .map(|byte| ((byte + index * 7) % 251) as u8)
        .collect()
}

/// Used byte regions of an ext4 file, chunk-aligned as the engine reads them.
fn used_regions(path: &Path) -> Vec<(u64, u64)> {
    let map = lr_fsmap::provider_for("ext4")
        .used_extents(path)
        .expect("used map");
    map.chunk_aligned(u64::from(CHUNK_SIZE), DEVICE_SIZE)
}

fn read_region(path: &Path, start: u64, end: u64) -> Vec<u8> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(path).expect("open");
    file.seek(SeekFrom::Start(start)).expect("seek");
    let mut buffer = vec![0u8; (end - start + 1) as usize];
    file.read_exact(&mut buffer).expect("read");
    buffer
}

/// A request with deterministic identifiers so failures are reproducible.
fn request(source: &Path, dest: &Path, encryption: Encryption) -> BackupRequest {
    let mut request = BackupRequest::new(source, dest, "laptop-root", encryption).expect("request");
    request.chunk_size = CHUNK_SIZE;
    request.compression = Compression::Zstd { level: 3 };
    request
}

fn backups() -> Vec<(String, Vec<u8>)> {
    vec![
        ("file0".to_owned(), payload(0, 1024 * 1024)),
        ("file1".to_owned(), payload(1, 512 * 1024)),
        ("sparse".to_owned(), vec![0u8; 4 * 1024 * 1024]),
    ]
}

#[test]
fn image_file_round_trips_unencrypted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("source.img");
    if !make_ext4(&source, &backups()) {
        return;
    }

    let backup =
        backup_block_full(&request(&source, dir.path(), Encryption::NoEncrypt)).expect("backup");
    assert_eq!(backup.chunk_size, CHUNK_SIZE);
    assert_eq!(
        backup.total_chunks,
        DEVICE_SIZE.div_ceil(u64::from(CHUNK_SIZE))
    );
    assert!(
        backup.stored_chunks > 0,
        "the populated filesystem has data"
    );
    assert!(
        backup.zero_chunks > 0,
        "the sparse file is recorded as zeros"
    );
    assert!(backup.used_bytes < DEVICE_SIZE, "free space is not imaged");
    assert!(
        backup.image_bytes < 100 * 1024 * 1024,
        "a 64 MiB filesystem with 5 MiB of data produced {} bytes",
        backup.image_bytes
    );
    assert!(backup.image_path.exists(), "the image was finalized");

    // Restore into a second file of the same size.
    let target = dir.path().join("target.img");
    sparse(&target, DEVICE_SIZE);
    let plan = prepare_restore(&PrepareRequest::from_path(
        &backup.image_path,
        &target,
        Encryption::NoEncrypt,
    ))
    .expect("prepare");
    assert_eq!(plan.source_size_bytes, DEVICE_SIZE);
    assert!(
        plan.warnings
            .iter()
            .any(|w| w.contains("not tamper-evident"))
    );

    let report = apply_restore(&ApplyRequest {
        token: plan.token.clone(),
        confirm: true,
        accept_inconsistent: false,
        encryption: Encryption::NoEncrypt,
        context: lr_engine::progress::EngineContext::silent(),
    })
    .expect("apply")
    .block()
    .expect("a block restore");
    assert_eq!(report.image_uuid, backup.image_uuid);
    assert_eq!(report.stored_chunks_written, backup.stored_chunks);

    for (start, end) in used_regions(&source) {
        assert_eq!(
            read_region(&source, start, end),
            read_region(&target, start, end),
            "used region {start}..={end} must be identical after restore"
        );
    }
}

#[test]
fn image_file_round_trips_with_a_passphrase() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("source.img");
    if !make_ext4(&source, &backups()) {
        return;
    }
    let key_path = dir.path().join("chain.key");
    std::fs::write(&key_path, b"correct horse battery staple\n").expect("write key");
    std::fs::set_permissions(
        &key_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .expect("chmod");
    let passphrase = resolve_passphrase(Some(&key_path)).expect("passphrase");

    let backup = backup_block_full(&request(
        &source,
        dir.path(),
        Encryption::Passphrase(Passphrase::new(passphrase.as_bytes().to_vec())),
    ))
    .expect("backup");
    assert!(backup.encrypted);

    let target = dir.path().join("target.img");
    sparse(&target, DEVICE_SIZE);
    let plan = prepare_restore(&PrepareRequest::from_path(
        &backup.image_path,
        &target,
        Encryption::Passphrase(Passphrase::new(b"wrong passphrase".to_vec())),
    ))
    .expect_err("a wrong passphrase must not unlock the image");
    assert!(matches!(plan, lr_core::Error::Aead), "{plan}");

    let plan = prepare_restore(&PrepareRequest::from_path(
        &backup.image_path,
        &target,
        Encryption::Passphrase(Passphrase::new(passphrase.as_bytes().to_vec())),
    ))
    .expect("prepare");
    // A current writer keeps metadata nonces apart, so there is no D-110
    // warning for a fresh encrypted image.
    assert!(
        !plan
            .warnings
            .iter()
            .any(|warning| warning.contains("D-110")),
        "{:?}",
        plan.warnings
    );
    let report = apply_restore(&ApplyRequest {
        token: plan.token,
        confirm: true,
        accept_inconsistent: false,
        encryption: Encryption::Passphrase(Passphrase::new(passphrase.as_bytes().to_vec())),
        context: lr_engine::progress::EngineContext::silent(),
    })
    .expect("apply")
    .block()
    .expect("a block restore");
    assert_eq!(report.stored_chunks_written, backup.stored_chunks);

    for (start, end) in used_regions(&source) {
        assert_eq!(
            read_region(&source, start, end),
            read_region(&target, start, end)
        );
    }
}

#[test]
fn restore_requires_confirmation_and_rejects_a_changed_target() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("source.img");
    if !make_ext4(&source, &backups()) {
        return;
    }
    let backup =
        backup_block_full(&request(&source, dir.path(), Encryption::NoEncrypt)).expect("backup");
    let target = dir.path().join("target.img");
    sparse(&target, DEVICE_SIZE);

    let plan = prepare_restore(&PrepareRequest::from_path(
        &backup.image_path,
        &target,
        Encryption::NoEncrypt,
    ))
    .expect("prepare");

    // Without --confirm nothing may be written.
    let refused = apply_restore(&ApplyRequest {
        token: plan.token.clone(),
        confirm: false,
        accept_inconsistent: false,
        encryption: Encryption::NoEncrypt,
        context: lr_engine::progress::EngineContext::silent(),
    })
    .expect_err("must refuse without --confirm");
    assert!(refused.to_string().contains("--confirm"), "{refused}");

    // Changing the target after prepare must invalidate the token.
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&target)
            .expect("open target");
        file.seek(SeekFrom::Start(0)).expect("seek");
        file.write_all(&[0xffu8; 4096]).expect("write");
        file.sync_all().expect("sync");
    }
    let error = apply_restore(&ApplyRequest {
        token: plan.token,
        confirm: true,
        accept_inconsistent: false,
        encryption: Encryption::NoEncrypt,
        context: lr_engine::progress::EngineContext::silent(),
    })
    .expect_err("must detect the change");
    assert!(matches!(error, lr_core::Error::TargetChanged), "{error}");
}

#[test]
fn a_tampered_token_is_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("source.img");
    if !make_ext4(&source, &backups()) {
        return;
    }
    let backup =
        backup_block_full(&request(&source, dir.path(), Encryption::NoEncrypt)).expect("backup");
    let target = dir.path().join("target.img");
    sparse(&target, DEVICE_SIZE);
    let plan = prepare_restore(&PrepareRequest::from_path(
        &backup.image_path,
        &target,
        Encryption::NoEncrypt,
    ))
    .expect("prepare");

    let mut token = lr_engine::RestoreToken::decode(&plan.token).expect("decode");
    token.target_path = PathBuf::from("/dev/attacker");
    let error = apply_restore(&ApplyRequest {
        token: token.encode(),
        confirm: true,
        accept_inconsistent: false,
        encryption: Encryption::NoEncrypt,
        context: lr_engine::progress::EngineContext::silent(),
    })
    .expect_err("must reject a moved target");
    assert!(matches!(error, lr_core::Error::Corrupt { .. }), "{error}");
}
