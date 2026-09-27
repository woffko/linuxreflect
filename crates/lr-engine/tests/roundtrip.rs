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

/// A token is bound to the user who prepared it and is used once: another
/// uid is refused without a write, and a second apply of a used token is
/// refused (A11).
#[test]
fn a_token_is_used_once_by_the_user_who_prepared_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("source.img");
    if !make_ext4(&source, &backups()) {
        return;
    }
    let backup =
        backup_block_full(&request(&source, dir.path(), Encryption::NoEncrypt)).expect("backup");
    let target = dir.path().join("target.img");
    sparse(&target, DEVICE_SIZE);
    let owner = 4242;
    let plan = lr_engine::restore::prepare_restore_as(
        &PrepareRequest::from_path(&backup.image_path, &target, Encryption::NoEncrypt),
        owner,
    )
    .expect("prepare");
    let apply = |uid: u32| {
        lr_engine::restore::apply_restore_as(
            &ApplyRequest {
                token: plan.token.clone(),
                confirm: true,
                accept_inconsistent: false,
                encryption: Encryption::NoEncrypt,
                context: lr_engine::progress::EngineContext::silent(),
            },
            uid,
        )
    };

    let other = apply(owner + 1).expect_err("another user must be refused");
    assert!(matches!(other, lr_core::Error::Denied { .. }), "{other}");
    assert!(
        std::fs::read(&target)
            .expect("target")
            .iter()
            .all(|byte| *byte == 0),
        "a refused apply must not write"
    );

    apply(owner).expect("the owner's first apply");
    // Put the target back as it was prepared, so only the used token can
    // stop a replay.
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&target)
        .expect("reopen target");
    file.set_len(0).expect("clear");
    file.set_len(DEVICE_SIZE).expect("size");
    drop(file);
    let again = apply(owner).expect_err("a used token must be refused");
    assert!(format!("{again}").contains("already used"), "{again}");
}

/// Every file below `root` whose name ends with one of `suffixes`.
fn files_ending(root: &Path, suffixes: &[&str]) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return found;
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            found.extend(files_ending(&path, suffixes));
        } else if suffixes
            .iter()
            .any(|suffix| path.to_string_lossy().ends_with(suffix))
        {
            found.push(path);
        }
    }
    found
}

/// Plays a user who can write the destination (or the shared scratch
/// directory): once the manifest spool is complete and before it is read
/// back, every spool it can see is replaced with a forged one (R08).
struct SpoolSubstituter {
    roots: Vec<PathBuf>,
    replaced: std::sync::Mutex<Vec<PathBuf>>,
}

impl lr_engine::progress::ProgressSink for SpoolSubstituter {
    fn phase(&self, name: &str) {
        if name != "manifest" {
            return;
        }
        for root in &self.roots {
            for spool in files_ending(root, &[".spool"]) {
                let _ = std::fs::remove_file(&spool);
                std::fs::write(&spool, vec![0xEEu8; 4096]).expect("forged spool");
                self.replaced.lock().expect("lock").push(spool);
            }
        }
    }

    fn bytes(&self, _done: u64, _total: u64) {}
}

/// The manifest spool has no name anyone else can reach, so nothing can be
/// substituted between writing and reading it, and the image restores the
/// source (R08).
#[test]
fn the_manifest_spool_cannot_be_substituted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("source.img");
    if !make_ext4(&source, &backups()) {
        return;
    }
    let dest = dir.path().join("dest");
    let substituter = std::sync::Arc::new(SpoolSubstituter {
        roots: vec![
            dest.clone(),
            std::env::temp_dir().join("linuxreflect-spool"),
        ],
        replaced: std::sync::Mutex::new(Vec::new()),
    });
    let mut backup_request = request(&source, &dest, Encryption::NoEncrypt);
    backup_request.context.progress = Some(substituter.clone());
    let backup = backup_block_full(&backup_request);
    let replaced = substituter.replaced.lock().expect("lock").clone();
    assert!(
        replaced.is_empty(),
        "a spool was reachable by name and was replaced: {replaced:?}"
    );
    let backup = backup.expect("backup");

    let target = dir.path().join("target.img");
    sparse(&target, DEVICE_SIZE);
    let plan = prepare_restore(&PrepareRequest::from_path(
        &backup.image_path,
        &target,
        Encryption::NoEncrypt,
    ))
    .expect("prepare");
    apply_restore(&ApplyRequest {
        token: plan.token,
        confirm: true,
        accept_inconsistent: false,
        encryption: Encryption::NoEncrypt,
        context: lr_engine::progress::EngineContext::silent(),
    })
    .expect("apply");
    for (start, end) in used_regions(&source) {
        assert_eq!(
            read_region(&source, start, end),
            read_region(&target, start, end),
            "used region {start}..={end}"
        );
    }
}

/// Cancels the job as soon as it starts scanning, which is after the
/// manifest spool and the temporary image exist.
struct CancelOnScan(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl lr_engine::progress::ProgressSink for CancelOnScan {
    fn phase(&self, name: &str) {
        if name == "scan" {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn bytes(&self, _done: u64, _total: u64) {}
}

/// A job that fails after its spool and temporary image exist leaves
/// neither behind (R39).
#[test]
fn a_cancelled_backup_leaves_no_spool_or_temporary_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("source.img");
    if !make_ext4(&source, &backups()) {
        return;
    }
    let dest = dir.path().join("dest");
    let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut backup_request = request(&source, &dest, Encryption::NoEncrypt);
    backup_request.context.progress = Some(std::sync::Arc::new(CancelOnScan(cancel.clone())));
    backup_request.context.cancel = Some(cancel);
    let error = backup_block_full(&backup_request).expect_err("the job was cancelled");
    assert!(error.to_string().contains("cancel"), "{error}");
    let leftovers = files_ending(&dest, &[".spool", ".tmp"]);
    assert!(leftovers.is_empty(), "left behind: {leftovers:?}");
}
