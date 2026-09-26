//! Slice S9 acceptance tests: full, incremental and differential chains,
//! delta manifests, positional scan-and-diff, the catalog and the set lock.
//!
//! The source is a real ext4 filesystem inside a sparse 1 GiB image, populated
//! with `debugfs`, so everything here runs unprivileged (spec §L.4). A 10 MiB
//! addition to a filesystem with ~50 MiB of data is the acceptance scenario:
//! the incremental must store roughly those 10 MiB plus metadata.

use std::path::{Path, PathBuf};
use std::process::Command;

use lr_core::catalog::MemberKind;
use lr_engine::backup::{BackupRequest, Compression, MemberType};
use lr_engine::catalog;
use lr_engine::keys::Encryption;
use lr_engine::keystore::Passphrase;
use lr_engine::restore::{ApplyRequest, PrepareRequest, apply_restore, prepare_restore};
use lr_engine::{ImageReport, backup_image};
use lr_store::{Destination, LocalDestination, LockOwner};

const DEVICE_SIZE: u64 = 1024 * 1024 * 1024;
const CHUNK_SIZE: u32 = 1024 * 1024;
const SET_NAME: &str = "chain-set";

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

/// Create an empty ext4 filesystem in a sparse image.
fn make_ext4(path: &Path) -> bool {
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
    true
}

/// Write (or replace) one file inside the filesystem with `debugfs`.
fn put_file(image: &Path, name: &str, contents: &[u8]) -> bool {
    let dir = tempfile::tempdir().expect("tempdir");
    let host = dir.path().join("payload");
    std::fs::write(&host, contents).expect("write payload");
    let script = dir.path().join("commands");
    std::fs::write(
        &script,
        format!("rm /{name}\nwrite {} /{name}\n", host.display()),
    )
    .expect("write script");
    run(
        "debugfs",
        &[
            "-w",
            "-f",
            &script.display().to_string(),
            &image.display().to_string(),
        ],
    )
}

/// Used byte regions of the source, chunk-aligned as the engine reads them.
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

fn request(source: &Path, dest: &Path, encryption: Encryption) -> BackupRequest {
    let mut request = BackupRequest::new(source, dest, SET_NAME, encryption).expect("request");
    request.chunk_size = CHUNK_SIZE;
    request.compression = Compression::None;
    request
}

fn stream_report(report: ImageReport) -> lr_engine::backup::BackupReport {
    match report {
        ImageReport::Block(report) => report,
        other => panic!("expected a block image, got {other:?}"),
    }
}

/// Read a member's superblock through a destination, as the engine does.
fn superblock_of(dest: &Path, path: &Path) -> lr_format::Superblock {
    let destination = LocalDestination::new(dest, SET_NAME);
    let set = destination
        .open_set(&lr_core::SetId::ZERO)
        .expect("open set");
    let name = path
        .strip_prefix(dest.join(SET_NAME))
        .expect("set-relative name")
        .to_string_lossy()
        .into_owned();
    lr_engine::chain::read_superblock(&destination, &set, &name).expect("superblock")
}

/// A 1 GiB ext4 filesystem with ~48 MiB of data.
fn populated_source(dir: &Path) -> PathBuf {
    let source = dir.join("source.img");
    assert!(make_ext4(&source), "mkfs.ext4");
    assert!(
        put_file(&source, "blob", &payload(1, 48 * 1024 * 1024)),
        "debugfs write"
    );
    source
}

#[test]
fn an_incremental_stores_only_what_changed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = populated_source(dir.path());
    let dest = dir.path().join("out");

    let full = stream_report(
        backup_image(&request(&source, &dest, Encryption::NoEncrypt)).expect("full backup"),
    );
    assert_eq!(full.member_kind, MemberKind::Full);
    assert_eq!(full.seq_in_chain, 0);
    assert_eq!(
        full.total_chunks,
        DEVICE_SIZE.div_ceil(u64::from(CHUNK_SIZE))
    );

    // Add 10 MiB: the incremental must scan everything but store only changes.
    assert!(
        put_file(&source, "added", &payload(2, 10 * 1024 * 1024)),
        "debugfs write"
    );
    let mut incremental_request = request(&source, &dest, Encryption::NoEncrypt);
    incremental_request.member_type = MemberType::Incremental;
    let incremental =
        stream_report(backup_image(&incremental_request).expect("incremental backup"));
    assert_eq!(incremental.member_kind, MemberKind::Incremental);
    assert_eq!(incremental.seq_in_chain, 1);
    assert_eq!(incremental.parent_uuid, full.image_uuid);
    assert_eq!(incremental.chain_id, full.chain_id);

    let changed_bytes = incremental.changed_chunks * u64::from(CHUNK_SIZE);
    assert!(
        (10 * 1024 * 1024..=14 * 1024 * 1024).contains(&changed_bytes),
        "a 10 MiB change stored {changed_bytes} bytes in {} chunks",
        incremental.changed_chunks
    );
    assert!(
        incremental.inherited_chunks > 900,
        "{} chunks should be inherited",
        incremental.inherited_chunks
    );
    assert!(
        incremental.image_bytes < full.image_bytes,
        "the incremental ({} bytes) must be smaller than the full ({} bytes)",
        incremental.image_bytes,
        full.image_bytes
    );

    // A second incremental with no source change stores nothing at all.
    let mut quiet_request = request(&source, &dest, Encryption::NoEncrypt);
    quiet_request.member_type = MemberType::Incremental;
    let quiet = stream_report(backup_image(&quiet_request).expect("quiet incremental"));
    assert_eq!(quiet.seq_in_chain, 2);
    assert_eq!(quiet.changed_chunks, 0, "nothing changed");
    assert!(
        quiet.image_bytes < 64 * 1024,
        "an unchanged incremental is metadata only, got {} bytes",
        quiet.image_bytes
    );
}

#[test]
fn a_restored_chain_is_byte_identical() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = populated_source(dir.path());
    let dest = dir.path().join("out");

    let full = stream_report(
        backup_image(&request(&source, &dest, Encryption::NoEncrypt)).expect("full backup"),
    );
    assert!(put_file(&source, "added", &payload(3, 10 * 1024 * 1024)));
    let mut incremental_request = request(&source, &dest, Encryption::NoEncrypt);
    incremental_request.member_type = MemberType::Incremental;
    let incremental = stream_report(backup_image(&incremental_request).expect("incremental"));
    assert_eq!(incremental.parent_uuid, full.image_uuid);

    // The plan resolves the whole chain and the token authorises it.
    let target = dir.path().join("target.img");
    sparse(&target, DEVICE_SIZE);
    let plan = prepare_restore(&PrepareRequest::from_path(
        &incremental.image_path,
        &target,
        Encryption::NoEncrypt,
    ))
    .expect("prepare");
    assert_eq!(plan.members.len(), 2, "full + incremental");
    assert!(
        plan.warnings.iter().any(|w| w.contains("chain")),
        "{:?}",
        plan.warnings
    );

    let report = apply_restore(&ApplyRequest {
        token: plan.token,
        confirm: true,
        accept_inconsistent: false,
        encryption: Encryption::NoEncrypt,
        context: lr_engine::progress::EngineContext::silent(),
    })
    .expect("apply")
    .block()
    .expect("a block restore");
    assert!(report.bytes_written > 0);

    for (start, end) in used_regions(&source) {
        assert_eq!(
            read_region(&source, start, end),
            read_region(&target, start, end),
            "used region {start}..={end} must be identical after a chain restore"
        );
    }
}

#[test]
fn a_differential_carries_every_chunk() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = populated_source(dir.path());
    let dest = dir.path().join("out");

    let full = stream_report(
        backup_image(&request(&source, &dest, Encryption::NoEncrypt)).expect("full backup"),
    );
    assert!(put_file(&source, "added", &payload(4, 2 * 1024 * 1024)));
    let mut differential_request = request(&source, &dest, Encryption::NoEncrypt);
    differential_request.member_type = MemberType::Differential;
    let differential =
        stream_report(backup_image(&differential_request).expect("differential backup"));
    assert_eq!(differential.member_kind, MemberKind::Differential);
    assert_eq!(differential.seq_in_chain, 1);
    assert!(
        differential.changed_chunks < differential.total_chunks,
        "a differential inherits unchanged chunks"
    );

    // Applying only the full plus the differential must reproduce the source.
    let target = dir.path().join("target.img");
    sparse(&target, DEVICE_SIZE);
    let plan = prepare_restore(&PrepareRequest::from_path(
        &differential.image_path,
        &target,
        Encryption::NoEncrypt,
    ))
    .expect("prepare");
    assert_eq!(plan.members.len(), 2, "{:?}", plan.members);
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
            "differential restore differs in {start}..={end}"
        );
    }
    let _ = full;
}

#[test]
fn a_second_job_on_a_locked_set_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = populated_source(dir.path());
    let dest = dir.path().join("out");

    // Hold the lock the way another job would.
    let destination = LocalDestination::new(&dest, SET_NAME);
    let handle = destination
        .open_set(&lr_core::SetId::ZERO)
        .expect("open set");
    let _lock = destination
        .lock_set(
            &handle,
            &LockOwner::local(),
            std::time::Duration::from_secs(60),
        )
        .expect("hold the lock");

    let error = backup_image(&request(&source, &dest, Encryption::NoEncrypt))
        .expect_err("a locked set must refuse the job");
    assert!(matches!(error, lr_core::Error::SetLocked { .. }), "{error}");
}

#[test]
fn a_stale_lock_can_be_broken_on_request() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = populated_source(dir.path());
    let dest = dir.path().join("out");

    let destination = LocalDestination::new(&dest, SET_NAME);
    let handle = destination
        .open_set(&lr_core::SetId::ZERO)
        .expect("open set");
    std::fs::write(
        destination.lock_path(),
        br#"{"host_id":"gone","pid":1,"created":1,"ttl_secs":1}"#,
    )
    .expect("write a stale lock");

    let mut request = request(&source, &dest, Encryption::NoEncrypt);
    request.break_stale_lock = true;
    let report = stream_report(backup_image(&request).expect("stale lock broken"));
    assert_eq!(report.member_kind, MemberKind::Full);
    let _ = handle;
}

#[test]
fn the_catalog_rebuilds_from_the_superblocks() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = populated_source(dir.path());
    let dest = dir.path().join("out");

    let full = stream_report(
        backup_image(&request(&source, &dest, Encryption::NoEncrypt)).expect("full backup"),
    );
    assert!(put_file(&source, "added", &payload(5, 2 * 1024 * 1024)));
    let mut incremental_request = request(&source, &dest, Encryption::NoEncrypt);
    incremental_request.member_type = MemberType::Incremental;
    backup_image(&incremental_request).expect("incremental");

    let destination = LocalDestination::new(&dest, SET_NAME);
    let handle = destination
        .open_set(&lr_core::SetId::ZERO)
        .expect("open set");
    let now = lr_engine::backup::now_unix();

    // The live catalog the backups wrote.
    let live = catalog::load(&destination, &handle, SET_NAME, now).expect("load");
    assert!(
        !live.rebuilt,
        "the backups wrote the catalog: {:?}",
        live.warnings
    );
    assert_eq!(live.catalog.chains.len(), 1);
    assert_eq!(live.catalog.chains[0].members.len(), 2);
    assert!(live.catalog.chains[0].is_complete());

    // A rebuild from the superblocks must describe exactly the same records.
    let rebuilt = catalog::build_catalog(
        SET_NAME,
        now,
        &catalog::scan_set(&destination, &handle).expect("scan"),
    );
    assert!(
        catalog::same_records(&live.catalog, &rebuilt),
        "rebuild differs from the live catalog:\nlive: {live:?}\nrebuilt: {rebuilt:?}"
    );
    catalog::write_catalog(&destination, &handle, &rebuilt).expect("write");
    let after = catalog::load(&destination, &handle, SET_NAME, now).expect("load");
    assert!(!after.rebuilt, "the rebuilt catalog is now accepted");
    assert_eq!(after.catalog.chains[0].members.len(), 2);
    assert_eq!(
        after.catalog.chains[0].members[1].image_uuid,
        live.catalog.chains[0].members[1].image_uuid
    );
    let _ = full;
}

#[test]
fn an_encrypted_chain_reuses_one_chain_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = populated_source(dir.path());
    let dest = dir.path().join("out");
    let encryption =
        || Encryption::Passphrase(Passphrase::new(b"correct horse battery staple".to_vec()));

    let full = stream_report(backup_image(&request(&source, &dest, encryption())).expect("full"));
    assert!(put_file(&source, "added", &payload(6, 10 * 1024 * 1024)));
    let mut incremental_request = request(&source, &dest, encryption());
    incremental_request.member_type = MemberType::Incremental;
    let incremental = stream_report(backup_image(&incremental_request).expect("incremental"));

    // The chain-level KDF salt must be identical in every member (spec §G.3).
    let full_sb = superblock_of(&dest, &full.image_path);
    let incremental_sb = superblock_of(&dest, &incremental.image_path);
    assert_eq!(full_sb.kdf_salt, incremental_sb.kdf_salt);
    assert_eq!(full_sb.chain_id, incremental_sb.chain_id);

    // A wrong passphrase must fail before anything is written.
    let target = dir.path().join("target.img");
    sparse(&target, DEVICE_SIZE);
    let error = prepare_restore(&PrepareRequest::from_path(
        &incremental.image_path,
        &target,
        Encryption::Passphrase(Passphrase::new(b"wrong".to_vec())),
    ))
    .expect_err("a wrong passphrase must not unlock the chain");
    assert!(matches!(error, lr_core::Error::Aead), "{error}");

    let plan = prepare_restore(&PrepareRequest::from_path(
        &incremental.image_path,
        &target,
        encryption(),
    ))
    .expect("prepare");
    apply_restore(&ApplyRequest {
        token: plan.token,
        confirm: true,
        accept_inconsistent: false,
        encryption: encryption(),
        context: lr_engine::progress::EngineContext::silent(),
    })
    .expect("apply");
    for (start, end) in used_regions(&source) {
        assert_eq!(
            read_region(&source, start, end),
            read_region(&target, start, end),
            "encrypted chain restore differs in {start}..={end}"
        );
    }
}

#[test]
fn a_superseded_parent_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = populated_source(dir.path());
    let dest = dir.path().join("out");

    let full =
        stream_report(backup_image(&request(&source, &dest, Encryption::NoEncrypt)).expect("full"));
    assert!(put_file(&source, "added", &payload(7, 1024 * 1024)));
    let mut incremental_request = request(&source, &dest, Encryption::NoEncrypt);
    incremental_request.member_type = MemberType::Incremental;
    backup_image(&incremental_request).expect("incremental");

    // The full is no longer the chain's newest member.
    let mut from_full = request(&source, &dest, Encryption::NoEncrypt);
    from_full.member_type = MemberType::Incremental;
    from_full.parent = Some(full.image_uuid.to_string());
    let error = backup_image(&from_full).expect_err("must refuse a superseded parent");
    assert!(error.to_string().contains("newer member"), "{error}");

    // An unknown parent is refused too.
    let mut unknown = request(&source, &dest, Encryption::NoEncrypt);
    unknown.member_type = MemberType::Incremental;
    unknown.parent = Some("11111111-1111-1111-1111-111111111111".to_owned());
    let error = backup_image(&unknown).expect_err("must refuse an unknown parent");
    assert!(error.to_string().contains("no such member"), "{error}");
}

#[test]
fn a_source_size_change_needs_a_new_chain() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = populated_source(dir.path());
    let dest = dir.path().join("out");
    backup_image(&request(&source, &dest, Encryption::NoEncrypt)).expect("full");

    // Grow the image: the positional comparison would be meaningless.
    sparse(&source, DEVICE_SIZE * 2);
    let mut incremental_request = request(&source, &dest, Encryption::NoEncrypt);
    incremental_request.member_type = MemberType::Incremental;
    let error = backup_image(&incremental_request).expect_err("must refuse a size change");
    assert!(
        error.to_string().contains("source has") || error.to_string().contains("size"),
        "{error}"
    );
}
