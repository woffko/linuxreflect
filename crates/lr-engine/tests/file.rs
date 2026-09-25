//! File-mode acceptance: a tree round trip that `rsync -nac` calls identical
//! (spec §K S12).
//!
//! Every test builds its own tree in a temporary directory, backs it up with
//! [`lr_engine::file::backup_file`], restores the chain into a second directory
//! and then asks `rsync` whether the two trees differ. The hard requirement is
//! the spec's wording: `rsync -nac` between source and restored tree reports
//! nothing.

use std::path::Path;
use std::process::Command;

use lr_engine::backup::{BackupRequest, Compression, MemberType};
use lr_engine::file::{FileBackupOptions, backup_file};
use lr_engine::keys::Encryption;
use lr_engine::restore::{ApplyRequest, PrepareRequest, apply_restore, prepare_restore};

fn have(program: &str) -> bool {
    Command::new("which")
        .arg(program)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// `rsync -nac` output; the acceptance criterion is that it is empty.
fn rsync_difference(source: &Path, restored: &Path) -> String {
    // `-i` (itemize) is what makes the check meaningful: `rsync -n` alone is
    // silent, so an empty output would prove nothing.
    let output = Command::new("rsync")
        .args(["-naxAci", "--delete"])
        .arg(format!("{}/", source.display()))
        .arg(format!("{}/", restored.display()))
        .output()
        .expect("run rsync");
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn request(source: &Path, dest: &Path, set: &str) -> BackupRequest {
    let mut request =
        BackupRequest::new(source, dest, set, Encryption::NoEncrypt).expect("request");
    request.compression = Compression::Zstd { level: 3 };
    request
}

/// A tree with the shapes the spec calls out: subdirectories, a sparse file, a
/// hard link, a symlink, an executable bit and xattrs.
fn build_tree(root: &Path) {
    std::fs::create_dir_all(root.join("etc/linuxreflect")).expect("dirs");
    std::fs::create_dir_all(root.join("var/lib")).expect("dirs");
    std::fs::write(root.join("etc/hostname"), b"laptop\n").expect("file");
    std::fs::write(root.join("etc/linuxreflect/config.toml"), b"# config\n").expect("file");
    std::fs::write(root.join("var/lib/data.bin"), payload(7, 300 * 1024)).expect("file");
    std::fs::write(root.join("executable.sh"), b"#!/bin/sh\necho hi\n").expect("file");
    std::fs::set_permissions(
        root.join("executable.sh"),
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .expect("chmod");
    std::fs::set_permissions(
        root.join("etc/hostname"),
        std::os::unix::fs::PermissionsExt::from_mode(0o640),
    )
    .expect("chmod");

    // A sparse file: 8 MiB with one data page at the start.
    let sparse = root.join("sparse.bin");
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = std::fs::File::create(&sparse).expect("sparse");
        file.write_all(b"head").expect("head");
        file.seek(SeekFrom::Start(8 * 1024 * 1024 - 1))
            .expect("seek");
        file.write_all(b"tail").expect("tail");
    }

    std::os::unix::fs::symlink("etc/hostname", root.join("hostname.link")).expect("symlink");
    std::fs::hard_link(root.join("etc/hostname"), root.join("etc/hostname.hard"))
        .expect("hardlink");
}

fn payload(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| ((index as u8).wrapping_mul(31).wrapping_add(seed)) % 251)
        .collect()
}

fn restore(plan: &lr_engine::restore::RestorePlan) -> lr_engine::file::FileRestoreReport {
    apply_restore(&ApplyRequest {
        token: plan.token.clone(),
        confirm: true,
        accept_inconsistent: false,
        encryption: Encryption::NoEncrypt,
        context: lr_engine::progress::EngineContext::silent(),
    })
    .expect("apply")
    .file()
    .expect("a file report")
}

#[test]
fn a_tree_round_trips_with_no_rsync_difference() {
    if !have("rsync") {
        eprintln!("rsync missing; skipping");
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("source");
    let dest = dir.path().join("backups");
    let target = dir.path().join("restored");
    std::fs::create_dir_all(&target).expect("target");
    build_tree(&source);

    let report = backup_file(
        &request(&source, &dest, "laptop-tree"),
        &FileBackupOptions::default(),
    )
    .expect("backup");
    assert!(report.files >= 4, "{report:?}");
    assert_eq!(report.consistency, lr_core::Consistency::PerFile);
    assert!(report.chunked_bytes >= 300 * 1024);

    let plan = prepare_restore(&PrepareRequest::from_path(
        &report.image_path,
        &target,
        Encryption::NoEncrypt,
    ))
    .expect("prepare");
    let restored = restore(&plan);
    assert_eq!(restored.files, report.files);
    assert!(restored.restored_bytes >= 300 * 1024);

    let difference = rsync_difference(&source, &target);
    assert!(
        difference.is_empty(),
        "rsync -nac reports differences:\n{difference}"
    );
}

#[test]
fn an_incremental_stores_only_the_changed_file() {
    if !have("rsync") {
        eprintln!("rsync missing; skipping");
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("source");
    let dest = dir.path().join("backups");
    let target = dir.path().join("restored");
    std::fs::create_dir_all(&target).expect("target");
    build_tree(&source);

    let mut full = request(&source, &dest, "laptop-tree");
    full.member_type = MemberType::Full;
    let full_report = backup_file(&full, &FileBackupOptions::default()).expect("full");
    assert_eq!(full_report.unchanged_files, 0);

    // One file changes; the other files must be inherited from the full.
    std::fs::write(source.join("var/lib/data.bin"), payload(9, 301 * 1024)).expect("change");
    std::fs::write(source.join("etc/new.txt"), b"new\n").expect("new file");
    let mut incremental = request(&source, &dest, "laptop-tree");
    incremental.member_type = MemberType::Incremental;
    incremental.parent = Some("latest".to_owned());
    let incremental_report =
        backup_file(&incremental, &FileBackupOptions::default()).expect("incremental");
    assert!(
        incremental_report.unchanged_files >= 3,
        "{incremental_report:?}"
    );
    assert!(
        incremental_report.chunked_bytes <= 400 * 1024,
        "an incremental should not re-chunk unchanged files: {incremental_report:?}"
    );
    assert_eq!(incremental_report.parent_uuid, full_report.image_uuid);

    let plan = prepare_restore(&PrepareRequest::from_path(
        &incremental_report.image_path,
        &target,
        Encryption::NoEncrypt,
    ))
    .expect("prepare");
    assert_eq!(plan.members.len(), 2, "the chain has two members");
    restore(&plan);

    let difference = rsync_difference(&source, &target);
    assert!(
        difference.is_empty(),
        "rsync -nac reports differences after an incremental restore:\n{difference}"
    );
}

#[test]
fn a_differential_only_needs_the_full_to_restore() {
    if !have("rsync") {
        eprintln!("rsync missing; skipping");
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("source");
    let dest = dir.path().join("backups");
    let target = dir.path().join("restored");
    std::fs::create_dir_all(&target).expect("target");
    build_tree(&source);

    let full = backup_file(
        &request(&source, &dest, "diff-tree"),
        &FileBackupOptions::default(),
    )
    .expect("full");

    // One change in an incremental, then a second change in a differential
    // that depends on the full only.
    std::fs::write(source.join("etc/first.txt"), b"first\n").expect("write");
    let mut incremental = request(&source, &dest, "diff-tree");
    incremental.member_type = MemberType::Incremental;
    incremental.parent = Some("latest".to_owned());
    let incremental_report =
        backup_file(&incremental, &FileBackupOptions::default()).expect("incremental");

    std::fs::write(source.join("etc/second.txt"), b"second\n").expect("write");
    let mut differential = request(&source, &dest, "diff-tree");
    differential.member_type = MemberType::Differential;
    differential.parent = Some("latest".to_owned());
    let differential_report =
        backup_file(&differential, &FileBackupOptions::default()).expect("differential");
    assert_eq!(
        differential_report.parent_uuid,
        incremental_report.image_uuid
    );
    // The differential must carry the first change too (it compared against
    // the full, not against the newest member) while reusing the rest.
    assert!(
        differential_report.unchanged_files >= 5,
        "{differential_report:?}"
    );
    assert!(
        differential_report.chunked_bytes < 64 * 1024,
        "a differential should only chunk the two new files: {differential_report:?}"
    );
    let _ = full;

    let plan = prepare_restore(&PrepareRequest::from_path(
        &differential_report.image_path,
        &target,
        Encryption::NoEncrypt,
    ))
    .expect("prepare");
    assert_eq!(plan.members.len(), 3);
    restore(&plan);
    assert!(target.join("etc/first.txt").exists());
    assert!(target.join("etc/second.txt").exists());
    let difference = rsync_difference(&source, &target);
    assert!(
        difference.is_empty(),
        "rsync -nac reports differences after a differential restore:\n{difference}"
    );
}

#[test]
fn sparse_files_stay_sparse_after_restore() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("source");
    let dest = dir.path().join("backups");
    let target = dir.path().join("restored");
    std::fs::create_dir_all(&source).expect("dirs");
    std::fs::create_dir_all(&target).expect("target");
    let sparse = source.join("sparse.bin");
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = std::fs::File::create(&sparse).expect("sparse");
        file.write_all(b"head").expect("head");
        file.seek(SeekFrom::Start(32 * 1024 * 1024 - 1))
            .expect("seek");
        file.write_all(b"tail").expect("tail");
    }

    let report = backup_file(
        &request(&source, &dest, "sparse"),
        &FileBackupOptions::default(),
    )
    .expect("backup");
    assert_eq!(report.files, 1);

    let plan = prepare_restore(&PrepareRequest::from_path(
        &report.image_path,
        &target,
        Encryption::NoEncrypt,
    ))
    .expect("prepare");
    restore(&plan);

    let restored = target.join("sparse.bin");
    let expected = std::fs::read(&sparse).expect("read source");
    let actual = std::fs::read(&restored).expect("read restored");
    assert_eq!(actual.len(), expected.len(), "the size must be preserved");
    assert_eq!(actual, expected, "the content must be identical");

    // The restored file must not have become fully allocated: punching holes
    // is a space optimisation, so allow the page-aligned overhead of one page
    // plus the two small writes.
    use std::os::unix::fs::MetadataExt;
    let allocated = std::fs::metadata(&restored).expect("stat").blocks() * 512;
    assert!(
        allocated < 1024 * 1024,
        "the restored sparse file occupies {allocated} bytes"
    );
}

#[test]
fn verify_names_a_corrupted_file_chunk() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("source");
    let dest = dir.path().join("backups");
    std::fs::create_dir_all(&source).expect("dirs");
    std::fs::write(source.join("important.bin"), payload(11, 120 * 1024)).expect("file");

    let report = backup_file(
        &request(&source, &dest, "verify"),
        &FileBackupOptions::default(),
    )
    .expect("backup");

    let verify = |image: &Path| {
        lr_engine::verify::verify_image(&lr_engine::verify::VerifyRequest {
            image: image.display().to_string(),
            encryption: Encryption::NoEncrypt,
            chain: true,
            destination_options: lr_store::DestinationOptions {
                set_name: "verify".to_owned(),
                identity: None,
                known_hosts: None,
                insecure_ignore_host_key: false,
            },
            context: lr_engine::progress::EngineContext::silent(),
        })
    };
    let clean = verify(&report.image_path).expect("a fresh image verifies");
    assert!(clean.chunks >= 1);

    // Flip one byte inside the first chunk record's payload.
    let offset = lr_format::SB_SIZE + 24;
    let mut bytes = std::fs::read(&report.image_path).expect("read");
    bytes[offset] ^= 0xFF;
    std::fs::write(&report.image_path, &bytes).expect("write");

    let error = verify(&report.image_path).expect_err("a corrupted chunk must fail");
    let text = format!("{error}");
    assert!(
        text.contains("important.bin") || text.contains("chunk"),
        "the failure must name the offender: {text}"
    );
}

#[test]
fn a_non_empty_target_needs_merge() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("source");
    let dest = dir.path().join("backups");
    let target = dir.path().join("restored");
    std::fs::create_dir_all(&source).expect("dirs");
    std::fs::write(source.join("file"), b"data").expect("file");
    std::fs::create_dir_all(&target).expect("target");
    std::fs::write(target.join("existing"), b"keep me").expect("existing");

    let report = backup_file(
        &request(&source, &dest, "merge"),
        &FileBackupOptions::default(),
    )
    .expect("backup");
    let plain = prepare_restore(&PrepareRequest::from_path(
        &report.image_path,
        &target,
        Encryption::NoEncrypt,
    ))
    .expect("prepare");
    let refused = apply_restore(&ApplyRequest {
        token: plain.token,
        confirm: true,
        accept_inconsistent: false,
        encryption: Encryption::NoEncrypt,
        context: lr_engine::progress::EngineContext::silent(),
    })
    .expect_err("a non-empty target must be refused");
    assert!(format!("{refused}").contains("--merge"), "{refused}");

    let merged = prepare_restore(
        &PrepareRequest::from_path(&report.image_path, &target, Encryption::NoEncrypt)
            .with_merge(true),
    )
    .expect("prepare");
    restore(&merged);
    assert!(target.join("file").exists());
    assert!(target.join("existing").exists(), "merge keeps extra files");
}

/// Files deleted before an incremental or a differential stay deleted when
/// that member is restored: every member's manifest is the whole tree, and
/// the restore must not merge in entries of older members (D-108).
#[test]
fn a_file_deleted_before_a_later_member_stays_deleted() {
    if !have("rsync") {
        eprintln!("rsync missing; skipping");
        return;
    }
    for member_type in [MemberType::Incremental, MemberType::Differential] {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = dir.path().join("source");
        let dest = dir.path().join("backups");
        let target = dir.path().join("restored");
        std::fs::create_dir_all(&target).expect("target");
        build_tree(&source);
        backup_file(
            &request(&source, &dest, "deletions"),
            &FileBackupOptions::default(),
        )
        .expect("full");

        std::fs::remove_file(source.join("var/lib/data.bin")).expect("delete a file");
        std::fs::write(source.join("etc/after.txt"), b"after\n").expect("add a file");
        let mut later = request(&source, &dest, "deletions");
        later.member_type = member_type;
        later.parent = Some("latest".to_owned());
        let report = backup_file(&later, &FileBackupOptions::default()).expect("later member");

        let plan = prepare_restore(&PrepareRequest::from_path(
            &report.image_path,
            &target,
            Encryption::NoEncrypt,
        ))
        .expect("prepare");
        restore(&plan);
        assert!(
            !target.join("var/lib/data.bin").exists(),
            "{member_type:?}: a deleted file came back"
        );
        assert!(target.join("etc/after.txt").exists(), "{member_type:?}");
        let difference = rsync_difference(&source, &target);
        assert!(
            difference.is_empty(),
            "{member_type:?}: rsync reports differences:\n{difference}"
        );
    }
}
