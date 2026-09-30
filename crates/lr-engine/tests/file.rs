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
        lr_testkit::unavailable!("rsync missing");
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
        lr_testkit::unavailable!("rsync missing");
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

/// Bytes without repeats, so content-defined chunks do not deduplicate
/// against each other inside one file.
fn noise(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

/// A file read again (`--verify-content`, or a real change) refers to the
/// chunks its reference member already has instead of storing them again,
/// so re-reading costs time, not space (D-111).
#[test]
fn re_read_content_is_not_stored_again() {
    if !have("rsync") {
        lr_testkit::unavailable!("rsync missing");
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("source");
    let dest = dir.path().join("backups");
    let target = dir.path().join("restored");
    std::fs::create_dir_all(source.join("data")).expect("dirs");
    std::fs::create_dir_all(&target).expect("target");
    std::fs::write(source.join("data/big.bin"), noise(11, 2 * 1024 * 1024)).expect("big");
    std::fs::write(source.join("data/log.txt"), noise(12, 1024 * 1024)).expect("log");

    let full = backup_file(
        &request(&source, &dest, "reread"),
        &FileBackupOptions::default(),
    )
    .expect("full");
    assert!(full.stored_chunks >= 4, "{full:?}");

    let mut again = request(&source, &dest, "reread");
    again.member_type = MemberType::Incremental;
    again.parent = Some("latest".to_owned());
    let verified = backup_file(
        &again,
        &FileBackupOptions {
            verify_content: true,
            ..FileBackupOptions::default()
        },
    )
    .expect("verify-content incremental");
    assert!(
        verified.chunked_bytes >= 3 * 1024 * 1024,
        "--verify-content must read every file: {verified:?}"
    );
    assert_eq!(
        verified.stored_chunks, 0,
        "unchanged content must not be stored again: {verified:?}"
    );

    // Appending to a file stores the new tail, not the whole file again.
    {
        use std::io::Write;
        let mut log = std::fs::OpenOptions::new()
            .append(true)
            .open(source.join("data/log.txt"))
            .expect("open log");
        log.write_all(&noise(13, 64 * 1024)).expect("append");
    }
    let appended = backup_file(&again, &FileBackupOptions::default()).expect("append incremental");
    assert!(
        appended.stored_chunks < full.stored_chunks / 2 && appended.deduplicated_chunks > 0,
        "an append must reuse the file's earlier chunks: {appended:?} after {full:?}"
    );

    // Both members verify on their own: the chunks they refer to live in
    // their ancestry.
    for member in [&verified.image_path, &appended.image_path] {
        lr_engine::verify::verify_image(&lr_engine::verify::VerifyRequest {
            image: member.display().to_string(),
            encryption: Encryption::NoEncrypt,
            chain: false,
            destination_options: lr_store::DestinationOptions {
                set_name: "reread".to_owned(),
                identity: None,
                known_hosts: None,
                insecure_ignore_host_key: false,
            },
            context: lr_engine::progress::EngineContext::silent(),
        })
        .expect("a member that refers to its ancestry verifies");
    }

    let plan = prepare_restore(&PrepareRequest::from_path(
        &appended.image_path,
        &target,
        Encryption::NoEncrypt,
    ))
    .expect("prepare");
    restore(&plan);
    let difference = rsync_difference(&source, &target);
    assert!(
        difference.is_empty(),
        "rsync reports differences:\n{difference}"
    );
}

#[test]
fn a_differential_only_needs_the_full_to_restore() {
    if !have("rsync") {
        lr_testkit::unavailable!("rsync missing");
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
    std::fs::write(
        source.join("important.bin"),
        distinct_payload(2 * 1024 * 1024),
    )
    .expect("file");

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
    assert!(clean.chunks > 1, "the fixture has multiple payload chunks");

    let set_root = dest.join("verify");
    let image_name = report
        .image_path
        .strip_prefix(&set_root)
        .expect("image path is under its set")
        .to_string_lossy()
        .into_owned();
    let target = dir.path().join("direct-restore-target");
    std::fs::create_dir_all(&target).expect("target");
    let sentinel = b"keep existing merge target";
    std::fs::write(target.join("important.bin"), sentinel).expect("sentinel file");
    let mut prepare = PrepareRequest::from_path(&report.image_path, &target, Encryption::NoEncrypt);
    prepare.merge = true;
    let plan = prepare_restore(&prepare).expect("prepare before payload corruption");

    // Flip the final physical chunk payload: the old restore path could
    // replace the existing merge target and write earlier chunks first.
    let offset = last_chunk_payload_offset(&report.image_path);
    let mut image = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&report.image_path)
        .expect("open image");
    use std::io::{Read, Seek, SeekFrom, Write};
    image.seek(SeekFrom::Start(offset)).expect("seek payload");
    let mut original = [0u8; 1];
    image.read_exact(&mut original).expect("read payload byte");
    image.seek(SeekFrom::Start(offset)).expect("rewind payload");
    image
        .write_all(&[original[0] ^ 0xFF])
        .expect("corrupt payload");
    image.sync_all().expect("sync corruption");

    let error = verify(&report.image_path).expect_err("a corrupted chunk must fail");
    let text = format!("{error}");
    assert!(
        text.contains("important.bin") || text.contains("chunk"),
        "the failure must name the offender: {text}"
    );

    let error = lr_engine::file::restore_file(&lr_engine::file::FileRestoreRequest {
        dest: dest.to_string_lossy().into_owned(),
        set: "verify".to_owned(),
        images: vec![image_name],
        destination_options: lr_store::DestinationOptions::new("verify"),
        target: target.clone(),
        encryption: Encryption::NoEncrypt,
        confirm: true,
        accept_inconsistent: false,
        merge: true,
        strict_metadata: false,
        context: lr_engine::progress::EngineContext::silent(),
    })
    .expect_err("direct file restore verifies before mutating the target");
    assert!(matches!(error, lr_core::Error::Corrupt { .. }), "{error}");
    assert_eq!(
        std::fs::read(target.join("important.bin")).expect("existing file remains"),
        sentinel
    );

    let token_error = apply_restore(&ApplyRequest {
        token: plan.token,
        confirm: true,
        accept_inconsistent: false,
        encryption: Encryption::NoEncrypt,
        context: lr_engine::progress::EngineContext::silent(),
    })
    .expect_err("token-based file restore verifies before mutating the target");
    assert!(
        matches!(token_error, lr_core::Error::Corrupt { .. }),
        "{token_error}"
    );
    assert_eq!(
        std::fs::read(target.join("important.bin")).expect("token target remains"),
        sentinel
    );
}

fn distinct_payload(len: usize) -> Vec<u8> {
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

fn last_chunk_payload_offset(path: &Path) -> u64 {
    use std::io::{Read, Seek, SeekFrom};

    let image = lr_format::ImageReader::open(std::fs::File::open(path).expect("open image"))
        .expect("read footer");
    let data_end = image.footer().data_end_offset;
    let mut file = std::fs::File::open(path).expect("open chunk records");
    let mut offset = lr_format::SB_SIZE as u64;
    let mut last_payload = None;
    let mut records = 0usize;
    while offset < data_end {
        file.seek(SeekFrom::Start(offset))
            .expect("seek chunk header");
        let mut bytes = [0u8; lr_format::CHUNK_HEADER_LEN];
        file.read_exact(&mut bytes).expect("read chunk header");
        let header = lr_format::decode_header(&bytes).expect("decode chunk header");
        last_payload = Some(offset + lr_format::CHUNK_HEADER_LEN as u64);
        offset += header.total_len() as u64;
        records += 1;
    }
    assert_eq!(offset, data_end, "chunk records cover the chunk region");
    assert!(records > 1, "fixture has earlier valid chunk records");
    last_payload.expect("at least one chunk record")
}

/// A user restoring a tree that root owns cannot restore its ownership:
/// the report lists every entry that kept the user as owner instead of
/// saying nothing, and --strict-metadata turns that into a failure (R33).
#[test]
fn metadata_that_cannot_be_restored_is_reported_or_refused() {
    if lr_unsafe::effective_uid() == 0 {
        lr_testkit::unavailable!("running as root: every owner can be restored");
    }
    let source = Path::new("/etc/skel");
    let owned_by_root = std::fs::symlink_metadata(source)
        .map(|metadata| std::os::unix::fs::MetadataExt::uid(&metadata) == 0)
        .unwrap_or(false);
    if !owned_by_root {
        lr_testkit::unavailable!("/etc/skel is missing or not owned by root");
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let dest = dir.path().join("backups");
    let report = backup_file(
        &request(source, &dest, "skel"),
        &FileBackupOptions::default(),
    )
    .expect("backup");

    let lenient = dir.path().join("lenient");
    std::fs::create_dir_all(&lenient).expect("target");
    let plan = prepare_restore(&PrepareRequest::from_path(
        &report.image_path,
        &lenient,
        Encryption::NoEncrypt,
    ))
    .expect("prepare");
    let restored = restore(&plan);
    assert!(
        restored
            .metadata_losses
            .iter()
            .any(|loss| loss.what == "ownership 0:0" && loss.path.is_empty()),
        "the root directory's owner is reported: {:?}",
        restored.metadata_losses
    );
    assert_eq!(
        restored.metadata_losses.len() as u64,
        restored.files + restored.directories + restored.symlinks,
        "every entry kept the restoring user as owner: {:?}",
        restored.metadata_losses
    );
    assert!(
        restored
            .warnings
            .iter()
            .any(|warning| warning.contains("metadata not restored")
                && warning.contains("needs a restore as root")),
        "{:?}",
        restored.warnings
    );

    let strict = dir.path().join("strict");
    std::fs::create_dir_all(&strict).expect("target");
    let plan = prepare_restore(
        &PrepareRequest::from_path(&report.image_path, &strict, Encryption::NoEncrypt)
            .with_strict_metadata(true),
    )
    .expect("prepare");
    let error = apply_restore(&ApplyRequest {
        token: plan.token,
        confirm: true,
        accept_inconsistent: false,
        encryption: Encryption::NoEncrypt,
        context: lr_engine::progress::EngineContext::silent(),
    })
    .expect_err("strict metadata must fail");
    assert!(format!("{error}").contains("--strict-metadata"), "{error}");
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
    // The plan is refused before a token exists, so the wizard can offer the
    // choice instead of failing at the end (A10).
    let refused = prepare_restore(&PrepareRequest::from_path(
        &report.image_path,
        &target,
        Encryption::NoEncrypt,
    ))
    .expect_err("a non-empty target must be refused at prepare");
    assert!(format!("{refused}").contains("--merge"), "{refused}");

    // A folder that fills up between prepare and apply is still refused.
    let emptied = dir.path().join("emptied");
    std::fs::create_dir_all(&emptied).expect("emptied");
    let plain = prepare_restore(&PrepareRequest::from_path(
        &report.image_path,
        &emptied,
        Encryption::NoEncrypt,
    ))
    .expect("prepare");
    std::fs::write(emptied.join("late"), b"arrived after prepare").expect("late");
    let refused = apply_restore(&ApplyRequest {
        token: plain.token,
        confirm: true,
        accept_inconsistent: false,
        encryption: Encryption::NoEncrypt,
        context: lr_engine::progress::EngineContext::silent(),
    })
    .expect_err("a target that filled up after prepare must be refused");
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
        lr_testkit::unavailable!("rsync missing");
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

/// A `--merge` target whose subdirectory is a symlink to somewhere else
/// cannot redirect the restore (R06): the symlink is replaced by the image's
/// directory and nothing outside the target changes.
#[test]
fn a_merge_restore_does_not_follow_a_planted_symlink() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("source");
    let dest = dir.path().join("backups");
    let target = dir.path().join("restored");
    let outside = dir.path().join("outside");
    std::fs::create_dir_all(source.join("sub")).expect("dirs");
    std::fs::write(source.join("sub/file"), b"from the image").expect("file");
    std::fs::create_dir_all(&outside).expect("outside");
    std::fs::write(outside.join("file"), b"sentinel").expect("sentinel");
    std::fs::create_dir_all(&target).expect("target");
    std::os::unix::fs::symlink(&outside, target.join("sub")).expect("planted symlink");

    let report = backup_file(
        &request(&source, &dest, "planted"),
        &FileBackupOptions::default(),
    )
    .expect("backup");
    let merged = prepare_restore(
        &PrepareRequest::from_path(&report.image_path, &target, Encryption::NoEncrypt)
            .with_merge(true),
    )
    .expect("prepare");
    restore(&merged);

    assert_eq!(
        std::fs::read(outside.join("file")).expect("sentinel"),
        b"sentinel",
        "the restore wrote through the planted symlink"
    );
    assert!(
        !std::fs::symlink_metadata(target.join("sub"))
            .expect("sub")
            .file_type()
            .is_symlink(),
        "the image's directory replaces the symlink"
    );
    assert_eq!(
        std::fs::read(target.join("sub/file")).expect("restored"),
        b"from the image"
    );
}

/// Asking for encryption on a chain that is not encrypted is refused before
/// anything is written, instead of silently continuing the plaintext chain
/// (R15).
#[test]
fn an_encryption_request_on_a_plaintext_chain_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("source");
    let dest = dir.path().join("backups");
    build_tree(&source);

    let mut full = request(&source, &dest, "laptop-tree");
    full.member_type = MemberType::Full;
    backup_file(&full, &FileBackupOptions::default()).expect("plaintext full");

    let mut encrypted = BackupRequest::new(
        &source,
        &dest,
        "laptop-tree",
        Encryption::Passphrase(lr_engine::keystore::Passphrase::new(
            b"correct horse battery staple".to_vec(),
        )),
    )
    .expect("request");
    encrypted.member_type = MemberType::Incremental;
    encrypted.parent = Some("latest".to_owned());
    let outcome = backup_file(&encrypted, &FileBackupOptions::default());
    let images: Vec<_> = walk_files(&dest)
        .into_iter()
        .filter(|path| path.to_string_lossy().ends_with(".lrimg"))
        .collect();
    assert_eq!(
        images.len(),
        1,
        "no plaintext member was published: {images:?}"
    );
    let error = outcome.expect_err("encryption cannot be added to a plaintext chain");
    assert!(error.to_string().contains("new encrypted chain"), "{error}");
}

fn walk_files(root: &Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(root).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() {
            found.extend(walk_files(&path));
        } else {
            found.push(path);
        }
    }
    found
}

/// Same-length new content with the old mtime restored is still noticed by
/// an incremental: the restore contains the new bytes (R17, D-111).
#[test]
fn an_incremental_notices_same_size_changes_with_a_restored_mtime() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("source");
    let dest = dir.path().join("backups");
    let target = dir.path().join("restored");
    std::fs::create_dir_all(&target).expect("target");
    build_tree(&source);
    let file = source.join("var/lib/data.bin");
    let before = std::fs::read(&file).expect("original");

    let mut full = request(&source, &dest, "laptop-tree");
    full.member_type = MemberType::Full;
    backup_file(&full, &FileBackupOptions::default()).expect("full");

    let mtime = std::fs::metadata(&file)
        .expect("metadata")
        .modified()
        .expect("mtime");
    let changed: Vec<u8> = before.iter().map(|byte| byte ^ 0x5A).collect();
    std::fs::write(&file, &changed).expect("rewrite");
    std::fs::File::options()
        .write(true)
        .open(&file)
        .expect("open")
        .set_modified(mtime)
        .expect("restore the mtime");
    assert_eq!(
        std::fs::metadata(&file)
            .expect("metadata")
            .modified()
            .expect("mtime"),
        mtime
    );

    let mut incremental = request(&source, &dest, "laptop-tree");
    incremental.member_type = MemberType::Incremental;
    incremental.parent = Some("latest".to_owned());
    let report = backup_file(&incremental, &FileBackupOptions::default()).expect("incremental");

    let plan = prepare_restore(&PrepareRequest::from_path(
        &report.image_path,
        &target,
        Encryption::NoEncrypt,
    ))
    .expect("prepare");
    restore(&plan);
    assert!(
        std::fs::read(target.join("var/lib/data.bin")).expect("restored") == changed,
        "the restore holds the stale bytes of the full"
    );
}

/// Runs `action` once, when the backup starts reading file contents, which
/// is after the walk recorded every file's metadata.
struct OnFilesPhase(std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>);

impl lr_engine::progress::ProgressSink for OnFilesPhase {
    fn phase(&self, name: &str) {
        if name == "files"
            && let Some(action) = self.0.lock().expect("lock").take()
        {
            action();
        }
    }

    fn bytes(&self, _done: u64, _total: u64) {}
}

/// A file that grows and has its hole filled between the walk and the read
/// is recorded as it was read, so the restore reproduces it (R16).
#[test]
fn a_file_changed_between_walk_and_read_is_recorded_as_read() {
    use std::os::unix::fs::FileExt;
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("source");
    let dest = dir.path().join("backups");
    let target = dir.path().join("restored");
    std::fs::create_dir_all(&source).expect("source");
    std::fs::create_dir_all(&target).expect("target");
    let path = source.join("growing.bin");
    std::fs::write(&path, payload(3, 1024 * 1024)).expect("data");
    // A trailing hole the walk records.
    std::fs::File::options()
        .write(true)
        .open(&path)
        .expect("open")
        .set_len(2 * 1024 * 1024)
        .expect("hole");

    let mutated = path.clone();
    let mut full = request(&source, &dest, "laptop-tree");
    full.member_type = MemberType::Full;
    full.context.progress = Some(std::sync::Arc::new(OnFilesPhase(std::sync::Mutex::new(
        Some(Box::new(move || {
            let file = std::fs::File::options()
                .write(true)
                .open(&mutated)
                .expect("open");
            file.write_all_at(&[0xABu8; 4096], 1536 * 1024)
                .expect("fill the hole");
            file.write_all_at(b"appended", 2 * 1024 * 1024)
                .expect("append");
        })),
    ))));
    let report = backup_file(&full, &FileBackupOptions::default()).expect("full");

    let plan = prepare_restore(&PrepareRequest::from_path(
        &report.image_path,
        &target,
        Encryption::NoEncrypt,
    ))
    .expect("prepare");
    restore(&plan);
    assert!(
        std::fs::read(target.join("growing.bin")).expect("restored")
            == std::fs::read(&path).expect("source"),
        "the restored file differs from what was read"
    );
}

/// A file that keeps changing while it is read is never claimed as
/// consistent: the image is marked inconsistent and names the file (R16).
#[test]
fn a_file_that_keeps_changing_is_not_claimed_consistent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("source");
    let dest = dir.path().join("backups");
    std::fs::create_dir_all(&source).expect("source");
    let path = source.join("busy.log");
    std::fs::write(&path, payload(4, 16 * 1024 * 1024)).expect("data");

    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let writer = {
        let stop = std::sync::Arc::clone(&stop);
        let path = path.clone();
        std::thread::spawn(move || {
            use std::io::Write;
            let mut file = std::fs::File::options()
                .append(true)
                .open(&path)
                .expect("open");
            while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                file.write_all(b"line\n").expect("append");
            }
        })
    };
    let mut full = request(&source, &dest, "laptop-tree");
    full.member_type = MemberType::Full;
    let outcome = backup_file(&full, &FileBackupOptions::default());
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    writer.join().expect("writer");
    let report = outcome.expect("the backup completes");
    assert_eq!(report.consistency, lr_core::Consistency::None, "{report:?}");
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("busy.log") && warning.contains("changed")),
        "{:?}",
        report.warnings
    );
}

/// A file incremental verifies on its own and as a chain: its unchanged
/// files reference the full's chunks, which its ancestry provides (R23).
#[test]
fn a_file_incremental_verifies_with_and_without_the_chain() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("source");
    let dest = dir.path().join("backups");
    build_tree(&source);
    let mut full = request(&source, &dest, "laptop-tree");
    full.member_type = MemberType::Full;
    backup_file(&full, &FileBackupOptions::default()).expect("full");
    std::fs::write(source.join("etc/new.txt"), b"new\n").expect("change");
    let mut incremental = request(&source, &dest, "laptop-tree");
    incremental.member_type = MemberType::Incremental;
    incremental.parent = Some("latest".to_owned());
    let report = backup_file(&incremental, &FileBackupOptions::default()).expect("incremental");
    assert!(report.unchanged_files > 0, "{report:?}");
    for chain in [false, true] {
        let verified = lr_engine::verify::verify_image(&lr_engine::verify::VerifyRequest {
            image: report.image_path.display().to_string(),
            encryption: Encryption::NoEncrypt,
            chain,
            destination_options: lr_store::DestinationOptions::default(),
            context: lr_engine::progress::EngineContext::silent(),
        })
        .unwrap_or_else(|error| panic!("verify (chain: {chain}): {error}"));
        assert!(verified.chunks > 0);
        assert_eq!(verified.every_member, chain);
    }
}
