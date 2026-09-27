//! The permanent fault-injection suite (remediation plan, phase 4).
//!
//! Each test makes one operation fail the way a disk, a server or a network
//! would, through a `fault+<kind>:` destination (`lr-store`'s test-only
//! `fault-injection` feature), and then checks what the failure left behind
//! through the plain destination: no half-written image under a final name,
//! no temporary file, a set whose lock was released, and a report that says
//! what happened.
//!
//! | Fault | Test |
//! |---|---|
//! | writing the image | `a_failed_write_publishes_nothing` |
//! | flushing it (sync) | `a_failed_flush_publishes_nothing` |
//! | publishing it (rename) | `a_failed_publication_publishes_nothing` |
//! | the set lock's lease | `a_lost_lease_stops_the_job_before_publication` |
//! | reading an image back | `a_failed_read_fails_verify_and_restore` |
//! | a snapshot that times out | `tests/snapshot_health.rs` (R29) |
//! | a source device that fails reads | `root_hardening`'s `dm-flakey` test |
//! | writeback of a restored tree | `root_file`'s `dm-flakey` test (R34) |

use std::path::{Path, PathBuf};

use lr_engine::backup::BackupRequest;
use lr_engine::file::{FileBackupOptions, FileReport, backup_file};
use lr_engine::keys::Encryption;
use lr_engine::restore::{ApplyRequest, PrepareRequest, apply_restore, prepare_restore};

const SET: &str = "faults";

/// A tree with one file large enough to span many chunks.
fn source_tree(root: &Path) {
    std::fs::create_dir_all(root.join("docs")).expect("dirs");
    std::fs::write(root.join("docs/note.txt"), b"a small file\n").expect("note");
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let noise: Vec<u8> = (0..2 * 1024 * 1024)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect();
    std::fs::write(root.join("docs/big.bin"), noise).expect("big");
}

fn backup(source: &Path, dest: &Path, uri: Option<String>) -> lr_core::Result<FileReport> {
    let mut request = BackupRequest::new(source, dest, SET, Encryption::NoEncrypt)?;
    if let Some(uri) = uri {
        request.dest = uri;
    }
    backup_file(&request, &FileBackupOptions::default())
}

/// Every file below the set directory, relative to it.
fn files_in_set(dest: &Path) -> Vec<String> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                out.push(
                    path.strip_prefix(root)
                        .unwrap_or(&path)
                        .display()
                        .to_string(),
                );
            }
        }
    }
    let root = dest.join(SET);
    let mut out = Vec::new();
    walk(&root, &root, &mut out);
    out.sort();
    out
}

fn images(dest: &Path) -> Vec<String> {
    files_in_set(dest)
        .into_iter()
        .filter(|name| name.ends_with(".lrimg"))
        .collect()
}

/// The failed job left no image, no temporary file and no lock behind, and
/// the next backup of the set works.
fn assert_nothing_published(source: &Path, dest: &Path, what: &str) {
    let left: Vec<String> = files_in_set(dest)
        .into_iter()
        .filter(|name| name != "catalog.json")
        .collect();
    assert!(left.is_empty(), "{what}: the failed job left {left:?}");
    let next = backup(source, dest, None).unwrap_or_else(|error| {
        panic!("{what}: the next backup must work (the lock was released): {error}")
    });
    assert_eq!(images(dest).len(), 1, "{what}: {:?}", files_in_set(dest));
    verify(&next.image_path.display().to_string()).expect("the next image verifies");
}

fn verify(image: &str) -> lr_core::Result<lr_engine::verify::VerifyReport> {
    lr_engine::verify::verify_image(&lr_engine::verify::VerifyRequest {
        image: image.to_owned(),
        encryption: Encryption::NoEncrypt,
        chain: false,
        destination_options: lr_store::DestinationOptions::new(""),
        context: lr_engine::progress::EngineContext::silent(),
    })
}

struct Fixture {
    _dir: tempfile::TempDir,
    source: PathBuf,
    dest: PathBuf,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("source");
    let dest = dir.path().join("backups");
    source_tree(&source);
    std::fs::create_dir_all(&dest).expect("dest");
    Fixture {
        source,
        dest,
        _dir: dir,
    }
}

fn fault(kind: &str, dest: &Path) -> Option<String> {
    Some(format!("fault+{kind}:{}", dest.display()))
}

#[test]
fn a_failed_write_publishes_nothing() {
    let f = fixture();
    let error = backup(&f.source, &f.dest, fault("write=65536", &f.dest))
        .expect_err("a write error must fail the backup");
    assert!(
        format!("{error}").contains("injected fault: write"),
        "{error}"
    );
    assert_nothing_published(&f.source, &f.dest, "write");
}

/// A flush that fails publishes nothing (R19).
#[test]
fn a_failed_flush_publishes_nothing() {
    let f = fixture();
    let error = backup(&f.source, &f.dest, fault("sync", &f.dest))
        .expect_err("a flush error must fail the backup");
    assert!(
        format!("{error}").contains("injected fault: sync"),
        "{error}"
    );
    assert_nothing_published(&f.source, &f.dest, "sync");
}

#[test]
fn a_failed_publication_publishes_nothing() {
    let f = fixture();
    let error = backup(&f.source, &f.dest, fault("publish", &f.dest))
        .expect_err("a failed rename must fail the backup");
    assert!(
        format!("{error}").contains("injected fault: publish"),
        "{error}"
    );
    assert_nothing_published(&f.source, &f.dest, "publish");
}

/// A holder whose lease is lost stops before it publishes (R21).
#[test]
fn a_lost_lease_stops_the_job_before_publication() {
    let f = fixture();
    let error = backup(&f.source, &f.dest, fault("lease", &f.dest))
        .expect_err("a lost lease must stop the job");
    assert!(matches!(error, lr_core::Error::SetLocked { .. }), "{error}");
    assert_nothing_published(&f.source, &f.dest, "lease");
}

/// An image that cannot be read back fails verification and the restore,
/// and the restore is refused before it reports anything restored.
#[test]
fn a_failed_read_fails_verify_and_restore() {
    let f = fixture();
    let report = backup(&f.source, &f.dest, None).expect("backup");
    let faulty = |bytes: u64| format!("fault+read={bytes}:{}", report.image_path.display());

    let error = verify(&faulty(256 * 1024)).expect_err("a read error must fail verify");
    assert!(
        format!("{error}").contains("injected fault: read"),
        "{error}"
    );

    let target = f.dest.parent().expect("parent").join("restored");
    std::fs::create_dir_all(&target).expect("target");
    let outcome = prepare_restore(&PrepareRequest::new(
        faulty(256 * 1024),
        &target,
        Encryption::NoEncrypt,
    ))
    .and_then(|plan| {
        apply_restore(&ApplyRequest {
            token: plan.token,
            confirm: true,
            accept_inconsistent: true,
            encryption: Encryption::NoEncrypt,
            context: lr_engine::progress::EngineContext::silent(),
        })
    });
    let error = outcome.expect_err("a read error must fail the restore");
    assert!(
        format!("{error}").contains("injected fault: read"),
        "{error}"
    );
    // The image itself is fine.
    verify(&report.image_path.display().to_string()).expect("the image verifies");
}
