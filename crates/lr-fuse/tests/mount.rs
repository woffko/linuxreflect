//! FUSE acceptance: `sha256sum` through the mounted view matches the source
//! (spec §K S12).
//!
//! The mount is created in a background session and unmounted when the session
//! is dropped. The test needs `/dev/fuse` and `fusermount3`; when either is
//! missing it prints why and skips, because no substitute check would prove the
//! acceptance criterion.

use std::path::Path;
use std::process::Command;

use lr_engine::backup::BackupRequest;
use lr_engine::file::{FileBackupOptions, backup_file};
use lr_engine::keys::Encryption;
use lr_engine::restore::{PrepareRequest, prepare_restore};
use lr_fuse::{FuseRequest, spawn};

fn have(program: &str) -> bool {
    Command::new("which")
        .arg(program)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn fuse_available() -> bool {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("/dev/fuse is missing; skipping the FUSE test");
        return false;
    }
    if !have("fusermount3") && !have("fusermount") {
        eprintln!("fusermount3 is missing; skipping the FUSE test");
        return false;
    }
    if !have("sha256sum") {
        eprintln!("sha256sum is missing; skipping the FUSE test");
        return false;
    }
    true
}

fn checksum(path: &Path) -> String {
    let output = Command::new("sha256sum")
        .arg(path)
        .output()
        .expect("run sha256sum");
    assert!(
        output.status.success(),
        "sha256sum {} failed: {}",
        path.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .expect("a checksum")
        .to_owned()
}

fn build_tree(root: &Path) {
    std::fs::create_dir_all(root.join("etc/nested")).expect("dirs");
    std::fs::write(root.join("etc/hostname"), b"laptop\n").expect("file");
    std::fs::write(root.join("etc/nested/big.bin"), payload(3, 700 * 1024)).expect("file");
    std::fs::write(root.join("readme"), b"hello fuse\n").expect("file");
    std::os::unix::fs::symlink("etc/hostname", root.join("hostname.link")).expect("symlink");
    std::fs::hard_link(root.join("readme"), root.join("readme.hard")).expect("hardlink");
}

fn payload(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| ((index as u8).wrapping_mul(17).wrapping_add(seed)) % 251)
        .collect()
}

#[test]
fn a_mounted_image_hashes_like_the_source() {
    if !fuse_available() {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("source");
    let dest = dir.path().join("backups");
    let mountpoint = dir.path().join("mnt");
    std::fs::create_dir_all(&source).expect("source");
    std::fs::create_dir_all(&mountpoint).expect("mountpoint");
    build_tree(&source);

    let report = backup_file(
        &BackupRequest::new(&source, &dest, "fuse-tree", Encryption::NoEncrypt).expect("request"),
        &FileBackupOptions::default(),
    )
    .expect("backup");

    // The plan names the chain members the way the image header does.
    let plan = prepare_restore(&PrepareRequest::from_path(
        &report.image_path,
        &mountpoint,
        Encryption::NoEncrypt,
    ))
    .expect("prepare");
    let session = spawn(&FuseRequest {
        dest: plan.dest.clone(),
        set: plan.set.clone(),
        images: plan.members.clone(),
        destination_options: lr_store::DestinationOptions {
            set_name: plan.set.clone(),
            identity: None,
            known_hosts: None,
            insecure_ignore_host_key: false,
        },
        encryption: Encryption::NoEncrypt,
        mountpoint: mountpoint.clone(),
    })
    .expect("mount");

    // The acceptance criterion: every file hashes the same through the mount.
    for relative in [
        "etc/hostname",
        "etc/nested/big.bin",
        "readme",
        "readme.hard",
    ] {
        let through_mount = checksum(&mountpoint.join(relative));
        let on_disk = checksum(&source.join(relative));
        assert_eq!(
            through_mount, on_disk,
            "{relative} differs through the FUSE view"
        );
    }

    // Directory listing and symlinks behave.
    let listing = std::fs::read_dir(mountpoint.join("etc"))
        .expect("readdir")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert!(listing.contains(&"hostname".to_owned()), "{listing:?}");
    assert!(listing.contains(&"nested".to_owned()), "{listing:?}");
    assert_eq!(
        std::fs::read_link(mountpoint.join("hostname.link")).expect("readlink"),
        Path::new("etc/hostname")
    );
    // A hard link shares its inode with the file it names.
    use std::os::unix::fs::MetadataExt;
    let first = std::fs::metadata(mountpoint.join("readme")).expect("stat");
    let second = std::fs::metadata(mountpoint.join("readme.hard")).expect("stat");
    assert_eq!(first.ino(), second.ino(), "hard links share an inode");
    assert_eq!(first.nlink(), 2, "the link count includes both names");

    // The view is read-only.
    let write = std::fs::write(mountpoint.join("etc/hostname"), b"changed\n");
    assert!(write.is_err(), "writing through the view must fail");

    drop(session);
    for _ in 0..50 {
        if std::fs::read_dir(&mountpoint)
            .map(|mut entries| entries.next().is_none())
            .unwrap_or(false)
        {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    eprintln!("warning: the mountpoint is still busy after the session was dropped");
}
