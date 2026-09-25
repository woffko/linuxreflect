//! Root-gated file-mode acceptance (spec §K S12).
//!
//! These need privileges: device nodes, ownership changes and (for the
//! snapshot test) mounting a Btrfs filesystem. Run with `LR_ROOT_TESTS=1` as
//! root; every test skips with a printed reason when its tools are missing.

use std::path::Path;
use std::process::Command;

use lr_engine::backup::{BackupRequest, MemberType};
use lr_engine::file::{FileBackupOptions, backup_file};
use lr_engine::keys::Encryption;
use lr_engine::restore::{ApplyRequest, PrepareRequest, apply_restore, prepare_restore};

fn root_tests_enabled() -> bool {
    if std::env::var("LR_ROOT_TESTS").as_deref() != Ok("1") {
        eprintln!("LR_ROOT_TESTS != 1; skipping");
        return false;
    }
    let uid = Command::new("id")
        .arg("-u")
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .unwrap_or_default();
    if uid != "0" {
        eprintln!("not running as root (uid {uid}); skipping");
        return false;
    }
    true
}

fn have(program: &str) -> bool {
    Command::new("which")
        .arg(program)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn run(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

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

fn restore_into(plan: &lr_engine::restore::RestorePlan) -> lr_engine::file::FileRestoreReport {
    apply_restore(&ApplyRequest {
        token: plan.token.clone(),
        confirm: true,
        accept_inconsistent: true,
        encryption: Encryption::NoEncrypt,
        context: lr_engine::progress::EngineContext::silent(),
    })
    .expect("apply")
    .file()
    .expect("a file report")
}

fn round_trip(
    source: &Path,
    dest: &Path,
    target: &Path,
    options: &FileBackupOptions,
) -> (
    lr_engine::file::FileReport,
    lr_engine::file::FileRestoreReport,
) {
    let report = backup_file(
        &BackupRequest::new(source, dest, "root-tree", Encryption::NoEncrypt).expect("request"),
        options,
    )
    .expect("backup");
    let plan = prepare_restore(&PrepareRequest::from_path(
        &report.image_path,
        target,
        Encryption::NoEncrypt,
    ))
    .expect("prepare");
    let restored = restore_into(&plan);
    (report, restored)
}

#[test]
#[ignore = "requires root: device nodes, chown and rsync -a"]
fn device_nodes_ownership_and_xattrs_round_trip() {
    if !root_tests_enabled() {
        return;
    }
    for tool in ["rsync", "mkfifo", "setfacl", "getfacl"] {
        if !have(tool) {
            eprintln!("{tool} missing; skipping");
            return;
        }
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("source");
    let dest = dir.path().join("backups");
    let target = dir.path().join("restored");
    std::fs::create_dir_all(source.join("devices")).expect("dirs");
    std::fs::create_dir_all(&target).expect("target");
    std::fs::write(source.join("root-owned"), b"root data").expect("file");
    // A second owner, to prove ownership is restored, not inherited.
    lr_unsafe::filemeta::lchown(&source.join("root-owned"), 65534, 65534).expect("chown");
    lr_unsafe::filemeta::set_xattr(&source.join("root-owned"), b"user.lrtest", b"value")
        .expect("setxattr");
    // A POSIX ACL travels as the `system.posix_acl_access` xattr.
    assert!(run(
        "setfacl",
        &[
            "-m",
            "u:65534:r--",
            &source.join("root-owned").display().to_string(),
        ],
    ));
    assert!(run("mkfifo", &[&source.join("fifo").display().to_string()]));
    lr_unsafe::filemeta::mknod(
        &source.join("devices/null"),
        libc::S_IFCHR | 0o666,
        libc::makedev(1, 3),
    )
    .expect("mknod");

    let (report, restored) = round_trip(&source, &dest, &target, &FileBackupOptions::default());
    assert_eq!(report.files, 1);
    assert_eq!(report.specials, 2, "a fifo and a character device");

    use std::os::unix::fs::MetadataExt;
    let copied = std::fs::metadata(target.join("root-owned")).expect("stat");
    assert_eq!((copied.uid(), copied.gid()), (65534, 65534));
    assert_eq!(
        lr_unsafe::filemeta::get_xattr(&target.join("root-owned"), b"user.lrtest")
            .expect("getxattr"),
        b"value"
    );
    let device = std::fs::symlink_metadata(target.join("devices/null")).expect("stat");
    assert_eq!(device.rdev(), libc::makedev(1, 3));
    assert_eq!(device.mode() & 0o170000, libc::S_IFCHR);
    let fifo = std::fs::symlink_metadata(target.join("fifo")).expect("stat");
    assert_eq!(fifo.mode() & 0o170000, libc::S_IFIFO);

    let acl = Command::new("getfacl")
        .args(["--omit-header", "-p"])
        .arg(target.join("root-owned"))
        .output()
        .expect("getfacl");
    let acl = String::from_utf8_lossy(&acl.stdout);
    assert!(
        acl.contains("user:nobody:r--") || acl.contains("user:65534:r--"),
        "the ACL must survive the round trip: {acl}"
    );

    let difference = rsync_difference(&source, &target);
    assert!(
        difference.is_empty(),
        "rsync -naxAci reports:\n{difference}"
    );
    assert!(restored.restored_bytes >= 9);
}

#[test]
#[ignore = "requires root: mounts a tmpfs to cross a filesystem boundary"]
fn one_file_system_does_not_cross_a_mount() {
    if !root_tests_enabled() {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("source");
    std::fs::create_dir_all(source.join("inside")).expect("dirs");
    std::fs::create_dir_all(source.join("mounted")).expect("mountpoint");
    std::fs::write(source.join("inside/kept.txt"), b"kept").expect("file");
    // A tmpfs has a different `st_dev`, which is what `--one-file-system`
    // (and `rsync -x`) use to notice a boundary.
    if !run(
        "mount",
        &[
            "-t",
            "tmpfs",
            "none",
            &source.join("mounted").display().to_string(),
        ],
    ) {
        eprintln!("mounting a tmpfs failed; skipping");
        return;
    }
    std::fs::write(source.join("mounted/other.txt"), b"other").expect("file");
    let walk = lr_engine::tree::walk(
        &source,
        &lr_engine::tree::WalkOptions::with_default_excludes_one_file_system(),
    )
    .expect("walk");
    let _ = run("umount", &[&source.join("mounted").display().to_string()]);

    let paths: Vec<Vec<u8>> = walk.entries.iter().map(|e| e.entry.path.clone()).collect();
    assert!(paths.iter().any(|path| path == b"inside/kept.txt"));
    assert!(
        !paths.iter().any(|path| path == b"mounted/other.txt"),
        "the mount must not be descended: {paths:?}"
    );
    assert!(
        paths.iter().any(|path| path == b"mounted"),
        "the mount point itself is recorded: {paths:?}"
    );
}

#[test]
#[ignore = "requires root: creates and mounts a Btrfs filesystem"]
fn a_btrfs_source_is_snapshotted_for_point_in_time() {
    if !root_tests_enabled() {
        return;
    }
    for tool in ["mkfs.btrfs", "btrfs", "losetup", "mount", "rsync"] {
        if !have(tool) {
            eprintln!("{tool} missing; skipping");
            return;
        }
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let backing = dir.path().join("btrfs.img");
    let file = std::fs::File::create(&backing).expect("create");
    file.set_len(512 * 1024 * 1024).expect("size");
    drop(file);
    let free = Command::new("losetup")
        .arg("-f")
        .output()
        .expect("losetup -f");
    let device = String::from_utf8_lossy(&free.stdout).trim().to_owned();
    if !run("losetup", &["-P", &device, &backing.display().to_string()]) {
        eprintln!("losetup failed; skipping");
        return;
    }
    let cleanup = |mountpoint: &Path| {
        let _ = run("umount", &[&mountpoint.display().to_string()]);
        let _ = run("losetup", &["-d", &device]);
    };
    if !run("mkfs.btrfs", &["-f", "-q", &device]) {
        cleanup(&dir.path().join("mnt"));
        eprintln!("mkfs.btrfs failed; skipping");
        return;
    }
    let top = dir.path().join("mnt");
    std::fs::create_dir_all(&top).expect("mountpoint");
    if !run("mount", &[&device, &top.display().to_string()]) {
        cleanup(&top);
        eprintln!("mounting btrfs failed; skipping");
        return;
    }
    // The provider snapshots subvolumes, not the top level (spec §E.1).
    if !run(
        "btrfs",
        &[
            "subvolume",
            "create",
            &top.join("data").display().to_string(),
        ],
    ) {
        cleanup(&top);
        eprintln!("btrfs subvolume create failed; skipping");
        return;
    }
    let _ = run("umount", &[&top.display().to_string()]);
    let source = dir.path().join("subvol");
    std::fs::create_dir_all(&source).expect("subvol mountpoint");
    if !run(
        "mount",
        &["-o", "subvol=data", &device, &source.display().to_string()],
    ) {
        let _ = run("losetup", &["-d", &device]);
        eprintln!("mounting the subvolume failed; skipping");
        return;
    }

    let dest = dir.path().join("backups");
    let target = dir.path().join("restored");
    std::fs::create_dir_all(source.join("nested")).expect("dirs");
    std::fs::create_dir_all(&target).expect("target");
    std::fs::write(source.join("nested/file.bin"), vec![0x5Au8; 200 * 1024]).expect("file");
    std::fs::write(source.join("note.txt"), b"point in time\n").expect("file");

    let mut request =
        BackupRequest::new(&source, &dest, "btrfs-tree", Encryption::NoEncrypt).expect("request");
    request.snapshot_provider = Some("btrfs".to_owned());
    let options = FileBackupOptions {
        consistency: lr_core::Consistency::PointInTime,
        ..FileBackupOptions::default()
    };
    let report = backup_file(&request, &options).expect("backup");
    assert_eq!(
        report.consistency,
        lr_core::Consistency::PointInTime,
        "a snapshot makes file mode point-in-time"
    );

    // The whole point of the snapshot: writes after it are not in the image.
    std::fs::write(source.join("note.txt"), b"changed after the snapshot\n").expect("change");
    let plan = prepare_restore(&PrepareRequest::from_path(
        &report.image_path,
        &target,
        Encryption::NoEncrypt,
    ))
    .expect("prepare");
    let restored = restore_into(&plan);
    assert!(restored.files >= 2, "{restored:?}");
    assert_eq!(
        std::fs::read(target.join("note.txt")).expect("read"),
        b"point in time\n",
        "the restored tree must hold the snapshot's content"
    );
    assert_eq!(
        std::fs::read(source.join("note.txt")).expect("read"),
        b"changed after the snapshot\n"
    );
    let difference = rsync_difference(&source, &target);
    assert!(
        difference.contains("note.txt"),
        "the live source and the snapshot now differ; rsync said [{difference}], \
         source={:?} target={:?}",
        std::fs::read(source.join("note.txt")),
        std::fs::read(target.join("note.txt"))
    );

    // An incremental against the snapshotted parent still finds the change.
    let mut incremental =
        BackupRequest::new(&source, &dest, "btrfs-tree", Encryption::NoEncrypt).expect("request");
    incremental.member_type = MemberType::Incremental;
    incremental.parent = Some("latest".to_owned());
    incremental.snapshot_provider = Some("btrfs".to_owned());
    let second = backup_file(&incremental, &options).expect("incremental");
    assert_eq!(second.parent_uuid, report.image_uuid);
    assert!(second.unchanged_files >= 1, "{second:?}");

    cleanup(&source);
}
