//! S8 acceptance test that needs root: Btrfs Stream mode (spec §K S8).
//!
//! Two subvolumes are snapshotted, a full image and then an incremental
//! (`btrfs send -p`) are produced, and both are received into a freshly
//! formatted filesystem. The test then checks `diff -r` against the live
//! source and that the default subvolume survived.
//!
//! Run with:
//!
//! ```text
//! LR_ROOT_TESTS=1 sudo -E cargo test -p lr-engine --test root_stream -- --ignored --nocapture --test-threads=1
//! ```

use std::path::{Path, PathBuf};
use std::process::Command;

use lr_engine::backup::{BackupRequest, Compression, MemberType};
use lr_engine::keys::Encryption;
use lr_engine::stream::{StreamRestoreRequest, restore_stream};
use lr_engine::{ImageReport, backup_image};

fn root_tests_enabled() -> bool {
    if std::env::var("LR_ROOT_TESTS").as_deref() != Ok("1") {
        lr_testkit::unavailable!(return false; "LR_ROOT_TESTS != 1 - root test");
    }
    let uid = Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default();
    if uid != "0" {
        lr_testkit::unavailable!(return false; "not running as root (uid {uid}) - root test");
    }
    true
}

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

fn output(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .output()
        .map(|o| {
            format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            )
        })
        .unwrap_or_default()
}

fn sparse(path: &Path, size: u64) {
    let file = std::fs::File::create(path).expect("create");
    file.set_len(size).expect("size");
    drop(file);
}

struct LoopDisk {
    device: PathBuf,
    _dir: tempfile::TempDir,
}

impl LoopDisk {
    fn attach(size: u64) -> Option<Self> {
        let dir = tempfile::tempdir().expect("tempdir");
        let backing = dir.path().join("disk.img");
        sparse(&backing, size);
        let free = Command::new("losetup")
            .arg("-f")
            .output()
            .expect("run losetup -f");
        if !free.status.success() {
            lr_testkit::fixture_failed!("losetup -f found no free loop device");
        }
        let device = PathBuf::from(String::from_utf8_lossy(&free.stdout).trim().to_owned());
        if !run(
            "losetup",
            &[
                "-P",
                &device.display().to_string(),
                &backing.display().to_string(),
            ],
        ) {
            lr_testkit::fixture_failed!("losetup could not attach {}", backing.display());
        }
        Some(Self { device, _dir: dir })
    }

    fn path(&self) -> String {
        self.device.display().to_string()
    }
}

impl Drop for LoopDisk {
    fn drop(&mut self) {
        let _ = run("losetup", &["-d", &self.path()]);
    }
}

/// A mount point that is unmounted on drop, even when the test panics.
struct Mount {
    at: PathBuf,
}

impl Mount {
    fn btrfs(device: &Path, at: &Path, subvol: Option<&str>) -> Option<Self> {
        std::fs::create_dir_all(at).expect("mount point");
        let option = match subvol {
            Some(path) => format!("subvol={path}"),
            None => "subvolid=5".to_owned(),
        };
        let mounted = run(
            "mount",
            &[
                "-t",
                "btrfs",
                "-o",
                &option,
                &device.display().to_string(),
                &at.display().to_string(),
            ],
        );
        mounted.then(|| Self {
            at: at.to_path_buf(),
        })
    }

    fn path(&self) -> &Path {
        &self.at
    }
}

impl Drop for Mount {
    fn drop(&mut self) {
        let _ = run("umount", &[&self.at.display().to_string()]);
    }
}

/// `diff -r --no-dereference` of two directories.
fn diff_dirs(left: &Path, right: &Path) -> bool {
    let output = Command::new("diff")
        .args(["-r", "--no-dereference"])
        .arg(left)
        .arg(right)
        .output()
        .expect("diff");
    if !output.status.success() {
        eprintln!(
            "diff {} {} failed:\n{}{}",
            left.display(),
            right.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    output.status.success()
}

fn write_file(path: &Path, contents: &str) {
    std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    std::fs::write(path, contents).expect("write");
    // The stream is taken from a read-only snapshot, so the data only has to
    // be visible on disk, not durable across a crash.
}

#[test]
#[ignore = "needs root, loop devices and btrfs-progs"]
fn btrfs_full_then_incremental_round_trips() {
    if !root_tests_enabled() {
        return;
    }
    for tool in ["btrfs", "mkfs.btrfs", "diff"] {
        if !have(tool) {
            lr_testkit::unavailable!("{tool} missing");
        }
    }

    let source = LoopDisk::attach(512 * 1024 * 1024).expect("source loop device");
    let target = LoopDisk::attach(512 * 1024 * 1024).expect("target loop device");
    if !run("mkfs.btrfs", &["-q", "-f", &source.path()])
        || !run("mkfs.btrfs", &["-q", "-f", &target.path()])
    {
        lr_testkit::fixture_failed!("mkfs.btrfs failed");
    }

    let work = tempfile::tempdir().expect("workdir");
    let top = Mount::btrfs(&source.device, &work.path().join("top"), None).expect("mount top");
    // The subvolumes must exist before their `subvol=` mounts can be made.
    std::fs::create_dir_all(top.path().join("home")).expect("home dir");
    assert!(run(
        "btrfs",
        &[
            "subvolume",
            "create",
            &top.path().join("@").display().to_string()
        ]
    ));
    assert!(run(
        "btrfs",
        &[
            "subvolume",
            "create",
            &top.path().join("home/u1").display().to_string()
        ]
    ));
    // Both subvolumes are mounted, which is what the provider looks for. They
    // are mounted as siblings so `diff -r` of `/@` never descends into the
    // other subvolume's mount.
    let root_subvol =
        Mount::btrfs(&source.device, &work.path().join("src-root"), Some("/@")).expect("mount @");
    let home_subvol = Mount::btrfs(
        &source.device,
        &work.path().join("src-u1"),
        Some("/home/u1"),
    )
    .expect("mount /home/u1");
    write_file(&root_subvol.path().join("etc/f1"), "one\n");
    write_file(&root_subvol.path().join("var/log/syslog"), "boot\n");
    std::fs::create_dir_all(root_subvol.path().join("home")).expect("home dir");
    write_file(&home_subvol.path().join("u/h1"), "home-one\n");

    // Default subvolume: `@`, exactly like a real deployment.
    let list = output(
        "btrfs",
        &["subvolume", "list", &top.path().display().to_string()],
    );
    let at_id = list
        .lines()
        .find(|line| line.trim_end().ends_with("path @"))
        .and_then(|line| line.split_whitespace().nth(1))
        .expect("id of @");
    assert!(run(
        "btrfs",
        &[
            "subvolume",
            "set-default",
            at_id,
            &top.path().display().to_string()
        ]
    ));

    let dest = work.path().join("images");
    std::fs::create_dir_all(&dest).expect("dest");

    // Full image.
    let mut first =
        BackupRequest::new(&source.device, &dest, "set", Encryption::NoEncrypt).expect("request");
    first.compression = Compression::None;
    let first_report = match backup_image(&first).expect("full stream backup") {
        ImageReport::Stream(report) => report,
        other => panic!("expected a stream image, got {other:?}"),
    };
    assert_eq!(first_report.subvolumes.len(), 2, "two mounted subvolumes");
    assert!(
        first_report
            .subvolumes
            .iter()
            .all(|subvol| subvol.parent_snapshot_uuid.is_none()),
        "the first image must be full"
    );
    assert!(first_report.image_bytes > 0);

    // Change both subvolumes: add, modify and delete.
    write_file(&root_subvol.path().join("etc/f2"), "two\n");
    std::fs::remove_file(root_subvol.path().join("etc/f1")).expect("remove f1");
    write_file(
        &root_subvol.path().join("var/log/syslog"),
        "boot\nrenewed\n",
    );
    write_file(&home_subvol.path().join("u/h2"), "home-two\n");

    // Incremental image in the same set.
    let mut second =
        BackupRequest::new(&source.device, &dest, "set", Encryption::NoEncrypt).expect("request");
    second.set_id = first.set_id;
    second.chain_id = first.chain_id;
    second.compression = Compression::None;
    // An S9-era incremental: the parent comes from the set catalog and the
    // provider reuses the snapshot `.linuxreflect/<set>/latest` points at.
    second.member_type = MemberType::Incremental;
    second.parent = Some("latest".to_owned());
    let second_report = match backup_image(&second).expect("incremental stream backup") {
        ImageReport::Stream(report) => report,
        other => panic!("expected a stream image, got {other:?}"),
    };
    assert_eq!(second_report.subvolumes.len(), 2);
    assert!(
        second_report
            .subvolumes
            .iter()
            .all(|subvol| subvol.parent_snapshot_uuid.is_some()),
        "the second image must be incremental: {:?}",
        second_report.subvolumes
    );
    assert!(
        second_report.send_stream_bytes < first_report.send_stream_bytes,
        "an incremental must send less than the full image ({} vs {})",
        second_report.send_stream_bytes,
        first_report.send_stream_bytes
    );

    // Restore both images into the fresh filesystem.
    let mount_root = work.path().join("restore-mnt");
    std::fs::create_dir_all(&mount_root).expect("mount root");
    // Names are relative to the set root, exactly as a destination resolves
    // them (`<dest-root>/<set-name>/<chain>/<file>`).
    let set_root = dest.join("set");
    let name = |path: &std::path::Path| {
        path.strip_prefix(&set_root)
            .expect("set-relative name")
            .to_string_lossy()
            .into_owned()
    };
    let restore = restore_stream(&StreamRestoreRequest {
        dest: dest.to_string_lossy().into_owned(),
        set: "set".to_owned(),
        images: vec![
            name(&first_report.image_path),
            name(&second_report.image_path),
        ],
        destination_options: lr_store::DestinationOptions::new("set"),
        target: target.device.clone(),
        encryption: Encryption::NoEncrypt,
        mount_root,
        confirm: true,
        accept_inconsistent: false,
        context: lr_engine::progress::EngineContext::silent(),
    })
    .expect("restore stream");
    assert_eq!(restore.fs_uuid, first_report.fs_uuid);
    assert_eq!(restore.subvolumes.len(), 2, "{:?}", restore.subvolumes);
    assert_eq!(restore.default_subvolume.as_deref(), Some("/@"));

    // Verify the content and the default subvolume of the restored filesystem.
    let restored_top =
        Mount::btrfs(&target.device, &work.path().join("restored"), None).expect("mount restored");
    let restored_root = Mount::btrfs(
        &target.device,
        &work.path().join("restored-root"),
        Some("/@"),
    )
    .expect("mount restored @");
    let restored_home = Mount::btrfs(
        &target.device,
        &work.path().join("restored-u1"),
        Some("/home/u1"),
    )
    .expect("mount restored /home/u1");

    assert!(
        diff_dirs(root_subvol.path(), restored_root.path()),
        "the restored @ must match the source"
    );
    assert!(
        diff_dirs(home_subvol.path(), restored_home.path()),
        "the restored /home/u1 must match the source"
    );

    let default = output(
        "btrfs",
        &[
            "subvolume",
            "get-default",
            &restored_top.path().display().to_string(),
        ],
    );
    assert!(
        default.contains("path @"),
        "the default subvolume must be restored: {default}"
    );
    // Exactly one subvolume per path survived the chain.
    let restored_list = output(
        "btrfs",
        &[
            "subvolume",
            "list",
            &restored_top.path().display().to_string(),
        ],
    );
    let paths: Vec<&str> = restored_list
        .lines()
        .filter_map(|line| line.split_whitespace().last())
        .collect();
    assert_eq!(
        paths.len(),
        2,
        "extra subvolumes were left behind: {paths:?}"
    );
}

/// The snapshot cleanup of a Btrfs stream backup touches only its own
/// snapshots (R02, D-115): foreign subvolumes, directories and files in the
/// set's state directory survive, and a set name of `..` is refused before
/// anything is mounted.
#[test]
#[ignore = "needs root, loop devices and btrfs-progs"]
fn btrfs_cleanup_stays_inside_its_own_snapshots() {
    if !root_tests_enabled() {
        return;
    }
    for tool in ["btrfs", "mkfs.btrfs"] {
        if !have(tool) {
            lr_testkit::unavailable!("{tool} missing");
        }
    }
    let source = LoopDisk::attach(512 * 1024 * 1024).expect("source loop device");
    if !run("mkfs.btrfs", &["-q", "-f", &source.path()]) {
        lr_testkit::fixture_failed!("mkfs.btrfs failed");
    }
    let work = tempfile::tempdir().expect("workdir");
    let top = Mount::btrfs(&source.device, &work.path().join("top"), None).expect("mount top");
    let subvol = |path: &Path| {
        assert!(run(
            "btrfs",
            &["subvolume", "create", &path.display().to_string()]
        ));
    };
    subvol(&top.path().join("@"));
    let root_subvol =
        Mount::btrfs(&source.device, &work.path().join("src-root"), Some("/@")).expect("mount @");
    write_file(&root_subvol.path().join("etc/f1"), "one\n");

    let dest = work.path().join("images");
    std::fs::create_dir_all(&dest).expect("dest");

    // `..` is refused before any mount or snapshot: the state directory
    // would otherwise be the top level, and cleanup would prune `@`.
    let Err(error) = BackupRequest::new(&source.device, &dest, "..", Encryption::NoEncrypt) else {
        panic!("a set name of `..` must be refused");
    };
    assert!(error.to_string().contains("invalid set name"), "{error}");

    let mut first =
        BackupRequest::new(&source.device, &dest, "set", Encryption::NoEncrypt).expect("request");
    first.compression = Compression::None;
    backup_image(&first).expect("first stream backup");
    let set_dir = top.path().join(".linuxreflect/set");
    let first_dir = set_dir.join(first.image_uuid.to_string());
    assert!(first_dir.is_dir(), "the first image keeps its snapshots");

    // Foreign entries in the set's state directory: a subvolume and a
    // directory with non-UUID names, and a UUID-named directory holding a
    // plain file rather than a snapshot.
    subvol(&set_dir.join("foreign-subvol"));
    write_file(&set_dir.join("foreign-subvol/keep"), "subvolume\n");
    write_file(&set_dir.join("notes/keep"), "directory\n");
    let stray = set_dir.join("abababab-abab-abab-abab-abababababab");
    write_file(&stray.join("keep"), "plain file\n");

    let mut second =
        BackupRequest::new(&source.device, &dest, "set", Encryption::NoEncrypt).expect("request");
    second.set_id = first.set_id;
    second.chain_id = first.chain_id;
    second.compression = Compression::None;
    second.member_type = MemberType::Incremental;
    second.parent = Some("latest".to_owned());
    backup_image(&second).expect("second stream backup");

    assert!(
        !first_dir.exists(),
        "the previous image's snapshots are pruned"
    );
    assert!(set_dir.join(second.image_uuid.to_string()).is_dir());
    for kept in [
        set_dir.join("foreign-subvol/keep"),
        set_dir.join("notes/keep"),
        stray.join("keep"),
        root_subvol.path().join("etc/f1"),
    ] {
        assert!(kept.exists(), "{} was removed by cleanup", kept.display());
    }
}
