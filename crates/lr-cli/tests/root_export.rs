//! Root-gated block-export acceptance (spec §K S13).
//!
//! The spec's criterion is "mount an exported ext4 and xfs image alongside the
//! running system; browse in a file manager; unmount/unexport clean". A file
//! manager uses the same VFS operations as `readdir`/`read`, so the test lists
//! directories and compares file contents byte for byte, then proves the mount
//! is read-only and that unmounting detaches the NBD device and removes the
//! export state.
//!
//! Everything runs through the real CLI: backup, export, mount, umount.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const CLI: &str = env!("CARGO_BIN_EXE_linuxreflect");

fn root_tests_enabled() -> bool {
    if std::env::var("LR_ROOT_TESTS").as_deref() != Ok("1") {
        lr_testkit::unavailable!(return false; "LR_ROOT_TESTS != 1");
    }
    let uid = Command::new("id")
        .arg("-u")
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .unwrap_or_default();
    if uid != "0" {
        lr_testkit::unavailable!(return false; "not running as root (uid {uid})");
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

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn cli(args: &[&str]) -> Output {
    Command::new(CLI).args(args).output().expect("run the CLI")
}

/// The JSON document in the CLI output, which may be pretty-printed after
/// progress lines.
fn json_of(output: &Output) -> serde_json::Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let start = stdout
        .find('{')
        .unwrap_or_else(|| panic!("no JSON in:\n{}", text(output)));
    let json = stdout[start..].trim();
    serde_json::from_str(json)
        .unwrap_or_else(|error| panic!("bad JSON ({error}) in:\n{}", text(output)))
}

/// A loop-backed filesystem with known contents, detached again.
struct SourceImage {
    loop_device: String,
    backing: PathBuf,
}

impl SourceImage {
    fn create(dir: &Path, fs: &str, size_mib: u64) -> Option<Self> {
        let backing = dir.join(format!("{fs}-source.img"));
        let file = std::fs::File::create(&backing).expect("create");
        file.set_len(size_mib * 1024 * 1024).expect("size");
        drop(file);
        let free = Command::new("losetup")
            .arg("-f")
            .output()
            .expect("losetup -f");
        let loop_device = String::from_utf8_lossy(&free.stdout).trim().to_owned();
        if !run(
            "losetup",
            &["-P", &loop_device, &backing.display().to_string()],
        ) {
            lr_testkit::fixture_failed!("losetup failed");
        }
        let formatted = match fs {
            "ext4" => run("mkfs.ext4", &["-F", "-q", "-L", "LREXPORT", &loop_device]),
            "xfs" => run("mkfs.xfs", &["-f", "-q", "-L", "LREXPORT", &loop_device]),
            _ => false,
        };
        if !formatted {
            let _ = run("losetup", &["-d", &loop_device]);
            lr_testkit::fixture_failed!("mkfs.{fs} failed");
        }
        let mountpoint = dir.join(format!("{fs}-populate"));
        std::fs::create_dir_all(&mountpoint).expect("mountpoint");
        if !run("mount", &[&loop_device, &mountpoint.display().to_string()]) {
            let _ = run("losetup", &["-d", &loop_device]);
            lr_testkit::fixture_failed!("mounting the source failed");
        }
        std::fs::create_dir_all(mountpoint.join("nested/deeper")).expect("dirs");
        std::fs::write(mountpoint.join("hello.txt"), b"block export\n").expect("file");
        std::fs::write(mountpoint.join("nested/data.bin"), payload(7, 400 * 1024)).expect("file");
        std::fs::write(
            mountpoint.join("nested/deeper/tail.bin"),
            payload(9, 32 * 1024),
        )
        .expect("file");
        let _ = run("umount", &[&mountpoint.display().to_string()]);
        // The loop device stays attached: the backup reads it offline, and only
        // a source that still exists can be imaged at all.
        Some(Self {
            loop_device,
            backing,
        })
    }

    fn detach(&self) {
        let _ = run("losetup", &["-d", &self.loop_device]);
    }
}

fn payload(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| ((index as u8).wrapping_mul(13).wrapping_add(seed)) % 251)
        .collect()
}

fn free_nbd_device() -> Option<PathBuf> {
    let output = Command::new("sh")
        .arg("-c")
        .arg("for dev in /sys/block/nbd*; do [ -e \"$dev/pid\" ] || { echo /dev/$(basename \"$dev\"); break; }; done")
        .output()
        .ok()?;
    let device = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if device.is_empty() || device == "/dev/" {
        lr_testkit::unavailable!(return None; "no free NBD device");
    }
    Some(PathBuf::from(device))
}

fn export_case(fs: &str, size_mib: u64) {
    if !root_tests_enabled() {
        return;
    }
    for tool in ["nbd-client", "losetup", "mount", "umount", "sha256sum"] {
        if !have(tool) {
            lr_testkit::unavailable!("{tool} missing");
        }
    }
    if !have("mkfs.ext4") || !have("mkfs.xfs") {
        lr_testkit::unavailable!("mkfs.ext4/mkfs.xfs missing");
    }
    if free_nbd_device().is_none() {
        return;
    }
    let dir = tempfile::tempdir_in("/tmp").expect("tempdir");
    let Some(source) = SourceImage::create(dir.path(), fs, size_mib) else {
        return;
    };
    let dest = dir.path().join("backups");
    let mountpoint = dir.path().join("mount");

    // 1. Back the (unmounted) filesystem up; the offline provider applies.
    let created = cli(&[
        "backup",
        "create",
        "--source",
        &source.loop_device,
        "--dest",
        &dest.display().to_string(),
        "--set",
        "export-case",
        "--no-encrypt",
        "--compress",
        "zstd:3",
        "--json",
    ]);
    assert!(created.status.success(), "{}", text(&created));
    let report = json_of(&created);
    let image = report["image_path"]
        .as_str()
        .expect("image_path")
        .to_owned();
    assert!(
        report["source_size_bytes"].as_u64().unwrap_or(0) > 0,
        "the image must have content: {report}"
    );
    assert!(
        report["total_chunks"].as_u64().unwrap_or(0) > 0,
        "the image must have chunks: {report}"
    );
    source.detach();
    let _ = &source.backing;

    // 2. Export it and mount the filesystem read-only.
    std::fs::create_dir_all(&mountpoint).expect("mountpoint");
    let exported = cli(&[
        "export",
        "mount",
        "--image",
        &image,
        "--at",
        &mountpoint.display().to_string(),
        "--json",
    ]);
    assert!(exported.status.success(), "{}", text(&exported));
    let state = json_of(&exported);
    assert_eq!(state["fs_type"], fs, "{state}");
    let options = state["mount_options"]
        .as_array()
        .expect("mount_options")
        .iter()
        .filter_map(|value| value.as_str())
        .collect::<Vec<_>>();
    match fs {
        "ext4" => assert!(options.contains(&"noload"), "{options:?}"),
        "xfs" => {
            assert!(options.contains(&"nouuid"), "{options:?}");
            assert!(options.contains(&"norecovery"), "{options:?}");
        }
        _ => {}
    }
    let device = state["device"].as_str().expect("device").to_owned();

    // 3. Browse and read: the same VFS calls a file manager makes.
    let listing = std::fs::read_dir(&mountpoint)
        .expect("readdir")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert!(listing.contains(&"hello.txt".to_owned()), "{listing:?}");
    assert!(listing.contains(&"nested".to_owned()), "{listing:?}");
    assert_eq!(
        std::fs::read(mountpoint.join("hello.txt")).expect("read"),
        b"block export\n"
    );
    assert_eq!(
        std::fs::read(mountpoint.join("nested/data.bin")).expect("read"),
        payload(7, 400 * 1024)
    );
    assert_eq!(
        std::fs::read(mountpoint.join("nested/deeper/tail.bin")).expect("read"),
        payload(9, 32 * 1024)
    );

    // 4. The export is read-only.
    let write = std::fs::write(mountpoint.join("hello.txt"), b"changed\n");
    assert!(write.is_err(), "writing through the export must fail");

    // 5. Unmount and unexport cleanly.
    let unmounted = cli(&[
        "export",
        "umount",
        "--at",
        &mountpoint.display().to_string(),
    ]);
    assert!(unmounted.status.success(), "{}", text(&unmounted));
    assert!(
        std::fs::read_dir(&mountpoint)
            .expect("readdir")
            .next()
            .is_none(),
        "the mount point is empty again"
    );
    assert!(
        !Path::new(&format!(
            "/sys/block/{}/pid",
            device.trim_start_matches("/dev/")
        ))
        .exists(),
        "the NBD device is detached"
    );
    let listed = cli(&["export", "list"]);
    assert!(listed.status.success(), "{}", text(&listed));
    let listing = String::from_utf8_lossy(&listed.stdout).into_owned();
    assert!(
        !listing.contains(&mountpoint.display().to_string()),
        "the export must not be listed any more:\n{listing}"
    );
}

#[test]
#[ignore = "requires root: loop devices, mkfs, nbd-client and mounts"]
fn an_ext4_image_mounts_read_only_through_nbd() {
    export_case("ext4", 128);
}

#[test]
#[ignore = "requires root: loop devices, mkfs, nbd-client and mounts"]
fn an_xfs_image_mounts_read_only_through_nbd() {
    // xfs refuses to format anything smaller than 300 MiB.
    export_case("xfs", 400);
}

/// The daemon serves exports too (spec §I `ExportImage`/`UnexportImage`), so the
/// same mount is driven through its socket.
#[test]
#[ignore = "requires root: loop devices, mkfs, nbd-client and mounts"]
fn the_daemon_exports_an_image() {
    if !root_tests_enabled() {
        return;
    }
    for tool in ["nbd-client", "losetup", "mount", "umount"] {
        if !have(tool) {
            lr_testkit::unavailable!("{tool} missing");
        }
    }
    if free_nbd_device().is_none() {
        return;
    }
    let dir = tempfile::tempdir_in("/tmp").expect("tempdir");
    let Some(source) = SourceImage::create(dir.path(), "ext4", 128) else {
        return;
    };
    let dest = dir.path().join("backups");
    let mountpoint = dir.path().join("daemon-mount");
    std::fs::create_dir_all(&mountpoint).expect("mountpoint");

    let created = cli(&[
        "backup",
        "create",
        "--source",
        &source.loop_device,
        "--dest",
        &dest.display().to_string(),
        "--set",
        "daemon-export",
        "--no-encrypt",
        "--compress",
        "none",
        "--json",
    ]);
    assert!(created.status.success(), "{}", text(&created));
    let image = json_of(&created)["image_path"]
        .as_str()
        .expect("image_path")
        .to_owned();
    source.detach();

    // A daemon of its own, with static authorization for this (root) process.
    let daemon_binary = Path::new(CLI)
        .parent()
        .expect("cli parent")
        .join("linuxreflect-daemon");
    assert!(daemon_binary.exists(), "the daemon binary is built");
    let socket = dir.path().join("daemon.sock");
    let mut daemon = Command::new(&daemon_binary)
        .args([
            "--socket",
            &socket.display().to_string(),
            "--socket-group",
            "lr-export-test",
            "--no-create-group",
            "--dev-mode",
            "--auth",
            "static:all",
            "--sd-notify=no",
            "--token-secret-file",
            &dir.path().join("token.key").display().to_string(),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("start the daemon");
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(socket.exists(), "the daemon created its socket");

    let exported = cli(&[
        "--socket",
        &socket.display().to_string(),
        "export",
        "mount",
        "--image",
        &image,
        "--at",
        &mountpoint.display().to_string(),
        "--json",
    ]);
    assert!(exported.status.success(), "{}", text(&exported));
    assert_eq!(
        std::fs::read(mountpoint.join("nested/data.bin")).expect("read"),
        payload(7, 400 * 1024),
    );

    let unmounted = cli(&[
        "--socket",
        &socket.display().to_string(),
        "export",
        "umount",
        "--at",
        &mountpoint.display().to_string(),
    ]);
    assert!(unmounted.status.success(), "{}", text(&unmounted));
    assert!(
        std::fs::read_dir(&mountpoint)
            .expect("readdir")
            .next()
            .is_none(),
        "the daemon unmounted the export"
    );
    let _ = daemon.kill();
    let _ = daemon.wait();
}
