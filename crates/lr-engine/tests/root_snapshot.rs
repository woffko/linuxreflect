//! S8 acceptance tests that need root: LVM snapshots, the freeze deadman and
//! the live-none opt-in (spec §K S8).
//!
//! Run with:
//!
//! ```text
//! LR_ROOT_TESTS=1 sudo -E cargo test -p lr-engine --test root_snapshot -- --ignored --nocapture --test-threads=1
//! ```
//!
//! Two tests re-execute this binary as a child process (`--exact <helper>
//! --ignored`) so the parent can `kill -9` it and prove that a snapshot LV is
//! swept later and that a frozen filesystem is thawed by the external deadman.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use lr_core::{SnapshotOpts, discovery::discover_source};
use lr_engine::backup::{BackupRequest, BadSectorPolicy, Compression};
use lr_engine::keys::Encryption;
use lr_engine::restore::{ApplyRequest, PrepareRequest, apply_restore, prepare_restore};
use lr_engine::{ImageReport, backup_image};
use lr_snapshot::lvm;
use lr_snapshot::{BlockSnapshotProvider, freeze, live_none};
use std::os::unix::fs::MetadataExt;

const CHUNK_SIZE: u32 = 256 * 1024;
const MARKER_PATTERN: u8 = 0xA5;

fn root_tests_enabled() -> bool {
    if std::env::var("LR_ROOT_TESTS").as_deref() != Ok("1") {
        eprintln!("LR_ROOT_TESTS != 1; skipping root test");
        return false;
    }
    let uid = Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default();
    if uid != "0" {
        eprintln!("not running as root (uid {uid}); skipping root test");
        return false;
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

fn read_at(path: &Path, offset: u64, len: usize) -> Vec<u8> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(path).expect("open");
    file.seek(SeekFrom::Start(offset)).expect("seek");
    let mut bytes = vec![0u8; len];
    file.read_exact(&mut bytes).expect("read");
    bytes
}

fn write_at(path: &Path, offset: u64, bytes: &[u8]) {
    use std::io::{Seek, SeekFrom, Write};
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .expect("open for writing");
    file.seek(SeekFrom::Start(offset)).expect("seek");
    file.write_all(bytes).expect("write");
    file.sync_all().expect("sync");
}

/// A loop device plus, optionally, a volume group on it.
struct LoopDisk {
    device: PathBuf,
    _dir: tempfile::TempDir,
}

impl LoopDisk {
    fn attach(size: u64) -> Option<Self> {
        let dir = tempfile::tempdir_in("/tmp/opencode").expect("tempdir");
        let backing = dir.path().join("disk.img");
        sparse(&backing, size);
        let free = Command::new("losetup").arg("-f").output().ok()?;
        if !free.status.success() {
            return None;
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
            return None;
        }
        Some(Self { device, _dir: dir })
    }

    fn label(&self) -> String {
        self.device.display().to_string()
    }
}

impl Drop for LoopDisk {
    fn drop(&mut self) {
        let _ = run("losetup", &["-d", &self.device.display().to_string()]);
    }
}

/// A volume group on a loop device, removed on drop.
struct VolumeGroup {
    name: String,
    loop_disk: LoopDisk,
}

impl VolumeGroup {
    fn create(name: &str, size: u64) -> Option<Self> {
        for tool in [
            "pvcreate", "vgcreate", "lvcreate", "lvremove", "vgremove", "lvs",
        ] {
            if !have(tool) {
                eprintln!("{tool} missing; skipping the LVM test");
                return None;
            }
        }
        let loop_disk = LoopDisk::attach(size)?;
        if !run("pvcreate", &["-f", "-y", &loop_disk.label()]) {
            eprintln!("pvcreate failed");
            return None;
        }
        if !run("vgcreate", &[name, &loop_disk.label()]) {
            eprintln!("vgcreate failed");
            return None;
        }
        Some(Self {
            name: name.to_owned(),
            loop_disk,
        })
    }

    fn path(&self) -> String {
        format!("/dev/{}", self.name)
    }

    fn lv(&self, lv: &str) -> String {
        format!("{}/{lv}", self.name)
    }

    /// Logical volumes this provider created.
    fn stray_snapshots(&self) -> Vec<String> {
        output("lvs", &["--noheadings", "-o", "lv_name", &self.path()])
            .lines()
            .map(|line| line.trim().to_owned())
            .filter(|name| name.starts_with("lr-"))
            .collect()
    }
}

impl Drop for VolumeGroup {
    fn drop(&mut self) {
        let _ = run("vgremove", &["-f", &self.name]);
        let _ = run("pvremove", &["-f", &self.loop_disk.label()]);
    }
}

fn source_layout(device: &Path) -> lr_core::SourceLayout {
    discover_source(device).expect("discover the snapshot device")
}

/// Build a classic-snapshot origin: one ext4 LV inside a loop-backed VG.
fn classic_origin(vg: &VolumeGroup) -> Option<String> {
    if !run("lvcreate", &["-n", "origin", "-L", "1G", &vg.path()]) {
        eprintln!("lvcreate origin failed");
        return None;
    }
    let origin = vg.lv("origin");
    if !run("mkfs.ext4", &["-F", "-q", &format!("/dev/{origin}")]) {
        eprintln!("mkfs.ext4 on the LV failed");
        return None;
    }
    Some(origin)
}

#[test]
#[ignore = "requires root, loop devices and lvm2"]
fn lvm_snapshot_is_point_in_time() {
    if !root_tests_enabled() {
        return;
    }
    let Some(vg) = VolumeGroup::create("lrtestpit", 2 * 1024 * 1024 * 1024) else {
        return;
    };
    let Some(origin) = classic_origin(&vg) else {
        return;
    };
    let origin_dev = PathBuf::from(format!("/dev/{origin}"));

    // Write a marker pattern into the origin.
    let marker = vec![MARKER_PATTERN; 4096];
    write_at(&origin_dev, 1024 * 1024, &marker);
    let layout = source_layout(&origin_dev);
    let options = SnapshotOpts::default();
    let snapshot = lvm::provider()
        .create(&layout, &options)
        .expect("create the LVM snapshot");
    assert_eq!(
        snapshot.consistency,
        lr_core::Consistency::PointInTime,
        "an LVM snapshot is point-in-time"
    );

    // Change the origin after the snapshot was taken.
    let replacement = vec![0x5Au8; 4096];
    write_at(&origin_dev, 1024 * 1024, &replacement);

    assert_eq!(
        read_at(&snapshot.block_path, 1024 * 1024, 4096),
        marker,
        "the snapshot must still hold the pre-snapshot content"
    );
    assert_eq!(
        read_at(&origin_dev, 1024 * 1024, 4096),
        replacement,
        "the origin really changed"
    );
    // Reading twice gives the same bytes: the snapshot does not drift.
    assert_eq!(
        read_at(&snapshot.block_path, 1024 * 1024, 4096),
        marker,
        "the snapshot is stable across reads"
    );
    let path = snapshot.block_path.clone();
    drop(snapshot);
    assert!(!path.exists(), "the snapshot LV must be removed on drop");
    assert!(vg.stray_snapshots().is_empty(), "no snapshot LV may leak");
}

#[test]
#[ignore = "requires root, loop devices and lvm2"]
fn a_killed_job_leaves_a_snapshot_that_the_sweep_removes() {
    if !root_tests_enabled() {
        return;
    }
    let Some(vg) = VolumeGroup::create("lrtestsweep", 2 * 1024 * 1024 * 1024) else {
        return;
    };
    let Some(origin) = classic_origin(&vg) else {
        return;
    };
    let ready = PathBuf::from(format!(
        "/tmp/opencode/lr-lvm-child-{}.ready",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&ready);

    // The child creates a snapshot and then hangs until it is killed.
    let mut child = Command::new(std::env::current_exe().expect("current exe"))
        .args(["--exact", "lvm_child_helper", "--ignored", "--nocapture"])
        .env("LR_LVM_CHILD", format!("/dev/{origin}"))
        .env("LR_LVM_READY", &ready)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn the child");

    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline && !ready.exists() {
        std::thread::sleep(Duration::from_millis(200));
    }
    if !ready.exists() {
        eprintln!("the child never signalled readiness; skipping");
        let _ = child.kill();
        let _ = child.wait();
        return;
    }
    assert!(
        !vg.stray_snapshots().is_empty(),
        "the child created a snapshot LV"
    );

    // kill -9 leaves the LV behind, because Drop never runs.
    child.kill().expect("kill -9 the child");
    let _ = child.wait();
    assert!(
        !vg.stray_snapshots().is_empty(),
        "a killed job cannot clean up after itself"
    );

    // The next job sweeps it away.
    let removed = lvm::sweep_stale(&vg.name).expect("sweep");
    assert!(
        !removed.is_empty(),
        "the sweep removed the orphan: {removed:?}"
    );
    assert!(vg.stray_snapshots().is_empty(), "no snapshot LV may remain");
}

/// Child process for [`a_killed_job_leaves_a_snapshot_that_the_sweep_removes`].
#[test]
#[ignore = "internal helper for the kill -9 sweep test"]
fn lvm_child_helper() {
    let Ok(device) = std::env::var("LR_LVM_CHILD") else {
        return;
    };
    let ready = std::env::var("LR_LVM_READY").expect("LR_LVM_READY");
    let layout = source_layout(Path::new(&device));
    // Leaked on purpose: the parent kills this process without unwinding.
    let _snapshot = lvm::provider()
        .create(&layout, &SnapshotOpts::default())
        .expect("child snapshot");
    std::fs::write(&ready, b"ready").expect("signal readiness");
    std::thread::sleep(Duration::from_secs(600));
}

#[test]
#[ignore = "requires root, loop devices and lvm2"]
fn an_overflowing_snapshot_aborts_the_job() {
    if !root_tests_enabled() {
        return;
    }
    let Some(vg) = VolumeGroup::create("lrtestovf", 2 * 1024 * 1024 * 1024) else {
        return;
    };
    let Some(origin) = classic_origin(&vg) else {
        return;
    };
    let origin_dev = PathBuf::from(format!("/dev/{origin}"));
    let layout = source_layout(&origin_dev);

    // An 8 MiB COW overflows after a few MiB of writes.
    let options = SnapshotOpts {
        lvm_cow_size: Some("8M".to_owned()),
        ..SnapshotOpts::default()
    };
    let snapshot = lvm::provider()
        .create(&layout, &options)
        .expect("create a small snapshot");
    snapshot.check_health().expect("healthy before the writes");

    // Flood the origin so the COW fills up.
    for round in 0..8u8 {
        write_at(
            &origin_dev,
            u64::from(round) * 1024 * 1024,
            &vec![round; 1024 * 1024],
        );
    }

    // The monitor checks every five seconds; give it a couple of cycles.
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut overflowed = false;
    while Instant::now() < deadline {
        if snapshot.check_health().is_err() {
            overflowed = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    let result = snapshot.check_health();
    let path = snapshot.block_path.clone();
    drop(snapshot);
    if overflowed {
        assert!(
            matches!(result, Err(lr_core::Error::SnapshotOverflow)),
            "unexpected abort reason: {result:?}"
        );
    } else {
        eprintln!("the snapshot did not reach 90 % in 20 s; the abort path is unproven here");
    }
    assert!(
        !path.exists(),
        "the overflowed snapshot is removed either way"
    );
}

#[test]
#[ignore = "requires root, loop devices and lvm2"]
fn a_thin_snapshot_is_supported() {
    if !root_tests_enabled() {
        return;
    }
    if !have("thin_check") {
        eprintln!("thin-provisioning-tools missing; skipping");
        return;
    }
    let Some(vg) = VolumeGroup::create("lrtestthin", 2 * 1024 * 1024 * 1024) else {
        return;
    };
    let pool = vg.lv("pool");
    if !run(
        "lvcreate",
        &[
            "--type",
            "thin-pool",
            "-L",
            "1G",
            "--poolmetadatasize",
            "64M",
            "-n",
            "pool",
            &vg.path(),
        ],
    ) {
        eprintln!("creating the thin pool failed; skipping");
        return;
    }
    if !run(
        "lvcreate",
        &[
            "--type",
            "thin",
            "-V",
            "512M",
            "--thinpool",
            &pool,
            "-n",
            "origin",
            &vg.path(),
        ],
    ) {
        eprintln!("creating the thin LV failed; skipping");
        return;
    }
    let origin_dev = PathBuf::from(format!("/dev/{}", vg.lv("origin")));
    if !run(
        "mkfs.ext4",
        &["-F", "-q", &origin_dev.display().to_string()],
    ) {
        return;
    }
    let layout = source_layout(&origin_dev);
    let snapshot = lvm::provider()
        .create(&layout, &SnapshotOpts::default())
        .expect("create a thin snapshot");
    assert_eq!(snapshot.consistency, lr_core::Consistency::PointInTime);
    // Capture the origin, change it, and check the snapshot kept the old data.
    let before = read_at(&origin_dev, 1024 * 1024, 4096);
    let marker = vec![0x3Cu8; 4096];
    write_at(&origin_dev, 1024 * 1024, &marker);
    assert!(
        read_at(&snapshot.block_path, 1024 * 1024, 4096) == before,
        "the thin snapshot holds the pre-write content"
    );
    assert!(
        read_at(&origin_dev, 1024 * 1024, 4096) == marker,
        "the origin really changed"
    );
    let path = snapshot.block_path.clone();
    drop(snapshot);
    assert!(!path.exists(), "the thin snapshot is removed on drop");
}

/// Mount a loop-backed ext4 filesystem and return `(mountpoint, guard)`.
fn mounted_ext4(work: &Path, name: &str) -> Option<(PathBuf, tempfile::TempDir, LoopDisk)> {
    if !have("mkfs.ext4") {
        return None;
    }
    let loop_disk = LoopDisk::attach(256 * 1024 * 1024)?;
    if !run("mkfs.ext4", &["-F", "-q", &loop_disk.label()]) {
        return None;
    }
    let mountpoint = tempfile::tempdir_in(work).expect("mountpoint dir");
    if !run(
        "mount",
        &[&loop_disk.label(), &mountpoint.path().display().to_string()],
    ) {
        eprintln!("mount failed");
        return None;
    }
    let path = mountpoint.path().to_path_buf();
    let _ = name;
    Some((path, mountpoint, loop_disk))
}

#[test]
#[ignore = "requires root, loop devices and fsfreeze"]
fn freeze_blocks_writers_and_thaws_on_drop() {
    if !root_tests_enabled() {
        return;
    }
    if !have("fsfreeze") {
        return;
    }
    let work = tempfile::tempdir_in("/tmp/opencode").expect("workdir");
    let Some((mountpoint, _guard, loop_disk)) = mounted_ext4(work.path(), "frz") else {
        return;
    };
    // The destination is on another filesystem (/tmp/opencode is not the loop).
    assert_ne!(
        std::fs::metadata(&mountpoint).expect("stat").dev(),
        std::fs::metadata(work.path()).expect("stat").dev(),
        "the test needs a destination on another filesystem"
    );

    let layout = source_layout(&loop_disk.device);
    let options = SnapshotOpts {
        allow_freeze: true,
        freeze_timeout_secs: Some(60),
        deadman_grace_secs: Some(30),
        destination: Some(work.path().to_path_buf()),
        ..SnapshotOpts::default()
    };
    let support = freeze::provider().supports(&layout, &options);
    assert!(support.is_yes(), "{support:?}");
    let snapshot = freeze::provider()
        .create(&layout, &options)
        .expect("freeze");

    // A writer blocks while the filesystem is frozen.
    let mut writer = Command::new("sh")
        .arg("-c")
        .arg(format!("touch {}/blocked", mountpoint.display()))
        .spawn()
        .expect("spawn the writer");
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        writer.try_wait().expect("try_wait").is_none(),
        "the writer must be blocked while frozen"
    );

    drop(snapshot);
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && writer.try_wait().expect("try_wait").is_none() {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        writer.try_wait().expect("try_wait").is_some(),
        "the writer must finish once the filesystem is thawed"
    );
    assert!(mountpoint.join("blocked").exists());
    let _ = run("umount", &[&mountpoint.display().to_string()]);
}

#[test]
#[ignore = "requires root, loop devices and fsfreeze"]
fn kill_9_is_recovered_by_the_deadman() {
    if !root_tests_enabled() {
        return;
    }
    if !have("fsfreeze") {
        return;
    }
    let work = tempfile::tempdir_in("/tmp/opencode").expect("workdir");
    let Some((mountpoint, _guard, loop_disk)) = mounted_ext4(work.path(), "dmn") else {
        return;
    };
    let ready = work.path().join("freeze-child.ready");
    let _ = std::fs::remove_file(&ready);

    let mut child = Command::new(std::env::current_exe().expect("current exe"))
        .args(["--exact", "freeze_child_helper", "--ignored", "--nocapture"])
        .env("LR_FREEZE_DEVICE", loop_disk.label())
        .env("LR_FREEZE_MOUNTPOINT", &mountpoint)
        .env("LR_FREEZE_DEST", work.path())
        .env("LR_FREEZE_READY", &ready)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn the child");

    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline && !ready.exists() {
        std::thread::sleep(Duration::from_millis(200));
    }
    if !ready.exists() {
        eprintln!("the child never froze; skipping");
        let _ = child.kill();
        let _ = child.wait();
        return;
    }

    // kill -9 with no chance to thaw: only the external deadman can help.
    child.kill().expect("kill -9 the child");
    let _ = child.wait();

    // The child used a 2 s timeout plus a 2 s grace, so a write must succeed
    // within a few seconds of the kill.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut thawed = false;
    while Instant::now() < deadline {
        if run(
            "sh",
            &[
                "-c",
                &format!("touch {}/after-deadman", mountpoint.display()),
            ],
        ) {
            thawed = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    assert!(
        thawed,
        "the deadman must thaw the filesystem after the job was killed"
    );
    let _ = run("umount", &[&mountpoint.display().to_string()]);
}

/// Child process for [`kill_9_is_recovered_by_the_deadman`].
#[test]
#[ignore = "internal helper for the freeze deadman test"]
fn freeze_child_helper() {
    let Ok(device) = std::env::var("LR_FREEZE_DEVICE") else {
        return;
    };
    let mountpoint = PathBuf::from(std::env::var("LR_FREEZE_MOUNTPOINT").expect("mountpoint"));
    let destination = PathBuf::from(std::env::var("LR_FREEZE_DEST").expect("destination"));
    let ready = std::env::var("LR_FREEZE_READY").expect("ready file");
    let layout = source_layout(Path::new(&device));
    let options = SnapshotOpts {
        allow_freeze: true,
        freeze_timeout_secs: Some(2),
        deadman_grace_secs: Some(2),
        destination: Some(destination),
        ..SnapshotOpts::default()
    };
    let _snapshot = freeze::provider()
        .create(&layout, &options)
        .expect("child freeze");
    std::fs::write(&ready, mountpoint.display().to_string()).expect("signal readiness");
    std::thread::sleep(Duration::from_secs(600));
}

#[test]
#[ignore = "requires root and loop devices"]
fn freeze_refuses_a_destination_on_the_frozen_filesystem() {
    if !root_tests_enabled() {
        return;
    }
    let work = tempfile::tempdir_in("/tmp/opencode").expect("workdir");
    let Some((mountpoint, _guard, loop_disk)) = mounted_ext4(work.path(), "same") else {
        return;
    };
    let layout = source_layout(&loop_disk.device);
    let options = SnapshotOpts {
        allow_freeze: true,
        destination: Some(mountpoint.clone()),
        ..SnapshotOpts::default()
    };
    let support = freeze::provider().supports(&layout, &options);
    assert!(
        support
            .reason()
            .is_some_and(|reason| reason.contains("deadlock")),
        "a destination on the same filesystem must be refused: {support:?}"
    );
    let _ = run("umount", &[&mountpoint.display().to_string()]);
}

#[test]
#[ignore = "requires root, loop devices and mount"]
fn live_none_marks_the_image_inconsistent() {
    if !root_tests_enabled() {
        return;
    }
    let work = tempfile::tempdir_in("/tmp/opencode").expect("workdir");
    let Some((mountpoint, _guard, loop_disk)) = mounted_ext4(work.path(), "live") else {
        return;
    };
    // A live read of a mounted device needs the opt-in.
    let layout = source_layout(&loop_disk.device);
    let strict = SnapshotOpts::default();
    assert!(
        !live_none::provider().supports(&layout, &strict).is_yes(),
        "live reads need --allow-inconsistent"
    );

    let outcome = work.path().join("out");
    let mut request = BackupRequest::new(
        &loop_disk.device,
        &outcome,
        "live-set",
        Encryption::NoEncrypt,
    )
    .expect("request");
    request.chunk_size = CHUNK_SIZE;
    request.compression = Compression::None;
    request.allow_inconsistent = true;
    let report = backup_image(&request).expect("live backup");
    let ImageReport::Block(report) = &report else {
        panic!("expected a block image");
    };
    assert_eq!(report.consistency, lr_core::Consistency::None);

    // Restoring it requires accepting the inconsistency.
    let target = work.path().join("target.img");
    sparse(&target, 256 * 1024 * 1024);
    let plan = prepare_restore(&PrepareRequest::from_path(
        &report.image_path,
        &target,
        Encryption::NoEncrypt,
    ))
    .expect("prepare");
    assert!(
        plan.warnings
            .iter()
            .any(|warning| warning.contains("inconsistent")),
        "the plan must warn: {:?}",
        plan.warnings
    );
    let refused = apply_restore(&ApplyRequest {
        token: plan.token.clone(),
        confirm: true,
        accept_inconsistent: false,
        encryption: Encryption::NoEncrypt,
        context: lr_engine::progress::EngineContext::silent(),
    })
    .expect_err("an inconsistent image must be refused");
    assert!(
        matches!(refused, lr_core::Error::Unsupported { .. }),
        "{refused}"
    );
    apply_restore(&ApplyRequest {
        token: plan.token,
        confirm: true,
        accept_inconsistent: true,
        encryption: Encryption::NoEncrypt,
        context: lr_engine::progress::EngineContext::silent(),
    })
    .expect("apply with --accept-inconsistent");
    let _ = run("umount", &[&mountpoint.display().to_string()]);
    let _ = BadSectorPolicy::Abort;
}
