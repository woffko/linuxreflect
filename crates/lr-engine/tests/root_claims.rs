//! Exclusive device claims (A1, A2, R05), on loop devices as root.
//!
//! A mount in another mount namespace (a container, a service with
//! `PrivateMounts=`, `unshare -m`) is invisible to sysfs holders and to this
//! process's `mountinfo`. These tests make such mounts with `unshare` and
//! check that a restore refuses to write over one (A1) and an offline backup
//! refuses to read one (A2). The last test restores a whole disk onto a
//! target whose kernel partition nodes still describe an older layout, and
//! checks that the swap area is recreated at the image's offset without
//! touching anything else (R05).
//!
//! ```text
//! LR_ROOT_TESTS=1 sudo -E cargo test -p lr-engine --test root_claims -- --ignored --nocapture --test-threads=1
//! ```

use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use lr_engine::backup::{BackupRequest, Compression};
use lr_engine::keys::Encryption;
use lr_engine::restore::{ApplyRequest, PrepareRequest, apply_restore, prepare_restore};
use lr_engine::{ImageReport, backup_image};

const MIB: u64 = 1024 * 1024;

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

fn run(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .stdout(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn require(tools: &[&str]) -> bool {
    for tool in tools {
        if !lr_testkit::have(tool) {
            lr_testkit::unavailable!(return false; "{tool} missing");
        }
    }
    true
}

/// A loop device over a sparse file, with partition scanning.
struct LoopDisk {
    device: PathBuf,
    _dir: tempfile::TempDir,
}

impl LoopDisk {
    fn attach(size: u64) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let backing = dir.path().join("disk.img");
        std::fs::File::create(&backing)
            .and_then(|file| file.set_len(size))
            .expect("backing file");
        // WSL's loop driver can briefly report no free device after a detach.
        for _ in 0..20 {
            let output = Command::new("losetup")
                .args(["-f", "-P", "--show", &backing.display().to_string()])
                .output()
                .expect("run losetup");
            if output.status.success() {
                let device = String::from_utf8_lossy(&output.stdout).trim().to_owned();
                return Self {
                    device: PathBuf::from(device),
                    _dir: dir,
                };
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        lr_testkit::fixture_failed!("losetup found no free loop device")
    }

    fn path(&self) -> String {
        self.device.display().to_string()
    }

    fn partition(&self, index: u32) -> String {
        format!("{}p{index}", self.path())
    }
}

impl Drop for LoopDisk {
    fn drop(&mut self) {
        let _ = run("losetup", &["-d", &self.path()]);
    }
}

/// A read-only mount of `device` inside a private mount namespace.
///
/// `ro,noload` (ext4) keeps the mount from writing anything, so the target's
/// recorded facts stay identical and only the claim can notice the mount.
struct HiddenMount {
    child: Child,
}

impl HiddenMount {
    fn new(device: &str, fs_type: &str, options: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("lr-hidden-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mount dir");
        let script = format!(
            "mount -t {fs_type} -o {options} {device} {dir} && echo mounted && exec sleep 600",
            dir = dir.display()
        );
        let mut child = Command::new("unshare")
            .args(["--mount", "--propagation", "private", "sh", "-c", &script])
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn unshare");
        let mut line = String::new();
        BufReader::new(child.stdout.take().expect("stdout"))
            .read_line(&mut line)
            .expect("read the mount result");
        if line.trim() != "mounted" {
            let _ = child.kill();
            lr_testkit::fixture_failed!("the private-namespace mount of {device} failed");
        }
        // The mount must be invisible here, or the test proves nothing.
        let mounts = std::fs::read_to_string("/proc/self/mountinfo").expect("mountinfo");
        assert!(
            !mounts.contains(&dir.display().to_string()),
            "the mount leaked into this namespace"
        );
        Self { child }
    }
}

impl Drop for HiddenMount {
    fn drop(&mut self) {
        // The namespace, and with it the mount, ends with its last process.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn sha(path: &str) -> String {
    let output = Command::new("sha256sum")
        .arg(path)
        .output()
        .expect("sha256sum");
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_owned()
}

fn ext4_with_file(device: &str, contents: &str) {
    assert!(run("mkfs.ext4", &["-F", "-q", device]), "mkfs.ext4");
    let file = tempfile::NamedTempFile::new().expect("temp");
    std::fs::write(file.path(), contents).expect("write");
    assert!(run(
        "debugfs",
        &[
            "-w",
            "-R",
            &format!("write {} data.txt", file.path().display()),
            device
        ]
    ));
}

fn block_backup(source: &str, dest: &Path) -> lr_core::Result<ImageReport> {
    let mut request =
        BackupRequest::new(source, dest, "claims", Encryption::NoEncrypt).expect("request");
    request.compression = Compression::None;
    backup_image(&request)
}

fn image_path(report: &ImageReport) -> PathBuf {
    match report {
        ImageReport::Block(report) => report.image_path.clone(),
        ImageReport::WholeDisk(report) => report.image_path.clone(),
        other => panic!("unexpected image kind {other:?}"),
    }
}

#[test]
#[ignore = "needs root, loop devices, unshare and e2fsprogs"]
fn a_restore_refuses_a_target_mounted_in_another_namespace() {
    if !root_tests_enabled() || !require(&["unshare", "mkfs.ext4", "debugfs", "sha256sum"]) {
        return;
    }
    let source = LoopDisk::attach(64 * MIB);
    let target = LoopDisk::attach(64 * MIB);
    ext4_with_file(&source.path(), "the image\n");
    ext4_with_file(&target.path(), "the mounted target\n");
    let work = tempfile::tempdir().expect("workdir");
    let report = block_backup(&source.path(), work.path()).expect("backup");

    // Prepared while the target is idle, applied while it is mounted.
    let plan = prepare_restore(&PrepareRequest::from_path(
        image_path(&report),
        &target.device,
        Encryption::NoEncrypt,
    ))
    .expect("prepare an idle target");
    let before = sha(&target.path());
    let hidden = HiddenMount::new(&target.path(), "ext4", "ro,noload");
    let error = apply_restore(&ApplyRequest {
        token: plan.token,
        confirm: true,
        accept_inconsistent: false,
        encryption: Encryption::NoEncrypt,
        context: lr_engine::progress::EngineContext::silent(),
    })
    .expect_err("a restore over a mounted filesystem must be refused");
    assert!(
        matches!(error, lr_core::Error::TargetBusy { .. }),
        "{error}"
    );
    assert_eq!(sha(&target.path()), before, "the target was modified");

    // prepare refuses a mounted target as well.
    let error = prepare_restore(&PrepareRequest::from_path(
        image_path(&report),
        &target.device,
        Encryption::NoEncrypt,
    ))
    .expect_err("prepare must refuse a mounted target");
    assert!(
        matches!(error, lr_core::Error::TargetBusy { .. }),
        "{error}"
    );
    drop(hidden);
}

#[test]
#[ignore = "needs root, loop devices, unshare and dosfstools"]
fn an_offline_backup_refuses_a_source_mounted_in_another_namespace() {
    if !root_tests_enabled() || !require(&["unshare", "mkfs.vfat"]) {
        return;
    }
    let source = LoopDisk::attach(64 * MIB);
    assert!(run("mkfs.vfat", &[&source.path()]), "mkfs.vfat");
    let work = tempfile::tempdir().expect("workdir");
    let hidden = HiddenMount::new(&source.path(), "vfat", "ro");
    let error = block_backup(&source.path(), work.path())
        .expect_err("a source mounted elsewhere is not offline");
    assert!(
        matches!(error, lr_core::Error::NoConsistentMethod { .. }),
        "{error}"
    );
    assert!(
        error.to_string().contains("another mount namespace"),
        "{error}"
    );
    drop(hidden);

    // Once the other mount is gone the same backup is offline.
    let report = block_backup(&source.path(), work.path()).expect("idle backup");
    match report {
        ImageReport::Block(report) => {
            assert_eq!(report.consistency, lr_core::Consistency::Offline);
        }
        other => panic!("unexpected image kind {other:?}"),
    }
}

fn read_region(path: &str, offset: u64, len: u64) -> Vec<u8> {
    let mut file = std::fs::File::open(path).expect("open");
    file.seek(SeekFrom::Start(offset)).expect("seek");
    let mut bytes = vec![0u8; usize::try_from(len).expect("len")];
    file.read_exact(&mut bytes).expect("read");
    bytes
}

#[test]
#[ignore = "needs root, loop devices, sgdisk, e2fsprogs and mkswap"]
fn a_whole_disk_restore_recreates_swap_at_the_image_offset() {
    if !root_tests_enabled()
        || !require(&[
            "sgdisk",
            "mkfs.ext4",
            "mkswap",
            "debugfs",
            "e2fsck",
            "blockdev",
        ])
    {
        return;
    }
    // Image: p1 ext4 at 1 MiB (40 MiB), p2 swap at 41 MiB (16 MiB).
    let source = LoopDisk::attach(128 * MIB);
    assert!(run(
        "sgdisk",
        &[
            "-n1:2048:+40M",
            "-t1:8300",
            "-n2:83968:+16M",
            "-t2:8200",
            &source.path()
        ]
    ));
    assert!(run("blockdev", &["--rereadpt", &source.path()]));
    // A 30 MiB file fills p1, so it covers the old layout's p2 start
    // (9 MiB on the disk, 8 MiB into p1).
    assert!(
        run("mkfs.ext4", &["-F", "-q", &source.partition(1)]),
        "mkfs.ext4"
    );
    let payload = tempfile::NamedTempFile::new().expect("payload");
    assert!(run(
        "dd",
        &[
            "if=/dev/urandom",
            &format!("of={}", payload.path().display()),
            "bs=1M",
            "count=30",
            "status=none"
        ]
    ));
    assert!(run(
        "debugfs",
        &[
            "-w",
            "-R",
            &format!("write {} payload.bin", payload.path().display()),
            &source.partition(1)
        ]
    ));
    assert!(run("mkswap", &["-L", "lrswap", &source.partition(2)]));

    // Target: an older layout whose p2 starts at 9 MiB, inside the image's p1.
    let target = LoopDisk::attach(128 * MIB);
    assert!(run(
        "sgdisk",
        &["-n1:2048:+8M", "-n2:18432:+60M", &target.path()]
    ));
    assert!(run("blockdev", &["--rereadpt", &target.path()]));
    assert!(
        Path::new(&target.partition(2)).exists(),
        "the stale partition node must exist for this test"
    );

    let work = tempfile::tempdir().expect("workdir");
    let report = block_backup(&source.path(), work.path()).expect("whole-disk backup");
    assert!(matches!(report, ImageReport::WholeDisk(_)), "{report:?}");
    let plan = prepare_restore(&PrepareRequest::from_path(
        image_path(&report),
        &target.device,
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

    // The kernel still has the old partition nodes; read the new table.
    assert!(run("blockdev", &["--rereadpt", &target.path()]));
    assert!(
        run("e2fsck", &["-fn", &target.partition(1)]),
        "the restored p1 is not a clean ext4"
    );
    let dump = |device: &str| {
        let out = tempfile::NamedTempFile::new().expect("dump");
        assert!(run(
            "debugfs",
            &[
                "-R",
                &format!("dump payload.bin {}", out.path().display()),
                device
            ]
        ));
        sha(&out.path().display().to_string())
    };
    assert_eq!(
        dump(&source.partition(1)),
        dump(&target.partition(1)),
        "the file across the old p2 start differs after the restore"
    );
    // The swap header is the source's, at the image's p2 offset.
    assert!(
        read_region(&source.path(), 41 * MIB, 4096) == read_region(&target.path(), 41 * MIB, 4096),
        "the swap header was not recreated at the image offset"
    );
}

/// Image kind against target kind (A3): a whole-disk image is refused on a
/// partition, and a single-filesystem image on a partitioned disk needs an
/// explicit acknowledgement whose warning names the partitions it removes.
#[test]
#[ignore = "needs root, loop devices, sgdisk and e2fsprogs"]
fn image_and_target_kinds_must_match() {
    if !root_tests_enabled() || !require(&["sgdisk", "mkfs.ext4", "blockdev"]) {
        return;
    }
    let work = tempfile::tempdir().expect("workdir");

    // A whole-disk image of a two-partition disk.
    let disk = LoopDisk::attach(96 * MIB);
    assert!(run(
        "sgdisk",
        &["-n1:2048:+40M", "-n2:0:+40M", &disk.path()]
    ));
    assert!(run("blockdev", &["--rereadpt", &disk.path()]));
    for index in [1, 2] {
        assert!(run("mkfs.ext4", &["-F", "-q", &disk.partition(index)]));
    }
    let whole = block_backup(&disk.path(), &work.path().join("whole")).expect("whole-disk backup");
    assert!(matches!(whole, ImageReport::WholeDisk(_)), "{whole:?}");

    // A single-filesystem image.
    let single_source = LoopDisk::attach(32 * MIB);
    ext4_with_file(&single_source.path(), "single\n");
    let single =
        block_backup(&single_source.path(), &work.path().join("single")).expect("block backup");

    // The target: a disk with two partitions, the first larger than the
    // whole-disk image.
    let target = LoopDisk::attach(256 * MIB);
    assert!(run(
        "sgdisk",
        &["-n1:2048:+200M", "-n2:0:+40M", &target.path()]
    ));
    assert!(run("blockdev", &["--rereadpt", &target.path()]));
    let partition = PathBuf::from(target.partition(1));

    let error = prepare_restore(&PrepareRequest::from_path(
        image_path(&whole),
        &partition,
        Encryption::NoEncrypt,
    ))
    .expect_err("a whole-disk image must not go into a partition");
    assert!(error.to_string().contains("is a partition"), "{error}");

    let error = prepare_restore(&PrepareRequest::from_path(
        image_path(&single),
        &target.device,
        Encryption::NoEncrypt,
    ))
    .expect_err("a partitioned disk needs an acknowledgement");
    let text = error.to_string();
    assert!(
        text.contains(&target.partition(1)) && text.contains(&target.partition(2)),
        "the refusal names the partitions: {text}"
    );

    let plan = prepare_restore(
        &PrepareRequest::from_path(image_path(&single), &target.device, Encryption::NoEncrypt)
            .with_replace_partition_table(true),
    )
    .expect("an acknowledged replacement is prepared");
    assert!(
        plan.warnings
            .iter()
            .any(|warning| warning.contains(&target.partition(2))),
        "{:?}",
        plan.warnings
    );

    // The partition itself is a fine target for the single-filesystem image.
    prepare_restore(&PrepareRequest::from_path(
        image_path(&single),
        &partition,
        Encryption::NoEncrypt,
    ))
    .expect("a partition image onto a partition");
}
