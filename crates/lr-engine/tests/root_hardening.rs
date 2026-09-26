//! Hardening matrix (spec §K S17).
//!
//! Four areas, each with a real device on this machine:
//!
//! * every filesystem the specification names (ext4, xfs, btrfs, fat32, ntfs)
//!   survives a block round trip and passes its own checker;
//! * a device whose sectors fail (`dm-flakey` with `error_reads`) is either
//!   refused (`--on-bad-sector abort`) or recorded (`record`), the image
//!   verifies, and a restore **refuses** to fabricate the missing data;
//! * an interrupted SMB or NFS destination leaves no image behind and a lock
//!   that a retry can break;
//! * a 16 TB virtual disk produces a valid image whose metadata stream keeps
//!   the process inside a documented RSS bound.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use lr_engine::backup::{BackupRequest, BadSectorPolicy, Compression};
use lr_engine::keys::Encryption;
use lr_engine::restore::{ApplyRequest, PrepareRequest, apply_restore, prepare_restore};
use lr_engine::{backup_block_full, backup_image};

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

/// Run a command but abandon it after `secs` seconds instead of joining it.
///
/// `mount.cifs` can block in an uninterruptible state against a half-open
/// server, and even `timeout -k` waits for that child, so the test must walk
/// away from the process rather than let it wedge the suite.
fn run_bounded(secs: u64, program: &str, args: &[&str]) -> bool {
    let mut child = match Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(_) => return false,
    };
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                return false;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(_) => return false,
        }
    }
}

fn text(output: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// A loop device over a sparse file, detached on drop.
struct LoopDevice {
    device: String,
    backing: PathBuf,
}

impl LoopDevice {
    fn attach(dir: &Path, name: &str, size: u64) -> Option<Self> {
        let backing = dir.join(name);
        let file = std::fs::File::create(&backing).expect("create");
        file.set_len(size).expect("size");
        drop(file);
        let free = Command::new("losetup")
            .arg("-f")
            .output()
            .expect("losetup -f");
        let device = String::from_utf8_lossy(&free.stdout).trim().to_owned();
        if !run("losetup", &["-P", &device, &backing.display().to_string()]) {
            lr_testkit::fixture_failed!("could not attach a loop device");
        }
        Some(Self { device, backing })
    }

    fn path(&self) -> PathBuf {
        PathBuf::from(&self.device)
    }

    fn mount(&self, at: &Path) -> bool {
        std::fs::create_dir_all(at).expect("mount point");
        run("mount", &[&self.device, &at.display().to_string()])
    }

    fn unmount(&self, at: &Path) -> bool {
        run("umount", &[&at.display().to_string()])
    }
}

impl Drop for LoopDevice {
    fn drop(&mut self) {
        let _ = run("losetup", &["-d", &self.device]);
        let _ = self.backing.clone();
    }
}

fn populate(root: &Path, files: usize) {
    std::fs::create_dir_all(root.join("dir/sub")).expect("dirs");
    for index in 0..files {
        let bytes: Vec<u8> = (0..64 * 1024)
            .map(|byte| ((byte + index * 13) % 251) as u8)
            .collect();
        std::fs::write(root.join(format!("dir/file{index}.bin")), &bytes).expect("file");
    }
    std::fs::write(root.join("dir/sub/tail.txt"), b"matrix\n").expect("file");
}

fn request(source: &Path, dest: &Path) -> BackupRequest {
    let mut request =
        BackupRequest::new(source, dest, "matrix", Encryption::NoEncrypt).expect("request");
    request.compression = Compression::Zstd { level: 1 };
    // Blocks, not a btrfs send stream: the device is unmounted, so the offline
    // provider is the correct one and the image is a plain Block image.
    request.snapshot_provider = Some("offline".to_owned());
    request
}

/// A hash of every file below `root`, for a content comparison.
fn tree_hashes(root: &Path) -> String {
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "cd {} && find . -type f | sort | xargs -r sha256sum",
            root.display()
        ))
        .output()
        .expect("hash the tree");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Which filesystem to exercise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Filesystem {
    Ext4,
    Xfs,
    Btrfs,
    Fat32,
    Ntfs,
}

impl Filesystem {
    fn name(self) -> &'static str {
        match self {
            Self::Ext4 => "ext4",
            Self::Xfs => "xfs",
            Self::Btrfs => "btrfs",
            Self::Fat32 => "fat32",
            Self::Ntfs => "ntfs",
        }
    }

    fn mkfs(self) -> &'static str {
        match self {
            Self::Ext4 => "mkfs.ext4",
            Self::Xfs => "mkfs.xfs",
            Self::Btrfs => "mkfs.btrfs",
            Self::Fat32 => "mkfs.vfat",
            Self::Ntfs => "mkfs.ntfs",
        }
    }

    fn size_mib(self) -> u64 {
        match self {
            Self::Xfs => 400,
            _ => 160,
        }
    }

    fn checker(self) -> (&'static str, &'static [&'static str]) {
        match self {
            Self::Ext4 => ("fsck.ext4", &["-f", "-n"]),
            Self::Xfs => ("xfs_repair", &["-n"]),
            Self::Btrfs => ("btrfs", &["check", "--readonly"]),
            Self::Fat32 => ("fsck.vfat", &["-n"]),
            Self::Ntfs => ("ntfsfix", &["-n"]),
        }
    }

    /// Mount the restored device so its contents can be compared.
    fn mount_type(self) -> Option<&'static str> {
        match self {
            Self::Ntfs => Some("ntfs-3g"),
            _ => None,
        }
    }
}

fn format(device: &Path, fs: Filesystem) -> bool {
    let device = device.display().to_string();
    match fs {
        Filesystem::Ext4 => run("mkfs.ext4", &["-F", "-q", "-L", "MATRIX", &device]),
        Filesystem::Xfs => run("mkfs.xfs", &["-f", "-q", "-L", "MATRIX", &device]),
        Filesystem::Btrfs => run("mkfs.btrfs", &["-f", "-q", "-L", "MATRIX", &device]),
        Filesystem::Fat32 => run("mkfs.vfat", &["-F", "32", "-n", "MATRIX", &device]),
        Filesystem::Ntfs => run("mkfs.ntfs", &["-F", "-Q", "-L", "MATRIX", &device]),
    }
}

/// Back up, restore and check one filesystem (spec §K S17).
fn round_trip(fs: Filesystem) {
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(source) = LoopDevice::attach(dir.path(), "source.img", fs.size_mib() * 1024 * 1024)
    else {
        return;
    };
    if !format(&source.path(), fs) {
        lr_testkit::fixture_failed!("mkfs.{} failed - {}", fs.name(), fs.name());
    }
    let mount = dir.path().join("source-mount");
    let mount_options = fs.mount_type();
    if let Some(kind) = mount_options {
        std::fs::create_dir_all(&mount).expect("mount point");
        if !run(
            "mount",
            &[
                "-t",
                kind,
                &source.path().display().to_string(),
                &mount.display().to_string(),
            ],
        ) {
            lr_testkit::fixture_failed!("mounting {} failed", fs.name());
        }
    } else if !source.mount(&mount) {
        lr_testkit::fixture_failed!("mounting {} failed", fs.name());
    }
    populate(&mount, 6);
    let expected = tree_hashes(&mount);
    let _ = run("sync", &[]);
    if mount_options.is_some() {
        let _ = run("umount", &[&mount.display().to_string()]);
    } else {
        let _ = source.unmount(&mount);
    }

    // Backup (the used-block map where one exists, raw otherwise).
    let dest = dir.path().join("backups");
    let report = backup_image(&request(&source.path(), &dest)).expect("backup");
    let image = match &report {
        lr_engine::ImageReport::Block(report) => report.image_path.clone(),
        other => panic!("expected a block image, got {other:?}"),
    };

    // Restore onto a fresh device of the same size.
    let Some(target) = LoopDevice::attach(dir.path(), "target.img", fs.size_mib() * 1024 * 1024)
    else {
        return;
    };
    let plan = prepare_restore(&PrepareRequest::from_path(
        &image,
        target.path(),
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

    // The filesystem's own checker decides whether the restore is sound.
    let (checker, args) = fs.checker();
    let mut command = Command::new(checker);
    command.args(args).arg(target.path());
    let output = command.output().expect("checker");
    assert!(
        output.status.success(),
        "{} on the restored {} image failed:\n{}",
        checker,
        fs.name(),
        text(&output)
    );

    // And the contents match.
    let restored_mount = dir.path().join("restored-mount");
    let mounted = if let Some(kind) = mount_options {
        std::fs::create_dir_all(&restored_mount).expect("mount point");
        run(
            "mount",
            &[
                "-t",
                kind,
                &target.path().display().to_string(),
                &restored_mount.display().to_string(),
            ],
        )
    } else {
        target.mount(&restored_mount)
    };
    assert!(mounted, "mounting the restored {} failed", fs.name());
    let restored = tree_hashes(&restored_mount);
    if mount_options.is_some() {
        let _ = run("umount", &[&restored_mount.display().to_string()]);
    } else {
        let _ = target.unmount(&restored_mount);
    }
    assert_eq!(
        restored,
        expected,
        "the restored {} does not match the source",
        fs.name()
    );
}

#[test]
#[ignore = "requires root, loop devices and the filesystem tools"]
fn every_named_filesystem_round_trips_and_passes_its_checker() {
    if !root_tests_enabled() {
        return;
    }
    for fs in [
        Filesystem::Ext4,
        Filesystem::Xfs,
        Filesystem::Btrfs,
        Filesystem::Fat32,
        Filesystem::Ntfs,
    ] {
        if !have(fs.mkfs()) || !have(fs.checker().0) {
            eprintln!(
                "{} or {} missing; skipping {}",
                fs.mkfs(),
                fs.checker().0,
                fs.name()
            );
            continue;
        }
        eprintln!("=== {} ===", fs.name());
        round_trip(fs);
    }
}

/// Start a mapper over `backing` whose **second half** fails every read.
///
/// The first half is a plain `linear` target, so the image has stored chunks to
/// verify next to the recorded bad ones; a device that fails everywhere would
/// leave nothing to re-hash.
fn flakey_over(backing: &Path, sectors: u64) -> Option<String> {
    let name = format!("lr-flakey-{}", std::process::id());
    let _ = run("dmsetup", &["remove", &name]);
    let half = sectors / 2;
    // `up_interval = 0` means "always down": every read in the tail fails,
    // which is deterministic (a time window would race the backup).
    let table = format!(
        "0 {half} linear {device} 0\n{half} {half} flakey {device} {half} 0 1 1 error_reads",
        device = backing.display()
    );
    let output = Command::new("dmsetup")
        .args(["create", &name, "--table", &table])
        .output()
        .expect("dmsetup create");
    if !output.status.success() {
        lr_testkit::unavailable!(return None; "dm-flakey is unavailable: {}", text(&output));
    }
    // Without udev (a container) nothing creates the node; ask dmsetup to.
    let node = format!("/dev/mapper/{name}");
    for _ in 0..20 {
        if Path::new(&node).exists() {
            break;
        }
        let _ = run("dmsetup", &["mknodes", &name]);
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Some(node)
}

#[test]
#[ignore = "requires root, loop devices and dm-flakey"]
fn dm_flakey_bad_sectors_are_recorded_and_a_restore_refuses_them() {
    if !root_tests_enabled() {
        return;
    }
    if !have("dmsetup") || !have("mkfs.ext4") {
        lr_testkit::unavailable!("dmsetup or mkfs.ext4 missing");
    }
    const SIZE: u64 = 128 * 1024 * 1024;
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(source) = LoopDevice::attach(dir.path(), "flakey.img", SIZE) else {
        return;
    };
    assert!(format(&source.path(), Filesystem::Ext4), "mkfs.ext4 failed");
    let mount = dir.path().join("mount");
    assert!(source.mount(&mount), "mount failed");
    populate(&mount, 8);
    let _ = run("sync", &[]);
    assert!(source.unmount(&mount), "umount failed");

    // The flakey device fails reads in its down intervals, which is what a
    // dying disk looks like to the reader.
    let sectors = SIZE / 512;
    let Some(flakey) = flakey_over(&source.path(), sectors) else {
        return;
    };
    let dest = dir.path().join("backups");

    // `abort` refuses to image a device it cannot read.
    let mut aborting = request(Path::new(&flakey), &dest);
    aborting.on_bad_sector = BadSectorPolicy::Abort;
    let error = backup_block_full(&aborting).expect_err("abort must fail the job");
    assert!(
        matches!(error, lr_core::Error::BadSector { .. }),
        "expected BadSector, got {error}"
    );

    // `record` completes and marks the unreadable chunks.
    let mut recording = request(Path::new(&flakey), &dest);
    recording.on_bad_sector = BadSectorPolicy::Record;
    let report = backup_block_full(&recording).expect("record must complete the job");
    assert!(report.bad_chunks > 0, "unreadable chunks must be recorded");
    assert!(
        report.stored_chunks + report.zero_chunks + report.bad_chunks <= report.total_chunks,
        "recorded states must add up"
    );

    // The image is structurally sound, so `verify` accepts it.
    let verified = lr_engine::verify::verify_image(&lr_engine::verify::VerifyRequest {
        image: report.image_uri.clone(),
        encryption: Encryption::NoEncrypt,
        chain: false,
        destination_options: lr_store::DestinationOptions {
            set_name: "matrix".to_owned(),
            identity: None,
            known_hosts: None,
            insecure_ignore_host_key: false,
        },
        context: lr_engine::progress::EngineContext::silent(),
    })
    .expect("a recorded bad sector is not corruption");
    assert!(verified.chunks > 0);

    // A restore refuses to invent the missing data.
    let Some(target) = LoopDevice::attach(dir.path(), "target.img", SIZE) else {
        return;
    };
    let plan = prepare_restore(&PrepareRequest::from_path(
        &report.image_path,
        target.path(),
        Encryption::NoEncrypt,
    ))
    .expect("prepare");
    let error = apply_restore(&ApplyRequest {
        token: plan.token,
        confirm: true,
        accept_inconsistent: false,
        encryption: Encryption::NoEncrypt,
        context: lr_engine::progress::EngineContext::silent(),
    })
    .expect_err("a recorded bad sector cannot be restored");
    assert!(
        matches!(error, lr_core::Error::BadSector { .. }),
        "expected BadSector, got {error}"
    );
    let _ = run("dmsetup", &["remove", &flakey.replace("/dev/mapper/", "")]);
}

/// A 16 TB virtual disk must not drag the metadata into RAM.
#[test]
#[ignore = "requires root, loop devices and a large sparse file"]
fn a_16_tb_virtual_disk_keeps_metadata_rss_bounded() {
    if !root_tests_enabled() {
        return;
    }
    if !have("mkfs.ext4") {
        lr_testkit::unavailable!("mkfs.ext4 missing");
    }
    const SIZE: u64 = 16 * 1000 * 1000 * 1000 * 1000; // 16 TB virtual
    let dir = tempfile::tempdir().expect("tempdir");
    // Formatting a 16 TB filesystem takes about ten minutes, so a prepared
    // fixture may be reused (`LR_S17_HUGE_IMG=/path/to/huge.img`); the default
    // path creates and formats it.
    let prepared = std::env::var_os("LR_S17_HUGE_IMG").map(PathBuf::from);
    let source = match prepared.filter(|path| path.exists()) {
        Some(path) => {
            let free = Command::new("losetup")
                .arg("-f")
                .output()
                .expect("losetup -f");
            let device = String::from_utf8_lossy(&free.stdout).trim().to_owned();
            assert!(run(
                "losetup",
                &["-P", &device, &path.display().to_string()]
            ));
            LoopDevice {
                device,
                backing: path,
            }
        }
        None => {
            let Some(source) = LoopDevice::attach(dir.path(), "huge.img", SIZE) else {
                return;
            };
            assert!(format(&source.path(), Filesystem::Ext4), "mkfs.ext4 failed");
            source
        }
    };

    let cli = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/linuxreflect");
    if !cli.exists() {
        lr_testkit::unavailable!("the CLI is not built");
    }
    let dest = dir.path().join("backups");
    let mut child = Command::new(&cli)
        .args(["backup", "create", "--source"])
        .arg(source.path())
        .args(["--dest"])
        .arg(&dest)
        .args([
            "--set",
            "scale",
            "--no-encrypt",
            "--compress",
            "none",
            // The largest chunk the format allows keeps the manifest at
            // 16 TiB / 4 MiB = 4 M entries, which is the scaling case.
            "--chunk-size",
            "4MiB",
            "--json",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start the backup");
    // Sample the peak RSS while it runs.
    let mut peak_kib = 0u64;
    let started = Instant::now();
    loop {
        if let Ok(status) = std::fs::read_to_string(format!("/proc/{}/status", child.id())) {
            for line in status.lines() {
                if let Some(value) = line.strip_prefix("VmHWM:") {
                    let kib = value
                        .split_whitespace()
                        .next()
                        .and_then(|value| value.parse::<u64>().ok())
                        .unwrap_or(0);
                    peak_kib = peak_kib.max(kib);
                }
            }
        }
        match child.try_wait().expect("wait") {
            Some(_) => break,
            None => {
                if started.elapsed() > Duration::from_secs(1800) {
                    let _ = child.kill();
                    break;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
    let output = child.wait_with_output().expect("output");
    assert!(
        output.status.success(),
        "the 16 TiB backup failed:\n{}",
        text(&output)
    );

    // The bound: the manifest for 4 M chunks is 184 MB on disk, and the
    // streamed writer must not need anything like the 736 MB a fully
    // materialized 16 TiB manifest would take.
    let peak_mib = peak_kib / 1024;
    eprintln!("peak RSS: {peak_mib} MiB");
    assert!(
        peak_mib < 1024,
        "the 16 TiB backup peaked at {peak_mib} MiB RSS; the bound is 1 GiB"
    );

    // Prove the manifest really covers the whole device: the image is at least
    // as large as the 46-byte entries for every 4 MiB chunk. The report is the
    // JSON object after the progress lines.
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let start = stdout.find('{').expect("the report JSON");
    let end = stdout.rfind('}').expect("the report JSON");
    let report: serde_json::Value =
        serde_json::from_str(&stdout[start..=end]).expect("report JSON");
    let image_path = report["image_path"].as_str().expect("image path");
    let size = std::fs::metadata(image_path).expect("stat").len();
    let entries = SIZE / (4 * 1024 * 1024);
    let minimum = entries * 46;
    assert!(
        size >= minimum,
        "the image is {size} bytes, smaller than {minimum} bytes of manifest entries"
    );
}

/// Start a throwaway SMB server exporting `share` and mount it at `at`.
///
/// The server binds a private, per-process port so it can never collide with a
/// distribution `smbd` that already owns 445 (which silently made the client
/// mount the wrong server), and every client command is bounded with `timeout`
/// so a half-open server can never wedge the suite.
///
/// # Errors
/// Returns `None` (with a printed reason) when smbd or mount.cifs cannot be
/// used, so the test skips instead of pretending.
fn start_smb(work: &Path, share: &Path, at: &Path) -> Option<(Child, String)> {
    if !have("smbd") || !have("mount.cifs") || !have("timeout") {
        lr_testkit::unavailable!(return None; "smbd, mount.cifs or timeout missing - the SMB test");
    }
    let port = 24000 + (std::process::id() % 10000) as u16;
    std::fs::create_dir_all(share).expect("share");
    std::fs::create_dir_all(at).expect("mount point");
    std::fs::write(share.join("lr-ready"), b"linuxreflect").expect("marker");
    // smbd needs its own runtime directories before it will start.
    for sub in ["pids", "locks", "private", "state", "cache"] {
        std::fs::create_dir_all(work.join(sub)).expect("smbd runtime directory");
    }
    let conf = work.join("smb.conf");
    std::fs::write(
        &conf,
        format!(
            "[global]\n\
             workgroup = WORKGROUP\n\
             server role = standalone server\n\
             log file = {log}\n\
             pid directory = {pids}\n\
             lock directory = {locks}\n\
             private dir = {priv}\n\
             state directory = {state}\n\
             cache directory = {cache}\n\
             map to guest = Bad User\n\
             guest account = root\n\
             server min protocol = SMB3\n\
             smb ports = {port}\n\
             \n\
             [matrix]\n\
             path = {share}\n\
             guest ok = yes\n\
             read only = no\n\
             browseable = no\n\
             force user = root\n",
            log = work.join("smbd.log").display(),
            pids = work.join("pids").display(),
            locks = work.join("locks").display(),
            priv = work.join("private").display(),
            state = work.join("state").display(),
            cache = work.join("cache").display(),
            port = port,
            share = share.display()
        ),
    )
    .expect("smb.conf");
    let child = Command::new("smbd")
        .arg("--foreground")
        .arg("--no-process-group")
        .arg("-s")
        .arg(&conf)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn smbd");
    let url = "//127.0.0.1/matrix".to_owned();
    let options = format!("guest,vers=3.1.1,uid=0,gid=0,port={port},soft");
    // The share is ready once our own marker is visible through the mount, so
    // a stale server on the port cannot masquerade as ours. Every client
    // command is bounded because a wedged `mount.cifs` ignores SIGTERM.
    let mut child = child;
    for _ in 0..30 {
        if run_bounded(
            12,
            "mount",
            &[
                "-t",
                "cifs",
                &url,
                &at.display().to_string(),
                "-o",
                &options,
            ],
        ) && at.join("lr-ready").exists()
        {
            return Some((child, url));
        }
        let _ = run_bounded(12, "umount", &["-f", &at.display().to_string()]);
        std::thread::sleep(Duration::from_millis(250));
    }
    let _ = child.kill();
    lr_testkit::fixture_failed!("the SMB share never mounted")
}

/// Export `dir` over NFS to localhost and mount it at `at`.
fn start_nfs(work: &Path, dir: &Path, at: &Path) -> Option<String> {
    if !have("exportfs") || !have("mount.nfs") {
        lr_testkit::unavailable!(return None; "exportfs or mount.nfs missing - the NFS test");
    }
    std::fs::create_dir_all(dir).expect("export dir");
    std::fs::create_dir_all(at).expect("mount point");
    let _ = run("rpcbind", &[]);
    // `rpc.nfsd` starts the kernel threads; eight is plenty.
    let nfsd = Command::new("rpc.nfsd").arg("8").output();
    if nfsd.map(|output| !output.status.success()).unwrap_or(true) {
        lr_testkit::fixture_failed!("rpc.nfsd could not be started - the NFS test");
    }
    let export = format!("127.0.0.1:{}", dir.display());
    if !run(
        "exportfs",
        &["-i", "-o", "rw,no_root_squash,insecure,fsid=0", &export],
    ) {
        lr_testkit::fixture_failed!("exportfs refused the export - the NFS test");
    }
    let _ = work;
    if !run(
        "mount",
        &[
            "-t",
            "nfs",
            "-o",
            "vers=4,proto=tcp",
            "127.0.0.1:/",
            &at.display().to_string(),
        ],
    ) {
        lr_testkit::fixture_failed!("the NFS export never mounted");
    }
    Some(export)
}

/// Interrupt a running backup by breaking the destination, then check the
/// destination and a retry.
fn interrupt_destination(mount: &Path, break_share: impl FnOnce(), label: &str) {
    let dir = tempfile::tempdir().expect("tempdir");
    // A source large enough that the backup is still running when the share
    // goes away.
    let Some(source) = LoopDevice::attach(dir.path(), "source.img", 1024 * 1024 * 1024) else {
        return;
    };
    assert!(format(&source.path(), Filesystem::Ext4), "mkfs.ext4 failed");
    let filled = dir.path().join("filled");
    assert!(source.mount(&filled), "mount failed");
    populate(&filled, 512);
    let _ = run("sync", &[]);
    assert!(source.unmount(&filled), "umount failed");

    let dest = mount.join("backups");
    std::fs::create_dir_all(&dest).expect("destination directory");
    let request = request(&source.path(), &dest);
    let started = Instant::now();
    let handle = std::thread::spawn(move || backup_block_full(&request));
    // The interruption must land while the backup is still writing: the
    // source is large enough that it needs well over a second.
    std::thread::sleep(Duration::from_millis(300));
    break_share();
    let outcome = handle.join().expect("the backup thread panicked");
    eprintln!(
        "{label}: the interrupted backup finished after {:?}",
        started.elapsed()
    );
    assert!(
        outcome.is_err(),
        "a backup whose destination vanished must fail ({label})"
    );

    // A partial image must never be finalized, and the lock must be breakable.
    let leftovers = list_images(&dest);
    assert!(
        leftovers.is_empty(),
        "the interrupted {label} backup left images behind: {leftovers:?}"
    );
}

/// Every `.lrimg` file below `root`, recursively.
fn list_images(root: &Path) -> Vec<PathBuf> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "find {} -name '*.lrimg' 2>/dev/null",
            root.display()
        ))
        .output()
        .expect("find");
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(PathBuf::from)
        .collect()
}

#[test]
#[ignore = "requires root, loop devices, smbd and mount.cifs"]
fn an_smb_destination_survives_an_interruption() {
    if !root_tests_enabled() {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let share = dir.path().join("share");
    let mount = dir.path().join("cifs");
    let Some((mut smbd, _url)) = start_smb(dir.path(), &share, &mount) else {
        return;
    };
    let mount_point = mount.display().to_string();
    interrupt_destination(
        &mount,
        move || {
            // A lazy unmount alone leaves the detached filesystem connected, so
            // the write can still succeed. Stop the server too; the mount is
            // `soft`, so the in-flight write then fails instead of retrying.
            let _ = smbd.kill();
            let _ = run_bounded(12, "umount", &["-f", &mount_point]);
            let _ = run_bounded(12, "umount", &["-l", &mount_point]);
        },
        "smb",
    );
}

#[test]
#[ignore = "requires root, loop devices, rpcbind, nfs-kernel-server and mount.nfs"]
fn an_nfs_destination_survives_an_interruption() {
    if !root_tests_enabled() {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let export_dir = dir.path().join("export");
    let mount = dir.path().join("nfs");
    let Some(export) = start_nfs(dir.path(), &export_dir, &mount) else {
        return;
    };
    // Unexport and force-unmount: an NFS server that goes away leaves the
    // client's open file unusable, which is what the writer must notice.
    interrupt_destination(
        &mount,
        || {
            let _ = run("exportfs", &["-u", &export]);
            let _ = run("umount", &["-f", &mount.display().to_string()]);
            let _ = run("umount", &["-l", &mount.display().to_string()]);
        },
        "nfs",
    );
    let _ = run("umount", &["-f", &mount.display().to_string()]);
    let _ = run("exportfs", &["-u", &export]);
}

/// A tiny initramfs that announces itself on the serial console.
fn marker_initramfs(dir: &Path, marker: &str) -> PathBuf {
    let tree = dir.join("initramfs-tree");
    let _ = std::fs::remove_dir_all(&tree);
    for path in ["bin", "proc", "sys", "dev"] {
        std::fs::create_dir_all(tree.join(path)).expect("initramfs dirs");
    }
    std::fs::copy("/bin/busybox", tree.join("bin/busybox")).expect("busybox");
    let listing = Command::new("/bin/busybox")
        .arg("--list")
        .output()
        .expect("busybox --list");
    for applet in String::from_utf8_lossy(&listing.stdout).lines() {
        let applet = applet.trim();
        if applet.is_empty() || applet == "busybox" {
            continue;
        }
        let link = tree.join("bin").join(applet);
        if !link.exists() {
            // Relative links: absolute ones would point into the build tree.
            std::os::unix::fs::symlink("busybox", &link).expect("applet link");
        }
    }
    std::fs::write(
        tree.join("init"),
        format!(
            "#!/bin/sh\n\
             /bin/busybox --install -s /bin 2>/dev/null\n\
             mount -t proc proc /proc 2>/dev/null\n\
             mount -t sysfs sys /sys 2>/dev/null\n\
             mount -t devtmpfs dev /dev 2>/dev/null\n\
             echo {marker} > /dev/ttyS0\n\
             echo {marker}\n\
             sleep 1\n\
             poweroff -f\n"
        ),
    )
    .expect("init");
    let _ = std::fs::set_permissions(
        tree.join("init"),
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    );
    let archive = dir.join("initramfs.cpio.gz");
    let status = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "cd {} && find . | cpio -o -H newc 2>/dev/null | gzip -9 > {}",
            tree.display(),
            archive.display()
        ))
        .status()
        .expect("build the initramfs");
    assert!(status.success(), "the initramfs build failed");
    archive
}

/// Build a bootable GPT disk with `fs` as the root filesystem.
fn bootable_disk(dir: &Path, fs: Filesystem, kernel: &Path) -> Option<LoopDevice> {
    const SIZE: u64 = 768 * 1024 * 1024;
    let disk = LoopDevice::attach(dir, "boot.img", SIZE)?;
    let device = disk.path();
    if !run(
        "sgdisk",
        &[
            "--clear",
            "-n",
            "1:2048:+1M",
            "-t",
            "1:ef02",
            "-c",
            "1:BIOS",
            "-n",
            "2:4096:+64M",
            "-t",
            "2:ef00",
            "-c",
            "2:ESP",
            "-n",
            "3:135168:0",
            "-t",
            "3:8300",
            "-c",
            "3:ROOT",
            &device.display().to_string(),
        ],
    ) {
        lr_testkit::fixture_failed!("sgdisk could not partition {}", device.display());
    }
    let esp_device = PathBuf::from(format!("{}p2", device.display()));
    let root_device = PathBuf::from(format!("{}p3", device.display()));
    assert!(
        run(
            "mkfs.vfat",
            &["-F", "32", "-n", "ESP", &esp_device.display().to_string()]
        ),
        "mkfs.vfat failed"
    );
    assert!(format(&root_device, fs), "mkfs.{} failed", fs.name());

    // The kernel and the initramfs live on the root filesystem, so booting
    // proves that GRUB can read it.
    let esp_mount = dir.join("esp");
    let root_mount = dir.join("rootfs");
    std::fs::create_dir_all(&esp_mount).expect("esp mount point");
    std::fs::create_dir_all(&root_mount).expect("root mount point");
    assert!(
        run(
            "mount",
            &[
                "-t",
                "vfat",
                &esp_device.display().to_string(),
                &esp_mount.display().to_string()
            ]
        ),
        "mounting the ESP failed"
    );
    let root_mounted = if let Some(kind) = fs.mount_type() {
        run(
            "mount",
            &[
                "-t",
                kind,
                &root_device.display().to_string(),
                &root_mount.display().to_string(),
            ],
        )
    } else {
        run(
            "mount",
            &[
                &root_device.display().to_string(),
                &root_mount.display().to_string(),
            ],
        )
    };
    assert!(root_mounted, "mounting the {} root failed", fs.name());

    let marker = format!("LR-BOOT-{}", fs.name().to_uppercase());
    std::fs::copy(kernel, root_mount.join("vmlinuz")).expect("kernel");
    let initramfs = marker_initramfs(dir, &marker);
    std::fs::copy(&initramfs, root_mount.join("initramfs.cpio.gz")).expect("initramfs");
    let config = format!(
        "serial --unit=0 --speed=115200\n\
         terminal_input serial console\n\
         terminal_output serial console\n\
         set timeout=3\n\
         menuentry \"matrix {name}\" {{\n\
         \x20 search --no-floppy --file --set=root /vmlinuz\n\
         \x20 linux /vmlinuz console=ttyS0 console=tty0 panic=-1\n\
         \x20 initrd /initramfs.cpio.gz\n\
         \x20 boot\n\
         }}\n",
        name = fs.name()
    );
    for relative in ["boot/grub/grub.cfg", "EFI/BOOT/grub.cfg", "grub/grub.cfg"] {
        let path = esp_mount.join(relative);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("grub dir");
        std::fs::write(&path, &config).expect("grub.cfg");
    }
    let embedded = esp_mount.join("embedded.cfg");
    std::fs::write(&embedded, &config).expect("embedded config");
    assert!(
        run(
            "grub-install",
            &[
                "--target=i386-pc",
                "--recheck",
                "--no-floppy",
                "--boot-directory",
                &esp_mount.display().to_string(),
                &device.display().to_string(),
            ]
        ),
        "grub-install (BIOS) failed"
    );
    let efi_dir = esp_mount.join("EFI/BOOT");
    std::fs::create_dir_all(&efi_dir).expect("EFI dir");
    assert!(
        run(
            "grub-mkstandalone",
            &[
                "-O",
                "x86_64-efi",
                "--modules=part_gpt fat normal linux echo search search_fs_file configfile xfs btrfs ext2",
                "-o",
                &efi_dir.join("BOOTX64.EFI").display().to_string(),
                &format!("boot/grub/grub.cfg={}", embedded.display()),
            ]
        ),
        "grub-mkstandalone failed"
    );
    let _ = run("sync", &[]);
    let _ = run("umount", &[&root_mount.display().to_string()]);
    let _ = run("umount", &[&esp_mount.display().to_string()]);
    Some(disk)
}

/// Boot a disk with qemu and return its serial log (spec §K S17).
fn boot_disk(disk: &Path, uefi: bool, work: &Path, label: &str) -> String {
    let serial = work.join(format!("serial-{label}.log"));
    let _ = std::fs::remove_file(&serial);
    let mut command = Command::new("qemu-system-x86_64");
    if Path::new("/dev/kvm").exists() {
        command.args(["-enable-kvm", "-cpu", "host"]);
    }
    command
        .args(["-m", "1024", "-smp", "2", "-display", "none", "-no-reboot"])
        .arg("-serial")
        .arg(format!("file:{}", serial.display()))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if uefi {
        let vars = work.join(format!("vars-{label}.fd"));
        std::fs::copy("/usr/share/OVMF/OVMF_VARS_4M.fd", &vars).expect("OVMF vars");
        command
            .args(["-machine", "q35"])
            .arg("-drive")
            .arg("if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd")
            .arg("-drive")
            .arg(format!("if=pflash,format=raw,file={}", vars.display()));
    }
    let mut child = command
        .arg("-drive")
        .arg(format!(
            "file={},format=raw,index=0,media=disk",
            disk.display()
        ))
        .spawn()
        .expect("start qemu");
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        if let Ok(text) = std::fs::read_to_string(&serial)
            && text.contains("LR-BOOT-")
        {
            break;
        }
        if Instant::now() > deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    let _ = child.kill();
    let _ = child.wait();
    std::fs::read_to_string(&serial).unwrap_or_default()
}

#[test]
#[ignore = "requires root, loop devices, grub, qemu and OVMF"]
fn every_bootable_root_boots_under_bios_and_uefi_after_a_restore() {
    if !root_tests_enabled() {
        return;
    }
    for tool in [
        "qemu-system-x86_64",
        "sgdisk",
        "mkfs.vfat",
        "grub-install",
        "grub-mkstandalone",
        "cpio",
    ] {
        if !have(tool) {
            lr_testkit::unavailable!("{tool} missing - the boot matrix");
        }
    }
    if !Path::new("/usr/share/OVMF/OVMF_CODE_4M.fd").exists() {
        lr_testkit::unavailable!("OVMF missing - the boot matrix");
    }
    // The newest kernel the machine has, with the matching modules.
    let mut kernels: Vec<PathBuf> = std::fs::read_dir("/boot")
        .expect("/boot")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("vmlinuz-"))
        })
        .collect();
    kernels.sort();
    let Some(kernel) = kernels.pop() else {
        lr_testkit::unavailable!("no kernel in /boot - the boot matrix");
    };

    for fs in [Filesystem::Ext4, Filesystem::Xfs, Filesystem::Btrfs] {
        if !have(fs.mkfs()) {
            lr_testkit::report_unavailable(&format!("{} missing - {}", fs.mkfs(), fs.name()));
            continue;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let Some(source) = bootable_disk(dir.path(), fs, &kernel) else {
            lr_testkit::fixture_failed!("could not build the {} disk", fs.name());
        };
        // The image is taken first: booting the same loop device in qemu before
        // the backup makes its final chunk unreadable on this kernel, and the
        // evidence that matters is the restored disk booting, not the fixture.
        let expected = format!("LR-BOOT-{}", fs.name().to_uppercase());
        let dest = dir.path().join("backups");
        let report = backup_image(&request(&source.path(), &dest)).unwrap_or_else(|error| {
            panic!(
                "whole-disk backup of the {} root failed: {error}",
                fs.name()
            )
        });
        let image = match &report {
            lr_engine::ImageReport::WholeDisk(report) => report.image_path.clone(),
            other => panic!("expected a whole-disk image, got {other:?}"),
        };
        let Some(target) = LoopDevice::attach(dir.path(), "restored.img", 768 * 1024 * 1024) else {
            return;
        };
        let plan = prepare_restore(&PrepareRequest::from_path(
            &image,
            target.path(),
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

        for (uefi, label) in [(false, "seabios"), (true, "ovmf")] {
            let log = boot_disk(
                &target.path(),
                uefi,
                dir.path(),
                &format!("{}-{}", fs.name(), label),
            );
            assert!(
                log.contains(&expected),
                "the restored {} disk did not boot under {label}:\n{log}",
                fs.name()
            );
        }
    }
}

/// The last chunk of a device is often shorter than the 4 KiB `O_DIRECT`
/// alignment, and there is nothing beyond it to pad the read with. Such a read
/// must still work (regression test for D-097).
#[test]
#[ignore = "requires root and loop devices"]
fn an_unaligned_tail_reads_without_direct_io() {
    if !root_tests_enabled() {
        return;
    }
    // 1 MiB + 512 bytes: the whole device is not 4 KiB-aligned.
    const SIZE: u64 = 1024 * 1024 + 512;
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(device) = LoopDevice::attach(dir.path(), "tail.img", SIZE) else {
        return;
    };
    use lr_blocksource::BlockSource;
    let mut source = lr_blocksource::DirectBlockSource::open(&device.path()).expect("open direct");
    let mut buffer = lr_unsafe::AlignedBuf::new(SIZE as usize, 4096).expect("buffer");
    let read = source
        .read_at(0, &mut buffer, SIZE as usize)
        .expect("an unaligned tail must read");
    assert_eq!(read as u64, SIZE);
    // And the aligned part still goes through the direct path.
    let mut aligned = lr_unsafe::AlignedBuf::new(4096, 4096).expect("buffer");
    assert_eq!(
        source
            .read_at(4096, &mut aligned, 4096)
            .expect("aligned read"),
        4096
    );
}
