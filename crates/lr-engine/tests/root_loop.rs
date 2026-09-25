//! Acceptance tests that need loop devices, mounts and filesystem tools.
//!
//! Run with:
//!
//! ```text
//! LR_ROOT_TESTS=1 sudo -E cargo test -p lr-engine --test root_loop -- --ignored --nocapture --test-threads=1
//! ```
//!
//! These cover the spec §K S5 completeness proof (image used blocks only,
//! restore, `fsck -n`/`xfs_repair -n` clean, identical file hashes) and the
//! §K S6 acceptance criteria (byte-identical restore, `E_TARGET_CHANGED`,
//! refusal on mounted or swap targets, bad-sector handling).

use std::path::{Path, PathBuf};
use std::process::Command;

use lr_engine::backup::{BackupRequest, BadSectorPolicy, Compression};
use lr_engine::keys::Encryption;
use lr_engine::restore::{ApplyRequest, PrepareRequest, apply_restore, prepare_restore};
use lr_engine::{RestoreToken, backup_block_full};

const CHUNK_SIZE: u32 = 1024 * 1024;

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

/// A loop device backed by a freshly created image file.
struct LoopDevice {
    device: PathBuf,
    backing: PathBuf,
    _dir: tempfile::TempDir,
}

impl LoopDevice {
    fn attach(size_bytes: u64) -> Option<Self> {
        let dir = tempfile::tempdir_in("/tmp").expect("tempdir");
        let backing = dir.path().join("disk.img");
        let file = std::fs::File::create(&backing).expect("create");
        file.set_len(size_bytes).expect("size");
        drop(file);

        let free = Command::new("losetup").arg("-f").output().ok()?;
        if !free.status.success() {
            eprintln!("losetup -f failed");
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
            eprintln!("losetup attach failed for {}", device.display());
            let _ = run("losetup", &["-d", &device.display().to_string()]);
            return None;
        }
        Some(Self {
            device,
            backing,
            _dir: dir,
        })
    }

    fn path(&self) -> &Path {
        &self.device
    }

    /// Shrink the backing file so reads past the new end fail with EIO.
    fn truncate_backing(&self, size: u64) {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&self.backing)
            .expect("open backing");
        file.set_len(size).expect("truncate backing");
    }

    fn mount(&self, at: &Path) -> bool {
        run(
            "mount",
            &[
                &self.device.display().to_string(),
                &at.display().to_string(),
            ],
        )
    }

    fn unmount(&self, at: &Path) -> bool {
        run("umount", &[at.display().to_string().as_str()])
    }
}

impl Drop for LoopDevice {
    fn drop(&mut self) {
        let _ = run("losetup", &["-d", &self.device.display().to_string()]);
    }
}

/// Populate a mounted filesystem the way the spec's completeness AC describes.
fn populate(mountpoint: &Path, data_mib: usize) {
    let mnt = mountpoint.display().to_string();
    let script = format!(
        r#"
set -e
cd {mnt}
mkdir -p dir/sub dir/other
head -c {data_mib}M /dev/urandom > big.bin
head -c 4096 /dev/urandom > dir/small.bin
: > empty
truncate -s 8M sparse.bin
ln big.bin hardlink.bin
for i in $(seq 1 20); do head -c $((i * 1000)) /dev/urandom > dir/f$i; done
for i in $(seq 1 10); do rm -f dir/f$i; done
for i in $(seq 21 30); do head -c $((i * 777)) /dev/urandom > dir/other/new$i; done
command -v setfattr >/dev/null && setfattr -n user.lrtest -v "hello" dir/small.bin || true
sync
"#
    );
    assert!(run("bash", &["-c", &script]), "populate failed");
}

/// Content hash of every file below `root`, independent of path order.
fn tree_hashes(root: &Path) -> String {
    let script = format!(
        "cd {} && find . -type f -print0 | sort -z | xargs -0 sha256sum",
        root.display()
    );
    output("bash", &["-c", &script])
}

/// Runs `fsck`/`xfs_repair` in check-only mode and asserts a clean result.
///
/// The exit status is the authoritative signal: `e2fsck -n` returns 4 when it
/// finds errors it did not fix, `xfs_repair -n` returns non-zero for an
/// unclean filesystem. The output is also scanned so a failure shows why.
fn assert_filesystem_clean(tool: &str, device: &Path) {
    let device = device.display().to_string();
    let (args, status) = match tool {
        "fsck.ext4" => (
            vec!["-n", "-f", device.as_str()],
            Command::new(tool).args(["-n", "-f", &device]).output(),
        ),
        "xfs_repair" => (
            vec!["-n", device.as_str()],
            Command::new(tool).args(["-n", &device]).output(),
        ),
        other => panic!("unknown tool {other}"),
    };
    let _ = args;
    let result = status.expect("run the checker");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        result.status.success(),
        "{tool} exited with {} for an unrestorable image:\n{text}",
        result.status
    );
    let suspicious = [
        "would fix",
        "corrupt",
        "bad magic",
        "unexpected inconsistency",
    ];
    for marker in suspicious {
        assert!(
            !text.to_lowercase().contains(marker),
            "{tool} reported '{marker}':\n{text}"
        );
    }
}

fn request(source: &Path, dest: &Path, encryption: Encryption) -> BackupRequest {
    let mut request = BackupRequest::new(source, dest, "root-set", encryption).expect("request");
    request.chunk_size = CHUNK_SIZE;
    request.compression = Compression::None;
    request.on_bad_sector = BadSectorPolicy::Abort;
    request
}

/// Used byte regions of the source, chunk-aligned as the engine reads them.
fn used_regions(device: &Path, fs_type: &str, size: u64) -> Vec<(u64, u64)> {
    let map = lr_fsmap::provider_for(fs_type)
        .used_extents(device)
        .expect("used map");
    map.chunk_aligned(u64::from(CHUNK_SIZE), size)
}

fn files_equal(a: &Path, b: &Path, regions: &[(u64, u64)]) -> bool {
    use std::io::{Read, Seek, SeekFrom};
    let mut left = std::fs::File::open(a).expect("open left");
    let mut right = std::fs::File::open(b).expect("open right");
    for (start, end) in regions {
        let len = (end - start + 1) as usize;
        let mut l = vec![0u8; len];
        let mut r = vec![0u8; len];
        left.seek(SeekFrom::Start(*start)).expect("seek");
        right.seek(SeekFrom::Start(*start)).expect("seek");
        left.read_exact(&mut l).expect("read left");
        right.read_exact(&mut r).expect("read right");
        if l != r {
            return false;
        }
    }
    true
}

#[test]
#[ignore = "requires root, loop devices, mount and fsck"]
fn ext4_loop_completeness_and_size_bound() {
    if !root_tests_enabled() {
        return;
    }
    if !have("mkfs.ext4") || !have("fsck.ext4") {
        eprintln!("e2fsprogs missing; skipping");
        return;
    }

    const SIZE: u64 = 1024 * 1024 * 1024;
    let Some(source) = LoopDevice::attach(SIZE) else {
        return;
    };
    assert!(run(
        "mkfs.ext4",
        &[
            "-F",
            "-q",
            "-L",
            "ROOTFS",
            &source.path().display().to_string()
        ]
    ));

    let mountpoint = tempfile::tempdir_in("/tmp").expect("mountpoint");
    assert!(source.mount(mountpoint.path()), "mount failed");
    populate(mountpoint.path(), 50);
    let source_hashes = tree_hashes(mountpoint.path());
    assert!(source.unmount(mountpoint.path()), "unmount failed");

    let outcome = tempfile::tempdir_in("/tmp").expect("outcome");
    let backup = backup_block_full(&request(
        source.path(),
        outcome.path(),
        Encryption::NoEncrypt,
    ))
    .expect("backup");
    assert_eq!(backup.fs_type, "ext4");
    assert!(backup.map_complete, "ext4 must have a real used-block map");
    assert!(
        backup.image_bytes < 100 * 1024 * 1024,
        "a 1 GiB filesystem with 50 MiB of data produced {} bytes; the used-block map is not working",
        backup.image_bytes
    );
    assert!(backup.used_bytes < SIZE / 2, "only used blocks are imaged");
    eprintln!(
        "ext4 acceptance: image {} bytes, used {}, imaged {}, chunks {} total ({} stored, {} zero), fsck clean, hashes match",
        backup.image_bytes,
        backup.used_bytes,
        backup.imaged_bytes,
        backup.total_chunks,
        backup.stored_chunks,
        backup.zero_chunks
    );

    // Restore onto a second, equal-sized loop device.
    let Some(target) = LoopDevice::attach(SIZE) else {
        return;
    };
    let plan = prepare_restore(&PrepareRequest::from_path(
        &backup.image_path,
        target.path(),
        Encryption::NoEncrypt,
    ))
    .expect("prepare");
    let report = apply_restore(&ApplyRequest {
        token: plan.token,
        confirm: true,
        accept_inconsistent: false,
        encryption: Encryption::NoEncrypt,
        context: lr_engine::progress::EngineContext::silent(),
    })
    .expect("apply")
    .block()
    .expect("a block restore");
    assert_eq!(
        report.bytes_written, backup.imaged_bytes,
        "every imaged chunk is written back (stored plus zero chunks)"
    );
    assert!(
        backup.imaged_bytes >= backup.used_bytes,
        "chunk alignment can only add bytes"
    );

    // Byte-identical on every used region.
    let regions = used_regions(source.path(), "ext4", SIZE);
    assert!(
        files_equal(source.path(), target.path(), &regions),
        "restored used regions differ from the source"
    );

    // Mountable and clean, with identical file hashes.
    assert_filesystem_clean("fsck.ext4", target.path());
    let target_mount = tempfile::tempdir_in("/tmp").expect("mountpoint");
    assert!(
        target.mount(target_mount.path()),
        "mounting the restored device failed"
    );
    let restored_hashes = tree_hashes(target_mount.path());
    assert!(target.unmount(target_mount.path()), "unmount failed");
    assert_eq!(
        source_hashes, restored_hashes,
        "file hashes differ after restore"
    );
}

#[test]
#[ignore = "requires root, loop devices, mount and xfs_repair"]
fn xfs_loop_completeness() {
    if !root_tests_enabled() {
        return;
    }
    if !have("mkfs.xfs") || !have("xfs_repair") {
        eprintln!("xfsprogs missing; skipping");
        return;
    }

    const SIZE: u64 = 512 * 1024 * 1024;
    let Some(source) = LoopDevice::attach(SIZE) else {
        return;
    };
    assert!(run(
        "mkfs.xfs",
        &[
            "-f",
            "-q",
            "-L",
            "XFSROOT",
            &source.path().display().to_string()
        ]
    ));

    let mountpoint = tempfile::tempdir_in("/tmp").expect("mountpoint");
    assert!(source.mount(mountpoint.path()), "mount failed");
    populate(mountpoint.path(), 8);
    let source_hashes = tree_hashes(mountpoint.path());
    assert!(source.unmount(mountpoint.path()), "unmount failed");

    let outcome = tempfile::tempdir_in("/tmp").expect("outcome");
    let backup = backup_block_full(&request(
        source.path(),
        outcome.path(),
        Encryption::NoEncrypt,
    ))
    .expect("backup");
    assert_eq!(backup.fs_type, "xfs");

    let Some(target) = LoopDevice::attach(SIZE) else {
        return;
    };
    let plan = prepare_restore(&PrepareRequest::from_path(
        &backup.image_path,
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

    assert_filesystem_clean("xfs_repair", target.path());
    let target_mount = tempfile::tempdir_in("/tmp").expect("mountpoint");
    assert!(
        target.mount(target_mount.path()),
        "mounting the restored device failed"
    );
    let restored_hashes = tree_hashes(target_mount.path());
    assert!(target.unmount(target_mount.path()), "unmount failed");
    assert_eq!(
        source_hashes, restored_hashes,
        "file hashes differ after restore"
    );
}

#[test]
#[ignore = "requires root and loop devices"]
fn restore_refuses_a_changed_target_and_a_mounted_target() {
    if !root_tests_enabled() {
        return;
    }
    if !have("mkfs.ext4") {
        return;
    }
    const SIZE: u64 = 64 * 1024 * 1024;
    let Some(source) = LoopDevice::attach(SIZE) else {
        return;
    };
    assert!(run(
        "mkfs.ext4",
        &["-F", "-q", &source.path().display().to_string()]
    ));
    let outcome = tempfile::tempdir_in("/tmp").expect("outcome");
    let backup = backup_block_full(&request(
        source.path(),
        outcome.path(),
        Encryption::NoEncrypt,
    ))
    .expect("backup");

    let Some(target) = LoopDevice::attach(SIZE) else {
        return;
    };
    let plan = prepare_restore(&PrepareRequest::from_path(
        &backup.image_path,
        target.path(),
        Encryption::NoEncrypt,
    ))
    .expect("prepare");

    // Repartitioning the target between prepare and apply must be detected.
    assert!(run(
        "sgdisk",
        &["--clear", &target.path().display().to_string()]
    ));
    let error = apply_restore(&ApplyRequest {
        token: plan.token,
        confirm: true,
        accept_inconsistent: false,
        encryption: Encryption::NoEncrypt,
        context: lr_engine::progress::EngineContext::silent(),
    })
    .expect_err("a changed target must be rejected");
    assert!(
        matches!(error, lr_core::Error::TargetChanged),
        "expected TargetChanged, got {error}"
    );

    // A mounted target must be refused before anything is written.
    let mountpoint = tempfile::tempdir_in("/tmp").expect("mountpoint");
    assert!(run(
        "mkfs.ext4",
        &["-F", "-q", &target.path().display().to_string()]
    ));
    assert!(target.mount(mountpoint.path()), "mount failed");
    let error = prepare_restore(&PrepareRequest::from_path(
        &backup.image_path,
        target.path(),
        Encryption::NoEncrypt,
    ))
    .expect_err("a mounted target must be refused");
    assert!(
        matches!(error, lr_core::Error::TargetBusy { .. }),
        "expected TargetBusy, got {error}"
    );
    assert!(target.unmount(mountpoint.path()), "unmount failed");
}

#[test]
#[ignore = "requires root and loop devices"]
fn restore_refuses_a_swap_target() {
    if !root_tests_enabled() {
        return;
    }
    const SIZE: u64 = 64 * 1024 * 1024;
    let Some(source) = LoopDevice::attach(SIZE) else {
        return;
    };
    assert!(run(
        "mkfs.ext4",
        &["-F", "-q", &source.path().display().to_string()]
    ));
    let outcome = tempfile::tempdir_in("/tmp").expect("outcome");
    let backup = backup_block_full(&request(
        source.path(),
        outcome.path(),
        Encryption::NoEncrypt,
    ))
    .expect("backup");

    let Some(target) = LoopDevice::attach(SIZE) else {
        return;
    };
    assert!(run("mkswap", &[&target.path().display().to_string()]));
    if !run("swapon", &[&target.path().display().to_string()]) {
        eprintln!("swapon unavailable in this environment; skipping the swap check");
        return;
    }
    let result = prepare_restore(&PrepareRequest::from_path(
        &backup.image_path,
        target.path(),
        Encryption::NoEncrypt,
    ));
    let _ = run("swapoff", &[&target.path().display().to_string()]);
    let error = result.expect_err("a swap target must be refused");
    assert!(
        matches!(error, lr_core::Error::TargetBusy { .. }),
        "expected TargetBusy, got {error}"
    );
}

#[test]
#[ignore = "requires root and loop devices"]
fn bad_sectors_abort_or_are_recorded() {
    if !root_tests_enabled() {
        return;
    }
    if !have("mkfs.ext4") || !have("dd") {
        return;
    }
    const SIZE: u64 = 64 * 1024 * 1024;
    let Some(source) = LoopDevice::attach(SIZE) else {
        return;
    };
    assert!(run(
        "mkfs.ext4",
        &["-F", "-q", &source.path().display().to_string()]
    ));
    let mountpoint = tempfile::tempdir_in("/tmp").expect("mountpoint");
    assert!(source.mount(mountpoint.path()), "mount failed");
    populate(mountpoint.path(), 8);
    assert!(source.unmount(mountpoint.path()), "unmount failed");

    // Shrink the backing file: reads past it fail with EIO, which is exactly a
    // device-level read error (this kernel has no dm-error target).
    source.truncate_backing(4 * 1024 * 1024);

    let outcome = tempfile::tempdir_in("/tmp").expect("outcome");
    let mut aborting = request(source.path(), outcome.path(), Encryption::NoEncrypt);
    aborting.on_bad_sector = BadSectorPolicy::Abort;
    let error = backup_block_full(&aborting).expect_err("abort must fail the job");
    assert!(
        matches!(error, lr_core::Error::BadSector { .. }),
        "expected BadSector, got {error}"
    );

    let mut recording = request(source.path(), outcome.path(), Encryption::NoEncrypt);
    recording.on_bad_sector = BadSectorPolicy::Record;
    let report = backup_block_full(&recording).expect("record must complete the job");
    assert!(report.bad_chunks > 0, "unreadable chunks must be recorded");
    assert!(
        report.stored_chunks + report.zero_chunks + report.bad_chunks <= report.total_chunks,
        "recorded states must add up"
    );
}

#[test]
#[ignore = "requires root and loop devices"]
fn a_tampered_token_is_rejected_on_a_real_device() {
    if !root_tests_enabled() {
        return;
    }
    if !have("mkfs.ext4") {
        return;
    }
    const SIZE: u64 = 64 * 1024 * 1024;
    let Some(source) = LoopDevice::attach(SIZE) else {
        return;
    };
    assert!(run(
        "mkfs.ext4",
        &["-F", "-q", &source.path().display().to_string()]
    ));
    let outcome = tempfile::tempdir_in("/tmp").expect("outcome");
    let backup = backup_block_full(&request(
        source.path(),
        outcome.path(),
        Encryption::NoEncrypt,
    ))
    .expect("backup");
    let Some(target) = LoopDevice::attach(SIZE) else {
        return;
    };
    let plan = prepare_restore(&PrepareRequest::from_path(
        &backup.image_path,
        target.path(),
        Encryption::NoEncrypt,
    ))
    .expect("prepare");

    // Re-point the token at a different target: the MAC covers the path.
    let mut token = RestoreToken::decode(&plan.token).expect("decode");
    token.target_path = PathBuf::from("/dev/definitely-not-the-target");
    let error = apply_restore(&ApplyRequest {
        token: token.encode(),
        confirm: true,
        accept_inconsistent: false,
        encryption: Encryption::NoEncrypt,
        context: lr_engine::progress::EngineContext::silent(),
    })
    .expect_err("a tampered token must be rejected");
    assert!(matches!(error, lr_core::Error::Corrupt { .. }), "{error}");
}
