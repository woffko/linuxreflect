//! Tracked-freeze block images (spec v2.2 §E.7, Slice 18 phase 2).
//!
//! Root tests on loop disks the tests create themselves: an ext4 filesystem
//! on a GPT partition, mounted and written to while it is copied live.
//!
//! ```text
//! LR_ROOT_TESTS=1 sudo -E cargo test -p lr-engine --test root_tracked -- --ignored --nocapture
//! ```

use std::io::Write as _;
use std::os::unix::fs::FileExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use lr_engine::backup::{BackupRequest, Compression};
use lr_engine::keys::Encryption;
use lr_engine::restore::{ApplyRequest, PrepareRequest, apply_restore, prepare_restore};
use lr_engine::{ImageReport, backup_image};

const CHUNK_SIZE: u32 = 1024 * 1024;
const DISK_BYTES: u64 = 512 << 20;
const BLOCKS: u64 = 4096; // 16 MiB of 4 KiB blocks in random.bin

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

fn prerequisites() -> bool {
    for tool in [
        "sfdisk",
        "losetup",
        "blockdev",
        "mkfs.ext4",
        "e2fsck",
        "dumpe2fs",
        "mount",
        "umount",
        "blkdiscard",
        "systemd-run",
    ] {
        if !have(tool) {
            lr_testkit::unavailable!(return false; "{tool} missing");
        }
    }
    let Some(tracefs) = lr_snapshot::tracking::tracefs_root() else {
        lr_testkit::unavailable!(return false; "tracefs is not mounted");
    };
    if !tracefs
        .join("events")
        .join(lr_snapshot::tracking::TRACEPOINT)
        .is_dir()
    {
        lr_testkit::unavailable!(return false; "the block_bio_queue tracepoint is unavailable");
    }
    true
}

/// A GPT loop disk whose second partition holds a mounted ext4.
struct Source {
    dir: tempfile::TempDir,
    device: String,
}

impl Source {
    fn create() -> Option<Self> {
        let dir = tempfile::tempdir().expect("dir");
        let image = dir.path().join("disk.img");
        std::fs::File::create(&image)
            .and_then(|f| f.set_len(DISK_BYTES))
            .expect("image");
        let mut sfdisk = Command::new("sfdisk")
            .arg("--quiet")
            .arg(&image)
            .stdin(Stdio::piped())
            .spawn()
            .expect("sfdisk");
        sfdisk
            .stdin
            .take()
            .expect("stdin")
            .write_all(b"label: gpt\nstart=2048, size=16MiB\n,\n")
            .expect("layout");
        if !sfdisk.wait().expect("sfdisk").success() {
            lr_testkit::fixture_failed!("sfdisk failed");
        }
        let output = Command::new("losetup")
            .args(["--find", "--show", "--partscan"])
            .arg(&image)
            .output()
            .expect("losetup");
        if !output.status.success() {
            lr_testkit::fixture_failed!("losetup failed");
        }
        let device = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        let source = Self { dir, device };
        let _ = run("blockdev", &["--rereadpt", &source.device]);
        for _ in 0..100 {
            if Path::new(&source.partition()).exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        if !run("mkfs.ext4", &["-q", "-F", &source.partition()]) {
            lr_testkit::fixture_failed!("mkfs.ext4 failed");
        }
        std::fs::create_dir(source.mountpoint()).expect("mountpoint");
        if !run(
            "mount",
            &[
                &source.partition(),
                &source.mountpoint().display().to_string(),
            ],
        ) {
            lr_testkit::fixture_failed!("mount failed");
        }
        Some(source)
    }

    fn partition(&self) -> String {
        format!("{}p2", self.device)
    }

    fn mountpoint(&self) -> PathBuf {
        self.dir.path().join("mnt")
    }

    fn partition_bytes(&self) -> u64 {
        let name = format!(
            "{}p2",
            Path::new(&self.device)
                .file_name()
                .expect("name")
                .to_string_lossy()
        );
        let sectors: u64 =
            std::fs::read_to_string(Path::new("/sys/class/block").join(name).join("size"))
                .expect("size")
                .trim()
                .parse()
                .expect("number");
        sectors * 512
    }
}

impl Drop for Source {
    fn drop(&mut self) {
        let _ = run("umount", &[&self.mountpoint().display().to_string()]);
        let _ = run("losetup", &["--detach", &self.device]);
    }
}

/// A writer that keeps the source busy: an fsync'd hash-chained log, random
/// 4 KiB overwrites whose blocks describe themselves, and file churn.
struct Writer {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<Vec<(u64, Instant, Instant)>>>,
}

fn link(previous: u64, seq: u64) -> u64 {
    // FNV-1a over the previous link and the sequence number.
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in previous.to_le_bytes().into_iter().chain(seq.to_le_bytes()) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn block_bytes(index: u64, version: u64) -> Vec<u8> {
    let mut block = vec![0u8; 4096];
    block[..8].copy_from_slice(&index.to_le_bytes());
    block[8..16].copy_from_slice(&version.to_le_bytes());
    let fill = link(index, version);
    for (at, word) in block[16..].chunks_exact_mut(8).enumerate() {
        word.copy_from_slice(&(fill ^ at as u64).to_le_bytes());
    }
    block
}

impl Writer {
    fn start(dir: &Path) -> Self {
        std::fs::create_dir_all(dir).expect("work dir");
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("chain.log"))
            .expect("log");
        let data = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(dir.join("random.bin"))
            .expect("data");
        data.set_len(BLOCKS * 4096).expect("size data");
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let dir = dir.to_path_buf();
        let handle = std::thread::spawn(move || {
            let mut log = log;
            let mut records = Vec::new();
            let mut previous = 0u64;
            let mut seq = 0u64;
            let mut state = 0x9e37_79b9_7f4a_7c15u64;
            while !flag.load(Ordering::Relaxed) {
                let started = Instant::now();
                previous = link(previous, seq);
                writeln!(log, "{seq} {previous:016x}").expect("log");
                log.sync_all().expect("fsync log");
                records.push((seq, started, Instant::now()));
                for _ in 0..4 {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    let index = state % BLOCKS;
                    data.write_all_at(&block_bytes(index, seq), index * 4096)
                        .expect("pwrite");
                }
                if seq.is_multiple_of(25) {
                    data.sync_data().expect("fdatasync");
                    let churn = dir.join(format!("churn-{}.tmp", seq % 7));
                    std::fs::write(&churn, vec![seq as u8; 48 * 1024]).expect("churn");
                    if seq.is_multiple_of(3) {
                        let _ = std::fs::remove_file(&churn);
                    }
                }
                seq += 1;
                std::thread::sleep(Duration::from_millis(2));
            }
            records
        });
        Self {
            stop,
            handle: Some(handle),
        }
    }

    fn stop(mut self) -> Vec<(u64, Instant, Instant)> {
        self.stop.store(true, Ordering::Relaxed);
        self.handle
            .take()
            .expect("writer thread")
            .join()
            .expect("writer thread")
    }
}

impl Drop for Writer {
    // A failing test must not unmount the source under a running writer.
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn request(source: &str, dest: &Path) -> BackupRequest {
    let mut request =
        BackupRequest::new(source, dest, "tracked-set", Encryption::NoEncrypt).expect("request");
    request.chunk_size = CHUNK_SIZE;
    request.compression = Compression::None;
    request.snapshot_provider = Some("tracked-freeze".to_owned());
    request
}

#[test]
#[ignore = "requires root, loop devices, tracefs and fsfreeze"]
fn a_busy_ext4_partition_is_copied_live_and_restores_clean() {
    if !root_tests_enabled() || !prerequisites() {
        return;
    }
    let Some(source) = Source::create() else {
        return;
    };
    let work = tempfile::tempdir().expect("work");
    let dest = work.path().join("backups");

    let writer = Writer::start(&source.mountpoint().join("work"));
    std::thread::sleep(Duration::from_millis(500));
    let backup_started = Instant::now();
    let report = backup_image(&request(&source.partition(), &dest)).expect("tracked backup");
    let backup_ended = Instant::now();
    std::thread::sleep(Duration::from_millis(300));
    let records = writer.stop();

    let ImageReport::Block(report) = &report else {
        panic!("expected a block image");
    };
    assert_eq!(report.consistency, lr_core::Consistency::Frozen);
    let tracked = report.tracked.expect("a tracked summary");
    println!("{tracked:?}");
    assert!(tracked.passes >= 1);
    assert!(
        tracked.final_freeze_ms < 3000,
        "the final freeze took {} ms",
        tracked.final_freeze_ms
    );

    // Restore into a file of the partition's size and check it offline.
    let target = work.path().join("restored.img");
    std::fs::File::create(&target)
        .and_then(|f| f.set_len(source.partition_bytes()))
        .expect("target");
    let plan = prepare_restore(&PrepareRequest::from_path(
        &report.image_path,
        &target,
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

    let fsck = Command::new("e2fsck")
        .arg("-fn")
        .arg(&target)
        .output()
        .expect("e2fsck");
    assert!(
        fsck.status.success(),
        "e2fsck:\n{}{}",
        String::from_utf8_lossy(&fsck.stdout),
        String::from_utf8_lossy(&fsck.stderr)
    );
    // e2fsck -n alone does not see a journal left to replay (phase 0).
    let header = Command::new("dumpe2fs")
        .arg("-h")
        .arg(&target)
        .output()
        .expect("dumpe2fs");
    let header = String::from_utf8_lossy(&header.stdout);
    assert!(
        !header.contains("needs_recovery"),
        "the copy still needs journal recovery:\n{header}"
    );

    let check = work.path().join("check");
    std::fs::create_dir(&check).expect("check dir");
    assert!(run(
        "mount",
        &[
            "-o",
            "ro,loop",
            &target.display().to_string(),
            &check.display().to_string()
        ]
    ));
    let log = std::fs::read_to_string(check.join("work/chain.log")).expect("log");
    let blocks = std::fs::read(check.join("work/random.bin")).expect("data");
    let _ = run("umount", &[&check.display().to_string()]);

    // The log is a whole, valid chain…
    assert!(log.ends_with('\n') || log.is_empty(), "torn last record");
    let mut previous = 0u64;
    let mut count = 0u64;
    for line in log.lines() {
        let (seq, hash) = line.split_once(' ').expect("record");
        assert_eq!(
            seq.parse::<u64>().expect("seq"),
            count,
            "records out of order"
        );
        previous = link(previous, count);
        assert_eq!(hash, format!("{previous:016x}"), "broken chain at {count}");
        count += 1;
    }
    // …that ends inside the backup: everything synced before it started is
    // there, nothing begun after it ended is.
    let synced_before = records
        .iter()
        .filter(|(_, _, synced)| *synced < backup_started)
        .count() as u64;
    let begun_before_end = records
        .iter()
        .filter(|(_, started, _)| *started < backup_ended)
        .count() as u64;
    assert!(
        (synced_before..=begun_before_end).contains(&count),
        "{count} records; expected between {synced_before} and {begun_before_end}"
    );
    // Every 4 KiB block is whole: either never written or one version.
    for (index, block) in blocks.chunks_exact(4096).enumerate() {
        if block.iter().all(|byte| *byte == 0) {
            continue;
        }
        let stored = u64::from_le_bytes(block[..8].try_into().expect("8 bytes"));
        let version = u64::from_le_bytes(block[8..16].try_into().expect("8 bytes"));
        assert_eq!(stored, index as u64, "block {index} holds block {stored}");
        assert_eq!(
            block,
            block_bytes(stored, version).as_slice(),
            "block {index} is torn"
        );
    }
}

#[test]
#[ignore = "requires root, loop devices and tracefs"]
fn a_destination_on_the_source_filesystem_is_refused_before_tracking() {
    if !root_tests_enabled() || !prerequisites() {
        return;
    }
    let Some(source) = Source::create() else {
        return;
    };
    let error = backup_image(&request(
        &source.partition(),
        &source.mountpoint().join("backups"),
    ))
    .expect_err("a destination on the source must be refused");
    assert!(
        error.to_string().contains("frozen"),
        "unexpected refusal: {error}"
    );
    let tracefs = lr_snapshot::tracking::tracefs_root().expect("tracefs");
    let leftovers = std::fs::read_dir(tracefs.join("instances"))
        .expect("instances")
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("lr-tf-"))
        .count();
    assert_eq!(leftovers, 0, "a trace instance was left behind");
}

#[test]
#[ignore = "requires root, loop devices and tracefs"]
fn an_incremental_is_refused_in_this_release() {
    if !root_tests_enabled() || !prerequisites() {
        return;
    }
    let Some(source) = Source::create() else {
        return;
    };
    let work = tempfile::tempdir().expect("work");
    let dest = work.path().join("backups");
    backup_image(&request(&source.partition(), &dest)).expect("full");
    let mut incremental = request(&source.partition(), &dest);
    incremental.member_type = lr_engine::backup::MemberType::Incremental;
    incremental.parent = Some("latest".to_owned());
    let error = backup_image(&incremental).expect_err("an incremental must be refused");
    assert!(error.to_string().contains("full images"), "{error}");
}

fn images_under(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            found.extend(images_under(&path));
        } else if path.extension().is_some_and(|ext| ext == "lrimg") {
            found.push(path);
        }
    }
    found
}

fn trace_leftovers() -> usize {
    let tracefs = lr_snapshot::tracking::tracefs_root().expect("tracefs");
    std::fs::read_dir(tracefs.join("instances"))
        .expect("instances")
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("lr-tf-"))
        .count()
}

/// Whether a write to `mountpoint` completes within `limit`. The probe is a
/// separate process that is never waited on past the deadline: a write to a
/// frozen filesystem sleeps uninterruptibly, so `timeout` cannot end it (a
/// probe left behind finishes once the filesystem thaws).
#[allow(clippy::zombie_processes)] // A frozen probe is left to finish after the thaw.
fn writable_within(mountpoint: &Path, limit: Duration) -> bool {
    let mut probe = Command::new("touch")
        .arg(mountpoint.join("writable"))
        .spawn()
        .expect("spawn touch");
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if let Ok(Some(status)) = probe.try_wait() {
            return status.success();
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

#[test]
#[ignore = "requires root, loop devices, tracefs and fsfreeze"]
fn a_source_that_keeps_changing_fails_without_publishing() {
    if !root_tests_enabled() || !prerequisites() {
        return;
    }
    let Some(source) = Source::create() else {
        return;
    };
    let work = tempfile::tempdir().expect("work");
    let dest = work.path().join("backups");
    let writer = Writer::start(&source.mountpoint().join("work"));
    std::thread::sleep(Duration::from_millis(300));
    // One pass, and at most one chunk under the freeze: the writer dirties more.
    let mut tight = request(&source.partition(), &dest);
    tight.tracked_tuning = lr_core::TrackedTuning {
        final_max_bytes: Some(u64::from(CHUNK_SIZE)),
        max_passes: Some(1),
        ..lr_core::TrackedTuning::default()
    };
    let outcome = backup_image(&tight);
    drop(writer.stop());
    let error = outcome.expect_err("a source that keeps changing must fail");
    assert!(
        matches!(error, lr_core::Error::NoConvergence { .. }),
        "expected E_NO_CONVERGENCE, got {error}"
    );
    assert!(images_under(&dest).is_empty(), "an image was published");
    assert_eq!(trace_leftovers(), 0, "a trace instance was left behind");
    assert!(
        writable_within(&source.mountpoint(), Duration::from_secs(5)),
        "the source stayed frozen"
    );
}

/// An executable hook script with `mode`.
fn hook(dir: &Path, name: &str, mode: u32, body: &str) {
    use std::os::unix::fs::PermissionsExt as _;
    let path = dir.join(name);
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("hook");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("mode");
}

/// A hooks directory with empty, root-only stage directories.
fn hooks_dir(work: &Path, name: &str) -> (PathBuf, PathBuf, PathBuf) {
    let root = work.join(name);
    let pre = root.join("pre-freeze.d");
    let post = root.join("post-thaw.d");
    for dir in [&root, &pre, &post] {
        std::fs::create_dir_all(dir).expect("hooks dir");
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).expect("mode");
    }
    (root, pre, post)
}

/// Spec §E.7 hooks. Pre-freeze hooks run in name order before the final
/// freeze, so what they write is in the image; post-thaw hooks run after the
/// thaw, so what they write reaches the source but not the image. Hooks see
/// a clean environment, `run-parts` leftovers and files without the execute
/// bit do not run, and a failed post-thaw hook is a warning. A failed
/// pre-freeze hook stops the job and publishes nothing, while the post-thaw
/// hooks still run; an unsafe hook refuses the job before tracing starts.
#[test]
#[ignore = "requires root, loop devices, tracefs and fsfreeze"]
fn hooks_run_around_the_final_freeze() {
    if !root_tests_enabled() || !prerequisites() {
        return;
    }
    let Some(source) = Source::create() else {
        return;
    };
    let work = tempfile::tempdir().expect("work");
    let log = work.path().join("hooks.log");
    let env_dump = work.path().join("hook-env.txt");
    let (root, pre, post) = hooks_dir(work.path(), "hooks");
    let (log_s, env_s) = (log.display(), env_dump.display());
    hook(&pre, "20-second", 0o755, &format!("echo pre-20 >> {log_s}"));
    hook(
        &pre,
        "10-first",
        0o755,
        &format!(
            "echo \"pre-10 $LINUXREFLECT_STAGE\" >> {log_s}; env > {env_s}\n\
             for fs in $LINUXREFLECT_FILESYSTEMS; do echo flushed > \"$fs/before-freeze\"; done"
        ),
    );
    hook(&pre, "README", 0o644, &format!("echo readme >> {log_s}"));
    hook(
        &pre,
        "10-first.dpkg-old",
        0o755,
        &format!("echo old >> {log_s}"),
    );
    hook(
        &post,
        "30-resume",
        0o755,
        &format!(
            "echo \"post $LINUXREFLECT_STAGE\" >> {log_s}\n\
             for fs in $LINUXREFLECT_FILESYSTEMS; do echo resumed > \"$fs/after-thaw\"; done"
        ),
    );
    hook(
        &post,
        "40-complains",
        0o755,
        "echo 'resume failed' >&2; exit 1",
    );

    let dest = work.path().join("backups");
    let mut hooked = request(&source.partition(), &dest);
    hooked.hooks_dir = Some(root);
    let report = backup_image(&hooked).expect("a backup with hooks");
    let ImageReport::Block(report) = &report else {
        panic!("expected a block image");
    };
    assert_eq!(report.consistency, lr_core::Consistency::Frozen);
    let ran = std::fs::read_to_string(&log).expect("hook log");
    assert_eq!(
        ran.lines().collect::<Vec<_>>(),
        ["pre-10 pre-freeze", "pre-20", "post post-thaw"],
        "hooks ran out of order or ran what they should not"
    );
    let env = std::fs::read_to_string(&env_dump).expect("hook environment");
    assert!(
        env.contains(&format!(
            "LINUXREFLECT_FILESYSTEMS={}",
            source.mountpoint().display()
        )),
        "{env}"
    );
    assert!(
        !env.contains("LR_ROOT_TESTS"),
        "the job's environment leaked: {env}"
    );
    let complaints: Vec<&String> = report
        .warnings
        .iter()
        .filter(|warning| warning.contains("post-thaw hook"))
        .collect();
    assert_eq!(complaints.len(), 1, "{:?}", report.warnings);
    assert!(
        complaints[0].contains("40-complains") && complaints[0].contains("resume failed"),
        "{}",
        complaints[0]
    );
    assert!(
        source.mountpoint().join("after-thaw").exists(),
        "the post-thaw hook could not write to the thawed source"
    );

    // The image holds the pre-freeze write and not the post-thaw one.
    let target = work.path().join("restored.img");
    std::fs::File::create(&target)
        .and_then(|f| f.set_len(source.partition_bytes()))
        .expect("target");
    let plan = prepare_restore(&PrepareRequest::from_path(
        &report.image_path,
        &target,
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
    let check = work.path().join("check");
    std::fs::create_dir(&check).expect("check dir");
    assert!(run(
        "mount",
        &[
            "-o",
            "ro,loop",
            &target.display().to_string(),
            &check.display().to_string()
        ]
    ));
    let before = std::fs::read_to_string(check.join("before-freeze"));
    let after = check.join("after-thaw").exists();
    let _ = run("umount", &[&check.display().to_string()]);
    assert_eq!(
        before.ok().as_deref(),
        Some("flushed\n"),
        "the pre-freeze write is missing"
    );
    assert!(!after, "a write made after the thaw is in the image");

    // A failing pre-freeze hook stops the job; the post-thaw hooks still run.
    let failed_log = work.path().join("failed.log");
    let (root, pre, post) = hooks_dir(work.path(), "failing-hooks");
    hook(
        &pre,
        "10-pause",
        0o755,
        "echo 'service refused to pause' >&2; exit 4",
    );
    hook(
        &post,
        "10-resume",
        0o755,
        &format!("echo resumed >> {}", failed_log.display()),
    );
    let failed_dest = work.path().join("failed-backups");
    let mut failing = request(&source.partition(), &failed_dest);
    failing.hooks_dir = Some(root);
    let error = backup_image(&failing).expect_err("a failed pre-freeze hook must stop the job");
    assert!(
        matches!(error, lr_core::Error::HookFailed { .. }),
        "expected E_HOOK_FAILED, got {error}"
    );
    let message = error.to_string();
    assert!(
        message.contains("10-pause")
            && message.contains("exit status: 4")
            && message.contains("service refused to pause"),
        "{message}"
    );
    assert_eq!(
        std::fs::read_to_string(&failed_log).ok().as_deref(),
        Some("resumed\n"),
        "the post-thaw hooks did not run after the failure"
    );
    assert!(
        images_under(&failed_dest).is_empty(),
        "an image was published"
    );
    assert_eq!(trace_leftovers(), 0, "a trace instance was left behind");
    assert!(
        writable_within(&source.mountpoint(), Duration::from_secs(5)),
        "the source stayed frozen"
    );

    // A hook anyone may change is refused before anything is traced.
    let (root, pre, _post) = hooks_dir(work.path(), "open-hooks");
    hook(&pre, "10-open", 0o777, "true");
    let open_dest = work.path().join("open-backups");
    let mut open = request(&source.partition(), &open_dest);
    open.hooks_dir = Some(root);
    let error = backup_image(&open).expect_err("a world-writable hook must be refused");
    assert!(
        error
            .to_string()
            .contains("writable by its group or by others"),
        "{error}"
    );
    assert!(
        images_under(&open_dest).is_empty(),
        "an image was published"
    );
    assert_eq!(trace_leftovers(), 0, "a trace instance was left behind");
}

/// Child process for [`a_sigkill_during_the_final_freeze_is_thawed_by_the_deadman`].
#[test]
#[ignore = "internal helper for the tracked-freeze deadman test"]
fn tracked_freeze_child_helper() {
    let Ok(device) = std::env::var("LR_TRACKED_DEVICE") else {
        return;
    };
    let destination = PathBuf::from(std::env::var("LR_TRACKED_DEST").expect("destination"));
    let ready = std::env::var("LR_TRACKED_READY").expect("ready file");
    let layout = lr_core::discover_source(Path::new(&device)).expect("discover");
    let options = lr_core::SnapshotOpts {
        provider: Some("tracked-freeze".to_owned()),
        deadman_grace_secs: Some(2),
        tracked: lr_core::TrackedTuning {
            freeze_max_secs: Some(1),
            ..lr_core::TrackedTuning::default()
        },
        destination: Some(destination),
        ..lr_core::SnapshotOpts::default()
    };
    use lr_snapshot::BlockSnapshotProvider as _;
    let mut snapshot = lr_snapshot::tracked_freeze::provider()
        .create(&layout, &options)
        .expect("child tracked copy");
    let tracked = snapshot.tracked_mut().expect("tracked");
    tracked.bind(u64::from(CHUNK_SIZE)).expect("bind");
    // Freeze for the final read and never come back: only the deadman thaws.
    let _ = tracked.final_read(|_| -> lr_core::Result<()> {
        std::fs::write(&ready, b"frozen").expect("signal readiness");
        std::thread::sleep(Duration::from_secs(600));
        Ok(())
    });
}

#[test]
#[ignore = "requires root, loop devices, tracefs and fsfreeze"]
fn a_sigkill_during_the_final_freeze_is_thawed_by_the_deadman() {
    if !root_tests_enabled() || !prerequisites() {
        return;
    }
    let Some(source) = Source::create() else {
        return;
    };
    let work = tempfile::tempdir().expect("work");
    let ready = work.path().join("tracked-child.ready");
    let mut child = Command::new(std::env::current_exe().expect("current exe"))
        .args([
            "--exact",
            "tracked_freeze_child_helper",
            "--ignored",
            "--nocapture",
        ])
        .env("LR_TRACKED_DEVICE", source.partition())
        .env("LR_TRACKED_DEST", work.path())
        .env("LR_TRACKED_READY", &ready)
        .spawn()
        .expect("spawn the child");
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline && !ready.exists() {
        std::thread::sleep(Duration::from_millis(100));
    }
    if !ready.exists() {
        let _ = child.kill();
        let _ = child.wait();
        lr_testkit::fixture_failed!("the child never froze the source");
    }
    // Frozen now: a write must block.
    assert!(
        !writable_within(&source.mountpoint(), Duration::from_millis(300)),
        "the source was not frozen"
    );
    // kill -9 with no chance to thaw: only the external deadman can help (the
    // kernel keeps a filesystem frozen after the process that froze it dies).
    let killed = Instant::now();
    child.kill().expect("kill -9 the child");
    let _ = child.wait();
    assert!(
        !writable_within(&source.mountpoint(), Duration::from_millis(200)),
        "the kill itself thawed the source; the deadman was not what thawed it"
    );
    // freeze_max 1 s + grace 2 s after the freeze began.
    assert!(
        writable_within(&source.mountpoint(), Duration::from_secs(30)),
        "the deadman must thaw the source after the job was killed"
    );
    println!("thawed {:?} after the kill", killed.elapsed());
    // The killed job's instance is left for the start-up sweep.
    let tracefs = lr_snapshot::tracking::tracefs_root().expect("tracefs");
    let swept = lr_snapshot::tracking::sweep(&tracefs);
    assert!(
        swept.iter().any(|dir| dir
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with("lr-tf-"))),
        "the sweep found no leftover instance: {swept:?}"
    );
}

#[test]
#[ignore = "requires root, loop devices, tracefs and fsfreeze"]
fn lost_events_fail_the_copy() {
    if !root_tests_enabled() || !prerequisites() {
        return;
    }
    let Some(source) = Source::create() else {
        return;
    };
    let work = tempfile::tempdir().expect("work");
    let layout = lr_core::discover_source(Path::new(&source.partition())).expect("discover");
    let options = lr_core::SnapshotOpts {
        provider: Some("tracked-freeze".to_owned()),
        destination: Some(work.path().to_path_buf()),
        tracked: lr_core::TrackedTuning {
            buffer_kb: Some(4),
            ..lr_core::TrackedTuning::default()
        },
        ..lr_core::SnapshotOpts::default()
    };
    use lr_snapshot::BlockSnapshotProvider as _;
    let mut snapshot = lr_snapshot::tracked_freeze::provider()
        .create(&layout, &options)
        .expect("tracked copy");
    let tracked = snapshot.tracked_mut().expect("tracked");
    tracked.bind(u64::from(CHUNK_SIZE)).expect("bind");
    // Starve the reader while the source is written: a 4 KiB ring buffer
    // per CPU overflows, and those writes are never seen.
    tracked.pause_reader(true);
    let dir = source.mountpoint().join("burst");
    std::fs::create_dir(&dir).expect("burst dir");
    for index in 0..300 {
        let path = dir.join(format!("{index}.bin"));
        let mut file = std::fs::File::create(&path).expect("create");
        file.write_all(&[index as u8; 16 * 1024]).expect("write");
        file.sync_all().expect("fsync");
    }
    tracked.pause_reader(false);
    tracked
        .final_read(|_| -> lr_core::Result<()> { Ok(()) })
        .expect("final read");
    let error = tracked
        .finish()
        .expect_err("lost events must fail the copy");
    assert!(
        matches!(error, lr_core::Error::TrackingLost { .. }),
        "expected E_TRACKING_LOST, got {error}"
    );
    println!("{error}");
}

/// A GPT loop disk like a small installed system: an ESP (vfat, mounted)
/// and an ext4 "root" (mounted, written to).
struct SystemDisk {
    dir: tempfile::TempDir,
    device: String,
}

impl SystemDisk {
    fn create() -> Option<Self> {
        if !have("mkfs.vfat") || !have("fsck.vfat") {
            lr_testkit::unavailable!(return None; "dosfstools missing");
        }
        let dir = tempfile::tempdir().expect("dir");
        let image = dir.path().join("disk.img");
        std::fs::File::create(&image)
            .and_then(|f| f.set_len(DISK_BYTES))
            .expect("image");
        let mut sfdisk = Command::new("sfdisk")
            .arg("--quiet")
            .arg(&image)
            .stdin(Stdio::piped())
            .spawn()
            .expect("sfdisk");
        sfdisk
            .stdin
            .take()
            .expect("stdin")
            .write_all(
                b"label: gpt\nstart=2048, size=64MiB, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B\n\
                  type=0FC63DAF-8483-4772-8E79-3D69D8477DE4\n",
            )
            .expect("layout");
        if !sfdisk.wait().expect("sfdisk").success() {
            lr_testkit::fixture_failed!("sfdisk failed");
        }
        let output = Command::new("losetup")
            .args(["--find", "--show", "--partscan"])
            .arg(&image)
            .output()
            .expect("losetup");
        if !output.status.success() {
            lr_testkit::fixture_failed!("losetup failed");
        }
        let disk = Self {
            dir,
            device: String::from_utf8_lossy(&output.stdout).trim().to_owned(),
        };
        let _ = run("blockdev", &["--rereadpt", &disk.device]);
        for _ in 0..100 {
            if Path::new(&disk.partition(2)).exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        if !run("mkfs.vfat", &["-F", "32", &disk.partition(1)])
            || !run("mkfs.ext4", &["-q", "-F", &disk.partition(2)])
        {
            lr_testkit::fixture_failed!("mkfs failed");
        }
        std::fs::create_dir_all(disk.root()).expect("root mountpoint");
        if !run(
            "mount",
            &[&disk.partition(2), &disk.root().display().to_string()],
        ) {
            lr_testkit::fixture_failed!("mount root failed");
        }
        std::fs::create_dir_all(disk.esp()).expect("esp mountpoint");
        if !run(
            "mount",
            &[&disk.partition(1), &disk.esp().display().to_string()],
        ) {
            lr_testkit::fixture_failed!("mount esp failed");
        }
        std::fs::create_dir_all(disk.esp().join("EFI/BOOT")).expect("efi dir");
        std::fs::write(
            disk.esp().join("EFI/BOOT/BOOTX64.EFI"),
            vec![0x4d; 300 * 1024],
        )
        .expect("loader");
        let _ = run("sync", &[]);
        Some(disk)
    }

    fn partition(&self, index: u32) -> String {
        format!("{}p{index}", self.device)
    }

    fn root(&self) -> PathBuf {
        self.dir.path().join("root")
    }

    fn esp(&self) -> PathBuf {
        self.dir.path().join("root-esp")
    }
}

impl Drop for SystemDisk {
    fn drop(&mut self) {
        let _ = run("umount", &[&self.esp().display().to_string()]);
        let _ = run("umount", &[&self.root().display().to_string()]);
        let _ = run("losetup", &["--detach", &self.device]);
    }
}

fn whole_disk_request(disk: &str, dest: &Path) -> BackupRequest {
    request(disk, dest)
}

/// `PlanBackup` for a running system disk (spec §E.7, D-136): the plan
/// predicts tracked-freeze and `Frozen`, names the filesystems the final
/// freeze holds and its budget, and refuses what the backup would refuse,
/// all without tracing or freezing anything.
#[test]
#[ignore = "requires root, loop devices and tracefs"]
fn the_backup_plan_predicts_a_live_whole_disk_copy() {
    if !root_tests_enabled() || !prerequisites() {
        return;
    }
    let Some(disk) = SystemDisk::create() else {
        return;
    };
    let work = tempfile::tempdir().expect("work");
    let plan_of = |request: &BackupRequest| {
        lr_engine::plan_backup(
            request,
            lr_engine::options::Mode::Auto,
            &lr_engine::FileBackupOptions::default(),
        )
    };
    let mut live = whole_disk_request(&disk.device, &work.path().join("backups"));
    live.hooks_dir = Some(work.path().join("no-hooks"));
    let plan = plan_of(&live).expect("a plan for the running disk");
    assert_eq!(plan.provider, "tracked-freeze");
    assert_eq!(plan.consistency, lr_core::Consistency::Frozen);
    assert_eq!(plan.image_kind, lr_core::ImageKind::Block);
    let notes = plan.warnings.join("\n");
    assert!(
        notes.contains(&format!(
            "freezes {} together for at most 3 s",
            disk.root().display()
        )),
        "{notes}"
    );
    // The boot area before the first partition and the vfat ESP.
    assert!(
        notes.contains("2 region(s) that cannot be frozen"),
        "{notes}"
    );
    assert!(notes.contains("no hooks are installed"), "{notes}");
    assert_eq!(trace_leftovers(), 0, "planning created a trace instance");
    assert!(
        writable_within(&disk.root(), Duration::from_secs(2)),
        "planning froze the source"
    );

    // A longer budget is shown as asked; one past the cap is refused.
    let mut longer = whole_disk_request(&disk.device, &work.path().join("backups"));
    longer.hooks_dir = Some(work.path().join("no-hooks"));
    longer.tracked_tuning.freeze_max_secs = Some(10);
    let notes = plan_of(&longer).expect("plan").warnings.join("\n");
    assert!(notes.contains("for at most 10 s"), "{notes}");
    longer.tracked_tuning.freeze_max_secs = Some(31);
    let error = plan_of(&longer).expect_err("past the cap");
    assert!(error.to_string().contains("1 to 30 seconds"), "{error}");

    // What the backup refuses, the plan refuses: a destination on the root
    // filesystem, and a mounted disk without tracked-freeze.
    let on_root = whole_disk_request(&disk.device, &disk.root().join("backups"));
    let error = plan_of(&on_root).expect_err("a destination on a frozen filesystem");
    assert!(error.to_string().contains("will be frozen"), "{error}");
    let mut offline = whole_disk_request(&disk.device, &work.path().join("backups"));
    offline.snapshot_provider = None;
    let error = plan_of(&offline).expect_err("a mounted disk without tracked-freeze");
    assert!(
        error.to_string().contains("offline read refused"),
        "{error}"
    );
}

/// `sfdisk -d` without the device names, for comparing two disks' layouts.
fn layout_of(device: &str) -> String {
    let output = Command::new("sfdisk")
        .arg("-d")
        .arg(device)
        .output()
        .expect("sfdisk -d");
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.starts_with("device:") && !line.starts_with("last-lba:"))
        .map(|line| {
            line.split_once(':')
                .map_or(line, |(_, rest)| rest)
                .trim()
                .to_owned()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
#[ignore = "requires root, loop devices, tracefs and fsfreeze"]
fn a_busy_system_disk_is_imaged_live_and_restores_clean() {
    if !root_tests_enabled() || !prerequisites() {
        return;
    }
    let Some(disk) = SystemDisk::create() else {
        return;
    };
    let work = tempfile::tempdir().expect("work");
    let dest = work.path().join("backups");
    let writer = Writer::start(&disk.root().join("work"));
    std::thread::sleep(Duration::from_millis(500));
    let backup_started = Instant::now();
    let report = backup_image(&whole_disk_request(&disk.device, &dest)).expect("live whole disk");
    let backup_ended = Instant::now();
    std::thread::sleep(Duration::from_millis(300));
    let records = writer.stop();

    let ImageReport::WholeDisk(report) = &report else {
        panic!("expected a whole-disk image");
    };
    let tracked = report.tracked.expect("a tracked summary");
    println!("{tracked:?}");
    assert_eq!(tracked.frozen_filesystems, 1, "only the ext4 is frozen");
    for region in &report.regions {
        assert_eq!(
            region.consistency,
            lr_core::Consistency::Frozen,
            "{region:?}"
        );
    }

    // Restore onto a second loop disk of the same size.
    let target_image = work.path().join("target.img");
    std::fs::File::create(&target_image)
        .and_then(|f| f.set_len(DISK_BYTES))
        .expect("target");
    let plan = prepare_restore(&PrepareRequest::from_path(
        &report.image_path,
        &target_image,
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
    let output = Command::new("losetup")
        .args(["--find", "--show", "--partscan", "--read-only"])
        .arg(&target_image)
        .output()
        .expect("losetup target");
    let target = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let _ = run("blockdev", &["--rereadpt", &target]);
    for _ in 0..100 {
        if Path::new(&format!("{target}p2")).exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let detach = || {
        let _ = run("losetup", &["--detach", &target]);
    };

    assert_eq!(
        layout_of(&target),
        layout_of(&disk.device),
        "the partition table differs"
    );
    let fsck = Command::new("e2fsck")
        .arg("-fn")
        .arg(format!("{target}p2"))
        .output()
        .expect("e2fsck");
    // A mounted vfat keeps its dirty flag in the primary boot sector only, so
    // fsck.vfat always reports a mounted copy; compare with the source instead
    // (the source ESP is idle in this test).
    let esp_same = Command::new("cmp")
        .arg(disk.partition(1))
        .arg(format!("{target}p1"))
        .status()
        .expect("cmp")
        .success();
    let header = Command::new("dumpe2fs")
        .arg("-h")
        .arg(format!("{target}p2"))
        .output()
        .expect("dumpe2fs");
    let check = work.path().join("check");
    std::fs::create_dir(&check).expect("check dir");
    let mounted = run(
        "mount",
        &[
            "-o",
            "ro",
            &format!("{target}p2"),
            &check.display().to_string(),
        ],
    );
    let log = std::fs::read_to_string(check.join("work/chain.log")).unwrap_or_default();
    let _ = run("umount", &[&check.display().to_string()]);
    detach();

    assert!(
        fsck.status.success(),
        "e2fsck:\n{}",
        String::from_utf8_lossy(&fsck.stdout)
    );
    assert!(esp_same, "the restored ESP differs from the source ESP");
    assert!(
        !String::from_utf8_lossy(&header.stdout).contains("needs_recovery"),
        "the root copy still needs journal recovery"
    );
    assert!(mounted, "the restored root does not mount");
    let mut previous = 0u64;
    let mut count = 0u64;
    for line in log.lines() {
        let (seq, hash) = line.split_once(' ').expect("record");
        assert_eq!(seq.parse::<u64>().expect("seq"), count);
        previous = link(previous, count);
        assert_eq!(hash, format!("{previous:016x}"), "broken chain at {count}");
        count += 1;
    }
    let synced_before = records
        .iter()
        .filter(|(_, _, s)| *s < backup_started)
        .count() as u64;
    let begun_before_end = records.iter().filter(|(_, b, _)| *b < backup_ended).count() as u64;
    assert!(
        (synced_before..=begun_before_end).contains(&count),
        "{count} records; expected between {synced_before} and {begun_before_end}"
    );
}

#[test]
#[ignore = "requires root, loop devices, tracefs and fsfreeze"]
fn a_busy_esp_is_copied_consistently_or_refused() {
    if !root_tests_enabled() || !prerequisites() {
        return;
    }
    let Some(disk) = SystemDisk::create() else {
        return;
    };
    let work = tempfile::tempdir().expect("work");
    let dest = work.path().join("backups");
    // Something keeps rewriting a file on the ESP, which cannot be frozen.
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let esp = disk.esp();
    let hammer = std::thread::spawn(move || {
        let mut round = 1u64;
        while !flag.load(Ordering::Relaxed) {
            let mut file = std::fs::File::create(esp.join("grubenv")).expect("esp file");
            file.write_all(&round.to_le_bytes().repeat(512))
                .expect("esp write");
            file.sync_all().expect("esp fsync");
            round += 1;
        }
    });
    let outcome = backup_image(&whole_disk_request(&disk.device, &dest));
    stop.store(true, Ordering::Relaxed);
    hammer.join().expect("hammer");
    match outcome {
        // Refused: the quiet window failed, or the copy could not converge;
        // nothing may be published.
        Err(error) => {
            assert!(
                matches!(
                    error,
                    lr_core::Error::SourceChanged { .. } | lr_core::Error::NoConvergence { .. }
                ),
                "unexpected failure: {error}"
            );
            println!("refused: {error}");
            assert!(images_under(&dest).is_empty(), "an image was published");
        }
        // Accepted: then the ESP in the image must hold one whole version of
        // the file, never a mix of two.
        Ok(ImageReport::WholeDisk(report)) => {
            let target_image = work.path().join("target.img");
            std::fs::File::create(&target_image)
                .and_then(|f| f.set_len(DISK_BYTES))
                .expect("target");
            let plan = prepare_restore(&PrepareRequest::from_path(
                &report.image_path,
                &target_image,
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
            let output = Command::new("losetup")
                .args(["--find", "--show", "--partscan", "--read-only"])
                .arg(&target_image)
                .output()
                .expect("losetup target");
            let target = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            let _ = run("blockdev", &["--rereadpt", &target]);
            for _ in 0..100 {
                if Path::new(&format!("{target}p1")).exists() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let check = work.path().join("esp-check");
            std::fs::create_dir(&check).expect("check dir");
            let mounted = run(
                "mount",
                &[
                    "-o",
                    "ro",
                    &format!("{target}p1"),
                    &check.display().to_string(),
                ],
            );
            let grubenv = std::fs::read(check.join("grubenv")).unwrap_or_default();
            let loader = std::fs::read(check.join("EFI/BOOT/BOOTX64.EFI")).unwrap_or_default();
            let _ = run("umount", &[&check.display().to_string()]);
            let _ = run("losetup", &["--detach", &target]);
            assert!(mounted, "the restored ESP does not mount");
            assert_eq!(loader, vec![0x4d; 300 * 1024], "the loader is damaged");
            assert_eq!(
                grubenv.len(),
                4096,
                "the file is torn: {} bytes",
                grubenv.len()
            );
            let first = &grubenv[..8];
            assert!(
                grubenv.chunks_exact(8).all(|word| word == first),
                "the file mixes two versions"
            );
            println!("accepted: one whole version, {:?}", report.tracked);
        }
        Ok(other) => panic!("expected a whole-disk image, got {other:?}"),
    }
    assert_eq!(trace_leftovers(), 0, "a trace instance was left behind");
}
