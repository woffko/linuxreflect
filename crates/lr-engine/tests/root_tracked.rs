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
        buffer_kb: None,
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
        freeze_timeout_secs: Some(1),
        deadman_grace_secs: Some(2),
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
