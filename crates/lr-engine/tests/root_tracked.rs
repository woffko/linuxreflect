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

/// A GPT loop disk with a mounted ext4 on one of its partitions.
struct Source {
    dir: tempfile::TempDir,
    device: String,
    /// The partition that holds the ext4.
    part: u32,
}

impl Source {
    /// A 16 MiB partition without a filesystem, then the ext4.
    fn create() -> Option<Self> {
        Self::create_with("label: gpt\nstart=2048, size=16MiB\n,\n", 2)
    }

    /// `layout` for `sfdisk`, with the ext4 on partition `part`.
    fn create_with(layout: &str, part: u32) -> Option<Self> {
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
            .write_all(layout.as_bytes())
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
        let source = Self { dir, device, part };
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
        format!("{}p{}", self.device, self.part)
    }

    fn mountpoint(&self) -> PathBuf {
        self.dir.path().join("mnt")
    }

    fn partition_bytes(&self) -> u64 {
        let name = format!(
            "{}p{}",
            Path::new(&self.device)
                .file_name()
                .expect("name")
                .to_string_lossy(),
            self.part
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
    restore_to_file(&report.image_path, source.partition_bytes(), &target);
    check_restored(
        &target,
        work.path(),
        "full",
        &records,
        (backup_started, backup_ended),
    );
}

/// Restore `image` (with its chain) into a new file of `bytes`.
fn restore_to_file(image: &Path, bytes: u64, target: &Path) {
    std::fs::File::create(target)
        .and_then(|f| f.set_len(bytes))
        .expect("target");
    let plan = prepare_restore(&PrepareRequest::from_path(
        image,
        target,
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
}

/// Check a restored copy of the writer's filesystem offline: a clean ext4
/// with no journal left to replay, the writer's log a whole hash chain that
/// ends inside `window` (everything synced before it began is there, nothing
/// begun after it ended is), and every 4 KiB block of `random.bin` whole.
/// Returns `static.bin` from the copy, when there is one.
fn check_restored(
    target: &Path,
    work: &Path,
    label: &str,
    records: &[(u64, Instant, Instant)],
    window: (Instant, Instant),
) -> Option<Vec<u8>> {
    let fsck = Command::new("e2fsck")
        .arg("-fn")
        .arg(target)
        .output()
        .expect("e2fsck");
    assert!(
        fsck.status.success(),
        "{label}: e2fsck:\n{}{}",
        String::from_utf8_lossy(&fsck.stdout),
        String::from_utf8_lossy(&fsck.stderr)
    );
    // e2fsck -n alone does not see a journal left to replay (phase 0).
    let header = Command::new("dumpe2fs")
        .arg("-h")
        .arg(target)
        .output()
        .expect("dumpe2fs");
    let header = String::from_utf8_lossy(&header.stdout);
    assert!(
        !header.contains("needs_recovery"),
        "{label}: the copy still needs journal recovery:\n{header}"
    );

    let check = work.join(format!("check-{}", label.replace(' ', "-")));
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
    let static_data = std::fs::read(check.join("static.bin")).ok();
    let _ = run("umount", &[&check.display().to_string()]);

    // The log is a whole, valid chain…
    assert!(
        log.ends_with('\n') || log.is_empty(),
        "{label}: torn last record"
    );
    let mut previous = 0u64;
    let mut count = 0u64;
    for line in log.lines() {
        let (seq, hash) = line.split_once(' ').expect("record");
        assert_eq!(
            seq.parse::<u64>().expect("seq"),
            count,
            "{label}: records out of order"
        );
        previous = link(previous, count);
        assert_eq!(
            hash,
            format!("{previous:016x}"),
            "{label}: broken chain at {count}"
        );
        count += 1;
    }
    // …that ends inside the backup.
    let (started, ended) = window;
    let synced_before = records
        .iter()
        .filter(|(_, _, synced)| *synced < started)
        .count() as u64;
    let begun_before_end = records
        .iter()
        .filter(|(_, begun, _)| *begun < ended)
        .count() as u64;
    assert!(
        (synced_before..=begun_before_end).contains(&count),
        "{label}: {count} records; expected between {synced_before} and {begun_before_end}"
    );
    // Every 4 KiB block is whole: either never written or one version.
    for (index, block) in blocks.chunks_exact(4096).enumerate() {
        if block.iter().all(|byte| *byte == 0) {
            continue;
        }
        let stored = u64::from_le_bytes(block[..8].try_into().expect("8 bytes"));
        let version = u64::from_le_bytes(block[8..16].try_into().expect("8 bytes"));
        assert_eq!(
            stored, index as u64,
            "{label}: block {index} holds block {stored}"
        );
        assert_eq!(
            block,
            block_bytes(stored, version).as_slice(),
            "{label}: block {index} is torn"
        );
    }
    static_data
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

/// Incompressible bytes that never change during a test.
fn static_payload(len: usize) -> Vec<u8> {
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut bytes = Vec::with_capacity(len);
    while bytes.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        bytes.extend_from_slice(&state.to_le_bytes());
    }
    bytes.truncate(len);
    bytes
}

/// Series B1: a live chain of a busy partition. A full, an incremental, a
/// differential and an incremental through the automatic choice are each
/// copied live while the writer runs. Each restores to a clean copy whose log
/// ends inside its own backup; data that never changed is inherited, not
/// stored again; `verify` passes for the chain and names a corrupted member.
#[test]
#[ignore = "requires root, loop devices, tracefs and fsfreeze"]
fn a_live_chain_of_a_busy_partition_restores_every_member() {
    use lr_core::catalog::MemberKind;
    use lr_engine::backup::MemberType;
    if !root_tests_enabled() || !prerequisites() {
        return;
    }
    let Some(source) = Source::create() else {
        return;
    };
    let work = tempfile::tempdir().expect("work");
    let dest = work.path().join("backups");
    // 48 MiB that the full stores and every later member inherits.
    let static_data = static_payload(48 << 20);
    std::fs::write(source.mountpoint().join("static.bin"), &static_data).expect("static");
    let _ = run("sync", &[]);

    let writer = Writer::start(&source.mountpoint().join("work"));
    std::thread::sleep(Duration::from_millis(500));
    let mut members = Vec::new();
    for (label, member_type, automatic) in [
        ("full", MemberType::Full, false),
        ("incremental", MemberType::Incremental, false),
        ("differential", MemberType::Differential, false),
        ("automatic incremental", MemberType::Incremental, true),
    ] {
        let mut member = request(&source.partition(), &dest);
        member.member_type = member_type;
        if member_type != MemberType::Full {
            member.parent = Some("latest".to_owned());
        }
        if automatic {
            member.snapshot_provider = None;
            member.allow_freeze = true;
        }
        let started = Instant::now();
        let report = backup_image(&member).unwrap_or_else(|error| panic!("{label}: {error}"));
        let ended = Instant::now();
        let ImageReport::Block(report) = report else {
            panic!("{label}: expected a block image");
        };
        assert_eq!(report.consistency, lr_core::Consistency::Frozen, "{label}");
        let tracked = report
            .tracked
            .unwrap_or_else(|| panic!("{label}: not copied live"));
        println!("{label}: {tracked:?}, stored {}", report.stored_chunks);
        members.push((label, report, started, ended));
        std::thread::sleep(Duration::from_millis(700));
    }
    let records = writer.stop();

    let kinds: Vec<(MemberKind, u32)> = members
        .iter()
        .map(|(_, report, _, _)| (report.member_kind, report.seq_in_chain))
        .collect();
    assert_eq!(
        kinds,
        [
            (MemberKind::Full, 0),
            (MemberKind::Incremental, 1),
            (MemberKind::Differential, 2),
            (MemberKind::Incremental, 3),
        ]
    );
    let full_stored = members[0].1.stored_chunks;
    for (label, report, _, _) in &members[1..] {
        assert!(
            report.stored_chunks * 2 < full_stored,
            "{label} stored {} chunks of the full's {full_stored}",
            report.stored_chunks
        );
    }

    for (label, report, started, ended) in &members {
        let target = work.path().join(format!("{}.img", label.replace(' ', "-")));
        restore_to_file(&report.image_path, source.partition_bytes(), &target);
        let restored_static =
            check_restored(&target, work.path(), label, &records, (*started, *ended));
        assert!(
            restored_static.as_deref() == Some(static_data.as_slice()),
            "{label}: static.bin differs"
        );
    }

    // The chain verifies from its newest member; a corrupted member is named.
    let newest = &members[3].1;
    let verify = |image: &str| {
        lr_engine::verify::verify_image(&lr_engine::verify::VerifyRequest {
            image: image.to_owned(),
            encryption: Encryption::NoEncrypt,
            chain: true,
            destination_options: lr_store::DestinationOptions::default(),
            context: lr_engine::progress::EngineContext::silent(),
        })
    };
    let report = verify(&newest.image_uri).expect("the chain verifies");
    assert_eq!(report.members, 4, "{report:?}");
    let incremental = &members[1].1.image_path;
    // The last byte of the last chunk record: a chunk of the final read,
    // which the manifest references (an earlier copy of a chunk read again
    // is unreferenced, spec §E.7, and verify rightly ignores it).
    let data_end = lr_format::ImageReader::open(std::fs::File::open(incremental).expect("open"))
        .expect("member")
        .footer()
        .data_end_offset;
    let mut bytes = std::fs::read(incremental).expect("member");
    let at = usize::try_from(data_end - 1).expect("offset");
    bytes[at] ^= 0xFF;
    std::fs::write(incremental, bytes).expect("corrupt");
    let error = verify(&newest.image_uri).expect_err("a corrupted member must fail");
    let name = incremental
        .file_name()
        .expect("name")
        .to_string_lossy()
        .into_owned();
    assert!(error.to_string().contains(&name), "{error}");

    // A member chunked differently from its parent is refused before a
    // snapshot is made, so nothing is frozen or traced.
    let mut other = request(&source.partition(), &dest);
    other.member_type = MemberType::Incremental;
    other.parent = Some("latest".to_owned());
    other.chunk_size = 2 * CHUNK_SIZE;
    let error = backup_image(&other).expect_err("another chunk size");
    assert!(error.to_string().contains("-byte chunks"), "{error}");
    assert_eq!(trace_leftovers(), 0, "a trace instance was left behind");
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

/// Spec §E step 4 (D-141): `auto` with `--allow-freeze` chooses tracked-freeze
/// for a mounted ext4 partition and for a disk in use, and the plan says so
/// first. Without the consent nothing live is chosen and the refusal names
/// the option; a precondition that does not hold is named in the refusal.
#[test]
#[ignore = "requires root, loop devices, tracefs and fsfreeze"]
fn the_automatic_choice_with_allow_freeze_copies_live() {
    if !root_tests_enabled() || !prerequisites() {
        return;
    }
    let Some(disk) = SystemDisk::create() else {
        return;
    };
    let work = tempfile::tempdir().expect("work");
    let automatic = |source: &str, dest: &Path, allow_freeze: bool| {
        let mut request = request(source, dest);
        request.snapshot_provider = None;
        request.allow_freeze = allow_freeze;
        request.hooks_dir = Some(work.path().join("no-hooks"));
        request
    };
    let plan_of = |request: &BackupRequest| {
        lr_engine::plan_backup(
            request,
            lr_engine::options::Mode::Auto,
            &lr_engine::FileBackupOptions::default(),
        )
    };

    // A mounted ext4 partition.
    let partition = automatic(&disk.partition(2), &work.path().join("partition"), true);
    let plan = plan_of(&partition).expect("a plan for the mounted partition");
    assert_eq!(plan.provider, "tracked-freeze");
    assert_eq!(plan.consistency, lr_core::Consistency::Frozen);
    let notes = plan.warnings.join("\n");
    assert!(
        notes.contains("the automatic choice goes on to the next method"),
        "{notes}"
    );
    let report = backup_image(&partition).expect("a live partition copy");
    let ImageReport::Block(report) = &report else {
        panic!("expected a block image");
    };
    assert_eq!(report.consistency, lr_core::Consistency::Frozen);
    assert!(report.tracked.is_some(), "not copied with tracked-freeze");

    // The whole disk in use.
    let whole = automatic(&disk.device, &work.path().join("disk"), true);
    let plan = plan_of(&whole).expect("a plan for the disk in use");
    assert_eq!(plan.provider, "tracked-freeze");
    let report = backup_image(&whole).expect("a live whole-disk copy");
    let ImageReport::WholeDisk(report) = &report else {
        panic!("expected a whole-disk image");
    };
    assert!(report.tracked.is_some(), "not copied with tracked-freeze");
    for region in &report.regions {
        assert_eq!(
            region.consistency,
            lr_core::Consistency::Frozen,
            "{region:?}"
        );
    }

    // Without the consent: refused before anything is traced or frozen.
    let refused = work.path().join("refused");
    for source in [disk.partition(2), disk.device.clone()] {
        let unconsented = automatic(&source, &refused, false);
        let error = plan_of(&unconsented).expect_err("no live copy without the consent");
        assert!(
            error.to_string().contains("--allow-freeze to copy"),
            "{error}"
        );
        let error = backup_image(&unconsented).expect_err("no live copy without the consent");
        assert!(
            matches!(error, lr_core::Error::NoConsistentMethod { .. }),
            "{error}"
        );
    }
    // A precondition that does not hold is named: the destination on the
    // filesystem the copy would freeze.
    let on_root = automatic(&disk.device, &disk.root().join("backups"), true);
    let error = backup_image(&on_root).expect_err("a destination on a frozen filesystem");
    assert!(
        error
            .to_string()
            .contains("tracked-freeze cannot copy it live: the destination"),
        "{error}"
    );
    assert!(images_under(&refused).is_empty(), "an image was published");
    assert_eq!(trace_leftovers(), 0, "a trace instance was left behind");
    assert!(
        writable_within(&disk.root(), Duration::from_secs(5)),
        "the source stayed frozen"
    );
}

/// A loop disk whose image lives on an ext4 over `dm-delay`, so a test can
/// slow the source's reads at a moment it chooses. The loop disk reads its
/// image with direct I/O, so no page cache hides the delay.
struct SlowSource {
    dir: tempfile::TempDir,
    /// The loop device under the delay target.
    outer: String,
    sectors: u64,
    /// The delay target's name.
    delay: String,
    /// The loop disk with the mounted ext4 on its first partition.
    device: String,
    mounted_outer: bool,
    mounted: bool,
}

impl SlowSource {
    fn create() -> Option<Self> {
        if !have("dmsetup") {
            lr_testkit::unavailable!(return None; "dmsetup missing");
        }
        let has_delay = || {
            Command::new("dmsetup")
                .arg("targets")
                .output()
                .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("delay"))
        };
        if !has_delay() {
            let _ = run("modprobe", &["dm-delay"]);
            if !has_delay() {
                lr_testkit::unavailable!(return None; "the dm-delay target is unavailable");
            }
        }
        let mut source = Self {
            dir: tempfile::tempdir().expect("dir"),
            outer: String::new(),
            sectors: 0,
            delay: format!("lr-delay-{}", std::process::id()),
            device: String::new(),
            mounted_outer: false,
            mounted: false,
        };
        let outer_image = source.dir.path().join("outer.img");
        std::fs::File::create(&outer_image)
            .and_then(|f| f.set_len(256 << 20))
            .expect("outer image");
        source.outer = attach(&["--find", "--show"], &outer_image);
        let sectors = Command::new("blockdev")
            .args(["--getsz", &source.outer])
            .output()
            .expect("blockdev");
        source.sectors = String::from_utf8_lossy(&sectors.stdout)
            .trim()
            .parse()
            .expect("sectors");
        if !run(
            "dmsetup",
            &["create", &source.delay, "--table", &source.table(0)],
        ) {
            source.delay.clear();
            lr_testkit::fixture_failed!("dmsetup create failed");
        }
        let mapper = format!("/dev/mapper/{}", source.delay);
        let outer_mnt = source.dir.path().join("outer");
        std::fs::create_dir(&outer_mnt).expect("outer mountpoint");
        if !run("mkfs.ext4", &["-q", "-F", &mapper])
            || !run("mount", &[&mapper, &outer_mnt.display().to_string()])
        {
            lr_testkit::fixture_failed!("the delayed filesystem could not be made");
        }
        source.mounted_outer = true;
        let image = outer_mnt.join("disk.img");
        std::fs::File::create(&image)
            .and_then(|f| f.set_len(96 << 20))
            .expect("disk image");
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
            .write_all(b"label: gpt\nstart=2048, size=64MiB\n")
            .expect("layout");
        if !sfdisk.wait().expect("sfdisk").success() {
            lr_testkit::fixture_failed!("sfdisk failed");
        }
        source.device = attach(
            &["--find", "--show", "--partscan", "--direct-io=on"],
            &image,
        );
        let name = Path::new(&source.device)
            .file_name()
            .expect("name")
            .to_string_lossy()
            .into_owned();
        let dio =
            std::fs::read_to_string(format!("/sys/block/{name}/loop/dio")).unwrap_or_default();
        if dio.trim() != "1" {
            lr_testkit::unavailable!(return None; "loop direct I/O is unavailable");
        }
        let _ = run("blockdev", &["--rereadpt", &source.device]);
        for _ in 0..100 {
            if Path::new(&source.partition()).exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        std::fs::create_dir(source.mountpoint()).expect("mountpoint");
        if !run("mkfs.ext4", &["-q", "-F", &source.partition()])
            || !run(
                "mount",
                &[
                    &source.partition(),
                    &source.mountpoint().display().to_string(),
                ],
            )
        {
            lr_testkit::fixture_failed!("the source filesystem could not be made");
        }
        source.mounted = true;
        Some(source)
    }

    /// The delay table: reads wait `read_ms`, writes do not wait.
    fn table(&self, read_ms: u32) -> String {
        format!(
            "0 {} delay {} 0 {read_ms} {} 0 0",
            self.sectors, self.outer, self.outer
        )
    }

    fn partition(&self) -> String {
        format!("{}p1", self.device)
    }

    fn mountpoint(&self) -> PathBuf {
        self.dir.path().join("src")
    }
}

impl Drop for SlowSource {
    // Each layer is released only once the one above it is gone: a loop
    // device detaches asynchronously, and the filesystem under it stays busy
    // until it has.
    fn drop(&mut self) {
        if !self.delay.is_empty() {
            let _ = run("dmsetup", &["suspend", &self.delay]);
            let _ = run("dmsetup", &["load", &self.delay, "--table", &self.table(0)]);
            let _ = run("dmsetup", &["resume", &self.delay]);
        }
        if self.mounted {
            let _ = run("umount", &[&self.mountpoint().display().to_string()]);
        }
        if !self.device.is_empty() {
            let _ = run("losetup", &["--detach", &self.device]);
            let name = Path::new(&self.device)
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            let backing = PathBuf::from(format!("/sys/block/{name}/loop/backing_file"));
            let image = self.dir.path().join("outer/disk.img");
            until(|| {
                std::fs::read_to_string(&backing)
                    .map_or(true, |file| !file.contains(&image.display().to_string()))
            });
        }
        if self.mounted_outer {
            let outer = self.dir.path().join("outer").display().to_string();
            until(|| run("umount", &[&outer]));
        }
        if !self.delay.is_empty() {
            until(|| run("dmsetup", &["remove", &self.delay]));
        }
        if !self.outer.is_empty() {
            let _ = run("losetup", &["--detach", &self.outer]);
        }
    }
}

/// Retry `done` for up to ten seconds.
fn until(mut done: impl FnMut() -> bool) {
    for _ in 0..100 {
        if done() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// `losetup` with `args`, attaching `image`; the new device.
fn attach(args: &[&str], image: &Path) -> String {
    let output = Command::new("losetup")
        .args(args)
        .arg(image)
        .output()
        .expect("losetup");
    if !output.status.success() {
        lr_testkit::fixture_failed!(
            "losetup failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// Slice 18 AC (c): a final read that outlasts `--freeze-max` thaws first
/// and then fails with `E_FREEZE_TIMEOUT`, publishing nothing. The
/// pre-freeze hook writes 8 MiB, which the final read must read, and slows
/// the source's reads to 250 ms each underneath its loop disk; the
/// post-thaw hook lifts the delay. The deadman (31 s) never has to act.
#[test]
#[ignore = "requires root, loop devices, dm-delay, tracefs and fsfreeze"]
fn a_final_read_longer_than_freeze_max_thaws_first_and_publishes_nothing() {
    if !root_tests_enabled() || !prerequisites() {
        return;
    }
    let Some(source) = SlowSource::create() else {
        return;
    };
    let work = tempfile::tempdir().expect("work");
    let (root, pre, post) = hooks_dir(work.path(), "hooks");
    let dm = |read_ms: u32| {
        format!(
            "dmsetup suspend {name} && dmsetup load {name} --table '{table}' && dmsetup resume {name}",
            name = source.delay,
            table = source.table(read_ms)
        )
    };
    hook(
        &pre,
        "10-slow-reads",
        0o755,
        &format!(
            "set -e\n\
             for fs in $LINUXREFLECT_FILESYSTEMS; do\n\
             dd if=/dev/urandom of=\"$fs/burst\" bs=1M count=8 oflag=direct conv=fsync status=none\n\
             done\n\
             {}",
            dm(250)
        ),
    );
    let lifted = work.path().join("lifted");
    hook(
        &post,
        "10-fast-reads",
        0o755,
        &format!("{} && touch {}", dm(0), lifted.display()),
    );
    let dest = work.path().join("backups");
    let mut slow = request(&source.partition(), &dest);
    slow.hooks_dir = Some(root);
    slow.tracked_tuning.freeze_max_secs = Some(1);
    slow.deadman_grace_secs = Some(30);
    let started = Instant::now();
    let error = backup_image(&slow).expect_err("a final read past --freeze-max must fail");
    let failed_after = started.elapsed();
    // Thawed before the error came back: a write completes at once.
    assert!(
        writable_within(&source.mountpoint(), Duration::from_secs(2)),
        "the source was still frozen when E_FREEZE_TIMEOUT came back"
    );
    assert!(
        matches!(error, lr_core::Error::FreezeTimeout),
        "expected E_FREEZE_TIMEOUT, got {error}"
    );
    assert!(
        failed_after < Duration::from_secs(31),
        "the deadman, not the copy, ended the freeze ({failed_after:?})"
    );
    assert!(lifted.exists(), "the post-thaw hook did not run");
    assert!(images_under(&dest).is_empty(), "an image was published");
    assert_eq!(trace_leftovers(), 0, "a trace instance was left behind");
}

/// Slice 18 AC (c): a partition table changed mid-job fails the copy with
/// `E_SOURCE_CHANGED` and publishes nothing. The pre-freeze hook appends a
/// partition to the disk being copied (the kernel keeps its old view while a
/// partition is mounted, so only the on-disk table changes).
#[test]
#[ignore = "requires root, loop devices, tracefs and fsfreeze"]
fn a_partition_table_changed_mid_job_publishes_nothing() {
    if !root_tests_enabled() || !prerequisites() {
        return;
    }
    // One ext4 partition and free space after it.
    let Some(source) = Source::create_with("label: gpt\nstart=2048, size=128MiB\n", 1) else {
        return;
    };
    let work = tempfile::tempdir().expect("work");
    let (root, pre, _post) = hooks_dir(work.path(), "hooks");
    let table_before = layout_of(&source.device);
    hook(
        &pre,
        "10-repartition",
        0o755,
        &format!(
            "echo ',16MiB' | sfdisk --quiet --append --no-reread {} > /dev/null 2>&1 || true",
            source.device
        ),
    );
    let dest = work.path().join("backups");
    let mut changing = whole_disk_request(&source.device, &dest);
    changing.hooks_dir = Some(root);
    let error = backup_image(&changing).expect_err("a changed partition table must fail");
    assert_ne!(
        layout_of(&source.device),
        table_before,
        "the hook did not change the partition table"
    );
    assert!(
        matches!(error, lr_core::Error::SourceChanged { .. }),
        "expected E_SOURCE_CHANGED, got {error}"
    );
    assert!(
        error.to_string().contains("partition table changed"),
        "{error}"
    );
    assert!(images_under(&dest).is_empty(), "an image was published");
    assert_eq!(trace_leftovers(), 0, "a trace instance was left behind");
    assert!(
        writable_within(&source.mountpoint(), Duration::from_secs(5)),
        "the source stayed frozen"
    );
}

/// Attach a restored disk image read-only with its partitions.
fn attach_restored(image: &Path) -> String {
    let output = Command::new("losetup")
        .args(["--find", "--show", "--partscan", "--read-only"])
        .arg(image)
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
    target
}

/// Series B2 (D-142): a live chain of a busy system disk (ESP + ext4). A
/// full, an incremental and a differential of the whole disk are each copied
/// live while the writer runs, and a marker file lands on the ESP before
/// each. Every member restores to a disk with the source's partition table,
/// a clean root whose log ends inside that member's backup, the static data
/// it inherited, and exactly the ESP markers written before it; the chain
/// verifies.
#[test]
#[ignore = "requires root, loop devices, tracefs and fsfreeze"]
fn a_live_chain_of_a_busy_system_disk_restores_every_member() {
    use lr_core::catalog::MemberKind;
    use lr_engine::backup::MemberType;
    if !root_tests_enabled() || !prerequisites() {
        return;
    }
    let Some(disk) = SystemDisk::create() else {
        return;
    };
    let work = tempfile::tempdir().expect("work");
    let dest = work.path().join("backups");
    let static_data = static_payload(128 << 20);
    std::fs::write(disk.root().join("static.bin"), &static_data).expect("static");
    let _ = run("sync", &[]);
    let writer = Writer::start(&disk.root().join("work"));
    std::thread::sleep(Duration::from_millis(500));

    let labels = ["full", "incremental", "differential"];
    let mut members = Vec::new();
    for (position, (label, member_type)) in labels
        .into_iter()
        .zip([
            MemberType::Full,
            MemberType::Incremental,
            MemberType::Differential,
        ])
        .enumerate()
    {
        std::fs::write(
            disk.esp().join(format!("EFI/marker-{position}")),
            label.as_bytes(),
        )
        .expect("esp marker");
        let _ = run("sync", &[]);
        let mut member = whole_disk_request(&disk.device, &dest);
        member.member_type = member_type;
        if member_type != MemberType::Full {
            member.parent = Some("latest".to_owned());
        }
        let started = Instant::now();
        let report = backup_image(&member).unwrap_or_else(|error| panic!("{label}: {error}"));
        let ended = Instant::now();
        let ImageReport::WholeDisk(report) = report else {
            panic!("{label}: expected a whole-disk image");
        };
        let tracked = report
            .tracked
            .unwrap_or_else(|| panic!("{label}: not copied live"));
        println!(
            "{label}: {tracked:?}, changed {}, inherited {}",
            report.changed_chunks, report.inherited_chunks
        );
        for region in &report.regions {
            assert_eq!(
                region.consistency,
                lr_core::Consistency::Frozen,
                "{label}: {region:?}"
            );
        }
        members.push((label, report, started, ended));
        std::thread::sleep(Duration::from_millis(700));
    }
    let records = writer.stop();

    assert_eq!(
        members
            .iter()
            .map(|(_, report, _, _)| (report.member_kind, report.seq_in_chain))
            .collect::<Vec<_>>(),
        [
            (MemberKind::Full, 0),
            (MemberKind::Incremental, 1),
            (MemberKind::Differential, 2),
        ]
    );
    let full_stored = members[0].1.stored_chunks();
    assert!(
        members[2].1.changed_chunks < members[2].1.inherited_chunks,
        "the differential inherits the unchanged data"
    );
    assert!(
        members[1].1.stored_chunks() * 2 < full_stored,
        "the incremental stored {} chunks of the full's {full_stored}",
        members[1].1.stored_chunks()
    );

    for (position, (label, report, started, ended)) in members.iter().enumerate() {
        let image = work.path().join(format!("{label}.img"));
        std::fs::File::create(&image)
            .and_then(|f| f.set_len(DISK_BYTES))
            .expect("target");
        let plan = prepare_restore(&PrepareRequest::from_path(
            &report.image_path,
            &image,
            Encryption::NoEncrypt,
        ))
        .expect("prepare");
        assert_eq!(
            plan.members.len(),
            position + 1,
            "{label}: {:?}",
            plan.members
        );
        apply_restore(&ApplyRequest {
            token: plan.token,
            confirm: true,
            accept_inconsistent: false,
            encryption: Encryption::NoEncrypt,
            context: lr_engine::progress::EngineContext::silent(),
        })
        .unwrap_or_else(|error| panic!("{label}: {error}"));
        let target = attach_restored(&image);
        let same_table = layout_of(&target) == layout_of(&disk.device);
        let esp = work.path().join(format!("esp-{label}"));
        std::fs::create_dir(&esp).expect("esp dir");
        let esp_mounted = run(
            "mount",
            &[
                "-o",
                "ro",
                &format!("{target}p1"),
                &esp.display().to_string(),
            ],
        );
        let markers: Vec<bool> = (0..labels.len())
            .map(|index| esp.join(format!("EFI/marker-{index}")).exists())
            .collect();
        let _ = run("umount", &[&esp.display().to_string()]);
        let root = work.path().join(format!("{label}-root.img"));
        let copied = Command::new("dd")
            .arg(format!("if={target}p2"))
            .arg(format!("of={}", root.display()))
            .args(["bs=4M", "status=none"])
            .status()
            .is_ok_and(|status| status.success());
        let _ = run("losetup", &["--detach", &target]);
        assert!(same_table, "{label}: the partition table differs");
        assert!(esp_mounted, "{label}: the restored ESP does not mount");
        assert_eq!(
            markers,
            (0..labels.len())
                .map(|index| index <= position)
                .collect::<Vec<_>>(),
            "{label}: the ESP is not as it was at this member"
        );
        assert!(copied, "{label}: the root partition could not be copied");
        let restored_static =
            check_restored(&root, work.path(), label, &records, (*started, *ended));
        assert!(
            restored_static.as_deref() == Some(static_data.as_slice()),
            "{label}: static.bin differs"
        );
    }

    let newest = &members[2].1;
    let report = lr_engine::verify::verify_image(&lr_engine::verify::VerifyRequest {
        image: newest.image_path.display().to_string(),
        encryption: Encryption::NoEncrypt,
        chain: true,
        destination_options: lr_store::DestinationOptions::default(),
        context: lr_engine::progress::EngineContext::silent(),
    })
    .expect("the chain verifies");
    assert_eq!(report.members, 3, "{report:?}");
}

/// Series B2 (D-142): an offline chain of a disk whose ext4 is mapped by its
/// used blocks. Between the members a file is deleted and another written;
/// the incremental restores the disk without the deleted file and with the
/// new one, and the filesystem checks clean.
#[test]
#[ignore = "requires root and loop devices"]
fn an_offline_whole_disk_chain_follows_deleted_and_new_files() {
    use lr_engine::backup::MemberType;
    if !root_tests_enabled() || !prerequisites() {
        return;
    }
    let Some(source) = Source::create_with("label: gpt\nstart=2048, size=128MiB\n", 1) else {
        return;
    };
    let work = tempfile::tempdir().expect("work");
    let dest = work.path().join("backups");
    let mountpoint = source.mountpoint().display().to_string();
    let first = static_payload(8 << 20);
    std::fs::write(source.mountpoint().join("first.bin"), &first).expect("first");
    assert!(run("umount", &[&mountpoint]));
    let mut full = whole_disk_request(&source.device, &dest);
    full.snapshot_provider = None;
    let ImageReport::WholeDisk(full) = backup_image(&full).expect("full") else {
        panic!("expected a whole-disk image");
    };
    assert_eq!(full.regions[1].consistency, lr_core::Consistency::Offline);

    assert!(run("mount", &[&source.partition(), &mountpoint]));
    std::fs::remove_file(source.mountpoint().join("first.bin")).expect("delete");
    let second = static_payload(5 << 20);
    std::fs::write(source.mountpoint().join("second.bin"), &second[..3 << 20]).expect("second");
    assert!(run("umount", &[&mountpoint]));
    let mut incremental = whole_disk_request(&source.device, &dest);
    incremental.snapshot_provider = None;
    incremental.member_type = MemberType::Incremental;
    incremental.parent = Some("latest".to_owned());
    let ImageReport::WholeDisk(incremental) = backup_image(&incremental).expect("incremental")
    else {
        panic!("expected a whole-disk image");
    };
    assert!(incremental.inherited_chunks > 0, "{incremental:?}");
    // Remounted for the source's own teardown.
    assert!(run("mount", &[&source.partition(), &mountpoint]));

    let image = work.path().join("restored.img");
    std::fs::File::create(&image)
        .and_then(|f| f.set_len(DISK_BYTES))
        .expect("target");
    let plan = prepare_restore(&PrepareRequest::from_path(
        &incremental.image_path,
        &image,
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
    let target = attach_restored(&image);
    let fsck = Command::new("e2fsck")
        .arg("-fn")
        .arg(format!("{target}p1"))
        .output()
        .expect("e2fsck");
    let check = work.path().join("check");
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
    let had_first = check.join("first.bin").exists();
    let second_restored = std::fs::read(check.join("second.bin")).ok();
    let _ = run("umount", &[&check.display().to_string()]);
    let _ = run("losetup", &["--detach", &target]);
    assert!(
        fsck.status.success(),
        "e2fsck:\n{}",
        String::from_utf8_lossy(&fsck.stdout)
    );
    assert!(mounted, "the restored filesystem does not mount");
    assert!(
        !had_first,
        "a file deleted before the incremental came back"
    );
    assert!(
        second_restored.as_deref() == Some(&second[..3 << 20]),
        "the file written before the incremental is not restored"
    );
}
