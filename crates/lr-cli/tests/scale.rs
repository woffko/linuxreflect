//! Scale profiles with memory budgets (remediation plan, phase 4).
//!
//! Each test runs the real CLI on a large input, takes the process's peak
//! resident set from `wait4(2)` (`ru_maxrss`) and holds it to a budget
//! recorded in `docs/performance.md`. They take minutes and gigabytes of scratch space,
//! so they run only with `LR_SCALE_TESTS=1` (`cargo xtask scale`), not in the
//! ordinary test run. No root is needed.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

const CLI: &str = env!("CARGO_BIN_EXE_linuxreflect");

/// One measured run of the CLI.
struct Run {
    peak_mib: u64,
    seconds: f64,
    stdout: String,
}

fn enabled() -> bool {
    if std::env::var("LR_SCALE_TESTS").as_deref() == Ok("1") {
        return true;
    }
    lr_testkit::unavailable!(return false; "LR_SCALE_TESTS != 1 (cargo xtask scale)");
}

/// Run the CLI with `args` and measure its peak RSS and duration.
///
/// The child starts in this process's address space (`posix_spawn` shares it
/// until `exec`), and the kernel carries that address space's high-water mark
/// into the child's `ru_maxrss`. A test must therefore never hold a large
/// buffer of its own, or every later measurement reports at least that peak.
// The child is reaped by `wait4` in `lr_unsafe::wait_with_peak_rss`, which
// clippy cannot see.
#[allow(clippy::zombie_processes)]
fn measure(what: &str, args: &[&str]) -> Run {
    let started = Instant::now();
    // No daemon: the engine itself runs in the measured process.
    let mut child = Command::new(CLI)
        .args(["--socket", "/nonexistent/lr-scale.sock"])
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start the CLI");
    // The pipes are read on their own threads so the child never blocks.
    let mut stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let out = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = std::io::Read::read_to_string(&mut stdout, &mut text);
        text
    });
    let err = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = std::io::Read::read_to_string(&mut stderr, &mut text);
        text
    });
    // The exact peak, from the kernel's accounting when the child is reaped.
    let (raw_status, peak_kib) = lr_unsafe::wait_with_peak_rss(child.id()).expect("wait4");
    let status = std::os::unix::process::ExitStatusExt::from_raw(raw_status);
    let status: std::process::ExitStatus = status;
    let stdout = out.join().unwrap_or_default();
    let stderr = err.join().unwrap_or_default();
    assert!(status.success(), "{what} failed:\n{stdout}\n{stderr}");
    let run = Run {
        peak_mib: peak_kib.div_ceil(1024),
        seconds: started.elapsed().as_secs_f64(),
        stdout,
    };
    eprintln!(
        "SCALE {what}: peak RSS {} MiB, {:.1} s",
        run.peak_mib, run.seconds
    );
    run
}

/// The `image_path` of a JSON report on stdout.
fn image_path(run: &Run) -> String {
    let start = run.stdout.find('{').expect("a JSON report");
    let end = run.stdout.rfind('}').expect("a JSON report");
    let report: serde_json::Value =
        serde_json::from_str(&run.stdout[start..=end]).expect("report JSON");
    report["image_path"]
        .as_str()
        .expect("image_path")
        .to_owned()
}

fn backup(what: &str, source: &Path, dest: &Path, member: &str) -> Run {
    let source = source.display().to_string();
    let dest = dest.display().to_string();
    let mut args = vec![
        "backup",
        "create",
        "--mode",
        "file",
        "--source",
        &source,
        "--dest",
        &dest,
        "--set",
        "scale",
        "--no-encrypt",
        "--type",
        member,
        "--json",
    ];
    if member != "full" {
        args.extend(["--parent", "latest"]);
    }
    measure(what, &args)
}

/// Prepare and apply a restore to `target`, a directory or an image file
/// that already exists; both steps are held to `budget_mib`.
fn restore(what: &str, image: &str, target: &Path, budget_mib: u64) -> Run {
    let target = target.display().to_string();
    let plan = measure(
        &format!("{what} (prepare)"),
        &["restore", "prepare", "--image", image, "--target", &target],
    );
    assert_budget(&plan, &format!("{what} (prepare)"), budget_mib);
    let token = plan
        .stdout
        .lines()
        .find_map(|line| line.strip_prefix("token: "))
        .expect("a token")
        .to_owned();
    measure(
        what,
        &["restore", "apply", "--token", &token, "--confirm", "--json"],
    )
}

fn assert_budget(run: &Run, what: &str, budget_mib: u64) {
    assert!(
        run.peak_mib <= budget_mib,
        "{what} peaked at {} MiB; its budget is {budget_mib} MiB (docs/performance.md)",
        run.peak_mib
    );
}

fn scratch() -> tempfile::TempDir {
    // Large trees go to the disk-backed temporary directory, not a tmpfs.
    let base = std::env::var_os("LR_SCALE_DIR").map_or_else(std::env::temp_dir, PathBuf::from);
    tempfile::tempdir_in(base).expect("scratch directory")
}

/// A million small files in a thousand directories: backup, an unchanged
/// incremental and a restore stay within their budgets.
#[test]
#[ignore = "scale profile: LR_SCALE_TESTS=1 (cargo xtask scale)"]
fn a_million_file_tree() {
    if !enabled() {
        return;
    }
    let dir = scratch();
    let source = dir.path().join("tree");
    for directory in 0..1000 {
        let path = source.join(format!("d{directory:03}"));
        std::fs::create_dir_all(&path).expect("dir");
        for file in 0..1000 {
            std::fs::write(
                path.join(format!("file-{file:04}.txt")),
                format!("{directory}/{file}\n"),
            )
            .expect("file");
        }
    }
    let dest = dir.path().join("backups");
    let full = backup("1M files: full", &source, &dest, "full");
    // Budgets: the measured peak (docs/performance.md) plus headroom.
    assert_budget(&full, "1M files: full", 1024);
    let incremental = backup(
        "1M files: unchanged incremental",
        &source,
        &dest,
        "incremental",
    );
    assert_budget(&incremental, "1M files: unchanged incremental", 1536);
    std::fs::create_dir_all(dir.path().join("restored")).expect("target");
    let restored = restore(
        "1M files: restore",
        &image_path(&incremental),
        &dir.path().join("restored"),
        1280,
    );
    assert_budget(&restored, "1M files: restore", 1280);
    assert!(
        dir.path().join("restored/d999/file-0999.txt").exists(),
        "the last file was restored"
    );
}

/// A hundred thousand files with eight 400-byte xattrs each (about 320 MB
/// of xattr values; ext4 keeps a file's xattrs in one 4 KiB block, so the
/// set per file is bounded): backup and restore stay within their budgets
/// and the xattrs come back.
#[test]
#[ignore = "scale profile: LR_SCALE_TESTS=1 (cargo xtask scale)"]
fn large_xattr_sets() {
    if !enabled() {
        return;
    }
    let dir = scratch();
    let source = dir.path().join("tree");
    std::fs::create_dir_all(&source).expect("tree");
    for file in 0..100_000 {
        let path = source.join(format!("x{file:06}"));
        std::fs::write(&path, b"x").expect("file");
        for attribute in 0..8u8 {
            let name = format!("user.lr-scale-{attribute:02}");
            let value = vec![attribute; 400];
            match lr_unsafe::filemeta::set_xattr(&path, name.as_bytes(), &value) {
                Ok(()) => {}
                // EOPNOTSUPP: this filesystem has no user xattrs.
                Err(error) if error.raw_os_error() == Some(95) => {
                    lr_testkit::unavailable!("user xattrs are not supported here: {error}");
                }
                Err(error) => lr_testkit::fixture_failed!("setting an xattr failed: {error}"),
            }
        }
    }
    let dest = dir.path().join("backups");
    let full = backup("xattrs: full", &source, &dest, "full");
    assert_budget(&full, "xattrs: full", 640);
    std::fs::create_dir_all(dir.path().join("restored")).expect("target");
    let restored = restore(
        "xattrs: restore",
        &image_path(&full),
        &dir.path().join("restored"),
        1024,
    );
    assert_budget(&restored, "xattrs: restore", 1024);
    let back =
        lr_unsafe::filemeta::get_xattr(&dir.path().join("restored/x099999"), b"user.lr-scale-07")
            .expect("xattr");
    assert_eq!(back, vec![7u8; 400]);
}

/// A chain of one full and 199 incrementals, each changing a few files:
/// the newest member restores within its budget, whatever the chain length.
#[test]
#[ignore = "scale profile: LR_SCALE_TESTS=1 (cargo xtask scale)"]
fn a_long_chain() {
    if !enabled() {
        return;
    }
    let dir = scratch();
    let source = dir.path().join("tree");
    std::fs::create_dir_all(&source).expect("tree");
    for file in 0..2000 {
        std::fs::write(source.join(format!("f{file:04}")), vec![b'a'; 4096]).expect("file");
    }
    let dest = dir.path().join("backups");
    let mut last = backup("chain: full", &source, &dest, "full");
    let mut peak = last.peak_mib;
    for member in 1..200 {
        std::fs::write(
            source.join(format!("f{:04}", member % 2000)),
            format!("changed in member {member}\n"),
        )
        .expect("change");
        last = backup_quiet(&source, &dest);
        peak = peak.max(last.peak_mib);
    }
    eprintln!("SCALE chain: 199 incrementals, peak RSS {peak} MiB");
    assert!(
        peak <= 64,
        "an incremental of a long chain peaked at {peak} MiB; its budget is 64 MiB"
    );
    std::fs::create_dir_all(dir.path().join("restored")).expect("target");
    let restored = restore(
        "chain: restore of member 200",
        &image_path(&last),
        &dir.path().join("restored"),
        64,
    );
    assert_budget(&restored, "chain: restore of member 200", 64);
    assert_eq!(
        std::fs::read_to_string(dir.path().join("restored/f0199")).expect("file"),
        "changed in member 199\n"
    );
}

/// An incremental without its own log line.
fn backup_quiet(source: &Path, dest: &Path) -> Run {
    let source = source.display().to_string();
    let dest = dest.display().to_string();
    let args = [
        "backup",
        "create",
        "--mode",
        "file",
        "--source",
        &source,
        "--dest",
        &dest,
        "--set",
        "scale",
        "--no-encrypt",
        "--type",
        "incremental",
        "--parent",
        "latest",
        "--json",
    ];
    measure("chain: incremental", &args)
}

const MIB: u64 = 1024 * 1024;
/// The whole-disk profile's disk: 256 MiB of GPT with a BIOS boot partition
/// at 1 MiB, an ESP at 2 MiB and a data partition from 34 MiB to the end.
const DISK_SIZE: u64 = 256 * MIB;
const ESP_START: u64 = 2 * MIB;
const ESP_SIZE: u64 = 32 * MIB;
const DATA_START: u64 = 34 * MIB;

/// Whether `program` can be started.
fn have(program: &str) -> bool {
    Command::new(program)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn write_at(path: &Path, offset: u64, bytes: &[u8]) {
    use std::os::unix::fs::FileExt;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .expect("open for writing");
    file.write_all_at(bytes, offset).expect("write");
}

/// A sparse file of `size` bytes.
fn sparse(path: &Path, size: u64) {
    std::fs::File::create(path)
        .expect("create")
        .set_len(size)
        .expect("size");
}

/// The GPT disk of the whole-disk profile: a BIOS boot partition, a FAT32
/// ESP and a data partition without a filesystem (copied whole) that holds
/// 64 MiB of data that never changes.
fn build_disk(path: &Path, scratch: &Path) -> bool {
    for tool in ["sgdisk", "mkfs.vfat"] {
        if !have(tool) {
            lr_testkit::unavailable!(return false; "{tool} missing");
        }
    }
    sparse(path, DISK_SIZE);
    let layout = Command::new("sgdisk")
        .args([
            "--clear",
            "-n",
            "1:2048:+1M",
            "-t",
            "1:ef02",
            "-n",
            &format!("2:{}:+32M", ESP_START / 512),
            "-t",
            "2:ef00",
            "-n",
            &format!("3:{}:0", DATA_START / 512),
            "-t",
            "3:8300",
        ])
        .arg(path)
        .stdout(Stdio::null())
        .status()
        .expect("sgdisk");
    if !layout.success() {
        lr_testkit::fixture_failed!("sgdisk failed");
    }
    let esp = scratch.join("esp.img");
    sparse(&esp, ESP_SIZE);
    let formatted = Command::new("mkfs.vfat")
        .args(["-F", "32", "-n", "ESP"])
        .arg(&esp)
        .stdout(Stdio::null())
        .status()
        .expect("mkfs.vfat");
    if !formatted.success() {
        lr_testkit::fixture_failed!("mkfs.vfat failed");
    }
    // Copied and generated a mebibyte at a time: a large buffer here would
    // raise the high-water mark that `measure` attributes to the CLI.
    let mut from = std::fs::File::open(&esp).expect("open the ESP");
    let mut to = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .expect("open the disk");
    std::io::Seek::seek(&mut to, std::io::SeekFrom::Start(ESP_START)).expect("seek");
    std::io::copy(&mut from, &mut to).expect("copy the ESP");
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut piece = vec![0u8; MIB as usize];
    for mebibyte in 0..64 {
        for word in piece.chunks_exact_mut(8) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            word.copy_from_slice(&state.to_le_bytes());
        }
        write_at(path, DATA_START + (8 + mebibyte) * MIB, &piece);
    }
    true
}

/// A whole-disk member of `disk`: its image URI and its peak RSS in MiB.
fn disk_backup(what: &str, disk: &Path, dest: &Path, member: &str) -> (String, u64) {
    let source = disk.display().to_string();
    let dest_arg = dest.display().to_string();
    let mut args = vec![
        "backup",
        "create",
        "--source",
        &source,
        "--dest",
        &dest_arg,
        "--set",
        "scale-disk",
        "--no-encrypt",
        "--type",
        member,
        "--json",
    ];
    if member != "full" {
        args.extend(["--parent", "latest"]);
    }
    let run = measure(what, &args);
    let path = PathBuf::from(image_path(&run));
    let path = if path.is_absolute() {
        path
    } else {
        dest.join(path)
    };
    (path.display().to_string(), run.peak_mib)
}

/// Whether two files hold the same bytes, read 1 MiB at a time.
fn same_bytes(left: &Path, right: &Path) -> bool {
    use std::io::Read;
    let mut left = std::fs::File::open(left).expect("open");
    let mut right = std::fs::File::open(right).expect("open");
    let mut a = vec![0u8; MIB as usize];
    let mut b = vec![0u8; MIB as usize];
    loop {
        let read = left.read(&mut a).expect("read");
        if read == 0 {
            return right.read(&mut b).expect("read") == 0;
        }
        if right.read_exact(&mut b[..read]).is_err() || a[..read] != b[..read] {
            return false;
        }
    }
}

/// A whole-disk chain of one full and 199 incrementals, each changing one
/// chunk of the data partition (D-142). Restoring or verifying the newest
/// member opens every member of the chain at once (`chain::DiskWalk`), so
/// the restore and `verify --chain` of member 200 are held to budgets, and
/// the restored disk must equal the source.
#[test]
#[ignore = "scale profile: LR_SCALE_TESTS=1 (cargo xtask scale)"]
fn a_long_whole_disk_chain() {
    if !enabled() {
        return;
    }
    let dir = scratch();
    let disk = dir.path().join("disk.img");
    if !build_disk(&disk, dir.path()) {
        return;
    }
    let dest = dir.path().join("backups");
    disk_backup("disk chain: full", &disk, &dest, "full");
    let mut last = String::new();
    let mut peak = 0;
    for member in 1..200u64 {
        let offset = DATA_START + 8 * MIB + (member % 64) * MIB + 4096;
        write_at(&disk, offset, format!("member {member}").as_bytes());
        let (image, member_peak) =
            disk_backup("disk chain: incremental", &disk, &dest, "incremental");
        last = image;
        peak = peak.max(member_peak);
    }
    eprintln!("SCALE disk chain: 199 incrementals, peak RSS {peak} MiB");
    assert!(
        peak <= 32,
        "an incremental of a long whole-disk chain peaked at {peak} MiB; its budget is 32 MiB"
    );

    let target = dir.path().join("restored.img");
    sparse(&target, DISK_SIZE);
    let restored = restore("disk chain: restore of member 200", &last, &target, 24);
    assert_budget(&restored, "disk chain: restore of member 200", 24);
    assert!(
        same_bytes(&disk, &target),
        "the restored disk differs from the source"
    );

    let verified = measure(
        "disk chain: verify --chain of member 200",
        &["verify", "--image", &last, "--chain", "--json"],
    );
    assert_budget(&verified, "disk chain: verify --chain of member 200", 18);
}
