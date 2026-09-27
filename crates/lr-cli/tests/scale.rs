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

/// Prepare and apply a restore; both steps are held to `budget_mib`.
fn restore(what: &str, image: &str, target: &Path, budget_mib: u64) -> Run {
    std::fs::create_dir_all(target).expect("target");
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
