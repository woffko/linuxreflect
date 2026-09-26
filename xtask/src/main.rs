//! Build automation for the LinuxReflect workspace.
//!
//! Run with `cargo xtask <command>`: the CI gate, the root acceptance run and
//! the GPT fixture generator used by S2 tests.
//!
//! Both test runs report *executed*, *ignored* and *unavailable* tests
//! separately (remediation plan R40): a test that could not run its scenario
//! records the reason through `lr-testkit` in `LR_UNAVAILABLE_LOG`, and is
//! never counted as a pass.
#![forbid(unsafe_code)]

use std::io::{BufRead as _, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("ci") => ci(),
        Some("root") => root(),
        Some("fixture") => fixture(args.next()),
        Some("help") | None => {
            println!(
                "xtask commands:\n  ci               run fmt/clippy/test/deny as CI does\n  root             run every root acceptance test binary (LR_ROOT_RUNNER prefixes the command, e.g. `wsl.exe -u root --`)\n  fixture <path>   build the S2 GPT fixture image\n  help             show this message"
            );
            Ok(())
        }
        Some(other) => anyhow::bail!("unknown xtask command '{other}' (try `cargo xtask help`)"),
    }
}

fn run(program: &str, args: &[&str]) -> anyhow::Result<()> {
    println!("+ {program} {}", args.join(" "));
    let status = Command::new(program).args(args).status()?;
    if !status.success() {
        anyhow::bail!("{program} {} failed with {status}", args.join(" "));
    }
    Ok(())
}

fn ci() -> anyhow::Result<()> {
    run("python3", &["tools/test_install_preflight.py"])?;
    run("cargo", &["fmt", "--all", "--", "--check"])?;
    run(
        "cargo",
        &[
            "clippy",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ],
    )?;
    let log = unavailable_log("ci")?;
    let mut tally = Tally::default();
    let mut command = Command::new("cargo");
    command
        .args(["test", "--workspace"])
        .env("LR_UNAVAILABLE_LOG", &log);
    let ok = run_counted(command, &mut tally)?;
    tally.report(&log);
    if !ok {
        anyhow::bail!("cargo test --workspace failed");
    }
    run("cargo", &["deny", "check"])?;
    run("cargo", &["audit"])?;
    Ok(())
}

/// Counts parsed from libtest's `test result:` lines.
#[derive(Default)]
struct Tally {
    passed: u64,
    failed: u64,
    ignored: u64,
}

impl Tally {
    fn add_line(&mut self, line: &str) {
        let Some(rest) = line.trim().strip_prefix("test result: ") else {
            return;
        };
        let number = |label: &str| -> u64 {
            rest.split(';')
                .find_map(|part| part.trim().strip_suffix(label))
                .and_then(|value| value.trim().rsplit(' ').next())
                .and_then(|value| value.parse().ok())
                .unwrap_or(0)
        };
        self.passed += number("passed");
        self.failed += number("failed");
        self.ignored += number("ignored");
    }

    /// Print the three counts and every unavailable scenario with its reason.
    fn report(&self, log: &Path) -> u64 {
        let reasons = std::fs::read_to_string(log).unwrap_or_default();
        let mut lines: Vec<&str> = reasons.lines().filter(|line| !line.is_empty()).collect();
        lines.sort_unstable();
        lines.dedup();
        println!();
        println!("== test accounting ==");
        println!(
            "executed:    {} ({} passed, {} failed)",
            self.passed + self.failed,
            self.passed,
            self.failed
        );
        println!("ignored:     {}", self.ignored);
        println!("unavailable: {}", lines.len());
        for line in &lines {
            println!("  - {}", line.replace('\t', ": "));
        }
        lines.len() as u64
    }
}

/// A fresh file for `lr-testkit` to record unavailable scenarios in.
fn unavailable_log(name: &str) -> anyhow::Result<PathBuf> {
    let dir = PathBuf::from("target");
    std::fs::create_dir_all(&dir)?;
    let log = std::fs::canonicalize(&dir)?.join(format!("lr-unavailable-{name}.log"));
    let _ = std::fs::remove_file(&log);
    std::fs::write(&log, "")?;
    Ok(log)
}

/// Run a test command, echoing its output and counting its results.
fn run_counted(mut command: Command, tally: &mut Tally) -> anyhow::Result<bool> {
    println!("+ {command:?}");
    let mut child = command.stdout(Stdio::piped()).spawn()?;
    let stdout = child.stdout.take().expect("piped stdout");
    for line in BufReader::new(stdout).lines() {
        let line = line?;
        println!("{line}");
        tally.add_line(&line);
    }
    Ok(child.wait()?.success())
}

/// Build and run every root acceptance test binary, one at a time, as root.
///
/// `LR_ROOT_RUNNER` is split on spaces and prefixed to each command, for
/// example `wsl.exe -u root --` or `sudo`; without it the binaries run
/// directly, which needs this process to be root. `LR_ALLOW_UNAVAILABLE=1`
/// is passed through for hosts that knowingly lack some tools.
fn root() -> anyhow::Result<()> {
    run("cargo", &["build", "--workspace"])?;
    // The rescue-media tests embed the static CLI.
    let musl = Command::new("cargo")
        .args([
            "build",
            "--release",
            "-p",
            "lr-cli",
            "--target",
            "x86_64-unknown-linux-musl",
        ])
        .env("CC_x86_64_unknown_linux_musl", "musl-gcc")
        .status()?;
    if musl.success() {
        let release = "target/x86_64-unknown-linux-musl/release";
        run(
            "strip",
            &[
                "-o",
                &format!("{release}/linuxreflect.stripped"),
                &format!("{release}/linuxreflect"),
            ],
        )?;
    }
    let built = Command::new("cargo")
        .args(["test", "--workspace", "--no-run"])
        .output()?;
    if !built.status.success() {
        anyhow::bail!(
            "building the tests failed:\n{}",
            String::from_utf8_lossy(&built.stderr)
        );
    }
    let mut binaries: Vec<String> = String::from_utf8_lossy(&built.stderr)
        .lines()
        .filter(|line| line.contains("tests/root_"))
        .filter_map(|line| {
            let start = line.rfind('(')? + 1;
            let end = line.rfind(')')?;
            Some(line[start..end].to_owned())
        })
        .collect();
    binaries.sort();
    binaries.dedup();
    if binaries.is_empty() {
        anyhow::bail!("no root test binaries were built");
    }

    let log = unavailable_log("root")?;
    let runner: Vec<String> = std::env::var("LR_ROOT_RUNNER")
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    let workspace = std::env::current_dir()?;
    let mut tally = Tally::default();
    let mut failed = Vec::new();
    for binary in &binaries {
        let path = workspace.join(binary);
        let mut argv: Vec<String> = runner.clone();
        argv.extend([
            "env".to_owned(),
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_owned(),
            "LR_ROOT_TESTS=1".to_owned(),
            format!("LR_UNAVAILABLE_LOG={}", log.display()),
        ]);
        if std::env::var("LR_ALLOW_UNAVAILABLE").as_deref() == Ok("1") {
            argv.push("LR_ALLOW_UNAVAILABLE=1".to_owned());
        }
        argv.push(path.display().to_string());
        argv.extend(["--ignored", "--nocapture", "--test-threads=1"].map(str::to_owned));
        let mut command = Command::new(&argv[0]);
        command.args(&argv[1..]);
        if !run_counted(command, &mut tally)? {
            failed.push(binary.clone());
        }
    }
    let unavailable = tally.report(&log);
    println!(
        "binaries:    {} run, {} failed",
        binaries.len(),
        failed.len()
    );
    for binary in &failed {
        println!("  - failed: {binary}");
    }
    if !failed.is_empty() || unavailable > 0 {
        anyhow::bail!("the root run is not clean");
    }
    Ok(())
}

/// Lay out a GPT fixture disk: ESP, BIOS boot, ext4 data, swap.
fn fixture(path: Option<String>) -> anyhow::Result<()> {
    let path = path.ok_or_else(|| anyhow::anyhow!("usage: cargo xtask fixture <path>"))?;
    let path = Path::new(&path);
    if path.exists() {
        anyhow::bail!("{} already exists; refusing to overwrite", path.display());
    }
    let size_mib = 128;
    let file = std::fs::File::create(path)?;
    file.set_len(size_mib * 1024 * 1024)?;
    drop(file);

    let path_str = path.display().to_string();
    run("sgdisk", &["--clear", &path_str])?;
    // 1 MiB alignment; sizes chosen to match the S2 acceptance criteria.
    run(
        "sgdisk",
        &[
            "-n",
            "1:2048:+16M",
            "-t",
            "1:ef00",
            "-c",
            "1:ESP",
            "-n",
            "2:0:+1M",
            "-t",
            "2:ef02",
            "-c",
            "2:BIOS",
            "-n",
            "3:0:+32M",
            "-t",
            "3:8300",
            "-c",
            "3:ROOT",
            "-n",
            "4:0:+16M",
            "-t",
            "4:8200",
            "-c",
            "4:SWAP",
            &path_str,
        ],
    )?;
    println!("wrote {size_mib} MiB GPT fixture to {path_str}");
    Ok(())
}
