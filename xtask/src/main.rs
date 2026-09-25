//! Build automation for the LinuxReflect workspace.
//!
//! Run with `cargo xtask <command>`. Commands grow with the slices; today it
//! provides the CI gate and the GPT fixture generator used by S2 tests.
#![forbid(unsafe_code)]

use std::path::Path;
use std::process::Command;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("ci") => ci(),
        Some("fixture") => fixture(args.next()),
        Some("help") | None => {
            println!(
                "xtask commands:\n  ci               run fmt/clippy/test/deny as CI does\n  fixture <path>   build the S2 GPT fixture image\n  help             show this message"
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
    run("cargo", &["test", "--workspace"])?;
    run("cargo", &["deny", "check"])?;
    run("cargo", &["audit"])?;
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
