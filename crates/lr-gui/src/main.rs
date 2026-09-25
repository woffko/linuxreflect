//! `linuxreflect-gui`: the Slint GUI (spec §K S15).

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

/// LinuxReflect's graphical client.
#[derive(Debug, Parser)]
#[command(name = "linuxreflect-gui", version)]
struct Cli {
    /// Daemon socket.
    #[arg(
        long,
        value_name = "PATH",
        default_value = "/run/linuxreflect/daemon.sock"
    )]
    socket: PathBuf,

    /// Run an automation script instead of waiting for clicks (tests).
    #[arg(long, value_name = "PATH")]
    script: Option<PathBuf>,

    /// Quit after this many milliseconds (a smoke run).
    #[arg(long, value_name = "MS")]
    exit_after_ms: Option<u64>,

    /// Increase logging verbosity.
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let level = match cli.verbose {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level)),
        )
        .init();
    let options = lr_gui::GuiOptions {
        socket: cli.socket,
        script: cli.script,
        exit_after_ms: cli.exit_after_ms,
    };
    match lr_gui::run(options) {
        Ok(outcome) => {
            for line in &outcome.log {
                println!("{line}");
            }
            println!("script: {} step(s) done", outcome.steps);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("linuxreflect-gui: {error:#}");
            ExitCode::FAILURE
        }
    }
}
