//! `linuxreflect-session`: a user service that forwards daemon job events to
//! the desktop notification service (spec §K S14).
//!
//! The daemon runs as root and cannot post into a user's session (spec risk
//! R0-19), so this helper runs in the session (`systemd --user`) and watches
//! the daemon's event stream.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

/// Forward daemon job events to the desktop notification service.
#[derive(Debug, Parser)]
#[command(name = "linuxreflect-session", version)]
struct Cli {
    /// Daemon socket.
    #[arg(
        long,
        value_name = "PATH",
        default_value = "/run/linuxreflect/daemon.sock"
    )]
    socket: PathBuf,

    /// Session bus address; defaults to `$DBUS_SESSION_BUS_ADDRESS`.
    #[arg(long, value_name = "ADDRESS")]
    session_bus: Option<String>,

    /// Exit after this many notifications (tests).
    #[arg(long, value_name = "N")]
    events: Option<usize>,

    /// Increase logging verbosity.
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let level = match cli.verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level)),
        )
        .init();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("linuxreflect-session: cannot build a runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(lr_session::run(
        &cli.socket,
        cli.session_bus.as_deref(),
        cli.events,
    )) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("linuxreflect-session: {error}");
            ExitCode::FAILURE
        }
    }
}
