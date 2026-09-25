//! `linuxreflect-daemon` — the root daemon (spec §I, Slice S11).
//!
//! Arguments are parsed by hand: the daemon has a handful of flags and should
//! not grow a CLI dependency for them.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lr_daemon::auth;
use lr_daemon::jobs::Jobs;
use lr_daemon::service::{DaemonService, PeerInterceptor};
use lr_daemon::{notify, socket};
use lr_proto::v1::linux_reflect_server::LinuxReflectServer;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Server;

/// How the daemon was started.
struct Args {
    socket: PathBuf,
    socket_group: Option<String>,
    create_group: bool,
    auth: Option<String>,
    dev_mode: bool,
    sd_notify: bool,
    /// Octal socket mode override (tests, containers).
    socket_mode: Option<u32>,
    token_secret_file: Option<PathBuf>,
    help: bool,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            socket: socket::default_path(),
            socket_group: Some(socket::DEFAULT_GROUP.to_owned()),
            create_group: true,
            auth: None,
            dev_mode: std::env::var("LR_DEV_MODE").is_ok_and(|value| value == "1"),
            sd_notify: true,
            socket_mode: None,
            token_secret_file: None,
            help: false,
        }
    }
}

impl Args {
    fn parse() -> Result<Self, String> {
        let mut args = Self::default();
        let mut argv = std::env::args().skip(1);
        while let Some(argument) = argv.next() {
            match argument.as_str() {
                "--socket" => {
                    args.socket = argv.next().ok_or("--socket needs a path")?.into();
                }
                "--socket-group" => {
                    args.socket_group = Some(argv.next().ok_or("--socket-group needs a name")?);
                }
                "--no-create-group" => args.create_group = false,
                "--socket-mode" => {
                    let value = argv.next().ok_or("--socket-mode needs an octal mode")?;
                    args.socket_mode = Some(
                        u32::from_str_radix(value.trim_start_matches("0o"), 8)
                            .map_err(|_| format!("`{value}` is not an octal mode"))?,
                    );
                }
                "--auth" => args.auth = Some(argv.next().ok_or("--auth needs a value")?),
                "--dev-mode" => args.dev_mode = true,
                "--token-secret-file" => {
                    args.token_secret_file = Some(
                        argv.next()
                            .ok_or("--token-secret-file needs a path")?
                            .into(),
                    );
                }
                "--sd-notify=no" | "--no-sd-notify" => args.sd_notify = false,
                "--sd-notify=yes" => args.sd_notify = true,
                "--help" | "-h" => args.help = true,
                other => return Err(format!("unknown argument `{other}`")),
            }
        }
        Ok(args)
    }

    fn usage() -> &'static str {
        "linuxreflect-daemon [--socket PATH] [--socket-group NAME] [--no-create-group]\n\
         \x20                    [--socket-mode OCTAL] [--auth static:<uid,...>] [--dev-mode]\n\
         \x20                    [--sd-notify=no] [--token-secret-file PATH]"
    }
}

fn main() -> ExitCode {
    let args = match Args::parse() {
        Ok(args) => args,
        Err(error) => {
            eprintln!("linuxreflect-daemon: {error}\n{}", Args::usage());
            return ExitCode::from(2);
        }
    };
    if args.help {
        println!("{}", Args::usage());
        return ExitCode::SUCCESS;
    }
    init_logging();
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("linuxreflect-daemon: {error}");
            ExitCode::FAILURE
        }
    }
}

fn init_logging() {
    use tracing_subscriber::prelude::*;
    let level = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_owned());
    let filter = tracing_subscriber::EnvFilter::new(level);
    let journald = std::path::Path::new("/run/systemd/journal/socket").exists();
    if journald {
        let layer = tracing_journald::layer().expect("journald socket");
        let _ = tracing_subscriber::registry()
            .with(filter)
            .with(layer)
            .try_init();
    } else {
        let _ = tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
            .try_init();
    }
}

/// Start the daemon and serve until the process is stopped.
fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(path) = &args.token_secret_file {
        lr_engine::restore::init_token_secret(path)?;
    }
    // The daemon owns the restore-token secret: creating it here (or reading
    // the one already on disk) is what makes a standalone CLI run's tokens
    // verify against the daemon's.
    let _ = lr_engine::restore::token_secret();

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let auth = auth::build(args.auth.as_deref(), args.dev_mode).await?;
        let jobs = Arc::new(Jobs::new());
        let (listener, origin) = socket::listen(
            &args.socket,
            args.socket_group.as_deref(),
            args.create_group,
            args.socket_mode,
        )
        .await?;
        tracing::info!(socket = %args.socket.display(), ?origin, "listening");

        let service = DaemonService::new(Arc::clone(&auth), Arc::clone(&jobs), args.dev_mode);
        if args.sd_notify && notify::send("READY=1")? {
            tracing::info!("systemd notified");
        }
        if args.sd_notify
            && let Some(interval) = notify::watchdog_interval()
        {
            spawn_watchdog(interval);
        }

        let incoming = UnixListenerStream::new(listener);
        Server::builder()
            .add_service(LinuxReflectServer::with_interceptor(
                service,
                PeerInterceptor,
            ))
            .serve_with_incoming(incoming)
            .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}

/// Send `WATCHDOG=1` at half the interval systemd asked for.
fn spawn_watchdog(interval: Duration) {
    tokio::spawn(async move {
        let started = Instant::now();
        loop {
            tokio::time::sleep(interval).await;
            let status = format!(
                "WATCHDOG=1\nSTATUS=serving for {}",
                started.elapsed().as_secs()
            );
            if let Err(error) = notify::send(&status) {
                tracing::warn!(%error, "watchdog notification failed");
            }
        }
    });
}
