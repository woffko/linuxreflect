//! `linuxreflect` — the LinuxReflect command-line client.
//!
//! Before the daemon exists (Slice S11) the CLI runs the engine in-process:
//! `backup create`, `restore prepare` and `restore apply` call the same engine
//! entry points the daemon will wrap over gRPC (D-018). Commands that belong to
//! later slices report the slice that will implement them.
#![forbid(unsafe_code)]

mod cli;
mod client;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, bail};
use clap::Parser;
use cli::{
    BackupCommand, BackupType, BadSectorChoice, Cli, Command, DaemonCommand, DiskCommand,
    ExportCommand, JobCommand, RestoreCommand, RetentionCommand, ScheduleCommand,
};
use lr_core::catalog::Catalog;
use lr_core::{Capabilities, discover_source};
use lr_engine::backup::BackupRequest;
use lr_engine::catalog as engine_catalog;

use lr_engine::restore::{ApplyRequest, PrepareRequest, apply_restore, prepare_restore};
use lr_engine::{ImageReport, backup_image};
use lr_export::BlockBackend;
use lr_store::{DestinationOptions, SetHandle};

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.verbose, cli.quiet);
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            let code = if err.downcast_ref::<NotImplemented>().is_some() {
                2
            } else {
                1
            };
            eprintln!("linuxreflect: {err:#}");
            ExitCode::from(code)
        }
    }
}

fn run(cli: &Cli) -> anyhow::Result<()> {
    match &cli.command {
        Command::Disk(DiskCommand::List { all }) => {
            disk_list(cli.json, *all, cli.socket.as_deref())
        }
        Command::Disk(DiskCommand::Map { device }) => {
            disk_map(cli.json, device, cli.socket.as_deref())
        }
        Command::Caps => caps(cli.json),
        Command::Backup(BackupCommand::Create {
            source,
            dest,
            set,
            r#type,
            chunk_size,
            compress,
            passphrase_file,
            no_encrypt,
            on_bad_sector,
            parent,
            break_stale_lock,
            identity,
            known_hosts,
            insecure_ignore_host_key,
            snapshot,
            allow_freeze,
            freeze_timeout,
            allow_inconsistent,
            lvm_cow_size,
            deadman_grace,
            mode,
            one_file_system,
            max_incrementals,
        }) => backup_create(
            cli.json,
            &BackupOptions {
                source,
                socket: cli.socket.as_deref(),
                dest,
                set,
                backup_type: *r#type,
                parent: parent.clone(),
                break_stale_lock: *break_stale_lock,
                identity: identity.as_deref(),
                known_hosts: known_hosts.as_deref(),
                insecure_ignore_host_key: *insecure_ignore_host_key,
                chunk_size,
                compress,
                passphrase_file: passphrase_file.as_deref(),
                no_encrypt: *no_encrypt,
                on_bad_sector: *on_bad_sector,
                snapshot: snapshot.map(|choice| snapshot_id(choice).to_owned()),
                allow_freeze: *allow_freeze,
                freeze_timeout: *freeze_timeout,
                allow_inconsistent: *allow_inconsistent,
                lvm_cow_size: lvm_cow_size.clone(),
                deadman_grace: *deadman_grace,
                mode: *mode,
                one_file_system: *one_file_system,
                max_incrementals: *max_incrementals,
            },
        ),
        Command::Restore(RestoreCommand::Prepare {
            image,
            target,
            passphrase_file,
            ttl,
            identity,
            known_hosts,
            insecure_ignore_host_key,
            merge,
        }) => restore_prepare(
            cli.json,
            image,
            target,
            passphrase_file.as_deref(),
            PrepareFlags {
                ttl: *ttl,
                merge: *merge,
            },
            &DestinationOptions {
                set_name: String::new(),
                identity: identity.clone(),
                known_hosts: known_hosts.clone(),
                insecure_ignore_host_key: *insecure_ignore_host_key,
            },
            cli.socket.as_deref(),
        ),
        Command::Retention(RetentionCommand::Apply {
            dest,
            set,
            keep_chains,
            dry_run,
            identity,
            known_hosts,
            insecure_ignore_host_key,
        }) => retention_apply(
            cli.json,
            dest,
            set,
            *keep_chains,
            *dry_run,
            &DestinationOptions {
                set_name: set.clone(),
                identity: identity.clone(),
                known_hosts: known_hosts.clone(),
                insecure_ignore_host_key: *insecure_ignore_host_key,
            },
            cli.socket.as_deref(),
        ),
        Command::Schedule(ScheduleCommand::Set {
            config,
            systemd_dir,
            dry_run,
        }) => schedule_set(
            cli.json,
            config.as_deref(),
            systemd_dir.as_deref(),
            *dry_run,
            cli.socket.as_deref(),
        ),
        Command::Schedule(ScheduleCommand::List { config }) => {
            schedule_list(cli.json, config.as_deref(), cli.socket.as_deref())
        }
        Command::Schedule(ScheduleCommand::Remove { job, systemd_dir }) => {
            schedule_remove(cli.json, job, systemd_dir.as_deref(), cli.socket.as_deref())
        }
        Command::Export(ExportCommand::Mount {
            image,
            at,
            kind,
            passphrase_file,
            identity,
            known_hosts,
            insecure_ignore_host_key,
        }) => export_mount(
            cli.json,
            image,
            at,
            *kind,
            passphrase_file.as_deref(),
            &DestinationOptions {
                set_name: String::new(),
                identity: identity.clone(),
                known_hosts: known_hosts.clone(),
                insecure_ignore_host_key: *insecure_ignore_host_key,
            },
            cli.socket.as_deref(),
        ),
        Command::Export(ExportCommand::Umount { at }) => {
            export_umount(cli.json, at, cli.socket.as_deref())
        }
        Command::Export(ExportCommand::List) => export_list(cli.json),
        Command::Export(ExportCommand::Serve {
            image,
            socket,
            passphrase_file,
            identity,
            known_hosts,
            insecure_ignore_host_key,
        }) => export_serve(
            image,
            socket,
            passphrase_file.as_deref(),
            &DestinationOptions {
                set_name: String::new(),
                identity: identity.clone(),
                known_hosts: known_hosts.clone(),
                insecure_ignore_host_key: *insecure_ignore_host_key,
            },
        ),
        Command::Restore(RestoreCommand::Mount {
            image,
            at,
            passphrase_file,
            identity,
            known_hosts,
            insecure_ignore_host_key,
        }) => restore_mount(
            image,
            at,
            passphrase_file.as_deref(),
            &DestinationOptions {
                set_name: String::new(),
                identity: identity.clone(),
                known_hosts: known_hosts.clone(),
                insecure_ignore_host_key: *insecure_ignore_host_key,
            },
        ),
        Command::Restore(RestoreCommand::Apply {
            token,
            confirm,
            accept_inconsistent,
            passphrase_file,
        }) => restore_apply(
            cli.json,
            token,
            *confirm,
            *accept_inconsistent,
            passphrase_file.as_deref(),
            cli.socket.as_deref(),
        ),
        Command::Probe {
            source,
            snapshot,
            mode,
        } => probe(cli.json, source, *snapshot, *mode, cli.socket.as_deref()),
        Command::Backup(BackupCommand::List {
            dest,
            set,
            identity,
            known_hosts,
            insecure_ignore_host_key,
        }) => backup_list(
            cli.json,
            dest,
            set.as_deref(),
            &DestinationOptions {
                set_name: set.clone().unwrap_or_default(),
                identity: identity.clone(),
                known_hosts: known_hosts.clone(),
                insecure_ignore_host_key: *insecure_ignore_host_key,
            },
            cli.socket.as_deref(),
        ),
        Command::Verify {
            image,
            chain,
            passphrase_file,
            identity,
            known_hosts,
            insecure_ignore_host_key,
        } => verify(
            cli.json,
            image,
            *chain,
            passphrase_file.as_deref(),
            &DestinationOptions {
                set_name: String::new(),
                identity: identity.clone(),
                known_hosts: known_hosts.clone(),
                insecure_ignore_host_key: *insecure_ignore_host_key,
            },
            cli.socket.as_deref(),
        ),
        Command::Catalog {
            dest,
            set,
            identity,
            known_hosts,
            insecure_ignore_host_key,
        } => catalog_rebuild(
            cli.json,
            dest,
            set,
            &DestinationOptions {
                set_name: set.clone(),
                identity: identity.clone(),
                known_hosts: known_hosts.clone(),
                insecure_ignore_host_key: *insecure_ignore_host_key,
            },
            cli.socket.as_deref(),
        ),
        Command::Daemon { command } => match command {
            DaemonCommand::Run { args } => daemon_run(args),
            DaemonCommand::Status => daemon_status(cli.json, cli.socket.as_deref()),
        },
        Command::Job { command } => match command {
            JobCommand::Get { job_id } => job_show(cli.json, cli.socket.as_deref(), job_id, false),
            JobCommand::Cancel { job_id } => {
                job_show(cli.json, cli.socket.as_deref(), job_id, true)
            }
        },
    }
}

/// `daemon run`: hand over to the daemon binary next to this executable.
fn daemon_run(args: &[String]) -> anyhow::Result<()> {
    let exe = std::env::current_exe().context("locating the CLI binary")?;
    let directory = exe.parent().context("the CLI binary has no directory")?;
    let candidate = directory.join("linuxreflect-daemon");
    if !candidate.exists() {
        bail!(
            "{} is not installed next to this binary; install the linuxreflect-daemon package",
            candidate.display()
        );
    }
    let status = std::process::Command::new(&candidate)
        .args(args)
        .status()
        .with_context(|| format!("running {}", candidate.display()))?;
    if status.success() {
        Ok(())
    } else {
        bail!("{} exited with {status}", candidate.display())
    }
}

/// `daemon status`: is a daemon answering?
fn daemon_status(json: bool, socket: Option<&Path>) -> anyhow::Result<()> {
    let path = client::socket_path(socket);
    let available = client::daemon_available(&path);
    let version = if available {
        client::Client::connect(&path)
            .ok()
            .and_then(|mut client| client.version().ok())
    } else {
        None
    };
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "socket": path.display().to_string(),
                "running": available,
                "version": version.as_ref().map(|version| version.daemon.clone()),
                "dev_mode": version.as_ref().map(|version| version.dev_mode),
            }))?
        );
        return Ok(());
    }
    println!("socket:  {}", path.display());
    match version {
        Some(version) => {
            println!(
                "running: yes (daemon {}, dev mode: {})",
                version.daemon, version.dev_mode
            );
        }
        None => println!("running: no"),
    }
    Ok(())
}

/// `job get|cancel`.
fn job_show(json: bool, socket: Option<&Path>, job_id: &str, cancel: bool) -> anyhow::Result<()> {
    let path = client::socket_path(socket);
    if !client::daemon_available(&path) {
        bail!("no daemon is running; jobs live in the daemon's memory");
    }
    let mut client = client::Client::connect(&path)?;
    let state = if cancel {
        client.cancel_job(job_id)?
    } else {
        client.get_job(job_id)?
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&state)?);
        return Ok(());
    }
    println!("job:   {}", state.job_id);
    println!("set:   {}", state.set);
    println!("state: {}", state.state);
    if let Some(progress) = &state.progress
        && let Some(lr_proto::v1::progress::Step::Failure(failure)) = &progress.step
    {
        println!("error: {}: {}", failure.code, failure.message);
    }
    Ok(())
}

/// Marker error for commands reserved for a later slice.
#[derive(Debug)]
struct NotImplemented(&'static str, &'static str);

impl std::fmt::Display for NotImplemented {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "`{}` is not implemented yet; it arrives in slice {}",
            self.0, self.1
        )
    }
}

impl std::error::Error for NotImplemented {}

fn snapshot_id(choice: cli::SnapshotChoice) -> &'static str {
    match choice {
        cli::SnapshotChoice::Auto => "auto",
        cli::SnapshotChoice::Btrfs => "btrfs",
        cli::SnapshotChoice::Lvm => "lvm",
        cli::SnapshotChoice::Freeze => "freeze",
        cli::SnapshotChoice::Offline => "offline",
        cli::SnapshotChoice::None => "none",
    }
}

fn init_tracing(verbose: u8, quiet: u8) {
    let level = match i32::from(verbose) - i32::from(quiet) {
        i32::MIN..=-1 => "error",
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

/// Everything `backup create` needs, so the handler keeps one argument.
struct BackupOptions<'a> {
    source: &'a Path,
    socket: Option<&'a Path>,
    dest: &'a str,
    set: &'a str,
    backup_type: BackupType,
    parent: Option<String>,
    break_stale_lock: bool,
    identity: Option<&'a Path>,
    known_hosts: Option<&'a Path>,
    insecure_ignore_host_key: bool,
    chunk_size: &'a str,
    compress: &'a str,
    passphrase_file: Option<&'a Path>,
    no_encrypt: bool,
    on_bad_sector: BadSectorChoice,
    snapshot: Option<String>,
    allow_freeze: bool,
    freeze_timeout: u64,
    allow_inconsistent: bool,
    lvm_cow_size: Option<String>,
    deadman_grace: u64,
    mode: cli::ModeChoice,
    one_file_system: bool,
    max_incrementals: u64,
}

/// Resolve `--mode`/`auto` to a concrete mode for the in-process path.
fn resolve_mode(mode: cli::ModeChoice, source: &Path) -> anyhow::Result<lr_engine::options::Mode> {
    let parsed = lr_engine::options::parse_mode(mode_id(mode))?;
    Ok(match parsed {
        lr_engine::options::Mode::Auto if source.is_dir() => lr_engine::options::Mode::File,
        other => other,
    })
}

/// A mode name for the daemon and the engine (spec §D.1).
fn mode_id(mode: cli::ModeChoice) -> &'static str {
    match mode {
        cli::ModeChoice::Auto => "auto",
        cli::ModeChoice::Block => "block",
        cli::ModeChoice::Stream => "stream",
        cli::ModeChoice::File => "file",
    }
}

fn backup_create(json: bool, options: &BackupOptions<'_>) -> anyhow::Result<()> {
    if let Some(mut client) = client_if_available(options.socket) {
        let spec = lr_proto::v1::BackupSpec {
            source: options.source.display().to_string(),
            dest: options.dest.to_owned(),
            set: options.set.to_owned(),
            member_type: match options.backup_type {
                BackupType::Full => "full",
                BackupType::Incremental => "incremental",
                BackupType::Differential => "differential",
            }
            .to_owned(),
            parent: options.parent.clone().unwrap_or_default(),
            mode: mode_id(options.mode).to_owned(),
            snapshot: options.snapshot.clone().unwrap_or_default(),
            compress: options.compress.to_owned(),
            no_encrypt: options.no_encrypt,
            passphrase_file: options
                .passphrase_file
                .map(|path| path.display().to_string())
                .unwrap_or_default(),
            on_bad_sector: match options.on_bad_sector {
                BadSectorChoice::Abort => "abort",
                BadSectorChoice::Record => "record",
            }
            .to_owned(),
            chunk_size: options.chunk_size.to_owned(),
            allow_freeze: options.allow_freeze,
            allow_inconsistent: options.allow_inconsistent,
            lvm_cow_size: options.lvm_cow_size.clone().unwrap_or_default(),
            identity: options
                .identity
                .map(|path| path.display().to_string())
                .unwrap_or_default(),
            known_hosts: options
                .known_hosts
                .map(|path| path.display().to_string())
                .unwrap_or_default(),
            insecure_ignore_host_key: options.insecure_ignore_host_key,
            max_incrementals: options.max_incrementals,
            ..lr_proto::v1::BackupSpec::default()
        };
        let summary = client.create_backup(spec, |progress| {
            if let Some(line) = client::progress_line(progress) {
                println!("{line}");
            }
        })?;
        if json {
            println!("{summary}");
        } else {
            print_json_report(&summary);
        }
        return Ok(());
    }
    let encryption =
        lr_engine::options::backup_encryption(options.no_encrypt, options.passphrase_file)?;
    let mut request = BackupRequest::new(options.source, options.dest, options.set, encryption)?;
    request.dest = options.dest.to_owned();
    request.dest_root = if options.dest.contains("://") {
        // A remote destination has no local path; the freeze provider is told
        // through `destination_options`/`snapshot_opts`.
        PathBuf::new()
    } else {
        PathBuf::from(options.dest)
    };
    request.destination_options = DestinationOptions {
        set_name: options.set.to_owned(),
        identity: options.identity.map(Path::to_path_buf),
        known_hosts: options.known_hosts.map(Path::to_path_buf),
        insecure_ignore_host_key: options.insecure_ignore_host_key,
    };
    if !options.dest.contains("://")
        && let Ok(facts) = lr_store::local_mount_facts(Path::new(options.dest))
        && !facts.is_mount
    {
        eprintln!(
            "note: {} is not a mount point; a network destination is normally a mounted path",
            options.dest
        );
    }
    request.member_type = match options.backup_type {
        BackupType::Full => lr_engine::backup::MemberType::Full,
        BackupType::Incremental => lr_engine::backup::MemberType::Incremental,
        BackupType::Differential => lr_engine::backup::MemberType::Differential,
    };
    request.parent = options.parent.clone();
    request.break_stale_lock = options.break_stale_lock;
    request.chunk_size = u32::try_from(lr_engine::options::parse_size(options.chunk_size)?)
        .context("chunk size does not fit in 32 bits")?;
    request.compression = lr_engine::options::parse_compression(options.compress)?;
    request.on_bad_sector = match options.on_bad_sector {
        BadSectorChoice::Abort => lr_engine::backup::BadSectorPolicy::Abort,
        BadSectorChoice::Record => lr_engine::backup::BadSectorPolicy::Record,
    };
    request.snapshot_provider = options.snapshot.clone().filter(|name| name != "auto");
    request.allow_freeze = options.allow_freeze;
    request.freeze_timeout_secs = Some(options.freeze_timeout);
    request.allow_inconsistent = options.allow_inconsistent;
    request.lvm_cow_size = options.lvm_cow_size.clone();
    request.deadman_grace_secs = Some(options.deadman_grace);
    request.max_incrementals_per_chain =
        (options.max_incrementals > 0).then_some(options.max_incrementals);

    let report = match resolve_mode(options.mode, options.source)? {
        lr_engine::options::Mode::File => {
            let file_options = lr_engine::file::FileBackupOptions {
                one_file_system: options.one_file_system,
                ..lr_engine::file::FileBackupOptions::default()
            };
            lr_engine::backup::ImageReport::File(lr_engine::file::backup_file(
                &request,
                &file_options,
            )?)
        }
        _ => backup_image(&request)?,
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    match &report {
        ImageReport::Block(report) => {
            println!("mode:        block");
            println!("image:       {}", report.image_uri);
            println!("image uuid:  {}", report.image_uuid);
            println!("chain:       {}", report.chain_id);
            println!(
                "source:      {} ({} bytes, {})",
                options.source.display(),
                report.source_size_bytes,
                report.fs_type
            );
            println!("consistency: {}", report.consistency);
            println!(
                "member:      {} seq {}, parent {}",
                match report.member_kind {
                    lr_core::catalog::MemberKind::Full => "full",
                    lr_core::catalog::MemberKind::Incremental => "incremental",
                    lr_core::catalog::MemberKind::Differential => "differential",
                },
                report.seq_in_chain,
                report.parent_uuid
            );
            println!(
                "chunks:      {} total, {} stored, {} zero, {} bad",
                report.total_chunks, report.stored_chunks, report.zero_chunks, report.bad_chunks
            );
            if report.seq_in_chain > 0 {
                println!(
                    "changes:     {} changed, {} inherited from ancestors",
                    report.changed_chunks, report.inherited_chunks
                );
            }
            println!(
                "image size:  {} bytes ({} used, {} imaged of {} source bytes)",
                report.image_bytes,
                report.used_bytes,
                report.imaged_bytes,
                report.source_size_bytes
            );
            if !report.map_complete {
                println!(
                    "note:        no used-block map for this filesystem; the whole device was read"
                );
            }
            if report.consistency == lr_core::Consistency::None {
                println!(
                    "warning:     the image is inconsistent; restoring it needs --accept-inconsistent"
                );
            }
            if !report.encrypted {
                println!("note:        image is not encrypted and not tamper-evident");
            }
        }
        ImageReport::WholeDisk(report) => {
            println!("mode:        whole-disk");
            println!(
                "image:       {}/{}",
                options.dest.trim_end_matches('/'),
                report.image_path.display()
            );
            println!("image uuid:  {}", report.image_uuid);
            println!(
                "source:      {} ({} bytes, partition table {})",
                options.source.display(),
                report.disk_size_bytes,
                report.pt_type
            );
            println!(
                "image size:  {} bytes, leading region {} bytes, {} stored chunks",
                report.image_bytes,
                report.leading_bytes,
                report.stored_chunks()
            );
            println!("regions:");
            for region in &report.regions {
                let mapping = if region.map_backed { "used-map" } else { "raw" };
                println!(
                    "  #{} {:<15} lba {:<10} {:>10} bytes  {:<8} {:<9} {} ({} stored, {} zero, {} bad)",
                    region.index,
                    region.kind,
                    region.start_lba,
                    region.size_bytes,
                    region.fs_type,
                    mapping,
                    region.consistency,
                    region.stored_chunks,
                    region.zero_chunks,
                    region.bad_chunks
                );
            }
            if !report.encrypted {
                println!("note:        image is not encrypted and not tamper-evident");
            }
        }
        ImageReport::File(report) => {
            println!("mode:        file");
            println!("image:       {}", report.image_path.display());
            println!("image uuid:  {}", report.image_uuid);
            println!("consistency: {}", report.consistency);
            println!(
                "entries:     {} files, {} directories, {} symlinks, {} hard links, {} special",
                report.files,
                report.directories,
                report.symlinks,
                report.hardlinks,
                report.specials
            );
            if report.unchanged_files > 0 {
                println!(
                    "inherited:   {} files unchanged since the parent",
                    report.unchanged_files
                );
            }
            println!(
                "chunks:      {} stored, {} deduplicated",
                report.stored_chunks, report.deduplicated_chunks
            );
            println!("bytes:       {}", report.image_bytes);
            for warning in &report.warnings {
                println!("warning:     {warning}");
            }
        }
        ImageReport::Stream(report) => {
            println!("mode:        stream");
            println!(
                "image:       {}/{}",
                options.dest.trim_end_matches('/'),
                report.image_path.display()
            );
            println!("image uuid:  {}", report.image_uuid);
            println!(
                "source:      {} (btrfs {}, label '{}')",
                options.source.display(),
                report.fs_uuid,
                report.label
            );
            println!("consistency: {}", report.consistency);
            println!(
                "member:      {} seq {}, parent {}",
                match report.member_kind {
                    lr_core::catalog::MemberKind::Full => "full",
                    lr_core::catalog::MemberKind::Incremental => "incremental",
                    lr_core::catalog::MemberKind::Differential => "differential",
                },
                report.seq_in_chain,
                report.parent_uuid
            );
            println!(
                "streams:     {} subvolume(s), {} send bytes",
                report.subvolumes.len(),
                report.send_stream_bytes
            );
            for subvol in &report.subvolumes {
                let mode = if subvol.parent_snapshot_uuid.is_some() {
                    "incremental"
                } else {
                    "full"
                };
                println!(
                    "  {:<24} subvolid {:<8} {:>10} bytes  {:<11} {} chunks ({} stored)",
                    subvol.subvol_path,
                    subvol.subvolid,
                    subvol.send_stream_bytes,
                    mode,
                    subvol.chunks,
                    subvol.stored_chunks
                );
            }
            println!(
                "chunks:      {} total, {} stored, {} deduplicated",
                report.total_chunks, report.stored_chunks, report.deduplicated_chunks
            );
            println!("image size:  {} bytes", report.image_bytes);
            if !report.encrypted {
                println!("note:        image is not encrypted and not tamper-evident");
            }
        }
    }
    Ok(())
}

/// Open a destination and its set.
fn open_set(
    dest: &str,
    options: &DestinationOptions,
) -> anyhow::Result<(std::sync::Arc<dyn lr_store::Destination>, SetHandle)> {
    let destination = lr_store::open(dest, options).with_context(|| format!("opening {dest}"))?;
    let handle = destination
        .open_set(&lr_core::SetId::ZERO)
        .with_context(|| format!("opening the set '{}'", options.set_name))?;
    Ok((destination, handle))
}

/// Load one set's catalog, validating it against the member superblocks.
fn load_set_catalog(
    dest: &str,
    set_name: &str,
    options: &DestinationOptions,
) -> anyhow::Result<(Catalog, Vec<String>)> {
    let (destination, handle) = open_set(dest, options)?;
    let loaded = engine_catalog::load(
        &*destination,
        &handle,
        set_name,
        lr_engine::backup::now_unix(),
    )
    .with_context(|| format!("reading the catalog of set '{set_name}'"))?;
    Ok((loaded.catalog, loaded.warnings))
}

/// `verify`: structural and content verification of an image (spec §G.8).
fn verify(
    json: bool,
    image: &str,
    chain: bool,
    passphrase_file: Option<&Path>,
    options: &DestinationOptions,
    socket: Option<&Path>,
) -> anyhow::Result<()> {
    if let Some(mut client) = client_if_available(socket) {
        let spec = lr_proto::v1::VerifySpec {
            image: image.to_owned(),
            chain,
            passphrase_file: passphrase_file
                .map(|path| path.display().to_string())
                .unwrap_or_default(),
            identity: options
                .identity
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_default(),
            known_hosts: options
                .known_hosts
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_default(),
            insecure_ignore_host_key: options.insecure_ignore_host_key,
        };
        let summary = client.verify_image(spec, |progress| {
            if let Some(line) = client::progress_line(progress) {
                println!("{line}");
            }
        })?;
        if json {
            println!("{summary}");
        } else {
            print_json_report(&summary);
        }
        return Ok(());
    }
    let request = lr_engine::verify::VerifyRequest {
        image: image.to_owned(),
        encryption: lr_engine::options::restore_encryption(passphrase_file)?,
        chain,
        destination_options: options.clone(),
        context: lr_engine::progress::EngineContext::silent(),
    };
    let report = lr_engine::verify::verify_image(&request)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    println!("verified:    {}", report.image_uri);
    println!("kind:        {:?}", report.image_kind);
    println!("members:     {}", report.members);
    println!("pages:       {}", report.pages);
    println!("chunks:      {}", report.chunks);
    println!("bytes:       {}", report.bytes_checked);
    for warning in &report.warnings {
        eprintln!("warning: {warning}");
    }
    Ok(())
}

/// `backup list`: chains and members from the validated catalog.
fn backup_list(
    json: bool,
    dest: &str,
    set: Option<&str>,
    options: &DestinationOptions,
    socket: Option<&Path>,
) -> anyhow::Result<()> {
    if let Some(set_name) = set
        && let Some(mut client) = client_if_available(socket)
    {
        let info = client.list_sets(dest, set_name)?;
        if json {
            println!("{}", serde_json::to_string_pretty(&info)?);
            return Ok(());
        }
        println!("set:   {}", info.set);
        for chain in &info.chains {
            println!(
                "  chain {}: {} member(s), created {}, {}",
                chain.chain_id,
                chain.members.len(),
                chain.created_unix,
                if chain.complete {
                    "complete"
                } else {
                    "INCOMPLETE"
                }
            );
            for member in &chain.members {
                println!(
                    "    {:>3} {:<13} {} parent {} {} bytes  {}",
                    member.seq_in_chain,
                    member.kind,
                    member.image_uuid,
                    member.parent_uuid,
                    member.size_bytes,
                    member.file_name
                );
            }
        }
        for warning in &info.warnings {
            println!("  warning: {warning}");
        }
        return Ok(());
    }
    if set.is_none() && client_if_available(socket).is_some() {
        bail!("listing every set needs a local destination; pass --set for a daemon");
    }
    let names: Vec<String> = match set {
        Some(name) => vec![name.to_owned()],
        None => {
            if !options.set_name.is_empty() {
                bail!("an sftp destination needs --set");
            }
            let mut found = Vec::new();
            for entry in std::fs::read_dir(dest).with_context(|| format!("listing {dest}"))? {
                let entry = entry?;
                if entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false) {
                    found.push(entry.file_name().to_string_lossy().into_owned());
                }
            }
            found.sort();
            found
        }
    };

    let mut sets = Vec::new();
    for name in &names {
        let mut options = options.clone();
        options.set_name.clone_from(name);
        let (catalog, warnings) = load_set_catalog(dest, name, &options)?;
        sets.push((name.clone(), catalog, warnings));
    }

    if json {
        let value = serde_json::json!({
            "dest": dest,
            "sets": sets
                .iter()
                .map(|(name, catalog, warnings)| serde_json::json!({
                    "set": name,
                    "catalog": catalog,
                    "warnings": warnings,
                }))
                .collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }

    for (name, catalog, warnings) in &sets {
        println!("set:   {name}");
        if catalog.chains.is_empty() {
            println!("  (no chains)");
        }
        for chain in catalog.chains_oldest_first() {
            println!(
                "  chain {}: {} member(s), created {}, {}",
                chain.chain_id,
                chain.members.len(),
                chain.created_unix,
                if chain.is_complete() {
                    "complete"
                } else {
                    "INCOMPLETE"
                }
            );
            let mut members = chain.members.clone();
            members.sort_by_key(|member| member.seq_in_chain);
            for member in members {
                println!(
                    "    {:>3} {:<13} {} parent {} {} bytes  {}",
                    member.seq_in_chain,
                    format!("{:?}", member.kind).to_lowercase(),
                    member.image_uuid,
                    member.parent_uuid,
                    member.size_bytes,
                    member.file_name
                );
            }
        }
        for warning in warnings {
            println!("  warning: {warning}");
        }
    }
    Ok(())
}

/// `catalog rebuild`: validate from the superblocks and write `catalog.json`.
fn catalog_rebuild(
    json: bool,
    dest: &str,
    set: &str,
    options: &DestinationOptions,
    socket: Option<&Path>,
) -> anyhow::Result<()> {
    if let Some(mut client) = client_if_available(socket) {
        let progress = client.rebuild_catalog(dest, set)?;
        if json {
            println!("{}", serde_json::to_string_pretty(&progress)?);
            return Ok(());
        }
        if let Some(lr_proto::v1::progress::Step::Finished(finished)) = progress.step {
            println!("set:     {set}");
            print_json_report(&finished.summary_json);
        }
        return Ok(());
    }
    let (catalog, warnings) = load_set_catalog(dest, set, options)?;
    let (destination, handle) = open_set(dest, options)?;
    engine_catalog::write_catalog(&*destination, &handle, &catalog)
        .context("writing catalog.json")?;

    let members: usize = catalog.chains.iter().map(|chain| chain.members.len()).sum();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "set": set,
                "chains": catalog.chains.len(),
                "members": members,
                "catalog": catalog,
                "warnings": warnings,
            }))?
        );
        return Ok(());
    }
    println!(
        "set:     {set}\nchains:  {}\nmembers: {members}\nwritten: {}/catalog.json",
        catalog.chains.len(),
        handle.path.trim_end_matches('/'),
    );
    for warning in &warnings {
        println!("warning: {warning}");
    }
    Ok(())
}

/// `probe`: print the snapshot plan without touching the source.
fn probe(
    json: bool,
    source: &Path,
    snapshot: cli::SnapshotChoice,
    _mode: cli::ModeChoice,
    socket: Option<&Path>,
) -> anyhow::Result<()> {
    if let Some(mut client) = client_if_available(socket) {
        let plan = client.probe(source)?;
        if json {
            println!("{}", serde_json::to_string_pretty(&plan)?);
            return Ok(());
        }
        println!("source:      {}", source.display());
        println!("provider:    {}", plan.provider);
        println!("mode:        {}", plan.image_kind);
        println!("consistency: {}", plan.consistency);
        println!(
            "estimated:   {} bytes ({})",
            plan.estimated_bytes,
            lr_engine::inspect::human_size(plan.estimated_bytes)
        );
        for warning in &plan.warnings {
            println!("warning:     {warning}");
        }
        return Ok(());
    }
    if source.is_dir() {
        // File mode: the source is a directory tree (spec §D.1, §K S12).
        let walk = lr_engine::tree::walk(
            source,
            &lr_engine::tree::WalkOptions::with_default_excludes(),
        )
        .with_context(|| format!("probing {}", source.display()))?;
        let plan = serde_json::json!({
            "provider": "file",
            "image_kind": "file",
            "consistency": lr_core::Consistency::PerFile.to_string(),
            "estimated_bytes": walk.total_bytes,
            "warnings": walk.warnings,
        });
        if json {
            println!("{}", serde_json::to_string_pretty(&plan)?);
            return Ok(());
        }
        println!("source:      {}", source.display());
        println!("provider:    file");
        println!("image kind:  File");
        println!("consistency: {}", lr_core::Consistency::PerFile);
        println!(
            "estimated:   {} bytes ({})",
            walk.total_bytes,
            lr_engine::inspect::human_size(walk.total_bytes)
        );
        for warning in &walk.warnings {
            println!("warning:     {warning}");
        }
        return Ok(());
    }
    let layout =
        discover_source(source).with_context(|| format!("probing {}", source.display()))?;
    let options = lr_core::SnapshotOpts {
        provider: Some(snapshot_id(snapshot).to_owned()).filter(|name| name != "auto"),
        destination: None,
        ..lr_core::SnapshotOpts::default()
    };
    let plan = lr_snapshot::probe_source(&layout, &options)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&plan)?);
        return Ok(());
    }
    println!("source:      {}", source.display());
    println!("provider:    {}", plan.provider);
    println!("image kind:  {:?}", plan.image_kind);
    println!("consistency: {}", plan.consistency);
    if let Some(path) = &plan.block_path {
        println!("read from:   {}", path.display());
    }
    println!(
        "estimated:   {} bytes ({})",
        plan.estimated_bytes,
        lr_engine::inspect::human_size(plan.estimated_bytes)
    );
    for warning in &plan.warnings {
        println!("warning:     {warning}");
    }
    Ok(())
}

/// Scalar knobs of `restore prepare` (the rest travels in `DestinationOptions`).
struct PrepareFlags {
    ttl: u64,
    merge: bool,
}

fn restore_prepare(
    json: bool,
    image: &str,
    target: &Path,
    passphrase_file: Option<&Path>,
    flags: PrepareFlags,
    options: &DestinationOptions,
    socket: Option<&Path>,
) -> anyhow::Result<()> {
    let PrepareFlags { ttl, merge } = flags;
    if ttl > lr_engine::DEFAULT_TTL.as_secs() {
        bail!(
            "token lifetime {ttl}s exceeds the {}s allowed by spec §H.2",
            lr_engine::DEFAULT_TTL.as_secs()
        );
    }
    let encryption = lr_engine::options::restore_encryption(passphrase_file)?;
    if let Some(mut client) = client_if_available(socket) {
        let plan = client.prepare_restore(lr_proto::v1::RestoreSpec {
            image: image.to_owned(),
            target: target.display().to_string(),
            passphrase_file: passphrase_file
                .map(|path| path.display().to_string())
                .unwrap_or_default(),
            identity: options
                .identity
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_default(),
            known_hosts: options
                .known_hosts
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_default(),
            insecure_ignore_host_key: options.insecure_ignore_host_key,
            ttl_secs: ttl,
            merge,
        })?;
        if json {
            println!("{}", serde_json::to_string_pretty(&plan)?);
            return Ok(());
        }
        println!("image:       {}/{}", plan.dest, plan.image);
        println!("image uuid:  {}", plan.image_uuid);
        println!("kind:        {}", plan.image_kind);
        println!("consistency: {}", plan.consistency);
        println!(
            "source:      {} bytes in {} byte chunks",
            plan.source_size_bytes, plan.chunk_size
        );
        println!(
            "target:      {} ({} bytes)",
            plan.target, plan.target_size_bytes
        );
        println!("members:     {}", plan.members.len());
        println!("encrypted:   {}", plan.encrypted);
        for warning in &plan.warnings {
            println!("warning:     {warning}");
        }
        println!();
        println!("token: {}", plan.token);
        println!();
        println!("apply with: linuxreflect restore apply --token <token> --confirm");
        return Ok(());
    }
    let mut request = PrepareRequest::new(image, target, encryption);
    request.identity.clone_from(&options.identity);
    request.known_hosts.clone_from(&options.known_hosts);
    request.insecure_ignore_host_key = options.insecure_ignore_host_key;
    request.merge = merge;
    request.ttl = std::time::Duration::from_secs(ttl);
    let plan = prepare_restore(&request)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&plan)?);
        return Ok(());
    }
    println!("image:       {}/{}", plan.dest, plan.image);
    println!("image uuid:  {}", plan.image_uuid);
    println!("kind:        {:?}", plan.image_kind);
    println!("consistency: {}", plan.consistency);
    println!(
        "source:      {} bytes in {} byte chunks",
        plan.source_size_bytes, plan.chunk_size
    );
    println!(
        "target:      {} ({} bytes)",
        plan.target.display(),
        plan.target_size_bytes
    );
    println!("encrypted:   {}", plan.encrypted);
    for warning in &plan.warnings {
        println!("warning:     {warning}");
    }
    println!();
    println!("token: {}", plan.token);
    println!();
    println!("apply with: linuxreflect restore apply --token <token> --confirm");
    Ok(())
}

/// `retention apply`: whole-chain deletion beyond `keep_chains` (spec §J.3).
fn retention_apply(
    json: bool,
    dest: &str,
    set: &str,
    keep_chains: usize,
    dry_run: bool,
    options: &DestinationOptions,
    socket: Option<&Path>,
) -> anyhow::Result<()> {
    if let Some(mut client) = client_if_available(socket) {
        let summary = client.apply_retention(
            dest,
            set,
            u32::try_from(keep_chains).unwrap_or(u32::MAX),
            dry_run,
        )?;
        let report: serde_json::Value = serde_json::from_str(&summary)?;
        if json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            print_retention(&report);
        }
        return Ok(());
    }
    let destination = lr_store::open(dest, options)?;
    let handle = destination.open_set(&lr_core::SetId::ZERO)?;
    let report = lr_engine::retention::apply(
        &*destination,
        &handle,
        set,
        &lr_engine::retention::RetentionOptions {
            keep_chains,
            dry_run,
            ..lr_engine::retention::RetentionOptions::default()
        },
    )?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    print_retention(&serde_json::to_value(&report)?);
    Ok(())
}

fn print_retention(report: &serde_json::Value) {
    if report.get("dry_run").and_then(serde_json::Value::as_bool) == Some(true) {
        println!("dry run: nothing was deleted");
    }
    println!(
        "set:         {} ({} complete chains)",
        report
            .get("set")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("-"),
        report
            .get("complete_chains")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
    );
    let kept = report
        .get("kept")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    println!("kept:        {} chain(s)", kept.len());
    for chain in &kept {
        println!("  {}", chain.as_str().unwrap_or("-"));
    }
    let deleted = report
        .get("deleted")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    println!("deleted:     {} chain(s)", deleted.len());
    for chain in &deleted {
        println!(
            "  {} ({} file(s), {} bytes, {})",
            chain
                .get("chain_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("-"),
            chain
                .get("files")
                .and_then(serde_json::Value::as_array)
                .map_or(0, Vec::len),
            chain
                .get("bytes")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
            chain
                .get("reason")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("-"),
        );
    }
}

/// `schedule set`: write the systemd units described by a config file (§J.4).
fn schedule_set(
    json: bool,
    config: Option<&Path>,
    systemd_dir: Option<&Path>,
    dry_run: bool,
    socket: Option<&Path>,
) -> anyhow::Result<()> {
    let config = config.unwrap_or(Path::new(lr_engine::schedule::DEFAULT_CONFIG));
    if let Some(mut client) = client_if_available(socket) {
        let summary = client.set_schedule(
            &config.display().to_string(),
            &systemd_dir
                .map(|dir| dir.display().to_string())
                .unwrap_or_default(),
            dry_run,
        )?;
        let report: serde_json::Value = serde_json::from_str(&summary)?;
        if json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            print_schedule(&report);
        }
        return Ok(());
    }
    let cli = std::env::current_exe().context("resolving the CLI path")?;
    let report =
        lr_engine::schedule::materialize(config, &cli, systemd_dir, dry_run, true, !dry_run)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    print_schedule(&serde_json::to_value(&report)?);
    Ok(())
}

fn print_schedule(report: &serde_json::Value) {
    let jobs = report
        .get("jobs")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    println!(
        "config:      {}",
        report
            .get("config")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("-")
    );
    println!(
        "units:       {}",
        report
            .get("systemd_dir")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("-")
    );
    println!("jobs:        {}", jobs.len());
    for job in &jobs {
        println!(
            "  {:<20} {} -> {}",
            job.get("job")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("-"),
            job.get("destination")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("-"),
            job.get("timer_name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("-"),
        );
    }
    if report.get("dry_run").and_then(serde_json::Value::as_bool) == Some(true) {
        println!("dry run: nothing was written");
    }
    if report.get("reloaded").and_then(serde_json::Value::as_bool) == Some(true) {
        println!("systemd:     daemon-reload done");
    }
    if report.get("started").and_then(serde_json::Value::as_bool) == Some(true) {
        println!("systemd:     timers enabled and started");
    }
    for warning in report
        .get("warnings")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        println!("warning:     {}", warning.as_str().unwrap_or("-"));
    }
}

fn schedule_list(json: bool, config: Option<&Path>, socket: Option<&Path>) -> anyhow::Result<()> {
    let config = config.unwrap_or(Path::new(lr_engine::schedule::DEFAULT_CONFIG));
    if let Some(mut client) = client_if_available(socket) {
        let summary = client.get_schedule(&config.display().to_string())?;
        let jobs: serde_json::Value = serde_json::from_str(&summary)?;
        if json {
            println!("{}", serde_json::to_string_pretty(&jobs)?);
        } else {
            print_schedule(&serde_json::json!({
                "config": config.display().to_string(),
                "jobs": jobs,
            }));
        }
        return Ok(());
    }
    let cli = std::env::current_exe().context("resolving the CLI path")?;
    let jobs = lr_engine::schedule::list(config, &cli)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&jobs)?);
        return Ok(());
    }
    print_schedule(&serde_json::json!({
        "config": config.display().to_string(),
        "systemd_dir": lr_engine::schedule::DEFAULT_SYSTEMD_DIR,
        "jobs": jobs,
    }));
    Ok(())
}

fn schedule_remove(
    json: bool,
    job: &str,
    systemd_dir: Option<&Path>,
    socket: Option<&Path>,
) -> anyhow::Result<()> {
    if let Some(mut client) = client_if_available(socket) {
        let summary = client.remove_schedule(
            job,
            &systemd_dir
                .map(|dir| dir.display().to_string())
                .unwrap_or_default(),
        )?;
        if json {
            let value: serde_json::Value = serde_json::from_str(&summary)?;
            println!("{}", serde_json::to_string_pretty(&value)?);
        } else {
            println!("removed {job}");
        }
        return Ok(());
    }
    let removed = lr_engine::schedule::remove(job, systemd_dir)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "job": job,
                "removed": removed,
            }))?
        );
        return Ok(());
    }
    println!("removed {job} ({} file(s))", removed.len());
    Ok(())
}

/// Turn an image URI into everything the export needs.
fn export_target(
    image: &str,
    passphrase_file: Option<&Path>,
    options: &DestinationOptions,
) -> anyhow::Result<(lr_engine::keys::Encryption, DestinationOptions, Vec<String>)> {
    let encryption = lr_engine::options::restore_encryption(passphrase_file)?;
    let (_, destination_options, images) = lr_export::session::resolve_image(image, options)?;
    Ok((encryption, destination_options, images))
}

/// Serve an image over NBD on a Unix socket until the process is stopped.
fn export_serve(
    image: &str,
    socket: &Path,
    passphrase_file: Option<&Path>,
    options: &DestinationOptions,
) -> anyhow::Result<()> {
    let (encryption, destination_options, images) = export_target(image, passphrase_file, options)?;
    let location = lr_store::uri::split_image(image)?;
    let backend =
        lr_export::ImageBackend::open(&location.dest, &images, &destination_options, &encryption)?;
    if backend.size_bytes() == 0 {
        bail!("the image has no content to export");
    }
    let _ = std::fs::remove_file(socket);
    if let Some(parent) = socket.parent() {
        std::fs::create_dir_all(parent)?;
    }
    eprintln!(
        "serving {} ({} bytes, {} stored chunks, fs {}) on {}",
        location.name,
        backend.size_bytes(),
        backend.stored_chunks(),
        backend.fs_type(),
        socket.display()
    );
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    lr_export::nbd::serve_unix(
        socket,
        std::sync::Arc::new(backend),
        lr_export::ExportConfig::default(),
        stop,
    )?;
    Ok(())
}

/// `export mount`: serve the image, attach it with NBD and mount it read-only.
fn export_mount(
    json: bool,
    image: &str,
    at: &Path,
    kind: cli::ExportKind,
    passphrase_file: Option<&Path>,
    options: &DestinationOptions,
    socket: Option<&Path>,
) -> anyhow::Result<()> {
    if let cli::ExportKind::Ublk = kind {
        bail!(
            "ublk is optional (spec §K S13) and this build has no ublk backend; \
             use --kind nbd"
        );
    }
    if let Some(mut client) = client_if_available(socket) {
        let summary = client.export_image(image, &at.display().to_string(), "nbd")?;
        if json {
            println!("{summary}");
        } else {
            print_json_report(&summary);
        }
        return Ok(());
    }
    let (nbd, mount) = lr_export::session::available();
    if !nbd || !mount {
        bail!("NBD export needs the nbd module, `nbd-client` and `mount`");
    }
    if std::fs::read_dir(at).map_or(true, |mut entries| entries.next().is_some()) {
        bail!("{} is not an empty directory", at.display());
    }
    let state_dir = Path::new(lr_export::session::STATE_DIR);
    std::fs::create_dir_all(state_dir)?;
    let socket_path = state_dir.join(format!("serve-{}.sock", std::process::id()));
    let exe = std::env::current_exe().context("resolving the CLI path")?;
    // The server must not inherit this process's stdout/stderr: a caller that
    // captures the CLI's pipes would wait for them to close, and the server
    // lives until `export umount`.
    let log_path = state_dir.join(format!("serve-{}.log", std::process::id()));
    let log = std::fs::File::create(&log_path).context("creating the serve log")?;
    let child = std::process::Command::new(exe)
        .args([
            "export",
            "serve",
            "--image",
            image,
            "--socket",
            &socket_path.display().to_string(),
        ])
        .args(
            passphrase_file
                .map(|path| vec!["--passphrase-file".to_owned(), path.display().to_string()])
                .unwrap_or_default(),
        )
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::from(log))
        .spawn()
        .context("starting the NBD server")?;
    let server_pid = child.id();

    let device = match wait_for_socket_and_device(&socket_path, server_pid) {
        Ok(device) => device,
        Err(error) => {
            let _ = std::process::Command::new("kill")
                .arg(server_pid.to_string())
                .status();
            return Err(error);
        }
    };
    // The filesystem type comes from the image itself, so the mount options
    // are the ones the spec prescribes for it.
    let (encryption, destination_options, images) = export_target(image, passphrase_file, options)?;
    let location = lr_store::uri::split_image(image)?;
    let backend =
        lr_export::ImageBackend::open(&location.dest, &images, &destination_options, &encryption)?;
    let fs_type = backend.fs_type().to_owned();
    drop(backend);

    let mount_options = match lr_export::session::mount_read_only(&device, at, &fs_type) {
        Ok(options) => options,
        Err(error) => {
            let _ = lr_export::session::detach(&device);
            let _ = std::process::Command::new("kill")
                .arg(server_pid.to_string())
                .status();
            return Err(error.into());
        }
    };
    let state = lr_export::session::ExportState {
        image: image.to_owned(),
        mountpoint: at.to_path_buf(),
        socket: socket_path,
        device: device.clone(),
        fs_type,
        mount_options: mount_options.clone(),
        server_pid,
        in_process: false,
    };
    lr_export::session::save_state(&state)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&state)?);
        return Ok(());
    }
    println!("image:       {image}");
    println!("device:      {}", device.display());
    println!("mount:       {}", at.display());
    println!("filesystem:  {}", state.fs_type);
    println!("options:     {}", mount_options.join(","));
    println!("read-only:   yes (spec §K S13)");
    println!();
    println!(
        "unmount with: linuxreflect export umount --at {}",
        at.display()
    );
    Ok(())
}

fn wait_for_socket_and_device(socket: &Path, server_pid: u32) -> anyhow::Result<PathBuf> {
    for _ in 0..100 {
        if socket.exists()
            && let Ok(devices) = lr_export::session::free_devices()
            && let Some(device) = devices.first()
        {
            lr_export::session::attach(socket, device)?;
            return Ok(device.clone());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    bail!("the NBD server (pid {server_pid}) did not produce a usable socket")
}

/// `export umount`: unmount, detach and stop the server.
fn export_umount(json: bool, at: &Path, socket: Option<&Path>) -> anyhow::Result<()> {
    // When the daemon serves the export it also owns the socket, so the stop
    // request has to go through it.
    if lr_export::session::load_state(at).is_ok_and(|state| state.in_process) {
        if let Some(mut client) = client_if_available(socket) {
            let summary = client.unexport_image(&at.display().to_string())?;
            if json {
                println!("{summary}");
            } else {
                print_json_report(&summary);
            }
            return Ok(());
        }
        bail!(
            "{} is served by the daemon, which is not reachable; start the daemon and retry",
            at.display()
        );
    }
    let state = lr_export::session::load_state(at)?;
    if lr_export::session::is_mounted(&state.mountpoint) {
        lr_export::session::unmount(&state.mountpoint)?;
    }
    let _ = lr_export::session::detach(&state.device);
    let _ = std::process::Command::new("kill")
        .arg(state.server_pid.to_string())
        .status();
    let _ = std::fs::remove_file(&state.socket);
    lr_export::session::clear_state(&state.mountpoint)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&state)?);
        return Ok(());
    }
    println!(
        "unmounted {} (device {}, server {})",
        at.display(),
        state.device.display(),
        state.server_pid
    );
    Ok(())
}

fn export_list(json: bool) -> anyhow::Result<()> {
    let states = lr_export::session::list_state()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&states)?);
        return Ok(());
    }
    if states.is_empty() {
        println!("(no live exports)");
        return Ok(());
    }
    for state in states {
        println!(
            "{:<24} {:<12} {} {}",
            state.mountpoint.display(),
            state.fs_type,
            state.device.display(),
            state.image
        );
    }
    Ok(())
}

/// Mount a file-mode image read-only through FUSE (spec §K S12).
///
/// The mount lives in this process's namespace, so it is done here rather than
/// through the daemon; the destination is opened directly, exactly as the
/// in-process restore path does.
fn restore_mount(
    image: &str,
    at: &Path,
    passphrase_file: Option<&Path>,
    options: &DestinationOptions,
) -> anyhow::Result<()> {
    let encryption = lr_engine::options::restore_encryption(passphrase_file)?;
    let mut request = PrepareRequest::new(image, at, encryption.clone());
    request.identity.clone_from(&options.identity);
    request.known_hosts.clone_from(&options.known_hosts);
    request.insecure_ignore_host_key = options.insecure_ignore_host_key;
    let plan = prepare_restore(&request)?;
    if plan.image_kind != lr_core::ImageKind::File {
        bail!(
            "restore mount is for file-mode images; {} is {:?}",
            plan.image,
            plan.image_kind
        );
    }
    println!(
        "mounting {} at {} (read-only, Ctrl-C to unmount)",
        plan.image,
        at.display()
    );
    lr_fuse::mount(&lr_fuse::FuseRequest {
        dest: plan.dest.clone(),
        set: plan.set.clone(),
        images: plan.members.clone(),
        destination_options: DestinationOptions {
            set_name: plan.set.clone(),
            identity: options.identity.clone(),
            known_hosts: options.known_hosts.clone(),
            insecure_ignore_host_key: options.insecure_ignore_host_key,
        },
        encryption: encryption.clone(),
        mountpoint: at.to_path_buf(),
    })?;
    Ok(())
}

fn restore_apply(
    json: bool,
    token: &str,
    confirm: bool,
    accept_inconsistent: bool,
    passphrase_file: Option<&Path>,
    socket: Option<&Path>,
) -> anyhow::Result<()> {
    if let Some(mut client) = client_if_available(socket) {
        let outcome = client.restore_image(
            lr_proto::v1::RestoreToken {
                token: token.to_owned(),
                confirm,
                accept_inconsistent,
                passphrase_file: passphrase_file
                    .map(|path| path.display().to_string())
                    .unwrap_or_default(),
                ..lr_proto::v1::RestoreToken::default()
            },
            |progress| {
                if let Some(line) = client::progress_line(progress) {
                    println!("{line}");
                }
            },
        )?;
        if json {
            println!("{outcome}");
        } else {
            print_json_report(&outcome);
        }
        return Ok(());
    }
    let encryption = lr_engine::options::restore_encryption(passphrase_file)?;
    let outcome = apply_restore(&ApplyRequest {
        token: token.to_owned(),
        confirm,
        accept_inconsistent,
        encryption,
        context: lr_engine::progress::EngineContext::silent(),
    })?;
    if json {
        println!("{}", serde_json::to_string_pretty(&outcome)?);
        return Ok(());
    }
    match outcome {
        lr_engine::restore::RestoreOutcome::Block(report) => {
            println!("mode:        block");
            println!("image:       {}", report.image);
            println!("target:      {}", report.target.display());
            println!("consistency: {}", report.consistency);
            println!(
                "chunks:      {} stored, {} zero, {} skipped (holes left untouched)",
                report.stored_chunks_written, report.zero_chunks_written, report.skipped_chunks
            );
            println!("bytes:       {}", report.bytes_written);
        }
        lr_engine::restore::RestoreOutcome::Stream(report) => {
            println!("mode:        stream");
            println!("target:      {}", report.target.display());
            println!("filesystem:  {} (label '{}')", report.fs_uuid, report.label);
            println!(
                "images:      {} applied, {} send bytes received",
                report.images.len(),
                report.received_bytes
            );
            println!("subvolumes:  {}", report.subvolumes.join(", "));
            if let Some(default) = &report.default_subvolume {
                println!("default:     {default}");
            }
            for warning in &report.warnings {
                println!("warning:     {warning}");
            }
        }
        lr_engine::restore::RestoreOutcome::File(report) => {
            println!("mode:        file");
            println!("target:      {}", report.target.display());
            println!(
                "entries:     {} files, {} directories, {} symlinks, {} hard links, {} special",
                report.files,
                report.directories,
                report.symlinks,
                report.hardlinks,
                report.specials
            );
            println!("bytes:       {}", report.restored_bytes);
            for warning in &report.warnings {
                println!("warning:     {warning}");
            }
        }
    }
    Ok(())
}

/// Print a JSON report field by field, for the text mode.
fn print_json_report(json: &str) {
    match serde_json::from_str::<serde_json::Value>(json) {
        Ok(serde_json::Value::Object(fields)) => {
            for (key, value) in fields {
                let rendered = match value {
                    serde_json::Value::String(text) => text,
                    other => other.to_string(),
                };
                println!("{key:<12} {rendered}");
            }
        }
        _ => println!("{json}"),
    }
}

/// A connected client when a daemon answers on the socket.
fn client_if_available(socket: Option<&Path>) -> Option<client::Client> {
    let path = client::socket_path(socket);
    if !client::daemon_available(&path) {
        return None;
    }
    match client::Client::connect(&path) {
        Ok(client) => Some(client),
        Err(error) => {
            eprintln!("warning: a daemon socket exists but is unusable: {error:#}");
            None
        }
    }
}

/// Print the shared disk-list entries, however they were obtained.
fn print_disk_entries(entries: &[lr_engine::inspect::DiskListEntry]) {
    if entries.is_empty() {
        println!("no block devices found");
        return;
    }
    println!(
        "{:<12} {:>10} {:>6} {:>6} {:<10} MOUNTPOINTS",
        "NAME", "SIZE", "LBS", "PBS", "TYPE"
    );
    for entry in entries {
        println!(
            "{:<12} {:>10} {:>6} {:>6} {:<10} {}",
            entry.name,
            entry.size_human,
            entry.logical_block_size,
            entry.physical_block_size,
            entry.type_label(),
            entry.mountpoints.join(", ")
        );
    }
}

/// Print a layout JSON body the way `disk map` prints a local one.
fn print_disk_map(value: &serde_json::Value) {
    let path = |value: &serde_json::Value| {
        value
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| value.to_string())
    };
    println!(
        "device:      {}",
        value.get("device").map(path).unwrap_or_default()
    );
    if let Some(facts) = value.get("device_facts") {
        let size = facts.get("size_bytes").and_then(serde_json::Value::as_u64);
        if let Some(size) = size {
            println!(
                "size:        {} ({} B)",
                lr_engine::inspect::human_size(size),
                size
            );
        }
        println!(
            "sector size: logical {} / physical {}",
            facts
                .get("logical_block_size")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
            facts
                .get("physical_block_size")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0)
        );
    }
    if let Some(table) = value.get("partition_table")
        && let Some(kind) = table.get("kind").and_then(serde_json::Value::as_str)
    {
        println!("table:       {kind}");
    }
    if let Some(fs) = value.get("fs").filter(|fs| !fs.is_null()) {
        println!(
            "filesystem:  {} {} {}",
            fs.get("fs_type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("-"),
            fs.get("uuid")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("-"),
            fs.get("label")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("-")
        );
    }
    for warning in value
        .get("warnings")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
    {
        eprintln!("warning: {}", path(warning));
    }
}

/// `disk list`: block devices, from the shared inspector.
fn disk_list(json: bool, all: bool, socket: Option<&Path>) -> anyhow::Result<()> {
    if let Some(mut client) = client_if_available(socket) {
        let body = client.list_disks()?;
        if json {
            println!("{body}");
            return Ok(());
        }
        let entries: Vec<lr_engine::inspect::DiskListEntry> =
            serde_json::from_str(&body).context("the daemon returned an unexpected disk list")?;
        print_disk_entries(&entries);
        return Ok(());
    }
    let entries =
        lr_engine::inspect::disk_list(all).context("enumerating block devices from sysfs")?;

    if json {
        println!("{}", lr_engine::inspect::disk_list_json(all)?);
        return Ok(());
    }
    print_disk_entries(&entries);
    Ok(())
}

/// `disk map`: the discovered layout of one device.
fn disk_map(json: bool, device: &std::path::Path, socket: Option<&Path>) -> anyhow::Result<()> {
    if let Some(mut client) = client_if_available(socket) {
        let body = client.disk_map(device)?;
        if json {
            println!("{body}");
            return Ok(());
        }
        let value: serde_json::Value =
            serde_json::from_str(&body).context("the daemon returned an unexpected map")?;
        print_disk_map(&value);
        return Ok(());
    }
    let layout =
        discover_source(device).with_context(|| format!("mapping {}", device.display()))?;
    if json {
        println!("{}", lr_engine::inspect::disk_map_json(device)?);
        return Ok(());
    }
    println!("device:      {}", layout.device.display());
    println!(
        "size:        {} ({} B)",
        lr_engine::inspect::human_size(layout.device_facts.size_bytes),
        layout.device_facts.size_bytes
    );
    println!(
        "sector size: logical {} / physical {}",
        layout.device_facts.logical_block_size, layout.device_facts.physical_block_size
    );
    if let Some(table) = &layout.partition_table {
        println!("table:       {}", table.kind);
    }
    if let Some(fs) = &layout.fs {
        println!(
            "filesystem:  {} {} {}",
            fs.fs_type,
            fs.uuid.as_deref().unwrap_or("-"),
            fs.label.as_deref().unwrap_or("-")
        );
    }
    if !layout.mountpoints.is_empty() {
        println!(
            "mountpoints: {}",
            layout
                .mountpoints
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if !layout.holders.is_empty() {
        println!("holders:     {}", layout.holders.join(", "));
    }
    if !layout.partitions.is_empty() {
        println!();
        println!(
            "{:<4} {:<10} {:>10} {:<10} {:<10} MOUNTPOINTS",
            "N", "NAME", "SIZE", "TYPE", "FS"
        );
        for part in &layout.partitions {
            println!(
                "{:<4} {:<10} {:>10} {:<10} {:<10} {}",
                part.index,
                part.name.as_deref().unwrap_or("-"),
                lr_engine::inspect::human_size(part.size_bytes),
                part.type_name.clone().unwrap_or_else(|| "-".to_owned()),
                part.fs_type.clone().unwrap_or_else(|| "-".to_owned()),
                part.mountpoints
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
    for warning in &layout.warnings {
        eprintln!("warning: {warning}");
    }
    Ok(())
}

fn caps(json: bool) -> anyhow::Result<()> {
    let caps = Capabilities::probe();
    if json {
        println!("{}", serde_json::to_string_pretty(&caps)?);
        return Ok(());
    }
    println!("kernel: {}", caps.kernel_release);
    for (name, capability) in caps.entries() {
        println!(
            "{:<10} {:<8} {}",
            name,
            if capability.available { "yes" } else { "no" },
            capability.detail
        );
    }
    if let Some(warning) = caps.freeze_provider_warning() {
        println!("warning: {warning}");
    }
    Ok(())
}
