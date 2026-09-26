//! Command-line surface for LinuxReflect (spec §J.1).

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

/// GUI-driven backup and disaster recovery for Linux.
#[derive(Debug, Parser)]
#[command(
    name = "linuxreflect",
    version,
    about = "LinuxReflect: system-level backup and disaster recovery for Linux",
    long_about = None,
    propagate_version = true
)]
pub(crate) struct Cli {
    /// Path to the daemon socket (default `/run/linuxreflect/daemon.sock`).
    #[arg(long, global = true, value_name = "PATH")]
    pub(crate) socket: Option<PathBuf>,

    /// Increase log verbosity (repeatable).
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub(crate) verbose: u8,

    /// Decrease log verbosity (repeatable).
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub(crate) quiet: u8,

    /// Emit machine-readable JSON.
    #[arg(long, global = true)]
    pub(crate) json: bool,

    /// Subcommand.
    #[command(subcommand)]
    pub(crate) command: Command,
}

/// Top-level commands (spec §J.1).
#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Inspect disks and partitions.
    #[command(subcommand)]
    Disk(DiskCommand),

    /// Report the platform capabilities detected by `caps::probe()`.
    Caps,

    /// Compute the backup plan for a source without touching it (Slice S8).
    Probe {
        /// Source device or path.
        #[arg(long, value_name = "DEV|PATH")]
        source: PathBuf,

        /// Snapshot provider selection.
        #[arg(long, value_enum, default_value_t = SnapshotChoice::Auto)]
        snapshot: SnapshotChoice,

        /// Imaging mode selection.
        #[arg(long, value_enum, default_value_t = ModeChoice::Auto)]
        mode: ModeChoice,
    },

    /// Create and inspect backups.
    #[command(subcommand)]
    Backup(BackupCommand),

    /// Restore an image.
    #[command(subcommand)]
    Restore(RestoreCommand),

    /// Export an image as a read-only block device (Slice S13).
    #[command(subcommand)]
    Export(ExportCommand),

    /// Apply chain-based retention (Slice S14).
    #[command(subcommand)]
    Retention(RetentionCommand),

    /// Manage systemd job timers (Slice S14).
    #[command(subcommand)]
    Schedule(ScheduleCommand),

    /// Verify an image (Slice S11).
    Verify {
        /// Image URI: `<dest>/<set>/<chain>/<file>.lrimg`.
        #[arg(long, value_name = "URI")]
        image: String,

        /// Walk the whole chain, not just the image itself.
        #[arg(long)]
        chain: bool,

        /// Passphrase file.
        #[arg(long, value_name = "PATH")]
        passphrase_file: Option<PathBuf>,

        /// Private key for an SFTP image.
        #[arg(long, value_name = "PATH")]
        identity: Option<PathBuf>,

        /// `known_hosts` file for an SFTP image.
        #[arg(long, value_name = "PATH")]
        known_hosts: Option<PathBuf>,

        /// Skip host-key verification (tests only).
        #[arg(long)]
        insecure_ignore_host_key: bool,
    },

    /// Rebuild a set's catalog (Slice S9).
    Catalog {
        /// Destination: a path or `sftp://…`.
        #[arg(long, value_name = "URI")]
        dest: String,

        /// Set name.
        #[arg(long)]
        set: String,

        /// Private key for an SFTP destination.
        #[arg(long, value_name = "PATH")]
        identity: Option<PathBuf>,

        /// `known_hosts` file for an SFTP destination.
        #[arg(long, value_name = "PATH")]
        known_hosts: Option<PathBuf>,

        /// Skip host-key verification (tests only).
        #[arg(long)]
        insecure_ignore_host_key: bool,
    },

    /// Daemon control (Slice S11).
    Daemon {
        /// What to do.
        #[command(subcommand)]
        command: DaemonCommand,
    },

    /// Inspect or cancel a running job (Slice S11).
    Job {
        /// What to do.
        #[command(subcommand)]
        command: JobCommand,
    },
}

/// `backup` subcommands.
#[derive(Debug, Subcommand)]
pub(crate) enum BackupCommand {
    /// Create a backup image.
    Create {
        /// Source device or image file.
        #[arg(long, value_name = "DEV|PATH")]
        source: PathBuf,

        /// Destination: a path, `file://` or `sftp://[user@]host[:port]/path`.
        #[arg(long, value_name = "URI")]
        dest: String,

        /// Backup set name.
        #[arg(long)]
        set: String,

        /// Private key for an SFTP destination.
        #[arg(long, value_name = "PATH")]
        identity: Option<PathBuf>,

        /// `known_hosts` file for an SFTP destination (default ~/.ssh/known_hosts).
        #[arg(long, value_name = "PATH")]
        known_hosts: Option<PathBuf>,

        /// Skip host-key verification. Tests only; never use it for real backups.
        #[arg(long)]
        insecure_ignore_host_key: bool,

        /// Chain member type.
        #[arg(long, value_enum, default_value_t = BackupType::Full)]
        r#type: BackupType,

        /// Parent member for an incremental or differential: `latest` or an
        /// image UUID (default `latest`).
        #[arg(long, value_name = "latest|UUID")]
        parent: Option<String>,

        /// Break an expired set lock instead of failing.
        #[arg(long)]
        break_stale_lock: bool,

        /// Block-mode chunk size (`256KiB` .. `4MiB`).
        #[arg(long, default_value = "1MiB")]
        chunk_size: String,

        /// Compression: `zstd:9` or `none`.
        #[arg(long, default_value = "zstd:9")]
        compress: String,

        /// Encrypt with the passphrase in this file.
        #[arg(long, value_name = "PATH", conflicts_with = "no_encrypt")]
        passphrase_file: Option<PathBuf>,

        /// Store chunks in the clear (not tamper-evident).
        #[arg(long)]
        no_encrypt: bool,

        /// What to do when a chunk cannot be read.
        #[arg(long, value_enum, default_value_t = BadSectorChoice::Abort)]
        on_bad_sector: BadSectorChoice,

        /// Snapshot provider override.
        #[arg(long, value_enum)]
        snapshot: Option<SnapshotChoice>,

        /// Allow the freeze provider (writers block for the whole read).
        #[arg(long)]
        allow_freeze: bool,

        /// Freeze timeout in seconds (default 300).
        #[arg(long, default_value_t = 300)]
        freeze_timeout: u64,

        /// Read a mounted device as-is and flag the image inconsistent.
        #[arg(long)]
        allow_inconsistent: bool,

        /// LVM snapshot COW size, e.g. `2G` or `25%`.
        #[arg(long, value_name = "SIZE")]
        lvm_cow_size: Option<String>,

        /// Extra grace before the freeze deadman fires, in seconds.
        #[arg(long, default_value_t = 30)]
        deadman_grace: u64,

        /// Start a new chain when the newest one already has this many
        /// incrementals (0 = no limit, spec §J.3).
        #[arg(long, default_value_t = 0)]
        max_incrementals: u64,

        /// Imaging mode; `auto` picks file mode for a directory source.
        #[arg(long, value_enum, default_value_t = ModeChoice::Auto)]
        mode: ModeChoice,

        /// File mode: stay on one filesystem (spec §K S12).
        #[arg(long)]
        one_file_system: bool,
    },

    /// List chains and members (Slice S9).
    List {
        /// Destination: a path or `sftp://…`.
        #[arg(long, value_name = "URI")]
        dest: String,

        /// Set name.
        #[arg(long)]
        set: Option<String>,

        /// Private key for an SFTP destination.
        #[arg(long, value_name = "PATH")]
        identity: Option<PathBuf>,

        /// `known_hosts` file for an SFTP destination.
        #[arg(long, value_name = "PATH")]
        known_hosts: Option<PathBuf>,

        /// Skip host-key verification (tests only).
        #[arg(long)]
        insecure_ignore_host_key: bool,
    },
}

/// `restore` subcommands.
#[derive(Debug, Subcommand)]
pub(crate) enum RestoreCommand {
    /// Check an image against a target and print a plan plus a token.
    Prepare {
        /// Image URI: `<dest>/<set>/<chain>/<file>.lrimg`, a path or `sftp://…`.
        #[arg(long, value_name = "URI")]
        image: String,

        /// Target block device.
        #[arg(long, value_name = "DEV")]
        target: PathBuf,

        /// Passphrase file.
        #[arg(long, value_name = "PATH")]
        passphrase_file: Option<PathBuf>,

        /// Token lifetime in seconds (at most 600).
        #[arg(long, default_value_t = 600)]
        ttl: u64,

        /// Private key for an SFTP image.
        #[arg(long, value_name = "PATH")]
        identity: Option<PathBuf>,

        /// `known_hosts` file for an SFTP image.
        #[arg(long, value_name = "PATH")]
        known_hosts: Option<PathBuf>,

        /// Skip host-key verification (tests only).
        #[arg(long)]
        insecure_ignore_host_key: bool,

        /// Allow a file-mode restore into a non-empty directory.
        #[arg(long)]
        merge: bool,

        /// Allow a single-filesystem image onto a whole disk, replacing its
        /// partition table and every partition on it.
        #[arg(long)]
        replace_partition_table: bool,
    },

    /// Mount a file-mode image read-only through FUSE.
    Mount {
        /// Image URI: `<dest>/<set>/<chain>/<file>.lrimg`, a path or `sftp://…`.
        #[arg(long, value_name = "URI")]
        image: String,

        /// Existing directory to mount on.
        #[arg(long, value_name = "DIR")]
        at: PathBuf,

        /// Passphrase file.
        #[arg(long, value_name = "PATH")]
        passphrase_file: Option<PathBuf>,

        /// Private key for an SFTP image.
        #[arg(long, value_name = "PATH")]
        identity: Option<PathBuf>,

        /// `known_hosts` file for an SFTP image.
        #[arg(long, value_name = "PATH")]
        known_hosts: Option<PathBuf>,

        /// Skip host-key verification (tests only).
        #[arg(long)]
        insecure_ignore_host_key: bool,
    },

    /// Apply a prepared restore.
    Apply {
        /// Token printed by `restore prepare`.
        #[arg(long, value_name = "TOKEN")]
        token: String,

        /// Required: acknowledge that the target will be overwritten.
        #[arg(long)]
        confirm: bool,

        /// Apply an image that is flagged inconsistent.
        #[arg(long)]
        accept_inconsistent: bool,

        /// Passphrase file.
        #[arg(long, value_name = "PATH")]
        passphrase_file: Option<PathBuf>,
    },
}

/// `retention` subcommands (Slice S14).
#[derive(Debug, Subcommand)]
pub(crate) enum RetentionCommand {
    /// Delete whole chains beyond `keep_chains`.
    Apply {
        /// Destination: a path or `sftp://…`.
        #[arg(long, value_name = "URI")]
        dest: String,

        /// Set name.
        #[arg(long)]
        set: String,

        /// Complete chains to keep (the newest is always kept).
        #[arg(long, default_value_t = 2)]
        keep_chains: usize,

        /// Report what would be deleted without deleting it.
        #[arg(long)]
        dry_run: bool,

        /// Private key for an SFTP destination.
        #[arg(long, value_name = "PATH")]
        identity: Option<PathBuf>,

        /// `known_hosts` file for an SFTP destination.
        #[arg(long, value_name = "PATH")]
        known_hosts: Option<PathBuf>,

        /// Skip host-key verification (tests only).
        #[arg(long)]
        insecure_ignore_host_key: bool,
    },
}

/// `schedule` subcommands (Slice S14).
#[derive(Debug, Subcommand)]
pub(crate) enum ScheduleCommand {
    /// Materialize the systemd units described by a config file.
    Set {
        /// Config file (`/etc/linuxreflect/config.toml` by default).
        #[arg(long, value_name = "PATH")]
        config: Option<PathBuf>,

        /// Write the units somewhere else (tests).
        #[arg(long, value_name = "DIR")]
        systemd_dir: Option<PathBuf>,

        /// Validate and print the units without writing them.
        #[arg(long)]
        dry_run: bool,
    },

    /// List the configured jobs.
    List {
        /// Config file.
        #[arg(long, value_name = "PATH")]
        config: Option<PathBuf>,
    },

    /// Remove the units of one job.
    Remove {
        /// Job name.
        job: String,

        /// Directory the units live in.
        #[arg(long, value_name = "DIR")]
        systemd_dir: Option<PathBuf>,
    },
}

/// `export` subcommands (Slice S13).
#[derive(Debug, Subcommand)]
pub(crate) enum ExportCommand {
    /// Attach an image with NBD and mount its filesystem read-only.
    Mount {
        /// Image URI: `<dest>/<set>/<chain>/<file>.lrimg`.
        #[arg(long, value_name = "URI")]
        image: String,

        /// Directory to mount on.
        #[arg(long, value_name = "DIR")]
        at: PathBuf,

        /// Export mechanism (spec §K S13: NBD is the baseline).
        #[arg(long, value_enum, default_value_t = ExportKind::Nbd)]
        kind: ExportKind,

        /// Passphrase file.
        #[arg(long, value_name = "PATH")]
        passphrase_file: Option<PathBuf>,

        /// Private key for an SFTP image.
        #[arg(long, value_name = "PATH")]
        identity: Option<PathBuf>,

        /// `known_hosts` file for an SFTP image.
        #[arg(long, value_name = "PATH")]
        known_hosts: Option<PathBuf>,

        /// Skip host-key verification (tests only).
        #[arg(long)]
        insecure_ignore_host_key: bool,
    },

    /// Unmount and stop serving an export.
    Umount {
        /// Mount point used by `export mount`.
        #[arg(long, value_name = "DIR")]
        at: PathBuf,
    },

    /// List live exports.
    List,

    /// Serve an image on a Unix socket (used by `export mount`).
    #[command(hide = true)]
    Serve {
        /// Image URI.
        #[arg(long, value_name = "URI")]
        image: String,

        /// Socket to listen on.
        #[arg(long, value_name = "PATH")]
        socket: PathBuf,

        /// Passphrase file.
        #[arg(long, value_name = "PATH")]
        passphrase_file: Option<PathBuf>,

        /// Private key for an SFTP image.
        #[arg(long, value_name = "PATH")]
        identity: Option<PathBuf>,

        /// `known_hosts` file for an SFTP image.
        #[arg(long, value_name = "PATH")]
        known_hosts: Option<PathBuf>,

        /// Skip host-key verification (tests only).
        #[arg(long)]
        insecure_ignore_host_key: bool,
    },
}

/// `--kind` values for `export mount`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum ExportKind {
    /// Newstyle NBD over a Unix socket (spec §K S13 baseline).
    Nbd,
    /// ublk, where the kernel provides it (optional).
    Ublk,
}

/// `daemon` subcommands.
#[derive(Debug, Subcommand)]
pub(crate) enum DaemonCommand {
    /// Run the daemon in the foreground (executes `linuxreflect-daemon`).
    Run {
        /// Arguments passed to the daemon binary.
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
    /// Report whether a daemon answers on the socket.
    Status,
}

/// `job` subcommands.
#[derive(Debug, Subcommand)]
pub(crate) enum JobCommand {
    /// Report one job.
    Get {
        /// Job identifier.
        job_id: String,
    },
    /// Ask a job to stop.
    Cancel {
        /// Job identifier.
        job_id: String,
    },
}

/// `disk` subcommands.
#[derive(Debug, Subcommand)]
pub(crate) enum DiskCommand {
    /// List block devices with size and sector size.
    List {
        /// Include partitions, not just whole disks.
        #[arg(long)]
        all: bool,
    },

    /// Show the partition table, filesystems, holders and mount points of a device.
    Map {
        /// Device or image file to inspect.
        #[arg(value_name = "DEVICE")]
        device: PathBuf,
    },
}

/// `--type` values (spec §J.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum BackupType {
    /// A full image; starts a new chain.
    Full,
    /// Changes since the previous member (Slice S9).
    Incremental,
    /// Changes since the chain's full (Slice S9).
    Differential,
}

/// `--on-bad-sector` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum BadSectorChoice {
    /// Fail the job.
    Abort,
    /// Record the bad region in the manifest and continue.
    Record,
}

/// `--snapshot` values (spec §E).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum SnapshotChoice {
    /// Pick the first provider that supports the source.
    Auto,
    /// Btrfs read-only snapshot (stream mode, Slice S8).
    Btrfs,
    /// LVM snapshot (Slice S8).
    Lvm,
    /// `FIFREEZE`/`FITHAW` quiesced read (Slice S8).
    Freeze,
    /// Read an unmounted, holder-free device.
    Offline,
    /// Live, inconsistent read (Slice S8).
    None,
}

/// `--mode` values (spec §D.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum ModeChoice {
    /// Pick from the source filesystem.
    Auto,
    /// Block image.
    Block,
    /// Stream image (Slice S8).
    Stream,
    /// File-mode tree image (Slice S12).
    File,
}
