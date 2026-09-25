//! `linuxreflect-rescue`: boot repair and layout recreation for a restored
//! machine, plus the rescue menu used inside the rescue media (spec §H.5,
//! §K S16).

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use lr_rescue::{
    BootRepairOptions, FilesystemSpec, Firmware, apply_boot_repair, apply_layout_recreation,
    capture_target, plan_boot_repair, plan_layout_recreation,
};

/// Rescue-mode operations.
#[derive(Debug, Parser)]
#[command(name = "linuxreflect-rescue", version)]
struct Cli {
    /// Print what would be done without doing it.
    #[arg(long, global = true)]
    dry_run: bool,

    /// JSON output.
    #[arg(long, global = true)]
    json: bool,

    /// Required to write to a disk (`boot-repair`, `recreate-layout`); without
    /// it the plan is printed and nothing is written.
    #[arg(long, global = true)]
    confirm: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Make a restored disk bootable again (spec §H.5).
    BootRepair {
        /// Disk to repair.
        #[arg(long, value_name = "DEV")]
        disk: PathBuf,

        /// Firmware the machine uses.
        #[arg(long, value_enum, default_value_t = FirmwareChoice::Uefi)]
        firmware: FirmwareChoice,

        /// ESP mount point, when it is already mounted.
        #[arg(long, value_name = "DIR")]
        esp_mount: Option<PathBuf>,

        /// ESP partition number, mounted by this tool when needed.
        #[arg(long, value_name = "N")]
        esp_partition: Option<u32>,

        /// ESP device node (`/dev/sda1`); needed when the disk is a file.
        #[arg(long, value_name = "DEV")]
        esp_device: Option<PathBuf>,

        /// Loader to place at the fallback path (defaults to the signed shim).
        #[arg(long, value_name = "PATH")]
        loader: Option<PathBuf>,

        /// Label for a new NVRAM entry.
        #[arg(long, default_value = "LinuxReflect")]
        label: String,

        /// The partition layout changed since the image was taken.
        #[arg(long)]
        layout_changed: bool,
    },

    /// Build the rescue USB image (spec §K S16).
    BuildMedia {
        /// Image file to write.
        #[arg(long, value_name = "PATH")]
        output: PathBuf,

        /// Kernel to include.
        #[arg(long, value_name = "PATH")]
        kernel: PathBuf,

        /// Static rescue CLI to include.
        #[arg(long, value_name = "PATH")]
        cli: Option<PathBuf>,

        /// Image size in MiB.
        #[arg(long, default_value_t = 512)]
        size_mib: u64,

        /// Install the BIOS bootloader.
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        bios: bool,

        /// Install the UEFI bootloader.
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        uefi: bool,

        /// Use the distribution's signed shim and GRUB (Secure Boot).
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        secure_boot: bool,

        /// Extra kernel command-line arguments, repeatable (unattended runs).
        #[arg(long = "cmdline-extra", value_name = "ARG")]
        cmdline_extra: Vec<String>,
    },

    /// Recreate a disk's partition table and filesystems for a file-mode
    /// restore (spec §K S16).
    RecreateLayout {
        /// Disk to write.
        #[arg(long, value_name = "DEV")]
        disk: PathBuf,

        /// `sfdisk -d` dump taken before the backup.
        #[arg(long, value_name = "PATH")]
        dump: PathBuf,

        /// A filesystem, as `<partition>:<fs>:<uuid>:<label>`, repeatable.
        #[arg(long = "filesystem", value_name = "SPEC")]
        filesystems: Vec<String>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FirmwareChoice {
    Uefi,
    Bios,
}

impl From<FirmwareChoice> for Firmware {
    fn from(choice: FirmwareChoice) -> Self {
        match choice {
            FirmwareChoice::Uefi => Self::Uefi,
            FirmwareChoice::Bios => Self::Bios,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("linuxreflect-rescue: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> anyhow::Result<()> {
    match &cli.command {
        Command::BootRepair {
            disk,
            firmware,
            esp_mount,
            esp_partition,
            esp_device,
            loader,
            label,
            layout_changed,
        } => {
            let options = BootRepairOptions {
                firmware: (*firmware).into(),
                esp_mount: esp_mount.clone(),
                esp_partition: *esp_partition,
                esp_device: esp_device.clone(),
                loader: loader.clone(),
                entry_label: label.clone(),
                force_bios_reinstall: false,
                layout_changed: *layout_changed,
            };
            let plan = plan_boot_repair(disk, &options)?;
            if cli.dry_run || !cli.confirm {
                print_plan(cli.json, &plan)?;
                return refuse_without_confirm(cli, disk);
            }
            let report = apply_boot_repair(&plan)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                for step in &report.completed {
                    println!("done: {step}");
                }
                for warning in &report.plan.warnings {
                    println!("warning: {warning}");
                }
            }
            Ok(())
        }
        Command::BuildMedia {
            output,
            kernel,
            cli: cli_path,
            size_mib,
            bios,
            uefi,
            secure_boot,
            cmdline_extra,
        } => {
            let request = lr_rescue::MediaRequest {
                output: output.clone(),
                size_mib: *size_mib,
                kernel: kernel.clone(),
                cli: cli_path.clone(),
                extra: Vec::new(),
                cmdline_extra: cmdline_extra.clone(),
                bios: *bios,
                uefi: *uefi,
                secure_boot: *secure_boot,
            };
            let report = lr_rescue::build_media(&request)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("image:      {}", report.image.display());
                println!("size:       {} bytes", report.size_bytes);
                println!("initramfs:  {} bytes", report.initramfs_bytes);
                println!("esp files:  {}", report.esp_files.len());
                for step in &report.steps {
                    println!("step:       {step}");
                }
                for warning in &report.warnings {
                    println!("warning:    {warning}");
                }
            }
            Ok(())
        }
        Command::RecreateLayout {
            disk,
            dump,
            filesystems,
        } => {
            let dump = std::fs::read_to_string(dump)
                .map_err(|error| anyhow::anyhow!("reading {}: {error}", dump.display()))?;
            let specs = filesystems
                .iter()
                .map(|text| parse_filesystem(text))
                .collect::<anyhow::Result<Vec<_>>>()?;
            let plan = plan_layout_recreation(disk, &dump, &specs)?;
            // The facts are taken with the plan the operator is shown, and
            // re-read immediately before the first write.
            let reviewed = capture_target(disk)?;
            if cli.dry_run || !cli.confirm {
                if cli.json {
                    println!("{}", serde_json::to_string_pretty(&plan)?);
                } else {
                    for step in &plan.steps {
                        println!("would: {step}");
                    }
                    for command in &plan.commands {
                        println!("command: {}", command.display());
                    }
                }
                return refuse_without_confirm(cli, disk);
            }
            let report = apply_layout_recreation(&plan, &reviewed)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                for step in &report.completed {
                    println!("done: {step}");
                }
            }
            Ok(())
        }
    }
}

/// A plan without `--confirm` is a preview: it succeeds under `--dry-run` and
/// is an error otherwise, so a script that forgot the flag cannot mistake it
/// for a completed repair.
fn refuse_without_confirm(cli: &Cli, disk: &std::path::Path) -> anyhow::Result<()> {
    if cli.dry_run {
        return Ok(());
    }
    anyhow::bail!(
        "nothing was written to {}; review the plan above and rerun with --confirm",
        disk.display()
    )
}

fn print_plan(json: bool, plan: &lr_rescue::RepairPlan) -> anyhow::Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(plan)?);
        return Ok(());
    }
    for step in &plan.steps {
        println!("would: {step}");
    }
    for warning in &plan.warnings {
        println!("warning: {warning}");
    }
    Ok(())
}

/// `<partition>:<fs>:<uuid>:<label>` (`uuid` and `label` may be empty).
fn parse_filesystem(text: &str) -> anyhow::Result<FilesystemSpec> {
    let mut parts = text.split(':');
    let partition = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("`{text}` has no partition number"))?
        .parse::<u32>()
        .map_err(|error| anyhow::anyhow!("`{text}`: {error}"))?;
    let fs_type = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("`{text}` has no filesystem type"))?
        .to_owned();
    if fs_type.is_empty() {
        anyhow::bail!("`{text}` has an empty filesystem type");
    }
    let uuid = parts
        .next()
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let label = parts
        .next()
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    if parts.next().is_some() {
        anyhow::bail!("`{text}` has too many fields; use <partition>:<fs>:<uuid>:<label>");
    }
    Ok(FilesystemSpec {
        partition,
        fs_type,
        uuid,
        label,
        mount_point: None,
    })
}
