//! Boot repair and layout recreation (spec §H.5, §K S16).
//!
//! `boot repair` finishes a whole-disk restore: the ESP must hold
//! `\EFI\BOOT\BOOTX64.EFI` (the firmware's fallback path, so the machine boots
//! even when NVRAM is empty) and, where the firmware kept an entry, an NVRAM
//! entry pointing at the loader. The BIOS side arrives with the image's leading
//! region (`core.img`), and is reinstalled only when the restored layout no
//! longer matches what that `core.img` expects.
//!
//! Everything is planned before it is executed, so `--dry-run` prints exactly
//! what `apply` would do; nothing here runs on its own.

use std::path::{Path, PathBuf};
use std::process::Command;

use lr_core::{Error, Result};
use serde::{Deserialize, Serialize};

pub mod media;

pub use media::{MediaReport, MediaRequest, RESCUE_CMDLINE, RESCUE_MARKER, build_media};

/// The rescue TUI: a busybox-sh menu shown on the console when the medium boots
/// interactively (the spec's TUI fallback for machines without a graphical
/// session; `contrib/rescue/mkosi.conf` adds `cage` + the GUI).
pub const TUI_SCRIPT: &str = r#"#!/bin/sh
# LinuxReflect rescue menu (busybox sh).
set -u
while true; do
    clear
    echo "=============================================="
    echo " LinuxReflect rescue"
    echo "=============================================="
    echo " 1) Restore a backup (linuxreflect restore ...)"
    echo " 2) Verify an image (linuxreflect verify ...)"
    echo " 3) Repair the bootloader (linuxreflect-rescue boot-repair)"
    echo " 4) Recreate a disk layout (linuxreflect-rescue recreate-layout)"
    echo " 5) Shell"
    echo " 6) Reboot"
    echo " 7) Power off"
    printf "choice: "
    read -r choice
    case "$choice" in
        1|2) echo "run: /bin/linuxreflect --help"; /bin/linuxreflect --help 2>/dev/null || echo "the rescue CLI is not in this image"; sleep 5 ;;
        3|4) echo "run: linuxreflect-rescue --help"; linuxreflect-rescue --help 2>/dev/null || echo "linuxreflect-rescue is not in this image"; sleep 5 ;;
        5) /bin/sh ;;
        6) reboot -f ;;
        7) poweroff -f ;;
    esac
done
"#;

/// The rescue init script: mount the pseudo filesystems, announce readiness on
/// the console (the serial marker the acceptance test looks for) and either run
/// the self check (`rescue.auto=1`) or start the TUI.
pub const INIT_SCRIPT: &str = r#"#!/bin/sh
# LinuxReflect rescue init (busybox).
/bin/busybox --install -s /bin 2>/dev/null
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sys /sys 2>/dev/null
mount -t devtmpfs dev /dev 2>/dev/null

# Announce on the serial port as well as on stdout: with `console=tty0` in the
# command line the init's stdout is the invisible VGA console, and a rescue
# medium is usually driven from a serial line (or a headless test).
announce() {
    echo "$1"
    [ -c /dev/ttyS0 ] && echo "$1" > /dev/ttyS0
}

announce "LINUXREFLECT-RESCUE-READY"
announce "kernel: $(uname -r)"
if [ -x /bin/linuxreflect ]; then
    /bin/linuxreflect --version > /dev/ttyS0 2>&1 || true
fi
if [ -x /usr/bin/rescue-tui ]; then
    announce "rescue-tui: present"
fi

if grep -q 'linuxreflect.autorun=' /proc/cmdline 2>/dev/null; then
    param() {
        tr ' ' '\n' </proc/cmdline | sed -n "s/^$1=//p" | head -1
    }
    mkdir -p /tmp
    # `prepare` and `apply` are separate processes and share the token secret
    # through this file.
    export LR_TOKEN_SECRET_FILE=/tmp/linuxreflect-token.key
    image=$(param linuxreflect.image)
    target=$(param linuxreflect.target)
    backup=$(param linuxreflect.backup)
    announce "LINUXREFLECT-AUTORUN image=$image target=$target"
    if [ -n "$backup" ]; then
        mkdir -p /mnt/backup
        mount "$backup" /mnt/backup 2>/dev/null || announce "LINUXREFLECT-AUTORUN backup-mount-failed"
    fi
    if [ -x /bin/linuxreflect ]; then
        /bin/linuxreflect restore prepare --image "$image" --target "$target" >/tmp/prepare.log 2>&1
        token=$(sed -n 's/^token: //p' /tmp/prepare.log | head -1)
        if [ -n "$token" ]; then
            if /bin/linuxreflect restore apply --token "$token" --confirm >/tmp/apply.log 2>&1; then
                announce "LINUXREFLECT-AUTORUN-RESTORED"
            else
                announce "LINUXREFLECT-AUTORUN-FAILED $(tail -c 400 /tmp/apply.log)"
            fi
        else
            announce "LINUXREFLECT-AUTORUN no-token $(tail -c 400 /tmp/prepare.log)"
        fi
    else
        announce "LINUXREFLECT-AUTORUN no-cli"
    fi
    sync
    announce "LINUXREFLECT-AUTORUN-DONE"
    poweroff -f
    exit 0
fi

if grep -q 'rescue.auto=1' /proc/cmdline 2>/dev/null; then
    announce "LINUXREFLECT-RESCUE-SELFTEST-OK"
    sleep 1
    poweroff -f
    exit 0
fi

# Non-interactive bare-metal restore, driven by the kernel command line:
#   linuxreflect.autorun=1 linuxreflect.image=<img> linuxreflect.target=<dev>
#   [linuxreflect.backup=<dev>]
exec /usr/bin/rescue-tui
"#;

/// Path of the UEFI fallback loader inside an ESP.
pub const EFI_FALLBACK: &str = "EFI/BOOT/BOOTX64.EFI";
/// Where the distro keeps the signed shim.
pub const SHIM_SIGNED: &str = "/usr/lib/shim/shimx64.efi.signed";
/// Where the distro keeps the signed GRUB EFI binary.
pub const GRUB_SIGNED: &str = "/usr/lib/grub/x86_64-efi-signed/grubx64.efi.signed";

/// Which firmware a machine boots with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Firmware {
    /// BIOS/CSM: the bootloader lives in the disk's leading region.
    Bios,
    /// UEFI: the ESP holds the loader and NVRAM holds the entries.
    Uefi,
}

/// One command the repair wants to run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedCommand {
    /// Program to run.
    pub program: String,
    /// Arguments, in order.
    pub args: Vec<String>,
}

impl PlannedCommand {
    fn new(program: impl Into<String>, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }

    /// A human-readable form, for reports.
    #[must_use]
    pub fn display(&self) -> String {
        format!("{} {}", self.program, self.args.join(" "))
    }
}

/// What a boot repair will do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairPlan {
    /// Disk being repaired.
    pub disk: PathBuf,
    /// Firmware the plan targets.
    pub firmware: Firmware,
    /// ESP partition number, when the plan touches one.
    pub esp_partition: Option<u32>,
    /// Human-readable steps, in order.
    pub steps: Vec<String>,
    /// Commands to execute when the plan is applied.
    pub commands: Vec<PlannedCommand>,
    /// Non-fatal notes, e.g. tools the rescue environment must provide.
    pub warnings: Vec<String>,
}

impl RepairPlan {
    /// `true` when the plan changes nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.commands.is_empty()
    }
}

/// What a repair did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairReport {
    /// The plan that was applied.
    pub plan: RepairPlan,
    /// Steps that succeeded.
    pub completed: Vec<String>,
    /// Output of the commands, one entry per command.
    pub output: Vec<String>,
    /// Steps that were skipped because the environment does not support them
    /// (`efibootmgr` on a machine without EFI variables, for example).
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// How the repair should behave.
#[derive(Debug, Clone)]
pub struct BootRepairOptions {
    /// Firmware the machine boots with.
    pub firmware: Firmware,
    /// Mount point of the ESP, when the caller already mounted it.
    pub esp_mount: Option<PathBuf>,
    /// Partition number of the ESP, used when mounting it ourselves.
    pub esp_partition: Option<u32>,
    /// Explicit ESP device (`/dev/loop0p2`); needed when the disk is a file,
    /// because `<file>2` is not a device node.
    pub esp_device: Option<PathBuf>,
    /// Loader to place at the fallback path; defaults to the signed shim.
    pub loader: Option<PathBuf>,
    /// Label for a new NVRAM entry.
    pub entry_label: String,
    /// Reinstall the BIOS bootloader even if the layout matches.
    pub force_bios_reinstall: bool,
    /// `true` when the disk's partition layout changed since the image was
    /// taken, which invalidates an embedded `core.img`.
    pub layout_changed: bool,
}

impl Default for BootRepairOptions {
    fn default() -> Self {
        Self {
            firmware: Firmware::Uefi,
            esp_mount: None,
            esp_partition: None,
            esp_device: None,
            loader: None,
            entry_label: "LinuxReflect".to_owned(),
            force_bios_reinstall: false,
            layout_changed: false,
        }
    }
}

/// Plan the repair of a restored disk (spec §H.5).
///
/// # Errors
/// Returns [`Error::Unsupported`] when the disk or the ESP cannot be inspected,
/// and [`Error::Corrupt`] when the ESP has no filesystem to write into.
pub fn plan_boot_repair(disk: &Path, options: &BootRepairOptions) -> Result<RepairPlan> {
    if !disk.exists() {
        return Err(Error::unsupported(format!(
            "{} does not exist",
            disk.display()
        )));
    }
    let mut plan = RepairPlan {
        disk: disk.to_path_buf(),
        firmware: options.firmware,
        esp_partition: options.esp_partition,
        steps: Vec::new(),
        commands: Vec::new(),
        warnings: Vec::new(),
    };

    match options.firmware {
        Firmware::Uefi => plan_uefi(disk, options, &mut plan)?,
        Firmware::Bios => plan_bios(disk, options, &mut plan),
    }
    Ok(plan)
}

fn plan_uefi(disk: &Path, options: &BootRepairOptions, plan: &mut RepairPlan) -> Result<()> {
    let esp = match (&options.esp_mount, options.esp_partition) {
        (Some(mount), _) => mount.clone(),
        (None, Some(partition)) => {
            let mount = PathBuf::from("/run/linuxreflect/esp");
            plan.commands.push(PlannedCommand::new(
                "mkdir",
                ["-p", &mount.display().to_string()],
            ));
            let partition_device = options
                .esp_device
                .clone()
                .unwrap_or_else(|| partition_device(disk, partition));
            if !partition_device.exists() {
                return Err(Error::unsupported(format!(
                    "{} does not exist; pass --esp-device with the ESP's device node (a disk                      image has no <file>N node)",
                    partition_device.display()
                )));
            }
            plan.commands.push(PlannedCommand::new(
                "mount",
                [
                    "-t",
                    "vfat",
                    &partition_device.display().to_string(),
                    &mount.display().to_string(),
                ],
            ));
            plan.steps.push(format!(
                "mount ESP partition {partition} ({}) at {}",
                partition_device.display(),
                mount.display()
            ));
            mount
        }
        (None, None) => {
            return Err(Error::unsupported(
                "UEFI repair needs the ESP: pass --esp-mount or --esp-partition",
            ));
        }
    };

    // Whether a fallback loader is already there can only be decided for an ESP
    // that is mounted *now*: when this plan mounts it later, the path may be a
    // stale directory from an earlier run, so the copy is always planned (it is
    // idempotent: it writes the same signed loader).
    let esp_is_mounted = options.esp_mount.is_some() && esp.is_dir();
    let fallback = esp.join(EFI_FALLBACK);
    let loader = options.loader.clone().unwrap_or_else(|| {
        if Path::new(SHIM_SIGNED).exists() {
            PathBuf::from(SHIM_SIGNED)
        } else {
            PathBuf::from(GRUB_SIGNED)
        }
    });
    if !Path::new(SHIM_SIGNED).exists() && options.loader.is_none() {
        plan.warnings.push(format!(
            "no signed shim at {SHIM_SIGNED}; the fallback loader will not be usable with Secure Boot"
        ));
    }
    if options.loader.is_none() && !Path::new(GRUB_SIGNED).exists() {
        plan.warnings.push(format!(
            "no signed GRUB at {GRUB_SIGNED}; Secure Boot needs a signed loader"
        ));
    }
    if esp_is_mounted && fallback.exists() {
        plan.steps.push(format!(
            "{} already exists; leaving it alone",
            fallback.display()
        ));
    } else {
        plan.commands.push(PlannedCommand::new(
            "mkdir",
            ["-p", &esp.join("EFI/BOOT").display().to_string()],
        ));
        plan.commands.push(PlannedCommand::new(
            "cp",
            [
                &loader.display().to_string(),
                &fallback.display().to_string(),
            ],
        ));
        // A shim loads `grubx64.efi` from the same directory, so the signed
        // GRUB has to travel with it.
        if loader == Path::new(SHIM_SIGNED) && Path::new(GRUB_SIGNED).exists() {
            plan.commands.push(PlannedCommand::new(
                "cp",
                [
                    GRUB_SIGNED,
                    &esp.join("EFI/BOOT/grubx64.efi").display().to_string(),
                ],
            ));
        }
        plan.steps.push(format!(
            "install {} as {}",
            loader.display(),
            fallback.display()
        ));
    }

    // An NVRAM entry makes the firmware pick the loader by name; the fallback
    // path above covers the empty-NVRAM case.
    if options.esp_partition.is_some() {
        plan.commands.push(PlannedCommand::new(
            "efibootmgr",
            [
                "-c",
                "-d",
                &disk.display().to_string(),
                "-p",
                &options.esp_partition.unwrap_or(1).to_string(),
                "-L",
                &options.entry_label,
                "-l",
                "\\EFI\\BOOT\\BOOTX64.EFI",
            ],
        ));
        plan.steps
            .push("add an NVRAM entry for \\EFI\\BOOT\\BOOTX64.EFI".to_owned());
        plan.warnings
            .push("efibootmgr needs the EFI variables of the machine being repaired".to_owned());
    } else {
        plan.warnings.push(
            "no ESP partition number; only the fallback path is repaired, no NVRAM entry is added"
                .to_owned(),
        );
    }
    Ok(())
}

fn plan_bios(disk: &Path, options: &BootRepairOptions, plan: &mut RepairPlan) {
    // The leading region carries `core.img`, so nothing has to be reinstalled
    // unless the layout changed under it.
    if options.layout_changed || options.force_bios_reinstall {
        plan.commands.push(PlannedCommand::new(
            "grub-install",
            ["--target=i386-pc", "--recheck", &disk.display().to_string()],
        ));
        plan.steps.push(
            "reinstall the BIOS bootloader (the layout no longer matches the image's core.img)"
                .to_owned(),
        );
    } else {
        plan.steps.push(
            "the BIOS bootloader arrives with the image's leading region; nothing to reinstall"
                .to_owned(),
        );
    }
}

/// `true` when the device for a partition exists as `/dev/<disk><n>` or
/// `/dev/<disk>p<n>`.
fn partition_device(disk: &Path, partition: u32) -> PathBuf {
    let name = disk
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    // `nvme0n1` and `mmcblk0` take a `p` separator; `sda` and `vda` do not.
    let separator = if name
        .chars()
        .last()
        .is_some_and(|last| last.is_ascii_digit())
    {
        "p"
    } else {
        ""
    };
    disk.with_file_name(format!("{name}{separator}{partition}"))
}

/// Run every command in a plan (spec §H.5).
///
/// # Errors
/// Returns [`Error::Unsupported`] when a command is missing or fails, naming the
/// command and its output.
pub fn apply_boot_repair(plan: &RepairPlan) -> Result<RepairReport> {
    let mut completed = Vec::new();
    let mut output = Vec::new();
    let mut warnings = plan.warnings.clone();
    for command in &plan.commands {
        let result = Command::new(&command.program)
            .args(&command.args)
            .output()
            .map_err(|error| {
                Error::unsupported(format!("{} could not be run: {error}", command.display()))
            })?;
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        if !result.status.success() {
            // The NVRAM entry is a convenience: the fallback path repaired above
            // is what makes the disk boot, and a rescue environment often has no
            // EFI variables at all (a BIOS machine, or a VM started without
            // pflash). Report it instead of failing the whole repair.
            if command.program == "efibootmgr" {
                warnings.push(format!(
                    "{} failed and was skipped: {}",
                    command.display(),
                    text.trim()
                ));
                continue;
            }
            return Err(Error::unsupported(format!(
                "{} failed: {}",
                command.display(),
                text.trim()
            )));
        }
        completed.push(command.display());
        output.push(text);
    }
    Ok(RepairReport {
        plan: plan.clone(),
        completed,
        output,
        warnings,
    })
}

/// One filesystem to recreate for a file-mode restore (spec §K S16).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilesystemSpec {
    /// Partition number the filesystem lives on.
    pub partition: u32,
    /// Filesystem type, as `mkfs` knows it (`ext4`, `xfs`, `vfat`, …).
    pub fs_type: String,
    /// UUID to assign, so `/etc/fstab` and the bootloader keep working.
    pub uuid: Option<String>,
    /// Label to assign.
    pub label: Option<String>,
    /// Mount point, for the report.
    pub mount_point: Option<String>,
}

/// What a layout recreation will do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayoutPlan {
    /// Disk being recreated.
    pub disk: PathBuf,
    /// `sfdisk` dump to apply (spec §K S16).
    pub sfdisk_dump: String,
    /// Filesystems to create.
    pub filesystems: Vec<FilesystemSpec>,
    /// Commands to run, in order.
    pub commands: Vec<PlannedCommand>,
    /// Steps, in the same order as the commands.
    pub steps: Vec<String>,
    /// Non-fatal notes.
    pub warnings: Vec<String>,
}

/// Plan the recreation of a disk's layout and filesystems.
///
/// The partition table comes from a dump taken before the backup (`sfdisk -d`),
/// which is why a file-mode restore of a whole machine can rebuild it even
/// though the image holds only files.
///
/// # Errors
/// Returns [`Error::Corrupt`] when the dump is empty or names no partitions.
pub fn plan_layout_recreation(
    disk: &Path,
    sfdisk_dump: &str,
    filesystems: &[FilesystemSpec],
) -> Result<LayoutPlan> {
    if sfdisk_dump.trim().is_empty() {
        return Err(Error::corrupt("the sfdisk dump is empty"));
    }
    if !sfdisk_dump.contains("label:") {
        return Err(Error::corrupt(
            "the sfdisk dump has no `label:` line; it does not look like `sfdisk -d` output",
        ));
    }
    if !sfdisk_dump.contains('/') && !sfdisk_dump.contains("start=") {
        return Err(Error::corrupt("the sfdisk dump describes no partitions"));
    }
    let mut plan = LayoutPlan {
        disk: disk.to_path_buf(),
        sfdisk_dump: sfdisk_dump.to_owned(),
        filesystems: filesystems.to_vec(),
        commands: Vec::new(),
        steps: Vec::new(),
        warnings: Vec::new(),
    };
    plan.steps
        .push("write the recorded partition table".to_owned());
    plan.commands
        .push(PlannedCommand::new("sfdisk", [&disk.display().to_string()]));
    for filesystem in filesystems {
        let device = partition_device(disk, filesystem.partition);
        plan.steps.push(format!(
            "create {} on partition {} ({})",
            filesystem.fs_type,
            filesystem.partition,
            device.display()
        ));
        plan.commands.push(formatter_command(filesystem, &device)?);
    }
    plan.steps
        .push("reinstall the bootloader and run boot repair".to_owned());
    plan.warnings
        .push("run `linuxreflect-rescue boot-repair` after the filesystems exist".to_owned());
    Ok(plan)
}

/// Filesystem types a layout recreation can create.
pub const SUPPORTED_FILESYSTEMS: &[&str] =
    &["ext2", "ext3", "ext4", "xfs", "btrfs", "vfat", "swap"];

/// The formatter invocation for one filesystem.
///
/// Formatters disagree on flags (`mkfs.fat -F` takes the FAT size, `mkfs.xfs`
/// forces with `-f` and sets the UUID with `-m uuid=`), so each supported type
/// is spelled out; anything else is refused rather than guessed.
fn formatter_command(filesystem: &FilesystemSpec, device: &Path) -> Result<PlannedCommand> {
    let fs_type = filesystem.fs_type.as_str();
    let uuid = filesystem.uuid.as_deref();
    let label = filesystem.label.as_deref();
    if let Some(label) = label {
        validate_label(label)?;
    }
    let mut args: Vec<String> = Vec::new();
    let program = match fs_type {
        "ext2" | "ext3" | "ext4" | "btrfs" => {
            args.extend(
                if fs_type == "btrfs" {
                    ["-f", "-q"]
                } else {
                    ["-F", "-q"]
                }
                .map(String::from),
            );
            if let Some(uuid) = uuid {
                args.extend(["-U".to_owned(), canonical_uuid(uuid)?]);
            }
            if let Some(label) = label {
                args.extend(["-L".to_owned(), label.to_owned()]);
            }
            format!("mkfs.{fs_type}")
        }
        "xfs" => {
            args.extend(["-f", "-q"].map(String::from));
            if let Some(uuid) = uuid {
                args.extend(["-m".to_owned(), format!("uuid={}", canonical_uuid(uuid)?)]);
            }
            if let Some(label) = label {
                args.extend(["-L".to_owned(), label.to_owned()]);
            }
            "mkfs.xfs".to_owned()
        }
        "vfat" => {
            if let Some(uuid) = uuid {
                args.extend(["-i".to_owned(), fat_volume_id(uuid)?]);
            }
            if let Some(label) = label {
                args.extend(["-n".to_owned(), label.to_owned()]);
            }
            "mkfs.fat".to_owned()
        }
        "swap" => {
            if let Some(uuid) = uuid {
                args.extend(["-U".to_owned(), canonical_uuid(uuid)?]);
            }
            if let Some(label) = label {
                args.extend(["-L".to_owned(), label.to_owned()]);
            }
            "mkswap".to_owned()
        }
        other => {
            return Err(Error::unsupported(format!(
                "cannot recreate a `{other}` filesystem; supported: {}",
                SUPPORTED_FILESYSTEMS.join(", ")
            )));
        }
    };
    args.push(device.display().to_string());
    Ok(PlannedCommand::new(program, args))
}

/// A standard UUID (`8-4-4-4-12` hex digits), lowercased.
fn canonical_uuid(text: &str) -> Result<String> {
    let groups: Vec<&str> = text.split('-').collect();
    let well_formed = groups.len() == 5
        && groups
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(group, len)| group.len() == len && group.chars().all(|c| c.is_ascii_hexdigit()));
    if !well_formed {
        return Err(Error::unsupported(format!(
            "`{text}` is not a filesystem UUID"
        )));
    }
    Ok(text.to_ascii_lowercase())
}

/// A FAT volume ID as `blkid` prints it (`1234-ABCD`) turned into the eight
/// hex digits `mkfs.fat -i` expects.
fn fat_volume_id(text: &str) -> Result<String> {
    let digits: String = text.chars().filter(|c| *c != '-').collect();
    if digits.len() != 8 || !digits.chars().all(|c| c.is_ascii_hexdigit()) || text.len() > 9 {
        return Err(Error::unsupported(format!(
            "`{text}` is not a FAT volume ID (expected XXXX-XXXX)"
        )));
    }
    Ok(digits.to_ascii_uppercase())
}

/// Labels are passed as a separate argument, but one starting with `-` would
/// still read as an option to some formatters.
fn validate_label(label: &str) -> Result<()> {
    if label.is_empty() || label.starts_with('-') || label.chars().any(char::is_control) {
        return Err(Error::unsupported(format!(
            "`{label}` cannot be used as a filesystem label"
        )));
    }
    Ok(())
}

/// Capture the facts a later [`apply_layout_recreation`] re-checks.
///
/// # Errors
/// Returns [`Error::Io`] when the disk cannot be inspected.
pub fn capture_target(disk: &Path) -> Result<lr_engine::restore::TargetFacts> {
    lr_engine::restore::TargetFacts::read(disk)
}

/// Write the `sfdisk` dump into `sfdisk`'s stdin, then run the rest.
///
/// Immediately before the first write the disk is re-read and compared with
/// `expected` (the facts the operator reviewed), and it must not be mounted,
/// held, used as swap or back the running system (spec §H.2, §H.3).
///
/// # Errors
/// Returns [`Error::TargetChanged`] when the disk is not the one reviewed,
/// [`Error::TargetBusy`] when it is in use, and [`Error::Unsupported`] when a
/// command is missing or fails.
pub fn apply_layout_recreation(
    plan: &LayoutPlan,
    expected: &lr_engine::restore::TargetFacts,
) -> Result<RepairReport> {
    let current = lr_engine::restore::TargetFacts::read(&plan.disk)?;
    if !current.matches(expected) {
        return Err(Error::TargetChanged);
    }
    lr_engine::target::preflight_target(&plan.disk)?;
    let mut completed = Vec::new();
    let mut output = Vec::new();
    let mut dump_written = false;
    for command in &plan.commands {
        let mut child = Command::new(&command.program);
        child.args(&command.args);
        if command.program == "sfdisk" && !dump_written {
            child.stdin(std::process::Stdio::piped());
        }
        let mut spawned = child.spawn().map_err(|error| {
            Error::unsupported(format!("{} could not be run: {error}", command.display()))
        })?;
        if command.program == "sfdisk" && !dump_written {
            use std::io::Write;
            if let Some(stdin) = spawned.stdin.as_mut() {
                stdin
                    .write_all(plan.sfdisk_dump.as_bytes())
                    .map_err(Error::Io)?;
            }
            dump_written = true;
        }
        let result = spawned.wait_with_output().map_err(Error::Io)?;
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        if !result.status.success() {
            return Err(Error::unsupported(format!(
                "{} failed: {}",
                command.display(),
                text.trim()
            )));
        }
        completed.push(command.display());
        output.push(text);
    }
    Ok(RepairReport {
        plan: RepairPlan {
            disk: plan.disk.clone(),
            firmware: Firmware::Bios,
            esp_partition: None,
            steps: plan.steps.clone(),
            commands: plan.commands.clone(),
            warnings: plan.warnings.clone(),
        },
        completed,
        output,
        warnings: plan.warnings.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        BootRepairOptions, FilesystemSpec, Firmware, plan_boot_repair, plan_layout_recreation,
    };

    #[test]
    fn a_uefi_repair_installs_the_fallback_loader() {
        let dir = tempfile::tempdir().expect("tempdir");
        let esp = dir.path().join("esp");
        std::fs::create_dir_all(&esp).expect("esp");
        let loader = dir.path().join("shim.efi");
        std::fs::write(&loader, b"signed shim").expect("loader");
        let disk = dir.path().join("disk.img");
        std::fs::write(&disk, b"disk").expect("disk");

        let plan = plan_boot_repair(
            &disk,
            &BootRepairOptions {
                firmware: Firmware::Uefi,
                esp_mount: Some(esp.clone()),
                esp_partition: Some(1),
                esp_device: None,
                loader: Some(loader),
                ..BootRepairOptions::default()
            },
        )
        .expect("plan");
        assert!(plan.commands.iter().any(|command| command.program == "cp"));
        assert!(
            plan.commands
                .iter()
                .any(|command| command.program == "efibootmgr")
        );
        assert!(
            plan.steps
                .iter()
                .any(|step| step.contains("EFI/BOOT/BOOTX64.EFI")),
            "{:?}",
            plan.steps
        );
        // An existing fallback loader is left alone: a repair must not fight
        // a working bootloader.
        std::fs::create_dir_all(esp.join("EFI/BOOT")).expect("dirs");
        std::fs::write(esp.join("EFI/BOOT/BOOTX64.EFI"), b"present").expect("write");
        let again = plan_boot_repair(
            &disk,
            &BootRepairOptions {
                firmware: Firmware::Uefi,
                esp_mount: Some(esp),
                esp_partition: Some(1),
                esp_device: None,
                loader: None,
                ..BootRepairOptions::default()
            },
        )
        .expect("plan");
        assert!(!again.commands.iter().any(|command| command.program == "cp"));
    }

    #[test]
    fn uefi_repair_needs_to_know_where_the_esp_is() {
        let dir = tempfile::tempdir().expect("tempdir");
        let disk = dir.path().join("disk.img");
        std::fs::write(&disk, b"disk").expect("disk");
        let error = plan_boot_repair(
            &disk,
            &BootRepairOptions {
                firmware: Firmware::Uefi,
                ..BootRepairOptions::default()
            },
        )
        .expect_err("no ESP");
        assert!(format!("{error}").contains("ESP"), "{error}");
    }

    #[test]
    fn a_bios_repair_only_reinstalls_when_the_layout_changed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let disk = dir.path().join("disk.img");
        std::fs::write(&disk, b"disk").expect("disk");
        let unchanged = plan_boot_repair(
            &disk,
            &BootRepairOptions {
                firmware: Firmware::Bios,
                ..BootRepairOptions::default()
            },
        )
        .expect("plan");
        assert!(unchanged.is_empty(), "the leading region carries core.img");
        let changed = plan_boot_repair(
            &disk,
            &BootRepairOptions {
                firmware: Firmware::Bios,
                layout_changed: true,
                ..BootRepairOptions::default()
            },
        )
        .expect("plan");
        assert_eq!(changed.commands.len(), 1);
        assert_eq!(changed.commands[0].program, "grub-install");
    }

    #[test]
    fn a_layout_plan_recreates_the_table_and_the_filesystems() {
        let dump = "label: gpt\nlabel-id: 0123\n\ndevice: /dev/sda\nunit: sectors\n\n/dev/sda1 : start=2048, size=2048, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, uuid=AAAA\n/dev/sda2 : start=4096, size=204800, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, uuid=BBBB\n";
        let plan = plan_layout_recreation(
            std::path::Path::new("/dev/loop9"),
            dump,
            &[
                FilesystemSpec {
                    partition: 1,
                    fs_type: "vfat".to_owned(),
                    uuid: Some("1234-ABCD".to_owned()),
                    label: Some("ESP".to_owned()),
                    mount_point: Some("/boot/efi".to_owned()),
                },
                FilesystemSpec {
                    partition: 2,
                    fs_type: "ext4".to_owned(),
                    uuid: Some("11111111-2222-3333-4444-555555555555".to_owned()),
                    label: None,
                    mount_point: Some("/".to_owned()),
                },
            ],
        )
        .expect("plan");
        assert_eq!(plan.commands[0].program, "sfdisk");
        let mkfs = plan
            .commands
            .iter()
            .filter(|command| command.program.starts_with("mkfs."))
            .collect::<Vec<_>>();
        assert_eq!(mkfs.len(), 2);
        // `loop9` needs the `p` separator.
        assert!(
            mkfs[0].args.iter().any(|arg| arg == "/dev/loop9p1"),
            "{:?}",
            mkfs[0]
        );
        assert!(
            mkfs[1].args.iter().any(|arg| arg == "-U"),
            "the UUID is preserved so fstab and the bootloader keep working"
        );
    }

    fn one_filesystem(fs_type: &str, uuid: Option<&str>, label: Option<&str>) -> FilesystemSpec {
        FilesystemSpec {
            partition: 1,
            fs_type: fs_type.to_owned(),
            uuid: uuid.map(str::to_owned),
            label: label.map(str::to_owned),
            mount_point: None,
        }
    }

    fn formatter(spec: FilesystemSpec) -> crate::Result<crate::PlannedCommand> {
        let dump = "label: gpt\n\n/dev/sda1 : start=2048, size=2048\n";
        plan_layout_recreation(std::path::Path::new("/dev/sdz"), dump, &[spec])
            .map(|plan| plan.commands[1].clone())
    }

    #[test]
    fn each_formatter_gets_its_own_flags() {
        let uuid = "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0";
        let xfs = formatter(one_filesystem("xfs", Some(uuid), Some("root"))).expect("xfs");
        assert_eq!(xfs.program, "mkfs.xfs");
        assert_eq!(
            xfs.args,
            [
                "-f",
                "-q",
                "-m",
                "uuid=0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
                "-L",
                "root",
                "/dev/sdz1"
            ]
        );
        let fat = formatter(one_filesystem("vfat", Some("1234-abcd"), Some("ESP"))).expect("vfat");
        assert_eq!(fat.program, "mkfs.fat");
        assert_eq!(fat.args, ["-i", "1234ABCD", "-n", "ESP", "/dev/sdz1"]);
        let btrfs = formatter(one_filesystem("btrfs", None, None)).expect("btrfs");
        assert_eq!(btrfs.args, ["-f", "-q", "/dev/sdz1"]);
        let swap = formatter(one_filesystem("swap", Some(uuid), None)).expect("swap");
        assert_eq!(swap.program, "mkswap");
        assert_eq!(swap.args.last().map(String::as_str), Some("/dev/sdz1"));
    }

    #[test]
    fn unknown_or_malformed_filesystems_are_refused() {
        for fs_type in ["ntfs", "../../tmp/x", "ext4 ", ""] {
            let error = formatter(one_filesystem(fs_type, None, None)).expect_err(fs_type);
            assert!(format!("{error}").contains("supported"), "{error}");
        }
        assert!(formatter(one_filesystem("ext4", Some("not-a-uuid"), None)).is_err());
        assert!(formatter(one_filesystem("vfat", Some("12345-ABCD"), None)).is_err());
        assert!(formatter(one_filesystem("ext4", None, Some("-O"))).is_err());
        assert!(formatter(one_filesystem("ext4", None, Some(""))).is_err());
    }

    #[test]
    fn a_bad_sfdisk_dump_is_refused() {
        let error =
            plan_layout_recreation(std::path::Path::new("/dev/loop9"), "", &[]).expect_err("empty");
        assert!(format!("{error}").contains("empty"), "{error}");
        let error = plan_layout_recreation(std::path::Path::new("/dev/loop9"), "hello world", &[])
            .expect_err("not a dump");
        assert!(format!("{error}").contains("label"), "{error}");
        let error = plan_layout_recreation(
            std::path::Path::new("/dev/loop9"),
            "label: gpt\nnothing else\n",
            &[],
        )
        .expect_err("no partitions");
        assert!(format!("{error}").contains("partitions"), "{error}");
    }
}
