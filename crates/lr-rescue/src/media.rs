//! Building the rescue media (spec §K S16).
//!
//! The image is assembled from distribution components: the distribution's
//! *signed* shim and GRUB for the UEFI path (so Secure Boot accepts it), GRUB
//! for the BIOS path, the distribution kernel, and a busybox initramfs that
//! carries the static `linuxreflect` rescue CLI and the TUI. Nothing is
//! downloaded: every input is a path in the running system, which keeps the
//! build offline and auditable.
//!
//! `contrib/rescue/mkosi.conf` describes the same medium for a distribution
//! build that adds the graphical rescue session (`cage` + the GUI); the
//! assembly here is the path this repository builds and boots (D-093).

use std::path::{Path, PathBuf};
use std::process::Command;

use lr_core::{Error, Result};
use serde::{Deserialize, Serialize};

/// Kernel command line the media boots with: serial console (so a headless
/// test can see the marker) and `rescue.auto=1`, which makes the init script
/// run the self check and power off instead of waiting for a human.
pub const RESCUE_CMDLINE: &str = "console=ttyS0 console=tty0 panic=-1 rescue.auto=1";

/// The marker the rescue init script prints once it is ready.
pub const RESCUE_MARKER: &str = "LINUXREFLECT-RESCUE-READY";

/// Largest rescue CLI the medium accepts, in bytes.
///
/// GRUB's BIOS loader cannot hand a very large initramfs to the kernel (a
/// 47 MiB debug-binary initramfs never reached the kernel at all), so the
/// medium ships the release, stripped binary; 24 MiB leaves room for busybox
/// and the TUI and stays well inside the loader's working range.
pub const MAX_RESCUE_CLI_BYTES: u64 = 24 * 1024 * 1024;

/// What to build.
#[derive(Debug, Clone)]
pub struct MediaRequest {
    /// Image file to create.
    pub output: PathBuf,
    /// Total image size in MiB.
    pub size_mib: u64,
    /// Kernel to include.
    pub kernel: PathBuf,
    /// Static rescue CLI to include.
    pub cli: Option<PathBuf>,
    /// Extra files to copy into the rescue root (TUI, docs).
    pub extra: Vec<(PathBuf, PathBuf)>,
    /// Extra kernel command-line arguments (for an unattended rescue run).
    pub cmdline_extra: Vec<String>,
    /// Install GRUB for BIOS machines.
    pub bios: bool,
    /// Install GRUB/shim for UEFI machines.
    pub uefi: bool,
    /// Use the distribution's signed shim and GRUB (Secure Boot).
    pub secure_boot: bool,
}

impl MediaRequest {
    /// A request with the spec's defaults.
    #[must_use]
    pub fn new(output: impl Into<PathBuf>, kernel: impl Into<PathBuf>) -> Self {
        Self {
            output: output.into(),
            size_mib: 512,
            kernel: kernel.into(),
            cli: None,
            extra: Vec::new(),
            cmdline_extra: Vec::new(),
            bios: true,
            uefi: true,
            secure_boot: true,
        }
    }
}

/// What the build produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaReport {
    /// Image that was written.
    pub image: PathBuf,
    /// Image size in bytes.
    pub size_bytes: u64,
    /// Initramfs size in bytes.
    pub initramfs_bytes: u64,
    /// Kernel that was included.
    pub kernel: String,
    /// Files placed in the ESP.
    pub esp_files: Vec<String>,
    /// Human-readable steps that ran.
    pub steps: Vec<String>,
    /// Non-fatal notes.
    pub warnings: Vec<String>,
}

/// Build the rescue image.
///
/// # Errors
/// Returns [`Error::Unsupported`] naming any missing tool or failing command,
/// so a build failure says exactly what to install.
pub fn build_media(request: &MediaRequest) -> Result<MediaReport> {
    let mut steps = Vec::new();
    let mut warnings = Vec::new();
    let mut tools = vec![
        "sgdisk",
        "losetup",
        "mkfs.vfat",
        "mount",
        "umount",
        "cpio",
        "gzip",
    ];
    if request.bios {
        tools.push("grub-install");
    }
    if request.uefi && !request.secure_boot {
        tools.push("grub-mkstandalone");
    }
    for tool in tools {
        if !have(tool) {
            return Err(Error::unsupported(format!(
                "{tool} is missing; install it before building the rescue media"
            )));
        }
    }
    if !request.kernel.exists() {
        return Err(Error::unsupported(format!(
            "{} does not exist",
            request.kernel.display()
        )));
    }
    let signed = Path::new(crate::SHIM_SIGNED).exists() && Path::new(crate::GRUB_SIGNED).exists();
    if request.uefi && request.secure_boot && !signed {
        return Err(Error::unsupported(format!(
            "Secure Boot needs the signed shim ({}) and GRUB ({}); install shim-signed and \
             grub-efi-amd64-signed, or build with secure_boot = false",
            crate::SHIM_SIGNED,
            crate::GRUB_SIGNED
        )));
    }
    if request.uefi && !request.secure_boot {
        warnings.push(
            "the fallback loader is unsigned; the firmware will only accept it with Secure Boot off"
                .to_owned(),
        );
    }

    // 1. The initramfs: busybox, the rescue CLI, the TUI and the init script.
    let initramfs = build_initramfs(request)?;
    let initramfs_size = std::fs::metadata(&initramfs).map_err(Error::Io)?.len();
    steps.push(format!("built a {initramfs_size}-byte initramfs"));

    // 2. The disk image and its partition table.
    let image = std::fs::File::create(&request.output).map_err(Error::Io)?;
    image
        .set_len(request.size_mib * 1024 * 1024)
        .map_err(Error::Io)?;
    drop(image);
    let mut sgdisk = Command::new("sgdisk");
    sgdisk.arg("--clear");
    if request.bios {
        sgdisk.args(["-n", "1:2048:+1M", "-t", "1:ef02", "-c", "1:BIOS"]);
    }
    let esp_start = if request.bios { 4096 } else { 2048 };
    let esp_size = format!("+{}M", request.size_mib.saturating_sub(16).max(64));
    sgdisk.args([
        "-n",
        &format!("2:{esp_start}:{esp_size}"),
        "-t",
        "2:ef00",
        "-c",
        "2:RESCUE",
    ]);
    run(sgdisk.arg(&request.output))?;
    steps.push("created a GPT with a BIOS boot partition and an ESP".to_owned());

    let loop_device = free_loop()?;
    run(Command::new("losetup").args(["-P", &loop_device, &request.output.display().to_string()]))?;
    let esp_device = partition_device(Path::new(&loop_device), 2);
    let cleanup = LoopGuard {
        loop_device: loop_device.clone(),
    };
    // The partition node appears asynchronously; on a busy machine it can take
    // a moment, and `mkfs.vfat` must not race it.
    let mut waited = 0;
    while !esp_device.exists() && waited < 30 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        waited += 1;
    }
    if !esp_device.exists() {
        let _ = Command::new("partx").args(["-u", &loop_device]).status();
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
    if !esp_device.exists() {
        return Err(Error::unsupported(format!(
            "{} did not appear after attaching {}; is the loop module able to scan partitions?",
            esp_device.display(),
            loop_device
        )));
    }
    run(Command::new("mkfs.vfat").args([
        "-F",
        "32",
        "-n",
        "LRRC",
        &esp_device.display().to_string(),
    ]))?;
    steps.push(format!("formatted {} as FAT32", esp_device.display()));

    let mount_root = request
        .output
        .parent()
        .unwrap_or_else(|| Path::new("/tmp"))
        .join("rescue-esp");
    std::fs::create_dir_all(&mount_root).map_err(Error::Io)?;
    run(Command::new("mount").args([
        "-t",
        "vfat",
        &esp_device.display().to_string(),
        &mount_root.display().to_string(),
    ]))?;
    let mut esp_files = Vec::new();
    let result = fill_esp(
        request,
        &initramfs,
        &mount_root,
        &mut esp_files,
        &mut warnings,
    );
    result?;
    steps.push(format!("placed {} file(s) in the ESP", esp_files.len()));

    // 3. GRUB for BIOS: `core.img` goes into the BIOS boot partition and its
    //    modules and config live in the ESP, so the ESP must still be mounted
    //    while `grub-install` runs.
    if request.bios {
        let boot_dir = mount_root.join("boot");
        std::fs::create_dir_all(&boot_dir).map_err(Error::Io)?;
        run(Command::new("grub-install").args([
            "--target=i386-pc",
            "--recheck",
            "--no-nvram",
            "--boot-directory",
            &boot_dir.display().to_string(),
            &loop_device,
        ]))?;
        steps.push("installed GRUB for BIOS (i386-pc)".to_owned());
    }
    let _ = Command::new("umount").arg(&mount_root).status();
    drop(cleanup);
    steps.push("detached the loop device".to_owned());

    let size_bytes = std::fs::metadata(&request.output).map_err(Error::Io)?.len();
    let initramfs_bytes = initramfs_size;
    Ok(MediaReport {
        image: request.output.clone(),
        size_bytes,
        initramfs_bytes,
        kernel: request.kernel.display().to_string(),
        esp_files,
        steps,
        warnings,
    })
}

/// Write the kernel, the initramfs, the bootloader and the GRUB config into the
/// mounted ESP.
fn fill_esp(
    request: &MediaRequest,
    initramfs: &Path,
    mount_root: &Path,
    esp_files: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> Result<()> {
    fn copy(from: &Path, to: &Path, mount_root: &Path, esp_files: &mut Vec<String>) -> Result<()> {
        if let Some(parent) = to.parent() {
            std::fs::create_dir_all(parent).map_err(Error::Io)?;
        }
        std::fs::copy(from, to).map_err(Error::Io)?;
        esp_files.push(
            to.strip_prefix(mount_root)
                .unwrap_or(to)
                .display()
                .to_string(),
        );
        Ok(())
    }
    copy(
        &request.kernel,
        &mount_root.join("vmlinuz"),
        mount_root,
        esp_files,
    )?;
    copy(
        initramfs,
        &mount_root.join("initramfs.cpio.gz"),
        mount_root,
        esp_files,
    )?;

    // GRUB talks to the serial console as well as the screen: a rescue medium
    // is often used headless, and the acceptance test reads what the kernel
    // prints there.
    let extra = request.cmdline_extra.join(" ");
    let extra = if extra.is_empty() {
        String::new()
    } else {
        format!(" {extra}")
    };
    let config = format!(
        "serial --unit=0 --speed=115200\n\
         terminal_input serial console\n\
         terminal_output serial console\n\
         set timeout=3\n\
         menuentry \"LinuxReflect rescue\" {{\n\
         \x20 search --no-floppy --file --set=root /vmlinuz\n\
         \x20 linux /vmlinuz {RESCUE_CMDLINE}{extra}\n\
         \x20 initrd /initramfs.cpio.gz\n\
         \x20 boot\n\
         }}\n"
    );
    for relative in [
        "EFI/BOOT/grub.cfg",
        "EFI/ubuntu/grub.cfg",
        "boot/grub/grub.cfg",
        "grub/grub.cfg",
    ] {
        let path = mount_root.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(Error::Io)?;
        }
        std::fs::write(&path, &config).map_err(Error::Io)?;
        esp_files.push(relative.to_owned());
    }

    if request.uefi {
        if request.secure_boot {
            copy(
                Path::new(crate::SHIM_SIGNED),
                &mount_root.join(crate::EFI_FALLBACK),
                mount_root,
                esp_files,
            )?;
            copy(
                Path::new(crate::GRUB_SIGNED),
                &mount_root.join("EFI/BOOT/grubx64.efi"),
                mount_root,
                esp_files,
            )?;
            warnings.push(
                "Secure Boot: the distribution's signed shim and GRUB are used, so the medium \
                 boots with the firmware's built-in keys"
                    .to_owned(),
            );
        } else {
            let embedded = mount_root.join("grub-embedded.cfg");
            std::fs::write(&embedded, &config).map_err(Error::Io)?;
            run(Command::new("grub-mkstandalone").args([
                "-O",
                "x86_64-efi",
                "--modules=part_gpt fat normal linux search search_fs_file",
                "-o",
                &mount_root.join(crate::EFI_FALLBACK).display().to_string(),
                &format!("boot/grub/grub.cfg={}", embedded.display()),
            ]))?;
            esp_files.push(crate::EFI_FALLBACK.to_owned());
        }
    }
    Ok(())
}

/// Build the initramfs and return its path.
///
/// # Errors
/// Returns [`Error::Unsupported`] when a tool is missing and [`Error::Io`] on
/// filesystem failures.
fn build_initramfs(request: &MediaRequest) -> Result<PathBuf> {
    let work = std::env::temp_dir().join(format!(
        "lr-rescue-init-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_millis())
    ));
    let _ = std::fs::remove_dir_all(&work);
    let tree = work.join("tree");
    for dir in [
        "bin",
        "sbin",
        "proc",
        "sys",
        "dev",
        "etc",
        "mnt",
        "run",
        "tmp",
        "usr/bin",
        "usr/sbin",
        "usr/share/linuxreflect",
    ] {
        std::fs::create_dir_all(tree.join(dir)).map_err(Error::Io)?;
    }
    let busybox = Path::new("/bin/busybox");
    if !busybox.exists() {
        return Err(Error::unsupported("busybox is missing"));
    }
    std::fs::copy(busybox, tree.join("bin/busybox")).map_err(Error::Io)?;
    // Install the applet links so the init script has a real userland. They
    // must be *relative*: `busybox --install` would point them at the build
    // tree, which does not exist inside the initramfs, and the kernel would
    // then refuse to run `/init` because its `#!/bin/sh` cannot be resolved.
    let listing = Command::new(busybox)
        .arg("--list")
        .output()
        .map_err(Error::Io)?;
    if !listing.status.success() {
        return Err(Error::unsupported("busybox --list failed"));
    }
    for applet in String::from_utf8_lossy(&listing.stdout).lines() {
        let applet = applet.trim();
        if applet.is_empty() || applet == "busybox" {
            continue;
        }
        let link = tree.join("bin").join(applet);
        if link.exists() {
            continue;
        }
        std::os::unix::fs::symlink("busybox", &link).map_err(Error::Io)?;
    }
    if let Some(cli) = &request.cli {
        let size = std::fs::metadata(cli).map_err(Error::Io)?.len();
        if size > MAX_RESCUE_CLI_BYTES {
            return Err(Error::unsupported(format!(
                "{} is {} MiB; the rescue CLI must be the release, stripped build ({} MiB or \
                 less), otherwise the initramfs is too large for the BIOS loader",
                cli.display(),
                size / (1024 * 1024),
                MAX_RESCUE_CLI_BYTES / (1024 * 1024)
            )));
        }
        std::fs::copy(cli, tree.join("bin/linuxreflect")).map_err(Error::Io)?;
        let _ = std::fs::set_permissions(
            tree.join("bin/linuxreflect"),
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        );
    }
    let tui = tree.join("usr/bin/rescue-tui");
    std::fs::write(&tui, crate::TUI_SCRIPT).map_err(Error::Io)?;
    let _ = std::fs::set_permissions(&tui, std::os::unix::fs::PermissionsExt::from_mode(0o755));
    for (from, to) in &request.extra {
        let target = tree.join(to.strip_prefix("/").unwrap_or(to));
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(Error::Io)?;
        }
        std::fs::copy(from, &target).map_err(Error::Io)?;
    }
    std::fs::write(tree.join("init"), crate::INIT_SCRIPT).map_err(Error::Io)?;
    let _ = std::fs::set_permissions(
        tree.join("init"),
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    );

    let archive = work.join("initramfs.cpio.gz");
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "cd {} && find . | cpio -o -H newc 2>/dev/null | gzip -9 > {}",
            tree.display(),
            archive.display()
        ))
        .output()
        .map_err(Error::Io)?;
    if !output.status.success() {
        return Err(Error::unsupported(format!(
            "building the initramfs failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(archive)
}

fn have(program: &str) -> bool {
    Command::new("which")
        .arg(program)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn run(command: &mut Command) -> Result<()> {
    let output = command
        .output()
        .map_err(|error| Error::unsupported(format!("{command:?} could not be run: {error}")))?;
    if !output.status.success() {
        return Err(Error::unsupported(format!(
            "{command:?} failed: {}",
            format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
            .trim()
        )));
    }
    Ok(())
}

fn free_loop() -> Result<String> {
    let output = Command::new("losetup")
        .arg("-f")
        .output()
        .map_err(Error::Io)?;
    if !output.status.success() {
        return Err(Error::unsupported("no free loop device"));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn partition_device(disk: &Path, partition: u32) -> PathBuf {
    let name = disk
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
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

/// Detaches the loop device when the build finishes (also on a failure).
struct LoopGuard {
    loop_device: String,
}

impl Drop for LoopGuard {
    fn drop(&mut self) {
        let _ = Command::new("losetup")
            .args(["-d", &self.loop_device])
            .status();
    }
}

#[cfg(test)]
mod tests {
    use super::{MediaRequest, RESCUE_CMDLINE, RESCUE_MARKER, have};

    #[test]
    fn the_request_defaults_cover_both_firmwares() {
        let request = MediaRequest::new("/tmp/rescue.img", "/boot/vmlinuz-test");
        assert!(request.bios);
        assert!(request.uefi);
        assert!(request.secure_boot);
        assert_eq!(request.size_mib, 512);
        assert!(RESCUE_CMDLINE.contains("console=ttyS0"));
        assert!(RESCUE_CMDLINE.contains("rescue.auto=1"));
        assert!(RESCUE_MARKER.contains("RESCUE-READY"));
    }

    #[test]
    fn a_missing_tool_is_named() {
        if have("sgdisk") {
            eprintln!("sgdisk is installed; the missing-tool path is exercised by the root test");
            return;
        }
        let error = super::build_media(&MediaRequest::new("/tmp/rescue.img", "/boot/vmlinuz"))
            .expect_err("no tools");
        assert!(format!("{error}").contains("missing"), "{error}");
    }
}
