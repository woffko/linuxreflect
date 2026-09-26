//! Rescue-media and boot-repair acceptance (spec §K S16).
//!
//! Three real end-to-end checks on this machine:
//!
//! * the assembled rescue image boots under **SeaBIOS** and under **OVMF with
//!   Secure Boot** (the distribution's signed shim/GRUB are what make the
//!   latter work), and an *unsigned* loader is rejected by the same firmware —
//!   the control that proves Secure Boot was really enforcing;
//! * a disk whose UEFI loader was destroyed by a restore boots again after
//!   `boot-repair` puts the fallback loader back;
//! * a `sfdisk -d` dump recreated on a fresh disk produces the same partition
//!   UUIDs and filesystem UUIDs, which is what lets a file-mode restore keep
//!   `/etc/fstab` and the bootloader working.
//!
//! Everything needs root, loop devices, qemu and OVMF, so the tests are
//! `#[ignore]`d and gated behind `LR_ROOT_TESTS=1`.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use lr_rescue::media::{MediaRequest, RESCUE_MARKER, build_media};
use lr_rescue::{
    BootRepairOptions, FilesystemSpec, Firmware, apply_boot_repair, plan_boot_repair,
    plan_layout_recreation,
};

const OVMF_CODE: &str = "/usr/share/OVMF/OVMF_CODE_4M.fd";
const OVMF_CODE_SECBOOT: &str = "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd";
const OVMF_VARS_MS: &str = "/usr/share/OVMF/OVMF_VARS_4M.ms.fd";
const SHIM_SIGNED: &str = "/usr/lib/shim/shimx64.efi.signed";
const GRUB_SIGNED: &str = "/usr/lib/grub/x86_64-efi-signed/grubx64.efi.signed";

fn root_tests_enabled() -> bool {
    if std::env::var("LR_ROOT_TESTS").as_deref() != Ok("1") {
        lr_testkit::unavailable!(return false; "LR_ROOT_TESTS != 1");
    }
    let uid = Command::new("id")
        .arg("-u")
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .unwrap_or_default();
    if uid != "0" {
        lr_testkit::unavailable!(return false; "not running as root (uid {uid})");
    }
    true
}

fn have(program: &str) -> bool {
    Command::new("which")
        .arg(program)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn run(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// The newest kernel the machine has.
fn kernel() -> Option<PathBuf> {
    let mut kernels: Vec<PathBuf> = std::fs::read_dir("/boot")
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("vmlinuz-"))
        })
        .collect();
    kernels.sort();
    kernels.pop()
}

/// The static rescue CLI: the release, stripped musl build the medium ships.
fn rescue_cli() -> Option<PathBuf> {
    let release = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/x86_64-unknown-linux-musl/release");
    for name in ["linuxreflect.stripped", "linuxreflect"] {
        let path = release.join(name);
        if path.exists() {
            return Some(path);
        }
    }
    None
}

/// Boot `disk` and return the serial log.
fn boot(disk: &Path, uefi: bool, secure_boot: bool, work: &Path, label: &str) -> String {
    let serial = work.join(format!("serial-{label}.log"));
    let _ = std::fs::remove_file(&serial);
    let mut command = Command::new("qemu-system-x86_64");
    // Hardware virtualisation makes the boots take a second instead of
    // minutes; without it the harness's own CPU load can starve the VM.
    if Path::new("/dev/kvm").exists() {
        command.args(["-enable-kvm", "-cpu", "host"]);
    }
    command
        .args(["-m", "1024", "-smp", "2", "-display", "none", "-no-reboot"])
        .arg("-serial")
        .arg(format!("file:{}", serial.display()))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if uefi {
        let vars = work.join(format!("vars-{label}.fd"));
        let code = if secure_boot {
            OVMF_CODE_SECBOOT
        } else {
            OVMF_CODE
        };
        let vars_template = if secure_boot { OVMF_VARS_MS } else { OVMF_CODE };
        if secure_boot {
            std::fs::copy(OVMF_VARS_MS, &vars).expect("copy OVMF vars");
        } else {
            let _ = std::fs::copy("/usr/share/OVMF/OVMF_VARS_4M.fd", &vars);
        }
        let _ = vars_template;
        command
            .args(["-machine", "q35"])
            .arg("-drive")
            .arg(format!("if=pflash,format=raw,readonly=on,file={code}"))
            .arg("-drive")
            .arg(format!("if=pflash,format=raw,file={}", vars.display()));
    }
    let mut child: Child = command
        .arg("-drive")
        .arg(format!(
            "file={},format=raw,index=0,media=disk",
            disk.display()
        ))
        .spawn()
        .expect("start qemu");
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        if let Ok(text) = std::fs::read_to_string(&serial)
            && (text.contains(RESCUE_MARKER) || text.contains("Kernel panic"))
        {
            break;
        }
        if Instant::now() > deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    let _ = child.kill();
    let _ = child.wait();
    std::fs::read_to_string(&serial).unwrap_or_default()
}

#[test]
#[ignore = "requires root, qemu, OVMF and the grub tooling"]
fn the_rescue_media_boots_on_seabios_and_with_secure_boot() {
    if !root_tests_enabled() {
        return;
    }
    for tool in [
        "qemu-system-x86_64",
        "sgdisk",
        "mkfs.vfat",
        "grub-install",
        "cpio",
    ] {
        if !have(tool) {
            lr_testkit::unavailable!("{tool} missing");
        }
    }
    for file in [OVMF_CODE_SECBOOT, OVMF_VARS_MS, SHIM_SIGNED, GRUB_SIGNED] {
        if !Path::new(file).exists() {
            lr_testkit::unavailable!("{file} missing");
        }
    }
    let Some(kernel) = kernel() else {
        lr_testkit::unavailable!("no /boot/vmlinuz-* found");
    };
    // A stable directory (not a temporary one) so a failure leaves the images
    // and the serial logs behind for inspection.
    let work_path = std::env::temp_dir()
        .join("linuxreflect-s16-media-test")
        .join(format!("run-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work_path);
    std::fs::create_dir_all(&work_path).expect("work dir");
    let work = work_path.clone();

    // The signed medium: Secure Boot's built-in keys accept shim, shim accepts
    // the signed GRUB, GRUB loads the kernel.
    let signed = work.join("rescue-signed.img");
    let mut request = MediaRequest::new(&signed, &kernel);
    request.cli = rescue_cli();
    request.size_mib = 256;
    let report = build_media(&request).expect("build the rescue medium");
    assert!(report.initramfs_bytes > 0);
    assert!(!report.esp_files.is_empty(), "{report:?}");

    let seabios = boot(&signed, false, false, &work, "seabios");
    assert!(
        seabios.contains(RESCUE_MARKER),
        "the medium did not boot under SeaBIOS (image {}, log {}):\n{seabios}",
        signed.display(),
        work.join("serial-seabios.log").display()
    );
    assert!(
        seabios.contains("LINUXREFLECT-RESCUE-SELFTEST-OK"),
        "the rescue init script did not finish its self check:\n{seabios}"
    );

    let secure = boot(&signed, true, true, &work, "secure");
    assert!(
        secure.contains(RESCUE_MARKER),
        "the medium did not boot with Secure Boot on:\n{secure}"
    );

    // The control: an unsigned loader must be refused by the same firmware,
    // which proves the Secure Boot run above was really enforcing.
    let unsigned = work.join("rescue-unsigned.img");
    let mut request = MediaRequest::new(&unsigned, &kernel);
    request.secure_boot = false;
    request.bios = false;
    let _ = build_media(&request).expect("build the unsigned medium");
    let refused = boot(&unsigned, true, true, &work, "unsigned");
    assert!(
        !refused.contains(RESCUE_MARKER),
        "an unsigned loader booted with Secure Boot on:\n{refused}"
    );
}

#[test]
#[ignore = "requires root, loop devices, qemu and OVMF"]
fn a_restored_esp_boots_again_after_boot_repair() {
    if !root_tests_enabled() {
        return;
    }
    for tool in [
        "qemu-system-x86_64",
        "sgdisk",
        "mkfs.vfat",
        "mkfs.ext4",
        "losetup",
    ] {
        if !have(tool) {
            lr_testkit::unavailable!("{tool} missing");
        }
    }
    if !Path::new(OVMF_CODE).exists() {
        lr_testkit::unavailable!("OVMF missing");
    }
    let Some(kernel) = kernel() else {
        lr_testkit::unavailable!("no /boot/vmlinuz-* found");
    };
    let work = tempfile::tempdir().expect("workdir");

    // A rescue medium that also serves as the "restored system" for this test:
    // its ESP carries shim/GRUB/kernel, exactly like a restored machine's.
    let image = work.path().join("restored.img");
    let mut request = MediaRequest::new(&image, &kernel);
    request.cli = rescue_cli();
    request.size_mib = 256;
    request.bios = false;
    if build_media(&request).is_err() {
        lr_testkit::fixture_failed!("could not build the fixture medium");
    }

    // Destroy the fallback loader: this is the state a restore that only wrote
    // partition payloads leaves behind on a UEFI machine.
    let loop_device = String::from_utf8_lossy(
        &Command::new("losetup")
            .arg("-f")
            .output()
            .expect("losetup -f")
            .stdout,
    )
    .trim()
    .to_owned();
    assert!(run(
        "losetup",
        &["-P", &loop_device, &image.display().to_string()]
    ));
    let esp_device = format!("{loop_device}p2");
    let mount = work.path().join("esp-mount");
    std::fs::create_dir_all(&mount).expect("mount dir");
    assert!(run(
        "mount",
        &["-t", "vfat", &esp_device, &mount.display().to_string()]
    ));
    assert!(run(
        "rm",
        &[
            "-f",
            &mount.join("EFI/BOOT/BOOTX64.EFI").display().to_string()
        ]
    ));
    let _ = run("umount", &[&mount.display().to_string()]);

    // Repair it with the tool the rescue medium ships. The disk is a file, so
    // the ESP is named by its loop device.
    let plan = plan_boot_repair(
        Path::new(&image),
        &BootRepairOptions {
            firmware: Firmware::Uefi,
            esp_mount: None,
            esp_partition: Some(2),
            esp_device: Some(PathBuf::from(&esp_device)),
            loader: None,
            entry_label: "LinuxReflect".to_owned(),
            force_bios_reinstall: false,
            layout_changed: false,
        },
    )
    .expect("plan the repair");
    assert!(
        plan.steps.iter().any(|step| step.contains("install")),
        "{plan:?}"
    );
    let report = apply_boot_repair(&plan).expect("apply the repair");
    assert!(!report.completed.is_empty(), "{report:?}");
    let _ = run("losetup", &["-d", &loop_device]);
    let _ = run("umount", &["/run/linuxreflect/esp"]);

    let serial = boot(&image, true, false, work.path(), "repaired");
    assert!(
        serial.contains(RESCUE_MARKER),
        "the repaired disk did not boot:\n{serial}"
    );
}

#[test]
#[ignore = "requires root and loop devices"]
fn recreating_a_layout_keeps_the_partition_and_filesystem_uuids() {
    if !root_tests_enabled() {
        return;
    }
    for tool in [
        "sgdisk",
        "sfdisk",
        "mkfs.ext4",
        "blkid",
        "losetup",
        "wipefs",
    ] {
        if !have(tool) {
            lr_testkit::unavailable!("{tool} missing");
        }
    }
    let work = tempfile::tempdir().expect("workdir");
    let image = work.path().join("layout.img");
    let file = std::fs::File::create(&image).expect("create");
    file.set_len(256 * 1024 * 1024).expect("size");
    drop(file);
    let loop_device = String::from_utf8_lossy(
        &Command::new("losetup")
            .arg("-f")
            .output()
            .expect("losetup -f")
            .stdout,
    )
    .trim()
    .to_owned();
    assert!(run(
        "losetup",
        &["-P", &loop_device, &image.display().to_string()]
    ));
    assert!(run(
        "sgdisk",
        &[
            "--clear",
            "-n",
            "1:2048:+32M",
            "-t",
            "1:8300",
            "-c",
            "1:DATA",
            &loop_device,
        ]
    ));
    let partition = format!("{loop_device}p1");
    assert!(run("mkfs.ext4", &["-F", "-q", "-L", "DATA", &partition]));

    // Record the layout and the filesystem UUID before wiping it.
    let dump = String::from_utf8_lossy(
        &Command::new("sfdisk")
            .args(["-d", &loop_device])
            .output()
            .expect("sfdisk -d")
            .stdout,
    )
    .into_owned();
    let uuid_line = String::from_utf8_lossy(
        &Command::new("blkid")
            .args(["-s", "UUID", "-o", "value", &partition])
            .output()
            .expect("blkid")
            .stdout,
    )
    .trim()
    .to_owned();
    assert!(!uuid_line.is_empty(), "the filesystem must have a UUID");
    let partition_uuid = String::from_utf8_lossy(
        &Command::new("sfdisk")
            .args(["--part-uuid", &loop_device, "1"])
            .output()
            .unwrap_or_else(|_| Command::new("true").output().expect("true"))
            .stdout,
    )
    .trim()
    .to_owned();

    // Destroy the table and the filesystem: this is a bare disk.
    let _ = run("umount", &[&partition]);
    assert!(run("wipefs", &["-a", &loop_device]));

    // Recreate it from the dump with the recorded UUIDs.
    let plan = plan_layout_recreation(
        Path::new(&loop_device),
        &dump,
        &[FilesystemSpec {
            partition: 1,
            fs_type: "ext4".to_owned(),
            uuid: Some(uuid_line.clone()),
            label: Some("DATA".to_owned()),
            mount_point: Some("/".to_owned()),
        }],
    )
    .expect("plan the recreation");
    let reviewed = lr_rescue::capture_target(Path::new(&loop_device)).expect("target facts");
    let report =
        lr_rescue::apply_layout_recreation(&plan, &reviewed).expect("apply the recreation");
    assert!(!report.completed.is_empty(), "{report:?}");

    let recreated = String::from_utf8_lossy(
        &Command::new("blkid")
            .args(["-s", "UUID", "-o", "value", &partition])
            .output()
            .expect("blkid")
            .stdout,
    )
    .trim()
    .to_owned();
    assert_eq!(
        recreated, uuid_line,
        "the filesystem UUID must survive so /etc/fstab keeps working"
    );
    if !partition_uuid.is_empty() {
        let recreated_part = String::from_utf8_lossy(
            &Command::new("sfdisk")
                .args(["--part-uuid", &loop_device, "1"])
                .output()
                .expect("sfdisk --part-uuid")
                .stdout,
        )
        .trim()
        .to_owned();
        assert_eq!(
            recreated_part, partition_uuid,
            "the partition UUID must survive so the bootloader entries keep working"
        );
    }
    let _ = run("losetup", &["-d", &loop_device]);
}

/// A layout recreation writes nothing when the disk changed after the plan was
/// reviewed (`E_TARGET_CHANGED`) or when one of its partitions is mounted.
#[test]
#[ignore = "requires root and loop devices"]
fn recreating_a_layout_refuses_a_changed_or_busy_disk() {
    if !root_tests_enabled() {
        return;
    }
    for tool in ["losetup", "sgdisk", "sfdisk", "mkfs.ext4", "mount"] {
        assert!(have(tool), "{tool} is required");
    }
    let work = tempfile::tempdir().expect("workdir");
    let image = work.path().join("guarded.img");
    let file = std::fs::File::create(&image).expect("create");
    file.set_len(64 * 1024 * 1024).expect("size");
    drop(file);
    let loop_device = attach_loop(&image).expect("attach a loop device");
    assert!(run(
        "sgdisk",
        &["--clear", "-n", "1:2048:+16M", "-t", "1:8300", &loop_device]
    ));
    let partition = format!("{loop_device}p1");
    assert!(run("mkfs.ext4", &["-F", "-q", &partition]));
    let dump = String::from_utf8_lossy(
        &Command::new("sfdisk")
            .args(["-d", &loop_device])
            .output()
            .expect("sfdisk -d")
            .stdout,
    )
    .into_owned();
    let plan = plan_layout_recreation(
        Path::new(&loop_device),
        &dump,
        &[FilesystemSpec {
            partition: 1,
            fs_type: "ext4".to_owned(),
            uuid: None,
            label: None,
            mount_point: None,
        }],
    )
    .expect("plan");
    let first_mib = || {
        let mut bytes = vec![0_u8; 1024 * 1024];
        use std::io::Read;
        std::fs::File::open(&loop_device)
            .expect("open")
            .read_exact(&mut bytes)
            .expect("read");
        bytes
    };

    // Changed after review: the first megabyte no longer matches.
    let reviewed = lr_rescue::capture_target(Path::new(&loop_device)).expect("facts");
    assert!(run(
        "sgdisk",
        &["-n", "2:0:+8M", "-t", "2:8300", &loop_device]
    ));
    let before = first_mib();
    let error = lr_rescue::apply_layout_recreation(&plan, &reviewed).expect_err("changed");
    assert!(
        matches!(error, lr_core::Error::TargetChanged),
        "expected E_TARGET_CHANGED, got {error}"
    );
    assert_eq!(first_mib(), before, "a refused recreation must not write");

    // Busy: a mounted partition is never reformatted.
    let mountpoint = work.path().join("mnt");
    std::fs::create_dir(&mountpoint).expect("mountpoint");
    assert!(run(
        "mount",
        &[&partition, &mountpoint.display().to_string()]
    ));
    std::fs::write(mountpoint.join("keep.txt"), b"still here").expect("write");
    let reviewed = lr_rescue::capture_target(Path::new(&loop_device)).expect("facts");
    let error = lr_rescue::apply_layout_recreation(&plan, &reviewed).expect_err("busy");
    assert!(
        matches!(error, lr_core::Error::TargetBusy { .. }),
        "expected E_TARGET_BUSY, got {error}"
    );
    assert_eq!(
        std::fs::read(mountpoint.join("keep.txt")).expect("read back"),
        b"still here"
    );
    assert!(run("umount", &[&mountpoint.display().to_string()]));
    detach_loop(&loop_device);
}

/// Attach a sparse image to the first free loop device.
fn attach_loop(image: &Path) -> Option<String> {
    let free = Command::new("losetup")
        .arg("-f")
        .output()
        .expect("run losetup -f");
    let device = String::from_utf8_lossy(&free.stdout).trim().to_owned();
    if device.is_empty() || !run("losetup", &["-P", &device, &image.display().to_string()]) {
        lr_testkit::fixture_failed!("could not attach {} to a loop device", image.display());
    }
    Some(device)
}

fn detach_loop(device: &str) {
    let _ = run("losetup", &["-d", device]);
}

/// Recursively copy `from` into `to` (directories, files and symlinks).
fn copy_tree(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        let kind = entry.file_type()?;
        if kind.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

/// The single `.lrimg` below `root`.
fn find_image(root: &Path) -> Option<PathBuf> {
    for entry in std::fs::read_dir(root).ok()? {
        let path = entry.ok()?.path();
        if path.is_dir() {
            if let Some(found) = find_image(&path) {
                return Some(found);
            }
        } else if path.extension().is_some_and(|ext| ext == "lrimg") {
            return Some(path);
        }
    }
    None
}

#[test]
#[ignore = "requires root, qemu, OVMF, grub, loop devices and the static CLI"]
fn a_bare_metal_restore_from_the_medium_boots() {
    if !root_tests_enabled() {
        return;
    }
    for tool in [
        "qemu-system-x86_64",
        "sgdisk",
        "mkfs.vfat",
        "mkfs.ext4",
        "losetup",
        "mount",
        "umount",
        "grub-install",
        "timeout",
    ] {
        if !have(tool) {
            lr_testkit::unavailable!("{tool} missing");
        }
    }
    let Some(kernel) = kernel() else {
        lr_testkit::unavailable!("no /boot/vmlinuz-* found");
    };
    let Some(cli) = rescue_cli() else {
        lr_testkit::unavailable!("the static rescue CLI is not built");
    };
    let work = tempfile::tempdir().expect("workdir");
    let secret = work.path().join("token.key");
    // A previous run may have left the shared ESP mount behind; that makes the
    // medium build fail, which must not silently turn into a skip.
    let _ = run("umount", &["/run/linuxreflect/esp"]);

    // A bootable "machine" to back up: the assembled rescue medium is a real
    // GPT disk with the signed chain, a kernel and the rescue system.
    let source = work.path().join("source.img");
    let mut request = MediaRequest::new(&source, &kernel);
    request.cli = Some(cli.clone());
    request.size_mib = 256;
    if let Err(error) = build_media(&request) {
        lr_testkit::fixture_failed!("could not build the source machine: {error}");
    }

    // Back it up whole-disk.
    let backups = work.path().join("backups");
    std::fs::create_dir_all(&backups).expect("backups");
    let Some(source_loop) = attach_loop(&source) else {
        lr_testkit::fixture_failed!("could not attach the source");
    };
    let backed_up = Command::new(&cli)
        .args([
            "backup",
            "create",
            "--source",
            &source_loop,
            "--dest",
            &backups.display().to_string(),
            "--set",
            "bare",
            "--mode",
            "block",
            "--no-encrypt",
            "--compress",
            "none",
        ])
        .env("LR_TOKEN_SECRET_FILE", &secret)
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    detach_loop(&source_loop);
    assert!(backed_up, "the whole-disk backup failed");
    let image = find_image(&backups).expect("an image");
    let relative = image.strip_prefix(&backups).expect("relative");

    // Put the image on its own small filesystem so the medium can mount it.
    let backup_disk = work.path().join("backup.img");
    let file = std::fs::File::create(&backup_disk).expect("backup disk");
    file.set_len(64 * 1024 * 1024).expect("size");
    drop(file);
    let Some(backup_loop) = attach_loop(&backup_disk) else {
        lr_testkit::fixture_failed!("could not attach the backup disk");
    };
    assert!(run("mkfs.ext4", &["-q", "-F", &backup_loop]), "mkfs.ext4");
    let backup_mount = work.path().join("backup-mnt");
    std::fs::create_dir_all(&backup_mount).expect("mount point");
    assert!(run(
        "mount",
        &[&backup_loop, &backup_mount.display().to_string()]
    ));
    copy_tree(&backups, &backup_mount).expect("copy the image");
    let _ = run("sync", &[]);
    assert!(run("umount", &[&backup_mount.display().to_string()]));
    detach_loop(&backup_loop);

    // A bare target disk of the same size.
    let target = work.path().join("target.img");
    let file = std::fs::File::create(&target).expect("target disk");
    file.set_len(256 * 1024 * 1024).expect("size");
    drop(file);

    // The rescue medium that performs the restore without a human.
    let rescue = work.path().join("rescue.img");
    let mut request = MediaRequest::new(&rescue, &kernel);
    request.cli = Some(cli.clone());
    request.size_mib = 256;
    request.cmdline_extra = vec![
        "linuxreflect.autorun=1".to_owned(),
        "linuxreflect.backup=/dev/vdb".to_owned(),
        format!("linuxreflect.image=/mnt/backup/{}", relative.display()),
        "linuxreflect.target=/dev/vdc".to_owned(),
    ];
    if let Err(error) = build_media(&request) {
        lr_testkit::fixture_failed!("could not build the rescue medium: {error}");
    }

    let serial = work.path().join("autorun.log");
    let status = Command::new("timeout")
        .args([
            "420",
            "qemu-system-x86_64",
            "-enable-kvm",
            "-cpu",
            "host",
            "-m",
            "1024",
            "-smp",
            "2",
            "-display",
            "none",
            "-no-reboot",
        ])
        .arg("-serial")
        .arg(format!("file:{}", serial.display()))
        .args([
            "-drive",
            &format!(
                "file={},format=raw,if=virtio,index=0,readonly=on",
                rescue.display()
            ),
            "-drive",
            &format!(
                "file={},format=raw,if=virtio,index=1,readonly=on",
                backup_disk.display()
            ),
            "-drive",
            &format!("file={},format=raw,if=virtio,index=2", target.display()),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let _ = status;
    let log = std::fs::read_to_string(&serial).unwrap_or_default();
    assert!(
        log.contains("LINUXREFLECT-AUTORUN-RESTORED"),
        "the medium did not restore the bare disk:\n{log}"
    );

    // The restored disk boots like the machine it came from.
    let booted = boot(&target, false, false, work.path(), "bare-metal");
    assert!(
        booted.contains("LINUXREFLECT-RESCUE-SELFTEST-OK"),
        "the restored bare disk did not boot:\n{booted}"
    );
}
