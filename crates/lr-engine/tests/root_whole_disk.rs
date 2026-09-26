//! S7 acceptance: a bootable whole disk is imaged, restored to a larger disk
//! and still boots — under SeaBIOS and under OVMF (spec §K S7).
//!
//! Run with:
//!
//! ```text
//! LR_ROOT_TESTS=1 sudo -E cargo test -p lr-engine --test root_whole_disk -- --ignored --nocapture --test-threads=1
//! ```
//!
//! The fixture is a real GPT disk with a `bios_grub` partition, an ESP holding
//! GRUB, the kernel and a busybox initramfs. Booting it prints `LRBOOT-OK` on
//! the serial console, which is the deterministic success signal (see D-030).

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use lr_engine::backup::{BackupRequest, Compression};
use lr_engine::keys::Encryption;
use lr_engine::restore::{ApplyRequest, PrepareRequest, apply_restore, prepare_restore};
use lr_engine::{ImageReport, backup_image};

const SRC_SIZE: u64 = 512 * 1024 * 1024;
const DST_SIZE: u64 = 1024 * 1024 * 1024;
const CHUNK_SIZE: u32 = 1024 * 1024;
const BOOT_MARKER: &str = "LRBOOT-OK";
const BOOT_TIMEOUT: Duration = Duration::from_secs(90);

const OVMF_CODE: &str = "/usr/share/OVMF/OVMF_CODE_4M.fd";
const OVMF_VARS: &str = "/usr/share/OVMF/OVMF_VARS_4M.fd";

fn root_tests_enabled() -> bool {
    if std::env::var("LR_ROOT_TESTS").as_deref() != Ok("1") {
        lr_testkit::unavailable!(return false; "LR_ROOT_TESTS != 1 - root test");
    }
    let uid = Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default();
    if uid != "0" {
        lr_testkit::unavailable!(return false; "not running as root (uid {uid}) - root test");
    }
    true
}

fn have(program: &str) -> bool {
    Command::new("which")
        .arg(program)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn run(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn output(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .output()
        .map(|o| {
            format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            )
        })
        .unwrap_or_default()
}

fn sparse(path: &Path, size: u64) {
    let file = std::fs::File::create(path).expect("create");
    file.set_len(size).expect("size");
    drop(file);
}

struct LoopDisk {
    device: PathBuf,
    backing: PathBuf,
    _dir: tempfile::TempDir,
}

impl LoopDisk {
    fn attach(dir: &Path, name: &str, size: u64) -> Option<Self> {
        let backing = dir.join(name);
        sparse(&backing, size);
        let free = Command::new("losetup")
            .arg("-f")
            .output()
            .expect("run losetup -f");
        if !free.status.success() {
            lr_testkit::fixture_failed!("losetup -f found no free loop device");
        }
        let device = PathBuf::from(String::from_utf8_lossy(&free.stdout).trim().to_owned());
        if !run(
            "losetup",
            &[
                "-P",
                &device.display().to_string(),
                &backing.display().to_string(),
            ],
        ) {
            lr_testkit::fixture_failed!("losetup could not attach {}", backing.display());
        }
        Some(Self {
            device,
            backing,
            _dir: tempfile::tempdir_in(dir).expect("tempdir"),
        })
    }

    fn partition(&self, index: u32) -> PathBuf {
        PathBuf::from(format!("{}p{index}", self.device.display()))
    }

    fn label(&self) -> String {
        self.device.display().to_string()
    }
}

impl Drop for LoopDisk {
    fn drop(&mut self) {
        let _ = run("losetup", &["-d", &self.device.display().to_string()]);
        let _ = &self.backing;
    }
}

/// Lay out a bootable GPT disk and install GRUB for BIOS and UEFI.
fn build_bootable_disk(disk: &LoopDisk, work: &Path) -> bool {
    for tool in [
        "sgdisk",
        "mkfs.vfat",
        "mkfs.ext4",
        "grub-install",
        "cpio",
        "gzip",
    ] {
        if !have(tool) {
            lr_testkit::unavailable!(return false; "{tool} missing - the boot test");
        }
    }
    let label = disk.label();
    if !run(
        "sgdisk",
        &[
            "--clear",
            "-n",
            "1:2048:+1M",
            "-t",
            "1:ef02",
            "-c",
            "1:BIOS",
            "-n",
            "2:0:+256M",
            "-t",
            "2:ef00",
            "-c",
            "2:ESP",
            "-n",
            "3:0:+200M",
            "-t",
            "3:8300",
            "-c",
            "3:ROOT",
            &label,
        ],
    ) {
        lr_testkit::fixture_failed!("sgdisk failed");
    }
    // Re-read the table so the partition nodes appear.
    let _ = run("blockdev", &["--rereadpt", &label]);
    let _ = run("partx", &["-a", &label]);
    for _ in 0..50 {
        if disk.partition(2).exists() && disk.partition(3).exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    if !run(
        "mkfs.vfat",
        &[
            "-F",
            "32",
            "-n",
            "ESP",
            &disk.partition(2).display().to_string(),
        ],
    ) {
        lr_testkit::fixture_failed!("mkfs.vfat failed");
    }
    if !run(
        "mkfs.ext4",
        &[
            "-F",
            "-q",
            "-L",
            "ROOT",
            &disk.partition(3).display().to_string(),
        ],
    ) {
        lr_testkit::fixture_failed!("mkfs.ext4 failed");
    }

    // ESP contents: kernel, initramfs and grub.cfg (GRUB reads them from FAT
    // without needing an ext4 driver).
    let esp = work.join("esp");
    let root = work.join("root");
    std::fs::create_dir_all(&esp).expect("esp dir");
    std::fs::create_dir_all(&root).expect("root dir");
    if !run(
        "mount",
        &[
            &disk.partition(2).display().to_string(),
            &esp.display().to_string(),
        ],
    ) {
        lr_testkit::fixture_failed!("mounting the ESP failed");
    }
    if !run(
        "mount",
        &[
            &disk.partition(3).display().to_string(),
            &root.display().to_string(),
        ],
    ) {
        let _ = run("umount", &[&esp.display().to_string()]);
        lr_testkit::fixture_failed!("mounting the root partition failed");
    }

    let kernel = newest_kernel();
    let Some(kernel) = kernel else {
        let _ = run("umount", &[&root.display().to_string()]);
        let _ = run("umount", &[&esp.display().to_string()]);
        lr_testkit::unavailable!(return false; "no /boot/vmlinuz-* found");
    };
    let initramfs = work.join("initramfs.cpio.gz");
    if !build_initramfs(&initramfs, work) {
        let _ = run("umount", &[&root.display().to_string()]);
        let _ = run("umount", &[&esp.display().to_string()]);
        lr_testkit::fixture_failed!("building the initramfs failed");
    }
    std::fs::copy(&kernel, esp.join("vmlinuz")).expect("copy the kernel");
    std::fs::copy(&initramfs, esp.join("initramfs.cpio.gz")).expect("copy the initramfs");
    // `search` finds the ESP by the kernel it holds: a standalone UEFI image has
    // the memdisk as `$root`, so paths alone would not resolve.
    let grub_cfg = "set timeout=0\nmenuentry \"LinuxReflect boot test\" {\n  search --no-floppy --file --set=root /vmlinuz\n  linux /vmlinuz console=ttyS0 panic=-1\n  initrd /initramfs.cpio.gz\n}\n";
    // GRUB reads <boot-directory>/grub/grub.cfg for BIOS; a `--removable` EFI
    // binary uses <esp>/EFI/BOOT/grub.cfg, so both places get the file.
    let grub_dir = esp.join("grub");
    std::fs::create_dir_all(&grub_dir).expect("grub dir");
    std::fs::write(grub_dir.join("grub.cfg"), grub_cfg).expect("write grub.cfg");

    let esp_str = esp.display().to_string();
    let bios_ok = run(
        "grub-install",
        &[
            "--target=i386-pc",
            "--boot-directory",
            &esp_str,
            "--no-floppy",
            &label,
        ],
    );
    // UEFI: `grub-install` would install Ubuntu's *signed* binary, whose
    // embedded config searches Ubuntu paths (`/boot/grub`, `/.disk/info`) and
    // ignores ours. A standalone image with the config inside is deterministic
    // and needs no shim chain in a test.
    let efi_boot = esp.join("EFI/BOOT");
    std::fs::create_dir_all(&efi_boot).expect("EFI/BOOT dir");
    let embedded_cfg = esp.join("grub-embedded.cfg");
    std::fs::write(&embedded_cfg, grub_cfg).expect("write the embedded config");
    let uefi_ok = run(
        "grub-mkstandalone",
        &[
            "-O",
            "x86_64-efi",
            "-o",
            &efi_boot.join("BOOTX64.EFI").display().to_string(),
            "--modules=part_gpt fat normal linux echo search search_fs_file configfile",
            &format!("boot/grub/grub.cfg={}", embedded_cfg.display()),
        ],
    );
    let _ = run("sync", &[]);
    let _ = run("umount", &[&root.display().to_string()]);
    let _ = run("umount", &[&esp.display().to_string()]);
    if !bios_ok {
        lr_testkit::fixture_failed!("grub-install for i386-pc failed");
    }
    if !uefi_ok {
        lr_testkit::fixture_failed!("grub-mkstandalone for x86_64-efi failed");
    }
    true
}

fn newest_kernel() -> Option<PathBuf> {
    let mut kernels: Vec<PathBuf> = std::fs::read_dir("/boot")
        .ok()?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().starts_with("vmlinuz-"))
                .unwrap_or(false)
        })
        .collect();
    kernels.sort();
    kernels.pop()
}

/// A busybox initramfs whose init prints the boot marker.
fn build_initramfs(destination: &Path, work: &Path) -> bool {
    let staged = work.join("initramfs-root");
    let _ = std::fs::remove_dir_all(&staged);
    for dir in ["bin", "dev", "proc", "sys"] {
        if std::fs::create_dir_all(staged.join(dir)).is_err() {
            return false;
        }
    }
    if std::fs::copy("/bin/busybox", staged.join("bin/busybox")).is_err() {
        lr_testkit::unavailable!(return false; "static busybox not available");
    }
    for tool in ["sh", "mount", "poweroff", "echo"] {
        let link = staged.join("bin").join(tool);
        let _ = std::fs::remove_file(&link);
        if std::os::unix::fs::symlink("busybox", &link).is_err() {
            return false;
        }
    }
    let init = format!(
        "#!/bin/sh\nmount -t devtmpfs devtmpfs /dev 2>/dev/null\nmount -t proc proc /proc 2>/dev/null\necho {BOOT_MARKER} > /dev/console\nsleep 2\npoweroff -f\n"
    );
    if std::fs::write(staged.join("init"), init).is_err() {
        return false;
    }
    std::fs::set_permissions(
        staged.join("init"),
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .expect("chmod init");

    let list = staged.join("filelist");
    let find = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "cd {} && find . | cpio -o -H newc 2>/dev/null | gzip -c > {}",
            staged.display(),
            destination.display()
        ))
        .status();
    let _ = find;
    let _ = std::fs::remove_file(&list);
    destination.exists()
}

/// Boot `disk` in qemu and return whether the marker appeared.
fn boots(disk: &Path, uefi: bool, work: &Path, label: &str) -> bool {
    let serial = work.join(format!("serial-{label}.log"));
    let _ = std::fs::remove_file(&serial);
    let vars = work.join(format!("vars-{label}.fd"));
    let mut command = Command::new("qemu-system-x86_64");
    command
        .arg("-m")
        .arg("512")
        .arg("-display")
        .arg("none")
        .arg("-no-reboot")
        .arg("-serial")
        .arg(format!("file:{}", serial.display()))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if uefi {
        std::fs::copy(OVMF_VARS, &vars).expect("copy OVMF vars");
        command
            .arg("-machine")
            .arg("q35")
            .arg("-drive")
            .arg(format!("if=pflash,format=raw,readonly=on,file={OVMF_CODE}"))
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
        .expect("spawn qemu");

    let deadline = Instant::now() + BOOT_TIMEOUT;
    let mut found = false;
    while Instant::now() < deadline {
        if let Ok(text) = std::fs::read_to_string(&serial)
            && text.contains(BOOT_MARKER)
        {
            found = true;
            break;
        }
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => std::thread::sleep(Duration::from_millis(200)),
            Err(_) => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    let text = std::fs::read_to_string(&serial).unwrap_or_default();
    eprintln!("[{label}] uefi={uefi} marker={found}");
    if !found {
        for line in text.lines().filter(|line| !line.trim().is_empty()).take(30) {
            eprintln!("[{label}]   {line}");
        }
    }
    found
}

fn partition_offsets(path: &Path) -> Vec<(u64, u64)> {
    let text = output("sgdisk", &["-p", &path.display().to_string()]);
    let mut out = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 4 && fields[0].parse::<u32>().is_ok() {
            let index: u32 = fields[0].parse().expect("index");
            let start: u64 = fields[1].parse().expect("start");
            let end: u64 = fields[2].parse().expect("end");
            if (1..=8).contains(&index) {
                out.push((start * 512, (end - start + 1) * 512));
            }
        }
    }
    out.sort_unstable();
    out
}

fn whole_disk_report(report: &ImageReport) -> &lr_engine::WholeDiskReport {
    match report {
        ImageReport::WholeDisk(report) => report,
        ImageReport::Block(_) | ImageReport::Stream(_) | ImageReport::File(_) => {
            panic!("expected a whole-disk image")
        }
    }
}

#[test]
#[ignore = "requires root, loop devices, grub, qemu and OVMF"]
fn a_bootable_disk_survives_a_whole_disk_round_trip() {
    if !root_tests_enabled() {
        return;
    }
    if !have("qemu-system-x86_64") || !Path::new(OVMF_CODE).exists() {
        lr_testkit::unavailable!("qemu or OVMF missing");
    }
    let work = tempfile::tempdir().expect("workdir");
    let Some(source) = LoopDisk::attach(work.path(), "boot-src.img", SRC_SIZE) else {
        lr_testkit::fixture_failed!("could not attach a loop device");
    };
    if !build_bootable_disk(&source, work.path()) {
        return;
    }

    // Baseline: the fixture itself must boot before we image it.
    let bios_baseline = boots(&source.backing, false, work.path(), "src-bios");
    let uefi_baseline = boots(&source.backing, true, work.path(), "src-uefi");
    assert!(
        bios_baseline,
        "the BIOS fixture does not boot; the test is broken"
    );
    assert!(
        uefi_baseline,
        "the UEFI fixture does not boot; the test is broken"
    );

    // Back up the whole disk (offline: nothing is mounted).
    let outcome = work.path().join("out");
    let mut request =
        BackupRequest::new(&source.device, &outcome, "boot-set", Encryption::NoEncrypt)
            .expect("request");
    request.chunk_size = CHUNK_SIZE;
    request.compression = Compression::None;
    let report = backup_image(&request).expect("backup");
    let disk = whole_disk_report(&report);
    assert_eq!(disk.pt_type, "gpt");
    assert!(
        disk.regions
            .iter()
            .any(|region| region.kind == "partition-fs" && region.map_backed),
        "the ext4 root partition must be imaged through its used-block map"
    );
    let offsets_before = partition_offsets(&source.device);

    // Restore onto a disk twice the size.
    let target = work.path().join("boot-dst.img");
    sparse(&target, DST_SIZE);
    let plan = prepare_restore(&PrepareRequest::from_path(
        &disk.image_path,
        &target,
        Encryption::NoEncrypt,
    ))
    .expect("prepare");
    apply_restore(&ApplyRequest {
        token: plan.token,
        confirm: true,
        accept_inconsistent: false,
        encryption: Encryption::NoEncrypt,
        context: lr_engine::progress::EngineContext::silent(),
    })
    .expect("apply");

    // The layout survives and the GPT is valid at the new size.
    assert!(
        run("sgdisk", &["--verify", &target.display().to_string()]),
        "sgdisk --verify failed"
    );
    assert_eq!(
        partition_offsets(&target),
        offsets_before,
        "the layout changed"
    );
    let verify = output("sgdisk", &["--verify", &target.display().to_string()]);
    assert!(
        verify.contains("No problems found"),
        "sgdisk --verify did not report a clean table: {verify}"
    );

    // The BIOS boot loader in the MBR gap is byte-identical. The first 34
    // sectors are excluded: they hold the primary GPT header and entries, which
    // restore deliberately regenerates for the larger disk.
    const GPT_AREA: usize = 34 * 512;
    let read_head = |path: &Path| -> Vec<u8> {
        let mut bytes = vec![0u8; 1024 * 1024];
        std::fs::File::open(path)
            .expect("open")
            .read_exact(&mut bytes)
            .expect("read the first MiB");
        bytes
    };
    let before = read_head(&source.backing);
    let after = read_head(&target);
    assert_eq!(
        before[GPT_AREA..],
        after[GPT_AREA..],
        "the BIOS core.img area must be identical"
    );
    assert_eq!(
        &before[0..512],
        &after[0..512],
        "the protective MBR must be identical"
    );

    // And the restored disk boots under both firmwares.
    assert!(
        boots(&target, false, work.path(), "dst-bios"),
        "the restored disk does not boot under SeaBIOS"
    );
    assert!(
        boots(&target, true, work.path(), "dst-uefi"),
        "the restored disk does not boot under OVMF"
    );
}

#[test]
#[ignore = "requires root, loop devices, grub and qemu"]
fn an_mbr_disk_round_trips_and_boots() {
    if !root_tests_enabled() {
        return;
    }
    if !have("qemu-system-x86_64") || !have("sfdisk") {
        lr_testkit::unavailable!("qemu or sfdisk missing");
    }
    let work = tempfile::tempdir().expect("workdir");
    let Some(source) = LoopDisk::attach(work.path(), "mbr-src.img", SRC_SIZE) else {
        return;
    };
    // DOS partition table with a single bootable Linux partition.
    let label = source.label();
    assert!(
        Command::new("sh")
            .arg("-c")
            .arg(format!(
                "printf 'label: dos\\nstart=2048, size=+400M, type=83, bootable\\n' | sfdisk {label}"
            ))
            .status()
            .expect("sfdisk")
            .success(),
        "sfdisk failed"
    );
    let _ = run("blockdev", &["--rereadpt", &label]);
    let _ = run("partx", &["-a", &label]);
    for _ in 0..50 {
        if source.partition(1).exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if !run(
        "mkfs.ext4",
        &["-F", "-q", &source.partition(1).display().to_string()],
    ) {
        return;
    }
    // GRUB in the MBR gap plus an embedded config.
    let boot = work.path().join("mbr-boot");
    std::fs::create_dir_all(&boot).expect("boot dir");
    if !run(
        "grub-install",
        &[
            "--target=i386-pc",
            "--boot-directory",
            &boot.display().to_string(),
            "--no-floppy",
            &label,
        ],
    ) {
        lr_testkit::fixture_failed!("grub-install (MBR) failed");
    }

    let outcome = work.path().join("mbr-out");
    let mut request =
        BackupRequest::new(&source.device, &outcome, "mbr-set", Encryption::NoEncrypt)
            .expect("request");
    request.chunk_size = CHUNK_SIZE;
    request.compression = Compression::None;
    let report = backup_image(&request).expect("backup");
    let disk = whole_disk_report(&report);
    assert_eq!(disk.pt_type, "mbr", "an MBR table must be detected");

    let target = work.path().join("mbr-dst.img");
    sparse(&target, DST_SIZE);
    let plan = prepare_restore(&PrepareRequest::from_path(
        &disk.image_path,
        &target,
        Encryption::NoEncrypt,
    ))
    .expect("prepare");
    apply_restore(&ApplyRequest {
        token: plan.token,
        confirm: true,
        accept_inconsistent: false,
        encryption: Encryption::NoEncrypt,
        context: lr_engine::progress::EngineContext::silent(),
    })
    .expect("apply");

    let entries = |text: &str| -> Vec<String> {
        text.lines()
            .filter(|line| line.contains(" : "))
            .map(|line| {
                line.split_once(" : ")
                    .map(|(_, rest)| rest.to_owned())
                    .unwrap_or_default()
            })
            .collect()
    };
    let table_before = output("sfdisk", &["--dump", &source.device.display().to_string()]);
    let table_after = output("sfdisk", &["--dump", &target.display().to_string()]);
    assert_eq!(
        entries(&table_before),
        entries(&table_after),
        "the MBR partition entries changed"
    );
    assert!(
        !entries(&table_before).is_empty(),
        "the fixture has an MBR entry"
    );
    // The MBR code itself is in the leading region.
    let mut before = vec![0u8; 512];
    let mut after = vec![0u8; 512];
    let mut src = std::fs::File::open(&source.backing).expect("open");
    src.seek(SeekFrom::Start(0)).expect("seek");
    src.read_exact(&mut before).expect("read");
    let mut dst = std::fs::File::open(&target).expect("open");
    dst.seek(SeekFrom::Start(0)).expect("seek");
    dst.read_exact(&mut after).expect("read");
    assert_eq!(before, after, "the MBR boot code must be identical");
}

#[test]
#[ignore = "needs no root, but checks the fixture helpers"]
fn helpers_are_consistent() {
    if !root_tests_enabled() {
        return;
    }
    // `newest_kernel` must find the kernel the boot test needs.
    assert!(newest_kernel().is_some(), "no /boot/vmlinuz-* on this host");
}
