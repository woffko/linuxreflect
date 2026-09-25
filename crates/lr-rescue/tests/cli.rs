//! The rescue CLI previews instead of writing unless `--confirm` is given.

use std::process::Command;

#[test]
fn boot_repair_without_confirm_prints_the_plan_and_fails() {
    let dir = tempfile::tempdir().expect("tempdir");
    let disk = dir.path().join("disk.img");
    std::fs::write(&disk, vec![0_u8; 4096]).expect("fixture");
    let before = std::fs::read(&disk).expect("read");

    let output = Command::new(env!("CARGO_BIN_EXE_linuxreflect-rescue"))
        .args([
            "boot-repair",
            "--firmware",
            "bios",
            "--layout-changed",
            "--disk",
        ])
        .arg(&disk)
        .output()
        .expect("run");
    assert!(
        !output.status.success(),
        "a preview must not report success"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.contains("would:"), "the plan is shown: {stdout}");
    assert!(stderr.contains("--confirm"), "{stderr}");
    assert_eq!(std::fs::read(&disk).expect("read"), before);

    let dry_run = Command::new(env!("CARGO_BIN_EXE_linuxreflect-rescue"))
        .args([
            "--dry-run",
            "boot-repair",
            "--firmware",
            "bios",
            "--layout-changed",
            "--disk",
        ])
        .arg(&disk)
        .output()
        .expect("run");
    assert!(dry_run.status.success(), "--dry-run is an explicit preview");
}

#[test]
fn recreate_layout_rejects_an_unsupported_filesystem_before_touching_the_disk() {
    let dir = tempfile::tempdir().expect("tempdir");
    let disk = dir.path().join("disk.img");
    std::fs::write(&disk, vec![0_u8; 4096]).expect("fixture");
    let dump = dir.path().join("layout.sfdisk");
    std::fs::write(&dump, "label: gpt\n\n/dev/sda1 : start=2048, size=2048\n").expect("dump");

    let output = Command::new(env!("CARGO_BIN_EXE_linuxreflect-rescue"))
        .args([
            "--confirm",
            "recreate-layout",
            "--filesystem",
            "1:../../tmp/x::",
        ])
        .arg("--disk")
        .arg(&disk)
        .arg("--dump")
        .arg(&dump)
        .output()
        .expect("run");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("supported"), "{stderr}");
    assert_eq!(std::fs::read(&disk).expect("read"), vec![0_u8; 4096]);
}
