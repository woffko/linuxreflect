//! S1/S2 acceptance tests that need a real loop device.
//!
//! Run manually in a privileged environment (root, or a privileged container):
//!
//! ```text
//! LR_ROOT_TESTS=1 sudo -E cargo test -p lr-core --test root_loop -- --ignored --nocapture
//! ```
//!
//! The tests are ignored by default so that `cargo test` stays green on an
//! unprivileged workstation, per spec §L.4. Each test creates its own loop
//! device and detaches it on drop; no pre-existing device is ever touched.

use std::path::{Path, PathBuf};
use std::process::Command;

fn root_tests_enabled() -> bool {
    if std::env::var("LR_ROOT_TESTS").as_deref() != Ok("1") {
        eprintln!("LR_ROOT_TESTS != 1; skipping root test");
        return false;
    }
    let uid = Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default();
    if uid != "0" {
        eprintln!("not running as root (uid {uid}); skipping root test");
        return false;
    }
    true
}

fn run(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// A loop device backed by a freshly created image file.
struct Loop {
    device: PathBuf,
    _dir: tempfile::TempDir,
}

impl Loop {
    fn attach(size_bytes: u64) -> Option<Self> {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("disk.img");
        let handle = std::fs::File::create(&file).expect("create image");
        handle.set_len(size_bytes).expect("size image");
        drop(handle);

        // `losetup --find --show` is racy in some kernels/containers, so pick a
        // free device and attach explicitly (works on WSL2, which has no udev).
        let free = Command::new("losetup").arg("-f").output().ok()?;
        if !free.status.success() {
            eprintln!(
                "losetup -f failed: {}",
                String::from_utf8_lossy(&free.stderr)
            );
            return None;
        }
        let device = PathBuf::from(String::from_utf8_lossy(&free.stdout).trim().to_owned());
        let attached = Command::new("losetup")
            .arg("-P")
            .arg(&device)
            .arg(&file)
            .output()
            .expect("run losetup");
        if !attached.status.success() {
            eprintln!(
                "losetup -P {} failed: {}",
                device.display(),
                String::from_utf8_lossy(&attached.stderr)
            );
            let _ = Command::new("losetup").arg("-d").arg(&device).status();
            return None;
        }
        Some(Self { device, _dir: dir })
    }

    /// Re-read the partition table and wait for partition nodes to appear.
    fn reread_partitions(&self, expected: u32) -> bool {
        let device = self.device.display().to_string();
        let _ = Command::new("blockdev")
            .args(["--rereadpt", &device])
            .status();
        let _ = Command::new("partx").args(["-a", &device]).status();
        for _ in 0..50 {
            let nodes = (1..=expected)
                .filter(|index| self.partition_path(*index).exists())
                .count();
            if nodes == expected as usize {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        false
    }

    fn partition_path(&self, index: u32) -> PathBuf {
        PathBuf::from(format!("{}p{index}", self.device.display()))
    }
}

impl Drop for Loop {
    fn drop(&mut self) {
        let _ = Command::new("losetup").arg("-d").arg(&self.device).status();
    }
}

#[test]
#[ignore = "requires root and a loop device"]
fn loop_device_reports_one_gib_geometry() {
    if !root_tests_enabled() {
        return;
    }
    let Some(loop_dev) = Loop::attach(1024 * 1024 * 1024) else {
        return;
    };
    let name = loop_dev
        .device
        .file_name()
        .expect("loop name")
        .to_string_lossy()
        .into_owned();

    // This is the S1 acceptance criterion: `disk list` reports the size and the
    // sector size of the loop device.
    let geometry = lr_core::Geometry::probe(&loop_dev.device).expect("probe loop geometry");
    assert_eq!(geometry.size_bytes, 1024 * 1024 * 1024, "1 GiB");
    assert_eq!(geometry.logical_block_size, 512);
    assert_eq!(geometry.sector_count(), 2 * 1024 * 1024);

    let devices = lr_core::sysfs::list_block_devices().expect("list devices");
    let device = devices
        .iter()
        .find(|d| d.name == name)
        .unwrap_or_else(|| panic!("{name} not found in sysfs"));
    assert_eq!(device.size_bytes, 1024 * 1024 * 1024);
    assert_eq!(device.logical_block_size, 512);
}

#[test]
#[ignore = "requires root and a loop device"]
fn real_loop_gpt_partitions_and_filesystems_are_discovered() {
    if !root_tests_enabled() {
        return;
    }
    let Some(loop_dev) = Loop::attach(128 * 1024 * 1024) else {
        return;
    };
    let device_str = loop_dev.device.display().to_string();

    // ESP + ext4 data + swap, matching the S2 fixture layout.
    let status = Command::new("sgdisk")
        .args([
            "--clear",
            "-n",
            "1:2048:+16M",
            "-t",
            "1:ef00",
            "-c",
            "1:ESP",
            "-n",
            "2:0:+32M",
            "-t",
            "2:8300",
            "-c",
            "2:ROOT",
            "-n",
            "3:0:+16M",
            "-t",
            "3:8200",
            "-c",
            "3:SWAP",
            &device_str,
        ])
        .status()
        .expect("run sgdisk");
    assert!(status.success(), "sgdisk must succeed");

    if !loop_dev.reread_partitions(3) {
        eprintln!("partition nodes did not appear; skipping the real-device part");
        return;
    }

    let root_part = loop_dev.partition_path(2);
    let swap_part = loop_dev.partition_path(3);
    assert!(
        run(
            "mkfs.ext4",
            &["-F", "-q", "-L", "ROOTFS", &root_part.display().to_string()]
        ),
        "mkfs.ext4 must succeed"
    );
    assert!(
        run(
            "mkswap",
            &["-L", "SWAPTEST", &swap_part.display().to_string()]
        ),
        "mkswap must succeed"
    );

    let layout = lr_core::discover_source(&loop_dev.device).expect("discover loop source");
    assert_eq!(layout.partitions.len(), 3, "three partitions");
    assert!(layout.is_offline(), "a fresh loop device is not mounted");
    assert!(layout.is_whole_disk(), "loop device is a whole disk here");

    let first = layout.partitions.iter().find(|p| p.index == 1).expect("p1");
    assert_eq!(first.type_name.as_deref(), Some("EFI System"));
    assert_eq!(
        first.path.as_deref(),
        Some(loop_dev.partition_path(1).as_path())
    );

    let root = layout.partitions.iter().find(|p| p.index == 2).expect("p2");
    assert_eq!(
        root.fs_type.as_deref(),
        Some("ext4"),
        "ext4 on the partition node"
    );
    assert_eq!(root.fs_label.as_deref(), Some("ROOTFS"));

    let swap = layout.partitions.iter().find(|p| p.index == 3).expect("p3");
    assert_eq!(
        swap.fs_type.as_deref(),
        Some("swap"),
        "swap on the partition node"
    );

    // The device itself carries a partition table, not a filesystem.
    assert!(layout.fs.is_none(), "no filesystem on the whole device");
    assert!(Path::new(&loop_dev.partition_path(2)).exists());
}
