//! Write tracking on this kernel (spec v2.2 §E.7, Slice 18 phase 1).
//!
//! Root tests on loop devices the tests create themselves:
//!
//! ```text
//! LR_ROOT_TESTS=1 sudo -E cargo test -p lr-snapshot --test root_tracking -- --ignored --nocapture
//! ```

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use lr_snapshot::tracking::{self, DevNumber, TrackedRegion, Tracker};

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

fn tracefs() -> Option<std::path::PathBuf> {
    let Some(root) = tracking::tracefs_root() else {
        lr_testkit::unavailable!(return None; "tracefs is not mounted");
    };
    if !root.join("events").join(tracking::TRACEPOINT).is_dir() {
        lr_testkit::unavailable!(return None; "the {} tracepoint is unavailable", tracking::TRACEPOINT);
    }
    Some(root)
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

#[test]
#[ignore = "requires root, loop devices and tracefs"]
fn the_self_test_passes_on_this_kernel() {
    if !root_tests_enabled() {
        return;
    }
    let Some(tracefs) = tracefs() else {
        return;
    };
    for tool in ["sfdisk", "losetup", "blockdev", "blkdiscard"] {
        if !have(tool) {
            lr_testkit::unavailable!("{tool} missing");
        }
    }
    let work = tempfile::tempdir().expect("workdir");
    let report = tracking::self_test(&tracefs, work.path()).expect("run the self test");
    println!("{report:?}");
    assert!(report.passed(), "{report:?}");
    assert!(report.write_mapped);
    assert!(
        !tracefs
            .join("instances")
            .join(format!("lr-self-test-{}", std::process::id()))
            .exists(),
        "the instance was removed"
    );
}

/// An ext4 filesystem on a loop partition, mounted; everything is undone on drop.
struct Mounted {
    dir: tempfile::TempDir,
    device: String,
}

impl Mounted {
    fn create() -> Option<Self> {
        for tool in [
            "sfdisk",
            "losetup",
            "mkfs.ext4",
            "mount",
            "umount",
            "blockdev",
        ] {
            if !have(tool) {
                lr_testkit::unavailable!(return None; "{tool} missing");
            }
        }
        let dir = tempfile::tempdir().expect("dir");
        let image = dir.path().join("disk.img");
        std::fs::File::create(&image)
            .and_then(|f| f.set_len(128 << 20))
            .expect("image");
        let mut sfdisk = Command::new("sfdisk")
            .arg("--quiet")
            .arg(&image)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .expect("sfdisk");
        use std::io::Write as _;
        sfdisk
            .stdin
            .take()
            .expect("stdin")
            .write_all(b"label: gpt\nstart=2048, size=8MiB\n,\n")
            .expect("layout");
        if !sfdisk.wait().expect("sfdisk").success() {
            lr_testkit::fixture_failed!("sfdisk failed");
        }
        let output = Command::new("losetup")
            .args(["--find", "--show", "--partscan"])
            .arg(&image)
            .output()
            .expect("losetup");
        if !output.status.success() {
            lr_testkit::fixture_failed!("losetup failed");
        }
        let device = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        let mounted = Self { dir, device };
        let _ = run("blockdev", &["--rereadpt", &mounted.device]);
        for _ in 0..100 {
            if Path::new(&mounted.partition()).exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        if !run("mkfs.ext4", &["-q", "-F", &mounted.partition()]) {
            lr_testkit::fixture_failed!("mkfs.ext4 failed");
        }
        std::fs::create_dir(mounted.mountpoint()).expect("mountpoint");
        if !run(
            "mount",
            &[
                &mounted.partition(),
                &mounted.mountpoint().display().to_string(),
            ],
        ) {
            lr_testkit::fixture_failed!("mount failed");
        }
        Some(mounted)
    }

    fn partition(&self) -> String {
        format!("{}p2", self.device)
    }

    fn mountpoint(&self) -> std::path::PathBuf {
        self.dir.path().join("mnt")
    }

    fn region(&self) -> TrackedRegion {
        use std::os::unix::fs::MetadataExt as _;
        let number = |path: &str| {
            let rdev = std::fs::metadata(path).expect("stat").rdev();
            DevNumber {
                major: (((rdev >> 32) & 0xffff_f000) | ((rdev >> 8) & 0x0000_0fff)) as u32,
                minor: (((rdev >> 12) & 0xffff_ff00) | (rdev & 0x0000_00ff)) as u32,
            }
        };
        let name = Path::new(&self.partition())
            .file_name()
            .expect("name")
            .to_string_lossy()
            .into_owned();
        let sysfs = |file: &str| -> u64 {
            std::fs::read_to_string(Path::new("/sys/class/block").join(&name).join(file))
                .expect("sysfs")
                .trim()
                .parse()
                .expect("number")
        };
        TrackedRegion {
            whole: number(&self.device),
            part: Some(number(&self.partition())),
            start_sector: sysfs("start"),
            sectors: sysfs("size"),
        }
    }
}

impl Drop for Mounted {
    fn drop(&mut self) {
        let _ = run("umount", &[&self.mountpoint().display().to_string()]);
        let _ = run("losetup", &["--detach", &self.device]);
    }
}

#[test]
#[ignore = "requires root, loop devices and tracefs"]
fn writes_through_a_mounted_ext4_are_tracked_and_reads_are_not() {
    if !root_tests_enabled() {
        return;
    }
    let Some(tracefs) = tracefs() else {
        return;
    };
    let Some(fs) = Mounted::create() else {
        return;
    };
    let name = format!("lr-root-test-{}", std::process::id());
    let mut tracker =
        Tracker::start(&tracefs, &name, vec![fs.region()], 1 << 20, 4096).expect("tracker");
    let mut taken = tracker.empty_map();
    tracker.drain(Duration::from_secs(5)).expect("drain");
    tracker.take_into(&mut taken);

    // 8 MiB of file data, synced: at least 8 dirty 1 MiB chunks.
    let file = fs.mountpoint().join("data.bin");
    std::fs::write(&file, vec![0x5a; 8 << 20]).expect("write");
    let _ = run("sync", &["-f", &file.display().to_string()]);
    tracker.drain(Duration::from_secs(5)).expect("drain");
    tracker.take_into(&mut taken);
    assert!(
        taken.count() >= 8,
        "dirty chunks after 8 MiB: {}",
        taken.count()
    );

    // Reading the raw partition dirties nothing.
    let _ = run(
        "dd",
        &[
            &format!("if={}", fs.partition()),
            "of=/dev/null",
            "bs=1M",
            "count=16",
            "iflag=direct",
            "status=none",
        ],
    );
    tracker.drain(Duration::from_secs(5)).expect("drain");
    tracker.take_into(&mut taken);
    assert_eq!(taken.count(), 0, "reads dirtied chunks");

    let losses = tracker.integrity().expect("integrity");
    assert!(losses.is_clean(), "{losses:?}");
    drop(tracker);
    assert!(!tracefs.join("instances").join(&name).exists());
}

#[test]
#[ignore = "requires root and tracefs"]
fn the_sweep_removes_a_leftover_instance() {
    if !root_tests_enabled() {
        return;
    }
    let Some(tracefs) = tracefs() else {
        return;
    };
    let leftover = tracefs
        .join("instances")
        .join(format!("lr-leftover-{}", std::process::id()));
    std::fs::create_dir(&leftover).expect("create a leftover instance");
    let foreign = tracefs
        .join("instances")
        .join(format!("not-ours-{}", std::process::id()));
    std::fs::create_dir(&foreign).expect("create a foreign instance");
    let removed = tracking::sweep(&tracefs);
    let foreign_survived = foreign.exists();
    let _ = std::fs::remove_dir(&foreign);
    assert!(removed.contains(&leftover), "{removed:?}");
    assert!(!leftover.exists());
    assert!(
        foreign_survived,
        "the sweep removed an instance that is not ours"
    );
}
