//! Provider tests against real filesystems created in image files.
//!
//! `dumpe2fs`, `mkfs.ext4`, `xfs_db` and `mkfs.xfs` all work on a regular file,
//! so the used-block maps can be exercised end to end without root. The loop
//! device completeness acceptance test (restore + `fsck -n`) lives in the
//! engine's root tests, because it needs S6.

use std::path::{Path, PathBuf};
use std::process::Command;

use lr_fsmap::{ExtentMap, provider_for};

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

fn sparse_file(dir: &Path, name: &str, size: u64) -> PathBuf {
    let path = dir.join(name);
    let file = std::fs::File::create(&path).expect("create image");
    file.set_len(size).expect("size image");
    drop(file);
    path
}

/// Structural invariants every complete map must satisfy.
fn assert_sane(map: &ExtentMap, device_size: u64) {
    assert!(map.complete, "a mapped filesystem is complete");
    assert!(!map.is_empty(), "a formatted filesystem has used blocks");
    for (start, end) in &map.extents {
        assert!(start <= end, "reversed extent {start}-{end}");
        assert!(*end < device_size, "extent past the device");
    }
    for pair in map.extents.windows(2) {
        assert!(pair[0].1 < pair[1].0, "extents must be sorted and disjoint");
    }
    assert!(map.covered_bytes() < device_size, "some space must be free");
}

#[test]
fn ext4_provider_maps_a_real_image_file() {
    if !have("mkfs.ext4") || !have("dumpe2fs") {
        lr_testkit::unavailable!("mkfs.ext4 or dumpe2fs missing");
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let size = 64 * 1024 * 1024;
    let image = sparse_file(dir.path(), "ext4.img", size);
    assert!(run(
        "mkfs.ext4",
        &["-F", "-q", "-L", "ROOTFS", &image.display().to_string()]
    ));

    let map = provider_for("ext4").used_extents(&image).expect("used map");
    assert_sane(&map, size);
    eprintln!(
        "ext4 image file: {} extents, {} used bytes of {size}",
        map.extents.len(),
        map.covered_bytes()
    );

    // The raw provider must claim nothing for the same file.
    let raw = provider_for("vfat").used_extents(&image).expect("raw map");
    assert!(!raw.complete);
    assert_eq!(raw.extents, vec![(0, size - 1)]);
}

#[test]
fn xfs_provider_maps_a_real_image_file() {
    if !have("mkfs.xfs") || !have("xfs_db") {
        lr_testkit::unavailable!("mkfs.xfs or xfs_db missing");
    }
    let dir = tempfile::tempdir().expect("tempdir");
    // mkfs.xfs refuses to build a filesystem smaller than 300 MiB.
    let size = 384 * 1024 * 1024;
    let image = sparse_file(dir.path(), "xfs.img", size);
    assert!(run(
        "mkfs.xfs",
        &["-f", "-q", "-L", "XFSROOT", &image.display().to_string()]
    ));

    let map = provider_for("xfs").used_extents(&image).expect("used map");
    assert_sane(&map, size);
    eprintln!(
        "xfs image file: {} extents, {} used bytes of {size}",
        map.extents.len(),
        map.covered_bytes()
    );
}

#[test]
fn missing_tools_are_reported_as_unsupported() {
    // An unknown filesystem type never needs a tool: it falls back to raw.
    let dir = tempfile::tempdir().expect("tempdir");
    let image = sparse_file(dir.path(), "blob.bin", 4096);
    let map = provider_for("unknown-fs")
        .used_extents(&image)
        .expect("raw");
    assert!(!map.complete);

    // But asking the ext4 provider for a file that is not an ext4 filesystem
    // must fail loudly rather than return a wrong map.
    if have("dumpe2fs") {
        let error = provider_for("ext4")
            .used_extents(&image)
            .expect_err("must fail");
        assert!(
            matches!(
                error,
                lr_core::Error::Corrupt { .. }
                    | lr_core::Error::Io(_)
                    | lr_core::Error::Unsupported { .. }
            ),
            "unexpected error: {error}"
        );
    }
}
