//! S2 acceptance support: partition discovery on a GPT fixture built by `sgdisk`.
//!
//! The fixture is a plain image file, so the test runs without root. The layout
//! matches the spec §K S2 criteria: ESP + BIOS boot + ext4 data + swap, with
//! real filesystem signatures written inside the partitions so that
//! `disk map --json` has to detect them (through `blkid -O`). The ESP keeps a
//! FAT filesystem only when `mkfs.vfat` is installed; the EFI System type GUID
//! is asserted regardless.

use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use lr_core::discovery::{PartitionTableKind, SourceLayout, discover_source};

/// Expected partition layout of the fixture, in order.
const EXPECTED: [(u32, &str, u64); 4] = [
    (1, "EFI System", 16 * 1024 * 1024),
    (2, "BIOS boot", 1024 * 1024),
    (3, "Linux filesystem", 32 * 1024 * 1024),
    (4, "Linux swap", 16 * 1024 * 1024),
];

const SECTOR: u64 = 512;

struct Fixture {
    _dir: tempfile::TempDir,
    image: PathBuf,
    layout: SourceLayout,
}

fn have(program: &str) -> bool {
    Command::new("which")
        .arg(program)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn build_partition_table(path: &Path) -> bool {
    let file = std::fs::File::create(path).expect("create fixture file");
    file.set_len(128 * 1024 * 1024).expect("size fixture");
    drop(file);
    let path_str = path.display().to_string();
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
            "2:0:+1M",
            "-t",
            "2:ef02",
            "-c",
            "2:BIOS",
            "-n",
            "3:0:+32M",
            "-t",
            "3:8300",
            "-c",
            "3:ROOT",
            "-n",
            "4:0:+16M",
            "-t",
            "4:8200",
            "-c",
            "4:SWAP",
            &path_str,
        ])
        .output()
        .expect("run sgdisk");
    if !status.status.success() {
        lr_testkit::fixture_failed!("sgdisk failed: {}", String::from_utf8_lossy(&status.stderr));
    }
    true
}

fn make_fixture() -> Option<Fixture> {
    if !have("sgdisk") {
        lr_testkit::unavailable!(return None; "sgdisk not installed - S2 fixture test");
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let image = dir.path().join("fixture.img");
    if !build_partition_table(&image) {
        lr_testkit::fixture_failed!("could not build the GPT fixture");
    }
    let layout = discover_source(&image).expect("discover fixture");
    Some(Fixture {
        _dir: dir,
        image,
        layout,
    })
}

/// Which filesystem to write into a partition.
#[derive(Debug, Clone, Copy)]
enum FsKind {
    Ext4,
    Swap,
    Vfat,
}

impl FsKind {
    fn tool(self) -> &'static str {
        match self {
            Self::Ext4 => "mkfs.ext4",
            Self::Swap => "mkswap",
            Self::Vfat => "mkfs.vfat",
        }
    }
}

/// Build a filesystem in a scratch file and copy it into `image` at `offset`.
///
/// The scratch file is exactly `size` bytes so that signatures stored at the end
/// of the region (swap) land where `blkid --size <partition size>` looks for
/// them.
fn write_filesystem(image: &Path, offset: u64, size: u64, kind: FsKind) -> bool {
    if !have(kind.tool()) {
        lr_testkit::unavailable!(return false;
            "{} not installed - {:?} signature",
            kind.tool(),
            kind
        );
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let scratch = dir.path().join("fs.img");
    let handle = std::fs::File::create(&scratch).expect("create scratch");
    handle.set_len(size).expect("size scratch");
    drop(handle);

    let status = match kind {
        FsKind::Ext4 => Command::new("mkfs.ext4")
            .args(["-F", "-q", "-L", "ROOTFS"])
            .arg(&scratch)
            .status(),
        FsKind::Swap => Command::new("mkswap")
            .args(["-L", "SWAPTEST"])
            .arg(&scratch)
            .status(),
        FsKind::Vfat => Command::new("mkfs.vfat")
            .args(["-n", "ESP"])
            .arg(&scratch)
            .status(),
    }
    .expect("run mkfs");
    if !status.success() {
        lr_testkit::fixture_failed!("mkfs for {kind:?} failed");
    }

    let data = std::fs::read(&scratch).expect("read scratch");
    assert_eq!(data.len() as u64, size, "scratch file must keep its size");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(image)
        .expect("open fixture for writing");
    file.seek(SeekFrom::Start(offset)).expect("seek fixture");
    file.write_all(&data).expect("write filesystem image");
    file.flush().expect("flush fixture");
    true
}

fn partition(layout: &SourceLayout, index: u32) -> Option<&lr_core::PartitionLayout> {
    layout.partitions.iter().find(|p| p.index == index)
}

#[test]
fn gpt_fixture_partitions_match_spec_layout() {
    let Some(fixture) = make_fixture() else {
        return;
    };
    let layout = &fixture.layout;

    let table = layout.partition_table.as_ref().expect("partition table");
    assert_eq!(table.kind, PartitionTableKind::Gpt);
    assert!(table.disk_guid.is_some(), "GPT disk GUID must be reported");
    assert!(table.has_mbr_signature, "sgdisk writes a protective MBR");
    assert_eq!(table.entry_count, Some(128));

    assert_eq!(layout.partitions.len(), EXPECTED.len(), "four partitions");
    for (index, name, size) in EXPECTED {
        let part = partition(layout, index).unwrap_or_else(|| panic!("partition {index} missing"));
        assert_eq!(
            part.type_name.as_deref(),
            Some(name),
            "partition {index} type"
        );
        assert_eq!(part.size_bytes, size, "partition {index} size");
        assert!(part.start_lba > 0, "partition {index} start LBA");
        assert!(part.part_uuid.is_some(), "partition {index} UUID");
    }

    let third = partition(layout, 3).expect("p3");
    let second = partition(layout, 2).expect("p2");
    assert!(
        third.start_lba * SECTOR >= second.start_lba * SECTOR + second.size_bytes,
        "partitions must not overlap"
    );

    let json = serde_json::to_string_pretty(layout).expect("serialize layout");
    assert!(json.contains("\"gpt\""), "JSON reports the table kind");
    let back: SourceLayout = serde_json::from_str(&json).expect("deserialize layout");
    assert_eq!(back, *layout);
}

#[test]
fn gpt_fixture_filesystems_are_detected_inside_partitions() {
    let Some(fixture) = make_fixture() else {
        return;
    };

    // Partition 3 is 32 MiB: a 24 MiB ext4 fits with room to spare.
    let p3 = partition(&fixture.layout, 3).expect("p3").clone();
    assert!(
        write_filesystem(
            &fixture.image,
            p3.start_lba * SECTOR,
            24 * 1024 * 1024,
            FsKind::Ext4
        ),
        "ext4 signature must be writable"
    );
    // Swap stores its signature in the last page, so it must fill the partition.
    let p4 = partition(&fixture.layout, 4).expect("p4").clone();
    assert!(
        write_filesystem(
            &fixture.image,
            p4.start_lba * SECTOR,
            p4.size_bytes,
            FsKind::Swap
        ),
        "swap signature must be writable"
    );
    // The ESP is FAT; only asserted when dosfstools is installed.
    let p1 = partition(&fixture.layout, 1).expect("p1").clone();
    let wrote_vfat = write_filesystem(
        &fixture.image,
        p1.start_lba * SECTOR,
        12 * 1024 * 1024,
        FsKind::Vfat,
    );

    let layout = discover_source(&fixture.image).expect("re-discover fixture");

    let root = partition(&layout, 3).expect("p3");
    assert_eq!(
        root.fs_type.as_deref(),
        Some("ext4"),
        "ext4 must be detected"
    );
    assert_eq!(root.fs_label.as_deref(), Some("ROOTFS"));
    assert!(root.fs_uuid.is_some(), "ext4 UUID must be reported");

    let swap = partition(&layout, 4).expect("p4");
    assert_eq!(
        swap.fs_type.as_deref(),
        Some("swap"),
        "swap must be detected"
    );
    assert_eq!(swap.fs_label.as_deref(), Some("SWAPTEST"));

    if wrote_vfat {
        let esp = partition(&layout, 1).expect("p1");
        assert!(
            esp.fs_type.as_deref() == Some("vfat"),
            "vfat must be detected, got {:?}",
            esp.fs_type
        );
    }

    // The BIOS boot partition holds no filesystem and must stay empty.
    let bios = partition(&layout, 2).expect("p2");
    assert!(bios.fs_type.is_none(), "BIOS boot is not a filesystem");

    // The image as a whole carries no filesystem, only a partition table.
    assert!(layout.fs.is_none(), "whole-disk image has no fs of its own");
}

#[test]
fn sparse_file_without_table_is_reported_as_none() {
    let dir = tempfile::tempdir().expect("tempdir");
    let image = dir.path().join("empty.img");
    let file = std::fs::File::create(&image).expect("create file");
    file.set_len(4 * 1024 * 1024).expect("size file");
    drop(file);
    let layout = discover_source(&image).expect("discover source");
    assert!(
        layout.partition_table.is_none(),
        "no partition table expected in a blank file"
    );
    assert!(layout.partitions.is_empty());
    assert_eq!(layout.device_facts.size_bytes, 4 * 1024 * 1024);
}

#[test]
fn an_mbr_disk_reports_one_partition_per_used_entry() {
    if !have("sfdisk") {
        lr_testkit::unavailable!("sfdisk not installed - MBR test");
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let image = dir.path().join("mbr.img");
    let file = std::fs::File::create(&image).expect("create");
    file.set_len(64 * 1024 * 1024).expect("size");
    drop(file);
    let script = format!(
        "printf 'label: dos\\nstart=2048, size=+16M, type=83, bootable\\n' | sfdisk {}",
        image.display()
    );
    let status = Command::new("sh")
        .arg("-c")
        .arg(&script)
        .status()
        .expect("sfdisk");
    assert!(status.success(), "sfdisk failed");

    let layout = discover_source(&image).expect("discover");
    let table = layout.partition_table.as_ref().expect("table");
    assert_eq!(table.kind, PartitionTableKind::Mbr);
    assert_eq!(layout.partitions.len(), 1, "one used MBR entry");
    let partition = &layout.partitions[0];
    assert_eq!(
        partition.index, 1,
        "mbrman numbers primary partitions from 1"
    );
    assert_eq!(partition.start_lba, 2048);
    assert_eq!(partition.size_bytes, 16 * 1024 * 1024);
    assert!(partition.bootable, "the partition was marked bootable");
}
