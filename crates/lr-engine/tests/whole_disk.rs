//! Whole-disk backup and restore on image files (spec §G.7, §K S7).
//!
//! Everything here runs without root: `sgdisk` writes a partition table into a
//! file, the filesystems are created at offsets, and the restore target is a
//! second, larger file. Filesystem partitions of an *image file* have no device
//! nodes, so they are imaged raw (documented in D-025); the used-block map path
//! is exercised by the loop-device acceptance test.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use lr_engine::backup::{BackupRequest, Compression};
use lr_engine::keys::Encryption;
use lr_engine::restore::{ApplyRequest, PrepareRequest, apply_restore, prepare_restore};
use lr_engine::{ImageReport, backup_image};

const CHUNK_SIZE: u32 = 256 * 1024;
const SRC_SIZE: u64 = 256 * 1024 * 1024;
const DST_SIZE: u64 = 384 * 1024 * 1024;
const LEADING_BYTES: u64 = 1024 * 1024;
/// Where the BIOS boot loader lives inside the MBR gap.
const CORE_IMG_OFFSET: u64 = 34 * 512;

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

fn sparse(path: &Path, size: u64) {
    let file = std::fs::File::create(path).expect("create");
    file.set_len(size).expect("size");
    drop(file);
}

fn write_at(path: &Path, offset: u64, bytes: &[u8]) {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .expect("open for writing");
    file.seek(SeekFrom::Start(offset)).expect("seek");
    file.write_all(bytes).expect("write");
    file.sync_all().expect("sync");
}

fn read_at(path: &Path, offset: u64, len: usize) -> Vec<u8> {
    let mut file = std::fs::File::open(path).expect("open");
    file.seek(SeekFrom::Start(offset)).expect("seek");
    let mut bytes = vec![0u8; len];
    file.read_exact(&mut bytes).expect("read");
    bytes
}

/// Build a GPT disk image: bios_grub, ESP, ext4 and swap.
fn build_disk(path: &Path) -> bool {
    if !have("sgdisk") || !have("mkfs.vfat") || !have("mkfs.ext4") || !have("mkswap") {
        lr_testkit::unavailable!(return false; "partition or filesystem tools missing");
    }
    sparse(path, SRC_SIZE);
    let image = path.display().to_string();
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
            "2:0:+32M",
            "-t",
            "2:ef00",
            "-c",
            "2:ESP",
            "-n",
            "3:0:+64M",
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
            &image,
        ],
    ) {
        lr_testkit::fixture_failed!("sgdisk failed");
    }
    // BIOS boot loader bytes in the MBR gap.
    write_at(path, CORE_IMG_OFFSET, &[0xEB, 0x63, 0x90, 0xA5, 0x5A]);

    // Partition offsets from the table we just wrote.
    let offsets = partition_offsets(path);
    let dir = tempfile::tempdir().expect("tempdir");
    let esp = dir.path().join("esp.img");
    sparse(&esp, 32 * 1024 * 1024);
    {
        let esp_file = std::fs::File::create(&esp).expect("create esp");
        esp_file.set_len(32 * 1024 * 1024).expect("size esp");
    }
    if !run(
        "mkfs.vfat",
        &["-F", "32", "-n", "ESP", &esp.display().to_string()],
    ) {
        lr_testkit::fixture_failed!("mkfs.vfat failed");
    }
    let esp_bytes = std::fs::read(&esp).expect("read esp");
    write_at(path, offsets[1], &esp_bytes);

    if !run(
        "mkfs.ext4",
        &[
            "-F",
            "-q",
            "-E",
            &format!("offset={}", offsets[2]),
            "-L",
            "ROOT",
            &image,
        ],
    ) {
        lr_testkit::fixture_failed!("mkfs.ext4 at an offset failed");
    }

    let swap = dir.path().join("swap.img");
    sparse(&swap, 16 * 1024 * 1024);
    if !run("mkswap", &["-L", "SWAPTEST", &swap.display().to_string()]) {
        lr_testkit::fixture_failed!("mkswap failed");
    }
    let swap_bytes = std::fs::read(&swap).expect("read swap");
    write_at(path, offsets[3], &swap_bytes);
    true
}

/// Byte offsets of the four partitions as `sgdisk` reports them.
fn partition_offsets(path: &Path) -> [u64; 4] {
    let text = Command::new("sgdisk")
        .args(["-p", &path.display().to_string()])
        .output()
        .expect("sgdisk -p");
    let stdout = String::from_utf8_lossy(&text.stdout);
    let mut offsets = [0u64; 4];
    for line in stdout.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // "   1            2048          4095   1.0 MiB  EF02  BIOS"
        if fields.len() >= 3 && fields[0].parse::<usize>().is_ok() {
            let index: usize = fields[0].parse().expect("index");
            let start: u64 = fields[1].parse().expect("start");
            if (1..=4).contains(&index) {
                offsets[index - 1] = start * 512;
            }
        }
    }
    offsets
}

fn request(source: &Path, dest: &Path) -> BackupRequest {
    let mut request =
        BackupRequest::new(source, dest, "disk-set", Encryption::NoEncrypt).expect("request");
    request.chunk_size = CHUNK_SIZE;
    request.compression = Compression::None;
    request
}

#[test]
fn a_whole_disk_image_round_trips_to_a_larger_disk() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("source.img");
    if !build_disk(&source) {
        return;
    }
    let offsets = partition_offsets(&source);

    let outcome = dir.path().join("out");
    let report = backup_image(&request(&source, &outcome)).expect("backup");
    let ImageReport::WholeDisk(disk) = &report else {
        panic!("expected a whole-disk image, got {report:?}");
    };
    assert_eq!(disk.pt_type, "gpt");
    assert_eq!(disk.disk_size_bytes, SRC_SIZE);
    assert_eq!(disk.leading_bytes, LEADING_BYTES);
    assert_eq!(disk.regions.len(), 5, "leading plus four partitions");
    assert_eq!(disk.regions[0].kind, "leading");
    assert_eq!(disk.regions[4].kind, "swap");
    assert!(
        disk.image_bytes < 100 * 1024 * 1024,
        "a 256 MiB disk with mostly empty partitions produced {} bytes",
        disk.image_bytes
    );

    // Restore onto a larger target.
    let target = dir.path().join("target.img");
    sparse(&target, DST_SIZE);
    let plan = prepare_restore(&PrepareRequest::from_path(
        &disk.image_path,
        &target,
        Encryption::NoEncrypt,
    ))
    .expect("prepare");
    assert!(
        plan.warnings
            .iter()
            .any(|warning| warning.contains("larger"))
    );
    let restore = apply_restore(&ApplyRequest {
        token: plan.token,
        confirm: true,
        accept_inconsistent: false,
        encryption: Encryption::NoEncrypt,
        context: lr_engine::progress::EngineContext::silent(),
    })
    .expect("apply")
    .block()
    .expect("a whole-disk restore");
    assert!(restore.bytes_written > 0);

    // The GPT must be valid on the larger disk: both headers, regenerated CRCs.
    let verify = Command::new("sgdisk")
        .args(["--verify", &target.display().to_string()])
        .output()
        .expect("sgdisk --verify");
    assert!(
        verify.status.success(),
        "sgdisk --verify failed: {}{}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );

    // Same partitions, same offsets and sizes.
    let restored_offsets = partition_offsets(&target);
    assert_eq!(restored_offsets, offsets, "partition layout changed");

    // Regions round-trip byte for byte: the leading area with its boot loader,
    // the two raw partitions and the swap header.
    assert_eq!(
        read_at(&source, CORE_IMG_OFFSET, 5),
        vec![0xEB, 0x63, 0x90, 0xA5, 0x5A],
        "the fixture's boot loader bytes are in place"
    );
    // The leading region matches except for the primary GPT (header, entries
    // and their CRCs), which restore regenerates for the larger target.
    const GPT_AREA: usize = 34 * 512;
    let source_head = read_at(&source, 0, LEADING_BYTES as usize);
    let target_head = read_at(&target, 0, LEADING_BYTES as usize);
    assert_eq!(
        source_head[GPT_AREA..],
        target_head[GPT_AREA..],
        "the boot loader area of the leading region must be identical"
    );
    assert_eq!(
        source_head[..512],
        target_head[..512],
        "the protective MBR must be identical"
    );
    assert_eq!(
        read_at(&source, offsets[0], 1024 * 1024),
        read_at(&target, offsets[0], 1024 * 1024),
        "the BIOS boot partition must be identical"
    );
    assert_eq!(
        read_at(&source, offsets[1], 4 * 1024 * 1024),
        read_at(&target, offsets[1], 4 * 1024 * 1024),
        "the ESP must be identical"
    );
    assert_eq!(
        read_at(&source, offsets[3], 4096),
        read_at(&target, offsets[3], 4096),
        "the swap header must be identical"
    );

    // Space beyond the source disk is untouched.
    let tail = read_at(&target, SRC_SIZE, 4096);
    assert!(
        tail.iter().all(|byte| *byte == 0),
        "extra space must stay untouched"
    );
}

#[test]
fn a_disk_without_a_partition_table_stays_a_block_backup() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("plain.img");
    sparse(&source, 8 * 1024 * 1024);
    let outcome = dir.path().join("out");
    let report = backup_image(&request(&source, &outcome)).expect("backup");
    assert!(
        matches!(report, ImageReport::Block(_)),
        "a disk without a table is a block source"
    );
}

#[test]
fn restore_of_a_whole_disk_refuses_a_changed_target() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("source.img");
    if !build_disk(&source) {
        return;
    }
    let outcome = dir.path().join("out");
    let report = backup_image(&request(&source, &outcome)).expect("backup");
    let ImageReport::WholeDisk(disk) = &report else {
        panic!("expected a whole-disk image");
    };
    let target = dir.path().join("target.img");
    sparse(&target, DST_SIZE);
    let plan = prepare_restore(&PrepareRequest::from_path(
        &disk.image_path,
        &target,
        Encryption::NoEncrypt,
    ))
    .expect("prepare");

    // Repartition the target between prepare and apply.
    assert!(run("sgdisk", &["--clear", &target.display().to_string()]));
    let error = apply_restore(&ApplyRequest {
        token: plan.token,
        confirm: true,
        accept_inconsistent: false,
        encryption: Encryption::NoEncrypt,
        context: lr_engine::progress::EngineContext::silent(),
    })
    .expect_err("a changed target must be rejected");
    assert!(matches!(error, lr_core::Error::TargetChanged), "{error}");
}

/// Keeps the helper list honest: the image path must exist after a backup.
#[test]
fn the_image_file_is_finalized() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("source.img");
    if !build_disk(&source) {
        return;
    }
    let outcome = dir.path().join("out");
    let report = backup_image(&request(&source, &outcome)).expect("backup");
    let path: PathBuf = match &report {
        ImageReport::Block(report) => report.image_path.clone(),
        ImageReport::WholeDisk(report) => report.image_path.clone(),
        ImageReport::Stream(report) => report.image_path.clone(),
        ImageReport::File(report) => report.image_path.clone(),
    };
    assert!(path.exists(), "{} must exist", path.display());
    assert!(!path.with_extension("lrimg.tmp").exists());
}
