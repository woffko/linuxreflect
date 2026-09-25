//! S1 acceptance support: sysfs parsing against a fixture tree.
//!
//! This proves the sysfs reader reports the size and sector size of a loop
//! device without requiring root. The fixture mirrors what the kernel exposes
//! for `truncate -s 1G d.img; losetup -f --show d.img`.

use std::path::Path;

use lr_core::sysfs::{list_block_devices_at, read_holders_at};

fn write(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create fixture dir");
    }
    std::fs::write(path, contents).expect("write fixture file");
}

#[test]
fn loop_device_reports_one_gib_and_sector_size() {
    let root = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(root.path().join("block")).expect("block dir");
    std::fs::create_dir_all(root.path().join("class/block")).expect("class dir");

    let loop_dir = root.path().join("block/loop0");
    write(&loop_dir.join("size"), "2097152\n"); // 1 GiB / 512 B
    write(&loop_dir.join("queue/logical_block_size"), "512\n");
    write(&loop_dir.join("queue/physical_block_size"), "4096\n");
    write(&loop_dir.join("dev"), "7:0\n");
    write(&loop_dir.join("removable"), "0\n");
    write(&loop_dir.join("ro"), "0\n");
    std::fs::create_dir_all(loop_dir.join("holders")).expect("holders dir");

    let devices = list_block_devices_at(root.path()).expect("list devices");
    assert_eq!(devices.len(), 1, "fixture must expose exactly one device");
    let device = &devices[0];
    assert_eq!(device.name, "loop0");
    assert_eq!(device.size_bytes, 1024 * 1024 * 1024, "1 GiB");
    assert_eq!(device.logical_block_size, 512);
    assert_eq!(device.physical_block_size, 4096);
    assert_eq!(device.dev_id, "7:0");
    assert!(device.holders.is_empty());
    assert_eq!(read_holders_at(root.path(), "loop0"), Vec::<String>::new());
}

#[test]
fn partition_devices_are_classified() {
    let root = tempfile::tempdir().expect("tempdir");
    let whole = root.path().join("block/sda");
    write(&whole.join("size"), "41943040\n"); // 20 GiB
    write(&whole.join("queue/logical_block_size"), "512\n");
    write(&whole.join("dev"), "8:0\n");
    std::fs::create_dir_all(whole.join("device")).expect("device dir");

    let part = root.path().join("class/block/sda1");
    write(&part.join("size"), "1048576\n"); // 512 MiB
    write(&part.join("queue/logical_block_size"), "512\n");
    write(&part.join("dev"), "8:1\n");
    write(&part.join("partition"), "1\n");

    let devices = list_block_devices_at(root.path()).expect("list whole disks");
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].size_bytes, 20 * 1024 * 1024 * 1024);

    let all = lr_core::sysfs::list_all_block_devices_at(root.path()).expect("list all");
    let partition = all
        .iter()
        .find(|d| d.name == "sda1")
        .expect("partition present");
    assert_eq!(partition.partition, Some(1));
    assert!(!partition.is_whole_disk());
}
