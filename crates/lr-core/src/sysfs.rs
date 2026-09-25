//! Read-only sysfs and `/proc` helpers for block-device discovery (spec §S1, §S2).
//!
//! All paths are derived from a configurable root (`LR_SYSFS_ROOT`,
//! `LR_MOUNTINFO`) so that tests can run against fixtures without root.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

/// Root of the sysfs tree (override with `LR_SYSFS_ROOT` for tests).
#[must_use]
pub fn sysfs_root() -> PathBuf {
    std::env::var_os("LR_SYSFS_ROOT").map_or_else(|| PathBuf::from("/sys"), PathBuf::from)
}

/// Path of the mount table (override with `LR_MOUNTINFO` for tests).
#[must_use]
pub fn mountinfo_path() -> PathBuf {
    std::env::var_os("LR_MOUNTINFO")
        .map_or_else(|| PathBuf::from("/proc/self/mountinfo"), PathBuf::from)
}

/// A block device as reported by sysfs.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SysfsBlockDevice {
    /// Kernel device name, e.g. `sda`, `sda1`, `loop0`.
    pub name: String,
    /// Device node path, e.g. `/dev/sda`.
    pub path: PathBuf,
    /// Size in bytes (`size` sysfs attribute is in 512-byte units).
    pub size_bytes: u64,
    /// Logical block size in bytes.
    pub logical_block_size: u32,
    /// Physical block size in bytes.
    pub physical_block_size: u32,
    /// `major:minor`.
    pub dev_id: String,
    /// Whether the device is removable.
    pub removable: bool,
    /// Whether the device is read-only.
    pub read_only: bool,
    /// Partition number when this device is a partition.
    pub partition: Option<u32>,
    /// Parent whole-disk name when this device is a partition.
    pub parent: Option<String>,
    /// Devices that hold this one (dm/md/LVM mappings).
    pub holders: Vec<String>,
}

impl SysfsBlockDevice {
    /// `true` when this is a whole disk (no `partition` attribute).
    #[must_use]
    pub const fn is_whole_disk(&self) -> bool {
        self.partition.is_none()
    }
}

fn parse_u64_file(path: &Path) -> io::Result<u64> {
    lr_unsafe::read_sysfs_u64(path)
}

fn parse_u32_file(path: &Path) -> io::Result<u32> {
    let raw = lr_unsafe::read_sysfs_string(path)?;
    raw.parse::<u32>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn read_bool_file(path: &Path) -> Option<bool> {
    lr_unsafe::read_sysfs_string(path).ok().map(|v| v != "0")
}

/// List whole disks under `/sys/block`.
///
/// # Errors
/// Returns an error only when the sysfs tree cannot be read at all.
pub fn list_block_devices() -> io::Result<Vec<SysfsBlockDevice>> {
    list_block_devices_at(&sysfs_root())
}

/// List whole disks under `<root>/block`.
///
/// # Errors
/// Returns an error only when the directory cannot be read at all.
pub fn list_block_devices_at(root: &Path) -> io::Result<Vec<SysfsBlockDevice>> {
    list_devices_in(&root.join("block"), false)
}

/// List every block device including partitions, via `/sys/class/block`.
///
/// # Errors
/// Returns an error only when the sysfs tree cannot be read at all.
pub fn list_all_block_devices() -> io::Result<Vec<SysfsBlockDevice>> {
    list_all_block_devices_at(&sysfs_root())
}

/// List every block device including partitions, via `<root>/class/block`.
///
/// # Errors
/// Returns an error only when the directory cannot be read at all.
pub fn list_all_block_devices_at(root: &Path) -> io::Result<Vec<SysfsBlockDevice>> {
    list_devices_in(&root.join("class/block"), true)
}

fn list_devices_in(dir: &Path, include_partitions: bool) -> io::Result<Vec<SysfsBlockDevice>> {
    let mut devices = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(devices),
        Err(e) => return Err(e),
    };
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        match read_device(&name, &path) {
            Ok(Some(device)) => {
                if include_partitions || device.is_whole_disk() {
                    devices.push(device);
                }
            }
            Ok(None) => {}
            Err(e) => {
                tracing::debug!(device = %name, error = %e, "skipping sysfs block device");
            }
        }
    }
    devices.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(devices)
}

fn read_device(name: &str, dir: &Path) -> io::Result<Option<SysfsBlockDevice>> {
    let size_sectors = match parse_u64_file(&dir.join("size")) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    let logical_block_size = parse_u32_file(&dir.join("queue/logical_block_size")).unwrap_or(512);
    let physical_block_size =
        parse_u32_file(&dir.join("queue/physical_block_size")).unwrap_or(logical_block_size);
    let dev_id =
        lr_unsafe::read_sysfs_string(&dir.join("dev")).unwrap_or_else(|_| "0:0".to_owned());
    let partition = parse_u32_file(&dir.join("partition")).ok();
    let parent = partition.and_then(|_| {
        std::fs::canonicalize(dir)
            .ok()
            .and_then(|real| real.parent().map(Path::to_path_buf))
            .and_then(|parent| parent.file_name().map(|n| n.to_string_lossy().into_owned()))
    });
    Ok(Some(SysfsBlockDevice {
        name: name.to_owned(),
        path: PathBuf::from("/dev").join(name),
        size_bytes: size_sectors * 512,
        logical_block_size,
        physical_block_size,
        dev_id,
        removable: read_bool_file(&dir.join("removable")).unwrap_or(false),
        read_only: read_bool_file(&dir.join("ro")).unwrap_or(false),
        partition,
        parent,
        holders: read_holders(name),
    }))
}

/// Read the holders of a device from `/sys/class/block/<name>/holders`.
#[must_use]
pub fn read_holders(name: &str) -> Vec<String> {
    read_holders_at(&sysfs_root(), name)
}

/// Read the holders of a device from `<root>/class/block/<name>/holders`.
#[must_use]
pub fn read_holders_at(root: &Path, name: &str) -> Vec<String> {
    read_dir_names(&root.join("class/block").join(name).join("holders"))
}

/// Read the slaves of a device (a dm/md device's underlying devices).
#[must_use]
pub fn read_slaves(name: &str) -> Vec<String> {
    read_dir_names(&sysfs_root().join("class/block").join(name).join("slaves"))
}

/// Logical block size for a `/dev/<name>` path, from sysfs.
///
/// # Errors
/// Fails when the device name cannot be derived or sysfs has no such device.
pub fn logical_block_size(device: &Path) -> io::Result<u32> {
    let name = device_name(device)?;
    parse_u32_file(
        &sysfs_root()
            .join("class/block")
            .join(name)
            .join("queue/logical_block_size"),
    )
}

/// Extract the kernel device name from a `/dev/...` path.
///
/// # Errors
/// Returns [`io::ErrorKind::InvalidInput`] when the path has no file name.
pub fn device_name(device: &Path) -> io::Result<String> {
    device
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "device path has no name"))
}

fn read_dir_names(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// One line of `/proc/self/mountinfo`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MountEntry {
    /// Device path or source as recorded by the kernel.
    pub source: String,
    /// Mount point.
    pub mountpoint: PathBuf,
    /// Filesystem type.
    pub fs_type: String,
    /// Mount options (comma separated).
    pub options: String,
    /// Major:minor as recorded in mountinfo.
    pub dev_id: String,
}

/// Parse `/proc/self/mountinfo`.
///
/// The format is `id parent major:minor root mountpoint options [optional...] - fstype source superopts`.
///
/// # Errors
/// Fails when the mount table cannot be read.
pub fn read_mounts() -> io::Result<Vec<MountEntry>> {
    let raw = std::fs::read_to_string(mountinfo_path())?;
    Ok(parse_mountinfo(&raw))
}

/// Parse mountinfo text; exposed for fixture-based tests.
#[must_use]
pub fn parse_mountinfo(raw: &str) -> Vec<MountEntry> {
    let mut entries = Vec::new();
    for line in raw.lines() {
        let Some((left, right)) = line.split_once(" - ") else {
            continue;
        };
        let left_fields: Vec<&str> = left.split_whitespace().collect();
        let right_fields: Vec<&str> = right.split_whitespace().collect();
        if left_fields.len() < 6 || right_fields.len() < 3 {
            continue;
        }
        entries.push(MountEntry {
            source: unescape_mount_field(right_fields[1]),
            mountpoint: PathBuf::from(unescape_mount_field(left_fields[4])),
            fs_type: right_fields[0].to_owned(),
            options: right_fields[2].to_owned(),
            dev_id: left_fields[2].to_owned(),
        });
    }
    entries
}

fn unescape_mount_field(field: &str) -> String {
    field
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

/// Mount points for a device path (matched by mountinfo source or `major:minor`).
///
/// # Errors
/// Fails when the mount table cannot be read.
pub fn read_mountpoints(device: &Path) -> io::Result<Vec<PathBuf>> {
    let name = device_name(device).unwrap_or_default();
    let dev_id =
        lr_unsafe::read_sysfs_string(&sysfs_root().join("class/block").join(&name).join("dev"))
            .ok();
    let mounts = read_mounts()?;
    Ok(mounts
        .into_iter()
        .filter(|m| {
            m.source == device.to_string_lossy()
                || Path::new(&m.source) == device
                || dev_id.as_deref() == Some(m.dev_id.as_str())
        })
        .map(|m| m.mountpoint)
        .collect())
}

/// Merge two mount-point lists preserving order and dropping duplicates.
#[must_use]
pub fn merge_mountpoints(a: Vec<PathBuf>, b: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut merged: BTreeMap<String, PathBuf> = BTreeMap::new();
    for p in a.into_iter().chain(b) {
        merged.entry(p.to_string_lossy().into_owned()).or_insert(p);
    }
    merged.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::{merge_mountpoints, parse_mountinfo};
    use std::path::PathBuf;

    const MOUNTINFO: &str = "\
20 28 0:19 / / rw,relatime shared:1 - ext4 /dev/sdd rw
25 20 8:1 / /boot rw,relatime - ext4 /dev/sda1 rw
30 20 8:17 / /mnt/with\\040space ro,relatime - btrfs /dev/nvme0n1p1 ro
";

    #[test]
    fn parses_mountinfo() {
        let entries = parse_mountinfo(MOUNTINFO);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].source, "/dev/sdd");
        assert_eq!(entries[0].fs_type, "ext4");
        assert_eq!(entries[2].mountpoint, PathBuf::from("/mnt/with space"));
    }

    #[test]
    fn merges_and_dedups() {
        let merged = merge_mountpoints(
            vec![PathBuf::from("/a"), PathBuf::from("/b")],
            vec![PathBuf::from("/b"), PathBuf::from("/c")],
        );
        assert_eq!(
            merged,
            vec![
                PathBuf::from("/a"),
                PathBuf::from("/b"),
                PathBuf::from("/c")
            ]
        );
    }
}
