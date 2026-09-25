//! Read-only inspection shared by the CLI and the daemon (spec §J.1, §I).
//!
//! Both front ends must print and serialize the same facts, so the formatting
//! and JSON live here instead of in the CLI.

use std::path::Path;

use lr_core::sysfs::SysfsBlockDevice;
use lr_core::{Error, Result, SourceLayout, discovery::discover_source};

/// One block device as `disk list` reports it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DiskListEntry {
    /// Kernel name.
    pub name: String,
    /// Device node path.
    pub path: String,
    /// Size in bytes.
    pub size_bytes: u64,
    /// Human-readable size.
    pub size_human: String,
    /// Logical sector size.
    pub logical_block_size: u32,
    /// Physical sector size.
    pub physical_block_size: u32,
    /// `major:minor`.
    pub dev_id: String,
    /// Removable medium.
    pub removable: bool,
    /// Read-only device.
    pub read_only: bool,
    /// Partition number, when this is a partition.
    pub partition: Option<u32>,
    /// Parent device name, when this is a partition.
    pub parent: Option<String>,
    /// Device-mapper or md holders.
    pub holders: Vec<String>,
    /// Mount points.
    pub mountpoints: Vec<String>,
}

impl DiskListEntry {
    /// Describe one sysfs device.
    #[must_use]
    pub fn from_sysfs(device: &SysfsBlockDevice) -> Self {
        let mountpoints = lr_core::sysfs::read_mountpoints(&device.path)
            .unwrap_or_default()
            .into_iter()
            .map(|path| path.display().to_string())
            .collect();
        Self {
            name: device.name.clone(),
            path: device.path.display().to_string(),
            size_bytes: device.size_bytes,
            size_human: human_size(device.size_bytes),
            logical_block_size: device.logical_block_size,
            physical_block_size: device.physical_block_size,
            dev_id: device.dev_id.clone(),
            removable: device.removable,
            read_only: device.read_only,
            partition: device.partition,
            parent: device.parent.clone(),
            holders: device.holders.clone(),
            mountpoints,
        }
    }

    /// A short device class label (`disk`, `partition`, `loop`, ...).
    #[must_use]
    pub fn type_label(&self) -> String {
        if self.partition.is_some() {
            "partition".to_owned()
        } else if self.name.starts_with("loop") {
            "loop".to_owned()
        } else if self.name.starts_with("dm-") {
            "dm".to_owned()
        } else if self.name.starts_with("ram") {
            "ram".to_owned()
        } else if self.read_only {
            "rom".to_owned()
        } else {
            "disk".to_owned()
        }
    }
}

/// `disk list`: every block device, optionally including partitions.
///
/// # Errors
/// Propagates sysfs read errors.
pub fn disk_list(all: bool) -> Result<Vec<DiskListEntry>> {
    let devices = if all {
        lr_core::sysfs::list_all_block_devices()
    } else {
        lr_core::sysfs::list_block_devices()
    }?;
    Ok(devices.iter().map(DiskListEntry::from_sysfs).collect())
}

/// `disk list --json`.
///
/// # Errors
/// Propagates sysfs and serialization errors.
pub fn disk_list_json(all: bool) -> Result<String> {
    let entries = disk_list(all)?;
    serde_json::to_string_pretty(&entries)
        .map_err(|error| Error::corrupt(format!("disk list json: {error}")))
}

/// `disk map --json`: the discovered layout of one device.
///
/// # Errors
/// Propagates discovery and serialization errors.
pub fn disk_map_json(device: &Path) -> Result<String> {
    let layout: SourceLayout = discover_source(device)?;
    let mut value = serde_json::to_value(&layout)
        .map_err(|error| Error::corrupt(format!("disk map json: {error}")))?;
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "size_human".to_owned(),
            serde_json::Value::String(human_size(layout.device_facts.size_bytes)),
        );
    }
    serde_json::to_string_pretty(&value)
        .map_err(|error| Error::corrupt(format!("disk map json: {error}")))
}

/// Bytes in binary units, as the CLI has always printed them.
#[must_use]
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::human_size;

    #[test]
    fn sizes_are_printed_in_binary_units() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(1023), "1023 B");
        assert_eq!(human_size(1024), "1.0 KiB");
        assert_eq!(human_size(1536), "1.5 KiB");
        assert_eq!(human_size(1024 * 1024 * 1024), "1.0 GiB");
    }
}
