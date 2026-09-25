//! Typed disk-list data and advisory destination eligibility, independent of UI.
//! The daemon must still revalidate the destination before every write.

#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct Device {
    pub name: String,
    pub path: String,
    pub size_bytes: u64,
    pub partition: Option<u32>,
    pub parent: Option<String>,
    pub read_only: bool,
    pub removable: bool,
    pub mountpoints: Vec<String>,
    pub holders: Vec<String>,
}

impl Device {
    fn unavailable(&self) -> Option<String> {
        if self.read_only {
            Some("Read-only device".into())
        } else if self.size_bytes == 0 {
            Some("No storage capacity reported".into())
        } else if !self.mountpoints.is_empty() {
            Some(format!("Mounted at {}", self.mountpoints.join(", ")))
        } else if !self.holders.is_empty() {
            Some(format!("In use by {}", self.holders.join(", ")))
        } else {
            None
        }
    }

    pub(crate) fn restore_unavailable(&self, entries: &[Self]) -> String {
        if let Some(reason) = self.unavailable() {
            return reason;
        }
        if self.partition.is_none() {
            for child in entries
                .iter()
                .filter(|entry| entry.parent.as_deref() == Some(&self.name))
            {
                if let Some(reason) = child.unavailable() {
                    return format!("{}: {reason}", child.path);
                }
            }
        }
        String::new()
    }
}

pub(crate) fn ordered(entries: &[Device], show_service: bool) -> Vec<&Device> {
    let mut disks: Vec<_> = entries
        .iter()
        .filter(|entry| {
            entry.partition.is_none()
                && (show_service
                    || (entry.size_bytes > 0
                        && !["loop", "ram", "fd", "sr", "zram"]
                            .iter()
                            .any(|prefix| entry.name.starts_with(prefix))))
        })
        .collect();
    disks.sort_by(|a, b| a.name.cmp(&b.name));
    let mut result = Vec::new();
    for disk in disks {
        result.push(disk);
        let mut partitions: Vec<_> = entries
            .iter()
            .filter(|entry| {
                entry.partition.is_some() && entry.parent.as_deref() == Some(&disk.name)
            })
            .collect();
        partitions.sort_by_key(|entry| entry.partition);
        result.extend(partitions);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn disk(name: &str) -> Device {
        serde_json::from_value(serde_json::json!({
            "name": name, "path": format!("/dev/{name}"), "size_bytes": 4096,
            "partition": null, "parent": null, "read_only": false,
            "removable": false, "mountpoints": [], "holders": []
        }))
        .unwrap()
    }

    #[test]
    fn null_partition_and_numeric_partition_are_grouped_and_sorted() {
        let disk = disk("sda");
        let mut second = disk.clone();
        second.name = "sda2".into();
        second.partition = Some(2);
        second.parent = Some("sda".into());
        let mut first = second.clone();
        first.name = "sda1".into();
        first.partition = Some(1);
        let entries = [second, disk, first];
        assert_eq!(
            ordered(&entries, false)
                .iter()
                .map(|d| d.name.as_str())
                .collect::<Vec<_>>(),
            ["sda", "sda1", "sda2"]
        );
    }

    #[test]
    fn mounted_child_blocks_whole_disk_but_not_other_partition() {
        let disk = disk("sda");
        let mut child = disk.clone();
        child.path = "/dev/sda1".into();
        child.partition = Some(1);
        child.parent = Some("sda".into());
        child.mountpoints.push("/boot".into());
        let mut other = child.clone();
        other.mountpoints.clear();
        let entries = [disk.clone(), child];
        assert!(disk.restore_unavailable(&entries).contains("/boot"));
        assert!(other.restore_unavailable(&entries).is_empty());
    }

    #[test]
    fn capacity_readonly_holders_and_filter_are_explicit() {
        let mut empty = disk("nbd0");
        empty.size_bytes = 0;
        let mut readonly = disk("sdc");
        readonly.read_only = true;
        let mut held = disk("sdb");
        held.holders.push("dm-0".into());
        let entries = [
            empty,
            readonly,
            held,
            disk("loop0"),
            disk("fd0"),
            disk("sr1"),
        ];
        // Zero-sized, loop, floppy and optical devices are service devices; a
        // read-only disk is still listed (it can be backed up, not restored to).
        assert_eq!(
            ordered(&entries, false)
                .iter()
                .map(|d| d.name.as_str())
                .collect::<Vec<_>>(),
            ["sdb", "sdc"]
        );
        assert_eq!(ordered(&entries, true).len(), 6);
        for entry in &entries[..3] {
            assert!(!entry.restore_unavailable(&entries).is_empty());
        }
        assert!(serde_json::from_str::<Device>(r#"{"name":"sda","partition":null}"#).is_err());
    }
}
