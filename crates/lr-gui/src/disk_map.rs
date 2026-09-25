//! Disk panels for the main view: every disk with a display-ready partition
//! bar, built from the daemon's disk map or, when that is unavailable, from
//! the plain device list. Independent of Slint so it can be tested directly.

use lr_core::SourceLayout;

use crate::devices::Device;
use crate::geometry;
use crate::human_size;

/// The narrowest a partition is drawn, as a fraction of the bar. Without it a
/// 1 MiB BIOS boot partition on a 2 TB disk would be impossible to click.
const MIN_EXTENT: f32 = 0.08;
/// Unallocated space smaller than this is not worth a tile of its own.
const MIN_GAP: f64 = 0.02;

/// One tile of a partition bar.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Segment {
    /// Index of the device row this tile selects, or `None` for free space and
    /// partitions the device list does not know.
    pub row: Option<usize>,
    /// Device node, empty for free space.
    pub path: String,
    /// First line: partition number and name.
    pub title: String,
    /// Second line: filesystem and size.
    pub detail: String,
    /// Mount points, comma separated.
    pub mounts: String,
    /// Filesystem type (`ext4`, `vfat`, …), `free` or `unknown`.
    pub fs: String,
    /// Display position and width, as fractions of the bar.
    pub start: f32,
    pub extent: f32,
}

/// One disk panel.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Panel {
    /// Index of the disk's own row.
    pub row: usize,
    pub title: String,
    pub subtitle: String,
    /// Why details are missing or approximate; empty when the map is exact.
    pub note: String,
    pub segments: Vec<Segment>,
}

/// A position on the disk before display widening: `(start, extent)` as
/// fractions of the disk, plus the tile itself.
type Placed = (f64, f64, Segment);

/// The panel for `disk` (row `disk_row`) from the daemon's exact disk map.
pub(crate) fn from_layout(
    disk_number: usize,
    disk_row: usize,
    rows: &[&Device],
    layout: &SourceLayout,
) -> Panel {
    let disk = rows[disk_row];
    let facts = &layout.device_facts;
    let table = layout
        .partition_table
        .as_ref()
        .map(|table| format!("{:?}", table.kind).to_uppercase());
    let mut panel = Panel {
        row: disk_row,
        title: disk_title(disk_number, disk, facts.model.as_deref()),
        subtitle: disk_subtitle(disk, facts.size_bytes, table.as_deref()),
        note: String::new(),
        segments: Vec::new(),
    };
    if layout.partitions.is_empty() {
        // A filesystem (or nothing recognisable) directly on the disk.
        let fs = layout
            .fs
            .as_ref()
            .map_or_else(|| "unknown".to_owned(), |fs| fs.fs_type.clone());
        let label = layout.fs.as_ref().and_then(|fs| fs.label.clone());
        panel.segments.push(Segment {
            row: Some(disk_row),
            path: disk.path.clone(),
            title: label.unwrap_or_else(|| "Whole disk".to_owned()),
            detail: format!("{fs} · {}", human_size(facts.size_bytes)),
            mounts: disk.mountpoints.join(", "),
            fs,
            start: 0.0,
            extent: 1.0,
        });
        return panel;
    }
    let mut placed: Vec<Placed> = Vec::new();
    for partition in &layout.partitions {
        let Some((start, extent)) = geometry::relative_extent(
            partition.start_lba,
            facts.logical_block_size,
            partition.size_bytes,
            facts.size_bytes,
        ) else {
            return from_list(
                disk_number,
                disk_row,
                rows,
                "The partition table does not fit the disk; sizes are approximate.",
            );
        };
        let path = partition
            .path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_default();
        let row = rows.iter().position(|device| {
            device.partition.is_some()
                && device.parent.as_deref() == Some(disk.name.as_str())
                && (device.path == path || device.partition == Some(partition.index))
        });
        let name = partition
            .fs_label
            .clone()
            .or_else(|| partition.name.clone())
            .filter(|name| !name.is_empty());
        let fs = partition
            .fs_type
            .clone()
            .unwrap_or_else(|| "unknown".to_owned());
        placed.push((
            f64::from(start),
            f64::from(extent),
            Segment {
                row,
                path: row.map_or(path, |row| rows[row].path.clone()),
                title: match name {
                    Some(name) => format!("{} · {name}", partition.index),
                    None => format!("Partition {}", partition.index),
                },
                detail: format!("{fs} · {}", human_size(partition.size_bytes)),
                mounts: partition
                    .mountpoints
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
                fs,
                start: 0.0,
                extent: 0.0,
            },
        ));
    }
    panel.segments = arrange(placed, facts.size_bytes);
    panel
}

/// The panel from the device list alone: partitions in order, sized by their
/// capacity. Used when the daemon cannot map the disk.
pub(crate) fn from_list(
    disk_number: usize,
    disk_row: usize,
    rows: &[&Device],
    note: &str,
) -> Panel {
    let disk = rows[disk_row];
    let partitions: Vec<usize> = rows
        .iter()
        .enumerate()
        .filter(|(_, device)| {
            device.partition.is_some() && device.parent.as_deref() == Some(disk.name.as_str())
        })
        .map(|(index, _)| index)
        .collect();
    let total = disk.size_bytes.max(1) as f64;
    let mut placed: Vec<Placed> = Vec::new();
    let mut offset = 0.0_f64;
    if partitions.is_empty() {
        placed.push((
            0.0,
            1.0,
            Segment {
                row: Some(disk_row),
                path: disk.path.clone(),
                title: "Whole disk".to_owned(),
                detail: human_size(disk.size_bytes),
                mounts: disk.mountpoints.join(", "),
                fs: "unknown".to_owned(),
                start: 0.0,
                extent: 0.0,
            },
        ));
    }
    for index in partitions {
        let device = rows[index];
        let extent = (device.size_bytes as f64 / total).clamp(0.0, 1.0 - offset);
        placed.push((
            offset,
            extent,
            Segment {
                row: Some(index),
                path: device.path.clone(),
                title: format!("Partition {}", device.partition.unwrap_or_default()),
                detail: human_size(device.size_bytes),
                mounts: device.mountpoints.join(", "),
                fs: "unknown".to_owned(),
                start: 0.0,
                extent: 0.0,
            },
        ));
        offset += extent;
    }
    Panel {
        row: disk_row,
        title: disk_title(disk_number, disk, None),
        subtitle: disk_subtitle(disk, disk.size_bytes, None),
        note: note.to_owned(),
        segments: arrange(placed, disk.size_bytes),
    }
}

fn disk_title(number: usize, disk: &Device, model: Option<&str>) -> String {
    match model.map(str::trim).filter(|model| !model.is_empty()) {
        Some(model) => format!("Disk {number} · {model}"),
        None => format!("Disk {number} · {}", disk.name),
    }
}

fn disk_subtitle(disk: &Device, size: u64, table: Option<&str>) -> String {
    let mut parts = vec![human_size(size)];
    parts.push(table.map_or_else(|| "no partition table".to_owned(), |t| t.to_owned()));
    parts.push(disk.path.clone());
    if disk.removable {
        parts.push("removable".to_owned());
    }
    if disk.read_only {
        parts.push("read-only".to_owned());
    }
    parts.join(" · ")
}

/// Sort the tiles, insert visible unallocated gaps and widen tiny tiles so
/// every one of them can be read and clicked, keeping the order and the sum.
fn arrange(mut placed: Vec<Placed>, disk_size: u64) -> Vec<Segment> {
    placed.sort_by(|a, b| a.0.total_cmp(&b.0));
    let free = |start: f64, extent: f64| Segment {
        row: None,
        path: String::new(),
        title: "Unallocated".to_owned(),
        detail: human_size((extent * disk_size as f64) as u64),
        mounts: String::new(),
        fs: "free".to_owned(),
        start: start as f32,
        extent: extent as f32,
    };
    let mut tiles: Vec<(f64, Segment)> = Vec::new();
    let mut cursor = 0.0_f64;
    for (start, extent, segment) in placed {
        if start - cursor >= MIN_GAP {
            tiles.push((start - cursor, free(cursor, start - cursor)));
        }
        tiles.push((extent, segment));
        cursor = cursor.max(start + extent);
    }
    if 1.0 - cursor >= MIN_GAP {
        tiles.push((1.0 - cursor, free(cursor, 1.0 - cursor)));
    }
    let widths = widen(&tiles.iter().map(|(extent, _)| *extent).collect::<Vec<_>>());
    let mut start = 0.0_f32;
    tiles
        .into_iter()
        .zip(widths)
        .map(|((_, mut segment), width)| {
            segment.start = start;
            segment.extent = width;
            start += width;
            segment
        })
        .collect()
}

/// Display widths: proportional, but never below [`MIN_EXTENT`] when there is
/// room, and always summing to 1.
fn widen(extents: &[f64]) -> Vec<f32> {
    let count = extents.len();
    if count == 0 {
        return Vec::new();
    }
    let floor = f64::from(MIN_EXTENT).min(1.0 / count as f64);
    let small: f64 = extents.iter().filter(|e| **e < floor).count() as f64 * floor;
    let large: f64 = extents.iter().filter(|e| **e >= floor).sum();
    let scale = if large > 0.0 {
        (1.0 - small) / large
    } else {
        0.0
    };
    let mut widths: Vec<f64> = extents
        .iter()
        .map(|extent| {
            if *extent < floor {
                floor
            } else {
                extent * scale
            }
        })
        .collect();
    if large <= 0.0 {
        widths = vec![1.0 / count as f64; count];
    }
    widths.into_iter().map(|width| width as f32).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(name: &str, size: u64, partition: Option<u32>, parent: Option<&str>) -> Device {
        serde_json::from_value(serde_json::json!({
            "name": name, "path": format!("/dev/{name}"), "size_bytes": size,
            "partition": partition, "parent": parent, "read_only": false,
            "removable": false, "mountpoints": [], "holders": []
        }))
        .expect("device")
    }

    fn sum(segments: &[Segment]) -> f32 {
        segments.iter().map(|segment| segment.extent).sum()
    }

    #[test]
    fn tiny_partitions_stay_clickable_and_the_bar_stays_full() {
        let widths = widen(&[0.000_001, 0.5, 0.499_999]);
        assert!(widths[0] >= MIN_EXTENT - f32::EPSILON, "{widths:?}");
        assert!((widths.iter().sum::<f32>() - 1.0).abs() < 1e-5);
        assert!(widths[1] > widths[0]);
    }

    #[test]
    fn many_partitions_share_the_bar_evenly_when_all_are_tiny() {
        let widths = widen(&[0.001; 20]);
        assert_eq!(widths.len(), 20);
        assert!((widths.iter().sum::<f32>() - 1.0).abs() < 1e-5);
    }

    #[test]
    fn the_device_list_fallback_keeps_rows_and_marks_free_space() {
        let disk = device("sda", 1000, None, None);
        let one = device("sda1", 100, Some(1), Some("sda"));
        let two = device("sda2", 500, Some(2), Some("sda"));
        let rows = [&disk, &one, &two];
        let panel = from_list(1, 0, &rows, "Details unavailable");
        let selectable: Vec<_> = panel.segments.iter().filter_map(|s| s.row).collect();
        assert_eq!(selectable, [1, 2]);
        assert_eq!(panel.segments.last().map(|s| s.fs.as_str()), Some("free"));
        assert!((sum(&panel.segments) - 1.0).abs() < 1e-5);
        assert_eq!(panel.note, "Details unavailable");
        assert!(panel.title.contains("sda"));
    }

    #[test]
    fn an_unpartitioned_disk_is_one_selectable_tile() {
        let disk = device("sdb", 4096, None, None);
        let rows = [&disk];
        let panel = from_list(2, 0, &rows, "");
        assert_eq!(panel.segments.len(), 1);
        assert_eq!(panel.segments[0].row, Some(0));
        assert_eq!(panel.segments[0].path, "/dev/sdb");
    }
}
