//! View models for the Slint window: disk rows and panels, the selection,
//! and the backup specification the wizard describes.

use super::*;

/// Snapshot every user-visible backup setting for inspection and execution.
pub(crate) fn backup_spec(ui: &MainWindow) -> BackupSpec {
    let member_type = ui.get_member_type().to_string();
    let snapshot = ui.get_snapshot().to_string();
    let encrypt = ui.get_encrypt();
    BackupSpec {
        source: ui.get_source().to_string(),
        dest: ui.get_destination().to_string(),
        set: ui.get_backup_set().to_string(),
        mode: ui.get_mode().to_string(),
        parent: if member_type == "full" {
            String::new()
        } else {
            "latest".into()
        },
        member_type,
        allow_freeze: snapshot == "freeze" && ui.get_allow_freeze(),
        allow_inconsistent: snapshot == "none" && ui.get_allow_inconsistent(),
        snapshot: if snapshot == "auto" {
            String::new()
        } else {
            snapshot
        },
        compress: ui.get_compress().to_string(),
        no_encrypt: !encrypt,
        passphrase_file: if encrypt {
            ui.get_passphrase_file().to_string()
        } else {
            String::new()
        },
        on_bad_sector: ui.get_bad_sector().to_string(),
        ..BackupSpec::default()
    }
}

/// Slint panels for the disk page; each tile carries the restore eligibility
/// of the row it selects.
pub(crate) fn disk_cards(panels: &[disk_map::Panel], rows: &[DiskRow]) -> slint::ModelRc<DiskCard> {
    let row_index = |row: Option<usize>| row.and_then(|row| i32::try_from(row).ok()).unwrap_or(-1);
    let cards: Vec<DiskCard> = panels
        .iter()
        .map(|panel| {
            let tiles: Vec<PartitionTile> = panel
                .segments
                .iter()
                .map(|segment| PartitionTile {
                    row: row_index(segment.row),
                    path: segment.path.clone().into(),
                    title: segment.title.clone().into(),
                    detail: segment.detail.clone().into(),
                    mounts: segment.mounts.clone().into(),
                    fs: segment.fs.clone().into(),
                    unavailable: segment
                        .row
                        .and_then(|row| rows.get(row))
                        .map(|row| row.restore_unavailable.clone())
                        .unwrap_or_default(),
                    start: segment.start,
                    extent: segment.extent,
                })
                .collect();
            DiskCard {
                disk_index: row_index(Some(panel.row)),
                title: panel.title.clone().into(),
                subtitle: panel.subtitle.clone().into(),
                note: panel.note.clone().into(),
                tiles: slint::ModelRc::new(slint::VecModel::from(tiles)),
            }
        })
        .collect();
    slint::ModelRc::new(slint::VecModel::from(cards))
}

/// The first line of an error chain, for a one-line message in a panel.
pub(crate) fn first_line(error: &anyhow::Error) -> String {
    let text = format!("{error:#}");
    text.lines().next().unwrap_or_default().to_owned()
}

/// The disk row containing `path`: the disk itself or the parent of a
/// partition row.
pub(crate) fn containing_disk(ui: &MainWindow, path: &str) -> i32 {
    let disks = ui.get_disks();
    let Some(index) = (0..disks.row_count())
        .find(|index| disks.row_data(*index).is_some_and(|row| row.path == path))
    else {
        return -1;
    };
    (0..=index)
        .rev()
        .find(|index| disks.row_data(*index).is_some_and(|row| row.is_disk))
        .and_then(|index| i32::try_from(index).ok())
        .unwrap_or(-1)
}

/// Keep the selection highlighted after the disk list was reloaded.
pub(crate) fn reselect(ui: &MainWindow) {
    let source = ui.get_source().to_string();
    ui.set_selected_disk(containing_disk(ui, &source));
}

/// One row of the disk map: a disk or one of its partitions.
pub(crate) fn disk_row(entry: &devices::Device, entries: &[devices::Device]) -> DiskRow {
    let is_disk = entry.partition.is_none();
    let mut kind = if is_disk { "disk" } else { "partition" }.to_owned();
    if entry.read_only {
        kind.push_str(" · read-only");
    }
    if entry.removable {
        kind.push_str(" · removable");
    }
    if !entry.mountpoints.is_empty() {
        kind.push_str(&format!(" · mounted {}", entry.mountpoints.join(", ")));
    }
    if !entry.holders.is_empty() {
        kind.push_str(&format!(" · in use by {}", entry.holders.join(", ")));
    }
    DiskRow {
        name: entry.name.clone().into(),
        kind: kind.into(),
        size: human_size(entry.size_bytes).into(),
        path: entry.path.clone().into(),
        is_disk,
        restore_unavailable: entry.restore_unavailable(entries).into(),
    }
}
