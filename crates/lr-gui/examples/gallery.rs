//! Render the main window's pages to PNG files without a display.
//!
//! ```sh
//! cargo run -p lr-gui --example gallery -- OUT_DIR [SCENE_FILTER] [SIZE_FILTER]
//! ```
//!
//! Every scene is rendered at 1024x768, 1280x720 and 1920x1080, each at 100%,
//! 150% and 200% scaling, with the software renderer the GUI also uses. The
//! data is a fixed set of example disks and jobs; nothing talks to a daemon.
//! This is for reviewing layout, not a substitute for a run on a real display.

use std::path::{Path, PathBuf};
use std::rc::Rc;

use lr_gui::ui::{
    DiskCard, DiskRow, HistoryRow, JobPresentation, JobStage, MainWindow, PartitionTile,
};
use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType};
use slint::platform::{Platform, PlatformError, WindowAdapter, WindowEvent};
use slint::{ComponentHandle, ModelRc, PhysicalSize, Rgb8Pixel, SharedString, VecModel};

thread_local! {
    static WINDOW: Rc<MinimalSoftwareWindow> =
        MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
}

struct Offscreen;

impl Platform for Offscreen {
    fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, PlatformError> {
        Ok(WINDOW.with(Clone::clone))
    }
}

const SIZES: &[(u32, u32, f32)] = &[
    (1024, 768, 1.0),
    (1280, 720, 1.0),
    (1920, 1080, 1.0),
    (1024, 768, 1.5),
    (1280, 720, 1.5),
    (1920, 1080, 1.5),
    (1024, 768, 2.0),
    (1280, 720, 2.0),
    (1920, 1080, 2.0),
];

type Scene = (&'static str, fn(&MainWindow));

const SCENES: &[Scene] = &[
    ("disks", |ui| {
        ui.set_source("/dev/nvme0n1p2".into());
        ui.set_selected_disk(0);
        ui.set_status("3 disks, 6 partitions".into());
    }),
    ("disks-error", |ui| {
        ui.set_disk_cards(ModelRc::default());
        ui.set_disk_error(true);
        ui.set_disk_status(
            "Could not load the disks: connecting to /run/linuxreflect/daemon.sock: \
             permission denied"
                .into(),
        );
    }),
    ("backup-source", |ui| {
        ui.set_current_tab(1);
        ui.set_backup_step(0);
        ui.set_source("/dev/nvme0n1p2".into());
        ui.set_selected_disk(0);
    }),
    ("backup-destination", |ui| {
        ui.set_current_tab(1);
        ui.set_backup_step(1);
        ui.set_source("/dev/nvme0n1p2".into());
        ui.set_destination(
            "/media/backup-drive/LinuxReflect/workstation/a-rather-long-folder-name".into(),
        );
        ui.set_backup_set("workstation-root".into());
        ui.set_advanced_backup(true);
        ui.set_encrypt(true);
    }),
    ("backup-summary", |ui| {
        ui.set_current_tab(1);
        ui.set_backup_step(2);
        ui.set_source("/dev/nvme0n1p2".into());
        ui.set_destination("/media/backup-drive/LinuxReflect".into());
        ui.set_backup_set("workstation-root".into());
        ui.set_show_source_details(true);
        ui.set_plan(
            "provider: btrfs\nimage kind: stream\nconsistency: PointInTime\n\
             estimated: 212.4 GiB"
                .into(),
        );
    }),
    ("backup-running", |ui| {
        ui.set_current_tab(1);
        ui.set_backup_step(3);
        ui.set_busy(true);
        ui.set_has_job(true);
        ui.set_job_id("backup-1".into());
        ui.set_job_operation("backup".into());
        ui.set_progress(0.42);
        ui.set_progress_text("89.2 GiB of 212.4 GiB · 1.1 GiB/s".into());
        ui.set_backup_job(JobPresentation {
            stage: JobStage::Running,
            detail: "Copying used blocks of /dev/nvme0n1p2.".into(),
            report: SharedString::new(),
        });
    }),
    ("library", |ui| {
        ui.set_current_tab(3);
        ui.set_destination("/media/backup-drive/LinuxReflect".into());
        ui.set_backup_set("workstation-root".into());
        ui.set_history(model(vec![
            history(
                "workstation-root",
                true,
                "Incremental backup · Copy 3",
                "Created: 2026-09-22 21:00 UTC · 2.7 GiB",
            ),
            history(
                "workstation-root",
                false,
                "Incremental backup · Copy 2",
                "Created: 2026-09-21 21:00 UTC · 3.1 GiB",
            ),
            history(
                "workstation-root",
                false,
                "Full backup · Copy 1",
                "Created: 2026-09-20 21:00 UTC · 212.4 GiB",
            ),
            history(
                "photos",
                true,
                "Full backup · Copy 1",
                "Created: 2026-09-18 09:12 UTC · 48.0 GiB",
            ),
        ]));
    }),
    ("restore-destination", |ui| {
        ui.set_current_tab(2);
        ui.set_restore_step(1);
        ui.set_image("/media/backup-drive/LinuxReflect/workstation-root/000-full.lrimg".into());
        ui.set_target("/dev/sdb1".into());
        ui.set_choosing_restore_target(true);
    }),
    ("restore-summary", |ui| {
        ui.set_current_tab(2);
        ui.set_restore_step(2);
        ui.set_image("/media/backup-drive/LinuxReflect/workstation-root/000-full.lrimg".into());
        ui.set_target("/dev/sdb1".into());
        ui.set_planned_image(ui.get_image());
        ui.set_planned_target(ui.get_target());
        ui.set_token("token".into());
        ui.set_restore_summary(
            "The backup of /dev/nvme0n1p2 (ext4, 200 GiB) will be written to /dev/sdb1 \
             (SanDisk Extreme, 64 GiB). The image needs 48.2 GiB."
                .into(),
        );
    }),
    ("activity", |ui| {
        ui.set_current_tab(4);
        ui.set_backup_job(JobPresentation {
            stage: JobStage::Succeeded,
            detail: "Backup of /dev/nvme0n1p2 finished: 212.4 GiB read, 96.0 GiB written.".into(),
            report: SharedString::new(),
        });
        ui.set_restore_job(JobPresentation {
            stage: JobStage::Failed,
            detail: "The destination changed after the review. Nothing was written.".into(),
            report: SharedString::new(),
        });
    }),
];

fn model<T: Clone + 'static>(rows: Vec<T>) -> ModelRc<T> {
    ModelRc::new(VecModel::from(rows))
}

fn history(group: &str, first: bool, name: &str, detail: &str) -> HistoryRow {
    HistoryRow {
        name: name.into(),
        detail: detail.into(),
        path: "/media/backup-drive/LinuxReflect/workstation-root/000-full.lrimg".into(),
        group: group.into(),
        first,
    }
}

fn row(name: &str, size: &str, is_disk: bool, unavailable: &str) -> DiskRow {
    DiskRow {
        name: name.into(),
        kind: if is_disk { "disk" } else { "partition" }.into(),
        size: size.into(),
        path: format!("/dev/{name}").into(),
        is_disk,
        restore_unavailable: unavailable.into(),
    }
}

#[allow(clippy::too_many_arguments)]
fn tile(
    row: i32,
    path: &str,
    title: &str,
    detail: &str,
    mounts: &str,
    fs: &str,
    unavailable: &str,
    extent: (f32, f32),
) -> PartitionTile {
    PartitionTile {
        row,
        path: path.into(),
        title: title.into(),
        detail: detail.into(),
        mounts: mounts.into(),
        fs: fs.into(),
        unavailable: unavailable.into(),
        start: extent.0,
        extent: extent.1,
    }
}

/// Three disks: a system NVMe drive, a removable stick and a data disk that
/// the daemon could not map.
fn example_disks(ui: &MainWindow) {
    let busy = "Mounted at /";
    ui.set_disks(model(vec![
        row("nvme0n1", "953.9 GiB", true, "nvme0n1p2: Mounted at /"),
        row("nvme0n1p1", "512 MiB", false, "Mounted at /boot/efi"),
        row("nvme0n1p2", "200 GiB", false, busy),
        row("nvme0n1p3", "737.4 GiB", false, "Mounted at /home"),
        row("nvme0n1p4", "16 GiB", false, "In use as swap"),
        row("sdb", "57.3 GiB", true, ""),
        row("sdb1", "57.3 GiB", false, ""),
        row("sdc", "1.8 TiB", true, ""),
        row("sdc1", "931 GiB", false, ""),
    ]));
    ui.set_disk_cards(model(vec![
        DiskCard {
            disk_index: 0,
            title: "Disk 1 · Samsung SSD 980 PRO 1TB".into(),
            subtitle: "953.9 GiB · GPT · /dev/nvme0n1".into(),
            note: SharedString::new(),
            tiles: model(vec![
                tile(
                    1,
                    "/dev/nvme0n1p1",
                    "1 · EFI",
                    "vfat · 512 MiB",
                    "/boot/efi",
                    "vfat",
                    "Mounted at /boot/efi",
                    (0.0, 0.08),
                ),
                tile(
                    2,
                    "/dev/nvme0n1p2",
                    "2 · root",
                    "ext4 · 200 GiB",
                    "/",
                    "ext4",
                    busy,
                    (0.08, 0.2),
                ),
                tile(
                    3,
                    "/dev/nvme0n1p3",
                    "3 · home",
                    "btrfs · 737.4 GiB",
                    "/home",
                    "btrfs",
                    "Mounted at /home",
                    (0.28, 0.64),
                ),
                tile(
                    4,
                    "/dev/nvme0n1p4",
                    "Partition 4",
                    "swap · 16 GiB",
                    "",
                    "swap",
                    "In use as swap",
                    (0.92, 0.08),
                ),
            ]),
        },
        DiskCard {
            disk_index: 5,
            title: "Disk 2 · SanDisk Extreme".into(),
            subtitle: "57.3 GiB · MBR · /dev/sdb · removable".into(),
            note: SharedString::new(),
            tiles: model(vec![tile(
                6,
                "/dev/sdb1",
                "1 · BACKUP",
                "exfat · 57.3 GiB",
                "",
                "exfat",
                "",
                (0.0, 1.0),
            )]),
        },
        DiskCard {
            disk_index: 7,
            title: "Disk 3 · sdc".into(),
            subtitle: "1.8 TiB · no partition table · /dev/sdc".into(),
            note: "Details unavailable: permission denied".into(),
            tiles: model(vec![
                tile(
                    8,
                    "/dev/sdc1",
                    "Partition 1",
                    "931 GiB",
                    "",
                    "unknown",
                    "",
                    (0.0, 0.5),
                ),
                tile(-1, "", "Unallocated", "931 GiB", "", "free", "", (0.5, 0.5)),
            ]),
        },
    ]));
}

fn render(ui: &MainWindow, window: &MinimalSoftwareWindow, width: u32, height: u32, out: &Path) {
    slint::platform::update_timers_and_animations();
    let mut pixels = vec![Rgb8Pixel::new(0, 0, 0); (width * height) as usize];
    window.request_redraw();
    let _ = ui;
    window.draw_if_needed(|renderer| {
        renderer.render(&mut pixels, width as usize);
    });
    let file = std::fs::File::create(out).expect("create png");
    let mut encoder = png::Encoder::new(std::io::BufWriter::new(file), width, height);
    encoder.set_color(png::ColorType::Rgb);
    encoder.set_depth(png::BitDepth::Eight);
    let bytes: Vec<u8> = pixels
        .iter()
        .flat_map(|pixel| [pixel.r, pixel.g, pixel.b])
        .collect();
    encoder
        .write_header()
        .and_then(|mut writer| writer.write_image_data(&bytes))
        .expect("write png");
}

fn main() {
    let mut args = std::env::args().skip(1);
    let out = PathBuf::from(args.next().expect("usage: gallery OUT_DIR [SCENE] [SIZE]"));
    let scene_filter = args.next().unwrap_or_default();
    let size_filter = args.next().unwrap_or_default();
    std::fs::create_dir_all(&out).expect("output directory");
    slint::platform::set_platform(Box::new(Offscreen)).expect("platform");
    let window = WINDOW.with(Clone::clone);

    for (name, apply) in SCENES {
        if !name.contains(scene_filter.as_str()) {
            continue;
        }
        for &(width, height, scale) in SIZES {
            let label = format!("{width}x{height}@{}", (scale * 100.0) as u32);
            if !label.contains(size_filter.as_str()) {
                continue;
            }
            window.dispatch_event(WindowEvent::ScaleFactorChanged {
                scale_factor: scale,
            });
            window.set_size(PhysicalSize::new(width, height));
            let ui = MainWindow::new().expect("window");
            example_disks(&ui);
            apply(&ui);
            ui.show().expect("show");
            let path = out.join(format!("{name}-{label}.png"));
            render(&ui, &window, width, height, &path);
            ui.hide().expect("hide");
            println!("{}", path.display());
        }
    }
}
