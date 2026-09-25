//! Wiring of the window's callbacks to actions, and the native dialogs.

use super::*;

/// What kind of path a mouse-driven picker selects.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Pick {
    /// An existing directory.
    Folder,
    /// An existing `.lrimg` image.
    Image,
    /// An existing file of any name (a passphrase file).
    File,
}

/// Open a native dialog on a worker thread and feed the chosen path to `apply`.
///
/// The blocking portal call must stay off the Slint event loop.
pub(crate) fn pick_path(
    weak: slint::Weak<MainWindow>,
    kind: Pick,
    title: &str,
    apply: impl Fn(&MainWindow, String) + Send + 'static,
) {
    let title = title.to_owned();
    std::thread::spawn(move || {
        let mut dialog = rfd::FileDialog::new().set_title(&title);
        let picked = match kind {
            Pick::Folder => dialog.pick_folder(),
            Pick::Image => {
                dialog = dialog.add_filter("LinuxReflect image", &["lrimg"]);
                dialog.pick_file()
            }
            Pick::File => dialog.pick_file(),
        };
        if let Some(path) = picked {
            let text = path.display().to_string();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    apply(&ui, text);
                }
            });
        }
    });
}

/// Wire every callback to its action.
pub(crate) fn connect_callbacks(ui: &MainWindow, actions: &Arc<Actions>) {
    {
        let weak = ui.as_weak();
        let actions = Arc::clone(actions);
        ui.on_check_job(move || {
            if let Some(ui) = weak.upgrade() {
                actions.check_job(
                    weak.clone(),
                    ui.get_job_id().to_string(),
                    ui.get_job_operation().to_string(),
                );
            }
        });
    }
    {
        let weak = ui.as_weak();
        let actions = Arc::clone(actions);
        ui.on_restore_inputs_changed(move || {
            actions
                .shared
                .restore_review
                .lock()
                .expect("review lock")
                .invalidate();
            if let Some(ui) = weak.upgrade() {
                ui.set_token("".into());
                ui.set_restore_confirmed(false);
                if ui.get_restore_step() >= 2 {
                    ui.set_restore_step(1);
                }
                ui.set_restore_plan(
                    "Selection changed. Review restoration before continuing.".into(),
                );
                ui.set_restore_summary("".into());
                ui.set_show_restore_details(false);
            }
        });
    }
    {
        let ui = ui.as_weak();
        let actions = Arc::clone(actions);
        connect(&ui, &actions, move |actions, ui| actions.refresh_disks(ui));
    }
    {
        let ui = ui.as_weak();
        let actions = Arc::clone(actions);
        ui.upgrade().expect("ui").on_refresh_history(move || {
            let dest = ui
                .upgrade()
                .map(|ui| ui.get_destination().to_string())
                .unwrap_or_default();
            // The library shows every set in the folder.
            let ui = ui.clone();
            actions.refresh_history(ui, dest, String::new());
        });
    }
    {
        let ui = ui.as_weak();
        let actions = Arc::clone(actions);
        ui.upgrade().expect("ui").on_probe_source(move || {
            let Some(strong) = ui.upgrade() else {
                return;
            };
            let requested = backup_spec(&strong);
            let ui = ui.clone();
            actions.probe_source(ui, requested);
        });
    }
    {
        let ui = ui.as_weak();
        let actions = Arc::clone(actions);
        ui.upgrade().expect("ui").on_start_backup(move || {
            let Some(strong) = ui.upgrade() else {
                return;
            };
            let spec = backup_spec(&strong);
            let ui = ui.clone();
            actions.start_backup(ui, spec);
        });
    }
    {
        let ui = ui.as_weak();
        let actions = Arc::clone(actions);
        ui.upgrade().expect("ui").on_prepare_restore(move || {
            let image = ui
                .upgrade()
                .map(|ui| ui.get_image().to_string())
                .unwrap_or_default();
            let target = ui
                .upgrade()
                .map(|ui| ui.get_target().to_string())
                .unwrap_or_default();
            let ui = ui.clone();
            actions.prepare_restore(ui, image, target);
        });
    }
    {
        let ui = ui.as_weak();
        let actions = Arc::clone(actions);
        ui.upgrade().expect("ui").on_start_restore(move || {
            let Some(strong) = ui.upgrade() else {
                return;
            };
            if strong.get_busy() {
                return;
            }
            if !strong.get_restore_plan_current() || !strong.get_restore_confirmed() {
                strong.set_status(
                    "Restore failed: review and confirm the current image and target first.".into(),
                );
                strong.set_phase("failed".into());
                return;
            }
            let token = actions
                .shared
                .restore_review
                .lock()
                .expect("review lock")
                .take_confirmed(
                    strong.get_image().as_str(),
                    strong.get_target().as_str(),
                    strong.get_restore_passphrase_file().as_str(),
                    strong.get_restore_confirmed(),
                );
            let Some(token) = token else {
                strong.set_status("Restore failed: the review has expired. Review again.".into());
                strong.set_phase("failed".into());
                return;
            };
            strong.set_token("".into());
            strong.set_restore_confirmed(false);
            let ui = ui.clone();
            actions.start_restore(ui, token);
        });
    }
    {
        let ui = ui.as_weak();
        let actions = Arc::clone(actions);
        ui.upgrade().expect("ui").on_cancel_job(move || {
            let job_id = ui
                .upgrade()
                .map(|ui| ui.get_job_id().to_string())
                .unwrap_or_default();
            let ui = ui.clone();
            actions.cancel_job(ui, job_id);
        });
    }
    {
        let ui = ui.as_weak();
        ui.upgrade().expect("ui").on_pick_destination(move || {
            let weak = ui.clone();
            pick_path(
                weak,
                Pick::Folder,
                "Choose the backup destination",
                |ui, path| {
                    ui.set_destination(path.clone().into());
                    ui.set_status(format!("destination: {path}").into());
                    // On the library page a new folder means a new list.
                    if ui.get_current_tab() == 3 {
                        ui.invoke_refresh_history();
                    }
                },
            );
        });
    }
    {
        let ui = ui.as_weak();
        ui.upgrade().expect("ui").on_pick_source_folder(move || {
            let weak = ui.clone();
            pick_path(
                weak,
                Pick::Folder,
                "Choose a folder to back up",
                |ui, path| {
                    ui.set_source(path.clone().into());
                    ui.set_status(format!("source: {path}").into());
                },
            );
        });
    }
    {
        let ui = ui.as_weak();
        ui.upgrade().expect("ui").on_pick_target_folder(move || {
            let weak = ui.clone();
            pick_path(
                weak,
                Pick::Folder,
                "Choose the folder to restore into",
                |ui, path| {
                    ui.invoke_restore_inputs_changed();
                    ui.set_target(path.clone().into());
                    ui.set_status(format!("target: {path}").into());
                },
            );
        });
    }
    {
        let ui = ui.as_weak();
        ui.upgrade().expect("ui").on_pick_image(move || {
            let weak = ui.clone();
            pick_path(weak, Pick::Image, "Choose a backup image", |ui, path| {
                ui.invoke_restore_inputs_changed();
                ui.set_image(path.clone().into());
                ui.set_image_detail("".into());
                ui.set_status(format!("image: {path}").into());
            });
        });
    }
    {
        let ui = ui.as_weak();
        ui.upgrade().expect("ui").on_pick_passphrase(move || {
            let weak = ui.clone();
            pick_path(
                weak,
                Pick::File,
                "Choose the passphrase file",
                |ui, path| {
                    ui.set_passphrase_file(path.into());
                },
            );
        });
    }
    {
        let weak = ui.as_weak();
        ui.on_pick_restore_passphrase(move || {
            pick_path(
                weak.clone(),
                Pick::File,
                "Choose the backup passphrase file",
                |ui, path| {
                    ui.invoke_restore_inputs_changed();
                    ui.set_restore_passphrase_file(path.into());
                },
            );
        });
    }
    {
        let ui = ui.as_weak();
        ui.upgrade().expect("ui").on_disk_selected(move |idx| {
            let Some(strong) = ui.upgrade() else {
                return;
            };
            if idx < 0 || strong.get_busy() {
                return;
            }
            let row = strong.get_disks().row_data(idx.max(0) as usize);
            if let Some(row) = row {
                let path = row.path.to_string();
                if strong.get_choosing_restore_target() {
                    if !row.restore_unavailable.is_empty() {
                        strong.set_status(
                            format!("Cannot restore to {path}: {}", row.restore_unavailable).into(),
                        );
                        return;
                    }
                    strong.invoke_restore_inputs_changed();
                    strong.set_target(path.clone().into());
                    strong.set_status(
                        format!("Restore destination: {path}. Review before writing.").into(),
                    );
                    return;
                }
                strong.set_source(path.clone().into());
                strong.set_selected_disk(containing_disk(&strong, &path));
                strong.set_source_is_folder(false);
                strong.set_status(format!("selected source: {path}").into());
            }
        });
    }
    {
        let ui = ui.as_weak();
        ui.upgrade().expect("ui").on_history_selected(move |idx| {
            let Some(strong) = ui.upgrade() else {
                return;
            };
            let row = strong.get_history().row_data(idx.max(0) as usize);
            if let Some(row) = row {
                let path = row.path.to_string();
                if path.is_empty() {
                    return;
                }
                let created = row.detail.lines().next().unwrap_or_default().to_owned();
                strong.invoke_restore_inputs_changed();
                strong.set_image(path.clone().into());
                strong.set_image_detail(format!("{} · {} · {created}", row.group, row.name).into());
                strong.set_restore_step(0);
                strong.set_current_tab(2);
                strong.set_status(format!("image from history: {path}").into());
            }
        });
    }
    {
        let weak = ui.as_weak();
        let actions = Arc::clone(actions);
        ui.on_verify_image(move |idx| {
            let Some(ui) = weak.upgrade() else {
                return;
            };
            let Some(row) = ui.get_history().row_data(idx.max(0) as usize) else {
                return;
            };
            if row.path.is_empty() {
                return;
            }
            let passphrase = ui.get_restore_passphrase_file().to_string();
            actions.verify_image(weak.clone(), row.path.to_string(), passphrase);
        });
    }
    {
        let ui = ui.as_weak();
        ui.upgrade().expect("ui").on_use_last_image(move || {
            let Some(strong) = ui.upgrade() else {
                return;
            };
            let last = strong.get_last_image().to_string();
            if last.is_empty() {
                strong.set_status("no backup has run in this session yet".into());
            } else {
                strong.invoke_restore_inputs_changed();
                strong.set_image(last.clone().into());
                strong.set_image_detail("The backup made in this window".into());
                strong.set_restore_step(0);
                strong.set_current_tab(2);
                strong.set_status(format!("image: {last}").into());
            }
        });
    }
    {
        let ui = ui.as_weak();
        ui.upgrade().expect("ui").on_show_backup_tab(move || {
            if let Some(strong) = ui.upgrade() {
                strong.set_choosing_restore_target(false);
                if !strong.get_busy() {
                    strong.set_backup_step(0);
                }
                strong.set_current_tab(1);
            }
        });
    }
    {
        let ui = ui.as_weak();
        ui.upgrade().expect("ui").on_show_restore_tab(move || {
            if let Some(strong) = ui.upgrade() {
                strong.set_choosing_restore_target(false);
                strong.set_current_tab(2);
            }
        });
    }
}

/// A callback that runs one action with the UI handle.
pub(crate) fn connect<F>(ui: &slint::Weak<MainWindow>, actions: &Arc<Actions>, run: F)
where
    F: Fn(&Actions, slint::Weak<MainWindow>) + 'static,
{
    let Some(strong) = ui.upgrade() else {
        return;
    };
    let actions = Arc::clone(actions);
    let ui = ui.clone();
    strong.on_refresh_disks(move || run(&actions, ui.clone()));
}
