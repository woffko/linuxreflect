//! LinuxReflect's Slint GUI (spec §K S15).
//!
//! The GUI is a daemon client: the disk map comes from `ListDisks`, the backup
//! wizard shows `ProbeSource`'s plan (including the consistency level) before
//! starting, the restore wizard shows `PrepareRestore`'s plan and token, and
//! progress and history come from the job streams. No device is ever opened
//! here (spec §B).
//!
//! Slint is used under the Royalty-Free 2.0 licence; the attribution it asks
//! for is the footer of the window (see D-090).

mod backup_review;
pub mod client;
mod devices;
mod geometry;
mod history;
mod job_view;
mod result;
mod review;
pub mod script;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use lr_proto::v1::BackupSpec;
use slint::Model as _;

use crate::client::Client;
use crate::script::{ScriptOutcome, Step};

/// The generated UI types; the generated code carries no docs of its own.
#[allow(missing_docs, unreachable_pub)]
mod generated {
    slint::include_modules!();
}

use generated::*;

/// How the GUI should start.
#[derive(Debug, Clone)]
pub struct GuiOptions {
    /// Daemon socket.
    pub socket: PathBuf,
    /// Automation script (tests).
    pub script: Option<PathBuf>,
    /// Quit after this many milliseconds even without `quit` (a smoke run).
    pub exit_after_ms: Option<u64>,
}

impl GuiOptions {
    /// Options for a daemon socket.
    #[must_use]
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
            script: None,
            exit_after_ms: None,
        }
    }
}

/// State shared by the callbacks and the running actions.
struct Shared {
    busy: AtomicBool,
    generation: AtomicU64,
    failure: Mutex<Option<String>>,
    restore_review: Mutex<review::Review>,
    backup_review: Mutex<backup_review::Review>,
}

/// Everything a callback needs, without keeping the UI alive.
struct Actions {
    runtime: tokio::runtime::Handle,
    socket: PathBuf,
    shared: Arc<Shared>,
}

impl Actions {
    fn start(&self, ui: &slint::Weak<MainWindow>, label: &str) -> bool {
        if self.shared.busy.swap(true, Ordering::SeqCst) {
            return false;
        }
        self.shared
            .generation
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                value.checked_add(1)
            })
            .expect("action generation exhausted");
        *self.shared.failure.lock().expect("failure lock") = None;
        if let Some(ui) = ui.upgrade() {
            ui.set_status(format!("{label}…").into());
            ui.set_phase(label.into());
            ui.set_busy(true);
            if matches!(label, "backup" | "restore") {
                ui.set_result_text("".into());
                ui.set_show_result_details(false);
            }
        }
        true
    }

    /// The disk map: `ListDisks` rendered into rows.
    fn refresh_disks(&self, ui: slint::Weak<MainWindow>) {
        if !self.start(&ui, "list disks") {
            return;
        }
        let show_system = ui.upgrade().is_some_and(|ui| ui.get_show_system_devices());
        if let Some(ui) = ui.upgrade() {
            ui.set_disk_status("Loading disks…".into());
            ui.set_selected_disk(-1);
            ui.set_partition_tiles(slint::ModelRc::default());
            ui.set_layout_title("Select a disk to inspect its partitions.".into());
        }
        let socket = self.socket.clone();
        let actions = self.clone_handle();
        let weak = ui.clone();
        self.runtime.spawn(async move {
            let outcome = async {
                let client = Client::connect(&socket).await?;
                let json = client.list_disks().await?;
                let entries: Vec<devices::Device> =
                    serde_json::from_str(&json).context("disk list JSON array")?;
                // Disks first, each followed by its partitions, so the list
                // reads like a device tree and every row carries the node the
                // daemon accepts as a source.
                let rows: Vec<_> = devices::ordered(&entries, show_system).into_iter()
                    .map(|entry| disk_row(entry, &entries)).collect();
                Ok::<_, anyhow::Error>(rows)
            }
            .await;
            match outcome {
                Ok(rows) => {
                    let weak = weak.clone();
                    let count = rows.len();
                    let disk_count = rows.iter().filter(|row| row.is_disk).count();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            ui.set_disk_cards(disk_cards(&rows));
                            ui.set_disks(slint::ModelRc::new(slint::VecModel::from(rows)));
                            ui.set_status(format!("{disk_count} disks, {} partitions", count - disk_count).into());
                            ui.set_disk_status(if count == 0 {
                                "No devices found. Try Refresh or show service devices.".into()
                            } else {
                                "Select a disk or partition below to inspect it.".into()
                            });
                            ui.set_busy(false);
                            actions.shared.busy.store(false, Ordering::SeqCst);
                        }
                    });
                }
                Err(error) => {
                    actions.fail(&weak, "list disks", &error);
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            ui.set_disks(slint::ModelRc::default());
                            ui.set_disk_cards(slint::ModelRc::default());
                            ui.set_disk_status("Could not load disks. Check the connection message below, then Refresh.".into());
                        }
                    });
                }
            }
        });
    }

    fn inspect_disk(&self, ui: slint::Weak<MainWindow>, source: String) {
        if !self.start(&ui, "inspect disk") {
            return;
        }
        if let Some(ui) = ui.upgrade() {
            ui.set_layout_title(format!("Inspecting {source}…").into());
            ui.set_partition_tiles(slint::ModelRc::default());
        }
        let socket = self.socket.clone();
        let actions = self.clone_handle();
        self.runtime.spawn(async move {
            let outcome = async { Client::connect(&socket).await?.disk_map(&source).await }.await;
            match outcome {
                Ok(layout) => {
                    let facts = &layout.device_facts;
                    let mut title = format!(
                        "{} · {} · {}",
                        source,
                        facts.model.as_deref().unwrap_or("Device"),
                        human_size(facts.size_bytes)
                    );
                    let mut tiles = Vec::new();
                    for partition in &layout.partitions {
                        let Some((start, extent)) = geometry::relative_extent(
                            partition.start_lba,
                            facts.logical_block_size,
                            partition.size_bytes,
                            facts.size_bytes,
                        ) else {
                            title.push_str(" · Invalid partition geometry; map unavailable");
                            tiles.clear();
                            break;
                        };
                        let path = partition
                            .path
                            .as_ref()
                            .map(|path| path.display().to_string())
                            .unwrap_or_default();
                        let mounts = partition
                            .mountpoints
                            .iter()
                            .map(|path| path.display().to_string())
                            .collect::<Vec<_>>()
                            .join(", ");
                        tiles.push(PartitionTile {
                            label: format!(
                                "Partition {} · {} · {} · {}",
                                partition.index,
                                partition.fs_type.as_deref().unwrap_or("unknown filesystem"),
                                human_size(partition.size_bytes),
                                mounts
                            )
                            .into(),
                            path: path.into(),
                            start,
                            extent,
                        });
                    }
                    if layout.partitions.is_empty() {
                        title.push_str(&format!(
                            " · {}",
                            layout
                                .fs
                                .as_ref()
                                .map_or("No partition table detected", |fs| fs.fs_type.as_str())
                        ));
                    }
                    if !layout.warnings.is_empty() {
                        title.push_str(&format!(" · {}", layout.warnings.join("; ")));
                    }
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui.upgrade() {
                            ui.set_busy(false);
                            if ui.get_source().as_str() == source.as_str() {
                                ui.set_partition_tiles(slint::ModelRc::new(slint::VecModel::from(
                                    tiles,
                                )));
                                ui.set_layout_title(title.into());
                                ui.set_status("Device information loaded.".into());
                            }
                            actions.shared.busy.store(false, Ordering::SeqCst);
                        }
                    });
                }
                Err(error) => {
                    actions.fail(&ui, "inspect disk", &error);
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui.upgrade() {
                            ui.set_layout_title(
                                "Device inspection failed. Select the disk to retry.".into(),
                            );
                        }
                    });
                }
            }
        });
    }

    /// The history tab: sets, chains and members.
    fn refresh_history(&self, ui: slint::Weak<MainWindow>, dest: String, set: String) {
        if !self.start(&ui, "history") {
            return;
        }
        let socket = self.socket.clone();
        let actions = self.clone_handle();
        let weak = ui.clone();
        self.runtime.spawn(async move {
            let outcome = async {
                let client = Client::connect(&socket).await?;
                let json = client.list_sets(&dest, &set).await?;
                let value: serde_json::Value = serde_json::from_str(&json).context("set JSON")?;
                let mut rows = Vec::new();
                for chain in value
                    .get("chains")
                    .and_then(serde_json::Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    for member in chain
                        .get("members")
                        .and_then(serde_json::Value::as_array)
                        .into_iter()
                        .flatten()
                    {
                        let created = history::created_at(
                            member
                                .get("created_unix")
                                .and_then(serde_json::Value::as_u64),
                        );
                        let kind = member
                            .get("kind")
                            .and_then(|value| value.as_str())
                            .unwrap_or("?");
                        let seq = member
                            .get("seq_in_chain")
                            .and_then(serde_json::Value::as_u64)
                            .unwrap_or(0);
                        let size = member
                            .get("size_bytes")
                            .and_then(serde_json::Value::as_u64)
                            .map_or_else(|| "-".to_owned(), human_size);
                        let file = member
                            .get("file_name")
                            .and_then(|value| value.as_str())
                            .unwrap_or("-");
                        let path = history::image_location(&dest, &set, file)
                            .context("catalog member has an invalid set-relative image path")?;
                        rows.push(HistoryRow {
                            name: format!(
                                "{} · Copy {}",
                                history::backup_kind(kind),
                                seq.saturating_add(1)
                            )
                            .into(),
                            detail: format!("Created: {created} · {size}\n{file}").into(),
                            path: path.into(),
                        });
                    }
                }
                Ok::<_, anyhow::Error>(rows)
            }
            .await;
            match outcome {
                Ok(rows) => {
                    let count = rows.len();
                    let weak = weak.clone();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            ui.set_history(slint::ModelRc::new(slint::VecModel::from(rows)));
                            ui.set_status(format!("{count} backup(s) available").into());
                            ui.set_busy(false);
                            actions.shared.busy.store(false, Ordering::SeqCst);
                        }
                    });
                }
                Err(error) => actions.fail(&weak, "history", &error),
            }
        });
    }

    /// The backup wizard's plan (`ProbeSource`), consistency included.
    fn probe_source(&self, ui: slint::Weak<MainWindow>, requested: BackupSpec) {
        if !self.start(&ui, "probe") {
            return;
        }
        self.shared
            .backup_review
            .lock()
            .expect("backup review lock")
            .begin();
        if requested.source.trim().is_empty() {
            self.clone_handle().fail(
                &ui,
                "probe",
                &anyhow::anyhow!("Choose a source before inspection."),
            );
            return;
        }
        let source = requested.source.clone();
        let socket = self.socket.clone();
        let actions = self.clone_handle();
        let weak = ui.clone();
        self.runtime.spawn(async move {
            let outcome = async {
                let client = Client::connect(&socket).await?;
                let plan = client.probe(&source).await?;
                let mut text = format!(
                    "source:      {source}\nprovider:    {}\nimage kind:  {}\nconsistency: {}\nestimated:   {} ({})",
                    plan.provider,
                    plan.image_kind,
                    plan.consistency,
                    plan.estimated_bytes,
                    human_size(plan.estimated_bytes)
                );
                for warning in &plan.warnings {
                    text.push_str("\nwarning:     ");
                    text.push_str(warning);
                }
                Ok::<_, anyhow::Error>(text)
            }
            .await;
            match outcome {
                Ok(text) => {
                    let weak = weak.clone();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            if !actions.shared.backup_review.lock().expect("backup review lock")
                                .accept(requested, &backup_spec(&ui)) {
                                ui.set_status("Backup settings changed. Review the new selection.".into());
                                ui.set_busy(false);
                                actions.shared.busy.store(false, Ordering::SeqCst);
                                return;
                            }
                            ui.set_plan(text.into());
                            ui.set_backup_step(2);
                            ui.set_status("plan ready".into());
                            ui.set_busy(false);
                            actions.shared.busy.store(false, Ordering::SeqCst);
                        }
                    });
                }
                Err(error) => actions.fail(&weak, "probe", &error),
            }
        });
    }

    /// Start the backup and stream its progress into the progress bar.
    fn start_backup(&self, ui: slint::Weak<MainWindow>, spec: BackupSpec) {
        if !self.start(&ui, "backup") {
            return;
        }
        let approved = backup_review::validate(&spec).and_then(|()| {
            self.shared
                .backup_review
                .lock()
                .expect("backup review lock")
                .take(&spec)
        });
        let spec = match approved {
            Ok(spec) => spec,
            Err(message) => {
                if let Some(ui) = ui.upgrade() {
                    ui.set_backup_step(1);
                }
                self.clone_handle()
                    .fail(&ui, "backup", &anyhow::anyhow!(message));
                return;
            }
        };
        if let Some(ui) = ui.upgrade() {
            ui.set_backup_step(3);
            job_view::start(&ui, "backup");
            ui.set_job_operation("backup".into());
            ui.set_progress(0.0);
            ui.set_progress_text("Starting backup…".into());
        }
        let socket = self.socket.clone();
        let actions = self.clone_handle();
        let weak = ui.clone();
        self.runtime.spawn(async move {
            let progress_ui = weak.clone();
            let progress_actions = actions.clone();
            let outcome = async {
                let client = Client::connect(&socket).await?;
                client
                    .create_backup(spec, move |progress| {
                        report_progress(&progress_actions, &progress_ui, progress);
                    })
                    .await
            }
            .await;
            match outcome {
                Ok(summary) => actions.finish(&weak, "backup", &summary),
                Err(error) => actions.fail(&weak, "backup", &error),
            }
        });
    }

    /// The restore wizard's token plan (`PrepareRestore`).
    fn prepare_restore(&self, ui: slint::Weak<MainWindow>, image: String, target: String) {
        if !self.start(&ui, "prepare") {
            return;
        }
        if let Some(ui) = ui.upgrade() {
            ui.set_token("".into());
            ui.set_restore_confirmed(false);
        }
        let passphrase_file = ui
            .upgrade()
            .map(|ui| ui.get_restore_passphrase_file().to_string())
            .unwrap_or_default();
        let request = self
            .shared
            .restore_review
            .lock()
            .expect("review lock")
            .begin(image.clone(), target.clone(), passphrase_file.clone());
        let socket = self.socket.clone();
        let actions = self.clone_handle();
        let weak = ui.clone();
        self.runtime.spawn(async move {
            let outcome = async {
                let client = Client::connect(&socket).await?;
                client.prepare_restore(&image, &target, &passphrase_file).await
            }
            .await;
            match outcome {
                Ok(plan) => {
                    let readable = result::restore_plan(&plan);
                    let mut text = format!(
                        "image:       {}/{}\ntarget:      {target}\nkind:        {}\nconsistency: {}\nsource:      {} bytes\nmembers:     {}",
                        plan.dest,
                        plan.image,
                        plan.image_kind,
                        plan.consistency,
                        plan.source_size_bytes,
                        plan.members.len()
                    );
                    for warning in &plan.warnings {
                        text.push_str("\nwarning:     ");
                        text.push_str(warning);
                    }
                    let weak = weak.clone();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            if ui.get_image().as_str() != image.as_str()
                                || ui.get_target().as_str() != target.as_str()
                                || ui.get_restore_passphrase_file().as_str() != passphrase_file.as_str()
                                || !actions
                                    .shared
                                    .restore_review
                                    .lock()
                                    .expect("review lock")
                                    .accept(request, plan.token.clone())
                            {
                                ui.set_status("Selection changed. Review a new restore plan.".into());
                                ui.set_busy(false);
                                actions.shared.busy.store(false, Ordering::SeqCst);
                                return;
                            }
                            ui.set_restore_plan(text.into());
                            ui.set_restore_summary(readable.into());
                            ui.set_show_restore_details(false);
                            ui.set_planned_image(image.into());
                            ui.set_planned_target(target.into());
                            ui.set_token(plan.token.clone().into());
                            ui.set_restore_step(2);
                            ui.set_status("restore plan ready".into());
                            ui.set_busy(false);
                            actions.shared.busy.store(false, Ordering::SeqCst);
                        }
                    });
                }
                Err(error) => actions.fail(&weak, "prepare", &error),
            }
        });
    }

    /// Apply the prepared token.
    fn start_restore(&self, ui: slint::Weak<MainWindow>, approved: review::Approved) {
        if !self.start(&ui, "restore") {
            return;
        }
        if let Some(ui) = ui.upgrade() {
            ui.set_restore_step(3);
            job_view::start(&ui, "restore");
            ui.set_job_operation("restore".into());
            ui.set_progress(0.0);
            ui.set_progress_text("Starting restoration…".into());
        }
        let socket = self.socket.clone();
        let actions = self.clone_handle();
        let weak = ui.clone();
        self.runtime.spawn(async move {
            let progress_ui = weak.clone();
            let progress_actions = actions.clone();
            let outcome = async {
                let client = Client::connect(&socket).await?;
                client
                    .restore(
                        &approved.token,
                        &approved.passphrase_file,
                        move |progress| {
                            report_progress(&progress_actions, &progress_ui, progress);
                        },
                    )
                    .await
            }
            .await;
            match outcome {
                Ok(summary) => actions.finish(&weak, "restore", &summary),
                Err(error) => actions.fail(&weak, "restore", &error),
            }
        });
    }

    /// Recover the current job's state without admitting a replacement job.
    fn check_job(&self, ui: slint::Weak<MainWindow>, job_id: String, operation: String) {
        if job_id.is_empty() {
            return;
        }
        let socket = self.socket.clone();
        let mut actions = self.clone_handle();
        actions.expected_job = Some(job_id.clone());
        self.runtime.spawn(async move {
            let result = async { Client::connect(&socket).await?.job_state(&job_id).await }.await;
            let _ = slint::invoke_from_event_loop(move || {
                let Some(strong) = ui.upgrade() else { return; };
                if strong.get_job_id().as_str() != job_id.as_str() || !strong.get_has_job() {
                    return;
                }
                match result {
                    Ok(state) if state.state == "finished" => {
                        let summary = state.progress.as_ref().and_then(client::summary_of).unwrap_or_default();
                        actions.finish(&ui, &operation, &summary);
                    }
                    Ok(state) if state.state == "failed" || state.state == "cancelled" => {
                        let failure = match state.progress.and_then(|progress| progress.step) {
                            Some(lr_proto::v1::progress::Step::Failure(failure)) => client::JobFailure { code: failure.code, message: failure.message },
                            _ => client::JobFailure { code: state.state.clone(), message: "The daemon confirmed the job has stopped.".into() },
                        };
                        actions.fail(&ui, &operation, &failure.into());
                    }
                    Ok(state) => {
                        let text = format!("Job is {}. You can check again or request cancellation.", state.state);
                        job_view::update(&strong, &operation, |view| view.detail = text.clone().into());
                        strong.set_status(text.into());
                    }
                    Err(error) => {
                        let text = format!("Cannot confirm the job state: {error}. Check again when the daemon is available.");
                        job_view::update(&strong, &operation, |view| view.detail = text.clone().into());
                        strong.set_status(text.into());
                    }
                }
            });
        });
    }

    /// Ask the daemon to stop the running job (spec §I `CancelJob`).
    fn cancel_job(&self, ui: slint::Weak<MainWindow>, job_id: String) {
        if job_id.is_empty() {
            return;
        }
        let socket = self.socket.clone();
        let weak = ui.clone();
        self.runtime.spawn(async move {
            let outcome = async {
                let client = Client::connect(&socket).await?;
                client.cancel(&job_id).await
            }
            .await;
            match outcome {
                Ok(state) => {
                    let weak = weak.clone();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            if ui.get_job_id().as_str() != job_id.as_str() || !ui.get_has_job() {
                                return;
                            }
                            job_view::update(&ui, ui.get_job_operation().as_str(), |view| {
                                view.stage = generated::JobStage::Cancelling;
                                view.detail = "Cancellation requested. Waiting for the daemon to confirm that the job has stopped.".into();
                            });
                            ui.set_status(format!("cancel requested: {state}").into());
                            ui.set_phase("cancelling".into());
                        }
                    });
                }
                Err(error) => {
                    // A failed cancellation request does not terminate the job.
                    // Its progress stream remains the authority for completion.
                    let text = format!("Could not cancel: {error}. The job may still be running.");
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            if ui.get_job_id().as_str() != job_id.as_str() || !ui.get_has_job() {
                                return;
                            }
                            job_view::update(&ui, ui.get_job_operation().as_str(), |view| {
                                view.detail = text.clone().into();
                            });
                            ui.set_status(text.into());
                        }
                    });
                }
            }
        });
    }

    /// An `Arc`-like handle for use inside a spawned task.
    fn clone_handle(&self) -> ActionsHandle {
        ActionsHandle {
            shared: Arc::clone(&self.shared),
            generation: self.shared.generation.load(Ordering::SeqCst),
            expected_job: None,
        }
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;

    #[test]
    #[ignore = "requires a display; run with Xvfb and a single test thread"]
    fn unavailable_daemon_does_not_release_a_job_after_cancel_or_status() {
        let directory = tempfile::tempdir().expect("private socket directory");
        let ui = MainWindow::new().expect("create test UI");
        let app = App::new(ui, &directory.path().join("absent.sock")).expect("create test app");
        let weak = app.ui.as_weak();
        assert!(app.actions.start(&weak, "backup"));
        app.ui.set_has_job(true);
        app.ui.set_job_id("unconfirmed-job".into());
        app.ui.set_job_operation("backup".into());
        app.actions
            .cancel_job(weak.clone(), "unconfirmed-job".into());

        let actions = Arc::clone(&app.actions);
        let checked = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&checked);
        let started = std::time::Instant::now();
        let stage = std::cell::Cell::new(0);
        let timer = slint::Timer::default();
        timer.start(
            slint::TimerMode::Repeated,
            Duration::from_millis(10),
            move || {
                assert!(
                    started.elapsed() < Duration::from_secs(5),
                    "RPC error did not reach the UI"
                );
                let ui = weak.upgrade().expect("test UI remains alive");
                let expected = if stage.get() == 0 {
                    "Could not cancel:"
                } else {
                    "Cannot confirm the job state:"
                };
                if !ui.get_status().starts_with(expected) {
                    return;
                }
                assert!(ui.get_busy());
                assert!(actions.shared.busy.load(Ordering::SeqCst));
                assert!(ui.get_has_job());
                assert_eq!(ui.get_job_id(), "unconfirmed-job");
                assert!(actions.shared.failure.lock().unwrap().is_none());
                assert!(!actions.start(&weak, "restore"));
                if stage.get() == 0 {
                    stage.set(1);
                    actions.check_job(weak.clone(), "unconfirmed-job".into(), "backup".into());
                } else {
                    observed.store(true, Ordering::SeqCst);
                    slint::quit_event_loop().expect("stop test event loop");
                }
            },
        );
        slint::run_event_loop_until_quit().expect("process RPC errors");
        assert!(checked.load(Ordering::SeqCst));
    }

    #[test]
    #[ignore = "requires a display; run with Xvfb and a single test thread"]
    fn completion_keeps_admission_closed_until_ui_cleanup() {
        let ui = MainWindow::new().expect("create test UI");
        let app = App::new(ui, Path::new("/nonexistent/lr-lifecycle-test.sock"))
            .expect("create test app");
        let weak = app.ui.as_weak();
        assert!(app.actions.start(&weak, "backup"));
        app.ui.set_has_job(true);
        app.ui.set_job_id("completed-job".into());
        app.ui.set_job_operation("backup".into());

        // Deliberately do not pump the event loop: completion has arrived on
        // the worker, but the UI still owns the previous job's identity.
        let stale_stream = app.actions.clone_handle();
        app.actions.clone_handle().finish(&weak, "backup", "{}");
        assert!(
            app.busy(),
            "completion must not release admission before UI cleanup"
        );
        assert!(!app.actions.start(&weak, "restore"));
        assert_eq!(app.ui.get_job_id(), "completed-job");
        assert!(app.ui.get_has_job());
        stale_stream.fail(
            &weak,
            "backup",
            &anyhow::anyhow!("disconnect after confirmed completion"),
        );

        let actions = Arc::clone(&app.actions);
        let checked = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&checked);
        slint::invoke_from_event_loop(move || {
            let ui = weak.upgrade().expect("test UI remains alive");
            assert!(!ui.get_busy());
            assert!(!ui.get_has_job());
            assert!(ui.get_job_id().is_empty());
            assert_eq!(ui.get_backup_job().stage, generated::JobStage::Succeeded);
            assert!(actions.start(&weak, "restore"));
            assert!(ui.get_busy());
            ui.set_has_job(true);
            ui.set_job_id("replacement-job".into());
            ui.set_progress(0.25);
            report_progress(
                &stale_stream,
                &weak,
                &lr_proto::v1::Progress {
                    step: Some(lr_proto::v1::progress::Step::Started(
                        lr_proto::v1::Started {
                            job_id: "completed-job".into(),
                        },
                    )),
                },
            );
            report_progress(
                &stale_stream,
                &weak,
                &lr_proto::v1::Progress {
                    step: Some(lr_proto::v1::progress::Step::Bytes(lr_proto::v1::Bytes {
                        done: 99,
                        total: 100,
                    })),
                },
            );
            // The original stream can terminate after GetJob has confirmed
            // completion and another operation has been admitted.
            stale_stream.finish(&weak, "backup", "{}");
            stale_stream.fail(&weak, "backup", &anyhow::anyhow!("late stream disconnect"));
            let mut stale = actions.clone_handle();
            stale.expected_job = Some("completed-job".into());
            stale.finish(&weak, "backup", "{}");
            stale.fail(
                &weak,
                "backup",
                &client::JobFailure {
                    code: "E_CANCELLED".into(),
                    message: "late terminal reply".into(),
                }
                .into(),
            );
            slint::invoke_from_event_loop(move || {
                let ui = weak.upgrade().expect("test UI remains alive");
                assert!(actions.shared.busy.load(Ordering::SeqCst));
                assert!(ui.get_busy());
                assert!(ui.get_has_job());
                assert_eq!(ui.get_job_id(), "replacement-job");
                assert_eq!(ui.get_progress(), 0.25);
                assert_eq!(ui.get_backup_job().stage, generated::JobStage::Succeeded);
                assert!(actions.shared.failure.lock().unwrap().is_none());
                observed.store(true, Ordering::SeqCst);
                slint::quit_event_loop().expect("stop test event loop");
            })
            .expect("queue stale-reply assertions");
        })
        .expect("queue post-completion assertions");
        slint::run_event_loop_until_quit().expect("drain completion queue");
        assert!(checked.load(Ordering::SeqCst));
    }
}

/// What a spawned task keeps alive: the shared state only.
#[derive(Clone)]
struct ActionsHandle {
    shared: Arc<Shared>,
    generation: u64,
    // GetJob replies can queue terminal UI updates after the receipt-time
    // identity check. Recheck when that update is actually applied.
    expected_job: Option<String>,
}

impl ActionsHandle {
    fn fail(&self, ui: &slint::Weak<MainWindow>, label: &str, error: &anyhow::Error) {
        let terminal = error.downcast_ref::<client::JobFailure>().is_some();
        let cancelled = error
            .downcast_ref::<client::JobFailure>()
            .is_some_and(|failure| failure.code == "E_CANCELLED" || failure.code == "cancelled");
        let shared = Arc::clone(&self.shared);
        let text = format!("{error}");
        let generation = self.generation;
        let expected_job = self.expected_job.clone();
        let weak = ui.clone();
        let label = label.to_owned();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(ui) = weak.upgrade() {
                if shared.generation.load(Ordering::SeqCst) != generation
                    || !shared.busy.load(Ordering::SeqCst)
                {
                    return;
                }
                if expected_job
                    .as_ref()
                    .is_some_and(|id| !ui.get_has_job() || ui.get_job_id().as_str() != id.as_str())
                {
                    return;
                }
                *shared.failure.lock().expect("failure lock") = Some(text.clone());
                if matches!(label.as_str(), "backup" | "restore") && ui.get_has_job() && !terminal {
                    shared.busy.store(true, Ordering::SeqCst);
                    ui.set_busy(true);
                    ui.set_phase("connection lost".into());
                    job_view::update(&ui, &label, |view| {
                        view.stage = generated::JobStage::Disconnected;
                        view.detail = format!("The job may still be running. Use Check status before retrying.\n{text}").into();
                    });
                    ui.set_status(
                        "The job may still be running. Use Check job status before retrying."
                            .into(),
                    );
                    ui.set_progress_text(text.into());
                    return;
                }
                shared.busy.store(false, Ordering::SeqCst);
                job_view::update(&ui, &label, |view| {
                    view.stage = if cancelled {
                        generated::JobStage::Cancelled
                    } else {
                        generated::JobStage::Failed
                    };
                    view.detail = text.clone().into();
                    view.report = Default::default();
                });
                if cancelled {
                    ui.set_status(format!("{label} cancelled").into());
                    ui.set_phase("cancelled".into());
                    ui.set_progress_text("Cancelled".into());
                } else {
                    ui.set_status(format!("{label} failed: {text}").into());
                    ui.set_phase("failed".into());
                    ui.set_progress_text(format!("error: {text}").into());
                }
                ui.set_busy(false);
                ui.set_has_job(false);
                ui.set_job_id("".into());
            }
        });
    }

    fn finish(&self, ui: &slint::Weak<MainWindow>, label: &str, summary: &str) {
        let shared = Arc::clone(&self.shared);
        let generation = self.generation;
        let expected_job = self.expected_job.clone();
        let weak = ui.clone();
        let label = label.to_owned();
        let summary = summary.to_owned();
        let readable = result::describe(&label, &summary);
        let image = (label == "backup")
            .then(|| image_of_summary(&summary))
            .flatten();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(ui) = weak.upgrade() {
                if shared.generation.load(Ordering::SeqCst) != generation
                    || !shared.busy.load(Ordering::SeqCst)
                {
                    return;
                }
                if expected_job
                    .as_ref()
                    .is_some_and(|id| !ui.get_has_job() || ui.get_job_id().as_str() != id.as_str())
                {
                    return;
                }
                ui.set_status(format!("{label} ok").into());
                job_view::update(&ui, &label, |view| {
                    view.stage = generated::JobStage::Succeeded;
                    view.detail = readable.clone().into();
                    view.report = summary.clone().into();
                });
                ui.set_phase("idle".into());
                ui.set_busy(false);
                ui.set_progress(1.0);
                ui.set_progress_text(summary.into());
                ui.set_result_text(readable.into());
                ui.set_has_job(false);
                ui.set_job_id("".into());
                if let Some(image) = image {
                    ui.set_last_image(image.clone().into());
                    ui.invoke_restore_inputs_changed();
                    ui.set_image(image.into());
                }
                // Admission stays closed until the old identity and UI state
                // have been cleared together on the event-loop thread.
                shared.busy.store(false, Ordering::SeqCst);
            }
        });
    }
}

/// Push one daemon progress step into the UI.
fn report_progress(
    actions: &ActionsHandle,
    ui: &slint::Weak<MainWindow>,
    progress: &lr_proto::v1::Progress,
) {
    let weak = ui.clone();
    let generation = actions.generation;
    if let Some(lr_proto::v1::progress::Step::Started(started)) = &progress.step {
        let job_id = started.job_id.clone();
        let shared = Arc::clone(&actions.shared);
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(ui) = weak.upgrade() {
                if shared.generation.load(Ordering::SeqCst) != generation
                    || !shared.busy.load(Ordering::SeqCst)
                {
                    return;
                }
                ui.set_job_id(job_id.into());
                ui.set_has_job(true);
                job_view::update(&ui, ui.get_job_operation().as_str(), |view| {
                    view.stage = generated::JobStage::Running;
                    view.detail = "The daemon has started the job.".into();
                });
            }
        });
    }
    let Some((phase, done, total)) = client::progress_line(progress) else {
        return;
    };
    let weak = ui.clone();
    let shared = Arc::clone(&actions.shared);
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(ui) = weak.upgrade() {
            if shared.generation.load(Ordering::SeqCst) != generation
                || !shared.busy.load(Ordering::SeqCst)
            {
                return;
            }
            ui.set_phase(phase.into());
            if total > 0 {
                ui.set_progress(done as f32 / total as f32);
                ui.set_progress_text(format!("{done} / {total} bytes").into());
                job_view::update(&ui, ui.get_job_operation().as_str(), |view| {
                    if view.stage == generated::JobStage::Running {
                        view.detail = format!("{done} / {total} bytes").into();
                    }
                });
            }
        }
    });
}

/// The image path inside a finished backup summary, when it names one.
fn image_of_summary(summary: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(summary).ok()?;
    value
        .get("image_path")
        .or_else(|| value.get("image_uri"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

/// Format a byte count for the GUI.
#[must_use]
pub fn human_size(bytes: u64) -> String {
    lr_engine_size(bytes)
}

/// A tiny duplicate of the engine's size formatting, to keep the GUI's
/// dependency list small (the GUI never touches the engine).
fn lr_engine_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Snapshot every user-visible backup setting for inspection and execution.
fn backup_spec(ui: &MainWindow) -> BackupSpec {
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

/// Group the already disk-first ordered rows without changing callback indices.
fn disk_cards(rows: &[DiskRow]) -> slint::ModelRc<DiskCard> {
    let mut cards = Vec::new();
    let mut start = 0;
    while start < rows.len() {
        let end = (start + 1..rows.len())
            .find(|&index| rows[index].is_disk)
            .unwrap_or(rows.len());
        if let Ok(disk_index) = i32::try_from(start) {
            let partitions: Vec<_> = (start + 1..end)
                .filter_map(|index| i32::try_from(index).ok())
                .collect();
            cards.push(DiskCard {
                disk_index,
                partition_indices: slint::ModelRc::new(slint::VecModel::from(partitions)),
            });
        }
        start = end;
    }
    slint::ModelRc::new(slint::VecModel::from(cards))
}

/// One row of the disk map: a disk or one of its partitions.
fn disk_row(entry: &devices::Device, entries: &[devices::Device]) -> DiskRow {
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

/// What kind of path a mouse-driven picker selects.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pick {
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
fn pick_path(
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

/// The wired application.
pub struct App {
    ui: MainWindow,
    actions: Arc<Actions>,
    runtime: tokio::runtime::Runtime,
}

impl App {
    /// Wire the UI to a daemon socket.
    ///
    /// # Errors
    /// Returns an error when the Slint component cannot be created or a runtime
    /// cannot be built.
    pub fn new(ui: MainWindow, socket: &Path) -> anyhow::Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("lr-gui")
            .build()
            .context("building the async runtime")?;
        let actions = Arc::new(Actions {
            runtime: runtime.handle().clone(),
            socket: socket.to_path_buf(),
            shared: Arc::new(Shared {
                busy: AtomicBool::new(false),
                generation: AtomicU64::new(0),
                failure: Mutex::new(None),
                restore_review: Mutex::new(review::Review::default()),
                backup_review: Mutex::new(backup_review::Review::default()),
            }),
        });
        connect_callbacks(&ui, &actions);
        Ok(Self {
            ui,
            actions,
            runtime,
        })
    }

    /// The UI handle.
    #[must_use]
    pub fn ui(&self) -> &MainWindow {
        &self.ui
    }

    /// `true` while an action is running.
    #[must_use]
    pub fn busy(&self) -> bool {
        self.actions.shared.busy.load(Ordering::SeqCst)
    }

    /// The last failure, if any.
    #[must_use]
    pub fn failure(&self) -> Option<String> {
        self.actions
            .shared
            .failure
            .lock()
            .expect("failure lock")
            .clone()
    }

    /// Keep the runtime alive until the end of the value's life.
    #[must_use]
    pub fn runtime(&self) -> &tokio::runtime::Runtime {
        &self.runtime
    }
}

/// Wire every callback to its action.
fn connect_callbacks(ui: &MainWindow, actions: &Arc<Actions>) {
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
            let set = ui
                .upgrade()
                .map(|ui| ui.get_backup_set().to_string())
                .unwrap_or_default();
            let ui = ui.clone();
            actions.refresh_history(ui, dest, set);
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
        let actions = Arc::clone(actions);
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
                    strong.set_choosing_restore_target(false);
                    strong.set_current_tab(2);
                    strong.set_status(
                        format!("Restore destination: {path}. Review before writing.").into(),
                    );
                    return;
                }
                strong.set_selected_disk(idx);
                strong.set_source(path.clone().into());
                strong.set_status(format!("selected source: {path}").into());
                actions.inspect_disk(ui.clone(), path);
            }
        });
    }
    {
        let weak = ui.as_weak();
        ui.on_partition_selected(move |idx| {
            let Some(ui) = weak.upgrade() else {
                return;
            };
            if idx < 0 || ui.get_busy() {
                return;
            }
            if let Some(tile) = ui.get_partition_tiles().row_data(idx as usize)
                && !tile.path.is_empty()
            {
                if ui.get_choosing_restore_target() {
                    let disks = ui.get_disks();
                    if let Some(index) = (0..disks.row_count())
                        .find(|index| {
                            disks
                                .row_data(*index)
                                .is_some_and(|row| row.path == tile.path)
                        })
                        .and_then(|index| i32::try_from(index).ok())
                    {
                        ui.invoke_disk_selected(index);
                    } else {
                        ui.set_status("Refresh disks before selecting this destination.".into());
                    }
                    return;
                }
                ui.set_selected_disk(-1);
                ui.set_source(tile.path.clone());
                ui.set_status(format!("Selected partition: {}", tile.path).into());
            }
        });
    }
    {
        let ui = ui.as_weak();
        ui.upgrade().expect("ui").on_history_selected(move |idx| {
            let Some(strong) = ui.upgrade() else {
                return;
            };
            let path = strong
                .get_history()
                .row_data(idx.max(0) as usize)
                .map(|row| row.path.to_string());
            if let Some(path) = path {
                if path.is_empty() {
                    return;
                }
                strong.invoke_restore_inputs_changed();
                strong.set_image(path.clone().into());
                strong.set_restore_step(0);
                strong.set_current_tab(2);
                strong.set_status(format!("image from history: {path}").into());
            }
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
fn connect<F>(ui: &slint::Weak<MainWindow>, actions: &Arc<Actions>, run: F)
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

/// Run the GUI, optionally executing an automation script.
///
/// # Errors
/// Returns an error when the UI cannot be built, the script cannot be read, or
/// a script step fails.
pub fn run(options: GuiOptions) -> anyhow::Result<ScriptOutcome> {
    let ui = MainWindow::new().context("creating the Slint window")?;
    let app = App::new(ui.clone_strong(), &options.socket)?;
    let steps = match &options.script {
        Some(path) => Some(script::load(path).map_err(|error| anyhow::anyhow!("{error}"))?),
        None => None,
    };
    let outcome_slot: Arc<Mutex<Option<Result<ScriptOutcome, String>>>> =
        Arc::new(Mutex::new(None));

    if steps.is_none() {
        // Let the desktop choose an initial size within its usable work area,
        // including decorations and display scaling, rather than placing a
        // preferred-size window partly off-screen on small rescue displays.
        ui.window().set_maximized(true);
        let weak = ui.as_weak();
        slint::invoke_from_event_loop(move || {
            if let Some(ui) = weak.upgrade() {
                ui.invoke_refresh_disks();
            }
        })
        .context("queueing initial disk discovery")?;
    }

    if let Some(steps) = steps {
        let weak = ui.as_weak();
        let slot = Arc::clone(&outcome_slot);
        std::thread::spawn(move || {
            // Let the window map first: a mapped window proves the backend.
            std::thread::sleep(Duration::from_millis(800));
            let result = run_script(&weak, &steps);
            *slot.lock().expect("outcome lock") = Some(result);
            let _ = slint::invoke_from_event_loop(|| {
                let _ = slint::quit_event_loop();
            });
        });
    }
    if let Some(millis) = options.exit_after_ms {
        let timer = Box::leak(Box::new(slint::Timer::default()));
        timer.start(
            slint::TimerMode::SingleShot,
            Duration::from_millis(millis),
            || {
                let _ = slint::quit_event_loop();
            },
        );
    }

    ui.run().context("running the Slint event loop")?;
    let _ = app;
    let outcome = outcome_slot
        .lock()
        .expect("outcome lock")
        .take()
        .unwrap_or_else(|| {
            Ok(ScriptOutcome {
                steps: 0,
                log: Vec::new(),
            })
        });
    outcome.map_err(|error| anyhow::anyhow!(error))
}

/// Execute the steps through the UI callbacks.
fn run_script(weak: &slint::Weak<MainWindow>, steps: &[Step]) -> Result<ScriptOutcome, String> {
    let mut log = Vec::new();
    let mut executed = 0usize;
    for step in steps {
        match step {
            Step::Source(value) => {
                let value = value.clone();
                set(weak, move |ui| ui.set_source(value.into()))?
            }
            Step::Destination(value) => {
                let value = value.clone();
                set(weak, move |ui| ui.set_destination(value.into()))?
            }
            Step::SetName(value) => {
                let value = value.clone();
                set(weak, move |ui| ui.set_backup_set(value.into()))?
            }
            Step::Mode(value) => {
                let value = value.clone();
                set(weak, move |ui| ui.set_mode(value.into()))?
            }
            Step::BackupPassphraseFile(value) => {
                let value = value.clone();
                set(weak, move |ui| {
                    ui.set_passphrase_file(value.into());
                    ui.set_encrypt(true);
                })?
            }
            Step::RestorePassphraseFile(value) => {
                let value = value.clone();
                set(weak, move |ui| {
                    ui.invoke_restore_inputs_changed();
                    ui.set_restore_passphrase_file(value.into());
                })?
            }
            Step::Image(value) => {
                let value = value.clone();
                set(weak, move |ui| {
                    ui.invoke_restore_inputs_changed();
                    ui.set_image(value.into());
                })?
            }
            Step::Target(value) => {
                let value = value.clone();
                set(weak, move |ui| {
                    ui.invoke_restore_inputs_changed();
                    ui.set_target(value.into());
                })?
            }
            Step::Token(value) => {
                let value = value.clone();
                set(weak, move |ui| ui.set_token(value.into()))?
            }
            Step::RefreshDisks => {
                invoke(weak, |ui| ui.invoke_refresh_disks())?;
                wait_for_idle(weak, Duration::from_secs(60))?;
            }
            Step::History => {
                invoke(weak, |ui| ui.invoke_refresh_history())?;
                wait_for_idle(weak, Duration::from_secs(60))?;
            }
            Step::Probe => {
                invoke(weak, |ui| ui.invoke_probe_source())?;
                wait_for_idle(weak, Duration::from_secs(60))?;
            }
            Step::Backup => {
                // Existing scripts may inspect before setting the destination.
                // Review the final request through the normal UI action before
                // execution, rather than bypassing the current-request guard.
                invoke(weak, |ui| ui.invoke_probe_source())?;
                wait_for_idle(weak, Duration::from_secs(60))?;
                invoke(weak, |ui| ui.invoke_start_backup())?;
                wait_for_idle(weak, Duration::from_secs(300))?;
                log.push("backup finished".to_owned());
            }
            Step::ImageFromSummary => {
                let summary = read(weak, |ui| ui.get_progress_text().to_string())?;
                let value: serde_json::Value = serde_json::from_str(&summary).map_err(|error| {
                    format!("the backup summary is not JSON ({error}); raw text was: {summary:?}")
                })?;
                let image = value
                    .get("image_path")
                    .or_else(|| value.get("image_uri"))
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| "the backup summary carries no image path".to_owned())?
                    .to_owned();
                let image_for_ui = image.clone();
                set(weak, move |ui| {
                    ui.invoke_restore_inputs_changed();
                    ui.set_image(image_for_ui.into());
                })?;
                log.push(format!("image: {image}"));
            }
            Step::Prepare => {
                invoke(weak, |ui| ui.invoke_prepare_restore())?;
                wait_for_idle(weak, Duration::from_secs(60))?;
            }
            Step::ExpectPrepareFailure(expected) => {
                invoke(weak, |ui| ui.invoke_prepare_restore())?;
                let error = wait_for_idle(weak, Duration::from_secs(60))
                    .err()
                    .ok_or_else(|| "restore preparation unexpectedly succeeded".to_owned())?;
                let safe = read(weak, |ui| {
                    (!ui.get_busy()
                        && !ui.get_has_job()
                        && ui.get_token().is_empty()
                        && !ui.get_restore_confirmed()
                        && ui.get_phase() == "failed")
                        .to_string()
                })? == "true";
                if !safe || !error.contains(expected) {
                    return Err(format!(
                        "unexpected preparation failure or uncleared state: {error}"
                    ));
                }
                log.push(
                    "expected preparation failure; approval cleared and retry available".into(),
                );
            }
            Step::Restore => {
                // The explicit automation command stands for the user's
                // confirmation. It still uses the same current-plan guard.
                invoke(weak, |ui| {
                    ui.set_restore_confirmed(true);
                    ui.invoke_start_restore();
                })?;
                wait_for_idle(weak, Duration::from_secs(300))?;
                log.push("restore finished".to_owned());
            }
            Step::ExpectFile(_) | Step::ExpectContains(..) | Step::ExpectEmptyDirectory(_) => {
                let message = script::check_expectation(step).map_err(|error| error.to_string())?;
                if let Some(message) = message {
                    log.push(message);
                }
            }
            Step::Print => {
                let status = read(weak, |ui| ui.get_status().to_string())?;
                let plan = read(weak, |ui| ui.get_plan().to_string())?;
                let restore_plan = read(weak, |ui| ui.get_restore_plan().to_string())?;
                log.push(format!("status: {status}"));
                log.push(format!("backup plan: {plan}"));
                log.push(format!("restore plan: {restore_plan}"));
            }
            Step::Quit => break,
        }
        executed += 1;
    }
    let status = read(weak, |ui| ui.get_status().to_string())?;
    if status.contains("failed") {
        return Err(status);
    }
    Ok(ScriptOutcome {
        steps: executed,
        log,
    })
}

fn set(
    weak: &slint::Weak<MainWindow>,
    apply: impl FnOnce(&MainWindow) + Send + 'static,
) -> Result<(), String> {
    let weak = weak.clone();
    let (sender, receiver) = std::sync::mpsc::channel();
    slint::invoke_from_event_loop(move || {
        if let Some(ui) = weak.upgrade() {
            apply(&ui);
            let _ = sender.send(Ok(()));
        } else {
            let _ = sender.send(Err("the window is gone".to_owned()));
        }
    })
    .map_err(|error| error.to_string())?;
    receiver.recv().map_err(|error| error.to_string())?
}

fn invoke(
    weak: &slint::Weak<MainWindow>,
    apply: impl FnOnce(&MainWindow) + Send + 'static,
) -> Result<(), String> {
    set(weak, apply)
}

fn read(
    weak: &slint::Weak<MainWindow>,
    read: impl FnOnce(&MainWindow) -> String + Send + 'static,
) -> Result<String, String> {
    let weak = weak.clone();
    let (sender, receiver) = std::sync::mpsc::channel();
    slint::invoke_from_event_loop(move || {
        if let Some(ui) = weak.upgrade() {
            let _ = sender.send(Ok(read(&ui)));
        } else {
            let _ = sender.send(Err("the window is gone".to_owned()));
        }
    })
    .map_err(|error| error.to_string())?;
    receiver.recv().map_err(|error| error.to_string())?
}

/// Wait until no action is running.
fn wait_for_idle(weak: &slint::Weak<MainWindow>, timeout: Duration) -> Result<(), String> {
    let started = Instant::now();
    // Give the action a moment to set its busy flag before polling it.
    std::thread::sleep(Duration::from_millis(150));
    loop {
        let busy = read(weak, |ui| ui.get_busy().to_string())? == "true";
        if !busy {
            if read(weak, |ui| ui.get_phase().to_string())? == "failed" {
                return Err(read(weak, |ui| ui.get_status().to_string())?);
            }
            return Ok(());
        }
        if started.elapsed() > timeout {
            return Err(format!("the action did not finish within {timeout:?}"));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
