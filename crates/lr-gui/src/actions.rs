//! Actions against the daemon, the admission gate they share, and the job
//! lifecycle that follows a running backup, restore or verification.

use super::*;

/// State shared by the callbacks and the running actions.
pub(crate) struct Shared {
    pub(crate) busy: AtomicBool,
    pub(crate) generation: AtomicU64,
    pub(crate) failure: Mutex<Option<String>>,
    pub(crate) restore_review: Mutex<review::Review>,
    pub(crate) backup_review: Mutex<backup_review::Review>,
    /// Where remembered folders are saved; `None` in scripted runs.
    pub(crate) prefs: Mutex<Option<PathBuf>>,
}

/// Everything a callback needs, without keeping the UI alive.
pub(crate) struct Actions {
    pub(crate) runtime: tokio::runtime::Handle,
    pub(crate) socket: PathBuf,
    pub(crate) shared: Arc<Shared>,
}

impl Actions {
    pub(crate) fn start(&self, ui: &slint::Weak<MainWindow>, label: &str) -> bool {
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
            if matches!(label, "backup" | "restore" | "verify") {
                ui.set_result_text("".into());
                ui.set_show_result_details(false);
            }
        }
        true
    }

    /// The disk map: `ListDisks` rendered into rows, and every disk's
    /// `DiskMap` rendered into a panel. A disk the daemon cannot map still
    /// gets a panel from the device list, with the reason shown on it.
    pub(crate) fn refresh_disks(&self, ui: slint::Weak<MainWindow>) {
        if !self.start(&ui, "list disks") {
            return;
        }
        let show_system = ui.upgrade().is_some_and(|ui| ui.get_show_system_devices());
        if let Some(ui) = ui.upgrade() {
            ui.set_disk_status("Loading disks…".into());
            ui.set_disk_error(false);
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
                // Disks first, each followed by its partitions, so every row
                // carries the node the daemon accepts as a source.
                let ordered = devices::ordered(&entries, show_system);
                let mut panels = Vec::new();
                for (disk_row, device) in ordered.iter().enumerate() {
                    if device.partition.is_some() {
                        continue;
                    }
                    let number = panels.len() + 1;
                    let panel = match client.disk_map(&device.path).await {
                        Ok(layout) => disk_map::from_layout(number, disk_row, &ordered, &layout),
                        Err(error) => disk_map::from_list(
                            number,
                            disk_row,
                            &ordered,
                            &format!("Details unavailable: {}", first_line(&error)),
                        ),
                    };
                    panels.push(panel);
                }
                let rows: Vec<_> = ordered
                    .iter()
                    .map(|entry| disk_row(entry, &entries))
                    .collect();
                Ok::<_, anyhow::Error>((rows, panels))
            }
            .await;
            match outcome {
                Ok((rows, panels)) => {
                    let weak = weak.clone();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            let disk_count = panels.len();
                            let partitions = rows.len() - disk_count;
                            ui.set_disk_cards(disk_cards(&panels, &rows));
                            ui.set_disks(slint::ModelRc::new(slint::VecModel::from(rows)));
                            ui.set_selected_disk(-1);
                            ui.set_status(
                                format!("{disk_count} disks, {partitions} partitions").into(),
                            );
                            ui.set_disk_error(false);
                            ui.set_disk_status(if disk_count == 0 {
                                "No disks found. Refresh, or show service devices.".into()
                            } else {
                                "".into()
                            });
                            reselect(&ui);
                            ui.set_busy(false);
                            actions.shared.busy.store(false, Ordering::SeqCst);
                        }
                    });
                }
                Err(error) => {
                    let message = format!("Could not load the disks: {}", first_line(&error));
                    actions.fail(&weak, "list disks", &error);
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            ui.set_disks(slint::ModelRc::default());
                            ui.set_disk_cards(slint::ModelRc::default());
                            ui.set_disk_error(true);
                            ui.set_disk_status(message.into());
                        }
                    });
                }
            }
        });
    }

    /// The backup library: every set at the destination (or only `set` when
    /// one is named), each with its members, newest first.
    pub(crate) fn refresh_history(&self, ui: slint::Weak<MainWindow>, dest: String, set: String) {
        if !self.start(&ui, "history") {
            return;
        }
        let socket = self.socket.clone();
        let actions = self.clone_handle();
        let weak = ui.clone();
        self.runtime.spawn(async move {
            let outcome = async {
                let client = Client::connect(&socket).await?;
                let sets = if set.is_empty() {
                    client.list_set_names(&dest).await?
                } else {
                    vec![set.clone()]
                };
                let mut rows = Vec::new();
                for set in sets {
                    let json = client.list_sets(&dest, &set).await?;
                    let value: serde_json::Value =
                        serde_json::from_str(&json).context("set JSON")?;
                    let mut members = Vec::new();
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
                            let unix = member
                                .get("created_unix")
                                .and_then(serde_json::Value::as_u64)
                                .unwrap_or(0);
                            members.push((
                                (unix, seq),
                                HistoryRow {
                                    name: format!(
                                        "{} · Copy {}",
                                        history::backup_kind(kind),
                                        seq.saturating_add(1)
                                    )
                                    .into(),
                                    detail: format!("Created: {created} · {size}\n{file}").into(),
                                    path: path.into(),
                                    group: set.clone().into(),
                                    first: false,
                                },
                            ));
                        }
                    }
                    // Newest first; copies made within the same second are
                    // ordered by their position in the chain.
                    members.sort_by_key(|member| std::cmp::Reverse(member.0));
                    for (index, (_, mut row)) in members.into_iter().enumerate() {
                        row.first = index == 0;
                        rows.push(row);
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
    pub(crate) fn probe_source(&self, ui: slint::Weak<MainWindow>, requested: BackupSpec) {
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
    pub(crate) fn start_backup(&self, ui: slint::Weak<MainWindow>, spec: BackupSpec) {
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

    /// Verify an image and its chain (`VerifyImage`), as a job the strip and
    /// the Activity page follow.
    pub(crate) fn verify_image(
        &self,
        ui: slint::Weak<MainWindow>,
        image: String,
        passphrase: String,
    ) {
        if !self.start(&ui, "verify") {
            return;
        }
        if let Some(ui) = ui.upgrade() {
            job_view::start(&ui, "verify");
            ui.set_job_operation("verify".into());
            ui.set_progress(0.0);
            ui.set_progress_text(format!("Verifying {image}…").into());
        }
        let socket = self.socket.clone();
        let actions = self.clone_handle();
        let weak = ui.clone();
        self.runtime.spawn(async move {
            let progress_ui = weak.clone();
            let progress_actions = actions.clone();
            let outcome = async {
                Client::connect(&socket)
                    .await?
                    .verify(&image, &passphrase, move |progress| {
                        report_progress(&progress_actions, &progress_ui, progress);
                    })
                    .await
            }
            .await;
            match outcome {
                Ok(summary) => actions.finish(&weak, "verify", &summary),
                Err(error) => actions.fail(&weak, "verify", &error),
            }
        });
    }

    /// The restore wizard's token plan (`PrepareRestore`).
    pub(crate) fn prepare_restore(
        &self,
        ui: slint::Weak<MainWindow>,
        image: String,
        target: String,
    ) {
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
    pub(crate) fn start_restore(&self, ui: slint::Weak<MainWindow>, approved: review::Approved) {
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
    pub(crate) fn check_job(&self, ui: slint::Weak<MainWindow>, job_id: String, operation: String) {
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
    pub(crate) fn cancel_job(&self, ui: slint::Weak<MainWindow>, job_id: String) {
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
    pub(crate) fn clone_handle(&self) -> ActionsHandle {
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

    /// Both scenarios need a window, and Slint binds its platform to the
    /// first thread that creates one while libtest gives every test its own
    /// thread; so they run one after the other inside a single test.
    #[test]
    #[ignore = "requires a display; run with Xvfb"]
    pub(crate) fn job_admission_lifecycle() {
        unavailable_daemon_does_not_release_a_job_after_cancel_or_status();
        completion_keeps_admission_closed_until_ui_cleanup();
    }

    pub(crate) fn unavailable_daemon_does_not_release_a_job_after_cancel_or_status() {
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

    pub(crate) fn completion_keeps_admission_closed_until_ui_cleanup() {
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
pub(crate) struct ActionsHandle {
    pub(crate) shared: Arc<Shared>,
    pub(crate) generation: u64,
    // GetJob replies can queue terminal UI updates after the receipt-time
    // identity check. Recheck when that update is actually applied.
    pub(crate) expected_job: Option<String>,
}

impl ActionsHandle {
    pub(crate) fn fail(&self, ui: &slint::Weak<MainWindow>, label: &str, error: &anyhow::Error) {
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
                if matches!(label.as_str(), "backup" | "restore" | "verify")
                    && ui.get_has_job()
                    && !terminal
                {
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

    pub(crate) fn finish(&self, ui: &slint::Weak<MainWindow>, label: &str, summary: &str) {
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
                if label == "backup" {
                    // The library reloads on its next visit and shows this copy.
                    ui.set_history(slint::ModelRc::default());
                }
                if label == "backup"
                    && let Some(file) = shared.prefs.lock().expect("prefs lock").clone()
                {
                    let recent = prefs::remember_destination(&file, ui.get_destination().as_str());
                    ui.set_recent_destinations(string_model(&recent));
                }
                if let Some(image) = image {
                    ui.set_last_image(image.clone().into());
                    ui.invoke_restore_inputs_changed();
                    ui.set_image(image.into());
                    ui.set_image_detail("The backup made in this window".into());
                }
                // Admission stays closed until the old identity and UI state
                // have been cleared together on the event-loop thread.
                shared.busy.store(false, Ordering::SeqCst);
            }
        });
    }
}

/// Push one daemon progress step into the UI.
pub(crate) fn report_progress(
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
pub(crate) fn image_of_summary(summary: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(summary).ok()?;
    value
        .get("image_path")
        .or_else(|| value.get("image_uri"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}
