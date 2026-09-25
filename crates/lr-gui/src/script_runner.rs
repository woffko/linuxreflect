//! Runs an automation script through the same callbacks a user triggers.

use super::*;

/// Execute the steps through the UI callbacks.
pub(crate) fn run_script(
    weak: &slint::Weak<MainWindow>,
    steps: &[Step],
) -> Result<ScriptOutcome, String> {
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
                    ui.set_image_detail("".into());
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
                    ui.set_image_detail("".into());
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
            Step::ExpectRestoreFailure(expected) => {
                invoke(weak, |ui| {
                    ui.set_restore_confirmed(true);
                    ui.invoke_start_restore();
                })?;
                let error = wait_for_idle(weak, Duration::from_secs(300))
                    .err()
                    .ok_or_else(|| "restore unexpectedly succeeded".to_owned())?;
                if !error.contains(expected) {
                    return Err(format!("unexpected restore failure: {error}"));
                }
                let released = read(weak, |ui| (!ui.get_busy()).to_string())? == "true";
                if !released {
                    return Err("the refused restore left the window busy".to_owned());
                }
                log.push(format!("expected restore failure: {expected}"));
                // The failure was the expected outcome, not a script failure.
                set(weak, |ui| {
                    ui.set_status("expected restore failure confirmed".into())
                })?;
            }
            Step::MemberType(value) => {
                let value = value.clone();
                set(weak, move |ui| ui.set_member_type(value.into()))?;
            }
            Step::Pick(index) => {
                let index = i32::try_from(*index).map_err(|error| error.to_string())?;
                invoke(weak, move |ui| ui.invoke_history_selected(index))?;
                let image = read(weak, |ui| ui.get_image().to_string())?;
                if image.is_empty() {
                    return Err(format!("library row {index} chose no image"));
                }
                log.push(format!("picked: {image}"));
            }
            Step::Verify(index) => {
                let index = i32::try_from(*index).map_err(|error| error.to_string())?;
                invoke(weak, move |ui| ui.invoke_verify_image(index))?;
                wait_for_idle(weak, Duration::from_secs(300))?;
                log.push("verify ok".to_owned());
            }
            Step::ExpectVerifyFailure(index, expected) => {
                let index = i32::try_from(*index).map_err(|error| error.to_string())?;
                invoke(weak, move |ui| ui.invoke_verify_image(index))?;
                let error = wait_for_idle(weak, Duration::from_secs(300))
                    .err()
                    .ok_or_else(|| "verification unexpectedly passed".to_owned())?;
                if !error.contains(expected.as_str()) {
                    return Err(format!("unexpected verification failure: {error}"));
                }
                log.push(format!("expected verification failure: {expected}"));
                set(weak, |ui| {
                    ui.set_status("expected verification failure confirmed".into());
                })?;
            }
            Step::Signal(path) => {
                std::fs::write(path, b"")
                    .map_err(|error| format!("signal {}: {error}", path.display()))?;
            }
            Step::WaitForFile(path) => {
                let deadline = std::time::Instant::now() + Duration::from_secs(60);
                while !path.exists() {
                    if std::time::Instant::now() >= deadline {
                        return Err(format!("timed out waiting for {}", path.display()));
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
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

pub(crate) fn set(
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

pub(crate) fn invoke(
    weak: &slint::Weak<MainWindow>,
    apply: impl FnOnce(&MainWindow) + Send + 'static,
) -> Result<(), String> {
    set(weak, apply)
}

pub(crate) fn read(
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
pub(crate) fn wait_for_idle(
    weak: &slint::Weak<MainWindow>,
    timeout: Duration,
) -> Result<(), String> {
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
