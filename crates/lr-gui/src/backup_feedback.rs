//! Readable planning failures; the daemon's complete diagnostic stays separate.

use crate::generated::MainWindow;

pub(crate) struct Failure {
    pub(crate) message: &'static str,
    pub(crate) details: String,
}

pub(crate) fn failure(error: &anyhow::Error) -> Failure {
    let status = error.downcast_ref::<tonic::Status>();
    // The daemon's status contract is `E_CODE: explanation`. Match only that
    // leading code, never words buried in an unrelated diagnostic.
    let code = status.and_then(|status| status.message().split_once(':').map(|pair| pair.0));
    let message = match (code, status.map(tonic::Status::code)) {
        (Some("E_NO_CONSISTENT_METHOD"), _) => {
            "No consistent imaging method is available for this source with the selected settings. \
             For an image of the running system disk, boot rescue media and back it up offline. \
             To test the GUI now, go Back to Source, choose a small local folder, and keep your \
             network folder as Destination. A second local drive is not required."
        }
        (_, Some(tonic::Code::Unimplemented)) => {
            "The connected daemon does not support planning the selected backup options. \
             Rebuild and restart the daemon from the same checkout as the GUI, then retry."
        }
        (_, Some(tonic::Code::PermissionDenied | tonic::Code::Unauthenticated)) => {
            "Backup planning was not authorized, or a required file is not accessible. \
             Check the daemon authorization and access to the selected files."
        }
        (_, Some(tonic::Code::Unavailable)) => {
            "The backup service could not be reached. Check that the daemon is running \
             and that the GUI uses its socket, then retry."
        }
        _ => {
            "The backup could not be planned with the selected settings. \
             Check the source, backup options and destination. Open Technical details for the reason."
        }
    };
    Failure {
        message,
        details: format!("{error:#}"),
    }
}

pub(crate) fn clear(ui: &MainWindow) {
    ui.set_backup_plan_error("".into());
    ui.set_backup_plan_error_details("".into());
    ui.set_show_backup_plan_error_details(false);
    ui.set_backup_summary("".into());
    ui.set_plan("(no plan yet)".into());
}

#[cfg(test)]
mod tests {
    use super::failure;
    use std::rc::Rc;
    use std::sync::mpsc::{self, Receiver, Sender};

    use slint::ComponentHandle;
    use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType};
    use slint::platform::{EventLoopProxy, Platform, PlatformError, WindowAdapter};

    enum Event {
        Invoke(Box<dyn FnOnce() + Send>),
        Quit,
    }

    struct Proxy(Sender<Event>);

    impl EventLoopProxy for Proxy {
        fn quit_event_loop(&self) -> Result<(), slint::EventLoopError> {
            self.0
                .send(Event::Quit)
                .map_err(|_| slint::EventLoopError::EventLoopTerminated)
        }

        fn invoke_from_event_loop(
            &self,
            event: Box<dyn FnOnce() + Send>,
        ) -> Result<(), slint::EventLoopError> {
            self.0
                .send(Event::Invoke(event))
                .map_err(|_| slint::EventLoopError::EventLoopTerminated)
        }
    }

    struct Headless {
        window: Rc<MinimalSoftwareWindow>,
        sender: Sender<Event>,
        receiver: Receiver<Event>,
    }

    impl Platform for Headless {
        fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, PlatformError> {
            Ok(self.window.clone())
        }

        fn new_event_loop_proxy(&self) -> Option<Box<dyn EventLoopProxy>> {
            Some(Box::new(Proxy(self.sender.clone())))
        }

        fn run_event_loop(&self) -> Result<(), PlatformError> {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                slint::platform::update_timers_and_animations();
                match self
                    .receiver
                    .recv_timeout(std::time::Duration::from_millis(10))
                {
                    Ok(Event::Invoke(event)) => event(),
                    Ok(Event::Quit) => return Ok(()),
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        assert!(std::time::Instant::now() < deadline, "GUI test timed out");
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => panic!("GUI queue disconnected"),
                }
            }
        }
    }

    #[test]
    fn planning_errors_are_classified_by_status_not_incidental_words() {
        let error = anyhow::Error::new(tonic::Status::failed_precondition(
            "E_NO_CONSISTENT_METHOD: mounted source cannot be read offline",
        ))
        .context("planning backup");
        let feedback = failure(&error);
        assert!(feedback.message.contains("rescue media"));
        assert!(feedback.message.contains("small local folder"));
        assert!(
            feedback
                .message
                .contains("second local drive is not required")
        );
        assert!(!feedback.message.contains("allow-inconsistent"));
        assert!(feedback.details.contains("E_NO_CONSISTENT_METHOD"));

        let unrelated =
            tonic::Status::internal("E_IO: cannot open a file named E_NO_CONSISTENT_METHOD");
        assert!(!failure(&unrelated.into()).message.contains("rescue media"));
        assert!(
            failure(&tonic::Status::permission_denied("E_DENIED: refused").into())
                .message
                .contains("not authorized")
        );
        assert!(
            failure(&tonic::Status::unimplemented("unknown method").into())
                .message
                .contains("Rebuild and restart")
        );
    }

    #[test]
    fn failed_plans_are_request_bound_and_edits_clear_feedback_and_approval() {
        let (sender, receiver) = mpsc::channel();
        slint::platform::set_platform(Box::new(Headless {
            window: MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer),
            sender,
            receiver,
        }))
        .expect("headless platform");
        let ui = crate::generated::MainWindow::new().expect("test UI");
        let app = crate::App::new(
            ui,
            std::path::Path::new("/nonexistent/lr-planning-test.sock"),
        )
        .expect("test app");
        let ui = app.ui();
        ui.set_source("/fixture/source".into());
        ui.set_destination("/fixture/backups".into());
        ui.set_backup_step(1);
        slint::platform::update_timers_and_animations();
        let old = crate::models::backup_spec(ui);
        let weak = ui.as_weak();
        assert!(app.actions.start(&weak, "probe"));
        let error: anyhow::Error =
            tonic::Status::failed_precondition("E_NO_CONSISTENT_METHOD: offline source required")
                .into();
        app.actions
            .clone_handle()
            .fail_backup_plan(&weak, &old, &error);
        ui.set_destination("/fixture/new-backups".into());
        let actions = app.actions.clone();
        slint::invoke_from_event_loop(move || {
            let ui = weak.upgrade().expect("test UI alive");
            assert!(!ui.get_busy());
            assert!(
                ui.get_backup_plan_error().is_empty(),
                "stale error was shown"
            );
            assert_eq!(ui.get_phase(), "idle");
            let current = crate::models::backup_spec(&ui);
            assert!(actions.start(&weak, "probe"));
            actions
                .clone_handle()
                .fail_backup_plan(&weak, &current, &error);
            slint::invoke_from_event_loop(move || {
                let ui = weak.upgrade().expect("test UI alive");
                assert!(!ui.get_busy());
                assert!(ui.get_backup_plan_error().contains("rescue media"));
                assert!(
                    ui.get_backup_plan_error_details()
                        .contains("E_NO_CONSISTENT_METHOD")
                );
                assert!(!ui.get_status().contains("E_NO_CONSISTENT_METHOD"));
                assert_eq!(ui.get_phase(), "failed");
                assert!(
                    actions
                        .shared
                        .backup_review
                        .lock()
                        .unwrap()
                        .take(&current)
                        .is_err()
                );
                assert!(
                    actions
                        .shared
                        .backup_review
                        .lock()
                        .unwrap()
                        .accept(current.clone(), &current)
                );
                ui.set_backup_step(2);
                ui.set_backup_summary("old plan".into());
                ui.set_compress("none".into());
                slint::platform::update_timers_and_animations();
                assert!(ui.get_backup_plan_error().is_empty());
                assert!(ui.get_backup_plan_error_details().is_empty());
                assert!(ui.get_backup_summary().is_empty());
                assert_eq!(ui.get_phase(), "idle");
                assert!(actions.shared.failure.lock().unwrap().is_none());
                assert_eq!(ui.get_backup_step(), 1);
                assert!(
                    actions
                        .shared
                        .backup_review
                        .lock()
                        .unwrap()
                        .take(&current)
                        .is_err()
                );
                slint::quit_event_loop().expect("stop headless test");
            })
            .expect("check current refusal and edited inputs");
        })
        .expect("check stale refusal");
        slint::run_event_loop_until_quit().expect("headless GUI events");
    }
}
