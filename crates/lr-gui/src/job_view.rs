//! Operation-bound presentation; admission and daemon liveness remain separate.

use crate::generated::{JobPresentation, JobStage, MainWindow};

pub(crate) fn update(ui: &MainWindow, operation: &str, change: impl FnOnce(&mut JobPresentation)) {
    let mut view = match operation {
        "backup" => ui.get_backup_job(),
        "restore" => ui.get_restore_job(),
        "verify" => ui.get_verify_job(),
        _ => return,
    };
    change(&mut view);
    match operation {
        "backup" => ui.set_backup_job(view),
        "restore" => ui.set_restore_job(view),
        "verify" => ui.set_verify_job(view),
        _ => unreachable!(),
    }
}

pub(crate) fn start(ui: &MainWindow, operation: &str) {
    update(ui, operation, |view| {
        *view = JobPresentation {
            stage: JobStage::Starting,
            detail: "Connecting to the backup service…".into(),
            report: Default::default(),
        };
    });
}
