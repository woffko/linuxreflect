//! Bridge from the engine's progress hook to the daemon's event bus.
//!
//! The engine is synchronous and reports through `ProgressSink`; the daemon
//! publishes over a tokio broadcast channel. This adapter is the only place
//! the two meet, so the engine stays free of IPC types.

use tokio::sync::broadcast;

use lr_engine::progress::ProgressSink;

use crate::jobs::JobEvent;

/// A sink that republishes engine progress as job events.
#[derive(Clone)]
pub struct Sink {
    job_id: String,
    events: broadcast::Sender<JobEvent>,
}

impl std::fmt::Debug for Sink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sink")
            .field("job_id", &self.job_id)
            .finish_non_exhaustive()
    }
}

impl Sink {
    /// Build a sink for one job on the daemon's event bus.
    #[must_use]
    pub fn new(job_id: String, events: broadcast::Sender<JobEvent>) -> Self {
        Self { job_id, events }
    }

    fn publish(&self, event: JobEvent) {
        // A subscriber that fell behind is skipped, never waited on: progress
        // must not slow the engine down.
        let _ = self.events.send(event);
    }
}

impl ProgressSink for Sink {
    fn phase(&self, name: &str) {
        self.publish(JobEvent::Phase {
            job_id: self.job_id.clone(),
            name: name.to_owned(),
        });
    }

    fn bytes(&self, done: u64, total: u64) {
        self.publish(JobEvent::Bytes {
            job_id: self.job_id.clone(),
            done,
            total,
        });
    }
}
