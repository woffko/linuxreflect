//! In-memory job registry (spec §I).
//!
//! Jobs are idempotent by the client's `job_id`, only one job may run per set
//! at a time, and cancellation is cooperative: the flag here is the same one
//! the engine checks through its progress hook, so a cancelled job still tears
//! its temporary files and snapshots down before it returns.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use lr_core::{Error, Result};
use tokio::sync::broadcast;

use crate::auth::{Action, PeerIdentity, SharedAuth};
use crate::progress_bridge::Sink;

/// Where a job is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    /// Registered but not started.
    Pending,
    /// Running now.
    Running,
    /// Completed successfully.
    Finished,
    /// Failed; the reason is in the snapshot.
    Failed,
    /// Cancelled by a client.
    Cancelled,
}

/// What a job reports to `GetJob`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct JobSnapshot {
    /// Client-supplied identifier.
    pub job_id: String,
    /// Set the job works on.
    pub set: String,
    /// Current state.
    pub state: JobState,
    /// Engine report as JSON, when the job finished.
    pub summary_json: Option<String>,
    /// Failure code and message, when the job failed.
    pub error: Option<(String, String)>,
}

/// One event published to `WatchEvents` and to a job's own stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobEvent {
    /// The job started.
    Started {
        /// Job identifier.
        job_id: String,
    },
    /// A phase began.
    Phase {
        /// Job identifier.
        job_id: String,
        /// Phase name.
        name: String,
    },
    /// Bytes processed.
    Bytes {
        /// Job identifier.
        job_id: String,
        /// Done so far.
        done: u64,
        /// Estimate, 0 when unknown.
        total: u64,
    },
    /// The job finished successfully.
    Finished {
        /// Job identifier.
        job_id: String,
        /// Engine report as JSON.
        summary_json: String,
    },
    /// The job failed or was cancelled.
    Failed {
        /// Job identifier.
        job_id: String,
        /// Stable code (`E_*`).
        code: String,
        /// Human-readable message.
        message: String,
    },
}

impl JobEvent {
    /// The job this event belongs to.
    #[must_use]
    pub fn job_id(&self) -> &str {
        match self {
            Self::Started { job_id }
            | Self::Phase { job_id, .. }
            | Self::Bytes { job_id, .. }
            | Self::Finished { job_id, .. }
            | Self::Failed { job_id, .. } => job_id,
        }
    }
}

struct Entry {
    set: String,
    state: JobState,
    cancel: Arc<AtomicBool>,
    summary_json: Option<String>,
    error: Option<(String, String)>,
}

/// The registry plus the event bus.
pub struct Jobs {
    entries: Mutex<HashMap<String, Entry>>,
    events: broadcast::Sender<JobEvent>,
}

impl std::fmt::Debug for Jobs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Jobs")
            .field("event_subscribers", &self.events.receiver_count())
            .finish_non_exhaustive()
    }
}

impl Default for Jobs {
    fn default() -> Self {
        Self::new()
    }
}

impl Jobs {
    /// A registry with a fresh event bus.
    #[must_use]
    pub fn new() -> Self {
        let (events, _) = broadcast::channel(1024);
        Self {
            entries: Mutex::new(HashMap::new()),
            events,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry>> {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Subscribe to every event, for `WatchEvents`.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<JobEvent> {
        self.events.subscribe()
    }

    /// Publish an event; a slow subscriber is skipped, never blocked on.
    fn publish(&self, event: JobEvent) {
        let _ = self.events.send(event);
    }

    /// Register a job and return the progress sink and cancellation flag the
    /// engine should use.
    ///
    /// # Errors
    /// Returns [`Error::TargetBusy`] when the same `job_id` is already running
    /// or when another job holds the set.
    pub fn register(&self, job_id: &str, set: &str) -> Result<(Sink, Arc<AtomicBool>)> {
        let mut entries = self.lock();
        if let Some(existing) = entries.get(job_id)
            && matches!(existing.state, JobState::Pending | JobState::Running)
        {
            return Err(Error::TargetBusy {
                holder: format!("job {job_id} is already {}", state_name(existing.state)),
            });
        }
        if let Some((running, _)) = entries
            .iter()
            .find(|(id, entry)| {
                id.as_str() != job_id
                    && entry.set == set
                    && matches!(entry.state, JobState::Pending | JobState::Running)
            })
            .map(|(id, entry)| (id.clone(), entry.state))
        {
            return Err(Error::TargetBusy {
                holder: format!("set {set} is busy with job {running}"),
            });
        }

        let cancel = Arc::new(AtomicBool::new(false));
        entries.insert(
            job_id.to_owned(),
            Entry {
                set: set.to_owned(),
                state: JobState::Running,
                cancel: Arc::clone(&cancel),
                summary_json: None,
                error: None,
            },
        );
        drop(entries);
        self.publish(JobEvent::Started {
            job_id: job_id.to_owned(),
        });
        Ok((Sink::new(job_id.to_owned(), self.events.clone()), cancel))
    }

    /// Record the outcome of a job.
    ///
    /// # Errors
    /// Returns [`Error::Unsupported`] for an unknown job.
    pub fn finish(&self, job_id: &str, outcome: Result<String>) -> Result<JobSnapshot> {
        let mut entries = self.lock();
        let entry = entries
            .get_mut(job_id)
            .ok_or_else(|| Error::unsupported(format!("no job {job_id}")))?;
        match outcome {
            Ok(summary) => {
                entry.state = JobState::Finished;
                entry.summary_json = Some(summary.clone());
                entry.error = None;
                drop(entries);
                self.publish(JobEvent::Finished {
                    job_id: job_id.to_owned(),
                    summary_json: summary,
                });
            }
            Err(error) => {
                let cancelled = matches!(error, Error::Cancelled);
                let (code, message) = crate::status::error_code(&error);
                entry.state = if cancelled {
                    JobState::Cancelled
                } else {
                    JobState::Failed
                };
                entry.error = Some((code.clone(), message.clone()));
                drop(entries);
                self.publish(JobEvent::Failed {
                    job_id: job_id.to_owned(),
                    code,
                    message,
                });
            }
        }
        self.snapshot(job_id)
    }

    /// Report a job.
    ///
    /// # Errors
    /// Returns [`Error::Unsupported`] for an unknown job.
    pub fn snapshot(&self, job_id: &str) -> Result<JobSnapshot> {
        let entries = self.lock();
        let entry = entries
            .get(job_id)
            .ok_or_else(|| Error::unsupported(format!("no job {job_id}")))?;
        Ok(JobSnapshot {
            job_id: job_id.to_owned(),
            set: entry.set.clone(),
            state: entry.state,
            summary_json: entry.summary_json.clone(),
            error: entry.error.clone(),
        })
    }

    /// Ask a job to stop; the engine notices on its next progress check.
    ///
    /// # Errors
    /// Returns [`Error::Unsupported`] for an unknown job.
    pub fn cancel(&self, job_id: &str) -> Result<JobSnapshot> {
        {
            let mut entries = self.lock();
            let entry = entries
                .get_mut(job_id)
                .ok_or_else(|| Error::unsupported(format!("no job {job_id}")))?;
            entry.cancel.store(true, Ordering::SeqCst);
            if matches!(entry.state, JobState::Pending) {
                entry.state = JobState::Cancelled;
            }
        }
        self.snapshot(job_id)
    }

    /// Every known job, newest state first by id.
    ///
    /// # Errors
    /// Never fails; the result mirrors the API of the other accessors.
    pub fn list(&self) -> Result<Vec<JobSnapshot>> {
        let entries = self.lock();
        let mut jobs: Vec<JobSnapshot> = entries
            .iter()
            .map(|(job_id, entry)| JobSnapshot {
                job_id: job_id.clone(),
                set: entry.set.clone(),
                state: entry.state,
                summary_json: entry.summary_json.clone(),
                error: entry.error.clone(),
            })
            .collect();
        jobs.sort_by(|left, right| left.job_id.cmp(&right.job_id));
        Ok(jobs)
    }
}

fn state_name(state: JobState) -> &'static str {
    match state {
        JobState::Pending => "pending",
        JobState::Running => "running",
        JobState::Finished => "finished",
        JobState::Failed => "failed",
        JobState::Cancelled => "cancelled",
    }
}

/// Authorize and register in one step, so handlers cannot forget the check.
///
/// # Errors
/// Returns the authorization error, or [`Error::TargetBusy`] from the registry.
pub async fn authorize_and_register(
    auth: &SharedAuth,
    jobs: &Jobs,
    peer: &PeerIdentity,
    action: Action,
    job_id: &str,
    set: &str,
) -> Result<(Sink, Arc<AtomicBool>)> {
    auth.check(peer, action).await?;
    jobs.register(job_id, set)
}

/// How many jobs are registered, for tests and diagnostics.
#[must_use]
pub fn count(jobs: &Jobs) -> usize {
    jobs.lock().len()
}

#[cfg(test)]
mod tests {
    use super::{JobState, Jobs};
    use lr_core::Error;
    use lr_engine::progress::ProgressSink;

    #[test]
    fn a_job_runs_once_and_finishes() {
        let jobs = Jobs::new();
        let (sink, cancel) = jobs.register("j1", "set-a").expect("register");
        assert!(!cancel.load(std::sync::atomic::Ordering::SeqCst));
        sink.phase("scan");
        let snapshot = jobs.finish("j1", Ok("{}".to_owned())).expect("finish");
        assert_eq!(snapshot.state, JobState::Finished);
        assert_eq!(snapshot.summary_json.as_deref(), Some("{}"));
        assert_eq!(jobs.snapshot("j1").expect("get").set, "set-a");
    }

    #[test]
    fn a_running_job_id_is_not_reused_and_a_set_runs_one_job() {
        let jobs = Jobs::new();
        let _first = jobs.register("j1", "set-a").expect("register");
        let error = jobs.register("j1", "set-a").expect_err("same id");
        assert!(matches!(error, Error::TargetBusy { .. }), "{error}");
        let error = jobs.register("j2", "set-a").expect_err("same set");
        assert!(error.to_string().contains("busy with job j1"), "{error}");
        // Another set is free.
        let _other = jobs.register("j3", "set-b").expect("other set");
        // A finished job id may be reused.
        jobs.finish("j1", Ok("{}".to_owned())).expect("finish");
        let _again = jobs.register("j1", "set-c").expect("reuse after finish");
    }

    #[test]
    fn cancelling_sets_the_flag_the_engine_reads() {
        let jobs = Jobs::new();
        let (_sink, cancel) = jobs.register("j1", "set-a").expect("register");
        let snapshot = jobs.cancel("j1").expect("cancel");
        assert_eq!(
            snapshot.state,
            JobState::Running,
            "the job is still finishing"
        );
        assert!(cancel.load(std::sync::atomic::Ordering::SeqCst));
        let snapshot = jobs
            .finish("j1", Err(Error::cancelled()))
            .expect("finish cancelled");
        assert_eq!(snapshot.state, JobState::Cancelled);
    }

    #[test]
    fn a_failed_job_keeps_its_error_code() {
        let jobs = Jobs::new();
        let _registered = jobs.register("j1", "set-a").expect("register");
        let snapshot = jobs
            .finish("j1", Err(Error::TargetChanged))
            .expect("finish");
        assert_eq!(snapshot.state, JobState::Failed);
        assert_eq!(
            snapshot.error.as_ref().map(|(code, _)| code.as_str()),
            Some("E_TARGET_CHANGED")
        );
    }

    #[test]
    fn events_reach_subscribers() {
        let jobs = Jobs::new();
        let mut events = jobs.subscribe();
        let (sink, _cancel) = jobs.register("j1", "set-a").expect("register");
        sink.phase("scan");
        let _ = jobs.finish("j1", Ok("{}".to_owned()));
        let mut seen = Vec::new();
        while let Ok(event) = events.try_recv() {
            seen.push(event.job_id().to_owned());
        }
        assert_eq!(seen.len(), 3, "started, phase, finished");
        assert_eq!(jobs.list().expect("list").len(), 1);
    }

    #[test]
    fn unknown_jobs_are_reported() {
        let jobs = Jobs::new();
        assert!(jobs.snapshot("nope").is_err());
        assert!(jobs.cancel("nope").is_err());
    }
}
