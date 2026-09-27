//! What a stopping daemon waits for (A7, D-113).
//!
//! A stop waits for running jobs (D-107), but a job blocked in I/O never
//! reaches a progress point and would hold a shutdown forever. The unit
//! therefore has a finite `TimeoutStopSec`, and while jobs drain the daemon
//! asks systemd for more time (`EXTEND_TIMEOUT_USEC`) only as long as some
//! job still makes progress. It also says, in the journal and in the unit's
//! status, which job holds the stop and how far it is.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::jobs::JobEvent;

/// A job that has not advanced for this long no longer earns more time.
pub const STALL_LIMIT: Duration = Duration::from_secs(300);
/// How much more time one extension asks for; it matches the unit's
/// `TimeoutStopSec`.
pub const EXTEND_BY: Duration = Duration::from_secs(600);

#[derive(Debug, Clone)]
struct Seen {
    phase: String,
    done: u64,
    total: u64,
    advanced: Instant,
}

/// The progress of the jobs a stopping daemon waits for.
#[derive(Debug)]
pub struct DrainWatch {
    started: Instant,
    jobs: HashMap<String, Seen>,
}

impl DrainWatch {
    /// A watch that starts at `now`: a job without events yet counts as
    /// having advanced then.
    #[must_use]
    pub fn new(now: Instant) -> Self {
        Self {
            started: now,
            jobs: HashMap::new(),
        }
    }

    /// Record one job event seen at `now`.
    pub fn observe(&mut self, event: &JobEvent, now: Instant) {
        let started = self.started;
        let seen = |jobs: &mut HashMap<String, Seen>, id: &str| {
            jobs.entry(id.to_owned())
                .or_insert_with(|| Seen {
                    phase: String::new(),
                    done: 0,
                    total: 0,
                    advanced: started,
                })
                .clone()
        };
        match event {
            JobEvent::Phase { job_id, name } => {
                let mut entry = seen(&mut self.jobs, job_id);
                if entry.phase != *name {
                    entry.phase.clone_from(name);
                    entry.advanced = now;
                }
                self.jobs.insert(job_id.clone(), entry);
            }
            JobEvent::Bytes {
                job_id,
                done,
                total,
            } => {
                let mut entry = seen(&mut self.jobs, job_id);
                if entry.done != *done {
                    entry.advanced = now;
                }
                entry.done = *done;
                entry.total = *total;
                self.jobs.insert(job_id.clone(), entry);
            }
            JobEvent::Finished { job_id, .. } | JobEvent::Failed { job_id, .. } => {
                self.jobs.remove(job_id);
            }
            JobEvent::Started { .. } => {}
        }
    }

    fn advanced(&self, job_id: &str) -> Instant {
        self.jobs
            .get(job_id)
            .map_or(self.started, |seen| seen.advanced)
    }

    /// Whether to ask for more time: some active job advanced recently.
    #[must_use]
    pub fn should_extend(&self, active: &[(String, String)], now: Instant) -> bool {
        active
            .iter()
            .any(|(job_id, _)| now.duration_since(self.advanced(job_id)) < STALL_LIMIT)
    }

    /// One line per active job: what it is, how far it got, and when it last
    /// advanced.
    #[must_use]
    pub fn describe(&self, active: &[(String, String)], now: Instant) -> Vec<String> {
        active
            .iter()
            .map(|(job_id, set)| {
                let seen = self.jobs.get(job_id);
                let phase = seen
                    .map(|seen| seen.phase.as_str())
                    .filter(|phase| !phase.is_empty())
                    .unwrap_or("starting");
                let amount = match seen {
                    Some(seen) if seen.total > 0 => {
                        format!(
                            ", {}% of {} bytes",
                            seen.done * 100 / seen.total,
                            seen.total
                        )
                    }
                    Some(seen) if seen.done > 0 => format!(", {} bytes", seen.done),
                    _ => String::new(),
                };
                format!(
                    "job {job_id} (set {set}): {phase}{amount}, last progress {}s ago",
                    now.duration_since(self.advanced(job_id)).as_secs()
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{DrainWatch, STALL_LIMIT};
    use crate::jobs::JobEvent;
    use std::time::{Duration, Instant};

    #[test]
    fn a_stalled_job_stops_earning_time_and_every_job_is_named() {
        let start = Instant::now();
        let mut watch = DrainWatch::new(start);
        let active = vec![("restore-1".to_owned(), "laptop".to_owned())];
        assert!(watch.should_extend(&active, start + Duration::from_secs(1)));

        let bytes = |done| JobEvent::Bytes {
            job_id: "restore-1".to_owned(),
            done,
            total: 1000,
        };
        watch.observe(
            &JobEvent::Phase {
                job_id: "restore-1".to_owned(),
                name: "restore".to_owned(),
            },
            start,
        );
        watch.observe(&bytes(450), start + Duration::from_secs(60));
        let later = start + Duration::from_secs(60) + STALL_LIMIT / 2;
        assert!(watch.should_extend(&active, later), "it advanced recently");
        let lines = watch.describe(&active, later);
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].contains("restore-1")
                && lines[0].contains("laptop")
                && lines[0].contains("45%"),
            "{lines:?}"
        );

        // The same count again is no progress: a job blocked in I/O.
        watch.observe(&bytes(450), later);
        let stalled = start + Duration::from_secs(60) + STALL_LIMIT + Duration::from_secs(1);
        assert!(
            !watch.should_extend(&active, stalled),
            "a stalled job earns no time"
        );

        watch.observe(
            &JobEvent::Finished {
                job_id: "restore-1".to_owned(),
                summary_json: String::new(),
            },
            stalled,
        );
        assert!(watch.describe(&[], stalled).is_empty());
    }
}
