//! Live progress and cooperative cancellation (spec §I, Slice S11).
//!
//! The engine reports only what it actually knows: the phase it is in and the
//! bytes it has read or written so far. Reporting is throttled so a fast loop
//! cannot drown its caller, and cancellation is checked in the same places —
//! a cancelled job returns [`Error::Cancelled`] and still tears everything
//! down through the existing guards.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use lr_core::{Error, Result};

/// Where progress events go.
pub trait ProgressSink: Send + Sync {
    /// A new phase has begun, e.g. `probe`, `scan`, `member 1`.
    fn phase(&self, name: &str);
    /// Bytes processed so far, out of an estimate when one is known.
    fn bytes(&self, done: u64, total: u64);
}

/// Progress and cancellation for one job.
#[derive(Default, Clone)]
pub struct EngineContext {
    /// Sink for phase and byte events; `None` reports nothing.
    pub progress: Option<Arc<dyn ProgressSink>>,
    /// Set by the caller to stop the job cooperatively.
    pub cancel: Option<Arc<AtomicBool>>,
}

impl std::fmt::Debug for EngineContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineContext")
            .field("progress", &self.progress.is_some())
            .field("cancel", &self.cancel.is_some())
            .finish()
    }
}

impl EngineContext {
    /// A context that reports nothing and cannot be cancelled.
    #[must_use]
    pub fn silent() -> Self {
        Self::default()
    }

    /// Report a phase.
    pub fn phase(&self, name: &str) {
        if let Some(sink) = &self.progress {
            sink.phase(name);
        }
    }

    /// Report absolute progress.
    pub fn bytes(&self, done: u64, total: u64) {
        if let Some(sink) = &self.progress {
            sink.bytes(done, total);
        }
    }

    /// Return [`Error::Cancelled`] when the caller asked to stop.
    ///
    /// # Errors
    /// Always returns an error when cancellation was requested.
    pub fn check_cancel(&self) -> Result<()> {
        match &self.cancel {
            Some(flag) if flag.load(Ordering::Relaxed) => Err(Error::cancelled()),
            _ => Ok(()),
        }
    }

    /// Wrap this context in a throttled reporter for a job with `total` units.
    ///
    /// # Errors
    /// Returns [`Error::Cancelled`] if cancellation was already requested.
    pub fn reporter(self, total: u64) -> Result<Reporter> {
        self.check_cancel()?;
        Ok(Reporter {
            context: self,
            total,
            last_report: 0,
            step: REPORT_STEP,
        })
    }
}

/// How many bytes may pass between two `bytes` events.
pub const REPORT_STEP: u64 = 64 * 1024 * 1024;

/// A throttled progress reporter plus the cancellation check.
pub struct Reporter {
    context: EngineContext,
    total: u64,
    last_report: u64,
    step: u64,
}

impl Reporter {
    /// The context, for callers that need it directly.
    #[must_use]
    pub fn context(&self) -> &EngineContext {
        &self.context
    }

    /// Report progress at `done` units and check for cancellation.
    ///
    /// # Errors
    /// Returns [`Error::Cancelled`] when the caller asked to stop.
    pub fn report(&mut self, done: u64) -> Result<()> {
        self.context.check_cancel()?;
        if done.saturating_sub(self.last_report) >= self.step {
            self.last_report = done;
            self.context.bytes(done, self.total);
        }
        Ok(())
    }

    /// Report a phase through the underlying context.
    pub fn phase(&self, name: &str) {
        self.context.phase(name);
    }

    /// Flush the final progress value, whatever the throttling said.
    pub fn finish(&mut self, done: u64) {
        self.last_report = done;
        self.context.bytes(done, self.total);
    }
}

#[cfg(test)]
mod tests {
    use super::{EngineContext, ProgressSink, Reporter};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Recorder {
        phases: Mutex<Vec<String>>,
        bytes: Mutex<Vec<(u64, u64)>>,
    }

    impl ProgressSink for Recorder {
        fn phase(&self, name: &str) {
            self.phases.lock().expect("lock").push(name.to_owned());
        }
        fn bytes(&self, done: u64, total: u64) {
            self.bytes.lock().expect("lock").push((done, total));
        }
    }

    #[test]
    fn reporting_is_throttled_but_the_final_value_always_arrives() {
        let recorder = Arc::new(Recorder::default());
        let context = EngineContext {
            progress: Some(Arc::clone(&recorder) as Arc<dyn ProgressSink>),
            cancel: None,
        };
        let mut reporter: Reporter = context.reporter(1_000).expect("reporter");
        reporter.phase("scan");
        for done in [1, 10, 100, 1_000, 700_000_000] {
            reporter.report(done).expect("report");
        }
        reporter.finish(2_000_000_000);

        let bytes = recorder.bytes.lock().expect("lock").clone();
        assert!(
            bytes.len() < 5,
            "throttled reporting keeps the event count low: {bytes:?}"
        );
        assert_eq!(*bytes.last().expect("last"), (2_000_000_000, 1_000));
        assert_eq!(recorder.phases.lock().expect("lock").as_slice(), ["scan"]);
    }

    #[test]
    fn cancellation_stops_the_job() {
        let flag = Arc::new(AtomicBool::new(false));
        let context = EngineContext {
            progress: None,
            cancel: Some(Arc::clone(&flag)),
        };
        assert!(context.check_cancel().is_ok());
        let mut reporter = context.reporter(10).expect("reporter");
        flag.store(true, Ordering::Relaxed);
        let error = reporter.report(1).expect_err("must stop");
        assert!(matches!(error, lr_core::Error::Cancelled), "{error}");
    }
}
