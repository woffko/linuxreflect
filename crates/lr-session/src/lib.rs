//! Desktop notifications for daemon job events (spec §K S14).
//!
//! A root daemon cannot post notifications into a user's session (spec risk
//! R0-19), so this helper runs as a user service, subscribes to the daemon's
//! `WatchEvents` stream and forwards each job event to
//! `org.freedesktop.Notifications` on the *session* bus. The notification
//! payload is built by a pure function so it can be checked without a desktop.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use lr_core::{Error, Result};
use lr_proto::v1::linux_reflect_client::LinuxReflectClient;
use lr_proto::v1::progress::Step;
use lr_proto::v1::{Event, Request};

/// The application name notifications appear under.
pub const APP_NAME: &str = "LinuxReflect";

/// Notification urgency (`org.freedesktop.Notifications` hint).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Urgency {
    /// Routine progress.
    Low,
    /// A finished job, or one that needs attention.
    Normal,
    /// A failed job.
    Critical,
}

impl Urgency {
    /// The hint value the spec's notification service expects.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Low => 0,
            Self::Normal => 1,
            Self::Critical => 2,
        }
    }
}

/// One notification to post.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    /// Short summary line.
    pub summary: String,
    /// Body text.
    pub body: String,
    /// Urgency hint.
    pub urgency: Urgency,
}

impl Notification {
    /// Build the notification for a daemon event, if it deserves one.
    ///
    /// Progress chatter (`phase`, `bytes`) is deliberately silent: a nightly
    /// job would otherwise post hundreds of notifications.
    #[must_use]
    pub fn for_event(event: &Event) -> Option<Self> {
        let job = if event.message.is_empty() {
            "job"
        } else {
            event.message.as_str()
        };
        match event.kind.as_str() {
            "started" => Some(Self {
                summary: "Job started".to_owned(),
                body: job.to_owned(),
                urgency: Urgency::Low,
            }),
            "finished" => {
                let summary_json = match event.progress.as_ref()?.step.as_ref()? {
                    Step::Finished(finished) => finished.summary_json.as_str(),
                    _ => return None,
                };
                Some(Self {
                    summary: "Job finished".to_owned(),
                    body: summarize(job, summary_json),
                    urgency: Urgency::Normal,
                })
            }
            "failed" => {
                let (code, message) = match event.progress.as_ref()?.step.as_ref()? {
                    Step::Failure(failure) => (failure.code.as_str(), failure.message.as_str()),
                    _ => return None,
                };
                let cancelled = code == "E_CANCELLED";
                Some(Self {
                    summary: if cancelled {
                        "Job cancelled"
                    } else {
                        "Job failed"
                    }
                    .to_owned(),
                    body: format!("{job}: {code}: {message}"),
                    urgency: if cancelled {
                        Urgency::Normal
                    } else {
                        Urgency::Critical
                    },
                })
            }
            // Cancellation arrives as a failure with E_CANCELLED.
            _ => None,
        }
    }
}

fn summarize(job: &str, summary_json: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(summary_json) {
        Ok(value) => {
            let image = value
                .get("image_uri")
                .or_else(|| value.get("image_path"))
                .and_then(|value| value.as_str());
            if let Some(image) = image {
                format!("{job}: image {image}")
            } else if let Some(target) = value.get("target").and_then(|value| value.as_str()) {
                format!("{job}: destination {target}")
            } else {
                format!("{job} finished")
            }
        }
        Err(_) => format!("{job} finished"),
    }
}

/// Post one notification on the session bus.
///
/// # Errors
/// Returns [`Error::Unsupported`] when the session bus or the notification
/// service is unavailable (a headless session, for example).
pub async fn notify(connection: &zbus::Connection, notification: &Notification) -> Result<u32> {
    let proxy = zbus::Proxy::new(
        connection,
        "org.freedesktop.Notifications",
        "/org/freedesktop/Notifications",
        "org.freedesktop.Notifications",
    )
    .await
    .map_err(|error| {
        Error::unsupported(format!(
            "org.freedesktop.Notifications is unavailable: {error}"
        ))
    })?;
    let mut hints: HashMap<String, zbus::zvariant::Value<'_>> = HashMap::new();
    hints.insert(
        "urgency".to_owned(),
        zbus::zvariant::Value::U8(notification.urgency.as_byte()),
    );
    let id: u32 = proxy
        .call(
            "Notify",
            &(
                APP_NAME,
                0u32,
                "",
                notification.summary.as_str(),
                notification.body.as_str(),
                Vec::<String>::new(),
                hints,
                -1i32,
            ),
        )
        .await
        .map_err(|error| Error::unsupported(format!("Notify failed: {error}")))?;
    Ok(id)
}

/// Connect to a session bus.
///
/// # Errors
/// Returns [`Error::Unsupported`] when no session bus is reachable.
pub async fn session_bus(address: Option<&str>) -> Result<zbus::Connection> {
    match address {
        Some(address) => zbus::connection::Builder::address(address)
            .map_err(|error| Error::unsupported(format!("session bus {address}: {error}")))?
            .build()
            .await
            .map_err(|error| Error::unsupported(format!("session bus {address}: {error}"))),
        None => zbus::Connection::session()
            .await
            .map_err(|error| Error::unsupported(format!("no session bus: {error}"))),
    }
}

/// Where the daemon listens by default.
#[must_use]
pub fn default_socket() -> PathBuf {
    PathBuf::from("/run/linuxreflect/daemon.sock")
}

/// Subscribe to `WatchEvents` and post a notification per event.
///
/// Runs until the stream ends or the process is stopped. `events_before_exit`
/// limits how many events are handled, which keeps a test bounded.
///
/// # Errors
/// Returns [`Error::Unsupported`] when the daemon or the session bus cannot be
/// reached, and propagates stream errors.
pub async fn run(
    socket: &Path,
    bus_address: Option<&str>,
    events_before_exit: Option<usize>,
) -> Result<()> {
    let endpoint = tonic::transport::Endpoint::from_shared(format!("unix://{}", socket.display()))
        .map_err(|error| Error::unsupported(format!("daemon endpoint: {error}")))?;
    let channel = endpoint
        .connect()
        .await
        .map_err(|error| Error::unsupported(format!("daemon at {}: {error}", socket.display())))?;
    let connection = session_bus(bus_address).await?;
    let mut client = LinuxReflectClient::new(channel);
    let mut stream = client
        .watch_events(Request::default())
        .await
        .map_err(|error| Error::unsupported(format!("watch_events: {error}")))?
        .into_inner();
    let mut handled = 0usize;
    loop {
        match stream.message().await {
            Ok(Some(event)) => {
                if let Some(notification) = Notification::for_event(&event) {
                    tracing::info!(
                        summary = %notification.summary,
                        "notifying the session"
                    );
                    notify(&connection, &notification).await?;
                    handled += 1;
                    if events_before_exit.is_some_and(|limit| handled >= limit) {
                        return Ok(());
                    }
                }
            }
            Ok(None) => return Ok(()),
            Err(status) => {
                return Err(Error::unsupported(format!("event stream: {status}")));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Notification, Urgency};
    use lr_proto::v1::progress::Step;
    use lr_proto::v1::{Event, Failure, Finished, Progress, Started};

    fn event(kind: &str, step: Option<Step>) -> Event {
        Event {
            event_id: 1,
            kind: kind.to_owned(),
            message: "backup-1".to_owned(),
            progress: step.map(|step| Progress { step: Some(step) }),
        }
    }

    #[test]
    fn a_started_job_notifies_quietly() {
        let notification = Notification::for_event(&event(
            "started",
            Some(Step::Started(Started {
                job_id: "backup-1".to_owned(),
            })),
        ))
        .expect("notification");
        assert_eq!(notification.summary, "Job started");
        assert_eq!(notification.body, "backup-1");
        assert_eq!(notification.urgency, Urgency::Low);
    }

    #[test]
    fn progress_chatter_is_silent() {
        assert!(Notification::for_event(&event("phase", None)).is_none());
        assert!(Notification::for_event(&event("bytes", None)).is_none());
    }

    #[test]
    fn a_finished_job_names_the_image() {
        let summary = serde_json::json!({
            "mode": "block",
            "image_uri": "/backups/laptop-root/chain/000-full.lrimg"
        })
        .to_string();
        let notification = Notification::for_event(&event(
            "finished",
            Some(Step::Finished(Finished {
                summary_json: summary,
            })),
        ))
        .expect("notification");
        assert_eq!(notification.summary, "Job finished");
        assert!(
            notification.body.contains("000-full.lrimg"),
            "{}",
            notification.body
        );
        assert_eq!(notification.urgency, Urgency::Normal);
    }

    #[test]
    fn a_failed_job_is_critical_and_keeps_the_error_code() {
        let notification = Notification::for_event(&event(
            "failed",
            Some(Step::Failure(Failure {
                code: "E_BAD_SECTOR".to_owned(),
                message: "sector 4096 is unreadable".to_owned(),
            })),
        ))
        .expect("notification");
        assert_eq!(notification.summary, "Job failed");
        assert!(notification.body.contains("E_BAD_SECTOR"));
        assert_eq!(notification.urgency, Urgency::Critical);
        assert_eq!(notification.urgency.as_byte(), 2);
    }

    #[test]
    fn restore_completion_does_not_invent_a_backup_image() {
        let notification = Notification::for_event(&event(
            "finished",
            Some(Step::Finished(Finished {
                summary_json: r#"{"target":"/restore destination","files":2}"#.to_owned(),
            })),
        ))
        .expect("notification");
        assert_eq!(notification.summary, "Job finished");
        assert_eq!(
            notification.body,
            "backup-1: destination /restore destination"
        );
    }

    #[test]
    fn confirmed_cancellation_is_not_a_critical_failure() {
        let notification = Notification::for_event(&event(
            "failed",
            Some(Step::Failure(Failure {
                code: "E_CANCELLED".to_owned(),
                message: "cancelled by user".to_owned(),
            })),
        ))
        .expect("notification");
        assert_eq!(notification.summary, "Job cancelled");
        assert_eq!(notification.urgency, Urgency::Normal);
        assert!(notification.body.contains("E_CANCELLED"));
    }

    #[test]
    fn an_event_without_a_progress_step_is_ignored() {
        assert!(Notification::for_event(&event("finished", None)).is_none());
        assert!(Notification::for_event(&event("failed", None)).is_none());
        assert!(Notification::for_event(&Event::default()).is_none());
    }
}
