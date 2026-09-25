//! The daemon client the GUI uses (spec §I).
//!
//! The GUI talks to the daemon over the Unix socket and never opens a device
//! (spec §B), so every action here is an RPC. The channel is created per call
//! on a shared runtime: the GUI's calls are user-paced and few.

use std::path::Path;

use anyhow::Context;
use lr_proto::v1::linux_reflect_client::LinuxReflectClient;
use lr_proto::v1::{
    BackupSpec, ExportSpec, JobRef, Plan, Progress, Request, RestoreSpec, RestoreToken, SetRef,
    SourceRef, VerifySpec,
};

/// A connected daemon client for one socket.
pub struct Client {
    channel: tonic::transport::Channel,
}

/// The daemon explicitly reported a terminal job failure.
#[derive(Debug)]
pub struct JobFailure {
    /// Machine-readable daemon error code.
    pub code: String,
    /// Daemon explanation.
    pub message: String,
}

impl std::fmt::Display for JobFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for JobFailure {}

impl Client {
    /// Connect to the daemon socket.
    ///
    /// # Errors
    /// Returns an error when the socket does not answer.
    pub async fn connect(socket: &Path) -> anyhow::Result<Self> {
        let endpoint =
            tonic::transport::Endpoint::from_shared(format!("unix://{}", socket.display()))
                .context("daemon endpoint")?;
        let channel = endpoint
            .connect()
            .await
            .with_context(|| format!("connecting to the daemon on {}", socket.display()))?;
        Ok(Self { channel })
    }

    fn service(&self) -> LinuxReflectClient<tonic::transport::Channel> {
        LinuxReflectClient::new(self.channel.clone())
    }

    /// `GetVersion`, used as a liveness check.
    ///
    /// # Errors
    /// Propagates gRPC errors.
    pub async fn version(&self) -> anyhow::Result<String> {
        let version = self
            .service()
            .get_version(Request::default())
            .await?
            .into_inner();
        Ok(format!(
            "format {} ({})",
            version.format_major,
            if version.daemon.is_empty() {
                "daemon"
            } else {
                version.daemon.as_str()
            }
        ))
    }

    /// `ListDisks`.
    ///
    /// # Errors
    /// Propagates gRPC errors.
    pub async fn list_disks(&self) -> anyhow::Result<String> {
        let disks = self
            .service()
            .list_disks(Request::default())
            .await?
            .into_inner();
        Ok(disks.json)
    }

    /// Read the selected device's partition layout through the daemon.
    ///
    /// # Errors
    /// Propagates authorization, discovery and malformed-response errors.
    pub async fn disk_map(&self, source: &str) -> anyhow::Result<lr_core::SourceLayout> {
        let response = self
            .service()
            .disk_map(SourceRef {
                source: source.to_owned(),
            })
            .await?
            .into_inner();
        serde_json::from_str(&response.json).context("device layout JSON")
    }

    /// `ProbeSource`: what the daemon would do with a source.
    ///
    /// # Errors
    /// Propagates gRPC errors.
    pub async fn probe(&self, source: &str) -> anyhow::Result<Plan> {
        Ok(self
            .service()
            .probe_source(SourceRef {
                source: source.to_owned(),
            })
            .await?
            .into_inner())
    }

    /// `ListSets`/`ListChains`.
    ///
    /// # Errors
    /// Propagates gRPC errors.
    pub async fn list_sets(&self, dest: &str, set: &str) -> anyhow::Result<String> {
        let info = self
            .service()
            .list_chains(SetRef {
                dest: dest.to_owned(),
                set: set.to_owned(),
                ..SetRef::default()
            })
            .await?
            .into_inner();
        serde_json::to_string_pretty(&info).context("serializing the set info")
    }

    /// `ListSets` without a set name: every set at `dest` that holds an image.
    ///
    /// # Errors
    /// Propagates gRPC errors.
    pub async fn list_set_names(&self, dest: &str) -> anyhow::Result<Vec<String>> {
        Ok(self
            .service()
            .list_sets(SetRef {
                dest: dest.to_owned(),
                ..SetRef::default()
            })
            .await?
            .into_inner()
            .sets)
    }

    /// `VerifyImage` of a whole chain, reporting every progress step.
    ///
    /// # Errors
    /// Propagates gRPC errors and the job's failure code (for example the
    /// corrupted chunk it names).
    pub async fn verify(
        &self,
        image: &str,
        passphrase_file: &str,
        mut on_progress: impl FnMut(&Progress) + Send,
    ) -> anyhow::Result<String> {
        let mut stream = self
            .service()
            .verify_image(VerifySpec {
                image: image.to_owned(),
                chain: true,
                passphrase_file: passphrase_file.to_owned(),
                ..VerifySpec::default()
            })
            .await?
            .into_inner();
        let mut summary = None;
        while let Some(progress) = stream.message().await? {
            on_progress(&progress);
            if let Some(finished) = summary_of(&progress) {
                summary = Some(finished);
            }
            if let Some(lr_proto::v1::progress::Step::Failure(failure)) = &progress.step {
                return Err(JobFailure {
                    code: failure.code.clone(),
                    message: failure.message.clone(),
                }
                .into());
            }
        }
        require_finished(summary)
    }

    /// `ExportImage`; returns the export state as JSON.
    ///
    /// # Errors
    /// Propagates gRPC errors.
    pub async fn export(&self, image: &str, at: &str) -> anyhow::Result<String> {
        let progress = self
            .service()
            .export_image(ExportSpec {
                image: image.to_owned(),
                at: at.to_owned(),
                kind: "nbd".to_owned(),
                ..ExportSpec::default()
            })
            .await?
            .into_inner();
        Ok(summary_of(&progress).unwrap_or_default())
    }

    /// `CreateBackup`, reporting every progress step to `on_progress`.
    ///
    /// # Errors
    /// Propagates gRPC errors and the job's failure code.
    pub async fn create_backup(
        &self,
        spec: BackupSpec,
        mut on_progress: impl FnMut(&Progress) + Send,
    ) -> anyhow::Result<String> {
        let mut stream = self.service().create_backup(spec).await?.into_inner();
        let mut summary = None;
        while let Some(progress) = stream.message().await? {
            on_progress(&progress);
            if let Some(finished) = summary_of(&progress) {
                summary = Some(finished);
            }
            if let Some(lr_proto::v1::progress::Step::Failure(failure)) = &progress.step {
                return Err(JobFailure {
                    code: failure.code.clone(),
                    message: failure.message.clone(),
                }
                .into());
            }
        }
        require_finished(summary)
    }

    /// `PrepareRestore`.
    ///
    /// # Errors
    /// Propagates gRPC errors.
    pub async fn prepare_restore(
        &self,
        image: &str,
        target: &str,
        passphrase_file: &str,
    ) -> anyhow::Result<lr_proto::v1::RestorePlanInfo> {
        Ok(self
            .service()
            .prepare_restore(RestoreSpec {
                image: image.to_owned(),
                target: target.to_owned(),
                passphrase_file: passphrase_file.to_owned(),
                ..RestoreSpec::default()
            })
            .await?
            .into_inner())
    }

    /// `RestoreImage`, reporting every progress step.
    ///
    /// # Errors
    /// Propagates gRPC errors and the job's failure code.
    pub async fn restore(
        &self,
        token: &str,
        passphrase_file: &str,
        mut on_progress: impl FnMut(&Progress) + Send,
    ) -> anyhow::Result<String> {
        let mut stream = self
            .service()
            .restore_image(RestoreToken {
                token: token.to_owned(),
                confirm: true,
                passphrase_file: passphrase_file.to_owned(),
                ..RestoreToken::default()
            })
            .await?
            .into_inner();
        let mut summary = None;
        while let Some(progress) = stream.message().await? {
            on_progress(&progress);
            if let Some(finished) = summary_of(&progress) {
                summary = Some(finished);
            }
            if let Some(lr_proto::v1::progress::Step::Failure(failure)) = &progress.step {
                return Err(JobFailure {
                    code: failure.code.clone(),
                    message: failure.message.clone(),
                }
                .into());
            }
        }
        require_finished(summary)
    }

    /// `CancelJob`: ask the daemon to stop a running job.
    ///
    /// # Errors
    /// Propagates gRPC errors.
    pub async fn cancel(&self, job_id: &str) -> anyhow::Result<String> {
        let state = self
            .service()
            .cancel_job(JobRef {
                job_id: job_id.to_owned(),
            })
            .await?
            .into_inner();
        Ok(state.state)
    }

    /// `GetJob`: the state of a job the GUI started.
    ///
    /// # Errors
    /// Propagates gRPC errors.
    pub async fn job(&self, job_id: &str) -> anyhow::Result<String> {
        Ok(self.job_state(job_id).await?.state)
    }

    /// Query a job without starting or replaying it.
    ///
    /// # Errors
    /// Propagates connection, authorization and unknown-job errors.
    pub async fn job_state(&self, job_id: &str) -> anyhow::Result<lr_proto::v1::JobState> {
        let state = self
            .service()
            .get_job(JobRef {
                job_id: job_id.to_owned(),
            })
            .await?
            .into_inner();
        Ok(state)
    }
}

// EOF is not proof that a job completed: the daemon may have restarted or
// closed the stream before sending its terminal event.
fn require_finished(summary: Option<String>) -> anyhow::Result<String> {
    summary.context(
        "The job stream ended without a completion event; check the job state before retrying",
    )
}

/// The `Finished` summary of a progress message, when it is terminal.
#[must_use]
pub fn summary_of(progress: &Progress) -> Option<String> {
    match progress.step.as_ref()? {
        lr_proto::v1::progress::Step::Finished(finished) => Some(finished.summary_json.clone()),
        _ => None,
    }
}

/// A one-line description of a progress step, for the GUI's status line.
#[must_use]
pub fn progress_line(progress: &Progress) -> Option<(String, u64, u64)> {
    use lr_proto::v1::progress::Step;
    match progress.step.as_ref()? {
        Step::Started(_) => Some(("started".to_owned(), 0, 0)),
        Step::Phase(phase) => Some((phase.name.clone(), 0, 0)),
        Step::Bytes(bytes) => Some(("copying".to_owned(), bytes.done, bytes.total)),
        Step::Finished(_) => Some(("finished".to_owned(), 1, 1)),
        Step::Failure(failure) => Some((format!("failed: {}", failure.code), 0, 0)),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn stream_eof_requires_a_terminal_event() {
        assert!(super::require_finished(None).is_err());
        assert_eq!(super::require_finished(Some(String::new())).unwrap(), "");
        assert_eq!(super::require_finished(Some("{}".into())).unwrap(), "{}");
    }
}
