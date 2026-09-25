//! The gRPC client mode (spec §J.1, §I).
//!
//! When a daemon socket is reachable the CLI asks the daemon instead of
//! running the engine itself, so privileged work is authorized by polkit. When
//! no socket is there (rescue media, a plain shell) every command falls back to
//! the in-process path, which is the same engine code.
//!
//! The client owns its runtime: a tonic `Channel` keeps a background task on
//! the runtime it was created on, so dropping that runtime would silently kill
//! the connection and later calls would fail with a transport error.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use lr_proto::v1::linux_reflect_client::LinuxReflectClient;
use lr_proto::v1::{
    BackupSpec, Request, RestoreSpec, RestoreToken, SetRef, SourceRef, VerifySpec, progress::Step,
};
use tokio::runtime::Runtime;
use tonic::transport::{Channel, Endpoint};

/// A boxed future returned by an RPC method.
// The progress callbacks are `FnMut` and need not be `Send`: `block_on`
// runs the future on the calling thread.
type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// Where the daemon socket lives by default.
pub(crate) const DEFAULT_SOCKET: &str = "/run/linuxreflect/daemon.sock";

/// The socket to use: the explicit path or the default one.
pub(crate) fn socket_path(explicit: Option<&Path>) -> PathBuf {
    explicit.map_or_else(|| PathBuf::from(DEFAULT_SOCKET), Path::to_path_buf)
}

/// `true` when something accepts connections on `path`.
pub(crate) fn daemon_available(path: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(path).is_ok()
}

/// A connected client.
pub(crate) struct Client {
    inner: LinuxReflectClient<Channel>,
    runtime: Arc<Runtime>,
}

impl Client {
    /// Connect to `path`.
    ///
    /// # Errors
    /// Propagates endpoint and connection errors.
    pub(crate) fn connect(path: &Path) -> anyhow::Result<Self> {
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .context("client runtime")?,
        );
        let endpoint = Endpoint::try_from(format!("unix://{}", path.display()))
            .context("the socket path is not a valid endpoint")?
            .timeout(Duration::from_secs(600))
            .connect_timeout(Duration::from_secs(5));
        let channel = runtime
            .block_on(endpoint.connect())
            .with_context(|| format!("connecting to the daemon at {}", path.display()))?;
        Ok(Self {
            inner: LinuxReflectClient::new(channel),
            runtime,
        })
    }

    /// Run one RPC on the client's runtime.
    fn call<T>(
        &mut self,
        operation: impl FnOnce(&mut LinuxReflectClient<Channel>) -> BoxFuture<'_, anyhow::Result<T>>,
    ) -> anyhow::Result<T> {
        let Self { inner, runtime } = self;
        runtime.block_on(operation(inner))
    }

    /// `GetVersion`, unauthenticated.
    ///
    /// # Errors
    /// Propagates gRPC errors.
    pub(crate) fn version(&mut self) -> anyhow::Result<lr_proto::v1::Version> {
        self.call(|inner| {
            Box::pin(async move {
                inner
                    .get_version(Request::default())
                    .await
                    .map(|response| response.into_inner())
                    .map_err(grpc_error)
            })
        })
    }

    /// `ListDisks`, returning the JSON body.
    ///
    /// # Errors
    /// Propagates gRPC errors.
    pub(crate) fn list_disks(&mut self) -> anyhow::Result<String> {
        self.call(|inner| {
            Box::pin(async move {
                inner
                    .list_disks(Request::default())
                    .await
                    .map(|response| response.into_inner().json)
                    .map_err(grpc_error)
            })
        })
    }

    /// `DiskMap`, returning the JSON body.
    ///
    /// # Errors
    /// Propagates gRPC errors.
    pub(crate) fn disk_map(&mut self, device: &Path) -> anyhow::Result<String> {
        let source = device.display().to_string();
        self.call(move |inner| {
            Box::pin(async move {
                inner
                    .disk_map(SourceRef { source })
                    .await
                    .map(|response| response.into_inner().json)
                    .map_err(grpc_error)
            })
        })
    }

    /// `ProbeSource`.
    ///
    /// # Errors
    /// Propagates gRPC errors.
    pub(crate) fn probe(&mut self, source: &Path) -> anyhow::Result<lr_proto::v1::Plan> {
        let source = source.display().to_string();
        self.call(move |inner| {
            Box::pin(async move {
                inner
                    .probe_source(SourceRef { source })
                    .await
                    .map(|response| response.into_inner())
                    .map_err(grpc_error)
            })
        })
    }

    /// `ListSets`.
    ///
    /// # Errors
    /// Propagates gRPC errors.
    pub(crate) fn list_sets(
        &mut self,
        dest: &str,
        set: &str,
    ) -> anyhow::Result<lr_proto::v1::SetInfo> {
        let request = SetRef {
            dest: dest.to_owned(),
            set: set.to_owned(),
            ..SetRef::default()
        };
        self.call(move |inner| {
            Box::pin(async move {
                inner
                    .list_sets(request)
                    .await
                    .map(|response| response.into_inner())
                    .map_err(grpc_error)
            })
        })
    }

    /// `RebuildCatalog`.
    ///
    /// # Errors
    /// Propagates gRPC errors.
    pub(crate) fn rebuild_catalog(
        &mut self,
        dest: &str,
        set: &str,
    ) -> anyhow::Result<lr_proto::v1::Progress> {
        let request = SetRef {
            dest: dest.to_owned(),
            set: set.to_owned(),
            ..SetRef::default()
        };
        self.call(move |inner| {
            Box::pin(async move {
                inner
                    .rebuild_catalog(request)
                    .await
                    .map(|response| response.into_inner())
                    .map_err(grpc_error)
            })
        })
    }

    /// `ApplyRetention` (Slice S14).
    ///
    /// # Errors
    /// Propagates gRPC errors.
    pub(crate) fn apply_retention(
        &mut self,
        dest: &str,
        set: &str,
        keep_chains: u32,
        dry_run: bool,
    ) -> anyhow::Result<String> {
        let request = lr_proto::v1::RetentionSpec {
            dest: dest.to_owned(),
            set: set.to_owned(),
            keep_chains,
            dry_run,
        };
        let progress = self.call(move |inner| {
            Box::pin(async move {
                inner
                    .apply_retention(request)
                    .await
                    .map(|response| response.into_inner())
                    .map_err(grpc_error)
            })
        })?;
        finished_summary(progress)
    }

    /// `SetSchedule` (Slice S14).
    ///
    /// # Errors
    /// Propagates gRPC errors.
    pub(crate) fn set_schedule(
        &mut self,
        config: &str,
        systemd_dir: &str,
        dry_run: bool,
    ) -> anyhow::Result<String> {
        let request = lr_proto::v1::ScheduleSpec {
            config: config.to_owned(),
            systemd_dir: systemd_dir.to_owned(),
            dry_run,
            remove: String::new(),
        };
        let progress = self.call(move |inner| {
            Box::pin(async move {
                inner
                    .set_schedule(request)
                    .await
                    .map(|response| response.into_inner())
                    .map_err(grpc_error)
            })
        })?;
        finished_summary(progress)
    }

    /// `GetSchedule` (Slice S14).
    ///
    /// # Errors
    /// Propagates gRPC errors.
    pub(crate) fn get_schedule(&mut self, config: &str) -> anyhow::Result<String> {
        let request = lr_proto::v1::ScheduleSpec {
            config: config.to_owned(),
            ..lr_proto::v1::ScheduleSpec::default()
        };
        let progress = self.call(move |inner| {
            Box::pin(async move {
                inner
                    .get_schedule(request)
                    .await
                    .map(|response| response.into_inner())
                    .map_err(grpc_error)
            })
        })?;
        finished_summary(progress)
    }

    /// `SetSchedule` with a job to remove (Slice S14).
    ///
    /// # Errors
    /// Propagates gRPC errors.
    pub(crate) fn remove_schedule(
        &mut self,
        job: &str,
        systemd_dir: &str,
    ) -> anyhow::Result<String> {
        let request = lr_proto::v1::ScheduleSpec {
            config: String::new(),
            systemd_dir: systemd_dir.to_owned(),
            dry_run: false,
            remove: job.to_owned(),
        };
        let progress = self.call(move |inner| {
            Box::pin(async move {
                inner
                    .set_schedule(request)
                    .await
                    .map(|response| response.into_inner())
                    .map_err(grpc_error)
            })
        })?;
        finished_summary(progress)
    }

    /// `ExportImage` (Slice S13).
    ///
    /// # Errors
    /// Propagates gRPC errors.
    pub(crate) fn export_image(
        &mut self,
        image: &str,
        at: &str,
        kind: &str,
    ) -> anyhow::Result<String> {
        let request = lr_proto::v1::ExportSpec {
            image: image.to_owned(),
            at: at.to_owned(),
            kind: kind.to_owned(),
            ..lr_proto::v1::ExportSpec::default()
        };
        let progress = self.call(move |inner| {
            Box::pin(async move {
                inner
                    .export_image(request)
                    .await
                    .map(|response| response.into_inner())
                    .map_err(grpc_error)
            })
        })?;
        finished_summary(progress)
    }

    /// `UnexportImage` (Slice S13).
    ///
    /// # Errors
    /// Propagates gRPC errors.
    pub(crate) fn unexport_image(&mut self, at: &str) -> anyhow::Result<String> {
        let request = lr_proto::v1::UnexportSpec { at: at.to_owned() };
        let progress = self.call(move |inner| {
            Box::pin(async move {
                inner
                    .unexport_image(request)
                    .await
                    .map(|response| response.into_inner())
                    .map_err(grpc_error)
            })
        })?;
        finished_summary(progress)
    }

    /// `PrepareRestore`.
    ///
    /// # Errors
    /// Propagates gRPC errors.
    pub(crate) fn prepare_restore(
        &mut self,
        spec: RestoreSpec,
    ) -> anyhow::Result<lr_proto::v1::RestorePlanInfo> {
        self.call(move |inner| {
            Box::pin(async move {
                inner
                    .prepare_restore(spec)
                    .await
                    .map(|response| response.into_inner())
                    .map_err(grpc_error)
            })
        })
    }

    /// `GetJob`.
    ///
    /// # Errors
    /// Propagates gRPC errors.
    pub(crate) fn get_job(&mut self, job_id: &str) -> anyhow::Result<lr_proto::v1::JobState> {
        let request = lr_proto::v1::JobRef {
            job_id: job_id.to_owned(),
        };
        self.call(move |inner| {
            Box::pin(async move {
                inner
                    .get_job(request)
                    .await
                    .map(|response| response.into_inner())
                    .map_err(grpc_error)
            })
        })
    }

    /// `CancelJob`.
    ///
    /// # Errors
    /// Propagates gRPC errors.
    pub(crate) fn cancel_job(&mut self, job_id: &str) -> anyhow::Result<lr_proto::v1::JobState> {
        let request = lr_proto::v1::JobRef {
            job_id: job_id.to_owned(),
        };
        self.call(move |inner| {
            Box::pin(async move {
                inner
                    .cancel_job(request)
                    .await
                    .map(|response| response.into_inner())
                    .map_err(grpc_error)
            })
        })
    }

    /// `CreateBackup`, streaming progress through `on_progress`.
    ///
    /// # Errors
    /// Propagates gRPC errors and the daemon's failure step.
    pub(crate) fn create_backup(
        &mut self,
        spec: BackupSpec,
        mut on_progress: impl FnMut(&lr_proto::v1::Progress) + 'static,
    ) -> anyhow::Result<String> {
        self.call(move |inner| {
            Box::pin(async move {
                let mut stream = inner
                    .create_backup(spec)
                    .await
                    .map_err(grpc_error)?
                    .into_inner();
                read_stream(&mut stream, &mut on_progress).await
            })
        })
    }

    /// `VerifyImage`, streaming progress.
    ///
    /// # Errors
    /// Propagates gRPC errors and the daemon's failure step.
    pub(crate) fn verify_image(
        &mut self,
        spec: VerifySpec,
        mut on_progress: impl FnMut(&lr_proto::v1::Progress) + 'static,
    ) -> anyhow::Result<String> {
        self.call(move |inner| {
            Box::pin(async move {
                let mut stream = inner
                    .verify_image(spec)
                    .await
                    .map_err(grpc_error)?
                    .into_inner();
                read_stream(&mut stream, &mut on_progress).await
            })
        })
    }

    /// `RestoreImage`, streaming progress.
    ///
    /// # Errors
    /// Propagates gRPC errors and the daemon's failure step.
    pub(crate) fn restore_image(
        &mut self,
        spec: RestoreToken,
        mut on_progress: impl FnMut(&lr_proto::v1::Progress) + 'static,
    ) -> anyhow::Result<String> {
        self.call(move |inner| {
            Box::pin(async move {
                let mut stream = inner
                    .restore_image(spec)
                    .await
                    .map_err(grpc_error)?
                    .into_inner();
                read_stream(&mut stream, &mut on_progress).await
            })
        })
    }
}

/// Read a progress stream to its `Finished` step, or fail on `Failure`.
async fn read_stream(
    stream: &mut tonic::Streaming<lr_proto::v1::Progress>,
    on_progress: &mut impl FnMut(&lr_proto::v1::Progress),
) -> anyhow::Result<String> {
    let mut summary = None;
    while let Some(progress) = stream.message().await.map_err(grpc_error)? {
        on_progress(&progress);
        match &progress.step {
            Some(Step::Finished(finished)) => summary = Some(finished.summary_json.clone()),
            Some(Step::Failure(failure)) => {
                anyhow::bail!("{}: {}", failure.code, failure.message);
            }
            _ => {}
        }
    }
    summary.context("the daemon ended the job without a result")
}

/// Turn a gRPC failure into an error the CLI prints with its code.
pub(crate) fn grpc_error(status: tonic::Status) -> anyhow::Error {
    anyhow::anyhow!("daemon refused: {}", status.message())
}

/// A one-line rendering of a progress step, for the terminal.
/// The `Finished` summary of a one-shot call, as JSON.
///
/// # Errors
/// Returns an error when the daemon answered with a failure step.
fn finished_summary(progress: lr_proto::v1::Progress) -> anyhow::Result<String> {
    match progress.step {
        Some(lr_proto::v1::progress::Step::Finished(finished)) => Ok(finished.summary_json),
        Some(lr_proto::v1::progress::Step::Failure(failure)) => {
            anyhow::bail!("{}: {}", failure.code, failure.message)
        }
        other => anyhow::bail!("the daemon did not finish the request: {other:?}"),
    }
}

pub(crate) fn progress_line(progress: &lr_proto::v1::Progress) -> Option<String> {
    match &progress.step {
        Some(Step::Started(started)) => Some(format!("job:      {}", started.job_id)),
        Some(Step::Phase(phase)) => Some(format!("phase:    {}", phase.name)),
        Some(Step::Bytes(bytes)) => {
            let percent = if bytes.total > 0 {
                format!(" ({:.0}%)", bytes.done as f64 * 100.0 / bytes.total as f64)
            } else {
                String::new()
            };
            Some(format!(
                "progress: {} bytes{percent}",
                lr_engine::inspect::human_size(bytes.done)
            ))
        }
        Some(Step::Finished(_)) | Some(Step::Failure(_)) | None => None,
    }
}
