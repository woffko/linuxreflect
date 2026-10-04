//! The gRPC service (spec §I).
//!
//! Every method authorizes the peer first, then runs the synchronous engine in
//! a blocking task while progress flows back over the job event bus. Methods
//! that belong to later slices answer `UNIMPLEMENTED` with their slice number
//! so the schema stays stable.

#[cfg(test)]
mod history_authorization_tests {
    use std::future::Future;
    use std::pin::Pin;

    use super::*;
    use crate::auth::AuthBackend;

    struct ReadOnly;
    impl AuthBackend for ReadOnly {
        fn check<'a>(
            &'a self,
            _peer: &'a PeerIdentity,
            action: Action,
        ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
            Box::pin(async move {
                if action == Action::DiskRead {
                    Ok(())
                } else {
                    Err(Error::denied(action.id(), "administrator required"))
                }
            })
        }
    }

    fn request<T>(uid: u32, body: T) -> GrpcRequest<T> {
        let mut request = GrpcRequest::new(body);
        request
            .extensions_mut()
            .insert(Peer(Arc::new(PeerIdentity::for_uid(uid))));
        request
    }

    #[tokio::test]
    async fn history_admin_authorization_precedes_policy_and_retained_lookup_is_owner_scoped() {
        let jobs = Arc::new(Jobs::new());
        let service = DaemonService::new(Arc::new(ReadOnly), Arc::clone(&jobs), true);
        let denied = service
            .list_verification_history(request(1000, Request::default()))
            .await
            .expect_err("disk-read permission cannot inspect global receipts");
        assert_eq!(
            denied.code(),
            tonic::Code::PermissionDenied,
            "authorization precedes disabled policy disclosure"
        );

        let _ = jobs
            .register_for("typed-result", "set", 1000)
            .expect("register");
        let _ = jobs
            .finish("typed-result", Ok("{}".to_owned()))
            .expect("legacy result");
        assert_eq!(
            service
                .get_verification_result(request(
                    2000,
                    JobRef {
                        job_id: "typed-result".to_owned()
                    }
                ))
                .await
                .expect_err("another owner")
                .code(),
            tonic::Code::PermissionDenied
        );
        for uid in [1000, 0] {
            assert_eq!(
                service
                    .get_verification_result(request(
                        uid,
                        JobRef {
                            job_id: "typed-result".to_owned()
                        }
                    ))
                    .await
                    .expect_err("legacy result never masquerades as captured")
                    .code(),
                tonic::Code::FailedPrecondition
            );
        }
        let _ = jobs
            .register_for("typed-result", "set", 2000)
            .expect("reuse");
        assert!(
            jobs.snapshot_owned("typed-result", 1000).is_err(),
            "owner and retained result are read under one lock after reuse"
        );
    }

    #[test]
    fn nonqueued_operation_admission_refuses_and_releases_exactly_one_slot() {
        let slots = Arc::new(Slots::new(1));
        let held = slots.try_acquire().expect("one slot");
        assert!(
            slots.try_acquire().is_none(),
            "busy does not queue or spawn a worker"
        );
        drop(held);
        assert!(slots.try_acquire().is_some());
    }
}

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use lr_core::{Error, ImageKind, Result};
use lr_engine::progress::EngineContext;
use lr_export::BlockBackend;
use lr_proto::v1::linux_reflect_server::LinuxReflect;
use lr_proto::v1::{
    BackupSpec, DiskList, Event, JobRef, JobState, Plan, Progress, Request, RestorePlanInfo,
    RestoreSpec, RestoreToken, SetInfo, SetRef, SourceRef, VerifyOutcome, VerifySpec, Version,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request as GrpcRequest, Response, Status};

use crate::auth::{Action, PeerIdentity, SharedAuth};
use crate::client_files::{self, ClientFiles};
use crate::jobs::{JobEvent, JobState as JobStateInner, Jobs};
use crate::status;
use crate::verification::{self, CapturedVerificationResult};
use crate::verification_policy::DaemonVerificationPolicy;
use lr_export::session::ExportState;

/// Identity attached to a request by [`PeerInterceptor`].
#[derive(Clone)]
pub struct Peer(pub Arc<PeerIdentity>);

/// Reads `SO_PEERCRED` from the socket and pins the peer before any handler
/// runs; a request without credentials is rejected here, not in the handlers.
#[derive(Clone)]
pub struct PeerInterceptor;

impl tonic::service::Interceptor for PeerInterceptor {
    fn call(
        &mut self,
        mut request: GrpcRequest<()>,
    ) -> std::result::Result<GrpcRequest<()>, Status> {
        let credentials = request
            .extensions()
            .get::<tonic::transport::server::UdsConnectInfo>()
            .and_then(|info| info.peer_cred.as_ref());
        let identity = PeerIdentity::capture(credentials).map_err(status::status_of)?;
        request.extensions_mut().insert(Peer(Arc::new(identity)));
        Ok(request)
    }
}

/// The daemon's service implementation.
pub struct DaemonService {
    auth: SharedAuth,
    jobs: Arc<Jobs>,
    dev_mode: bool,
    /// Live exports the daemon serves itself, by mount point.
    exports: Arc<Mutex<HashMap<PathBuf, Arc<AtomicBool>>>>,
    /// Bounds concurrent verifications (A5).
    verifications: Arc<Slots>,
    history: Option<Arc<HistoryRuntime>>,
}

struct HistoryRuntime {
    policy: DaemonVerificationPolicy,
    operations: Arc<Slots>,
    results: Arc<verification::ResultBudget>,
}

/// How many verifications may read at once; further ones wait.
const MAX_VERIFICATIONS: usize = 4;

/// A counting semaphore for blocking job threads.
struct Slots {
    free: std::sync::Mutex<usize>,
    released: std::sync::Condvar,
}

impl Slots {
    fn new(count: usize) -> Self {
        Self {
            free: std::sync::Mutex::new(count),
            released: std::sync::Condvar::new(),
        }
    }

    /// Wait for a slot; it is returned when the guard drops.
    fn acquire(self: &Arc<Self>) -> SlotGuard {
        let mut free = self
            .free
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while *free == 0 {
            free = self
                .released
                .wait(free)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        *free -= 1;
        SlotGuard(Arc::clone(self))
    }

    fn try_acquire(self: &Arc<Self>) -> Option<SlotGuard> {
        let mut free = self
            .free
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *free == 0 {
            return None;
        }
        *free -= 1;
        Some(SlotGuard(Arc::clone(self)))
    }
}

/// Returns a verification slot on drop.
struct SlotGuard(Arc<Slots>);

impl Drop for SlotGuard {
    fn drop(&mut self) {
        let mut free = self
            .0
            .free
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *free += 1;
        self.0.released.notify_one();
    }
}

impl DaemonService {
    /// Build the service.
    #[must_use]
    pub fn new(auth: SharedAuth, jobs: Arc<Jobs>, dev_mode: bool) -> Self {
        Self {
            auth,
            jobs,
            dev_mode,
            exports: Arc::new(Mutex::new(HashMap::new())),
            verifications: Arc::new(Slots::new(MAX_VERIFICATIONS)),
            history: None,
        }
    }

    /// Enable captured verification with an already validated startup policy.
    /// The default service has no history policy and creates no history paths.
    #[must_use]
    pub fn with_verification_policy(mut self, policy: DaemonVerificationPolicy) -> Self {
        let operations = Arc::new(Slots::new(policy.max_concurrent_operations()));
        let results = Arc::new(verification::ResultBudget::new(
            policy.max_retained_results(),
            policy.max_retained_result_bytes(),
        ));
        self.history = Some(Arc::new(HistoryRuntime {
            policy,
            operations,
            results,
        }));
        self
    }

    /// Start serving an image read-only and mount it (spec §K S13).
    fn export_with(
        exports: &Arc<Mutex<HashMap<PathBuf, Arc<AtomicBool>>>>,
        spec: &lr_proto::v1::ExportSpec,
    ) -> Result<ExportState> {
        let destination_options = lr_store::DestinationOptions {
            set_name: String::new(),
            identity: (!spec.identity.is_empty()).then(|| PathBuf::from(&spec.identity)),
            known_hosts: (!spec.known_hosts.is_empty()).then(|| PathBuf::from(&spec.known_hosts)),
            insecure_ignore_host_key: spec.insecure_ignore_host_key,
        };
        let encryption = lr_engine::options::restore_encryption(
            (!spec.passphrase_file.is_empty())
                .then(|| PathBuf::from(&spec.passphrase_file))
                .as_deref(),
        )?;
        let (location, options, images) =
            lr_export::session::resolve_image(&spec.image, &destination_options)?;
        let backend =
            lr_export::ImageBackend::open(&location.dest, &images, &options, &encryption)?;
        if backend.size_bytes() == 0 {
            return Err(Error::unsupported("the image has no content to export"));
        }
        let mountpoint = PathBuf::from(&spec.at);
        if !mountpoint.is_dir() {
            return Err(Error::unsupported(format!(
                "{} is not a directory",
                mountpoint.display()
            )));
        }
        if std::fs::read_dir(&mountpoint)
            .map_err(Error::Io)?
            .next()
            .is_some()
        {
            return Err(Error::unsupported(format!(
                "{} is not empty",
                mountpoint.display()
            )));
        }
        let (nbd, mount) = lr_export::session::available();
        if !nbd || !mount {
            return Err(Error::unsupported(
                "NBD export needs the nbd module, `nbd-client` and `mount`",
            ));
        }
        let state_dir = PathBuf::from(lr_export::session::STATE_DIR);
        std::fs::create_dir_all(&state_dir).map_err(Error::Io)?;
        let socket = state_dir.join(format!("daemon-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&socket);
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = Arc::clone(&stop);
        let fs_type = backend.fs_type().to_owned();
        let server_socket = socket.clone();
        std::thread::spawn(move || {
            if let Err(error) = lr_export::nbd::serve_unix(
                &server_socket,
                Arc::new(backend),
                lr_export::ExportConfig::default(),
                server_stop,
            ) {
                tracing::warn!(%error, "the NBD export ended with an error");
            }
        });

        // Wait for the socket, then attach and mount.
        let mut attached = None;
        for _ in 0..100 {
            if socket.exists()
                && let Ok(devices) = lr_export::session::free_devices()
                && let Some(device) = devices.first()
            {
                lr_export::session::attach(&socket, device)?;
                attached = Some(device.clone());
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let Some(device) = attached else {
            stop.store(true, Ordering::Relaxed);
            return Err(Error::unsupported("the NBD server produced no socket"));
        };
        let mount_options =
            match lr_export::session::mount_read_only(&device, &mountpoint, &fs_type) {
                Ok(options) => options,
                Err(error) => {
                    let _ = lr_export::session::detach(&device);
                    stop.store(true, Ordering::Relaxed);
                    return Err(error);
                }
            };
        let state = ExportState {
            image: spec.image.clone(),
            mountpoint: mountpoint.clone(),
            socket: socket.clone(),
            device: device.clone(),
            fs_type,
            mount_options,
            server_pid: std::process::id(),
            in_process: true,
        };
        lr_export::session::save_state(&state)?;
        exports
            .lock()
            .expect("export lock")
            .insert(mountpoint, stop);
        Ok(state)
    }

    /// Stop a daemon-served export (spec §K S13).
    fn unexport_with(
        exports: &Arc<Mutex<HashMap<PathBuf, Arc<AtomicBool>>>>,
        at: &Path,
    ) -> Result<ExportState> {
        let state = lr_export::session::load_state(at)?;
        if lr_export::session::is_mounted(&state.mountpoint) {
            lr_export::session::unmount(&state.mountpoint)?;
        }
        let _ = lr_export::session::detach(&state.device);
        if state.in_process {
            if let Some(stop) = exports
                .lock()
                .expect("export lock")
                .remove(&state.mountpoint)
            {
                stop.store(true, Ordering::Relaxed);
            }
        } else {
            let _ = std::process::Command::new("kill")
                .arg(state.server_pid.to_string())
                .status();
        }
        let _ = std::fs::remove_file(&state.socket);
        lr_export::session::clear_state(&state.mountpoint)?;
        Ok(state)
    }

    /// The peer of a request, as inserted by [`PeerInterceptor`].
    fn peer<T>(request: &GrpcRequest<T>) -> Result<Arc<PeerIdentity>> {
        request
            .extensions()
            .get::<Peer>()
            .map(|peer| Arc::clone(&peer.0))
            .ok_or_else(|| Error::denied("unknown", "the request carries no peer identity"))
    }

    /// Run file I/O, such as reading a passphrase file or an image header,
    /// on a blocking thread instead of an async request thread (R12).
    async fn off_thread<T, F>(work: F) -> std::result::Result<T, Status>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T> + Send + 'static,
    {
        tokio::task::spawn_blocking(work)
            .await
            .map_err(|error| Status::internal(format!("blocking task failed: {error}")))?
            .map_err(status::status_of)
    }

    /// Authorize one action for one request.
    async fn authorize<T>(
        &self,
        request: &GrpcRequest<T>,
        action: Action,
    ) -> std::result::Result<Arc<PeerIdentity>, Status> {
        let peer = Self::peer(request).map_err(status::status_of)?;
        self.auth
            .check(&peer, action)
            .await
            .map_err(status::status_of)?;
        Ok(peer)
    }

    /// Convert verification read options and pin caller-owned credential files.
    async fn verification_request(
        &self,
        uid: u32,
        spec: VerifySpec,
    ) -> std::result::Result<(lr_engine::verify::VerifyRequest, ClientFiles), Status> {
        // Both routes pin caller-owned files through their engine work (A4).
        client_files::check_host_key_policy(spec.insecure_ignore_host_key, self.dev_mode)
            .map_err(status::status_of)?;
        let named = spec.clone();
        let (encryption, files, identity, known_hosts) = Self::off_thread(move || {
            let encryption = match ClientFiles::passphrase(uid, &named.passphrase_file)? {
                Some(passphrase) => lr_engine::keys::Encryption::Passphrase(passphrase),
                None => lr_engine::options::restore_encryption(None)?,
            };
            let mut files = ClientFiles::new();
            let identity = files.pin(uid, &named.identity)?;
            let known_hosts = files.pin(uid, &named.known_hosts)?;
            Ok((encryption, files, identity, known_hosts))
        })
        .await?;
        Ok((
            lr_engine::verify::VerifyRequest {
                image: spec.image,
                encryption,
                chain: spec.chain,
                destination_options: lr_store::DestinationOptions {
                    set_name: String::new(),
                    identity,
                    known_hosts,
                    insecure_ignore_host_key: spec.insecure_ignore_host_key,
                },
                context: EngineContext::silent(),
            },
            files,
        ))
    }

    /// Run a job on a blocking thread, streaming its progress.
    fn run_job<F>(
        &self,
        job_id: String,
        set: String,
        owner: u32,
        work: F,
    ) -> Result<ReceiverStream<std::result::Result<Progress, Status>>>
    where
        F: FnOnce(EngineContext) -> Result<String> + Send + 'static,
    {
        // Registration publishes Started synchronously. Subscribe first so
        // clients always learn the ID needed to cancel or recover this job.
        let mut events = self.jobs.subscribe();
        let (sink, cancel) = self.jobs.register_for(&job_id, &set, owner)?;
        let context = EngineContext {
            progress: Some(Arc::new(sink)),
            cancel: Some(cancel),
        };

        let (sender, receiver) = mpsc::channel(64);
        let jobs = Arc::clone(&self.jobs);
        let forwarded = job_id.clone();
        tokio::spawn(async move {
            while let Ok(event) = events.recv().await {
                if event.job_id() != forwarded {
                    continue;
                }
                let terminal = matches!(
                    event,
                    JobEvent::Finished { .. }
                        | JobEvent::Failed { .. }
                        | JobEvent::VerificationCompleted { .. }
                );
                if sender.send(Ok(progress_of(&event))).await.is_err() {
                    break;
                }
                if terminal {
                    break;
                }
            }
        });

        let task_job_id = job_id;
        tokio::task::spawn_blocking(move || {
            // A panic ends this job as a failure and nothing else: the other
            // jobs, a restore halfway through a disk among them, keep running
            // (A8). The release profile unwinds for this to work.
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| work(context)))
                .unwrap_or_else(|payload| {
                    let message = payload
                        .downcast_ref::<String>()
                        .map(String::as_str)
                        .or_else(|| payload.downcast_ref::<&str>().copied())
                        .unwrap_or("no message");
                    tracing::error!(job = %task_job_id, message, "a job panicked");
                    Err(Error::Io(std::io::Error::other(format!(
                        "internal error: the job panicked ({message}); please report it"
                    ))))
                });
            if let Err(error) = jobs.finish(&task_job_id, outcome) {
                tracing::warn!(%error, "cannot record a job outcome");
            }
        });
        Ok(ReceiverStream::new(receiver))
    }

    fn run_verification_job<F>(
        &self,
        job_id: String,
        owner: u32,
        limit: usize,
        permit: SlotGuard,
        work: F,
    ) -> Result<ReceiverStream<std::result::Result<lr_proto::v1::VerificationProgress, Status>>>
    where
        F: FnOnce(EngineContext) -> Result<CapturedVerificationResult> + Send + 'static,
    {
        // Subscribe before registration; retain terminal state before publication.
        let mut events = self.jobs.subscribe();
        let (sink, cancel) = self.jobs.register_for(&job_id, &job_id, owner)?;
        let context = EngineContext {
            progress: Some(Arc::new(sink)),
            cancel: Some(cancel),
        };
        let (sender, receiver) = mpsc::channel(4);
        let forwarded = job_id.clone();
        let retained = Arc::clone(&self.jobs);
        tokio::spawn(async move {
            loop {
                let event = match events.recv().await {
                    Ok(event) => event,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        // A slow stream can recover the canonical terminal result.
                        if let Ok(snapshot) = retained.snapshot(&forwarded)
                            && let Some(event) = snapshot.terminal_event()
                        {
                            event
                        } else {
                            continue;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                };
                if event.job_id() != forwarded {
                    continue;
                }
                let terminal = matches!(
                    event,
                    JobEvent::Finished { .. }
                        | JobEvent::Failed { .. }
                        | JobEvent::VerificationCompleted { .. }
                );
                let message = verification_progress_of(&event);
                let message = verification::check_size(&message, limit)
                    .map(|()| message)
                    .map_err(|_| {
                        Status::resource_exhausted("verification response exceeds daemon policy")
                    });
                let failed = message.is_err();
                if sender.send(message).await.is_err() || terminal || failed {
                    break;
                }
            }
        });
        let jobs = Arc::clone(&self.jobs);
        tokio::task::spawn_blocking(move || {
            // Keep admission until the canonical result is retained and published.
            let _permit = permit;
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| work(context)))
                .unwrap_or_else(|_| {
                    Err(Error::Io(std::io::Error::other(
                        "internal error: captured verification panicked",
                    )))
                });
            let finished = match outcome {
                Ok(result) => jobs.finish_verification(&job_id, result),
                Err(error) => jobs.finish(&job_id, Err(error)),
            };
            if let Err(error) = finished {
                tracing::warn!(%error, "cannot retain verification result");
            }
        });
        Ok(ReceiverStream::new(receiver))
    }
}

fn verification_progress_of(event: &JobEvent) -> lr_proto::v1::VerificationProgress {
    use lr_proto::v1::verification_progress::Step;
    let step = match event {
        JobEvent::VerificationCompleted { result, .. } => Step::Result(result.wire()),
        _ => Step::Progress(progress_of(event)),
    };
    lr_proto::v1::VerificationProgress { step: Some(step) }
}

/// A one-shot `Progress` whose finished step carries `value` as JSON.
fn finished_progress<T: serde::Serialize>(value: &T) -> std::result::Result<Progress, Status> {
    let summary_json = serde_json::to_string(value)
        .map_err(|error| Status::internal(format!("report json: {error}")))?;
    Ok(Progress {
        step: Some(lr_proto::v1::progress::Step::Finished(
            lr_proto::v1::Finished { summary_json },
        )),
    })
}

/// Convert a job event into the wire `Progress` message.
fn progress_of(event: &JobEvent) -> Progress {
    use lr_proto::v1::progress::Step;
    use lr_proto::v1::{Bytes, Failure, Finished, Phase, Started};
    let step = match event {
        JobEvent::Started { job_id } => Step::Started(Started {
            job_id: job_id.clone(),
        }),
        JobEvent::Phase { name, .. } => Step::Phase(Phase { name: name.clone() }),
        JobEvent::Bytes { done, total, .. } => Step::Bytes(Bytes {
            done: *done,
            total: *total,
        }),
        JobEvent::Finished { summary_json, .. } => Step::Finished(Finished {
            summary_json: summary_json.clone(),
        }),
        JobEvent::Failed { code, message, .. } => Step::Failure(Failure {
            code: code.clone(),
            message: message.clone(),
        }),
        JobEvent::VerificationCompleted { result, .. } => return result.legacy_progress(),
    };
    Progress { step: Some(step) }
}

/// Convert a job snapshot into the wire message.
fn job_state_of(snapshot: &crate::jobs::JobSnapshot) -> JobState {
    let state = match snapshot.state {
        JobStateInner::Pending => "pending",
        JobStateInner::Running => "running",
        JobStateInner::Finished => "finished",
        JobStateInner::Failed => "failed",
        JobStateInner::Cancelled => "cancelled",
    };
    let progress = snapshot.terminal_event().as_ref().map(progress_of);
    JobState {
        job_id: snapshot.job_id.clone(),
        set: snapshot.set.clone(),
        state: state.to_owned(),
        progress,
    }
}

#[cfg(test)]
mod job_result_projection {
    use super::{job_state_of, progress_of};
    use crate::jobs::{JobEvent, Jobs};
    use lr_core::Error;
    use lr_proto::v1::progress::Step;

    fn terminal_event_from(events: &mut tokio::sync::broadcast::Receiver<JobEvent>) -> JobEvent {
        let started = events.try_recv().expect("Started event");
        assert!(matches!(started, JobEvent::Started { .. }));
        match events.try_recv().expect("terminal event") {
            event @ (JobEvent::Finished { .. } | JobEvent::Failed { .. }) => event,
            other => panic!("expected a terminal event, got {other:?}"),
        }
    }

    #[test]
    fn success_event_and_get_job_recover_the_same_summary() {
        let jobs = Jobs::new();
        let mut events = jobs.subscribe();
        let _ = jobs.register("success", "set").expect("register");
        let summary = r#"{"image_uri":"/backup/full.lrimg","warnings":["one"]}"#;
        jobs.finish("success", Ok(summary.to_owned()))
            .expect("finish");
        let event = terminal_event_from(&mut events);
        let snapshot = jobs.snapshot("success").expect("GetJob snapshot");

        let status = job_state_of(&snapshot);
        assert_eq!(status.state, "finished");
        assert_eq!(status.progress, Some(progress_of(&event)));
        assert!(matches!(
            status.progress.and_then(|progress| progress.step),
            Some(Step::Finished(finished)) if finished.summary_json == summary
        ));
    }

    #[test]
    fn failures_and_cancellations_project_the_same_terminal_error() {
        for (job_id, error, expected_state, expected_code) in [
            (
                "failure",
                Error::TargetChanged,
                "failed",
                "E_TARGET_CHANGED",
            ),
            ("cancel", Error::Cancelled, "cancelled", "E_CANCELLED"),
        ] {
            let jobs = Jobs::new();
            let mut events = jobs.subscribe();
            let _ = jobs.register(job_id, "set").expect("register");
            jobs.finish(job_id, Err(error)).expect("finish");
            let event = terminal_event_from(&mut events);
            let snapshot = jobs.snapshot(job_id).expect("GetJob snapshot");

            let status = job_state_of(&snapshot);
            assert_eq!(status.state, expected_state);
            assert_eq!(status.progress, Some(progress_of(&event)));
            assert!(matches!(
                status.progress.and_then(|progress| progress.step),
                Some(Step::Failure(failure)) if failure.code == expected_code
            ));
        }
    }
}

/// The configured destinations, for the client.
fn destination_list() -> std::result::Result<lr_proto::v1::DestinationList, Status> {
    let entries =
        lr_store::named::load(&lr_store::named::registry_path()).map_err(status::status_of)?;
    Ok(lr_proto::v1::DestinationList {
        destinations: entries
            .into_iter()
            .map(|entry| lr_proto::v1::NamedDestination {
                name: entry.name,
                uri: entry.uri,
                identity: entry
                    .identity
                    .map(|path| path.display().to_string())
                    .unwrap_or_default(),
                known_hosts: entry
                    .known_hosts
                    .map(|path| path.display().to_string())
                    .unwrap_or_default(),
                required_mount: entry
                    .required_mount
                    .map(|required| lr_proto::v1::RequiredMount {
                        path: required.path.display().to_string(),
                        source: required.source,
                        fs_type: required.fs_type,
                    }),
            })
            .collect(),
    })
}

#[tonic::async_trait]
impl LinuxReflect for DaemonService {
    type CreateBackupStream = ReceiverStream<std::result::Result<Progress, Status>>;
    type VerifyImageStream = ReceiverStream<std::result::Result<Progress, Status>>;
    type VerifyImageWithHistoryStream =
        ReceiverStream<std::result::Result<lr_proto::v1::VerificationProgress, Status>>;
    type ListVerificationHistoryStream =
        ReceiverStream<std::result::Result<lr_proto::v1::VerificationHistoryItem, Status>>;
    type RestoreImageStream = ReceiverStream<std::result::Result<Progress, Status>>;
    type WatchEventsStream = ReceiverStream<std::result::Result<Event, Status>>;

    async fn get_version(
        &self,
        _request: GrpcRequest<Request>,
    ) -> std::result::Result<Response<Version>, Status> {
        Ok(Response::new(Version {
            format_major: lr_format::FORMAT_MAJOR,
            daemon: env!("CARGO_PKG_VERSION").to_owned(),
            dev_mode: self.dev_mode,
        }))
    }

    async fn list_disks(
        &self,
        request: GrpcRequest<Request>,
    ) -> std::result::Result<Response<DiskList>, Status> {
        self.authorize(&request, Action::DiskRead).await?;
        let json = lr_engine::inspect::disk_list_json(true).map_err(status::status_of)?;
        Ok(Response::new(DiskList { json }))
    }

    async fn disk_map(
        &self,
        request: GrpcRequest<SourceRef>,
    ) -> std::result::Result<Response<DiskList>, Status> {
        self.authorize(&request, Action::DiskRead).await?;
        let device = PathBuf::from(&request.get_ref().source);
        let json = lr_engine::inspect::disk_map_json(&device).map_err(status::status_of)?;
        Ok(Response::new(DiskList { json }))
    }

    async fn probe_source(
        &self,
        request: GrpcRequest<SourceRef>,
    ) -> std::result::Result<Response<Plan>, Status> {
        self.authorize(&request, Action::DiskRead).await?;
        let source = PathBuf::from(&request.get_ref().source);
        if source.is_dir() {
            // File mode: the "device" is a directory tree (spec §D.1, §K S12).
            let walk = lr_engine::tree::walk(
                &source,
                &lr_engine::tree::WalkOptions::with_default_excludes(),
            )
            .map_err(status::status_of)?;
            return Ok(Response::new(Plan {
                provider: "file".to_owned(),
                image_kind: "File".to_owned(),
                consistency: lr_core::Consistency::PerFile.to_string(),
                estimated_bytes: walk.total_bytes,
                warnings: walk.warnings,
            }));
        }
        let layout = lr_core::discovery::discover_source(&source).map_err(status::status_of)?;
        let opts = lr_core::SnapshotOpts::default();
        let plan = lr_snapshot::probe_source(&layout, &opts).map_err(status::status_of)?;
        Ok(Response::new(Plan {
            provider: plan.provider,
            image_kind: format!("{:?}", plan.image_kind),
            consistency: plan.consistency.to_string(),
            estimated_bytes: plan.estimated_bytes,
            warnings: plan.warnings,
        }))
    }

    async fn list_sets(
        &self,
        request: GrpcRequest<SetRef>,
    ) -> std::result::Result<Response<SetInfo>, Status> {
        let peer = self.authorize(&request, Action::DiskRead).await?;
        Ok(Response::new(self.set_info(request.get_ref(), peer.uid)?))
    }

    async fn list_destinations(
        &self,
        request: GrpcRequest<lr_proto::v1::Request>,
    ) -> std::result::Result<Response<lr_proto::v1::DestinationList>, Status> {
        self.authorize(&request, Action::DiskRead).await?;
        Ok(Response::new(destination_list()?))
    }

    async fn set_destination(
        &self,
        request: GrpcRequest<lr_proto::v1::NamedDestination>,
    ) -> std::result::Result<Response<lr_proto::v1::DestinationList>, Status> {
        self.authorize(&request, Action::DestinationConfigure)
            .await?;
        let wanted = request.get_ref();
        let entry = lr_store::named::NamedDestination {
            name: wanted.name.clone(),
            uri: wanted.uri.clone(),
            identity: (!wanted.identity.is_empty()).then(|| PathBuf::from(&wanted.identity)),
            known_hosts: (!wanted.known_hosts.is_empty())
                .then(|| PathBuf::from(&wanted.known_hosts)),
            required_mount: wanted.required_mount.as_ref().map(|required| {
                lr_store::RequiredMount {
                    path: PathBuf::from(&required.path),
                    source: required.source.clone(),
                    fs_type: required.fs_type.clone(),
                }
            }),
        };
        let path = lr_store::named::registry_path();
        let mut entries = lr_store::named::load(&path).map_err(status::status_of)?;
        lr_store::named::upsert(&mut entries, entry).map_err(status::status_of)?;
        lr_store::named::save(&path, &entries).map_err(status::status_of)?;
        Ok(Response::new(destination_list()?))
    }

    async fn remove_destination(
        &self,
        request: GrpcRequest<lr_proto::v1::DestinationRef>,
    ) -> std::result::Result<Response<lr_proto::v1::DestinationList>, Status> {
        self.authorize(&request, Action::DestinationConfigure)
            .await?;
        let name = request.get_ref().name.clone();
        let path = lr_store::named::registry_path();
        let mut entries = lr_store::named::load(&path).map_err(status::status_of)?;
        let before = entries.len();
        entries.retain(|existing| existing.name != name);
        if entries.len() == before {
            return Err(status::not_found(format!("no destination named @{name}")));
        }
        lr_store::named::save(&path, &entries).map_err(status::status_of)?;
        Ok(Response::new(destination_list()?))
    }

    async fn list_chains(
        &self,
        request: GrpcRequest<SetRef>,
    ) -> std::result::Result<Response<SetInfo>, Status> {
        let peer = self.authorize(&request, Action::DiskRead).await?;
        Ok(Response::new(self.set_info(request.get_ref(), peer.uid)?))
    }

    async fn create_backup(
        &self,
        request: GrpcRequest<BackupSpec>,
    ) -> std::result::Result<Response<Self::CreateBackupStream>, Status> {
        let peer = self.authorize(&request, Action::BackupCreate).await?;
        let spec = request.get_ref().clone();
        client_files::check_host_key_policy(spec.insecure_ignore_host_key, self.dev_mode)
            .map_err(status::status_of)?;
        // The same conversion the CLI's direct route uses (R31), for files
        // the caller owns (A4).
        let described = spec.clone();
        let uid = peer.uid;
        let job = Self::off_thread(move || {
            client_files::check(
                uid,
                &[
                    &described.passphrase_file,
                    &described.identity,
                    &described.known_hosts,
                ],
            )?;
            lr_request::backup_job(&described)
        })
        .await?;
        let job_id = if spec.job_id.is_empty() {
            format!("backup-{}", job.request.image_uuid)
        } else {
            spec.job_id.clone()
        };
        let stream = self
            .run_job(job_id, spec.set.clone(), peer.uid, move |context| {
                let report = lr_request::run_backup(job, context)?;
                serde_json::to_string(&report)
                    .map_err(|error| Error::corrupt(format!("report json: {error}")))
            })
            .map_err(status::status_of)?;
        Ok(Response::new(stream))
    }

    async fn verify_image(
        &self,
        request: GrpcRequest<VerifySpec>,
    ) -> std::result::Result<Response<Self::VerifyImageStream>, Status> {
        let peer = self.authorize(&request, Action::DiskRead).await?;
        let (verify, files) = self
            .verification_request(peer.uid, request.into_inner())
            .await?;
        // Every verification is its own job with its own set key, so one
        // user's long verification never blocks another's; a counting
        // semaphore bounds how many read at once (A5).
        let id = format!(
            "verify-{}",
            lr_core::Id::generate().map_err(|error| status::status_of(Error::Io(error)))?
        );
        let slots = Arc::clone(&self.verifications);
        let stream = self
            .run_job(id.clone(), id, peer.uid, move |context| {
                let _slot = slots.acquire();
                let mut verify = verify;
                verify.context = context;
                let mut report =
                    lr_engine::verify::verify_image(&verify).map_err(|error| files.named(error))?;
                // A whole-chain verification is recorded for retention
                // (R20).
                if let Some(note) = lr_engine::verify::record_verification(&verify, &report)? {
                    report.warnings.push(note);
                }
                serde_json::to_string(&report)
                    .map_err(|error| Error::corrupt(format!("report json: {error}")))
            })
            .map_err(status::status_of)?;
        Ok(Response::new(stream))
    }

    async fn verify_image_with_history(
        &self,
        request: GrpcRequest<VerifySpec>,
    ) -> std::result::Result<Response<Self::VerifyImageWithHistoryStream>, Status> {
        let peer = self.authorize(&request, Action::DiskRead).await?;
        let runtime = self.history.as_ref().map(Arc::clone).ok_or_else(|| {
            Status::failed_precondition("daemon verification history is disabled")
        })?;
        let permit = runtime
            .operations
            .try_acquire()
            .ok_or_else(|| Status::resource_exhausted("daemon verification history is busy"))?;
        let reservation = runtime
            .results
            .try_reserve(runtime.policy.max_result_bytes())
            .ok_or_else(|| {
                Status::resource_exhausted("daemon retained verification result quota is full")
            })?;
        // Write authority comes exclusively from daemon startup policy.
        let (verify, files) = self
            .verification_request(peer.uid, request.into_inner())
            .await?;
        let id = format!(
            "verify-captured-{}",
            lr_core::Id::generate().map_err(|error| status::status_of(Error::Io(error)))?
        );
        let slots = Arc::clone(&self.verifications);
        let limit = runtime.policy.max_result_bytes();
        let stream = self
            .run_verification_job(id, peer.uid, limit, permit, move |context| {
                let _slot = slots.acquire();
                // Keep caller-owned credential descriptors pinned through the engine
                // attempt. Diagnostics stay outside the receipt and typed response.
                let _files = files;
                let mut verify = verify;
                verify.context = context;
                let attempt =
                    lr_engine::verify::verify_image_captured(&verify, runtime.policy.capture());
                let recording = lr_engine::verify::record_verification_attempt(
                    &attempt,
                    runtime.policy.history(),
                );
                CapturedVerificationResult::from_attempt(
                    &attempt,
                    recording,
                    &runtime.policy,
                    reservation,
                )
            })
            .map_err(status::status_of)?;
        Ok(Response::new(stream))
    }

    async fn get_verification_result(
        &self,
        request: GrpcRequest<JobRef>,
    ) -> std::result::Result<Response<lr_proto::v1::VerificationResult>, Status> {
        let peer = self.authorize(&request, Action::DiskRead).await?;
        let id = &request.get_ref().job_id;
        let snapshot = self
            .jobs
            .snapshot_owned(id, peer.uid)
            .map_err(status::status_of)?;
        let result = snapshot.verification.ok_or_else(|| {
            Status::failed_precondition("no retained captured verification result")
        })?;
        let runtime = self.history.as_ref().ok_or_else(|| {
            Status::failed_precondition("daemon verification history is disabled")
        })?;
        // Bound projection work, not only capture and ledger I/O. The canonical
        // result stays shared; each response is an independently owned wire value.
        let _permit = runtime
            .operations
            .try_acquire()
            .ok_or_else(|| Status::resource_exhausted("daemon verification history is busy"))?;
        Ok(Response::new(result.wire()))
    }

    async fn list_verification_history(
        &self,
        request: GrpcRequest<Request>,
    ) -> std::result::Result<Response<Self::ListVerificationHistoryStream>, Status> {
        // Version-1 receipts name recorder EUID, not requesting UID. Until
        // per-caller provenance is designed, global inspection is admin-only.
        self.authorize(&request, Action::BackupCreate).await?;
        let (sender, receiver) = mpsc::channel(1);
        let Some(runtime) = self.history.as_ref().map(Arc::clone) else {
            sender
                .send(Ok(verification::history_state(
                    lr_proto::v1::VerificationHistoryAvailability::Disabled,
                )))
                .await
                .map_err(|_| Status::internal("history stream closed"))?;
            return Ok(Response::new(ReceiverStream::new(receiver)));
        };
        let permit = runtime
            .operations
            .try_acquire()
            .ok_or_else(|| Status::resource_exhausted("daemon verification history is busy"))?;
        let history = Self::off_thread(move || {
            verification::check_size(
                &verification::history_state(
                    lr_proto::v1::VerificationHistoryAvailability::Available,
                ),
                runtime.policy.max_result_bytes(),
            )?;
            let history = lr_engine::verify::load_verification_history(runtime.policy.history());
            // Validate every receipt before saying history is available.
            if let Ok(history) = &history {
                for receipt in history.receipts() {
                    verification::check_observation_size(
                        receipt.observation(),
                        runtime.policy.max_result_bytes(),
                    )?;
                    verification::check_size(
                        &verification::wire_receipt(receipt),
                        runtime.policy.max_result_bytes(),
                    )?;
                }
            }
            Ok((history, permit))
        })
        .await?;
        tokio::spawn(async move {
            let (history, _permit) = history;
            use lr_proto::v1::VerificationHistoryAvailability as Availability;
            let availability = match &history {
                Err(_) => Availability::Unknown,
                Ok(history) if history.receipts().is_empty() => Availability::Empty,
                Ok(_) => Availability::Available,
            };
            if sender
                .send(Ok(verification::history_state(availability)))
                .await
                .is_err()
            {
                return;
            }
            if let Ok(history) = history {
                for receipt in history.receipts() {
                    if sender
                        .send(Ok(verification::wire_receipt(receipt)))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(receiver)))
    }

    async fn prepare_restore(
        &self,
        request: GrpcRequest<RestoreSpec>,
    ) -> std::result::Result<Response<RestorePlanInfo>, Status> {
        let peer = self.authorize(&request, Action::RestorePrepare).await?;
        let spec = request.get_ref().clone();
        client_files::check_host_key_policy(spec.insecure_ignore_host_key, self.dev_mode)
            .map_err(status::status_of)?;
        let uid = peer.uid;
        // Reading the passphrase, the image and the target is file I/O
        // (R12); the named files must be the caller's own (A4), and the
        // plan's token is bound to this caller (A11).
        let plan = Self::off_thread(move || {
            client_files::check(
                uid,
                &[&spec.passphrase_file, &spec.identity, &spec.known_hosts],
            )?;
            let encryption = lr_engine::options::restore_encryption(
                (!spec.passphrase_file.is_empty())
                    .then(|| PathBuf::from(&spec.passphrase_file))
                    .as_deref(),
            )?;
            let mut prepare =
                lr_engine::restore::PrepareRequest::new(&spec.image, &spec.target, encryption);
            prepare.identity = (!spec.identity.is_empty()).then(|| PathBuf::from(&spec.identity));
            prepare.known_hosts =
                (!spec.known_hosts.is_empty()).then(|| PathBuf::from(&spec.known_hosts));
            prepare.insecure_ignore_host_key = spec.insecure_ignore_host_key;
            prepare.merge = spec.merge;
            prepare.strict_metadata = spec.strict_metadata;
            prepare.replace_partition_table = spec.replace_partition_table;
            if spec.ttl_secs > 0 {
                prepare.ttl = std::time::Duration::from_secs(spec.ttl_secs.min(600));
            }
            lr_engine::restore::prepare_restore_as(&prepare, uid)
        })
        .await?;
        Ok(Response::new(RestorePlanInfo {
            dest: plan.dest,
            set: plan.set,
            image: plan.image,
            members: plan.members,
            image_uuid: plan.image_uuid.to_string(),
            consistency: plan.consistency.to_string(),
            image_kind: format!("{:?}", plan.image_kind),
            source_size_bytes: plan.source_size_bytes,
            chunk_size: u64::from(plan.chunk_size),
            target: plan.target.display().to_string(),
            target_size_bytes: plan.target_size_bytes,
            encrypted: plan.encrypted,
            warnings: plan.warnings,
            token: plan.token,
        }))
    }

    async fn restore_image(
        &self,
        request: GrpcRequest<RestoreToken>,
    ) -> std::result::Result<Response<Self::RestoreImageStream>, Status> {
        let peer = self.authorize(&request, Action::RestoreApply).await?;
        let uid = peer.uid;
        let spec = request.get_ref().clone();
        let passphrase_file = spec.passphrase_file.clone();
        let encryption =
            Self::off_thread(
                move || match ClientFiles::passphrase(uid, &passphrase_file)? {
                    Some(passphrase) => Ok(lr_engine::keys::Encryption::Passphrase(passphrase)),
                    None => lr_engine::options::restore_encryption(None),
                },
            )
            .await?;
        let apply = lr_engine::restore::ApplyRequest {
            token: spec.token.clone(),
            confirm: spec.confirm,
            accept_inconsistent: spec.accept_inconsistent,
            encryption,
            context: EngineContext::silent(),
        };
        let job_id = if spec.job_id.is_empty() {
            "restore".to_owned()
        } else {
            spec.job_id.clone()
        };
        let stream = self
            .run_job(job_id, "restore".to_owned(), uid, move |context| {
                // Only the user who prepared the token may use it, once (A11).
                let outcome = lr_engine::restore::apply_restore_as(
                    &lr_engine::restore::ApplyRequest { context, ..apply },
                    uid,
                )?;
                serde_json::to_string(&outcome)
                    .map_err(|error| Error::corrupt(format!("report json: {error}")))
            })
            .map_err(status::status_of)?;
        Ok(Response::new(stream))
    }

    async fn rebuild_catalog(
        &self,
        request: GrpcRequest<SetRef>,
    ) -> std::result::Result<Response<Progress>, Status> {
        self.authorize(&request, Action::BackupCreate).await?;
        let spec = request.get_ref().clone();
        let progress = tokio::task::spawn_blocking(move || -> Result<String> {
            let options = lr_store::DestinationOptions::new(&spec.set);
            let destination = lr_store::open(&spec.dest, &options)?;
            let set = destination.open_existing_set(&lr_core::SetId::ZERO)?;
            let lock = lr_engine::backup::acquire_set_lock_for(&*destination, &set, 300, false)?;
            let loaded = lr_engine::catalog::load(
                &*destination,
                &set,
                &spec.set,
                lr_engine::backup::now_unix(),
            )?;
            lock.verify()?;
            lr_engine::catalog::write_catalog(&*destination, &set, &loaded.catalog)?;
            serde_json::to_string(&loaded.catalog)
                .map_err(|error| Error::corrupt(format!("catalog json: {error}")))
        })
        .await
        .map_err(|error| Status::internal(format!("catalog task failed: {error}")))?
        .map_err(status::status_of)?;
        use lr_proto::v1::Finished;
        use lr_proto::v1::progress::Step;
        Ok(Response::new(Progress {
            step: Some(Step::Finished(Finished {
                summary_json: progress,
            })),
        }))
    }

    async fn get_job(
        &self,
        request: GrpcRequest<JobRef>,
    ) -> std::result::Result<Response<JobState>, Status> {
        self.authorize(&request, Action::DiskRead).await?;
        let snapshot = self
            .jobs
            .snapshot(&request.get_ref().job_id)
            .map_err(status::status_of)?;
        Ok(Response::new(job_state_of(&snapshot)))
    }

    async fn cancel_job(
        &self,
        request: GrpcRequest<JobRef>,
    ) -> std::result::Result<Response<JobState>, Status> {
        let peer = self.authorize(&request, Action::DiskRead).await?;
        let job_id = &request.get_ref().job_id;
        // A user cancels their own jobs; another user's job needs the
        // administrator action (R10). Root may always cancel.
        let owner = self.jobs.owner(job_id).map_err(status::status_of)?;
        if peer.uid != owner && peer.uid != 0 {
            self.authorize(&request, Action::JobCancelOther).await?;
        }
        let snapshot = self.jobs.cancel(job_id).map_err(status::status_of)?;
        Ok(Response::new(job_state_of(&snapshot)))
    }

    async fn watch_events(
        &self,
        request: GrpcRequest<Request>,
    ) -> std::result::Result<Response<Self::WatchEventsStream>, Status> {
        self.authorize(&request, Action::DiskRead).await?;
        let mut events = self.jobs.subscribe();
        let (sender, receiver) = mpsc::channel(64);
        tokio::spawn(async move {
            let mut next_id = 1u64;
            while let Ok(event) = events.recv().await {
                let message = Event {
                    event_id: next_id,
                    kind: match &event {
                        JobEvent::Started { .. } => "started",
                        JobEvent::Phase { .. } => "phase",
                        JobEvent::Bytes { .. } => "bytes",
                        JobEvent::Finished { .. } => "finished",
                        JobEvent::Failed { .. } => "failed",
                        JobEvent::VerificationCompleted { result, .. } => {
                            if result.job_outcome().0 == JobStateInner::Finished {
                                "finished"
                            } else {
                                "failed"
                            }
                        }
                    }
                    .to_owned(),
                    message: event.job_id().to_owned(),
                    progress: Some(progress_of(&event)),
                };
                next_id += 1;
                if sender.send(Ok(message)).await.is_err() {
                    break;
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(receiver)))
    }

    async fn export_image(
        &self,
        request: GrpcRequest<lr_proto::v1::ExportSpec>,
    ) -> std::result::Result<Response<Progress>, Status> {
        let peer = self.authorize(&request, Action::ExportManage).await?;
        let spec = request.get_ref().clone();
        client_files::check_host_key_policy(spec.insecure_ignore_host_key, self.dev_mode)
            .map_err(status::status_of)?;
        let exports = Arc::clone(&self.exports);
        let uid = peer.uid;
        let state = tokio::task::spawn_blocking(move || {
            client_files::check(
                uid,
                &[&spec.passphrase_file, &spec.identity, &spec.known_hosts],
            )?;
            DaemonService::export_with(&exports, &spec)
        })
        .await
        .map_err(|error| Status::internal(format!("export task failed: {error}")))?
        .map_err(status::status_of)?;
        Ok(Response::new(finished_progress(&state)?))
    }

    async fn unexport_image(
        &self,
        request: GrpcRequest<lr_proto::v1::UnexportSpec>,
    ) -> std::result::Result<Response<Progress>, Status> {
        self.authorize(&request, Action::ExportManage).await?;
        let spec = request.get_ref().clone();
        let exports = Arc::clone(&self.exports);
        let state = tokio::task::spawn_blocking(move || {
            DaemonService::unexport_with(&exports, Path::new(&spec.at))
        })
        .await
        .map_err(|error| Status::internal(format!("unexport task failed: {error}")))?
        .map_err(status::status_of)?;
        Ok(Response::new(finished_progress(&state)?))
    }

    async fn get_schedule(
        &self,
        request: GrpcRequest<lr_proto::v1::ScheduleSpec>,
    ) -> std::result::Result<Response<Progress>, Status> {
        self.authorize(&request, Action::ScheduleManage).await?;
        let spec = request.get_ref().clone();
        let jobs = tokio::task::spawn_blocking(move || {
            let config = if spec.config.is_empty() {
                PathBuf::from(lr_engine::schedule::DEFAULT_CONFIG)
            } else {
                PathBuf::from(&spec.config)
            };
            let cli = std::env::current_exe().map_or_else(
                |_| PathBuf::from("linuxreflect"),
                |path| path.with_file_name("linuxreflect"),
            );
            lr_engine::schedule::list(&config, &cli)
        })
        .await
        .map_err(|error| Status::internal(format!("schedule task failed: {error}")))?
        .map_err(status::status_of)?;
        Ok(Response::new(finished_progress(&jobs)?))
    }

    async fn set_schedule(
        &self,
        request: GrpcRequest<lr_proto::v1::ScheduleSpec>,
    ) -> std::result::Result<Response<Progress>, Status> {
        self.authorize(&request, Action::ScheduleManage).await?;
        let spec = request.get_ref().clone();
        let report = tokio::task::spawn_blocking(move || {
            if !spec.remove.is_empty() {
                let dir = (!spec.systemd_dir.is_empty()).then(|| PathBuf::from(&spec.systemd_dir));
                let removed = lr_engine::schedule::remove(&spec.remove, dir.as_deref())?;
                return Ok(serde_json::json!({
                    "job": spec.remove,
                    "removed": removed,
                })
                .to_string());
            }
            let config = if spec.config.is_empty() {
                PathBuf::from(lr_engine::schedule::DEFAULT_CONFIG)
            } else {
                PathBuf::from(&spec.config)
            };
            // The generated services run the CLI next to the daemon.
            let cli = std::env::current_exe().map_or_else(
                |_| PathBuf::from("linuxreflect"),
                |path| path.with_file_name("linuxreflect"),
            );
            let dir = (!spec.systemd_dir.is_empty()).then(|| PathBuf::from(&spec.systemd_dir));
            let report = lr_engine::schedule::materialize(
                &config,
                &cli,
                dir.as_deref(),
                spec.dry_run,
                true,
                !spec.dry_run,
            )?;
            serde_json::to_string(&report)
                .map_err(|error| Error::corrupt(format!("schedule json: {error}")))
        })
        .await
        .map_err(|error| Status::internal(format!("schedule task failed: {error}")))?
        .map_err(status::status_of)?;
        Ok(Response::new(finished_progress(&report)?))
    }

    async fn apply_retention(
        &self,
        request: GrpcRequest<lr_proto::v1::RetentionSpec>,
    ) -> std::result::Result<Response<Progress>, Status> {
        let peer = self.authorize(&request, Action::ScheduleManage).await?;
        let spec = request.get_ref().clone();
        let uid = peer.uid;
        let report = tokio::task::spawn_blocking(move || {
            client_files::check(uid, &[&spec.passphrase_file])?;
            let options = lr_store::DestinationOptions {
                set_name: spec.set.clone(),
                identity: None,
                known_hosts: None,
                insecure_ignore_host_key: false,
            };
            let destination = lr_store::open(&spec.dest, &options)?;
            let set = destination.open_existing_set(&lr_core::SetId::ZERO)?;
            let report = lr_engine::retention::apply(
                &*destination,
                &set,
                &spec.set,
                &lr_engine::retention::RetentionOptions {
                    keep_chains: usize::try_from(spec.keep_chains).unwrap_or(0),
                    dry_run: spec.dry_run,
                    verify_first: spec.verify_first,
                    encryption: lr_engine::options::restore_encryption(
                        (!spec.passphrase_file.is_empty())
                            .then(|| PathBuf::from(&spec.passphrase_file))
                            .as_deref(),
                    )?,
                    ..lr_engine::retention::RetentionOptions::default()
                },
            )?;
            serde_json::to_string(&report)
                .map_err(|error| Error::corrupt(format!("retention json: {error}")))
        })
        .await
        .map_err(|error| Status::internal(format!("retention task failed: {error}")))?
        .map_err(status::status_of)?;
        Ok(Response::new(finished_progress(
            &serde_json::Value::String(report),
        )?))
    }
}

impl DaemonService {
    /// Load and validate a set's catalog for `ListSets`/`ListChains`.
    fn set_info(&self, spec: &SetRef, uid: u32) -> std::result::Result<SetInfo, Status> {
        // The caller's SSH options reach the destination (A6); a named
        // destination replaces them with its own. The files must be the
        // caller's own and stay pinned while they are used (A4).
        client_files::check_host_key_policy(spec.insecure_ignore_host_key, self.dev_mode)
            .map_err(status::status_of)?;
        let mut files = ClientFiles::new();
        let options = lr_store::DestinationOptions {
            set_name: spec.set.clone(),
            identity: files.pin(uid, &spec.identity).map_err(status::status_of)?,
            known_hosts: files
                .pin(uid, &spec.known_hosts)
                .map_err(status::status_of)?,
            insecure_ignore_host_key: spec.insecure_ignore_host_key,
        };
        let destination = lr_store::open(&spec.dest, &options)
            .map_err(|error| status::status_of(files.named(error)))?;
        if spec.set.is_empty() {
            // No set named: list the sets instead of opening (and creating)
            // an unnamed one.
            let sets = destination
                .list_set_names()
                .map_err(|error| status::status_of(files.named(error)))?;
            return Ok(SetInfo {
                sets,
                ..SetInfo::default()
            });
        }
        let set = destination
            .open_existing_set(&lr_core::SetId::ZERO)
            .map_err(|error| status::status_of(files.named(error)))?;
        let loaded = lr_engine::catalog::load(
            &*destination,
            &set,
            &spec.set,
            lr_engine::backup::now_unix(),
        )
        .map_err(|error| status::status_of(files.named(error)))?;
        let chains = loaded
            .catalog
            .chains
            .iter()
            .map(|chain| lr_proto::v1::ChainInfo {
                chain_id: chain.chain_id.to_string(),
                created_unix: chain.created_unix,
                complete: chain.is_complete(),
                members: chain
                    .members
                    .iter()
                    .map(|member| lr_proto::v1::MemberInfo {
                        image_uuid: member.image_uuid.to_string(),
                        parent_uuid: member.parent_uuid.to_string(),
                        kind: format!("{:?}", member.kind).to_lowercase(),
                        seq_in_chain: member.seq_in_chain,
                        image_kind: format!("{:?}", member.image_kind),
                        consistency: member.consistency.to_string(),
                        created_unix: member.created_unix,
                        size_bytes: member.size_bytes,
                        file_name: member.file_name.clone(),
                    })
                    .collect(),
            })
            .collect();
        Ok(SetInfo {
            set: spec.set.clone(),
            chains,
            warnings: loaded.warnings,
            sets: Vec::new(),
        })
    }
}

/// The image kinds the daemon can restore.
#[must_use]
pub fn restore_supported(kind: ImageKind) -> bool {
    matches!(kind, ImageKind::Block | ImageKind::Stream)
}

/// A convenience for tests: a verify outcome is not part of the stream API, so
/// the daemon reports it through `Finished`; this keeps the type used.
#[must_use]
pub fn verify_outcome(json: &str) -> VerifyOutcome {
    let _ = json;
    VerifyOutcome::default()
}

#[cfg(test)]
mod panicking_jobs {
    use super::{DaemonService, Jobs};
    use std::sync::Arc;
    use tokio_stream::StreamExt;

    async fn steps(
        mut stream: tokio_stream::wrappers::ReceiverStream<
            std::result::Result<lr_proto::v1::Progress, tonic::Status>,
        >,
    ) -> Vec<lr_proto::v1::progress::Step> {
        let mut steps = Vec::new();
        while let Ok(Some(progress)) =
            tokio::time::timeout(std::time::Duration::from_secs(10), stream.next()).await
        {
            if let Some(step) = progress.expect("progress").step {
                steps.push(step);
            }
        }
        steps
    }

    /// A job that panics fails on its own: it is recorded as failed, and the
    /// daemon keeps running other jobs (A8).
    #[tokio::test]
    async fn a_panicking_job_fails_alone() {
        use lr_proto::v1::progress::Step;
        let auth = crate::auth::build(Some("static:0"), true)
            .await
            .expect("auth");
        let service = DaemonService::new(auth, Arc::new(Jobs::new()), true);
        let panicking = service
            .run_job("boom".to_owned(), "boom".to_owned(), 0, |_| {
                panic!("a deliberate panic in a job")
            })
            .expect("start");
        let failed = steps(panicking).await;
        assert!(
            failed.iter().any(|step| matches!(
                step,
                Step::Failure(failure) if failure.message.contains("deliberate")
            )),
            "{failed:?}"
        );
        let healthy = service
            .run_job("after".to_owned(), "after".to_owned(), 0, |_| {
                Ok("{}".to_owned())
            })
            .expect("start");
        let finished = steps(healthy).await;
        assert!(
            finished
                .iter()
                .any(|step| matches!(step, Step::Finished(_))),
            "{finished:?}"
        );
    }
}

#[cfg(test)]
mod job_owners {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    use lr_proto::v1::JobRef;
    use lr_proto::v1::linux_reflect_server::LinuxReflect;

    use super::{DaemonService, Jobs, Peer};
    use crate::auth::{Action, AuthBackend, PeerIdentity};

    /// Every session user may read and cancel their own jobs; nobody here is
    /// an administrator.
    struct SessionUsers;

    impl AuthBackend for SessionUsers {
        fn check<'a>(
            &'a self,
            _peer: &'a PeerIdentity,
            action: Action,
        ) -> Pin<Box<dyn Future<Output = lr_core::Result<()>> + Send + 'a>> {
            Box::pin(async move {
                if action == Action::JobCancelOther {
                    Err(lr_core::Error::denied(action.id(), "not an administrator"))
                } else {
                    Ok(())
                }
            })
        }
    }

    fn cancel_as(uid: u32, job_id: &str) -> tonic::Request<JobRef> {
        let mut request = tonic::Request::new(JobRef {
            job_id: job_id.to_owned(),
        });
        request
            .extensions_mut()
            .insert(Peer(Arc::new(PeerIdentity::for_uid(uid))));
        request
    }

    /// A job only its owner (or root) cancels; another user needs the
    /// administrator action, and a refused cancel leaves the job running
    /// (R10).
    #[tokio::test]
    async fn only_the_owner_cancels_a_job() {
        let jobs = Arc::new(Jobs::new());
        let service = DaemonService::new(Arc::new(SessionUsers), Arc::clone(&jobs), true);
        let start = |id: &str, owner: u32| {
            service
                .run_job(id.to_owned(), id.to_owned(), owner, |context| {
                    let cancel = context.cancel.clone().expect("a cancel flag");
                    while !cancel.load(Ordering::SeqCst) {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(lr_core::Error::Cancelled)
                })
                .expect("start")
        };
        let _first = start("owned", 1000);
        let refused = service
            .cancel_job(cancel_as(1001, "owned"))
            .await
            .expect_err("another user must not cancel");
        assert_eq!(refused.code(), tonic::Code::PermissionDenied, "{refused}");
        assert!(
            jobs.list()
                .expect("list")
                .iter()
                .any(|job| job.job_id == "owned" && job.state == crate::jobs::JobState::Running),
            "a refused cancel must leave the job running"
        );
        service
            .cancel_job(cancel_as(1000, "owned"))
            .await
            .expect("the owner cancels");

        let _second = start("by-root", 1000);
        service
            .cancel_job(cancel_as(0, "by-root"))
            .await
            .expect("root cancels");
    }
}

#[cfg(test)]
mod request_threads {
    use std::sync::Arc;

    use lr_proto::v1::RestoreSpec;
    use lr_proto::v1::linux_reflect_server::LinuxReflect;

    use super::{DaemonService, Jobs, Peer};
    use crate::auth::PeerIdentity;

    /// A FIFO named as the passphrase file is refused at once; the request
    /// neither waits for a writer nor holds an async request thread (R12).
    #[test]
    fn a_fifo_passphrase_is_refused_without_blocking() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fifo = dir.path().join("passphrase");
        assert!(
            std::process::Command::new("mkfifo")
                .args(["-m", "600"])
                .arg(&fifo)
                .status()
                .expect("mkfifo")
                .success()
        );
        let (sender, receiver) = std::sync::mpsc::channel();
        let passphrase_file = fifo.display().to_string();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            let outcome = runtime.block_on(async move {
                let auth = crate::auth::build(Some("static:all"), true)
                    .await
                    .expect("auth");
                let service = DaemonService::new(auth, Arc::new(Jobs::new()), true);
                let mut request = tonic::Request::new(RestoreSpec {
                    image: "/nonexistent/set/chain/000-full.lrimg".to_owned(),
                    target: "/nonexistent-target".to_owned(),
                    passphrase_file,
                    ..RestoreSpec::default()
                });
                request
                    .extensions_mut()
                    .insert(Peer(Arc::new(PeerIdentity::for_uid(1000))));
                service
                    .prepare_restore(request)
                    .await
                    .map(|_| ())
                    .map_err(|status| status.message().to_owned())
            });
            let _ = sender.send(outcome);
        });
        let outcome = receiver
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the request must not wait on the FIFO");
        let message = outcome.expect_err("a FIFO is not a passphrase file");
        assert!(message.contains("not a regular file"), "{message}");
    }
}

#[cfg(test)]
mod client_named_files {
    use std::sync::Arc;

    use lr_proto::v1::VerifySpec;
    use lr_proto::v1::linux_reflect_server::LinuxReflect;

    use super::{DaemonService, Jobs, Peer};
    use crate::auth::PeerIdentity;

    fn verify_as(uid: u32, spec: VerifySpec) -> tonic::Request<VerifySpec> {
        let mut request = tonic::Request::new(spec);
        request
            .extensions_mut()
            .insert(Peer(Arc::new(PeerIdentity::for_uid(uid))));
        request
    }

    /// Any session user may verify, so the daemon must not read a file of
    /// another user for them, nor skip host-key checks outside development
    /// mode (A4).
    #[tokio::test]
    async fn verify_reads_only_the_callers_files() {
        let auth = crate::auth::build(Some("static:all"), true)
            .await
            .expect("auth");
        let service = DaemonService::new(auth, Arc::new(Jobs::new()), false);
        let spec = VerifySpec {
            image: "sftp://backup@nas.local/backups/set/chain/000-full.lrimg".to_owned(),
            ..VerifySpec::default()
        };
        for (field, named) in [
            (
                "identity",
                VerifySpec {
                    identity: "/etc/hostname".to_owned(),
                    ..spec.clone()
                },
            ),
            (
                "known_hosts",
                VerifySpec {
                    known_hosts: "/etc/hostname".to_owned(),
                    ..spec.clone()
                },
            ),
            (
                "passphrase_file",
                VerifySpec {
                    passphrase_file: "/etc/hostname".to_owned(),
                    ..spec.clone()
                },
            ),
        ] {
            let Err(refused) = service.verify_image(verify_as(4242, named)).await else {
                panic!("{field}: root's file must be refused");
            };
            assert_eq!(refused.code(), tonic::Code::PermissionDenied, "{field}");
            assert!(
                refused.message().contains("belongs to uid 0"),
                "{field}: {refused}"
            );
        }
        let insecure = VerifySpec {
            insecure_ignore_host_key: true,
            ..spec
        };
        let Err(refused) = service.verify_image(verify_as(4242, insecure)).await else {
            panic!("ignoring host keys needs development mode");
        };
        assert_eq!(refused.code(), tonic::Code::PermissionDenied, "{refused}");
    }
}
