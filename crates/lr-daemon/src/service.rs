//! The gRPC service (spec §I).
//!
//! Every method authorizes the peer first, then runs the synchronous engine in
//! a blocking task while progress flows back over the job event bus. Methods
//! that belong to later slices answer `UNIMPLEMENTED` with their slice number
//! so the schema stays stable.

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
use crate::jobs::{JobEvent, JobState as JobStateInner, Jobs};
use crate::status;
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
        }
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

    /// Run a job on a blocking thread, streaming its progress.
    fn run_job<F>(
        &self,
        job_id: String,
        set: String,
        work: F,
    ) -> Result<ReceiverStream<std::result::Result<Progress, Status>>>
    where
        F: FnOnce(EngineContext) -> Result<String> + Send + 'static,
    {
        // Registration publishes Started synchronously. Subscribe first so
        // clients always learn the ID needed to cancel or recover this job.
        let mut events = self.jobs.subscribe();
        let (sink, cancel) = self.jobs.register(&job_id, &set)?;
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
                let terminal = matches!(event, JobEvent::Finished { .. } | JobEvent::Failed { .. });
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
            let outcome = work(context);
            if let Err(error) = jobs.finish(&task_job_id, outcome) {
                tracing::warn!(%error, "cannot record a job outcome");
            }
        });
        Ok(ReceiverStream::new(receiver))
    }
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
    let progress = snapshot.error.as_ref().map(|(code, message)| {
        progress_of(&JobEvent::Failed {
            job_id: snapshot.job_id.clone(),
            code: code.clone(),
            message: message.clone(),
        })
    });
    JobState {
        job_id: snapshot.job_id.clone(),
        set: snapshot.set.clone(),
        state: state.to_owned(),
        progress,
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
            })
            .collect(),
    })
}

#[tonic::async_trait]
impl LinuxReflect for DaemonService {
    type CreateBackupStream = ReceiverStream<std::result::Result<Progress, Status>>;
    type VerifyImageStream = ReceiverStream<std::result::Result<Progress, Status>>;
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
        self.authorize(&request, Action::DiskRead).await?;
        Ok(Response::new(self.set_info(request.get_ref())?))
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
        };
        lr_store::named::validate(&entry).map_err(status::status_of)?;
        let path = lr_store::named::registry_path();
        let mut entries = lr_store::named::load(&path).map_err(status::status_of)?;
        entries.retain(|existing| existing.name != entry.name);
        entries.push(entry);
        entries.sort_by(|left, right| left.name.cmp(&right.name));
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
        self.authorize(&request, Action::DiskRead).await?;
        Ok(Response::new(self.set_info(request.get_ref())?))
    }

    async fn create_backup(
        &self,
        request: GrpcRequest<BackupSpec>,
    ) -> std::result::Result<Response<Self::CreateBackupStream>, Status> {
        self.authorize(&request, Action::BackupCreate).await?;
        let spec = request.get_ref().clone();
        // The same conversion the CLI's direct route uses (R31).
        let job = lr_request::backup_job(&spec).map_err(status::status_of)?;
        let job_id = if spec.job_id.is_empty() {
            format!("backup-{}", job.request.image_uuid)
        } else {
            spec.job_id.clone()
        };
        let stream = self
            .run_job(job_id, spec.set.clone(), move |context| {
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
        self.authorize(&request, Action::DiskRead).await?;
        let spec = request.get_ref().clone();
        let encryption = lr_engine::options::restore_encryption(
            (!spec.passphrase_file.is_empty())
                .then(|| PathBuf::from(&spec.passphrase_file))
                .as_deref(),
        )
        .map_err(status::status_of)?;
        let verify = lr_engine::verify::VerifyRequest {
            image: spec.image.clone(),
            encryption,
            chain: spec.chain,
            destination_options: lr_store::DestinationOptions {
                set_name: String::new(),
                identity: (!spec.identity.is_empty()).then(|| PathBuf::from(&spec.identity)),
                known_hosts: (!spec.known_hosts.is_empty())
                    .then(|| PathBuf::from(&spec.known_hosts)),
                insecure_ignore_host_key: spec.insecure_ignore_host_key,
            },
            context: EngineContext::silent(),
        };
        // Every verification is its own job with its own set key, so one
        // user's long verification never blocks another's; a counting
        // semaphore bounds how many read at once (A5).
        let id = format!(
            "verify-{}",
            lr_core::Id::generate().map_err(|error| status::status_of(Error::Io(error)))?
        );
        let slots = Arc::clone(&self.verifications);
        let stream = self
            .run_job(id.clone(), id, move |context| {
                let _slot = slots.acquire();
                let mut verify = verify;
                verify.context = context;
                let mut report = lr_engine::verify::verify_image(&verify)?;
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

    async fn prepare_restore(
        &self,
        request: GrpcRequest<RestoreSpec>,
    ) -> std::result::Result<Response<RestorePlanInfo>, Status> {
        self.authorize(&request, Action::RestorePrepare).await?;
        let spec = request.get_ref().clone();
        let encryption = lr_engine::options::restore_encryption(
            (!spec.passphrase_file.is_empty())
                .then(|| PathBuf::from(&spec.passphrase_file))
                .as_deref(),
        )
        .map_err(status::status_of)?;
        let mut prepare =
            lr_engine::restore::PrepareRequest::new(&spec.image, &spec.target, encryption);
        prepare.identity = (!spec.identity.is_empty()).then(|| PathBuf::from(&spec.identity));
        prepare.known_hosts =
            (!spec.known_hosts.is_empty()).then(|| PathBuf::from(&spec.known_hosts));
        prepare.insecure_ignore_host_key = spec.insecure_ignore_host_key;
        prepare.merge = spec.merge;
        prepare.replace_partition_table = spec.replace_partition_table;
        if spec.ttl_secs > 0 {
            prepare.ttl = std::time::Duration::from_secs(spec.ttl_secs.min(600));
        }
        let plan = lr_engine::restore::prepare_restore(&prepare).map_err(status::status_of)?;
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
        self.authorize(&request, Action::RestoreApply).await?;
        let spec = request.get_ref().clone();
        let encryption = lr_engine::options::restore_encryption(
            (!spec.passphrase_file.is_empty())
                .then(|| PathBuf::from(&spec.passphrase_file))
                .as_deref(),
        )
        .map_err(status::status_of)?;
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
            .run_job(job_id, "restore".to_owned(), move |context| {
                let outcome =
                    lr_engine::restore::apply_restore(&lr_engine::restore::ApplyRequest {
                        context,
                        ..apply
                    })?;
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
        self.authorize(&request, Action::DiskRead).await?;
        let snapshot = self
            .jobs
            .cancel(&request.get_ref().job_id)
            .map_err(status::status_of)?;
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
        self.authorize(&request, Action::ExportManage).await?;
        let spec = request.get_ref().clone();
        let exports = Arc::clone(&self.exports);
        let state =
            tokio::task::spawn_blocking(move || DaemonService::export_with(&exports, &spec))
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
        self.authorize(&request, Action::ScheduleManage).await?;
        let spec = request.get_ref().clone();
        let report = tokio::task::spawn_blocking(move || {
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
    fn set_info(&self, spec: &SetRef) -> std::result::Result<SetInfo, Status> {
        // The caller's SSH options reach the destination (A6); a named
        // destination replaces them with its own.
        let options = lr_store::DestinationOptions {
            set_name: spec.set.clone(),
            identity: (!spec.identity.is_empty()).then(|| PathBuf::from(&spec.identity)),
            known_hosts: (!spec.known_hosts.is_empty()).then(|| PathBuf::from(&spec.known_hosts)),
            insecure_ignore_host_key: spec.insecure_ignore_host_key,
        };
        let destination = lr_store::open(&spec.dest, &options).map_err(status::status_of)?;
        if spec.set.is_empty() {
            // No set named: list the sets instead of opening (and creating)
            // an unnamed one.
            let sets = destination.list_set_names().map_err(status::status_of)?;
            return Ok(SetInfo {
                sets,
                ..SetInfo::default()
            });
        }
        let set = destination
            .open_existing_set(&lr_core::SetId::ZERO)
            .map_err(status::status_of)?;
        let loaded = lr_engine::catalog::load(
            &*destination,
            &set,
            &spec.set,
            lr_engine::backup::now_unix(),
        )
        .map_err(status::status_of)?;
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
