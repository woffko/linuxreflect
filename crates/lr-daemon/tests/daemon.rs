//! Daemon IPC tests: the real binary, a temporary socket, and the generated
//! client (spec §K S11).
//!
//! The daemon always runs as a separate process, so `daemon run` itself, the
//! socket setup and the interceptor are all exercised.

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use lr_proto::v1::linux_reflect_client::LinuxReflectClient;
use lr_proto::v1::{
    BackupSpec, JobRef, Progress, Request, RestoreSpec, SetRef, SourceRef, VerifySpec,
    progress::Step,
};
use tonic::transport::{Channel, Endpoint};

/// An explicit key with unsafe permissions stops startup before the socket is
/// bound, and the environment path is never used as a fallback.
#[test]
fn invalid_explicit_key_fails_before_serving_without_environment_fallback() {
    let dir = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .expect("private directory");
    let key = dir.path().join("unsafe.key");
    std::fs::write(&key, [0_u8; 32]).expect("fixture");
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644))
        .expect("fixture permissions");
    let fallback = dir.path().join("environment.key");
    let socket = dir.path().join("daemon.sock");
    let mut child = Command::new(env!("CARGO_BIN_EXE_linuxreflect-daemon"))
        .arg("--token-secret-file")
        .arg(&key)
        .arg("--socket")
        .arg(&socket)
        .env("LR_TOKEN_SECRET_FILE", &fallback)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait().expect("status") {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("invalid key did not stop daemon startup");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(!status.success());
    let mut error = String::new();
    child
        .stderr
        .take()
        .expect("stderr")
        .read_to_string(&mut error)
        .expect("read stderr");
    assert!(error.contains("mode-0600"), "expected key validation error");
    assert!(!socket.exists(), "must reject before creating a listener");
    assert!(!fallback.exists(), "must not initialize a fallback key");
}

/// A daemon process plus its temporary state.
struct Daemon {
    child: Child,
    socket: PathBuf,
    _dir: tempfile::TempDir,
}

impl Daemon {
    fn start(auth: &str) -> Self {
        let dir = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .expect("private daemon directory");
        let socket = dir.path().join("daemon.sock");
        let secret = dir.path().join("token.key");
        let unused_env_secret = dir.path().join("environment-token.key");
        let binary = env!("CARGO_BIN_EXE_linuxreflect-daemon");
        let child = Command::new(binary)
            .env("LR_TOKEN_SECRET_FILE", &unused_env_secret)
            .args([
                "--socket",
                &socket.display().to_string(),
                "--socket-group",
                "lr-daemon-test",
                "--socket-mode",
                "0666",
                "--no-create-group",
                "--dev-mode",
                "--auth",
                auth,
                "--sd-notify=no",
                "--token-secret-file",
                &secret.display().to_string(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn daemon");
        let mut daemon = Self {
            child,
            socket,
            _dir: dir,
        };
        if !daemon.wait_for_socket() {
            let error = daemon.stderr();
            panic!("daemon did not start: {error}");
        }
        assert!(secret.is_file(), "CLI-selected key must be created");
        assert!(
            !unused_env_secret.exists(),
            "the CLI key path must take precedence over the environment"
        );
        daemon
    }

    fn wait_for_socket(&mut self) -> bool {
        for _ in 0..50 {
            if self.socket.exists() {
                return true;
            }
            if let Ok(Some(_)) = self.child.try_wait() {
                return false;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
    }

    fn stderr(&mut self) -> String {
        use std::io::Read;
        let mut text = String::new();
        if let Some(mut pipe) = self.child.stderr.take() {
            let _ = pipe.read_to_string(&mut text);
        }
        text
    }

    async fn client(&self) -> LinuxReflectClient<Channel> {
        let endpoint =
            Endpoint::try_from(format!("unix://{}", self.socket.display())).expect("endpoint");
        LinuxReflectClient::connect(endpoint)
            .await
            .expect("connect")
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn uid() -> u32 {
    String::from_utf8_lossy(&Command::new("id").arg("-u").output().expect("id").stdout)
        .trim()
        .parse()
        .expect("uid")
}

/// A 64 MiB ext4 image with a little data, unprivileged.
fn source_image(dir: &Path) -> Option<PathBuf> {
    for tool in ["mkfs.ext4", "debugfs"] {
        if !Command::new("which")
            .arg(tool)
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
        {
            eprintln!("{tool} missing; skipping");
            return None;
        }
    }
    let source = dir.join("source.img");
    let file = std::fs::File::create(&source).expect("create");
    file.set_len(64 * 1024 * 1024).expect("size");
    drop(file);
    let status = Command::new("mkfs.ext4")
        .args(["-F", "-q", &source.display().to_string()])
        .status()
        .expect("mkfs.ext4");
    assert!(status.success(), "mkfs.ext4 failed");
    Some(source)
}

fn finished_summary(progress: &[Progress]) -> Option<&str> {
    progress.iter().find_map(|step| match &step.step {
        Some(Step::Finished(finished)) => Some(finished.summary_json.as_str()),
        _ => None,
    })
}

fn failure_code(progress: &[Progress]) -> Option<&str> {
    progress.iter().find_map(|step| match &step.step {
        Some(Step::Failure(failure)) => Some(failure.code.as_str()),
        _ => None,
    })
}

/// The `image_uri` field of a block backup report.
fn summary_image_uri(summary: &str) -> String {
    let value: serde_json::Value = serde_json::from_str(summary).expect("report json");
    assert_eq!(
        value.get("mode").and_then(|mode| mode.as_str()),
        Some("block"),
        "{summary}"
    );
    value
        .get("image_uri")
        .and_then(|uri| uri.as_str())
        .expect("image_uri")
        .to_owned()
}

#[tokio::test]
async fn version_is_unauthenticated_and_later_slices_are_unimplemented() {
    let daemon = Daemon::start("static:all");
    let mut client = daemon.client().await;

    let version = client
        .get_version(Request {
            unused: String::new(),
        })
        .await
        .expect("version")
        .into_inner();
    assert_eq!(version.format_major, lr_format::FORMAT_MAJOR);
    assert!(version.dev_mode, "the test starts the daemon in dev mode");

    // S13 is implemented, so an export of a nonexistent chain reports the
    // image rather than `unimplemented` (the real export needs root and the
    // NBD tools, which the root-gated lr-export suite covers).
    let work = tempfile::tempdir().expect("tempdir");
    let missing = work.path().join("set/chain/000-full.lrimg");
    let error = client
        .export_image(lr_proto::v1::ExportSpec {
            image: missing.display().to_string(),
            at: work.path().join("mnt").display().to_string(),
            kind: "nbd".to_owned(),
            ..lr_proto::v1::ExportSpec::default()
        })
        .await
        .expect_err("a nonexistent image cannot be exported");
    assert_ne!(
        error.code(),
        tonic::Code::Unimplemented,
        "S13 has a real handler now"
    );
    assert!(!error.message().is_empty());

    // S14 is implemented as well: retention on an empty set succeeds with an
    // empty report (and says so) instead of answering `unimplemented`.
    let work = tempfile::tempdir().expect("tempdir");
    let progress = client
        .apply_retention(lr_proto::v1::RetentionSpec {
            dest: work.path().join("backups").display().to_string(),
            set: "missing".to_owned(),
            keep_chains: 1,
            dry_run: false,
        })
        .await
        .expect("pruning an empty set is a no-op")
        .into_inner();
    let summary = match progress.step {
        Some(lr_proto::v1::progress::Step::Finished(finished)) => finished.summary_json,
        other => panic!("expected a finished step, got {other:?}"),
    };
    assert!(summary.contains("complete_chains"), "{summary}");

    // The schedule methods answer with real job lists.
    let schedule = client
        .get_schedule(lr_proto::v1::ScheduleSpec {
            config: work.path().join("absent.toml").display().to_string(),
            ..lr_proto::v1::ScheduleSpec::default()
        })
        .await
        .expect_err("a missing config is an error, not an empty schedule");
    assert_eq!(schedule.code(), tonic::Code::FailedPrecondition);
    assert!(
        schedule.message().contains("absent.toml"),
        "{}",
        schedule.message()
    );
}

#[tokio::test]
async fn the_static_backend_allows_and_denies_uids() {
    let daemon = Daemon::start(&format!("static:{}", uid()));
    let mut client = daemon.client().await;
    let disks = client
        .list_disks(Request {
            unused: String::new(),
        })
        .await
        .expect("allowed uid")
        .into_inner();
    assert!(!disks.json.is_empty());
    drop(client);
    drop(daemon);

    let denied_uid = if uid() == 0 { 12345 } else { 0 };
    let daemon = Daemon::start(&format!("static:{denied_uid}"));
    let mut client = daemon.client().await;
    let error = client
        .list_disks(Request {
            unused: String::new(),
        })
        .await
        .expect_err("another uid must be denied");
    assert_eq!(error.code(), tonic::Code::PermissionDenied);
    assert!(error.message().contains("E_DENIED"), "{}", error.message());
}

#[tokio::test]
async fn a_backup_runs_over_the_socket_and_reports_progress() {
    let daemon = Daemon::start(&format!("static:{}", uid()));
    let work = tempfile::tempdir().expect("workdir");
    let Some(source) = source_image(work.path()) else {
        return;
    };
    let dest = work.path().join("out");
    let mut client = daemon.client().await;

    let mut events = client
        .watch_events(Request {
            unused: String::new(),
        })
        .await
        .expect("watch")
        .into_inner();

    let mut stream = client
        .create_backup(BackupSpec {
            source: source.display().to_string(),
            dest: dest.display().to_string(),
            set: "daemon-set".to_owned(),
            member_type: "full".to_owned(),
            chunk_size: "1MiB".to_owned(),
            compress: "none".to_owned(),
            no_encrypt: true,
            on_bad_sector: "abort".to_owned(),
            ..BackupSpec::default()
        })
        .await
        .expect("create_backup")
        .into_inner();

    let mut progress = Vec::new();
    while let Some(step) = stream.message().await.expect("stream") {
        progress.push(step);
    }
    let summary = finished_summary(&progress)
        .expect("a finished step")
        .to_owned();
    assert!(summary.contains("image_uri"), "{summary}");
    assert!(failure_code(&progress).is_none(), "{progress:?}");

    let event = events
        .message()
        .await
        .expect("event stream")
        .expect("an event");
    assert!(!event.kind.is_empty());

    let sets = client
        .list_sets(SetRef {
            dest: dest.display().to_string(),
            set: "daemon-set".to_owned(),
            ..SetRef::default()
        })
        .await
        .expect("list_sets")
        .into_inner();
    assert_eq!(sets.chains.len(), 1, "{sets:?}");

    // Without a set name the daemon lists the sets instead, and browsing the
    // folder creates nothing.
    let before: Vec<_> = std::fs::read_dir(&dest)
        .expect("destination")
        .map(|entry| entry.expect("entry").file_name())
        .collect();
    let listing = client
        .list_sets(SetRef {
            dest: dest.display().to_string(),
            ..SetRef::default()
        })
        .await
        .expect("list set names")
        .into_inner();
    assert_eq!(listing.sets, ["daemon-set"], "{listing:?}");
    assert!(listing.chains.is_empty());
    let after: Vec<_> = std::fs::read_dir(&dest)
        .expect("destination")
        .map(|entry| entry.expect("entry").file_name())
        .collect();
    assert_eq!(before.len(), after.len(), "listing must not create a set");

    let image_uri = summary_image_uri(&summary);
    let rebuilt = client
        .rebuild_catalog(SetRef {
            dest: dest.display().to_string(),
            set: "daemon-set".to_owned(),
            ..SetRef::default()
        })
        .await
        .expect("rebuild")
        .into_inner();
    assert!(matches!(rebuilt.step, Some(Step::Finished(_))));

    let mut verify = client
        .verify_image(VerifySpec {
            image: image_uri.clone(),
            chain: true,
            ..VerifySpec::default()
        })
        .await
        .expect("verify")
        .into_inner();
    let mut verified = Vec::new();
    while let Some(step) = verify.message().await.expect("verify stream") {
        verified.push(step);
    }
    let verify_summary = finished_summary(&verified).expect("verify finished");
    assert!(verify_summary.contains("chunks"), "{verify_summary}");

    let target = work.path().join("target.img");
    let file = std::fs::File::create(&target).expect("target");
    file.set_len(64 * 1024 * 1024).expect("target size");
    drop(file);
    let plan = client
        .prepare_restore(RestoreSpec {
            image: image_uri,
            target: target.display().to_string(),
            ..RestoreSpec::default()
        })
        .await
        .expect("prepare")
        .into_inner();
    assert!(!plan.token.is_empty());
    assert_eq!(plan.members.len(), 1);

    let error = client
        .get_job(JobRef {
            job_id: "nope".to_owned(),
        })
        .await
        .expect_err("unknown job");
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert!(error.message().contains("no job"), "{}", error.message());
}

#[tokio::test]
async fn probe_source_reports_a_plan() {
    let daemon = Daemon::start(&format!("static:{}", uid()));
    let work = tempfile::tempdir().expect("workdir");
    let Some(source) = source_image(work.path()) else {
        return;
    };
    let mut client = daemon.client().await;
    let plan = client
        .probe_source(SourceRef {
            source: source.display().to_string(),
        })
        .await
        .expect("probe")
        .into_inner();
    assert_eq!(plan.provider, "offline");
    assert_eq!(plan.consistency.to_lowercase(), "offline");
}

#[tokio::test]
async fn disconnected_backup_can_be_cancelled_and_the_set_reused() {
    use std::io::Write;

    let daemon = Daemon::start(&format!("static:{}", uid()));
    let work = tempfile::tempdir().expect("workdir");
    let source = work.path().join("source");
    std::fs::create_dir(&source).expect("source directory");
    // Allocated data, not a sparse hole: leave enough real copying work to
    // cancel after the first byte-progress event, without artificial RPC hooks.
    let block = vec![0x5a; 1024 * 1024];
    let mut file = std::fs::File::create(source.join("data.bin")).expect("source file");
    for _ in 0..512 {
        file.write_all(&block).expect("populate source");
    }
    drop(file);
    let dest = work.path().join("out");
    let spec = BackupSpec {
        source: source.display().to_string(),
        dest: dest.display().to_string(),
        set: "cancel-retry".into(),
        mode: "file".into(),
        member_type: "full".into(),
        compress: "none".into(),
        no_encrypt: true,
        chunk_size: "1MiB".into(),
        on_bad_sector: "abort".into(),
        ..BackupSpec::default()
    };
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut client = daemon.client().await;
        let mut stream = client.create_backup(spec.clone()).await.expect("start backup").into_inner();
        let mut job_id = None;
        loop {
            let progress = stream.message().await.expect("progress transport").expect("progress before EOF");
            match progress.step {
                Some(Step::Started(started)) => job_id = Some(started.job_id),
                Some(Step::Bytes(bytes)) if bytes.done > 0 => break,
                Some(Step::Finished(_)) | Some(Step::Failure(_)) => panic!("job terminated before cancellation: {progress:?}"),
                _ => {}
            }
        }
        let job = JobRef { job_id: job_id.expect("Started precedes byte progress") };
        drop(stream);
        drop(client);

        let mut client = daemon.client().await;
        let running = client.get_job(job.clone()).await.expect("recover job after disconnect").into_inner();
        assert_eq!(running.state, "running", "disconnect must not erase or terminate the job");
        client.cancel_job(job.clone()).await.expect("request cancellation");
        loop {
            let state = client.get_job(job.clone()).await.expect("observe cancellation").into_inner();
            if state.state == "cancelled" {
                assert!(matches!(state.progress.and_then(|p| p.step), Some(Step::Failure(f)) if f.code == "E_CANCELLED"));
                break;
            }
            assert!(state.state == "running" || state.state == "pending", "unexpected terminal state: {state:?}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Retrying the same set must not encounter a leaked set lock. Use a
        // separate small source so the retry need not copy the large fixture.
        let retry_source = work.path().join("retry-source");
        std::fs::create_dir(&retry_source).expect("retry directory");
        std::fs::write(retry_source.join("hello.txt"), b"retry after cancellation\n").expect("retry data");
        let mut retry = client.create_backup(BackupSpec {
            source: retry_source.display().to_string(),
            ..spec
        }).await.expect("retry on same daemon and set").into_inner();
        let mut progress = Vec::new();
        while let Some(step) = retry.message().await.expect("retry stream") {
            progress.push(step);
        }
        assert!(failure_code(&progress).is_none(), "{progress:?}");
        assert!(finished_summary(&progress).is_some(), "retry must finish");
    }).await.expect("cancel/retry must terminate within its deadline");

    // The interrupted backup must never modify the source.
    use std::io::Read;
    let mut file = std::fs::File::open(source.join("data.bin")).expect("read source");
    let mut actual = vec![0; block.len()];
    for _ in 0..512 {
        file.read_exact(&mut actual)
            .expect("source length unchanged");
        assert_eq!(actual, block);
    }
    assert_eq!(file.read(&mut actual[..1]).expect("source EOF"), 0);
}

/// A file-mode source with `mib` MiB of allocated data, so a backup of it
/// is still running when the test acts.
fn large_source(dir: &Path, mib: usize) -> PathBuf {
    use std::io::Write;
    let source = dir.join("large-source");
    std::fs::create_dir(&source).expect("source directory");
    let block = vec![0x5a; 1024 * 1024];
    let mut file = std::fs::File::create(source.join("data.bin")).expect("source file");
    for _ in 0..mib {
        file.write_all(&block).expect("populate source");
    }
    source
}

fn slow_spec(source: &Path, dest: &Path, set: &str) -> BackupSpec {
    BackupSpec {
        source: source.display().to_string(),
        dest: dest.display().to_string(),
        set: set.into(),
        mode: "file".into(),
        member_type: "full".into(),
        compress: "none".into(),
        no_encrypt: true,
        chunk_size: "1MiB".into(),
        on_bad_sector: "abort".into(),
        ..BackupSpec::default()
    }
}

fn signal_daemon(daemon: &Daemon, signal: &str) {
    let status = Command::new("kill")
        .args([signal, &daemon.child.id().to_string()])
        .status()
        .expect("kill");
    assert!(status.success(), "kill {signal}");
}

/// Start a slow backup and return its stream once it is copying.
async fn copying(
    client: &mut LinuxReflectClient<Channel>,
    spec: BackupSpec,
) -> tonic::Streaming<Progress> {
    let mut stream = client
        .create_backup(spec)
        .await
        .expect("start backup")
        .into_inner();
    loop {
        let progress = stream
            .message()
            .await
            .expect("progress transport")
            .expect("progress before EOF");
        match progress.step {
            Some(Step::Bytes(bytes)) if bytes.done > 0 => return stream,
            Some(Step::Finished(_) | Step::Failure(_)) => {
                panic!("job terminated before the test acted: {progress:?}")
            }
            _ => {}
        }
    }
}

async fn rest_of(stream: &mut tonic::Streaming<Progress>) -> Vec<Progress> {
    let mut progress = Vec::new();
    while let Some(step) = stream.message().await.expect("progress stream") {
        progress.push(step);
    }
    progress
}

fn wait_for_exit(daemon: &mut Daemon) -> std::process::ExitStatus {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = daemon.child.try_wait().expect("daemon status") {
            return status;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the daemon did not exit after its jobs finished"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// SIGTERM stops admission but lets the running job finish; then the daemon
/// exits cleanly (D-107).
#[tokio::test]
async fn sigterm_waits_for_the_running_job_and_refuses_new_ones() {
    let mut daemon = Daemon::start(&format!("static:{}", uid()));
    let work = tempfile::tempdir().expect("workdir");
    let source = large_source(work.path(), 1024);
    let dest = work.path().join("out");
    let mut client = daemon.client().await;
    let mut stream = copying(&mut client, slow_spec(&source, &dest, "drain-a")).await;

    signal_daemon(&daemon, "-TERM");
    // Admission closes as soon as the signal is handled.
    let small = work.path().join("small");
    std::fs::create_dir(&small).expect("small source");
    std::fs::write(small.join("a.txt"), b"a").expect("small file");
    let refused = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match client
                .create_backup(slow_spec(&small, &dest, "drain-b"))
                .await
            {
                Err(status) if status.message().contains("stopping") => return status,
                Err(status) => panic!("unexpected refusal: {status:?}"),
                Ok(response) => {
                    // Admitted before the signal was handled; let it finish.
                    rest_of(&mut response.into_inner()).await;
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
        }
    })
    .await
    .expect("the stopping daemon refuses new jobs");
    assert!(refused.message().contains("stopping"), "{refused:?}");
    assert!(
        daemon.child.try_wait().expect("status").is_none(),
        "the daemon must not exit while a job runs"
    );

    let progress = rest_of(&mut stream).await;
    assert!(
        finished_summary(&progress).is_some(),
        "the running job completes: {progress:?}"
    );
    drop(client);
    let status = wait_for_exit(&mut daemon);
    assert!(status.success(), "{status:?}");
}

/// A second signal cancels the running job instead of waiting for it.
#[tokio::test]
async fn a_second_sigterm_cancels_the_running_job() {
    let mut daemon = Daemon::start(&format!("static:{}", uid()));
    let work = tempfile::tempdir().expect("workdir");
    let source = large_source(work.path(), 1024);
    let dest = work.path().join("out");
    let mut client = daemon.client().await;
    let mut stream = copying(&mut client, slow_spec(&source, &dest, "drain-c")).await;

    signal_daemon(&daemon, "-TERM");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(daemon.child.try_wait().expect("status").is_none());
    signal_daemon(&daemon, "-TERM");
    let progress = rest_of(&mut stream).await;
    assert_eq!(failure_code(&progress), Some("E_CANCELLED"), "{progress:?}");
    drop(client);
    let status = wait_for_exit(&mut daemon);
    assert!(status.success(), "{status:?}");
}
