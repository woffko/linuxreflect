//! Critical daemon history contracts over the real local gRPC transport.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use lr_engine::backup::BackupRequest;
use lr_engine::file::{FileBackupOptions, backup_file};
use lr_engine::keys::Encryption;
use lr_proto::v1 as p;
use p::linux_reflect_client::LinuxReflectClient;
use tonic::transport::{Channel, Endpoint};

const DAEMON: &str = env!("CARGO_BIN_EXE_linuxreflect-daemon");

struct Fixture {
    root: tempfile::TempDir,
    config: PathBuf,
    socket: PathBuf,
    ledger: PathBuf,
}

impl Fixture {
    fn new(ledger_bytes: u64, result_bytes: usize, retained_results: usize) -> Self {
        let root_path = std::env::var_os("LR_TEST_HISTORY_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/var/tmp"));
        let root = tempfile::Builder::new()
            .prefix("lr-daemon-history-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(root_path)
            .expect("private local fixture");
        let scratch = root.path().join("scratch");
        let ledger = root.path().join("ledger");
        for path in [&scratch, &ledger] {
            std::fs::create_dir(path).expect("fixture directory");
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                .expect("private fixture mode");
        }
        let config = root.path().join("policy.json");
        let value = serde_json::json!({
            "schema_version": 1,
            "capture": { "scratch_directory": scratch, "max_raw_bytes": 64 * 1024 * 1024,
                         "headroom_bytes": 0 },
            "history": { "history_directory": ledger, "max_receipt_bytes": 64 * 1024,
                         "max_members": 16, "max_entries": 16,
                         "max_total_ledger_bytes": ledger_bytes },
            "max_concurrent_operations": 1, "max_result_bytes": result_bytes,
            "max_retained_results": retained_results,
            "max_retained_result_bytes": result_bytes * retained_results
        });
        std::fs::write(&config, serde_json::to_vec(&value).expect("policy JSON"))
            .expect("fixture policy");
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600))
            .expect("private policy mode");
        let socket = root.path().join("daemon.sock");
        Self {
            root,
            config,
            socket,
            ledger,
        }
    }

    fn command(&self, enabled: bool, allowed_uid: u32) -> Command {
        let mut command = Command::new(DAEMON);
        command.args([
            "--socket-group",
            "lr-daemon-history-test",
            "--no-create-group",
            "--socket-mode",
            "0600",
            "--dev-mode",
            "--sd-notify=no",
        ]);
        command
            .arg("--auth")
            .arg(format!("static:{allowed_uid}"))
            .arg("--socket")
            .arg(&self.socket)
            .arg("--token-secret-file")
            .arg(self.root.path().join("token.key"))
            .arg("--destinations-file")
            .arg(self.root.path().join("destinations.toml"))
            .env(
                "LR_TOKEN_SECRET_FILE",
                self.root.path().join("unused-environment.key"),
            )
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        if enabled {
            command
                .arg("--verification-history-config")
                .arg(&self.config);
        }
        command
    }

    fn start(&self, enabled: bool) -> Daemon {
        let mut daemon = Daemon(
            self.command(enabled, lr_unsafe::effective_uid())
                .spawn()
                .expect("start own test daemon"),
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while !self.socket.exists() {
            assert!(
                daemon.0.try_wait().expect("daemon status").is_none(),
                "daemon stopped"
            );
            assert!(Instant::now() < deadline, "daemon startup timeout");
            std::thread::sleep(Duration::from_millis(10));
        }
        daemon
    }

    async fn client(&self) -> LinuxReflectClient<Channel> {
        LinuxReflectClient::connect(
            Endpoint::try_from(format!("unix://{}", self.socket.display())).expect("endpoint"),
        )
        .await
        .expect("local gRPC client")
    }
}

struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn file_image(root: &Path) -> (PathBuf, PathBuf) {
    let source = root.join("tree");
    std::fs::create_dir(&source).expect("tree fixture");
    std::fs::write(source.join("payload.txt"), vec![b'h'; 32 * 1024]).expect("fixture payload");
    let dest = root.join("backups");
    let request = BackupRequest::new(&source, &dest, "history-test", Encryption::NoEncrypt)
        .expect("file request");
    let report = backup_file(&request, &FileBackupOptions::default()).expect("file backup");
    (report.image_path, dest.join("history-test/catalog.json"))
}

async fn attempt(
    client: &mut LinuxReflectClient<Channel>,
    image: &Path,
    chain: bool,
) -> (String, p::VerificationResult) {
    let mut stream = client
        .verify_image_with_history(p::VerifySpec {
            image: image.display().to_string(),
            chain,
            ..p::VerifySpec::default()
        })
        .await
        .expect("captured job accepted")
        .into_inner();
    let mut id = None;
    let mut result = None;
    while let Some(item) = stream.message().await.expect("captured stream") {
        match item.step.expect("typed step") {
            p::verification_progress::Step::Progress(p::Progress {
                step: Some(p::progress::Step::Started(started)),
            }) => {
                assert!(id.replace(started.job_id).is_none());
            }
            p::verification_progress::Step::Result(value) => {
                assert!(result.replace(value).is_none(), "only one terminal result");
            }
            p::verification_progress::Step::Progress(p::Progress {
                step: Some(p::progress::Step::Failure(failure)),
            }) => panic!("unexpected general failure: {failure:?}"),
            _ => {}
        }
    }
    let id = id.expect("started before terminal");
    let result = result.expect("one terminal captured result");
    assert_eq!(
        client
            .get_verification_result(p::JobRef { job_id: id.clone() })
            .await
            .expect("reconnect result")
            .into_inner(),
        result,
        "stream and retained result share one canonical observation"
    );
    (id, result)
}

async fn history(
    client: &mut LinuxReflectClient<Channel>,
) -> (
    p::VerificationHistoryAvailability,
    Vec<p::VerificationReceipt>,
) {
    let mut stream = client
        .list_verification_history(p::Request::default())
        .await
        .expect("admin inspection")
        .into_inner();
    let mut state = None;
    let mut receipts = Vec::new();
    while let Some(item) = stream.message().await.expect("history stream") {
        match item.item.expect("typed item") {
            p::verification_history_item::Item::State(value) => {
                assert!(state.replace(value.availability).is_none());
            }
            p::verification_history_item::Item::Receipt(value) => receipts.push(value),
        }
    }
    (
        p::VerificationHistoryAvailability::try_from(state.expect("availability")).expect("enum"),
        receipts,
    )
}

#[test]
fn invalid_policy_refuses_startup_before_socket_token_or_ledger_effects() {
    let fixture = Fixture::new(1024 * 1024, 64 * 1024, 4);
    std::fs::write(&fixture.config, b"{}").expect("invalid fixture policy");
    let mut daemon = Daemon(
        fixture
            .command(true, lr_unsafe::effective_uid())
            .spawn()
            .expect("start refused daemon"),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = daemon.0.try_wait().expect("status") {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "invalid policy must fail without blocking"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(!status.success());
    for path in [
        &fixture.socket,
        &fixture.root.path().join("token.key"),
        &fixture.root.path().join("unused-environment.key"),
        &fixture.ledger.join(".history.lock"),
    ] {
        assert!(!path.exists(), "no startup side effect");
    }
}

#[tokio::test]
async fn typed_attempts_reconnect_and_historical_receipts_do_not_change_catalog() {
    let fixture = Fixture::new(1024 * 1024, 64 * 1024, 4);
    let (image, catalog) = file_image(fixture.root.path());
    let before = std::fs::read(&catalog).expect("original catalog");
    let daemon = fixture.start(true);
    let mut client = fixture.client().await;
    assert_eq!(
        history(&mut client).await.0,
        p::VerificationHistoryAvailability::Unknown,
        "a missing permanent lock is unknown, not empty"
    );
    assert!(
        !fixture.ledger.join(".history.lock").exists(),
        "inspection is read-only"
    );
    let mut results = Vec::new();
    for chain in [false, true] {
        let (id, result) = attempt(&mut client, &image, chain).await;
        let observation = result.observation.as_ref().expect("observation");
        assert_eq!(
            observation.outcome,
            Some(p::verification_observation::Outcome::Integrity(
                p::VerificationIntegrity::IntegrityVerified as i32
            ))
        );
        assert_eq!(
            observation.requested_scope,
            if chain {
                p::VerificationRecoveryScope::EveryMember
            } else {
                p::VerificationRecoveryScope::SelectedRecoveryPoint
            } as i32
        );
        assert_eq!(
            observation.content_coverage,
            Some(if chain {
                p::VerificationContentCoverage::FileEveryTreeReferences
            } else {
                p::VerificationContentCoverage::FileSelectedTreeReferences
            } as i32)
        );
        assert_eq!(
            observation.members[0]
                .raw_digest
                .as_ref()
                .expect("raw digest")
                .len(),
            32
        );
        assert_eq!(
            client
                .get_job(p::JobRef { job_id: id.clone() })
                .await
                .expect("legacy projection")
                .into_inner()
                .state,
            "finished"
        );
        results.push((id, result));
    }
    assert_eq!(
        std::fs::read(&catalog).expect("catalog after attempts"),
        before
    );
    let (state, receipts) = history(&mut client).await;
    assert_eq!(state, p::VerificationHistoryAvailability::Available);
    assert_eq!(receipts.len(), 2);
    for (_, result) in &results {
        let Some(p::verification_recording_outcome::Outcome::Recorded(recorded)) =
            &result.recording.as_ref().expect("recording").outcome
        else {
            panic!("recorded");
        };
        let receipt = receipts
            .iter()
            .find(|receipt| receipt.receipt_id == recorded.receipt_id)
            .expect("matching receipt");
        assert_eq!(receipt.observation, result.observation);
    }

    // Restart only our fixture daemon: receipt loading cannot recreate the
    // original transient job/publisher acknowledgement.
    drop(client);
    drop(daemon);
    if fixture.socket.exists() {
        std::fs::remove_file(&fixture.socket).expect("stale test socket");
    }
    let _restarted = fixture.start(true);
    let mut client = fixture.client().await;
    assert!(
        client
            .get_verification_result(p::JobRef {
                job_id: results[0].0.clone()
            })
            .await
            .is_err()
    );
    assert_eq!(history(&mut client).await.1, receipts);
}

#[tokio::test]
async fn integrity_recording_and_incomplete_job_states_are_not_conflated() {
    let fixture = Fixture::new(1, 64 * 1024, 4);
    let (image, _) = file_image(fixture.root.path());
    let _daemon = fixture.start(true);
    let mut client = fixture.client().await;
    let (id, result) = attempt(&mut client, &image, false).await;
    assert!(matches!(
        result.observation.as_ref().expect("facts").outcome,
        Some(p::verification_observation::Outcome::Integrity(_))
    ));
    assert!(
        result.report_json.is_some(),
        "integrity report remains available"
    );
    assert_eq!(
        result.recording.expect("recording").outcome,
        Some(p::verification_recording_outcome::Outcome::NotRecorded(
            p::VerificationNotRecorded {
                reason: p::VerificationHistoryFailure::QuotaExceeded as i32,
            }
        ))
    );
    assert_eq!(
        client
            .get_job(p::JobRef { job_id: id })
            .await
            .expect("job")
            .into_inner()
            .state,
        "failed"
    );

    let incomplete_fixture = Fixture::new(1024 * 1024, 64 * 1024, 4);
    let _daemon = incomplete_fixture.start(true);
    let mut client = incomplete_fixture.client().await;
    let (id, result) = attempt(
        &mut client,
        &incomplete_fixture.root.path().join("missing.lrimg"),
        true,
    )
    .await;
    assert!(matches!(
        result.observation.expect("incomplete facts").outcome,
        Some(p::verification_observation::Outcome::Incomplete(_))
    ));
    assert!(matches!(
        result.recording.expect("recording").outcome,
        Some(p::verification_recording_outcome::Outcome::Recorded(_))
    ));
    assert!(result.report_json.is_none());
    assert_eq!(
        client
            .get_job(p::JobRef { job_id: id })
            .await
            .expect("job")
            .into_inner()
            .state,
        "failed"
    );
}

#[tokio::test]
async fn disabled_policy_and_full_retention_or_response_caps_refuse_without_false_success() {
    let disabled = Fixture::new(1024 * 1024, 64 * 1024, 1);
    let _daemon = disabled.start(false);
    let mut client = disabled.client().await;
    assert_eq!(
        history(&mut client).await.0,
        p::VerificationHistoryAvailability::Disabled
    );
    assert_eq!(
        client
            .verify_image_with_history(p::VerifySpec::default())
            .await
            .expect_err("disabled")
            .code(),
        tonic::Code::FailedPrecondition
    );
    assert!(!disabled.ledger.join(".history.lock").exists());

    let fixture = Fixture::new(1024 * 1024, 64 * 1024, 1);
    let (image, _) = file_image(fixture.root.path());
    let _daemon = fixture.start(true);
    let mut client = fixture.client().await;
    let _ = attempt(&mut client, &image, false).await;
    assert_eq!(
        client
            .verify_image_with_history(p::VerifySpec {
                image: image.display().to_string(),
                ..p::VerifySpec::default()
            })
            .await
            .expect_err("retention budget full")
            .code(),
        tonic::Code::ResourceExhausted
    );
    assert_eq!(
        history(&mut client).await.1.len(),
        1,
        "no second capture or publication"
    );

    let tiny = Fixture::new(1024 * 1024, 256, 1);
    let (image, _) = file_image(tiny.root.path());
    let _daemon = tiny.start(true);
    let mut client = tiny.client().await;
    let mut stream = client
        .verify_image_with_history(p::VerifySpec {
            image: image.display().to_string(),
            ..p::VerifySpec::default()
        })
        .await
        .expect("job accepted")
        .into_inner();
    let mut id = None;
    let mut failed = false;
    while let Some(item) = stream.message().await.expect("bounded refusal stream") {
        match item.step.expect("step") {
            p::verification_progress::Step::Progress(p::Progress {
                step: Some(p::progress::Step::Started(value)),
            }) => id = Some(value.job_id),
            p::verification_progress::Step::Progress(p::Progress {
                step: Some(p::progress::Step::Failure(_)),
            }) => failed = true,
            p::verification_progress::Step::Result(_) => {
                panic!("oversized result is never truncated")
            }
            _ => {}
        }
    }
    assert!(failed);
    let id = id.expect("job ID");
    assert_eq!(
        client
            .get_job(p::JobRef { job_id: id.clone() })
            .await
            .expect("failed job")
            .into_inner()
            .state,
        "failed"
    );
    assert!(
        client
            .get_verification_result(p::JobRef { job_id: id })
            .await
            .is_err()
    );
    assert!(
        client
            .list_verification_history(p::Request::default())
            .await
            .is_err(),
        "oversized receipt response is refused before an available header"
    );
}
