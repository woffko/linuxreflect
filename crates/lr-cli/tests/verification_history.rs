//! Direct CLI contract for opt-in captured verification receipts.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use lr_engine::backup::BackupRequest;
use lr_engine::file::{FileBackupOptions, backup_file};
use lr_engine::keys::Encryption;

const CLI: &str = env!("CARGO_BIN_EXE_linuxreflect");

fn private_tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("lr-cli-history-private-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .expect("create private CLI fixture directory")
}

fn history_tempdir() -> tempfile::TempDir {
    let root = std::env::var_os("LR_TEST_HISTORY_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/tmp"));
    tempfile::Builder::new()
        .prefix("lr-cli-history-ledger-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(root)
        .expect("create persistent local history fixture")
}

fn file_image_fixture() -> (tempfile::TempDir, tempfile::TempDir, PathBuf, String) {
    let work = private_tempdir();
    let destination = private_tempdir();
    let source = work.path().join("tree");
    std::fs::create_dir(&source).expect("create file-mode source");
    std::fs::write(source.join("payload.txt"), vec![b'h'; 32 * 1024])
        .expect("create source payload");

    let set = "cli-local-history";
    let request = BackupRequest::new(&source, destination.path(), set, Encryption::NoEncrypt)
        .expect("create file backup request");
    let report = backup_file(&request, &FileBackupOptions::default()).expect("create file image");
    (work, destination, report.image_path, set.to_owned())
}

fn policy_file(
    config_dir: &Path,
    scratch_dir: &Path,
    history_dir: &Path,
    max_total_ledger_bytes: u64,
) -> PathBuf {
    let policy = policy_value(scratch_dir, history_dir, max_total_ledger_bytes);
    let path = config_dir.join("local-history.json");
    write_policy(
        &path,
        &serde_json::to_vec(&policy).expect("serialize policy"),
        0o600,
    );
    path
}

fn policy_value(
    scratch_dir: &Path,
    history_dir: &Path,
    max_total_ledger_bytes: u64,
) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "capture": {
            "scratch_directory": scratch_dir,
            "max_raw_bytes": 64 * 1024 * 1024,
            "headroom_bytes": 0
        },
        "history": {
            "history_directory": history_dir,
            "max_receipt_bytes": 64 * 1024,
            "max_members": 16,
            "max_entries": 16,
            "max_total_ledger_bytes": max_total_ledger_bytes
        }
    })
}

fn write_policy(path: &Path, contents: &[u8], mode: u32) {
    std::fs::write(path, contents).expect("write policy");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("set policy mode");
}

fn run_cli(args: &[&str]) -> Output {
    Command::new(CLI)
        .args(args)
        .output()
        .expect("run LinuxReflect CLI")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn run_file_verify(image: &Path, config: &Path, chain: bool) -> Output {
    let mut args = vec![
        "verify",
        "--image",
        image.to_str().expect("UTF-8 fixture path"),
    ];
    if chain {
        args.push("--chain");
    }
    args.extend([
        "--local-history-config",
        config.to_str().expect("UTF-8 fixture path"),
        "--json",
    ]);
    run_cli(&args)
}

fn history_summary(config: &Path) -> (Output, serde_json::Value) {
    let output = run_cli(&[
        "verification-history",
        "--config",
        config.to_str().expect("UTF-8 fixture path"),
        "--json",
    ]);
    let summary = serde_json::from_slice(&output.stdout).expect("parse history summary");
    (output, summary)
}

#[test]
fn opt_in_file_verification_records_and_inspects_without_changing_catalog() {
    let (_work, destination, image, set) = file_image_fixture();
    let history = history_tempdir();
    let config_dir = private_tempdir();
    let scratch = private_tempdir();
    let config = policy_file(
        config_dir.path(),
        scratch.path(),
        history.path(),
        1024 * 1024,
    );
    let catalog = destination.path().join(&set).join("catalog.json");
    let catalog_before = std::fs::read(&catalog).expect("read pre-verification catalog");

    let selected = run_file_verify(&image, &config, false);
    assert!(selected.status.success(), "{}", stderr(&selected));
    let selected_summary: serde_json::Value =
        serde_json::from_slice(&selected.stdout).expect("parse selected verify summary");
    assert_eq!(selected_summary["schema_version"], 1);
    assert_eq!(
        selected_summary["observation"]["outcome"]["status"],
        "integrity_verified"
    );
    assert_eq!(
        selected_summary["observation"]["content_coverage"],
        "file_selected_tree_references"
    );
    assert_eq!(selected_summary["recording"]["status"], "recorded");
    assert!(selected_summary["report"].is_object());

    let chain = run_file_verify(&image, &config, true);
    assert!(chain.status.success(), "{}", stderr(&chain));
    let chain_summary: serde_json::Value =
        serde_json::from_slice(&chain.stdout).expect("parse chain verify summary");
    assert_eq!(
        chain_summary["observation"]["outcome"]["status"],
        "integrity_verified"
    );
    assert_eq!(
        chain_summary["observation"]["content_coverage"],
        "file_every_tree_references"
    );
    assert_eq!(chain_summary["recording"]["status"], "recorded");
    assert!(chain_summary["report"].is_object());
    assert_eq!(
        std::fs::read(&catalog).expect("read post-verification catalog"),
        catalog_before,
        "neither captured route writes the catalog"
    );

    let (inspected, history_summary) = history_summary(&config);
    assert!(inspected.status.success(), "{}", stderr(&inspected));
    assert_eq!(history_summary["schema_version"], 1);
    assert_eq!(history_summary["kind"], "historical_observations");
    assert_eq!(history_summary["current_image_association"], "not_checked");
    let receipts = history_summary["receipts"]
        .as_array()
        .expect("receipt array");
    assert_eq!(receipts.len(), 2);

    for summary in [&selected_summary, &chain_summary] {
        let receipt_id = summary["recording"]["receipt_id"]
            .as_str()
            .expect("confirmed receipt ID");
        let receipt = receipts
            .iter()
            .find(|receipt| receipt["receipt_id"] == receipt_id)
            .expect("summary receipt is in the loaded history");
        assert_eq!(
            receipt["observation"], summary["observation"],
            "loaded receipt observation exactly matches the CLI attempt"
        );
    }
}

#[test]
fn quota_refusal_keeps_integrity_facts_and_exits_unsuccessfully() {
    let (_work, _destination, image, _set) = file_image_fixture();
    let history = history_tempdir();
    let config_dir = private_tempdir();
    let scratch = private_tempdir();
    let config = policy_file(config_dir.path(), scratch.path(), history.path(), 1);

    let output = run_file_verify(&image, &config, false);
    assert!(!output.status.success());
    let summary: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("facts remain on failed exit");
    assert_eq!(
        summary["observation"]["outcome"]["status"],
        "integrity_verified"
    );
    assert!(summary["report"].is_object());
    assert_eq!(summary["recording"]["status"], "not_recorded");
    assert_eq!(summary["recording"]["reason"], "quota_exceeded");
}

#[test]
fn incomplete_attempt_can_be_recorded_but_does_not_exit_successfully() {
    let (_work, _destination, image, _set) = file_image_fixture();
    std::fs::remove_file(&image).expect("remove only the test-created image");
    let history = history_tempdir();
    let config_dir = private_tempdir();
    let scratch = private_tempdir();
    let config = policy_file(
        config_dir.path(),
        scratch.path(),
        history.path(),
        1024 * 1024,
    );

    let output = run_file_verify(&image, &config, false);
    assert!(!output.status.success(), "{}", stderr(&output));
    let summary: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("incomplete attempt facts are emitted");
    assert_eq!(summary["observation"]["outcome"]["status"], "incomplete");
    assert!(summary["report"].is_null());
    assert_eq!(summary["recording"]["status"], "recorded");

    let (inspected, loaded) = history_summary(&config);
    assert!(inspected.status.success(), "{}", stderr(&inspected));
    assert_eq!(loaded["receipts"].as_array().map(Vec::len), Some(1));
    assert_eq!(loaded["receipts"][0]["observation"], summary["observation"]);
}

#[test]
fn strict_private_policy_and_socket_conflicts_are_refused() {
    let config_dir = private_tempdir();
    let scratch = private_tempdir();
    let history = history_tempdir();
    let valid = policy_file(
        config_dir.path(),
        scratch.path(),
        history.path(),
        1024 * 1024,
    );
    let valid_bytes = std::fs::read(&valid).expect("read valid policy fixture");

    let mut invalid_configs = Vec::new();

    let wrong_mode = config_dir.path().join("wrong-mode.json");
    write_policy(&wrong_mode, &valid_bytes, 0o644);
    invalid_configs.push(wrong_mode);

    let linked = config_dir.path().join("linked.json");
    write_policy(&linked, &valid_bytes, 0o600);
    std::fs::hard_link(&linked, config_dir.path().join("linked-alias.json"))
        .expect("create only a test policy hard link");
    invalid_configs.push(linked);

    let symlink = config_dir.path().join("symlink.json");
    std::os::unix::fs::symlink(&valid, &symlink).expect("create policy symlink");
    invalid_configs.push(symlink);

    let fifo = config_dir.path().join("policy.fifo");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("run mkfifo for FIFO refusal fixture")
            .success(),
        "mkfifo should create the fixture"
    );
    invalid_configs.push(fifo);

    let oversized = config_dir.path().join("oversized.json");
    write_policy(&oversized, &vec![b' '; 64 * 1024 + 1], 0o600);
    invalid_configs.push(oversized);

    let unknown = config_dir.path().join("unknown.json");
    let unknown_json = String::from_utf8(valid_bytes.clone()).expect("policy JSON is UTF-8");
    let unknown_json =
        unknown_json.trim_end_matches('}').to_owned() + ",\"secret_sentinel\":\"must-not-appear\"}";
    write_policy(&unknown, unknown_json.as_bytes(), 0o600);
    invalid_configs.push(unknown);

    let wrong_version = config_dir.path().join("wrong-version.json");
    let wrong_version_json =
        serde_json::from_slice::<serde_json::Value>(&valid_bytes).expect("parse policy fixture");
    let mut wrong_version_json = wrong_version_json;
    wrong_version_json["schema_version"] = serde_json::json!(2);
    write_policy(
        &wrong_version,
        &serde_json::to_vec(&wrong_version_json).expect("serialize wrong version"),
        0o600,
    );
    invalid_configs.push(wrong_version);

    let missing_field = config_dir.path().join("missing-field.json");
    write_policy(
        &missing_field,
        br#"{"schema_version":1,"capture":{},"history":{}}"#,
        0o600,
    );
    invalid_configs.push(missing_field);

    for field in ["scratch_directory", "max_raw_bytes", "headroom_bytes"] {
        let path = config_dir
            .path()
            .join(format!("missing-capture-{field}.json"));
        let mut value: serde_json::Value =
            serde_json::from_slice(&valid_bytes).expect("parse complete policy control");
        assert!(
            value["capture"]
                .as_object_mut()
                .expect("capture object")
                .remove(field)
                .is_some()
        );
        write_policy(
            &path,
            &serde_json::to_vec(&value).expect("serialize missing field"),
            0o600,
        );
        invalid_configs.push(path);
    }

    let unknown_capture = config_dir.path().join("unknown-capture.json");
    let mut value: serde_json::Value =
        serde_json::from_slice(&valid_bytes).expect("parse complete policy control");
    value["capture"]["implicit_default"] = serde_json::json!(true);
    write_policy(
        &unknown_capture,
        &serde_json::to_vec(&value).expect("serialize unknown capture field"),
        0o600,
    );
    invalid_configs.push(unknown_capture);

    let duplicate = config_dir.path().join("duplicate.json");
    let duplicate_json = String::from_utf8(valid_bytes.clone()).expect("policy JSON is UTF-8");
    let duplicate_json = duplicate_json.replacen(
        "\"schema_version\":1",
        "\"schema_version\":1,\"schema_version\":1",
        1,
    );
    write_policy(&duplicate, duplicate_json.as_bytes(), 0o600);
    invalid_configs.push(duplicate);

    let missing = config_dir.path().join("missing.json");
    invalid_configs.push(missing);

    for config in invalid_configs {
        let output = run_cli(&[
            "verify",
            "--image",
            "not-opened-before-policy-validation.lrimg",
            "--local-history-config",
            config.to_str().expect("UTF-8 fixture path"),
            "--json",
        ]);
        assert!(!output.status.success());
        assert!(
            stderr(&output).contains("local verification policy is invalid or unavailable"),
            "unexpected refusal for {}: {}",
            config.display(),
            stderr(&output)
        );
        assert!(!stderr(&output).contains("must-not-appear"));
        assert!(output.stdout.is_empty());
    }
    assert_eq!(
        std::fs::read_dir(history.path())
            .expect("inspect refused-policy ledger")
            .count(),
        0,
        "invalid policy must be refused before any ledger writes"
    );

    let verify_conflict = run_cli(&[
        "--socket",
        "/tmp/unused-linuxreflect-socket",
        "verify",
        "--image",
        "unused.lrimg",
        "--local-history-config",
        valid.to_str().expect("UTF-8 fixture path"),
    ]);
    assert!(!verify_conflict.status.success());
    assert!(stderr(&verify_conflict).contains("--socket"));

    let history_conflict = run_cli(&[
        "verification-history",
        "--config",
        valid.to_str().expect("UTF-8 fixture path"),
        "--socket",
        "/tmp/unused-linuxreflect-socket",
    ]);
    assert!(!history_conflict.status.success());
    assert!(stderr(&history_conflict).contains("--socket"));
}

#[test]
fn empty_history_requires_existing_lock_and_read_only_inspection_does_not_create_it() {
    let config_dir = private_tempdir();
    let scratch = private_tempdir();
    let history = history_tempdir();
    let config = policy_file(
        config_dir.path(),
        scratch.path(),
        history.path(),
        1024 * 1024,
    );
    let lock = history.path().join(".history.lock");

    let unavailable = run_cli(&[
        "verification-history",
        "--config",
        config.to_str().expect("UTF-8 fixture path"),
        "--json",
    ]);
    assert!(!unavailable.status.success());
    assert!(stderr(&unavailable).contains("history is unavailable or unknown"));
    assert!(
        !lock.exists(),
        "read-only inspection did not initialize a lock"
    );
    assert_eq!(
        std::fs::read_dir(history.path())
            .expect("read empty history directory")
            .count(),
        0
    );

    write_policy(&lock, b"", 0o600);
    let (empty, summary) = history_summary(&config);
    assert!(empty.status.success(), "{}", stderr(&empty));
    assert_eq!(summary["kind"], "historical_observations");
    assert_eq!(summary["current_image_association"], "not_checked");
    assert_eq!(summary["receipts"].as_array().map(Vec::len), Some(0));
}
