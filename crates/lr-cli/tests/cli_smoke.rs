//! End-to-end smoke tests for the `linuxreflect` binary (spec §J.1).

use std::process::Command;

/// The CLI in its in-process mode: an absent socket keeps these tests
/// independent of a daemon installed on the machine running them.
fn binary() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_linuxreflect"));
    command.args(["--socket", "/nonexistent/linuxreflect-test.sock"]);
    command
}

#[test]
fn caps_prints_a_parseable_report() {
    let output = binary()
        .arg("caps")
        .output()
        .expect("run linuxreflect caps");
    assert!(output.status.success(), "caps must exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    for capability in ["nbd", "ublk", "fsfreeze", "btrfs_send", "lvm2", "polkit"] {
        assert!(
            stdout.contains(capability),
            "caps output misses {capability}"
        );
    }

    let json_output = binary()
        .args(["caps", "--json"])
        .output()
        .expect("run linuxreflect caps --json");
    assert!(json_output.status.success());
    let value: serde_json::Value =
        serde_json::from_slice(&json_output.stdout).expect("caps --json must be valid JSON");
    assert!(value.get("kernel_release").is_some());
    assert!(value["nbd"].get("available").is_some());
}

#[test]
fn disk_list_json_is_an_array() {
    let output = binary()
        .args(["disk", "list", "--json"])
        .output()
        .expect("run linuxreflect disk list --json");
    assert!(output.status.success(), "disk list must exit 0");
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("disk list --json must be valid JSON");
    assert!(value.is_array(), "disk list JSON must be an array");
    for entry in value.as_array().expect("array") {
        assert!(entry.get("name").is_some());
        assert!(entry.get("size_bytes").is_some());
        assert!(entry.get("logical_block_size").is_some());
    }
}

#[test]
fn disk_map_reads_a_sparse_image() {
    let dir = tempfile::tempdir().expect("tempdir");
    let image = dir.path().join("blank.img");
    let handle = std::fs::File::create(&image).expect("create image");
    handle.set_len(8 * 1024 * 1024).expect("size image");
    drop(handle);

    let output = binary()
        .args(["disk", "map"])
        .arg(&image)
        .arg("--json")
        .output()
        .expect("run linuxreflect disk map --json");
    assert!(
        output.status.success(),
        "disk map failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("disk map --json must be valid JSON");
    assert_eq!(value["device_facts"]["size_bytes"], 8 * 1024 * 1024);
}

#[test]
fn schedule_list_reads_a_config_and_reports_missing_ones() {
    // Slice S14 implemented the schedule commands; a config is required, and a
    // missing one is a clean error rather than a reserved-command exit.
    let missing = binary()
        .args(["schedule", "list", "--config", "/nonexistent/config.toml"])
        .output()
        .expect("run linuxreflect schedule list");
    assert_eq!(
        missing.status.code(),
        Some(1),
        "a missing config is an error"
    );
    let stderr = String::from_utf8_lossy(&missing.stderr);
    assert!(stderr.contains("config.toml"), "stderr was: {stderr}");

    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        "[[job]]\nname = \"smoke\"\nsource = [\"/tmp\"]\ndest = \"/tmp/backups\"\nset = \"smoke\"\ntype = \"full\"\nencrypt = false\non_calendar = \"daily\"\n",
    )
    .expect("write config");
    let output = binary()
        .args(["schedule", "list", "--config"])
        .arg(&config)
        .arg("--json")
        .output()
        .expect("run linuxreflect schedule list");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let jobs: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("schedule list --json is JSON");
    assert_eq!(jobs[0]["job"], "smoke", "{jobs}");
    assert_eq!(jobs[0]["timer_name"], "linuxreflect-job@smoke.timer");
}

#[test]
fn destination_add_roundtrips_and_preserves_required_mount() {
    let dir = tempfile::tempdir().expect("tempdir");
    let registry = dir.path().join("destinations.toml");
    let mount = dir.path().join("nas");
    let destination = mount.join("backups");
    let uri = destination.display().to_string();
    let mount_arg = mount.display().to_string();
    let source = "nas:/exports/backups";

    let added = binary()
        .env("LR_DESTINATIONS_FILE", &registry)
        .args(["--json", "destination", "add", "--name", "archive", "--uri"])
        .arg(&uri)
        .args(["--required-mount", &mount_arg, "--required-source", source])
        .args(["--required-fs-type", "nfs4"])
        .output()
        .expect("add named destination");
    assert!(
        added.status.success(),
        "add failed: {}",
        String::from_utf8_lossy(&added.stderr)
    );
    let value: serde_json::Value =
        serde_json::from_slice(&added.stdout).expect("destination add JSON");
    assert_eq!(value[0]["required_mount"]["path"], mount_arg);
    assert_eq!(value[0]["required_mount"]["source"], source);
    assert_eq!(value[0]["required_mount"]["fs_type"], "nfs4");

    let updated = binary()
        .env("LR_DESTINATIONS_FILE", &registry)
        .args([
            "--json",
            "destination",
            "add",
            "--name",
            "archive",
            "--uri",
            "/srv/updated-backups",
        ])
        .output()
        .expect("update named destination without policy field");
    assert!(
        updated.status.success(),
        "update failed: {}",
        String::from_utf8_lossy(&updated.stderr)
    );
    let value: serde_json::Value =
        serde_json::from_slice(&updated.stdout).expect("updated destination JSON");
    assert_eq!(value[0]["required_mount"]["path"], mount_arg);
    assert_eq!(value[0]["required_mount"]["source"], source);

    let removed = binary()
        .env("LR_DESTINATIONS_FILE", &registry)
        .args(["destination", "remove", "--name", "archive"])
        .output()
        .expect("remove named destination");
    assert!(removed.status.success());
    let recreated = binary()
        .env("LR_DESTINATIONS_FILE", &registry)
        .args([
            "--json",
            "destination",
            "add",
            "--name",
            "archive",
            "--uri",
            "/srv/unguarded-backups",
        ])
        .output()
        .expect("recreate named destination without policy");
    assert!(recreated.status.success());
    let value: serde_json::Value =
        serde_json::from_slice(&recreated.stdout).expect("recreated destination JSON");
    assert!(value[0].get("required_mount").is_none());
}
