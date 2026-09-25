//! End-to-end smoke tests for the `linuxreflect` binary (spec §J.1).

use std::process::Command;

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_linuxreflect"))
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
