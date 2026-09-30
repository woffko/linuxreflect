//! End-to-end checks for named required-mount destination resolution.

use std::path::PathBuf;
use std::process::Command;

use lr_core::{Id, SetId};
use lr_store::{DestinationOptions, RequiredMount};

const CHILD_MODE: &str = "LR_REQUIRED_MOUNT_CHILD";
const CHILD_ROOT: &str = "LR_REQUIRED_MOUNT_ROOT";

#[test]
fn open_named_policy_refuses_before_creation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let required_path = dir.path().join("not-mounted");
    let root = required_path.join("backups");
    let registry = dir.path().join("destinations.toml");
    lr_store::named::save(
        &registry,
        &[lr_store::named::NamedDestination {
            name: "mounted-share".to_owned(),
            uri: root.display().to_string(),
            identity: None,
            known_hosts: None,
            required_mount: Some(RequiredMount {
                path: required_path.clone(),
                source: "nas.local:/exports/backups".to_owned(),
                fs_type: "nfs4".to_owned(),
            }),
        }],
    )
    .expect("write registry");

    let output = Command::new(std::env::current_exe().expect("test executable"))
        .arg("--exact")
        .arg("open_named_policy_child")
        .arg("--nocapture")
        .env(CHILD_MODE, "1")
        .env(CHILD_ROOT, &root)
        .env("LR_DESTINATIONS_FILE", &registry)
        .output()
        .expect("spawn isolated test process");
    assert!(
        output.status.success(),
        "child failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!required_path.exists());
    assert!(!root.exists());
}

#[test]
fn open_named_policy_child() {
    if std::env::var_os(CHILD_MODE).as_deref() != Some(std::ffi::OsStr::new("1")) {
        return;
    }
    let root = PathBuf::from(std::env::var_os(CHILD_ROOT).expect("destination root"));
    let destination = lr_store::open("@mounted-share", &DestinationOptions::new("test-set"))
        .expect("resolve named destination");
    let error = destination
        .open_set(&SetId::new(Id::from_bytes([0x33; 16])))
        .expect_err("missing required mount must fail");
    assert!(error.to_string().contains("required mount"), "{error}");
    assert!(!root.exists());
}

#[test]
fn ordinary_local_destination_still_creates_sets() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("local-backups");
    let destination = lr_store::open(
        &root.display().to_string(),
        &DestinationOptions::new("test-set"),
    )
    .expect("open ordinary local destination");
    let set = destination
        .open_set(&SetId::new(Id::from_bytes([0x44; 16])))
        .expect("create local set");
    assert!(std::path::Path::new(&set.path).is_dir());
}
