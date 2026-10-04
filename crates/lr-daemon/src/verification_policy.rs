//! Bounded, startup-only policy for daemon-owned captured verification.

use std::fs::{File, Metadata};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use lr_core::{Error, Result};
use lr_engine::verify::{CaptureOptions, VerificationHistoryOptions};
use serde::Deserialize;

const POLICY_SCHEMA_VERSION: u16 = 1;
const MAX_POLICY_BYTES: u64 = 64 * 1024;
const PRIVATE_FILE_MODE: u32 = 0o600;
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const MAX_CONCURRENT_OPERATIONS: usize = 4;
const MAX_RESULT_BYTES: usize = 1024 * 1024;

const INVALID_POLICY: &str = "daemon verification policy is invalid or unavailable";

/// Validated, immutable daemon policy for captured verification and receipts.
///
/// Instances can only be obtained by loading the strict private policy file.
#[derive(Debug)]
pub struct DaemonVerificationPolicy {
    capture: CaptureOptions,
    history: VerificationHistoryOptions,
    max_concurrent_operations: usize,
    max_result_bytes: usize,
    max_retained_results: usize,
    max_retained_result_bytes: usize,
}

impl DaemonVerificationPolicy {
    /// Load and validate one private version-1 policy file.
    ///
    /// The file, scratch directory, and history directory must already exist.
    /// No path is created, followed through a symlink, or reloaded implicitly.
    /// A non-root daemon may use an effective-user-owned policy only when the
    /// caller explicitly enables development mode.
    ///
    /// # Errors
    /// Returns a redacted unsupported error when the file, schema, resource
    /// limits, ownership, path ancestry, or storage preflight is invalid.
    pub fn load(path: &Path, dev_mode: bool) -> Result<Self> {
        Self::load_inner(path, dev_mode).map_err(|_| Error::unsupported(INVALID_POLICY))
    }

    /// Validated capture resource and scratch-path policy.
    #[must_use]
    pub const fn capture(&self) -> &CaptureOptions {
        &self.capture
    }

    /// Validated local receipt limits and history directory.
    #[must_use]
    pub const fn history(&self) -> &VerificationHistoryOptions {
        &self.history
    }

    /// Maximum number of daemon verification operations that may run together.
    #[must_use]
    pub const fn max_concurrent_operations(&self) -> usize {
        self.max_concurrent_operations
    }

    /// Maximum encoded size of one terminal result message.
    #[must_use]
    pub const fn max_result_bytes(&self) -> usize {
        self.max_result_bytes
    }

    /// Maximum number of canonical verification results retained by the daemon.
    #[must_use]
    pub const fn max_retained_results(&self) -> usize {
        self.max_retained_results
    }

    /// Aggregate byte budget for retained canonical verification results.
    #[must_use]
    pub const fn max_retained_result_bytes(&self) -> usize {
        self.max_retained_result_bytes
    }

    fn load_inner(path: &Path, dev_mode: bool) -> PolicyResult<Self> {
        let uid = lr_unsafe::effective_uid();
        let policy_uid = if uid == 0 || !dev_mode { 0 } else { uid };
        let mut file = open_policy_file(path, uid, policy_uid)?;
        let before = file.metadata().map_err(|_| PolicyError)?;
        validate_policy_file_metadata(&before, policy_uid)?;
        if before.len() > MAX_POLICY_BYTES {
            return Err(PolicyError);
        }

        let reserve = usize::try_from(MAX_POLICY_BYTES + 1).map_err(|_| PolicyError)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(reserve).map_err(|_| PolicyError)?;
        let read_result = (&mut file)
            .take(MAX_POLICY_BYTES + 1)
            .read_to_end(&mut bytes);
        let after = file.metadata().map_err(|_| PolicyError)?;
        if read_result.is_err()
            || u64::try_from(bytes.len()).map_err(|_| PolicyError)? > MAX_POLICY_BYTES
            || u64::try_from(bytes.len()).map_err(|_| PolicyError)? != before.len()
            || !same_policy_file(&before, &after, policy_uid)
        {
            return Err(PolicyError);
        }

        let document = serde_json::from_slice::<PolicyDocument>(&bytes).map_err(|_| PolicyError)?;
        if document.schema_version != POLICY_SCHEMA_VERSION
            || document.max_concurrent_operations == 0
            || document.max_concurrent_operations > MAX_CONCURRENT_OPERATIONS
            || document.max_result_bytes == 0
            || document.max_result_bytes > MAX_RESULT_BYTES
            || document.max_retained_results == 0
            || document.max_retained_result_bytes == 0
            || document.max_retained_result_bytes < document.max_result_bytes
            || document.capture.max_raw_bytes == 0
            || document.history.max_receipt_bytes() == 0
            || document.history.max_members() == 0
            || document.history.max_entries() == 0
            || document.history.max_total_ledger_bytes() == 0
        {
            return Err(PolicyError);
        }

        validate_directory(&document.capture.scratch_directory, uid)?;
        // The engine owns the ledger trust and supported-filesystem contract.
        document
            .history
            .preflight_directory()
            .map_err(|_| PolicyError)?;

        Ok(Self {
            capture: document.capture,
            history: document.history,
            max_concurrent_operations: document.max_concurrent_operations,
            max_result_bytes: document.max_result_bytes,
            max_retained_results: document.max_retained_results,
            max_retained_result_bytes: document.max_retained_result_bytes,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyDocument {
    schema_version: u16,
    capture: CaptureOptions,
    history: VerificationHistoryOptions,
    max_concurrent_operations: usize,
    max_result_bytes: usize,
    max_retained_results: usize,
    max_retained_result_bytes: usize,
}

#[derive(Clone, Copy)]
struct PolicyError;

type PolicyResult<T> = std::result::Result<T, PolicyError>;

fn open_policy_file(path: &Path, uid: u32, policy_uid: u32) -> PolicyResult<File> {
    let (parent, name) = open_pinned_parent(path, uid)?;
    let entry = lr_unsafe::beneath::entry_path(&parent, &name).map_err(|_| PolicyError)?;
    let descriptor = lr_unsafe::open_readonly_nofollow(&entry).map_err(|_| PolicyError)?;
    let file = File::from(descriptor);
    let metadata = file.metadata().map_err(|_| PolicyError)?;
    validate_policy_file_metadata(&metadata, policy_uid)?;
    Ok(file)
}

fn open_pinned_parent(path: &Path, uid: u32) -> PolicyResult<(File, std::ffi::OsString)> {
    if !path.is_absolute() {
        return Err(PolicyError);
    }
    let relative = path.strip_prefix("/").map_err(|_| PolicyError)?;
    let mut components =
        lr_unsafe::beneath::normal_components(relative).map_err(|_| PolicyError)?;
    let name = components.pop().ok_or(PolicyError)?.to_os_string();

    let mut current =
        File::from(lr_unsafe::beneath::open_root(Path::new("/")).map_err(|_| PolicyError)?);
    validate_trusted_ancestor(&current.metadata().map_err(|_| PolicyError)?, uid)?;
    for component in components {
        let next = lr_unsafe::beneath::open_dir_beneath(&current, Path::new(component))
            .map_err(|_| PolicyError)?;
        let next = File::from(next);
        validate_trusted_ancestor(&next.metadata().map_err(|_| PolicyError)?, uid)?;
        current = next;
    }
    Ok((current, name))
}

fn validate_policy_file_metadata(metadata: &Metadata, policy_uid: u32) -> PolicyResult<()> {
    if !metadata.is_file()
        || metadata.uid() != policy_uid
        || metadata.mode() & 0o7777 != PRIVATE_FILE_MODE
        || metadata.nlink() != 1
        || metadata.len() > MAX_POLICY_BYTES
    {
        return Err(PolicyError);
    }
    Ok(())
}

fn same_policy_file(before: &Metadata, after: &Metadata, policy_uid: u32) -> bool {
    validate_policy_file_metadata(after, policy_uid).is_ok()
        && before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.uid() == after.uid()
        && before.mode() == after.mode()
        && before.nlink() == after.nlink()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

fn validate_trusted_ancestor(metadata: &Metadata, uid: u32) -> PolicyResult<()> {
    let owner_is_trusted = metadata.uid() == uid || metadata.uid() == 0;
    let protected_root_sticky = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
    if !metadata.is_dir()
        || !owner_is_trusted
        || (metadata.mode() & 0o022 != 0 && !protected_root_sticky)
    {
        return Err(PolicyError);
    }
    Ok(())
}

fn validate_directory(path: &Path, uid: u32) -> PolicyResult<()> {
    if !path.is_absolute() {
        return Err(PolicyError);
    }
    let relative = path.strip_prefix("/").map_err(|_| PolicyError)?;
    let components = lr_unsafe::beneath::normal_components(relative).map_err(|_| PolicyError)?;
    if components.is_empty() {
        return Err(PolicyError);
    }

    let mut current =
        File::from(lr_unsafe::beneath::open_root(Path::new("/")).map_err(|_| PolicyError)?);
    validate_trusted_ancestor(&current.metadata().map_err(|_| PolicyError)?, uid)?;
    for (index, component) in components.iter().enumerate() {
        let next = lr_unsafe::beneath::open_dir_beneath(&current, Path::new(component))
            .map_err(|_| PolicyError)?;
        let next = File::from(next);
        let metadata = next.metadata().map_err(|_| PolicyError)?;
        let final_component = index + 1 == components.len();
        if final_component {
            if !metadata.is_dir()
                || metadata.uid() != uid
                || metadata.mode() & 0o7777 != PRIVATE_DIRECTORY_MODE
            {
                return Err(PolicyError);
            }
        } else {
            validate_trusted_ancestor(&metadata, uid)?;
        }
        current = next;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use super::DaemonVerificationPolicy;

    fn private_tempdir() -> tempfile::TempDir {
        let root = std::env::var_os("LR_TEST_HISTORY_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/var/tmp"));
        tempfile::Builder::new()
            .prefix("lr-daemon-verification-policy-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(root)
            .expect("create private policy fixture")
    }

    fn policy_value(scratch: &std::path::Path, history: &std::path::Path) -> serde_json::Value {
        serde_json::json!({
            "schema_version": 1,
            "capture": {
                "scratch_directory": scratch,
                "max_raw_bytes": 4 * 1024 * 1024,
                "headroom_bytes": 0
            },
            "history": {
                "history_directory": history,
                "max_receipt_bytes": 64 * 1024,
                "max_members": 16,
                "max_entries": 256,
                "max_total_ledger_bytes": 16 * 1024 * 1024
            },
            "max_concurrent_operations": 2,
            "max_result_bytes": 256 * 1024,
            "max_retained_results": 16,
            "max_retained_result_bytes": 4 * 1024 * 1024
        })
    }

    fn write_policy(path: &std::path::Path, bytes: &[u8], mode: u32) {
        std::fs::write(path, bytes).expect("write policy fixture");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .expect("set fixture mode");
    }

    fn valid_fixture() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
        let parent = private_tempdir();
        let scratch = parent.path().join("scratch");
        let history = parent.path().join("history");
        std::fs::create_dir(&scratch).expect("create scratch fixture");
        std::fs::create_dir(&history).expect("create history fixture");
        std::fs::set_permissions(&scratch, std::fs::Permissions::from_mode(0o700))
            .expect("set scratch mode");
        std::fs::set_permissions(&history, std::fs::Permissions::from_mode(0o700))
            .expect("set history mode");
        let policy = parent.path().join("policy.json");
        let value = policy_value(&scratch, &history);
        write_policy(
            &policy,
            &serde_json::to_vec(&value).expect("serialize fixture policy"),
            0o600,
        );
        (parent, policy, scratch, history)
    }

    #[test]
    fn explicit_dev_policy_loads_and_exposes_only_validated_values() {
        let (_parent, policy_path, scratch, history) = valid_fixture();
        let policy = DaemonVerificationPolicy::load(&policy_path, true)
            .expect("load explicit dev-mode policy");
        assert_eq!(policy.capture().scratch_directory, scratch);
        assert_eq!(policy.capture().max_raw_bytes, 4 * 1024 * 1024);
        assert_eq!(policy.history().history_directory(), history);
        assert_eq!(policy.max_concurrent_operations(), 2);
        assert_eq!(policy.max_result_bytes(), 256 * 1024);
        assert_eq!(policy.max_retained_results(), 16);
        assert_eq!(policy.max_retained_result_bytes(), 4 * 1024 * 1024);
        assert!(!history.join(".history.lock").exists());
    }

    #[test]
    fn private_regular_single_link_policy_is_required() {
        let (parent, policy_path, _scratch, _history) = valid_fixture();
        let contents = std::fs::read(&policy_path).expect("read policy fixture");

        std::fs::set_permissions(&policy_path, std::fs::Permissions::from_mode(0o640))
            .expect("make policy mode invalid");
        assert!(DaemonVerificationPolicy::load(&policy_path, true).is_err());
        write_policy(&policy_path, &contents, 0o600);

        let alias = parent.path().join("policy-link.json");
        std::os::unix::fs::symlink(&policy_path, &alias).expect("create policy symlink");
        assert!(DaemonVerificationPolicy::load(&alias, true).is_err());

        let hardlink = parent.path().join("policy-hardlink.json");
        std::fs::hard_link(&policy_path, &hardlink).expect("create policy hard link");
        assert_eq!(
            std::fs::metadata(&policy_path).expect("metadata").nlink(),
            2
        );
        assert!(DaemonVerificationPolicy::load(&policy_path, true).is_err());

        let fifo = parent.path().join("policy.fifo");
        assert!(
            Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .expect("run mkfifo")
                .success()
        );
        assert!(DaemonVerificationPolicy::load(&fifo, true).is_err());

        let oversized = parent.path().join("oversized-policy.json");
        write_policy(&oversized, &vec![b' '; 64 * 1024 + 1], 0o600);
        assert!(DaemonVerificationPolicy::load(&oversized, true).is_err());
    }

    #[test]
    fn effective_uid_owned_policy_is_refused_in_nonroot_production_mode() {
        if lr_unsafe::effective_uid() == 0 {
            return;
        }
        let (_parent, policy_path, _scratch, _history) = valid_fixture();
        let error = DaemonVerificationPolicy::load(&policy_path, false)
            .expect_err("production mode requires a root-owned policy");
        assert!(
            !error
                .to_string()
                .contains(policy_path.to_str().unwrap_or_default())
        );
    }

    #[test]
    fn strict_schema_required_fields_duplicates_versions_and_resource_caps_are_enforced() {
        let (_parent, policy_path, _scratch, _history) = valid_fixture();
        let bytes = std::fs::read(&policy_path).expect("read valid policy");
        let original =
            serde_json::from_slice::<serde_json::Value>(&bytes).expect("parse valid policy");
        let mut invalid = Vec::new();

        for field in [
            "schema_version",
            "capture",
            "history",
            "max_concurrent_operations",
            "max_result_bytes",
            "max_retained_results",
            "max_retained_result_bytes",
        ] {
            let mut value = original.clone();
            assert!(
                value
                    .as_object_mut()
                    .expect("policy object")
                    .remove(field)
                    .is_some()
            );
            invalid.push(value);
        }
        for (section, fields) in [
            (
                "capture",
                &["scratch_directory", "max_raw_bytes", "headroom_bytes"][..],
            ),
            (
                "history",
                &[
                    "history_directory",
                    "max_receipt_bytes",
                    "max_members",
                    "max_entries",
                    "max_total_ledger_bytes",
                ][..],
            ),
        ] {
            for field in fields {
                let mut value = original.clone();
                assert!(
                    value[section]
                        .as_object_mut()
                        .expect("section object")
                        .remove(*field)
                        .is_some()
                );
                invalid.push(value);
            }
        }

        let mut unknown = original.clone();
        unknown["unknown_sentinel"] = serde_json::json!("must-not-leak");
        invalid.push(unknown);
        let mut unknown_capture = original.clone();
        unknown_capture["capture"]["unknown_sentinel"] = serde_json::json!(true);
        invalid.push(unknown_capture);
        let mut unknown_history = original.clone();
        unknown_history["history"]["unknown_sentinel"] = serde_json::json!(true);
        invalid.push(unknown_history);

        let mut wrong_version = original.clone();
        wrong_version["schema_version"] = serde_json::json!(2);
        invalid.push(wrong_version);

        for (section, field) in [
            ("capture", "max_raw_bytes"),
            ("history", "max_receipt_bytes"),
            ("history", "max_members"),
            ("history", "max_entries"),
            ("history", "max_total_ledger_bytes"),
        ] {
            let mut value = original.clone();
            value[section][field] = serde_json::json!(0);
            invalid.push(value);
        }
        for concurrency in [0, 5] {
            let mut value = original.clone();
            value["max_concurrent_operations"] = serde_json::json!(concurrency);
            invalid.push(value);
        }
        for result_bytes in [0, 1024 * 1024 + 1] {
            let mut value = original.clone();
            value["max_result_bytes"] = serde_json::json!(result_bytes);
            invalid.push(value);
        }
        let mut zero_retained_results = original.clone();
        zero_retained_results["max_retained_results"] = serde_json::json!(0);
        invalid.push(zero_retained_results);
        for retained_result_bytes in [0, 256 * 1024 - 1] {
            let mut value = original.clone();
            value["max_retained_result_bytes"] = serde_json::json!(retained_result_bytes);
            invalid.push(value);
        }

        for (index, value) in invalid.into_iter().enumerate() {
            let path = policy_path.with_file_name(format!("invalid-{index}.json"));
            write_policy(
                &path,
                &serde_json::to_vec(&value).expect("serialize invalid case"),
                0o600,
            );
            let error = DaemonVerificationPolicy::load(&path, true)
                .expect_err("invalid schema or caps refused");
            assert!(!error.to_string().contains("must-not-leak"));
        }

        let duplicate = policy_path.with_file_name("duplicate.json");
        let text = String::from_utf8(bytes).expect("policy JSON is UTF-8");
        let duplicated_version = text.replacen(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1",
            1,
        );
        write_policy(&duplicate, duplicated_version.as_bytes(), 0o600);
        assert!(DaemonVerificationPolicy::load(&duplicate, true).is_err());
    }

    #[test]
    fn writable_ancestors_missing_directories_and_volatile_ledgers_are_refused_read_only() {
        let (parent, policy_path, scratch, history) = valid_fixture();

        std::fs::set_permissions(&scratch, std::fs::Permissions::from_mode(0o750))
            .expect("make scratch mode invalid");
        assert!(DaemonVerificationPolicy::load(&policy_path, true).is_err());
        std::fs::set_permissions(&scratch, std::fs::Permissions::from_mode(0o700))
            .expect("restore scratch mode");

        std::fs::set_permissions(&history, std::fs::Permissions::from_mode(0o701))
            .expect("make history mode invalid");
        assert!(DaemonVerificationPolicy::load(&policy_path, true).is_err());
        std::fs::set_permissions(&history, std::fs::Permissions::from_mode(0o700))
            .expect("restore history mode");

        let scratch_alias = parent.path().join("scratch-link");
        std::os::unix::fs::symlink(&scratch, &scratch_alias).expect("create scratch symlink");
        let symlink_policy = policy_value(&scratch_alias, &history);
        let symlink_policy_path = parent.path().join("symlink-directory-policy.json");
        write_policy(
            &symlink_policy_path,
            &serde_json::to_vec(&symlink_policy).expect("serialize symlink path"),
            0o600,
        );
        assert!(DaemonVerificationPolicy::load(&symlink_policy_path, true).is_err());

        for (section, field, name) in [
            ("capture", "scratch_directory", "missing-scratch"),
            ("history", "history_directory", "missing-history"),
        ] {
            let missing = parent.path().join(name);
            let mut value = policy_value(&scratch, &history);
            value[section][field] = serde_json::json!(missing);
            let missing_policy = parent.path().join(format!("{name}-policy.json"));
            write_policy(
                &missing_policy,
                &serde_json::to_vec(&value).expect("serialize missing path"),
                0o600,
            );
            assert!(DaemonVerificationPolicy::load(&missing_policy, true).is_err());
            assert!(!parent.path().join(name).exists());
        }

        let volatile = PathBuf::from("/dev/shm").join(format!(
            "lr-daemon-verification-policy-volatile-{}",
            std::process::id()
        ));
        let volatile_policy = parent.path().join("volatile-policy.json");
        let value = policy_value(&scratch, &volatile);
        write_policy(
            &volatile_policy,
            &serde_json::to_vec(&value).expect("serialize volatile path"),
            0o600,
        );
        assert!(DaemonVerificationPolicy::load(&volatile_policy, true).is_err());
        assert!(
            !volatile.exists(),
            "loader did not create volatile ledger path"
        );

        if Path::new("/dev/shm").is_dir() {
            let memory = tempfile::Builder::new()
                .prefix("lr-policy-volatile-")
                .permissions(std::fs::Permissions::from_mode(0o700))
                .tempdir_in("/dev/shm")
                .expect("private volatile fixture");
            let value = policy_value(&scratch, memory.path());
            write_policy(
                &volatile_policy,
                &serde_json::to_vec(&value).expect("serialize existing volatile fixture"),
                0o600,
            );
            assert!(
                DaemonVerificationPolicy::load(&volatile_policy, true).is_err(),
                "an existing private tmpfs directory is not a persistent ledger"
            );
            assert_eq!(
                std::fs::read_dir(memory.path())
                    .expect("volatile contents")
                    .count(),
                0
            );
        }

        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o777))
            .expect("make fixture ancestor writable by others");
        assert!(DaemonVerificationPolicy::load(&policy_path, true).is_err());
    }
}
