//! One validated request model for backups (remediation plan block 2.5).
//!
//! The CLI and the daemon used to build engine requests separately, and the
//! daemon route silently dropped options the direct route honoured (R31).
//! Both now describe a backup as a [`BackupSpec`] and turn it into an engine
//! job with [`backup_job`], so a command behaves the same whichever route
//! runs it. An option the chosen mode cannot honour is refused, never
//! dropped.
#![forbid(unsafe_code)]

use std::path::PathBuf;

use lr_core::{Error, Result};
use lr_engine::backup::{BackupRequest, ImageReport};
use lr_engine::file::FileBackupOptions;
use lr_engine::options::Mode;
use lr_engine::progress::EngineContext;
use lr_proto::v1::BackupSpec;

/// A backup ready to run.
pub struct BackupJob {
    /// The engine request.
    pub request: BackupRequest,
    /// The mode after resolving `auto`.
    pub mode: Mode,
    /// File-mode options; defaults for the other modes.
    pub file: FileBackupOptions,
}

/// Turn a backup description into a job, validating every field.
///
/// Empty optional fields mean the documented defaults, so a client that
/// leaves one out (the GUI, a script) need not repeat them.
///
/// # Errors
/// Returns [`Error::Unsupported`] for an invalid value or an option the
/// resolved mode cannot honour, and propagates key and name validation.
pub fn backup_job(spec: &BackupSpec) -> Result<BackupJob> {
    let encryption = lr_engine::options::backup_encryption(
        spec.no_encrypt,
        (!spec.passphrase_file.is_empty())
            .then(|| PathBuf::from(&spec.passphrase_file))
            .as_deref(),
    )?;
    let mut request = BackupRequest::new(&spec.source, &spec.dest, &spec.set, encryption)?;
    request.dest.clone_from(&spec.dest);
    // A remote destination has no local path; the freeze guard learns about
    // it from the parsed URI (R27).
    request.dest_root = if spec.dest.contains("://") {
        PathBuf::new()
    } else {
        PathBuf::from(&spec.dest)
    };
    request.member_type = lr_engine::options::parse_member_type(or(&spec.member_type, "full"))?;
    request.parent = (!spec.parent.is_empty()).then(|| spec.parent.clone());
    request.snapshot_provider = lr_engine::options::parse_snapshot(&spec.snapshot);
    request.compression = if spec.compress.is_empty() {
        lr_engine::backup::Compression::default()
    } else {
        lr_engine::options::parse_compression(&spec.compress)?
    };
    request.on_bad_sector = lr_engine::options::parse_bad_sector(or(&spec.on_bad_sector, "abort"))?;
    if !spec.chunk_size.is_empty() {
        request.chunk_size = u32::try_from(lr_engine::options::parse_size(&spec.chunk_size)?)
            .map_err(|_| Error::unsupported("chunk size does not fit in 32 bits"))?;
    }
    request.allow_freeze = spec.allow_freeze;
    request.freeze_timeout_secs =
        (spec.freeze_timeout_secs > 0).then_some(spec.freeze_timeout_secs);
    request.deadman_grace_secs = (spec.deadman_grace_secs > 0).then_some(spec.deadman_grace_secs);
    request.allow_inconsistent = spec.allow_inconsistent;
    request.lvm_cow_size = (!spec.lvm_cow_size.is_empty()).then(|| spec.lvm_cow_size.clone());
    request.break_stale_lock = spec.break_stale_lock;
    request.max_incrementals_per_chain =
        (spec.max_incrementals > 0).then_some(spec.max_incrementals);
    request.exclude_nested_subvolumes = spec.exclude_nested_subvolumes;
    request.destination_options = lr_store::DestinationOptions {
        set_name: spec.set.clone(),
        identity: (!spec.identity.is_empty()).then(|| PathBuf::from(&spec.identity)),
        known_hosts: (!spec.known_hosts.is_empty()).then(|| PathBuf::from(&spec.known_hosts)),
        insecure_ignore_host_key: spec.insecure_ignore_host_key,
    };

    let mode = match lr_engine::options::parse_mode(or(&spec.mode, "auto"))? {
        Mode::Auto if request.source.is_dir() => Mode::File,
        other => other,
    };
    if mode != Mode::File {
        for (set, flag) in [
            (spec.one_file_system, "--one-file-system"),
            (spec.verify_content, "--verify-content"),
        ] {
            if set {
                return Err(Error::unsupported(format!(
                    "{flag} applies to file mode only; this backup runs in {} mode",
                    mode_name(mode)
                )));
            }
        }
    }
    let file = FileBackupOptions {
        one_file_system: spec.one_file_system,
        verify_content: spec.verify_content,
        ..FileBackupOptions::default()
    };
    Ok(BackupJob {
        request,
        mode,
        file,
    })
}

/// Run a job with `context` for progress and cancellation.
///
/// # Errors
/// Propagates the engine's errors.
pub fn run_backup(job: BackupJob, context: EngineContext) -> Result<ImageReport> {
    let BackupJob {
        mut request,
        mode,
        file,
    } = job;
    request.context = context;
    match mode {
        Mode::File => Ok(ImageReport::File(lr_engine::file::backup_file(
            &request, &file,
        )?)),
        mode => lr_engine::backup_image_with_mode(&request, mode),
    }
}

/// Plan a validated job with the engine's execution-matched source decisions.
///
/// The plan reads source metadata and content estimates only. It does not open
/// the destination, acquire a set lock, or create a snapshot.
///
/// # Errors
/// Propagates source, provider, and option validation failures.
pub fn plan_backup(job: &BackupJob) -> Result<lr_engine::BackupPlan> {
    lr_engine::plan_backup(&job.request, job.mode, &job.file)
}

fn or<'a>(value: &'a str, default: &'a str) -> &'a str {
    if value.is_empty() { default } else { value }
}

fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::Auto => "auto",
        Mode::Block => "block",
        Mode::Stream => "stream",
        Mode::File => "file",
    }
}

#[cfg(test)]
mod tests {
    use super::{BackupSpec, backup_job, plan_backup, run_backup};
    use lr_engine::ImageReport;
    use lr_engine::options::Mode;
    use lr_engine::progress::EngineContext;

    /// Every non-default option reaches the job, whichever route builds it
    /// (R31): the CLI's direct route and the daemon call this one function.
    #[test]
    fn every_option_reaches_the_job() {
        let dir = tempfile::tempdir().expect("tempdir");
        let spec = BackupSpec {
            source: dir.path().display().to_string(),
            dest: "/srv/backups".to_owned(),
            set: "laptop".to_owned(),
            member_type: "incremental".to_owned(),
            parent: "latest".to_owned(),
            mode: "file".to_owned(),
            snapshot: "btrfs".to_owned(),
            compress: "zstd:9".to_owned(),
            no_encrypt: true,
            on_bad_sector: "record".to_owned(),
            chunk_size: "2MiB".to_owned(),
            allow_freeze: true,
            allow_inconsistent: true,
            lvm_cow_size: "5G".to_owned(),
            identity: "/root/.ssh/id".to_owned(),
            known_hosts: "/root/.ssh/known_hosts".to_owned(),
            insecure_ignore_host_key: true,
            max_incrementals: 7,
            verify_content: true,
            exclude_nested_subvolumes: true,
            one_file_system: true,
            freeze_timeout_secs: 45,
            deadman_grace_secs: 12,
            break_stale_lock: true,
            ..BackupSpec::default()
        };
        let job = backup_job(&spec).expect("job");
        let request = &job.request;
        assert_eq!(job.mode, Mode::File);
        assert!(job.file.one_file_system && job.file.verify_content);
        assert_eq!(request.dest, "/srv/backups");
        assert_eq!(request.dest_root, std::path::PathBuf::from("/srv/backups"));
        assert_eq!(
            request.member_type,
            lr_engine::backup::MemberType::Incremental
        );
        assert_eq!(request.parent.as_deref(), Some("latest"));
        assert_eq!(request.snapshot_provider.as_deref(), Some("btrfs"));
        assert_eq!(
            request.compression,
            lr_engine::backup::Compression::Zstd { level: 9 }
        );
        assert_eq!(
            request.on_bad_sector,
            lr_engine::backup::BadSectorPolicy::Record
        );
        assert_eq!(request.chunk_size, 2 * 1024 * 1024);
        assert!(request.allow_freeze && request.allow_inconsistent);
        assert_eq!(request.lvm_cow_size.as_deref(), Some("5G"));
        assert_eq!(request.max_incrementals_per_chain, Some(7));
        assert!(request.exclude_nested_subvolumes && request.break_stale_lock);
        assert_eq!(request.freeze_timeout_secs, Some(45));
        assert_eq!(request.deadman_grace_secs, Some(12));
        let destination = &request.destination_options;
        assert_eq!(destination.set_name, "laptop");
        assert!(destination.identity.is_some() && destination.known_hosts.is_some());
        assert!(destination.insecure_ignore_host_key);
    }

    /// A file-mode option on a block backup is refused, not dropped.
    #[test]
    fn an_option_the_mode_cannot_honour_is_refused() {
        let spec = BackupSpec {
            source: "/dev/null".to_owned(),
            dest: "/srv/backups".to_owned(),
            set: "disk".to_owned(),
            mode: "block".to_owned(),
            no_encrypt: true,
            one_file_system: true,
            ..BackupSpec::default()
        };
        let error = backup_job(&spec).err().expect("refused");
        assert!(error.to_string().contains("--one-file-system"), "{error}");
    }

    #[test]
    fn file_plan_is_read_only_and_matches_the_executed_consistency() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = dir.path().join("source");
        std::fs::create_dir(&source).expect("source directory");
        std::fs::write(source.join("data.txt"), b"planned bytes").expect("source data");
        let dest = dir.path().join("backups");
        let spec = BackupSpec {
            source: source.display().to_string(),
            dest: dest.display().to_string(),
            set: "file-plan".to_owned(),
            mode: "file".to_owned(),
            snapshot: "none".to_owned(),
            compress: "none".to_owned(),
            no_encrypt: true,
            one_file_system: true,
            verify_content: true,
            ..BackupSpec::default()
        };
        let job = backup_job(&spec).expect("job");
        let plan = plan_backup(&job).expect("read-only plan");

        assert_eq!(plan.provider, "file");
        assert_eq!(plan.image_kind, lr_core::ImageKind::File);
        assert_eq!(plan.consistency, lr_core::Consistency::PerFile);
        assert_eq!(plan.estimated_bytes, b"planned bytes".len() as u64);
        assert!(
            plan.warnings
                .iter()
                .any(|warning| warning.contains("source-side plan"))
        );
        assert!(!dest.exists(), "planning must not create the destination");

        let report = run_backup(job, EngineContext::silent()).expect("file backup");
        let ImageReport::File(report) = report else {
            panic!("file mode must produce a file report");
        };
        assert_eq!(plan.consistency, report.consistency);
        assert!(dest.is_dir(), "execution creates the destination");
    }

    #[test]
    fn file_plan_refuses_an_unavailable_forced_snapshot_provider() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = dir.path().join("source");
        std::fs::create_dir(&source).expect("source directory");
        let job = backup_job(&BackupSpec {
            source: source.display().to_string(),
            dest: dir.path().join("backups").display().to_string(),
            set: "file-plan".to_owned(),
            mode: "file".to_owned(),
            snapshot: "lvm".to_owned(),
            no_encrypt: true,
            ..BackupSpec::default()
        })
        .expect("job");

        let error = plan_backup(&job).expect_err("file mode cannot honor LVM snapshots");
        assert!(error.to_string().contains("`lvm`"), "{error}");
    }

    #[test]
    fn forced_stream_mode_on_a_block_source_fails_before_destination_creation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = dir.path().join("source.img");
        let image = std::fs::File::create(&source).expect("source image");
        image.set_len(4 * 1024 * 1024).expect("image size");
        drop(image);
        let dest = dir.path().join("backups");
        let job = backup_job(&BackupSpec {
            source: source.display().to_string(),
            dest: dest.display().to_string(),
            set: "mode-plan".to_owned(),
            mode: "stream".to_owned(),
            no_encrypt: true,
            ..BackupSpec::default()
        })
        .expect("job");

        let plan_error = plan_backup(&job).expect_err("stream requires a Btrfs stream source");
        assert!(
            plan_error.to_string().contains("resolves to block mode"),
            "{plan_error}"
        );
        assert!(
            !dest.exists(),
            "a refused plan must not create the destination"
        );

        let run_error = run_backup(job, EngineContext::silent())
            .expect_err("execution must enforce the same forced mode");
        assert!(
            run_error.to_string().contains("resolves to block mode"),
            "{run_error}"
        );
        assert!(
            !dest.exists(),
            "a refused execution must not create the destination"
        );
    }
}
