//! The freeze provider (spec §E.4).
//!
//! `FIFREEZE` makes a mounted filesystem consistent for the whole read, at the
//! cost of blocking every writer on it. Two properties make that safe:
//!
//! * the destination must live on another filesystem, otherwise the backup
//!   would deadlock against its own writes;
//! * an external deadman thaws the filesystem even if this process is killed,
//!   because a frozen filesystem blocks writers *indefinitely* (verified in
//!   step 0: a write to a frozen ext4 never returns until thaw).
//!
//! The deadman is layered: a `systemd-run --on-active` timer plus a detached
//! `sleep`-and-thaw helper, both guarded by a marker file so a stale timer
//! cannot thaw a later job. Timers on some systems (WSL) fire tens of seconds
//! late, which is why the detached helper is not optional.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use lr_core::{Consistency, Error, Result, SnapshotOpts, SourceLayout, Support};

use crate::probe::is_running_root;
use crate::{BlockSnapshot, BlockSnapshotProvider, SnapshotHealth};

/// Provider identifier.
pub const ID: &str = "freeze";

/// Default freeze timeout (spec §E.4).
pub const DEFAULT_TIMEOUT_SECS: u64 = 300;

/// Default extra grace before the deadman fires (spec §E.4).
pub const DEFAULT_GRACE_SECS: u64 = 30;

/// Paths a frozen filesystem may not contain.
pub const FORBIDDEN_PATHS: [&str; 4] = ["/var/log", "/var/lib/linuxreflect", "/run", "/tmp"];

static PROVIDER: FreezeProvider = FreezeProvider;
static JOB_COUNTER: AtomicU64 = AtomicU64::new(0);

/// The freeze provider.
#[derive(Debug, Default, Clone, Copy)]
pub struct FreezeProvider;

/// The shared instance.
#[must_use]
pub fn provider() -> &'static FreezeProvider {
    &PROVIDER
}

impl BlockSnapshotProvider for FreezeProvider {
    fn id(&self) -> &'static str {
        ID
    }

    fn supports(&self, src: &SourceLayout, opts: &SnapshotOpts) -> Support {
        match refusal(src, opts) {
            Some(reason) => Support::No(reason),
            None => Support::Yes,
        }
    }

    fn create(&self, src: &SourceLayout, opts: &SnapshotOpts) -> Result<BlockSnapshot> {
        if let Some(reason) = refusal(src, opts) {
            return Err(Error::no_consistent_method([
                format!("freeze refused: {reason}"),
                "unmount the filesystem for offline consistency".to_owned(),
                "install the source on LVM or Btrfs and snapshot it".to_owned(),
            ]));
        }
        let mountpoint = mountpoint_of(src).ok_or_else(|| {
            Error::unsupported("freeze needs a mounted source, but none was found")
        })?;
        let timeout = Duration::from_secs(opts.freeze_timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS));
        let grace = Duration::from_secs(opts.deadman_grace_secs.unwrap_or(DEFAULT_GRACE_SECS));
        let job = format!(
            "lr-{}-{}",
            std::process::id(),
            JOB_COUNTER.fetch_add(1, Ordering::SeqCst)
        );
        let marker = marker_path(&job)?;
        let log = Arc::new(FreezeLog::default());

        // 1. Arm the external deadman before freezing anything.
        arm_deadman(&job, &mountpoint, &marker, timeout + grace, &log)?;

        // 2. Freeze.
        let dir = lr_unsafe::open_dir_readonly(&mountpoint).map_err(|e| {
            remove_marker(&marker);
            Error::Io(std::io::Error::new(
                e.kind(),
                format!("open {}: {e}", mountpoint.display()),
            ))
        })?;
        if let Err(error) = lr_unsafe::freeze_fs(&dir) {
            remove_marker(&marker);
            disarm_deadman(&job);
            return Err(Error::Io(std::io::Error::new(
                error.kind(),
                format!("FIFREEZE on {}: {error}", mountpoint.display()),
            )));
        }
        log.record(&format!(
            "froze {} for job {job}; deadman fires in {}s",
            mountpoint.display(),
            (timeout + grace).as_secs()
        ));

        let health = Arc::new(FreezeHealth {
            started: Instant::now(),
            timeout,
        });
        Ok(BlockSnapshot::new(
            src.device.clone(),
            Consistency::Frozen,
            FreezeGuard {
                job,
                mountpoint,
                marker,
                dir: Some(dir),
                log,
                thawed: false,
            },
        )
        .with_health(health))
    }
}

/// Why this source cannot be frozen, if it cannot.
fn refusal(src: &SourceLayout, opts: &SnapshotOpts) -> Option<String> {
    let forced = opts.provider.as_deref().filter(|name| *name != "auto");
    if let Some(name) = forced
        && name != ID
    {
        return Some(format!("another provider ({name}) was requested"));
    }
    if !opts.allow_freeze && forced != Some(ID) {
        return Some("freezing blocks every writer on the source; pass --allow-freeze".to_owned());
    }
    let Some(mountpoint) = mountpoint_of(src) else {
        return Some("the source is not mounted; use the offline provider".to_owned());
    };
    if is_running_root(src) {
        return Some(format!("{} holds the running system", mountpoint.display()));
    }
    use std::os::unix::fs::MetadataExt;

    let mountpoint_dev = std::fs::metadata(&mountpoint).ok().map(|m| m.dev());
    let text = mountpoint.to_string_lossy();
    for forbidden in FORBIDDEN_PATHS {
        // The forbidden path lives *inside* the filesystem being frozen.
        // (The reverse — a mount point below /tmp, as in a test fixture — is a
        // different filesystem and is fine.)
        let inside = text == "/" || forbidden.starts_with(&format!("{text}/"));
        if text == forbidden || inside {
            return Some(format!(
                "{} contains {forbidden}, which must stay writable",
                mountpoint.display()
            ));
        }
        // Or the filesystem being frozen contains one of those paths.
        if let (Some(mountpoint_dev), Ok(metadata)) = (mountpoint_dev, std::fs::metadata(forbidden))
            && metadata.dev() == mountpoint_dev
        {
            return Some(format!("the filesystem being frozen contains {forbidden}"));
        }
    }
    // The working directory must not be on the frozen filesystem either: our
    // own writes would block.
    if let (Some(mountpoint_dev), Ok(cwd)) = (mountpoint_dev, std::env::current_dir())
        && std::fs::metadata(&cwd).is_ok_and(|metadata| metadata.dev() == mountpoint_dev)
    {
        return Some(format!(
            "the working directory {} is on the filesystem being frozen",
            cwd.display()
        ));
    }
    if opts.destination_remote {
        // A remote destination cannot be the filesystem being frozen.
        return None;
    }
    let Some(destination) = opts.destination.as_deref() else {
        return Some(
            "freeze needs the destination to prove it is on another filesystem".to_owned(),
        );
    };
    let (Ok(source_metadata), Ok(destination_metadata)) = (
        std::fs::metadata(&mountpoint),
        std::fs::metadata(destination),
    ) else {
        return Some(format!(
            "cannot stat {} or {}",
            mountpoint.display(),
            destination.display()
        ));
    };
    if source_metadata.dev() == destination_metadata.dev() {
        return Some(format!(
            "the destination {} is on the filesystem being frozen; the backup would deadlock",
            destination.display()
        ));
    }
    None
}

fn mountpoint_of(src: &SourceLayout) -> Option<PathBuf> {
    src.mountpoints.first().cloned().or_else(|| {
        src.partitions
            .iter()
            .find_map(|partition| partition.mountpoints.first().cloned())
    })
}

/// Where the runtime marker lives, so the deadman can tell jobs apart.
///
/// # Errors
/// Returns [`Error::Io`] when no runtime directory exists.
pub fn marker_path(job: &str) -> Result<PathBuf> {
    for dir in [PathBuf::from("/run/linuxreflect"), PathBuf::from("/tmp")] {
        if std::fs::create_dir_all(&dir).is_ok() && writable(&dir) {
            return Ok(dir.join(format!("{job}.freeze")));
        }
    }
    Err(Error::Io(std::io::Error::other(
        "no writable runtime directory for the freeze marker",
    )))
}

fn writable(dir: &Path) -> bool {
    let probe = dir.join(format!(".probe-{}", std::process::id()));
    match std::fs::File::create(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

fn arm_deadman(
    job: &str,
    mountpoint: &Path,
    marker: &Path,
    after: Duration,
    log: &FreezeLog,
) -> Result<()> {
    std::fs::write(marker, format!("{}\n", mountpoint.display())).map_err(Error::Io)?;
    let seconds = after.as_secs().max(1);
    let guard = format!(
        "if [ -f '{marker}' ]; then fsfreeze -u '{mp}'; rm -f '{marker}'; fi",
        marker = marker.display(),
        mp = mountpoint.display()
    );

    // Layer 1: a transient systemd timer, when systemd is available.
    let unit = format!("lr-thaw-{job}");
    if which("systemd-run") {
        let status = Command::new("systemd-run")
            .arg(format!("--on-active={seconds}"))
            .arg(format!("--unit={unit}"))
            .arg("--collect")
            .arg("/bin/sh")
            .arg("-c")
            .arg(&guard)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        match status {
            Ok(status) if status.success() => {
                log.record(&format!("armed systemd deadman {unit} (+{seconds}s)"));
            }
            other => {
                log.record(&format!(
                    "systemd-run could not arm {unit} ({other:?}); relying on the detached helper"
                ));
            }
        }
    }

    // Layer 2: a detached helper that survives this process being killed.
    let fallback = format!("sleep {seconds}; {guard}");
    Command::new("/bin/sh")
        .arg("-c")
        .arg(&fallback)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(Error::Io)?;
    log.record(&format!("armed detached deadman (+{seconds}s)"));
    Ok(())
}

fn which(program: &str) -> bool {
    Command::new("which")
        .arg(program)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn remove_marker(marker: &Path) {
    let _ = std::fs::remove_file(marker);
}

fn disarm_deadman(job: &str) {
    let unit = format!("lr-thaw-{job}");
    for action in ["stop", "reset-failed"] {
        let target = if action == "stop" {
            format!("{unit}.timer")
        } else {
            format!("{unit}.service")
        };
        let _ = Command::new("systemctl")
            .args([action, &target])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// Thaw on drop, always.
struct FreezeGuard {
    job: String,
    mountpoint: PathBuf,
    marker: PathBuf,
    dir: Option<std::os::fd::OwnedFd>,
    log: Arc<FreezeLog>,
    thawed: bool,
}

impl Drop for FreezeGuard {
    fn drop(&mut self) {
        if self.thawed {
            return;
        }
        // Removing the marker first stops the deadman from thawing twice.
        remove_marker(&self.marker);
        if let Some(dir) = self.dir.take() {
            match lr_unsafe::thaw_fs(&dir) {
                Ok(()) => self
                    .log
                    .record(&format!("thawed {}", self.mountpoint.display())),
                Err(error) => self.log.record(&format!(
                    "FITHAW on {} failed: {error}",
                    self.mountpoint.display()
                )),
            }
        }
        disarm_deadman(&self.job);
        self.log.flush();
        self.thawed = true;
    }
}

/// In-memory log, flushed after thaw: nothing may write to a frozen
/// filesystem, and journald lives on one.
#[derive(Default)]
pub struct FreezeLog {
    entries: Mutex<Vec<String>>,
}

impl FreezeLog {
    /// Record one line.
    pub fn record(&self, line: &str) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.push(line.to_owned());
        }
        tracing::debug!(target: "lr_snapshot::freeze", "{line}");
    }

    /// Emit everything recorded so far.
    pub fn flush(&self) {
        if let Ok(mut entries) = self.entries.lock() {
            for line in entries.drain(..) {
                tracing::info!(target: "lr_snapshot::freeze", "{line}");
            }
        }
    }
}

/// Aborts the job when the read outlives `--freeze-timeout` (spec §E.4 step 6).
struct FreezeHealth {
    started: Instant,
    timeout: Duration,
}

impl SnapshotHealth for FreezeHealth {
    fn check(&self) -> Result<()> {
        if self.started.elapsed() > self.timeout {
            return Err(Error::FreezeTimeout);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_GRACE_SECS, FreezeProvider, marker_path};
    use crate::BlockSnapshotProvider;
    use crate::test_layout::offline;
    use lr_core::SnapshotOpts;
    use std::path::PathBuf;

    fn layout(mountpoint: &str) -> lr_core::SourceLayout {
        let mut layout = offline("/dev/lr-freeze");
        layout.mountpoints.push(PathBuf::from(mountpoint));
        layout
    }

    fn opts(destination: &str) -> SnapshotOpts {
        SnapshotOpts {
            allow_freeze: true,
            destination: Some(PathBuf::from(destination)),
            ..SnapshotOpts::default()
        }
    }

    #[test]
    fn refuses_without_the_opt_in() {
        let support = FreezeProvider.supports(&layout("/mnt/data"), &SnapshotOpts::default());
        assert!(
            support
                .reason()
                .is_some_and(|reason| reason.contains("--allow-freeze"))
        );
    }

    #[test]
    fn refuses_the_running_root() {
        let support = FreezeProvider.supports(&layout("/"), &opts("/mnt/backup"));
        assert!(
            support
                .reason()
                .is_some_and(|reason| reason.contains("running system"))
        );
    }

    #[test]
    fn refuses_directories_that_must_stay_writable() {
        for mountpoint in [
            "/var/log",
            "/var/log/journal",
            "/tmp",
            "/run",
            "/var/lib/linuxreflect",
        ] {
            let support = FreezeProvider.supports(&layout(mountpoint), &opts("/mnt/backup"));
            assert!(support.reason().is_some(), "{mountpoint} must be refused");
        }
    }

    #[test]
    fn refuses_a_source_that_is_not_mounted() {
        let support = FreezeProvider.supports(&offline("/dev/lr-freeze"), &opts("/mnt/backup"));
        assert!(!support.is_yes());
    }

    #[test]
    fn requires_a_destination_for_the_same_filesystem_check() {
        let options = SnapshotOpts {
            allow_freeze: true,
            destination: None,
            ..SnapshotOpts::default()
        };
        let support = FreezeProvider.supports(&layout("/mnt/data"), &options);
        assert!(
            support.reason().is_some(),
            "no destination means no st_dev proof"
        );
    }

    #[test]
    fn the_default_grace_is_the_spec_value() {
        assert_eq!(DEFAULT_GRACE_SECS, 30);
    }

    #[test]
    fn the_marker_path_is_writable_and_job_specific() {
        let marker = marker_path("lr-test-marker").expect("marker path");
        assert!(marker.to_string_lossy().contains("lr-test-marker"));
        assert!(marker.parent().expect("parent").is_dir());
    }

    #[test]
    fn a_same_filesystem_destination_is_refused() {
        // /tmp and / share a filesystem in this environment only when /tmp is
        // not a separate mount; the check is exercised with two paths in the
        // same directory instead, which are always the same filesystem.
        let support = FreezeProvider.supports(&layout("/mnt"), &opts("/mnt"));
        assert!(
            support.reason().is_some(),
            "a destination inside the frozen filesystem must be refused"
        );
    }
}
