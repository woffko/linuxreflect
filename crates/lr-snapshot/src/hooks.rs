//! Pre-freeze and post-thaw hooks of the tracked-freeze provider (spec §E.7).
//!
//! Executables in `<root>/pre-freeze.d/` run in name order before the final
//! freeze, and those in `<root>/post-thaw.d/` after the thaw, so applications
//! that need their own quiescence (a database flush, a paused container) get
//! it. They run as root, so they are checked before the job starts: the
//! hooks directory, each stage directory and each hook must be owned by root
//! and not writable by group or others, and a hook must be a regular file;
//! anything else refuses the job. Names follow `run-parts`: only
//! `[A-Za-z0-9_-]` names run (`.dpkg-old` leftovers do not), and a file
//! without its owner's execute bit is skipped (D-140).
//!
//! A hook gets an empty environment except `PATH`, `LINUXREFLECT_STAGE`
//! (`pre-freeze` or `post-thaw`) and `LINUXREFLECT_FILESYSTEMS` (the
//! mount points the final freeze covers, one per line, `/` last), `/` as its
//! working directory, no standard input, and a time limit.

use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use lr_core::{Error, Result};

/// Where the hooks live (spec §E.7).
pub const DEFAULT_HOOKS_DIR: &str = "/etc/linuxreflect/hooks";
/// The time limit of one hook (spec §E.7: default 30 s).
pub const DEFAULT_HOOK_TIMEOUT: Duration = Duration::from_secs(30);
/// The `PATH` a hook runs with.
const HOOK_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
/// How much of a failing hook's standard error its message keeps.
const STDERR_TAIL_BYTES: usize = 512;

/// When a hook runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// Before the final freeze; a failure stops the job.
    PreFreeze,
    /// After the thaw; a failure is a warning.
    PostThaw,
}

impl Stage {
    /// The stage's name, as hooks see it in `LINUXREFLECT_STAGE`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::PreFreeze => "pre-freeze",
            Self::PostThaw => "post-thaw",
        }
    }

    const fn directory(self) -> &'static str {
        match self {
            Self::PreFreeze => "pre-freeze.d",
            Self::PostThaw => "post-thaw.d",
        }
    }
}

/// The checked hooks of both stages, in name order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hooks {
    pre_freeze: Vec<PathBuf>,
    post_thaw: Vec<PathBuf>,
    timeout: Duration,
}

impl Hooks {
    /// Find and check the hooks under `root`. A missing directory holds no
    /// hooks.
    ///
    /// # Errors
    /// Returns [`Error::Unsupported`] naming a directory or hook that is not
    /// safe to run as root, and [`Error::Io`] when one cannot be read.
    pub fn load(root: &Path, timeout: Duration) -> Result<Self> {
        if !safe_directory(root)? {
            return Ok(Self {
                timeout,
                ..Self::default()
            });
        }
        Ok(Self {
            pre_freeze: stage_hooks(root, Stage::PreFreeze)?,
            post_thaw: stage_hooks(root, Stage::PostThaw)?,
            timeout,
        })
    }

    /// The hooks of `stage`, in the order they run.
    #[must_use]
    pub fn of(&self, stage: Stage) -> &[PathBuf] {
        match stage {
            Stage::PreFreeze => &self.pre_freeze,
            Stage::PostThaw => &self.post_thaw,
        }
    }

    /// Run the pre-freeze hooks in order. The first one that fails stops the
    /// rest.
    ///
    /// # Errors
    /// Returns [`Error::HookFailed`] naming the hook and why.
    pub fn pre_freeze(&self, filesystems: &[PathBuf]) -> Result<()> {
        for hook in &self.pre_freeze {
            run(hook, Stage::PreFreeze, filesystems, self.timeout).map_err(|reason| {
                Error::HookFailed {
                    hook: hook.display().to_string(),
                    reason,
                }
            })?;
        }
        Ok(())
    }

    /// Run every post-thaw hook. A failure does not end the job, whose data
    /// is already read; each one is returned as a warning.
    #[must_use]
    pub fn post_thaw(&self, filesystems: &[PathBuf]) -> Vec<String> {
        let mut warnings = Vec::new();
        for hook in &self.post_thaw {
            if let Err(reason) = run(hook, Stage::PostThaw, filesystems, self.timeout) {
                warnings.push(format!("the post-thaw hook {} {reason}", hook.display()));
            }
        }
        warnings
    }
}

/// `Ok(false)` for a directory that does not exist; `Ok(true)` for one that
/// is safe to take hooks from.
fn safe_directory(path: &Path) -> Result<bool> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(Error::Io(error)),
    };
    if !metadata.file_type().is_dir() {
        return Err(unsafe_hook(path, "is not a directory"));
    }
    owned_by_root(path, &metadata)?;
    Ok(true)
}

fn owned_by_root(path: &Path, metadata: &std::fs::Metadata) -> Result<()> {
    if metadata.uid() != 0 {
        return Err(unsafe_hook(path, "is not owned by root"));
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(unsafe_hook(path, "is writable by its group or by others"));
    }
    Ok(())
}

fn unsafe_hook(path: &Path, why: &str) -> Error {
    Error::unsupported(format!(
        "{} {why}; tracked-freeze hooks run as root, so it is refused",
        path.display()
    ))
}

/// A name `run-parts` would run.
fn runnable_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn stage_hooks(root: &Path, stage: Stage) -> Result<Vec<PathBuf>> {
    let directory = root.join(stage.directory());
    if !safe_directory(&directory)? {
        return Ok(Vec::new());
    }
    let mut hooks = Vec::new();
    for entry in std::fs::read_dir(&directory).map_err(Error::Io)? {
        let entry = entry.map_err(Error::Io)?;
        let name = entry.file_name();
        if !name.to_str().is_some_and(runnable_name) {
            continue;
        }
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path).map_err(Error::Io)?;
        if !metadata.file_type().is_file() {
            return Err(unsafe_hook(&path, "is not a regular file"));
        }
        if metadata.mode() & 0o100 == 0 {
            continue;
        }
        owned_by_root(&path, &metadata)?;
        hooks.push(path);
    }
    hooks.sort();
    Ok(hooks)
}

/// Run one hook; the error says what went wrong.
fn run(
    hook: &Path,
    stage: Stage,
    filesystems: &[PathBuf],
    timeout: Duration,
) -> std::result::Result<(), String> {
    let mut listed = String::new();
    for filesystem in filesystems {
        listed.push_str(&filesystem.display().to_string());
        listed.push('\n');
    }
    let mut child = Command::new(hook)
        .env_clear()
        .env("PATH", HOOK_PATH)
        .env("LINUXREFLECT_STAGE", stage.name())
        .env("LINUXREFLECT_FILESYSTEMS", listed.trim_end())
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("could not be started: {error}"))?;
    // Standard error is read on its own thread, so a chatty hook cannot fill
    // the pipe and stall; only its tail is kept.
    let stderr = child.stderr.take();
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut tail = Vec::new();
        if let Some(mut stderr) = stderr {
            let mut block = [0u8; 4096];
            while let Ok(read) = stderr.read(&mut block) {
                if read == 0 {
                    break;
                }
                tail.extend_from_slice(&block[..read]);
                if tail.len() > STDERR_TAIL_BYTES {
                    tail.drain(..tail.len() - STDERR_TAIL_BYTES);
                }
            }
        }
        let _ = sender.send(tail);
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("could not be waited for: {error}"));
            }
        }
    };
    // A process the hook left behind may keep the pipe open: do not wait
    // for it.
    let tail = receiver
        .recv_timeout(Duration::from_millis(500))
        .unwrap_or_default();
    let tail = String::from_utf8_lossy(&tail).trim().to_owned();
    let said = if tail.is_empty() {
        String::new()
    } else {
        format!(": {tail}")
    };
    match status {
        None => Err(format!(
            "did not finish within {} s{said}",
            timeout.as_secs_f64()
        )),
        Some(status) if status.success() => Ok(()),
        Some(status) => Err(format!("failed ({status}){said}")),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("script");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("mode");
        path
    }

    #[test]
    fn only_run_parts_names_run() {
        for name in ["10-flush-db", "pause_containers", "A1"] {
            assert!(runnable_name(name), "{name}");
        }
        for name in [
            "",
            ".hidden",
            "hook.dpkg-old",
            "hook~",
            "two words",
            "räksmörgås",
        ] {
            assert!(!runnable_name(name), "{name}");
        }
    }

    #[test]
    fn a_missing_hooks_directory_holds_no_hooks() {
        let dir = tempfile::tempdir().expect("dir");
        let hooks = Hooks::load(&dir.path().join("absent"), DEFAULT_HOOK_TIMEOUT).expect("load");
        assert!(hooks.of(Stage::PreFreeze).is_empty() && hooks.of(Stage::PostThaw).is_empty());
    }

    #[test]
    fn hooks_not_owned_by_root_are_refused() {
        let dir = tempfile::tempdir().expect("dir");
        if std::fs::metadata(dir.path()).expect("meta").uid() == 0 {
            return; // As root the directory is root's; the root suite covers it.
        }
        let error = Hooks::load(dir.path(), DEFAULT_HOOK_TIMEOUT).expect_err("refused");
        assert!(
            error.to_string().contains("is not owned by root"),
            "{error}"
        );
    }

    #[test]
    fn a_hook_runs_with_a_clean_environment() {
        let dir = tempfile::tempdir().expect("dir");
        let out = dir.path().join("env.txt");
        let hook = script(dir.path(), "envdump", &format!("env > {}", out.display()));
        run(
            &hook,
            Stage::PreFreeze,
            &[PathBuf::from("/boot"), PathBuf::from("/")],
            DEFAULT_HOOK_TIMEOUT,
        )
        .expect("hook");
        let env = std::fs::read_to_string(&out).expect("env");
        assert!(env.contains("LINUXREFLECT_STAGE=pre-freeze"), "{env}");
        assert!(env.contains("LINUXREFLECT_FILESYSTEMS=/boot\n/\n"), "{env}");
        assert!(env.contains(&format!("PATH={HOOK_PATH}")), "{env}");
        assert!(
            !env.contains("HOME="),
            "the caller's environment leaked: {env}"
        );
    }

    #[test]
    fn a_failing_hook_reports_its_status_and_last_words() {
        let dir = tempfile::tempdir().expect("dir");
        let hook = script(
            dir.path(),
            "fails",
            "echo noise >&2; echo 'database not ready' >&2; exit 3",
        );
        let reason =
            run(&hook, Stage::PreFreeze, &[], DEFAULT_HOOK_TIMEOUT).expect_err("must fail");
        assert!(reason.contains("exit status: 3"), "{reason}");
        assert!(reason.contains("database not ready"), "{reason}");
    }

    #[test]
    fn a_hook_that_overruns_its_limit_is_killed() {
        let dir = tempfile::tempdir().expect("dir");
        let hook = script(dir.path(), "sleeps", "sleep 30");
        let started = Instant::now();
        let reason =
            run(&hook, Stage::PostThaw, &[], Duration::from_millis(200)).expect_err("timeout");
        assert!(reason.contains("did not finish within 0.2 s"), "{reason}");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
    }
}
