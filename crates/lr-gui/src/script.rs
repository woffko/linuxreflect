//! A small automation script for the GUI (spec §K S15).
//!
//! The GUI is driven by clicks, and a windowed test cannot click reliably on
//! every display server. This script therefore sets the same UI properties a
//! user would type and invokes the same callbacks a click invokes, while the
//! window is really shown on X11 or Wayland; the acceptance test then checks
//! the images and the restored data on disk.

use std::path::PathBuf;

use anyhow::Context;
use lr_core::Error;

/// One automation step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Set the source field.
    Source(String),
    /// Set the destination field.
    Destination(String),
    /// Set the set-name field.
    SetName(String),
    /// Set the mode field.
    Mode(String),
    /// Enable backup encryption using an existing protected passphrase file.
    BackupPassphraseFile(String),
    /// Choose the restore passphrase file, invalidating any prepared plan.
    RestorePassphraseFile(String),
    /// Set the image field.
    Image(String),
    /// Set the target field.
    Target(String),
    /// Replace the restore token.
    Token(String),
    /// Take the image path from the last backup summary (as the wizard does).
    ImageFromSummary,
    /// Invoke "Refresh" on the disks tab.
    RefreshDisks,
    /// Invoke "History".
    History,
    /// Invoke "Show plan".
    Probe,
    /// Invoke "Start backup".
    Backup,
    /// Invoke "Show token plan".
    Prepare,
    /// Require preparation to fail with the expected diagnostic and no approval.
    ExpectPrepareFailure(String),
    /// Invoke "Start restore".
    Restore,
    /// Require the restore to be refused with the expected diagnostic and the
    /// job released for a new review.
    ExpectRestoreFailure(String),
    /// Create a marker file so a test can act at this point of the script.
    Signal(PathBuf),
    /// Wait (at most a minute) until a test creates this marker file.
    WaitForFile(PathBuf),
    /// Assert a file exists (test convenience).
    ExpectFile(PathBuf),
    /// Assert a destination directory has not received any entries.
    ExpectEmptyDirectory(PathBuf),
    /// Assert a file contains a string.
    ExpectContains(PathBuf, String),
    /// Print the current status, plan and progress.
    Print,
    /// Stop the event loop.
    Quit,
}

/// Parse a script.
///
/// # Errors
/// Returns [`Error::Unsupported`] for an unknown directive or a missing
/// argument, so a typo fails loudly.
pub fn parse(text: &str) -> Result<Vec<Step>, Error> {
    let mut steps = Vec::new();
    for (number, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (directive, argument) = match line.split_once(char::is_whitespace) {
            Some((directive, argument)) => (directive, argument.trim()),
            None => (line, ""),
        };
        let need = |argument: &str| -> Result<String, Error> {
            if argument.is_empty() {
                Err(Error::corrupt(format!(
                    "line {}: `{directive}` needs an argument",
                    number + 1
                )))
            } else {
                Ok(argument.to_owned())
            }
        };
        steps.push(match directive {
            "source" => Step::Source(need(argument)?),
            "dest" => Step::Destination(need(argument)?),
            "set" => Step::SetName(need(argument)?),
            "mode" => Step::Mode(need(argument)?),
            "backup-passphrase-file" => Step::BackupPassphraseFile(need(argument)?),
            "restore-passphrase-file" => Step::RestorePassphraseFile(need(argument)?),
            "image" => Step::Image(need(argument)?),
            "target" => Step::Target(need(argument)?),
            "token" => Step::Token(need(argument)?),
            "image-from-summary" => Step::ImageFromSummary,
            "refresh-disks" => Step::RefreshDisks,
            "history" => Step::History,
            "probe" => Step::Probe,
            "backup" => Step::Backup,
            "prepare" => Step::Prepare,
            "expect-prepare-failure" => Step::ExpectPrepareFailure(need(argument)?),
            "restore" => Step::Restore,
            "expect-restore-failure" => Step::ExpectRestoreFailure(need(argument)?),
            "signal" => Step::Signal(PathBuf::from(need(argument)?)),
            "wait-for-file" => Step::WaitForFile(PathBuf::from(need(argument)?)),
            "expect-file" => Step::ExpectFile(PathBuf::from(need(argument)?)),
            "expect-empty-directory" => Step::ExpectEmptyDirectory(PathBuf::from(need(argument)?)),
            "expect-contains" => {
                let mut parts = argument.splitn(2, char::is_whitespace);
                let path = parts.next().unwrap_or_default();
                let needle = parts.next().unwrap_or_default().trim().to_owned();
                if path.is_empty() || needle.is_empty() {
                    return Err(Error::corrupt(format!(
                        "line {}: expect-contains needs a path and a string",
                        number + 1
                    )));
                }
                Step::ExpectContains(PathBuf::from(path), needle)
            }
            "print" => Step::Print,
            "quit" => Step::Quit,
            other => {
                return Err(Error::corrupt(format!(
                    "line {}: unknown directive `{other}`",
                    number + 1
                )));
            }
        });
    }
    if steps.is_empty() {
        return Err(Error::corrupt("the script is empty"));
    }
    Ok(steps)
}

/// The outcome of running a script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptOutcome {
    /// Steps that ran.
    pub steps: usize,
    /// What the run printed.
    pub log: Vec<String>,
}

/// Check the `expect` steps against the filesystem.
///
/// # Errors
/// Returns [`Error::Corrupt`] when a file is missing or its content does not
/// contain the expected text.
pub fn check_expectation(step: &Step) -> Result<Option<String>, Error> {
    match step {
        Step::ExpectEmptyDirectory(path) => {
            if std::fs::read_dir(path)
                .map_err(Error::Io)?
                .next()
                .transpose()
                .map_err(Error::Io)?
                .is_some()
            {
                return Err(Error::corrupt("expected restore directory to remain empty"));
            }
            Ok(Some("ok: destination remains empty".into()))
        }
        Step::ExpectFile(path) => {
            if !path.exists() {
                return Err(Error::corrupt(format!(
                    "expected {} to exist",
                    path.display()
                )));
            }
            Ok(Some(format!("ok: {} exists", path.display())))
        }
        Step::ExpectContains(path, needle) => {
            let text = std::fs::read_to_string(path).map_err(Error::Io)?;
            if !text.contains(needle) {
                return Err(Error::corrupt(format!(
                    "{} does not contain `{needle}`",
                    path.display()
                )));
            }
            Ok(Some(format!("ok: {} contains `{needle}`", path.display())))
        }
        _ => Ok(None),
    }
}

/// Read a script file.
///
/// # Errors
/// Returns [`Error::Unsupported`] when the file cannot be read.
pub fn load(path: &std::path::Path) -> Result<Vec<Step>, Error> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))
        .map_err(|error| Error::unsupported(error.to_string()))?;
    parse(&text)
}

#[cfg(test)]
mod tests {
    use super::{Step, check_expectation, parse};

    #[test]
    fn a_script_parses_into_steps() {
        let steps = parse(
            "# comment\nsource /home\ndest /mnt/backup\nset home\nmode file\nprobe\nbackup\nimage /x.lrimg\nimage-from-summary\ntarget /mnt/restore\nprepare\nrestore\nprint\nquit\n",
        )
        .expect("parse");
        assert_eq!(
            steps,
            vec![
                Step::Source("/home".to_owned()),
                Step::Destination("/mnt/backup".to_owned()),
                Step::SetName("home".to_owned()),
                Step::Mode("file".to_owned()),
                Step::Probe,
                Step::Backup,
                Step::Image("/x.lrimg".to_owned()),
                Step::ImageFromSummary,
                Step::Target("/mnt/restore".to_owned()),
                Step::Prepare,
                Step::Restore,
                Step::Print,
                Step::Quit,
            ]
        );
    }

    #[test]
    fn unknown_or_incomplete_directives_are_refused() {
        let error = parse("explode").expect_err("unknown");
        assert!(format!("{error}").contains("unknown directive"), "{error}");
        let error = parse("source").expect_err("missing argument");
        assert!(format!("{error}").contains("needs an argument"), "{error}");
        let error = parse("   \n# nothing\n").expect_err("empty");
        assert!(format!("{error}").contains("empty"), "{error}");
    }

    #[test]
    fn expectations_check_the_filesystem() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("out.txt");
        std::fs::write(&path, b"hello scheduler").expect("write");
        assert!(check_expectation(&Step::ExpectFile(path.clone())).is_ok());
        assert!(
            check_expectation(&Step::ExpectContains(path.clone(), "scheduler".to_owned())).is_ok()
        );
        let missing = dir.path().join("nope");
        assert!(check_expectation(&Step::ExpectFile(missing)).is_err());
        assert!(check_expectation(&Step::ExpectContains(path, "absent".to_owned())).is_err());
        assert!(check_expectation(&Step::Print).expect("no-op").is_none());
    }
}
