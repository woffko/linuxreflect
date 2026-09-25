//! Running external filesystem tools safely.
//!
//! Used-block maps come from `dumpe2fs` (spec §F) and `xfs_db`, so the helpers
//! here spawn them with a piped stdout, stream it into a parser, and report a
//! missing binary as [`Error::Unsupported`] rather than a confusing I/O error.
//! `stderr` is drained on a separate thread so a chatty tool cannot deadlock
//! against the pipe buffer.

use std::ffi::OsStr;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::process::{Command, Stdio};

use lr_core::{Error, Result};

/// Run `program` with `args` plus `dev`, streaming stdout into `parse`.
///
/// # Errors
/// Returns [`Error::Unsupported`] when the program is not installed and
/// [`Error::Io`] when it fails or cannot be spawned.
pub(crate) fn with_tool_output<T>(
    program: &str,
    args: &[&str],
    dev: &Path,
    parse: impl FnOnce(&mut dyn BufRead) -> Result<T>,
) -> Result<T> {
    let mut child = Command::new(program)
        .args(args.iter().map(OsStr::new))
        .arg(dev)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::unsupported(format!("{program} is not installed"))
            } else {
                Error::Io(e)
            }
        })?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::Io(std::io::Error::other(format!("{program}: no stdout pipe"))))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| Error::Io(std::io::Error::other(format!("{program}: no stderr pipe"))))?;
    let drain = std::thread::spawn(move || {
        let mut buffer = String::new();
        let mut reader = BufReader::new(stderr);
        let _ = reader.read_to_string(&mut buffer);
        buffer
    });

    let mut reader = BufReader::new(stdout);
    let parsed = parse(&mut reader);
    let status = child.wait().map_err(Error::Io)?;
    let stderr = drain.join().unwrap_or_default();

    match parsed {
        Ok(value) => {
            if status.success() {
                Ok(value)
            } else {
                Err(Error::Io(std::io::Error::other(format!(
                    "{program} exited with {status}: {}",
                    stderr.trim()
                ))))
            }
        }
        Err(error) => {
            // A parse failure is the more useful message; the tool's stderr is
            // appended when it said anything.
            if stderr.trim().is_empty() {
                Err(error)
            } else {
                Err(Error::corrupt(format!(
                    "{error} (tool stderr: {})",
                    stderr.trim()
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::with_tool_output;
    use std::path::Path;

    #[test]
    fn streams_stdout_and_reports_success() {
        let value = with_tool_output("echo", &["hello"], Path::new("world"), |reader| {
            let mut line = String::new();
            reader.read_line(&mut line).expect("read");
            Ok(line.trim().to_owned())
        })
        .expect("tool output");
        assert_eq!(value, "hello world");
    }

    #[test]
    fn a_missing_tool_is_unsupported() {
        let error = with_tool_output("lr-fsmap-does-not-exist", &[], Path::new("."), |_| Ok(()))
            .expect_err("must fail");
        assert!(
            matches!(error, lr_core::Error::Unsupported { .. }),
            "{error}"
        );
    }

    #[test]
    fn a_failing_tool_reports_its_status() {
        let error =
            with_tool_output("false", &[], Path::new("."), |_| Ok(())).expect_err("must fail");
        assert!(error.to_string().contains("false exited"), "{error}");
    }
}
