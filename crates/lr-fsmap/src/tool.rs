//! Running external filesystem tools safely.
//!
//! Used-block maps come from `dumpe2fs` (spec §F) and `xfs_db`, so the helpers
//! here spawn them with a piped stdout, stream it into a parser, and report a
//! missing binary as [`Error::Unsupported`] rather than a confusing I/O error.
//! `stderr` is drained on a separate thread so a chatty tool cannot deadlock
//! against the pipe buffer. Once the parser is done, stdout is drained (or,
//! after a parse failure, the tool is stopped), and a tool that still does
//! not exit within a timeout is stopped, so a job never waits on a tool
//! blocked on a full pipe (R38).

use std::ffi::OsStr;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::time::Duration;

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
    with_tool_output_within(program, args, dev, EXIT_TIMEOUT, parse)
}

/// How long a tool may take to finish once its output has been parsed.
const EXIT_TIMEOUT: Duration = Duration::from_secs(60);

/// [`with_tool_output`] with an explicit exit timeout.
pub(crate) fn with_tool_output_within<T>(
    program: &str,
    args: &[&str],
    dev: &Path,
    exit_timeout: Duration,
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
    let child = Arc::new(Mutex::new(child));
    let lock = |child: &Mutex<Child>| child.lock().unwrap_or_else(PoisonError::into_inner).kill();
    if parsed.is_err() {
        // Nobody reads the rest: stop the tool rather than wait for it to
        // write into a full pipe.
        let _ = lock(&child);
    }
    // From here the tool must finish within `exit_timeout`.
    let (finished, watch) = mpsc::channel::<()>();
    let watched = Arc::clone(&child);
    let watchdog = std::thread::spawn(move || {
        let expired = matches!(
            watch.recv_timeout(exit_timeout),
            Err(mpsc::RecvTimeoutError::Timeout)
        );
        if expired {
            let _ = lock(&watched);
        }
        expired
    });
    if parsed.is_ok() {
        // Output the parser did not need must still be read, or a tool with
        // more than a pipe's worth left would never finish.
        let _ = std::io::copy(&mut reader, &mut std::io::sink());
    }
    drop(reader);
    let status = loop {
        let polled = child
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .try_wait()
            .map_err(Error::Io)?;
        if let Some(status) = polled {
            break status;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let _ = finished.send(());
    let stopped = watchdog.join().unwrap_or(false);
    let stderr = drain.join().unwrap_or_default();
    if stopped {
        return Err(Error::Io(std::io::Error::other(format!(
            "{program} did not finish within {} s after its output was read, so it was stopped",
            exit_timeout.as_secs()
        ))));
    }

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

    /// Run `work` on a thread and fail the test if it does not return in
    /// time, instead of hanging the test run.
    fn within<T: Send + 'static>(seconds: u64, work: impl FnOnce() -> T + Send + 'static) -> T {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(work());
        });
        receiver
            .recv_timeout(std::time::Duration::from_secs(seconds))
            .expect("the tool call must return instead of hanging")
    }

    /// A parse failure stops the tool; waiting for it while it blocks on a
    /// full pipe would hang the job forever (R38).
    #[test]
    fn a_parse_failure_stops_a_tool_that_keeps_writing() {
        let error = within(20, || {
            with_tool_output("yes", &[], Path::new("y"), |_| {
                Err::<(), _>(lr_core::Error::corrupt("unexpected first line"))
            })
        })
        .expect_err("the parse error is returned");
        assert!(
            error.to_string().contains("unexpected first line"),
            "{error}"
        );
    }

    /// Output the parser did not need is drained, so a tool that writes more
    /// than a pipe holds still finishes.
    #[test]
    fn unread_output_is_drained() {
        let first = within(20, || {
            with_tool_output("seq", &["1"], Path::new("200000"), |reader| {
                let mut line = String::new();
                reader.read_line(&mut line).expect("read");
                Ok(line.trim().to_owned())
            })
        })
        .expect("the tool finishes");
        assert_eq!(first, "1");
    }

    /// A tool that stops writing but never exits is stopped after the exit
    /// timeout and reported.
    #[test]
    fn a_tool_that_never_exits_is_stopped() {
        let error = within(20, || {
            super::with_tool_output_within(
                "sh",
                &["-c", "echo ready; exec sleep 600"],
                Path::new("sh"),
                std::time::Duration::from_secs(1),
                |reader| {
                    let mut line = String::new();
                    reader.read_line(&mut line).expect("read");
                    Ok(line)
                },
            )
        })
        .expect_err("a hung tool is an error");
        assert!(error.to_string().contains("did not finish"), "{error}");
    }

    #[test]
    fn a_failing_tool_reports_its_status() {
        let error =
            with_tool_output("false", &[], Path::new("."), |_| Ok(())).expect_err("must fail");
        assert!(error.to_string().contains("false exited"), "{error}");
    }
}
