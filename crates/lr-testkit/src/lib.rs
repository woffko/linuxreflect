//! Honest test accounting (remediation plan R40).
//!
//! A test that cannot run its scenario must never look like a pass. Two
//! situations are distinguished:
//!
//! * **Unavailable** — a prerequisite of the environment is missing (a tool,
//!   root, a kernel module, a built binary). [`unavailable!`] records the
//!   reason with an `LR-UNAVAILABLE:` marker and, when `LR_UNAVAILABLE_LOG`
//!   names a file, appends it there so a runner can count it. In the root
//!   lane (`LR_ROOT_TESTS=1`) it **fails** unless `LR_ALLOW_UNAVAILABLE=1`
//!   says that an incomplete environment is accepted (for example a hosted
//!   CI container); in an ordinary `cargo test` run it returns early.
//! * **Fixture failure** — the environment is there but setting the scenario
//!   up failed (`mkfs`, `losetup`, a daemon that exits). [`fixture_failed!`]
//!   always fails: that is a broken test or a broken product, never a skip.
#![forbid(unsafe_code)]

use std::io::Write as _;

/// Whether a missing prerequisite must fail the test.
#[must_use]
pub fn strict() -> bool {
    strict_for(
        std::env::var("LR_ROOT_TESTS").ok().as_deref(),
        std::env::var("LR_ALLOW_UNAVAILABLE").ok().as_deref(),
    )
}

/// The strictness rule, separated from the environment for testing.
#[must_use]
pub fn strict_for(root_tests: Option<&str>, allow_unavailable: Option<&str>) -> bool {
    root_tests == Some("1") && allow_unavailable != Some("1")
}

/// Record an unavailable prerequisite; panics in a strict run.
///
/// # Panics
/// In a strict run (see [`strict`]).
pub fn report_unavailable(reason: &str) {
    let test = std::thread::current()
        .name()
        .unwrap_or("<unnamed>")
        .to_owned();
    eprintln!("LR-UNAVAILABLE: {test}: {reason}");
    if let Some(path) = std::env::var_os("LR_UNAVAILABLE_LOG")
        && let Ok(mut log) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
    {
        let _ = writeln!(log, "{test}\t{reason}");
    }
    assert!(
        !strict(),
        "prerequisite unavailable in a strict root run: {reason} \
         (set LR_ALLOW_UNAVAILABLE=1 only where an incomplete environment is accepted)"
    );
}

/// Stop the current test because a prerequisite is missing.
///
/// `unavailable!("xfsprogs missing")` returns `()`;
/// `unavailable!(return None; "no {tool}")` returns the given value from a
/// helper. Fails the test in a strict run.
#[macro_export]
macro_rules! unavailable {
    (return $ret:expr; $($arg:tt)+) => {{
        $crate::report_unavailable(&format!($($arg)+));
        return $ret;
    }};
    ($($arg:tt)+) => {{
        $crate::report_unavailable(&format!($($arg)+));
        return;
    }};
}

/// Fail the test because setting up its scenario failed.
#[macro_export]
macro_rules! fixture_failed {
    ($($arg:tt)+) => {
        panic!("fixture setup failed: {}", format!($($arg)+))
    };
}

/// `true` when `program` is on `PATH`.
#[must_use]
pub fn have(program: &str) -> bool {
    std::process::Command::new("which")
        .arg(program)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::strict_for;

    #[test]
    fn only_the_root_lane_is_strict_unless_explicitly_relaxed() {
        assert!(strict_for(Some("1"), None));
        assert!(strict_for(Some("1"), Some("0")));
        assert!(
            !strict_for(Some("1"), Some("1")),
            "an accepted incomplete host"
        );
        assert!(!strict_for(None, None), "an ordinary cargo test");
        assert!(!strict_for(Some("0"), None));
    }

    #[test]
    #[should_panic(expected = "fixture setup failed: mkfs.ext4 exited 1")]
    fn a_fixture_failure_always_fails() {
        crate::fixture_failed!("mkfs.ext4 exited {}", 1);
    }
}
