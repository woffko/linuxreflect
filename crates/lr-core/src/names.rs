//! Names that become path components (D-115).
//!
//! A set name is a directory at the destination and below a Btrfs
//! filesystem's `.linuxreflect/`; a job name is part of a systemd unit name.
//! A name that is `..`, contains `/`, or is empty would move those paths
//! somewhere else entirely, so names are checked against one grammar at
//! every entry point instead of being escaped later:
//!
//! `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`
//!
//! The first character is a letter or digit, which excludes `.`, `..`,
//! hidden names and names that look like options.

use crate::{Error, Result};

/// Longest accepted name, in bytes.
pub const MAX_NAME_LEN: usize = 64;

/// What kind of name is being checked, for the error message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameKind {
    /// A backup set name.
    Set,
    /// A scheduled job name.
    Job,
}

impl NameKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Set => "set name",
            Self::Job => "job name",
        }
    }
}

/// Check a name against the grammar.
///
/// # Errors
/// Returns [`Error::Unsupported`] naming the rule the value breaks.
pub fn validate_name(kind: NameKind, name: &str) -> Result<()> {
    let label = kind.label();
    let refuse = |why: &str| {
        Err(Error::unsupported(format!(
            "invalid {label} {name:?}: {why} (allowed: a letter or digit, then up to \
             {} letters, digits, '.', '_' or '-')",
            MAX_NAME_LEN - 1
        )))
    };
    let Some(first) = name.chars().next() else {
        return refuse("it is empty");
    };
    if name.len() > MAX_NAME_LEN {
        return refuse(&format!("it is longer than {MAX_NAME_LEN} bytes"));
    }
    if !first.is_ascii_alphanumeric() {
        return refuse("it must start with a letter or digit");
    }
    if let Some(bad) = name
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')))
    {
        return refuse(&format!("{bad:?} is not allowed"));
    }
    Ok(())
}

/// Check a backup set name.
///
/// # Errors
/// See [`validate_name`].
pub fn validate_set_name(name: &str) -> Result<()> {
    validate_name(NameKind::Set, name)
}

/// Check a scheduled job name.
///
/// # Errors
/// See [`validate_name`].
pub fn validate_job_name(name: &str) -> Result<()> {
    validate_name(NameKind::Job, name)
}

#[cfg(test)]
mod tests {
    use super::{MAX_NAME_LEN, validate_job_name, validate_set_name};

    #[test]
    fn ordinary_names_are_accepted() {
        for name in ["home", "nightly-root", "srv_01", "v1.2", "A", "0"] {
            assert!(validate_set_name(name).is_ok(), "{name}");
            assert!(validate_job_name(name).is_ok(), "{name}");
        }
        assert!(validate_set_name(&"a".repeat(MAX_NAME_LEN)).is_ok());
    }

    #[test]
    fn names_that_leave_their_directory_are_refused() {
        for name in [
            "",
            ".",
            "..",
            "../x",
            "a/b",
            "/abs",
            ".hidden",
            "-rf",
            "a b",
            "a\\b",
            "a\0b",
            "a\nb",
            "caf\u{e9}",
        ] {
            let error = validate_set_name(name).expect_err(name);
            assert!(error.to_string().contains("invalid set name"), "{error}");
        }
        assert!(validate_set_name(&"a".repeat(MAX_NAME_LEN + 1)).is_err());
        assert!(validate_job_name("..").is_err());
    }
}
