//! The error contract shared across LinuxReflect (spec §L.2).

/// Convenience alias for results carrying a LinuxReflect [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Error variants that cross crate boundaries.
///
/// Bins are free to wrap these in `anyhow`; libraries must return this type so
/// that callers can react to specific conditions (for example
/// [`Error::TargetChanged`] during restore).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Underlying I/O failure.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// A read hit an unreadable sector.
    #[error("bad sector at offset {offset} (length {len})")]
    BadSector {
        /// Byte offset of the unreadable region.
        offset: u64,
        /// Length in bytes of the unreadable region.
        len: u64,
    },

    /// The destination ran out of space.
    #[error("destination has no space left")]
    NoSpace,

    /// A network operation exceeded its retry/timeout budget.
    #[error("network timeout: {0}")]
    NetworkTimeout(String),

    /// An LVM snapshot exceeded its COW/pool usage threshold (spec §E.2).
    #[error("snapshot overflow")]
    SnapshotOverflow,

    /// A freeze read did not finish inside `--freeze-timeout` (spec §E.4).
    #[error("freeze timeout")]
    FreezeTimeout,

    /// An incremental Btrfs send needs a parent snapshot that no longer exists
    /// (spec §E.1: the incremental is refused and a new full is required).
    #[error(
        "incremental stream refused: the parent snapshot for subvolume {subvol} is missing; \
         run a new full backup"
    )]
    StreamParentMissing {
        /// Subvolume whose parent snapshot is gone.
        subvol: String,
    },

    /// No provider can produce a consistent image for this source (spec §E).
    #[error("no consistent snapshot method for this source: {}", options.join("; "))]
    NoConsistentMethod {
        /// Concrete alternatives the user can choose from.
        options: Vec<String>,
    },

    /// The backup set is locked by another owner (spec §D.3).
    #[error("backup set is locked by {owner}")]
    SetLocked {
        /// Human-readable owner description from `set.lock`.
        owner: String,
    },

    /// The restore target changed between prepare and apply (spec §H.2).
    #[error("restore target changed since prepare")]
    TargetChanged,

    /// The device is in use (mounted, a holder exists, active PV, swap).
    #[error("target is busy: {holder}")]
    TargetBusy {
        /// The detected holder (mountpoint, dm/md device, swap, PV).
        holder: String,
    },

    /// Authenticated decryption failed.
    #[error("authenticated decryption failed")]
    Aead,

    /// Structural corruption was detected in an image or metadata stream.
    #[error("corrupt image: {what}")]
    Corrupt {
        /// What exactly failed validation.
        what: String,
    },

    /// The caller cancelled the job (spec §I: cooperative cancellation).
    #[error("cancelled")]
    Cancelled,

    /// Authorization refused an operation (spec §I: polkit or the dev backend).
    #[error("permission denied for {action}: {reason}")]
    Denied {
        /// Action identifier, e.g. `org.linuxreflect.backup.create`.
        action: String,
        /// Why it was refused.
        reason: String,
    },

    /// A required platform capability is unavailable.
    #[error("unsupported: {cap}")]
    Unsupported {
        /// Missing capability name, as reported by `caps::probe()`.
        cap: String,
    },
}

impl Error {
    /// Build a [`Error::Corrupt`] from anything printable.
    pub fn corrupt(what: impl Into<String>) -> Self {
        Self::Corrupt { what: what.into() }
    }

    /// Build a [`Error::Unsupported`] from anything printable.
    pub fn unsupported(cap: impl Into<String>) -> Self {
        Self::Unsupported { cap: cap.into() }
    }

    /// Build a [`Error::Cancelled`].
    #[must_use]
    pub const fn cancelled() -> Self {
        Self::Cancelled
    }

    /// Build a [`Error::Denied`].
    pub fn denied(action: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Denied {
            action: action.into(),
            reason: reason.into(),
        }
    }

    /// Build a [`Error::StreamParentMissing`].
    pub fn stream_parent_missing(subvol: impl Into<String>) -> Self {
        Self::StreamParentMissing {
            subvol: subvol.into(),
        }
    }

    /// Build a [`Error::NoConsistentMethod`] from an iterator of options.
    pub fn no_consistent_method<I, S>(options: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::NoConsistentMethod {
            options: options.into_iter().map(Into::into).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Error;

    #[test]
    fn io_errors_convert() {
        let err: Error = std::io::Error::new(std::io::ErrorKind::NotFound, "nope").into();
        assert!(matches!(err, Error::Io(_)));
    }

    #[test]
    fn no_consistent_method_lists_options() {
        let err = Error::no_consistent_method(["boot rescue media", "--allow-inconsistent"]);
        let msg = err.to_string();
        assert!(msg.contains("boot rescue media"));
        assert!(msg.contains("--allow-inconsistent"));
    }
}
