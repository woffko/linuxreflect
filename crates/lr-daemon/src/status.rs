//! Error codes and gRPC statuses (spec §L.2, §I).
//!
//! The daemon reports a stable `E_*` code in `Progress::Failure` and picks a
//! gRPC status that matches what a client should do about it: authenticate
//! again, fix the request, wait, or give up.

use lr_core::Error;
use tonic::{Code, Status};

/// The stable code and message for an engine error.
#[must_use]
pub fn error_code(error: &Error) -> (String, String) {
    let code = match error {
        Error::Denied { .. } => "E_DENIED",
        Error::Cancelled => "E_CANCELLED",
        Error::SetLocked { .. } => "E_SET_LOCKED",
        Error::TargetChanged => "E_TARGET_CHANGED",
        Error::NoConsistentMethod { .. } => "E_NO_CONSISTENT_METHOD",
        Error::StreamParentMissing { .. } => "E_STREAM_PARENT_MISSING",
        Error::SnapshotOverflow => "E_SNAPSHOT_OVERFLOW",
        Error::FreezeTimeout => "E_FREEZE_TIMEOUT",
        Error::BadSector { .. } => "E_BAD_SECTOR",
        Error::Unsupported { .. } => "E_UNSUPPORTED",
        Error::Corrupt { .. } => "E_CORRUPT",
        Error::TargetBusy { .. } => "E_TARGET_BUSY",
        Error::NoSpace => "E_NO_SPACE",
        Error::NetworkTimeout(_) => "E_NETWORK_TIMEOUT",
        Error::Aead => "E_AEAD",
        Error::Io(_) => "E_IO",
    };
    (code.to_owned(), error.to_string())
}

/// The gRPC status a client should see for an engine error.
#[must_use]
pub fn grpc_status(error: &Error) -> Status {
    let (code, message) = error_code(error);
    let tonic_code = match error {
        Error::Denied { .. } => Code::PermissionDenied,
        Error::Cancelled => Code::Cancelled,
        Error::SetLocked { .. } | Error::TargetBusy { .. } | Error::NoSpace => {
            Code::FailedPrecondition
        }
        Error::TargetChanged
        | Error::NoConsistentMethod { .. }
        | Error::StreamParentMissing { .. } => Code::FailedPrecondition,
        // Nothing in the service is unimplemented any more: an unsupported
        // request means the inputs cannot be served as asked (a missing
        // source, an image kind an operation does not accept), so
        // `FailedPrecondition` is the honest code (D-089).
        Error::Unsupported { .. } => Code::FailedPrecondition,
        Error::Corrupt { .. } | Error::Aead | Error::BadSector { .. } => Code::DataLoss,
        Error::SnapshotOverflow | Error::FreezeTimeout => Code::Aborted,
        Error::NetworkTimeout(_) | Error::Io(_) => Code::Internal,
    };
    Status::new(tonic_code, format!("{code}: {message}"))
}

/// The gRPC status for an owned error, for `Result::map_err`.
#[must_use]
pub fn status_of(error: Error) -> Status {
    grpc_status(&error)
}

/// Map a service-level failure that is not an engine error.
#[must_use]
pub fn invalid_argument(message: impl Into<String>) -> Status {
    Status::invalid_argument(message)
}

/// Map a missing or malformed field.
#[must_use]
pub fn not_found(message: impl Into<String>) -> Status {
    Status::not_found(message)
}

#[cfg(test)]
mod tests {
    use super::{error_code, grpc_status};
    use lr_core::Error;

    #[test]
    fn known_errors_get_stable_codes() {
        for (error, expected) in [
            (
                Error::denied("org.linuxreflect.disk.read", "nope"),
                "E_DENIED",
            ),
            (Error::cancelled(), "E_CANCELLED"),
            (
                Error::SetLocked {
                    owner: "x".to_owned(),
                },
                "E_SET_LOCKED",
            ),
            (Error::TargetChanged, "E_TARGET_CHANGED"),
            (Error::unsupported("btrfs"), "E_UNSUPPORTED"),
            (Error::corrupt("chunk 3"), "E_CORRUPT"),
        ] {
            assert_eq!(error_code(&error).0, expected, "{error}");
        }
    }

    #[test]
    fn authorization_failures_are_permission_denied() {
        let status = grpc_status(&Error::denied("a", "b"));
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
        assert!(status.message().contains("E_DENIED"));
    }
}
