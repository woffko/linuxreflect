//! Core types and platform probing for LinuxReflect.
//!
//! This crate owns the vocabulary shared by every other crate: the error
//! contract (spec §L.2), identifiers, device geometry, the consistency enum
//! (spec §D.2), catalog records (spec §D.3), the runtime capability probe
//! (spec §A.4) and block-device discovery (spec §S2).
#![forbid(unsafe_code)]

pub mod caps;
pub mod catalog;
pub mod consistency;
pub mod discovery;
pub mod error;
pub mod geometry;
pub mod ids;
pub mod io;
pub mod names;
pub mod sysfs;

pub use caps::{Capabilities, Capability};
pub use catalog::{Catalog, ChainRecord, MemberKind, MemberRecord};
pub use consistency::Consistency;
pub use discovery::{
    BlockDeviceType, DeviceFacts, DeviceIdentity, FsFacts, LvmFacts, PartitionLayout,
    PartitionTableInfo, PartitionTableKind, SourceLayout, discover_source,
};
pub use error::{Error, Result};
pub use geometry::Geometry;
pub use ids::{ChainId, Id, ImageId, SetId};
pub use names::{validate_job_name, validate_set_name};
pub use sysfs::{SysfsBlockDevice, list_block_devices, read_holders, read_mountpoints};

/// Image kinds (spec §D.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageKind {
    /// Fixed-size chunks over used blocks of a block device.
    Block,
    /// CDC chunks over a filesystem tree send-stream (Btrfs, later ZFS).
    Stream,
    /// CDC chunks per file over a directory tree (spec Slice 12).
    File,
}

impl ImageKind {
    /// Single-byte on-disk/on-wire discriminants (spec §G.3).
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Block => 1,
            Self::Stream => 2,
            Self::File => 3,
        }
    }

    /// Reconstruct from the on-disk discriminant, rejecting unknown values.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] for an unknown discriminant.
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Block),
            2 => Ok(Self::Stream),
            3 => Ok(Self::File),
            other => Err(Error::Corrupt {
                what: format!("unknown image kind {other}"),
            }),
        }
    }
}

/// Snapshot options shared by the snapshot providers (spec §E).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SnapshotOpts {
    /// Explicit provider override from `--snapshot`.
    pub provider: Option<String>,
    /// Allow the freeze provider (writers are blocked for the whole read).
    pub allow_freeze: bool,
    /// Freeze timeout in seconds; the provider defaults to 300 s.
    pub freeze_timeout_secs: Option<u64>,
    /// Allow a torn, live read (`Consistency::None`).
    pub allow_inconsistent: bool,
    /// LVM snapshot COW size override.
    pub lvm_cow_size: Option<String>,
    /// Extra grace before the freeze deadman fires, in seconds (default 30,
    /// spec §E.4). Configurable so a test can exercise the deadman quickly.
    pub deadman_grace_secs: Option<u64>,
    /// Where the image is written; the freeze provider refuses a destination on
    /// the same filesystem as the frozen source (spec §E.4). `None` for a
    /// remote destination, which is never on the frozen filesystem.
    pub destination: Option<std::path::PathBuf>,
    /// `true` when the image is written to another host (SFTP).
    pub destination_remote: bool,
    /// Tracked-freeze budgets (spec §E.7); unset fields keep the defaults.
    #[serde(default)]
    pub tracked: TrackedTuning,
}

/// Tunable budgets of the tracked-freeze provider (spec §E.7).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TrackedTuning {
    /// Most bytes the final freeze may read (`final_max`, default 256 MiB).
    pub final_max_bytes: Option<u64>,
    /// Passes that do not shrink the dirty set (or only wait for a package
    /// transaction) before the copy gives up (`max_passes`, default 10).
    pub max_passes: Option<u32>,
    /// Per-CPU ring buffer of the trace instance in KiB (default 16384).
    pub buffer_kb: Option<u32>,
    /// Longest final freeze in seconds (`freeze_max`, default 3, at most
    /// 30). The freeze provider's `freeze_timeout_secs` does not apply.
    pub freeze_max_secs: Option<u64>,
}

/// Result of a provider support query.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Support {
    /// Provider can handle this source.
    Yes,
    /// Provider cannot handle this source; the string is a human-readable reason.
    No(String),
}

impl Support {
    /// Returns `true` for [`Support::Yes`].
    #[must_use]
    pub fn is_yes(&self) -> bool {
        matches!(self, Self::Yes)
    }

    /// Reason string when unsupported.
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Yes => None,
            Self::No(reason) => Some(reason),
        }
    }
}
