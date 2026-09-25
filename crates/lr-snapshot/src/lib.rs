//! Snapshot providers (spec §E, Slices S6 and S8).
//!
//! Block providers: the **offline** provider reads a device that is not
//! mounted, has no holders, is not swap and is not an active LVM physical
//! volume directly and is therefore consistent (spec §E.3); **LVM** (classic
//! and thin) and **freeze** provide point-in-time and frozen consistency, and
//! **live-none** is the explicit opt-in for a torn image. The **Btrfs** tree
//! provider snapshots mounted subvolumes read-only and feeds `btrfs send`
//! streams to Stream mode (spec §E.1).
#![forbid(unsafe_code)]

pub mod btrfs;
pub mod freeze;
pub mod live_none;
pub mod lvm;
pub mod offline;
pub mod probe;

pub use btrfs::{BtrfsProvider, PathMount, TreeSnapshot, TreeSnapshotOpts};
pub use freeze::FreezeProvider;
pub use live_none::LiveNoneProvider;
pub use lvm::LvmProvider;
pub use offline::OfflineProvider;
pub use probe::{Plan, decide, probe as probe_source};

use std::path::PathBuf;

use lr_core::{Consistency, Result, SnapshotOpts, SourceLayout, Support};

/// A provider's own health check, consulted while the image is being read.
///
/// This is how spec §E.2's snapshot-overflow abort and §E.4's freeze timeout
/// reach the read loop: the engine calls it between chunks and the provider
/// answers from shared state its monitor thread maintains.
pub trait SnapshotHealth: Send + Sync {
    /// `Ok(())` while the snapshot is safe to keep reading.
    ///
    /// # Errors
    /// Returns [`lr_core::Error::SnapshotOverflow`] or
    /// [`lr_core::Error::FreezeTimeout`] when the job must abort.
    fn check(&self) -> Result<()>;
}

/// A block-level snapshot or quiesced read of a source.
pub struct BlockSnapshot {
    /// Device to read; for offline backups this is the origin itself.
    pub block_path: PathBuf,
    /// Consistency level this snapshot actually provides.
    pub consistency: Consistency,
    /// Teardown handle: dropping it releases whatever the provider acquired.
    guard: Option<Box<dyn Send + Sync>>,
    /// Provider health check, when the provider needs one.
    health: Option<std::sync::Arc<dyn SnapshotHealth>>,
}

impl Drop for BlockSnapshot {
    fn drop(&mut self) {
        // Teardown must be guaranteed even on the error paths (spec §L.1), so
        // it runs here rather than relying on field order.
        drop(self.guard.take());
    }
}

impl BlockSnapshot {
    /// Build a snapshot, keeping `guard` alive until the snapshot is dropped.
    pub fn new(
        block_path: impl Into<PathBuf>,
        consistency: Consistency,
        guard: impl Send + Sync + 'static,
    ) -> Self {
        Self {
            block_path: block_path.into(),
            consistency,
            guard: Some(Box::new(guard)),
            health: None,
        }
    }

    /// Attach a provider health check.
    #[must_use]
    pub fn with_health(mut self, health: std::sync::Arc<dyn SnapshotHealth>) -> Self {
        self.health = Some(health);
        self
    }

    /// Ask the provider whether the snapshot is still safe to read.
    ///
    /// # Errors
    /// Propagates the provider's abort reason.
    pub fn check_health(&self) -> Result<()> {
        match &self.health {
            Some(health) => health.check(),
            None => Ok(()),
        }
    }
}

impl std::fmt::Debug for BlockSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockSnapshot")
            .field("block_path", &self.block_path)
            .field("consistency", &self.consistency)
            .finish_non_exhaustive()
    }
}

/// One way of obtaining a consistent block image of a source.
pub trait BlockSnapshotProvider: Send + Sync {
    /// Provider identifier used by `--snapshot` and reported in plans.
    fn id(&self) -> &'static str;

    /// Whether this provider can handle the source right now.
    fn supports(&self, src: &SourceLayout, opts: &SnapshotOpts) -> Support;

    /// Perform the snapshot.
    ///
    /// # Errors
    /// Returns [`lr_core::Error::TargetBusy`] when the source is in use and
    /// [`lr_core::Error::Unsupported`] when the platform cannot do it.
    fn create(&self, src: &SourceLayout, opts: &SnapshotOpts) -> Result<BlockSnapshot>;
}

static OFFLINE: OfflineProvider = OfflineProvider;
static ALL: [&dyn BlockSnapshotProvider; 1] = [&OFFLINE];

/// Registered block snapshot providers, most capable first.
#[must_use]
pub fn providers() -> &'static [&'static dyn BlockSnapshotProvider] {
    &ALL
}

/// The offline provider, which Slice S6 always uses.
#[must_use]
pub fn offline_provider() -> &'static OfflineProvider {
    &OFFLINE
}

#[cfg(test)]
pub(crate) mod test_layout {
    use lr_core::discovery::{
        BlockDeviceType, DeviceFacts, FsFacts, PartitionLayout, SourceLayout,
    };
    use std::path::PathBuf;

    /// A synthetic, unmounted, holder-free source layout.
    pub(crate) fn offline(device: &str) -> SourceLayout {
        SourceLayout {
            device: PathBuf::from(device),
            device_facts: DeviceFacts {
                name: device.trim_start_matches("/dev/").to_owned(),
                path: PathBuf::from(device),
                dev_type: BlockDeviceType::Disk,
                size_bytes: 64 * 1024 * 1024,
                logical_block_size: 512,
                physical_block_size: 4096,
                dev_id: Some("8:16".to_owned()),
                removable: false,
                read_only: false,
                model: None,
                serial: None,
                wwid: None,
            },
            partition_table: None,
            partitions: Vec::new(),
            fs: Some(FsFacts {
                fs_type: "ext4".to_owned(),
                uuid: None,
                label: Some("ROOT".to_owned()),
                block_size: Some(4096),
                usage: None,
            }),
            mountpoints: Vec::new(),
            holders: Vec::new(),
            lvm: None,
            btrfs: None,
            warnings: Vec::new(),
        }
    }

    /// Add a partition with the given mount points and holders.
    pub(crate) fn with_partition(
        layout: &mut SourceLayout,
        index: u32,
        mountpoints: Vec<PathBuf>,
        holders: Vec<String>,
    ) {
        layout.partitions.push(PartitionLayout {
            index,
            name: Some(format!("{}p{index}", layout.device_facts.name)),
            path: Some(PathBuf::from(format!(
                "{}p{index}",
                layout.device.display()
            ))),
            start_lba: 2048,
            size_bytes: 32 * 1024 * 1024,
            type_guid: None,
            type_name: Some("Linux filesystem".to_owned()),
            part_uuid: None,
            mbr_type: None,
            fs_type: Some("ext4".to_owned()),
            fs_uuid: None,
            fs_label: None,
            mountpoints,
            holders,
            bootable: false,
        });
    }
}
