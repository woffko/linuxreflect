//! The offline provider (spec §E.3).
//!
//! Reading a device that nothing else is using is the simplest way to get a
//! consistent image, and it is the only provider Slice S6 needs. Preconditions
//! are checked twice: once cheaply in [`OfflineProvider::supports`] from the
//! discovered layout, and again authoritatively in `create`, because a device
//! can be mounted between discovery and the first read.

use std::path::Path;
use std::process::Command;

use lr_core::sysfs;
use lr_core::{Consistency, Error, Result, SnapshotOpts, SourceLayout, Support};

use crate::{BlockSnapshot, BlockSnapshotProvider};

/// Provider identifier.
pub const ID: &str = "offline";

/// Path of the kernel swap table (overridable for tests).
pub const SWAPS_PATH: &str = "/proc/swaps";

/// The offline provider.
#[derive(Debug, Default, Clone, Copy)]
pub struct OfflineProvider;

impl BlockSnapshotProvider for OfflineProvider {
    fn id(&self) -> &'static str {
        ID
    }

    fn supports(&self, src: &SourceLayout, opts: &SnapshotOpts) -> Support {
        if let Some(reason) = layout_busy_reason(src) {
            return Support::No(reason);
        }
        if opts.provider.as_deref().is_some_and(|name| name != ID) {
            return Support::No(format!(
                "provider override '{}' requested",
                opts.provider.as_deref().unwrap_or_default()
            ));
        }
        Support::Yes
    }

    fn create(&self, src: &SourceLayout, _opts: &SnapshotOpts) -> Result<BlockSnapshot> {
        preflight(&src.device, src)?;
        let claim = claim(&src.device)?;
        Ok(BlockSnapshot::new(
            src.device.clone(),
            Consistency::Offline,
            OfflineGuard { _claim: claim },
        ))
    }
}

/// The exclusive claim on the source, held for the whole read.
///
/// While it is held nothing can mount the device or any of its partitions,
/// in any mount namespace, so "offline" stays true until the image is done.
struct OfflineGuard {
    _claim: std::os::fd::OwnedFd,
}

/// Claim `device` exclusively (`O_EXCL`), read-only.
///
/// This is the authoritative offline check (A2): the sysfs and `mountinfo`
/// checks above only see this mount namespace, while the kernel refuses the
/// claim with `EBUSY` whenever the device, or for a whole disk any of its
/// partitions, is mounted anywhere or held by another program.
///
/// # Errors
/// Returns [`Error::NoConsistentMethod`] when the device is in use and
/// [`Error::Io`] for other failures.
pub fn claim(device: &Path) -> Result<std::os::fd::OwnedFd> {
    lr_unsafe::open_block_exclusive(device, false, false).map_err(|error| {
        if error.kind() == std::io::ErrorKind::ResourceBusy {
            Error::no_consistent_method([
                format!(
                    "{} is in use although no mount of it is visible here: it is mounted in \
                     another mount namespace (a container or a private mount) or held by \
                     another program, so it cannot be read offline",
                    device.display()
                ),
                "unmount it everywhere and retry".to_owned(),
                "boot rescue media and run the statically linked CLI".to_owned(),
            ])
        } else {
            Error::Io(error)
        }
    })
}

/// Reason the layout cannot be read offline, derived from discovery alone.
fn layout_busy_reason(src: &SourceLayout) -> Option<String> {
    if let Some(mountpoint) = src.mountpoints.first() {
        return Some(format!(
            "{} is mounted at {}",
            src.device.display(),
            mountpoint.display()
        ));
    }
    if let Some(holder) = src.holders.first() {
        return Some(format!("{} is held by {holder}", src.device.display()));
    }
    for partition in &src.partitions {
        if let Some(mountpoint) = partition.mountpoints.first() {
            return Some(format!(
                "partition {} is mounted at {}",
                partition.index,
                mountpoint.display()
            ));
        }
        if let Some(holder) = partition.holders.first() {
            return Some(format!("partition {} is held by {holder}", partition.index));
        }
    }
    if src
        .fs
        .as_ref()
        .is_some_and(|facts| facts.fs_type.starts_with("LVM2_member"))
    {
        return Some(format!(
            "{} is an LVM physical volume",
            src.device.display()
        ));
    }
    None
}

/// Authoritative precondition check, run immediately before reading.
///
/// # Errors
/// Returns [`Error::TargetBusy`] with the concrete holder when the device, any
/// of its partitions, or any descendant is in use.
pub fn preflight(device: &Path, src: &SourceLayout) -> Result<()> {
    let metadata = std::fs::metadata(device).map_err(Error::Io)?;
    if metadata.file_type().is_dir() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is a directory", device.display()),
        )));
    }
    if let Some(reason) = layout_busy_reason(src) {
        return Err(Error::TargetBusy { holder: reason });
    }

    let name = sysfs::device_name(device).map_err(Error::Io)?;
    let swaps = read_swaps().unwrap_or_default();
    if swaps.iter().any(|swap| Path::new(swap) == device) {
        return Err(Error::TargetBusy {
            holder: format!("{} is in use as swap", device.display()),
        });
    }

    // Re-read holders from sysfs rather than trusting the layout.
    if let Some(holder) = sysfs::read_holders(&name).first() {
        return Err(Error::TargetBusy {
            holder: format!("{} is held by {holder}", device.display()),
        });
    }
    // Every partition and, transitively, everything built on top of it.
    if let Ok(devices) = sysfs::list_all_block_devices() {
        for child in devices
            .iter()
            .filter(|d| d.parent.as_deref() == Some(&name))
        {
            if !child.holders.is_empty() {
                return Err(Error::TargetBusy {
                    holder: format!("{} is held by {}", child.path.display(), child.holders[0]),
                });
            }
            if swaps.iter().any(|swap| Path::new(swap) == child.path) {
                return Err(Error::TargetBusy {
                    holder: format!("{} is in use as swap", child.path.display()),
                });
            }
            let mounts = sysfs::read_mountpoints(&child.path).unwrap_or_default();
            if let Some(mountpoint) = mounts.first() {
                return Err(Error::TargetBusy {
                    holder: format!(
                        "{} is mounted at {}",
                        child.path.display(),
                        mountpoint.display()
                    ),
                });
            }
        }
    }

    if is_active_pv(device) {
        return Err(Error::TargetBusy {
            holder: format!("{} is an active LVM physical volume", device.display()),
        });
    }
    Ok(())
}

/// Device paths listed in `/proc/swaps`, skipping the header.
///
/// # Errors
/// Propagates I/O errors from reading the swap table.
pub fn read_swaps() -> Result<Vec<String>> {
    let text = std::fs::read_to_string(SWAPS_PATH)?;
    Ok(parse_swaps(&text))
}

/// Parse `/proc/swaps` contents.
#[must_use]
pub fn parse_swaps(text: &str) -> Vec<String> {
    text.lines()
        .skip(1)
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_owned)
        .collect()
}

/// `true` when `pvs` reports the device as a physical volume.
///
/// Falls back to "no" when lvm2 is not installed; the caller also checks the
/// `blkid` filesystem type, so an LVM member is still recognised.
fn is_active_pv(device: &Path) -> bool {
    let Ok(output) = Command::new("pvs")
        .args(["--noheadings", "-o", "pv_name"])
        .output()
    else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    let wanted = device.to_string_lossy();
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .any(|line| line.trim() == wanted.trim())
}

#[cfg(test)]
mod tests {
    use super::{OfflineProvider, parse_swaps, preflight};
    use crate::BlockSnapshotProvider;
    use crate::test_layout::{offline, with_partition};
    use lr_core::{Consistency, SnapshotOpts, Support};
    use std::path::PathBuf;

    #[test]
    fn an_idle_device_is_supported() {
        let layout = offline("/dev/lr-test-idle");
        let support = OfflineProvider.supports(&layout, &SnapshotOpts::default());
        assert_eq!(support, Support::Yes);
    }

    #[test]
    fn a_mounted_device_is_refused() {
        let mut layout = offline("/dev/lr-test-mounted");
        layout.mountpoints.push(PathBuf::from("/mnt/data"));
        let support = OfflineProvider.supports(&layout, &SnapshotOpts::default());
        assert!(matches!(support, Support::No(ref reason) if reason.contains("mounted")));
    }

    #[test]
    fn a_device_with_a_holder_is_refused() {
        let mut layout = offline("/dev/lr-test-holder");
        layout.holders.push("dm-0".to_owned());
        let support = OfflineProvider.supports(&layout, &SnapshotOpts::default());
        assert!(matches!(support, Support::No(ref reason) if reason.contains("held by dm-0")));
    }

    #[test]
    fn a_mounted_partition_is_refused() {
        let mut layout = offline("/dev/lr-test-part");
        with_partition(&mut layout, 1, vec![PathBuf::from("/")], Vec::new());
        let support = OfflineProvider.supports(&layout, &SnapshotOpts::default());
        assert!(matches!(support, Support::No(ref reason) if reason.contains("partition 1")));
    }

    #[test]
    fn an_lvm_member_is_refused() {
        let mut layout = offline("/dev/lr-test-pv");
        if let Some(fs) = layout.fs.as_mut() {
            fs.fs_type = "LVM2_member".to_owned();
        }
        let support = OfflineProvider.supports(&layout, &SnapshotOpts::default());
        assert!(matches!(support, Support::No(ref reason) if reason.contains("physical volume")));
    }

    #[test]
    fn a_provider_override_is_respected() {
        let layout = offline("/dev/lr-test-override");
        let opts = SnapshotOpts {
            provider: Some("lvm".to_owned()),
            ..SnapshotOpts::default()
        };
        assert!(!OfflineProvider.supports(&layout, &opts).is_yes());
    }

    /// A real file, so preflight's existence check can pass on a test machine.
    fn idle_source(dir: &tempfile::TempDir, name: &str) -> lr_core::SourceLayout {
        let path = dir.path().join(name);
        std::fs::write(&path, b"device stand-in").expect("write");
        offline(&path.to_string_lossy())
    }

    #[test]
    fn create_returns_an_offline_snapshot_for_an_idle_device() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = idle_source(&dir, "idle.img");
        let snapshot = OfflineProvider
            .create(&layout, &SnapshotOpts::default())
            .expect("snapshot");
        assert_eq!(snapshot.consistency, Consistency::Offline);
        assert_eq!(snapshot.block_path, layout.device);
    }

    #[test]
    fn create_refuses_a_busy_device() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut layout = idle_source(&dir, "busy.img");
        layout.mountpoints.push(PathBuf::from("/mnt"));
        let error = OfflineProvider
            .create(&layout, &SnapshotOpts::default())
            .expect_err("must refuse");
        assert!(
            matches!(error, lr_core::Error::TargetBusy { .. }),
            "{error}"
        );
    }

    #[test]
    fn preflight_reports_a_missing_device() {
        let layout = offline("/dev/lr-does-not-exist");
        // The layout check passes, then the sysfs lookup fails on I/O.
        let result = preflight(std::path::Path::new("/dev/lr-does-not-exist"), &layout);
        assert!(result.is_err());
    }

    #[test]
    fn swap_table_parsing_skips_the_header() {
        let text = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n\
                    /dev/sda2                               partition\t8388604\t\t0\t\t-2\n\
                    /swapfile                               file\t\t2097148\t\t0\t\t-3\n";
        assert_eq!(parse_swaps(text), vec!["/dev/sda2", "/swapfile"]);
    }
}
