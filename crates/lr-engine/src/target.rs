//! Target safety checks (spec §H.2, §H.3).
//!
//! Before a single byte is written, the target and everything derived from it
//! must be free: not mounted in the daemon's namespace, not swap, no device
//! mapper or md holder, not an active LVM physical volume, and not the device
//! the running system is booted from.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use lr_core::sysfs;
use lr_core::{Error, Result, discovery::discover_source};

/// Mount points that may never be the restore target.
pub const BOOT_MOUNTPOINTS: [&str; 3] = ["/", "/boot", "/boot/efi"];

/// Facts of a directory restore target (file mode, spec §K S12).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DirectoryFacts {
    /// `st_dev` of the directory.
    pub dev_id: u64,
    /// `st_ino` of the directory.
    pub ino: u64,
    /// Canonical path of the directory.
    pub path: PathBuf,
}

impl DirectoryFacts {
    /// Capture the identity of a directory.
    ///
    /// # Errors
    /// Returns [`Error::Unsupported`] when the path is not a directory and
    /// propagates filesystem errors.
    pub fn read(path: &Path) -> Result<Self> {
        let canonical = path.canonicalize().map_err(Error::Io)?;
        let metadata = std::fs::metadata(&canonical).map_err(Error::Io)?;
        if !metadata.is_dir() {
            return Err(Error::unsupported(format!(
                "{} is not a directory; file-mode restores need one",
                canonical.display()
            )));
        }
        Ok(Self {
            dev_id: metadata.dev(),
            ino: metadata.ino(),
            path: canonical,
        })
    }

    /// `true` when the directory is still the same directory.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        self == other
    }

    /// Free bytes available in the filesystem holding the directory.
    ///
    /// # Errors
    /// Returns the raw `statvfs` error.
    pub fn free_bytes(&self) -> Result<u64> {
        Ok(lr_unsafe::filemeta::statvfs_bytes(&self.path)
            .map_err(Error::Io)?
            .0)
    }
}

/// Check that a device can be opened for writing.
///
/// # Errors
/// Returns [`Error::TargetBusy`] naming the concrete holder.
pub fn preflight_target(device: &Path) -> Result<()> {
    let layout = discover_source(device)?;
    lr_snapshot::offline::preflight(device, &layout)?;
    refuse_if_running_root(device)?;
    Ok(())
}

fn refuse_if_running_root(device: &Path) -> Result<()> {
    let metadata = std::fs::metadata(device).map_err(Error::Io)?;
    let target = metadata.rdev();
    if target == 0 {
        // A regular file has no device number; nothing to compare.
        return Ok(());
    }
    let (target_major, target_minor) = split_dev(target);
    for mount in sysfs::read_mounts().map_err(Error::Io)? {
        if !BOOT_MOUNTPOINTS.contains(&mount.mountpoint.to_string_lossy().as_ref()) {
            continue;
        }
        let Some((major, minor)) = parse_dev_id(&mount.dev_id) else {
            continue;
        };
        if major == target_major && minor == target_minor {
            return Err(Error::TargetBusy {
                holder: format!(
                    "{} backs the running system's {} mount",
                    device.display(),
                    mount.mountpoint.display()
                ),
            });
        }
    }
    Ok(())
}

fn parse_dev_id(text: &str) -> Option<(u32, u32)> {
    let (major, minor) = text.split_once(':')?;
    Some((major.trim().parse().ok()?, minor.trim().parse().ok()?))
}

fn split_dev(dev: u64) -> (u32, u32) {
    // glibc's encoding of major:minor in dev_t.
    let major = ((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff);
    let minor = (dev & 0xff) | ((dev >> 12) & !0xff);
    (major as u32, minor as u32)
}

#[cfg(test)]
mod tests {
    use super::{parse_dev_id, preflight_target, split_dev};

    #[test]
    fn device_ids_are_parsed_and_encoded_consistently() {
        assert_eq!(parse_dev_id("8:1"), Some((8, 1)));
        assert_eq!(parse_dev_id(" 259:0 "), Some((259, 0)));
        assert_eq!(parse_dev_id("nonsense"), None);

        // 8:1 as produced by makedev(8, 1).
        let dev = 8u64 << 8 | 1;
        assert_eq!(split_dev(dev), (8, 1));
        // A large major, as used by device mapper (major 259, minor 3).
        let dev = (259u64 << 8) | 3;
        assert_eq!(split_dev(dev), (259, 3));
    }

    #[test]
    fn a_missing_target_is_an_error() {
        assert!(preflight_target(std::path::Path::new("/nonexistent/lr-target")).is_err());
    }
}
