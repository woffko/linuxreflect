//! Used-block maps for LinuxReflect (spec §C.1, §F, Slice S5).
//!
//! A [`UsedBlockProvider`] answers one question: which byte ranges of a device
//! must be read to reconstruct a mountable filesystem? The acceptance bar
//! (spec §F) is that a populated filesystem imaged with the map and restored
//! passes `fsck -n`/`xfs_repair -n` and every file hash matches, so the
//! parsers here are deliberately strict: when the tool output is internally
//! inconsistent they fail instead of returning a map that would silently
//! produce an unrestorable image.
//!
//! Providers are selected by the filesystem type `blkid` reported
//! (`lr_core::discovery`); anything unrecognised falls back to
//! [`raw::RawProvider`], which covers the whole device and reports
//! `complete = false`.
#![forbid(unsafe_code)]

mod ext4;
mod extents;
mod raw;
mod tool;
mod xfs;

pub use ext4::{Ext4Dump, Ext4Facts, Ext4Provider, GroupFree, parse_dumpe2fs};
pub use raw::{FS_TYPE as RAW_FS_TYPE, RawProvider};
pub use xfs::{XfsFreeSpace, XfsGeometry, XfsProvider, parse_freesp, parse_geometry};

use std::path::Path;

use lr_core::{Error, Result};

/// A byte range map of everything that is in use on a device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtentMap {
    /// Inclusive `(start, end)` byte ranges, sorted and disjoint.
    pub extents: Vec<(u64, u64)>,
    /// `false` when the map is a whole-device fallback rather than a real
    /// used-block map (spec §C.1: `complete=false => raw fallback`).
    pub complete: bool,
}

impl ExtentMap {
    /// A map that covers the whole device and claims nothing.
    ///
    /// # Errors
    /// Propagates I/O errors when the device size cannot be determined.
    pub fn whole_device(dev: &Path) -> Result<Self> {
        let size = match lr_unsafe::block_device_size_bytes(dev) {
            Ok(size) => size,
            Err(_) => std::fs::metadata(dev).map_err(Error::Io)?.len(),
        };
        Ok(Self {
            extents: if size == 0 {
                Vec::new()
            } else {
                vec![(0, size - 1)]
            },
            complete: false,
        })
    }

    /// Total bytes covered by the extents.
    #[must_use]
    pub fn covered_bytes(&self) -> u64 {
        self.extents
            .iter()
            .map(|(start, end)| end - start + 1)
            .sum()
    }

    /// `true` when nothing is used.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.extents.is_empty()
    }

    /// Round every extent outward to chunk boundaries and clamp to the device.
    ///
    /// Spec §G.2: used extents are rounded outward to chunk boundaries, so a
    /// chunk is read and stored whole even when only part of it is in use.
    #[must_use]
    pub fn chunk_aligned(&self, chunk_size: u64, device_size: u64) -> Vec<(u64, u64)> {
        if chunk_size == 0 {
            return self.extents.clone();
        }
        let aligned: Vec<(u64, u64)> = self
            .extents
            .iter()
            .filter_map(|(start, end)| {
                let first = start / chunk_size * chunk_size;
                let last = end / chunk_size * chunk_size;
                let last = last
                    .saturating_add(chunk_size - 1)
                    .min(device_size.saturating_sub(1));
                (first <= last).then_some((first, last))
            })
            .collect();
        extents::merge(aligned)
    }
}

/// One used-block map implementation.
pub trait UsedBlockProvider: Send + Sync {
    /// Filesystem type this provider handles (`"ext4"`, `"xfs"`, `"raw"`).
    fn fs_type(&self) -> &'static str;

    /// Compute the used-byte map of `dev`.
    ///
    /// The caller must pass a device that is not mounted or otherwise changing:
    /// the tools read on-disk metadata (spec §F, §E.3).
    ///
    /// # Errors
    /// Returns [`Error::Unsupported`] when the required tool is missing and
    /// [`Error::Corrupt`] when the tool output cannot be trusted.
    fn used_extents(&self, dev: &Path) -> Result<ExtentMap>;
}

static EXT4: Ext4Provider = Ext4Provider;
static XFS: XfsProvider = XfsProvider;
static RAW: RawProvider = RawProvider;
static ALL: [&dyn UsedBlockProvider; 3] = [&EXT4, &XFS, &RAW];

/// Every registered provider, most specific first.
#[must_use]
pub fn providers() -> &'static [&'static dyn UsedBlockProvider] {
    &ALL
}

/// Pick the provider for a filesystem type reported by `blkid`.
///
/// Unknown types (and an empty string) select the raw fallback rather than
/// failing, because an unmapped filesystem is still restorable byte for byte.
#[must_use]
pub fn provider_for(fs_type: &str) -> &'static dyn UsedBlockProvider {
    let normalised = fs_type.trim().to_ascii_lowercase();
    if ext4::FS_TYPES.contains(&normalised.as_str()) {
        &EXT4
    } else if xfs::FS_TYPES.contains(&normalised.as_str()) {
        &XFS
    } else {
        &RAW
    }
}

/// `true` when a real used-block provider exists for this filesystem type.
#[must_use]
pub fn has_real_provider(fs_type: &str) -> bool {
    !std::ptr::eq(provider_for(fs_type), &RAW as &dyn UsedBlockProvider)
}

#[cfg(test)]
mod tests {
    use super::{ExtentMap, has_real_provider, provider_for, providers};

    #[test]
    fn dispatch_uses_the_specific_provider_when_it_exists() {
        assert_eq!(provider_for("ext4").fs_type(), "ext4");
        assert_eq!(provider_for("ext2").fs_type(), "ext4");
        assert_eq!(provider_for("XFS").fs_type(), "xfs");
        assert_eq!(provider_for("btrfs").fs_type(), "raw");
        assert_eq!(provider_for("").fs_type(), "raw");
        assert!(has_real_provider("ext4"));
        assert!(!has_real_provider("ntfs"));
        assert_eq!(providers().len(), 3);
    }

    #[test]
    fn chunk_alignment_rounds_outward_and_clamps() {
        let map = ExtentMap {
            extents: vec![(100, 4095), (8192, 9000)],
            complete: true,
        };
        // chunk 4096 on a 16 KiB device
        assert_eq!(
            map.chunk_aligned(4096, 16384),
            vec![(0, 4095), (8192, 12287)]
        );
    }

    #[test]
    fn chunk_alignment_clamps_the_last_extent_to_the_device() {
        let map = ExtentMap {
            extents: vec![(5000, 8191)],
            complete: true,
        };
        assert_eq!(map.chunk_aligned(4096, 8192), vec![(4096, 8191)]);
        assert_eq!(map.chunk_aligned(4096, 10000), vec![(4096, 8191)]);
    }

    #[test]
    fn an_empty_map_covers_nothing() {
        let map = ExtentMap {
            extents: Vec::new(),
            complete: true,
        };
        assert!(map.is_empty());
        assert_eq!(map.covered_bytes(), 0);
        assert!(map.chunk_aligned(4096, 1 << 20).is_empty());
    }
}
