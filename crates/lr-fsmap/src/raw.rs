//! Raw fallback for everything the MVP cannot map (spec §F).
//!
//! NTFS, FAT, swap headers, LUKS containers, LVM physical volumes, unknown
//! filesystems and anything else without a provider are imaged whole with
//! zero-chunk suppression; the map itself reports `complete = false` so the
//! engine never mistakes it for a used-block map.

use std::path::Path;

use lr_core::Result;

use crate::{ExtentMap, UsedBlockProvider};

/// Filesystem type reported when nothing more specific applies.
pub const FS_TYPE: &str = "raw";

/// The provider entry point.
#[derive(Debug, Default, Clone, Copy)]
pub struct RawProvider;

impl UsedBlockProvider for RawProvider {
    fn fs_type(&self) -> &'static str {
        FS_TYPE
    }

    fn used_extents(&self, dev: &Path) -> Result<ExtentMap> {
        ExtentMap::whole_device(dev)
    }
}

#[cfg(test)]
mod tests {
    use super::RawProvider;
    use crate::UsedBlockProvider;
    use std::path::Path;

    #[test]
    fn a_raw_map_is_complete_never() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("blob.bin");
        std::fs::write(&file, vec![0u8; 8192]).expect("write");
        let map = RawProvider.used_extents(&file).expect("map");
        assert!(!map.complete, "a raw map must not claim completeness");
        assert_eq!(map.extents, vec![(0, 8191)]);
    }

    #[test]
    fn a_missing_path_is_an_error() {
        assert!(
            RawProvider
                .used_extents(Path::new("/nonexistent/lr"))
                .is_err()
        );
    }
}
