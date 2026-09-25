//! Device geometry helpers (spec §B, §C).

use std::path::Path;

/// Block device geometry reported by ioctls/sysfs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Geometry {
    /// Total device size in bytes.
    pub size_bytes: u64,
    /// Logical (minimum I/O) sector size in bytes.
    pub logical_block_size: u32,
    /// Physical block size in bytes.
    pub physical_block_size: u32,
}

impl Geometry {
    /// Number of logical sectors, matching `BLKGETSIZE64 / BLKSSZGET`.
    #[must_use]
    pub const fn sector_count(&self) -> u64 {
        if self.logical_block_size == 0 {
            0
        } else {
            self.size_bytes / self.logical_block_size as u64
        }
    }

    /// Alignment required for `O_DIRECT` buffers (spec §C).
    #[must_use]
    pub fn direct_io_alignment(&self) -> usize {
        std::cmp::max(4096, self.logical_block_size as usize)
    }

    /// Round `bytes` up to a multiple of [`Geometry::direct_io_alignment`].
    #[must_use]
    pub fn align_up(&self, bytes: u64) -> u64 {
        let align = self.direct_io_alignment() as u64;
        bytes.div_ceil(align) * align
    }

    /// Probe a block device using the ioctls in `lr-unsafe`, falling back to
    /// sysfs when the logical/physical ioctls are unavailable.
    ///
    /// # Errors
    /// Returns an error when the device cannot be opened or has no size.
    pub fn probe(device: &Path) -> crate::Result<Self> {
        let size_bytes = lr_unsafe::block_device_size_bytes(device).map_err(|e| {
            crate::Error::Io(std::io::Error::new(
                e.kind(),
                format!("BLKGETSIZE64 on {}: {e}", device.display()),
            ))
        })?;
        let logical_block_size = lr_unsafe::block_device_logical_sector_size(device)
            .unwrap_or_else(|_| crate::sysfs::logical_block_size(device).unwrap_or(512));
        let physical_block_size =
            lr_unsafe::block_device_physical_sector_size(device).unwrap_or(logical_block_size);
        Ok(Self {
            size_bytes,
            logical_block_size,
            physical_block_size,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Geometry;

    fn geom(size: u64) -> Geometry {
        Geometry {
            size_bytes: size,
            logical_block_size: 512,
            physical_block_size: 4096,
        }
    }

    #[test]
    fn sector_count_divides() {
        assert_eq!(geom(1024 * 1024).sector_count(), 2048);
        assert_eq!(geom(0).sector_count(), 0);
    }

    #[test]
    fn alignment_is_at_least_4096() {
        assert_eq!(geom(0).direct_io_alignment(), 4096);
        let big = Geometry {
            size_bytes: 0,
            logical_block_size: 8192,
            physical_block_size: 8192,
        };
        assert_eq!(big.direct_io_alignment(), 8192);
    }

    #[test]
    fn align_up_rounds() {
        assert_eq!(geom(0).align_up(1), 4096);
        assert_eq!(geom(0).align_up(4096), 4096);
        assert_eq!(geom(0).align_up(4097), 8192);
    }
}
