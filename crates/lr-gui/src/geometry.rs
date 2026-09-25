//! Convert validated disk extents to relative display coordinates.

/// Reject impossible extents rather than drawing a misleading partition map.
pub(crate) fn relative_extent(
    start_lba: u64,
    sector_size: u32,
    size: u64,
    total: u64,
) -> Option<(f32, f32)> {
    if sector_size == 0 || size == 0 || total == 0 {
        return None;
    }
    let start = start_lba.checked_mul(u64::from(sector_size))?;
    if start.checked_add(size)? > total {
        return None;
    }
    Some((
        (start as f64 / total as f64) as f32,
        (size as f64 / total as f64) as f32,
    ))
}

#[cfg(test)]
mod tests {
    use super::relative_extent;

    #[test]
    fn sector_size_changes_the_physical_position() {
        assert_eq!(relative_extent(1, 4096, 4096, 16384), Some((0.25, 0.25)));
        assert_eq!(relative_extent(1, 512, 4096, 16384), Some((0.03125, 0.25)));
    }

    #[test]
    fn rejects_overflow_and_out_of_device_extents() {
        assert_eq!(relative_extent(u64::MAX, 4096, 512, u64::MAX), None);
        assert_eq!(relative_extent(1, 512, u64::MAX, u64::MAX), None);
        assert_eq!(relative_extent(2, 4096, 4096, 8192), None);
    }

    #[test]
    fn rejects_missing_geometry() {
        assert_eq!(relative_extent(0, 0, 512, 1024), None);
        assert_eq!(relative_extent(0, 512, 0, 1024), None);
        assert_eq!(relative_extent(0, 512, 512, 0), None);
    }
}
