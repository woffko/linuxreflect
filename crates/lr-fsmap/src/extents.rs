//! Range arithmetic shared by the used-block map providers.
//!
//! All ranges here are inclusive `(start, end)` pairs in one unit (filesystem
//! blocks for the parsers, bytes at the provider boundary). Providers must
//! return sorted, disjoint extents, so every list goes through
//! [`normalize`] and any overlap is treated as a parsing failure rather than
//! silently merged: an inconsistent map would produce an unrestorable image.

use lr_core::{Error, Result};

/// Sort and merge adjacent ranges, rejecting overlaps.
///
/// Adjacent ranges (`0-9`, `10-19`) merge into `0-19`; a genuine overlap
/// (`0-9`, `5-19`) is [`Error::Corrupt`].
///
/// # Errors
/// Returns [`Error::Corrupt`] for an overlapping or reversed range.
pub(crate) fn normalize(mut ranges: Vec<(u64, u64)>) -> Result<Vec<(u64, u64)>> {
    for (start, end) in &ranges {
        if start > end {
            return Err(Error::corrupt(format!("reversed range {start}-{end}")));
        }
    }
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if start <= last.1.saturating_add(1) => {
                if start <= last.1 && start != last.1 + 1 {
                    return Err(Error::corrupt(format!(
                        "overlapping ranges {}..{} and {start}..{end}",
                        last.0, last.1
                    )));
                }
                last.1 = last.1.max(end);
            }
            _ => merged.push((start, end)),
        }
    }
    Ok(merged)
}

/// Sort and merge ranges, tolerating overlaps.
///
/// Used after rounding extents outward, where two extents can legitimately end
/// up inside the same chunk. Parsers use [`normalize`] instead, which rejects
/// overlaps.
#[must_use]
pub(crate) fn merge(mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if start <= last.1.saturating_add(1) => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}

/// Complement `free` inside `[first, end_exclusive)`.
///
/// `free` must already be normalized and fully inside the region.
///
/// # Errors
/// Returns [`Error::Corrupt`] when a range lies outside the region.
pub(crate) fn complement(
    first: u64,
    end_exclusive: u64,
    free: &[(u64, u64)],
) -> Result<Vec<(u64, u64)>> {
    let mut used = Vec::new();
    let mut cursor = first;
    for (start, end) in free {
        if *start < first || *end >= end_exclusive {
            return Err(Error::corrupt(format!(
                "free range {start}-{end} lies outside {first}..{end_exclusive}"
            )));
        }
        if *start > cursor {
            used.push((cursor, start - 1));
        }
        cursor = end + 1;
    }
    if cursor < end_exclusive {
        used.push((cursor, end_exclusive - 1));
    }
    Ok(used)
}

/// Scale block ranges to byte ranges.
#[must_use]
pub(crate) fn to_bytes(ranges: &[(u64, u64)], block_size: u64) -> Vec<(u64, u64)> {
    ranges
        .iter()
        .map(|(start, end)| (start * block_size, (end + 1) * block_size - 1))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{complement, normalize, to_bytes};

    #[test]
    fn merge_tolerates_overlaps() {
        assert_eq!(super::merge(vec![(10, 19), (0, 9), (5, 25)]), vec![(0, 25)]);
        assert_eq!(super::merge(vec![(0, 1), (4, 5)]), vec![(0, 1), (4, 5)]);
    }

    #[test]
    fn merges_adjacent_and_keeps_gaps() {
        let merged = normalize(vec![(10, 19), (0, 9), (30, 39)]).expect("normalize");
        assert_eq!(merged, vec![(0, 19), (30, 39)]);
    }

    #[test]
    fn rejects_overlaps_and_reversed_ranges() {
        assert!(normalize(vec![(0, 9), (5, 19)]).is_err());
        assert!(normalize(vec![(9, 0)]).is_err());
    }

    #[test]
    fn complements_within_a_region() {
        let used = complement(0, 100, &[(10, 19), (50, 59)]).expect("complement");
        assert_eq!(used, vec![(0, 9), (20, 49), (60, 99)]);

        let empty = complement(0, 100, &[(0, 99)]).expect("complement");
        assert!(empty.is_empty());

        let all = complement(0, 100, &[]).expect("complement");
        assert_eq!(all, vec![(0, 99)]);
    }

    #[test]
    fn complement_handles_the_first_block_offset() {
        // `First block: 1` filesystems start their block numbering at 1.
        let used = complement(1, 10, &[(1, 4)]).expect("complement");
        assert_eq!(used, vec![(5, 9)]);
    }

    #[test]
    fn complement_rejects_out_of_range_free_ranges() {
        assert!(complement(0, 10, &[(5, 12)]).is_err());
        assert!(complement(1, 10, &[(0, 4)]).is_err());
    }

    #[test]
    fn scales_blocks_to_bytes() {
        assert_eq!(
            to_bytes(&[(0, 1), (3, 3)], 4096),
            vec![(0, 8191), (12288, 16383)]
        );
    }
}
