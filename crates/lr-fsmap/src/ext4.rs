//! ext4/ext2/ext3 used-block maps from `dumpe2fs` (spec §F).
//!
//! `dumpe2fs` prints one `Free blocks:` line per block group, indented by two
//! spaces, plus the superblock total at column zero. The list is complete
//! (e2fsprogs' `print_free()` never truncates it), so the parser cross-checks
//! the sum of the ranges against the superblock total and refuses to return a
//! map when they disagree: an incomplete used-block map would silently produce
//! an image that cannot be restored.

use std::io::BufRead;
use std::path::Path;

use lr_core::{Error, Result};

use crate::extents::{complement, normalize, to_bytes};
use crate::tool;
use crate::{ExtentMap, UsedBlockProvider};

/// Filesystem types this provider handles.
pub(crate) const FS_TYPES: [&str; 3] = ["ext4", "ext3", "ext2"];

/// The provider entry point.
#[derive(Debug, Default, Clone, Copy)]
pub struct Ext4Provider;

impl UsedBlockProvider for Ext4Provider {
    fn fs_type(&self) -> &'static str {
        "ext4"
    }

    fn used_extents(&self, dev: &Path) -> Result<ExtentMap> {
        let dump = tool::with_tool_output("dumpe2fs", &[], dev, |reader| parse_dumpe2fs(reader))?;
        dump.used_map()
    }
}

/// Superblock fields the parser needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ext4Facts {
    /// Filesystem block size in bytes.
    pub block_size: u64,
    /// Total blocks in the filesystem.
    pub block_count: u64,
    /// First data block (0 for 4 KiB blocks, 1 for 1 KiB blocks).
    pub first_block: u64,
    /// Free blocks as reported by the superblock.
    pub free_blocks_total: u64,
}

/// One block group's free list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupFree {
    /// Group number.
    pub group: u64,
    /// First block of the group, inclusive.
    pub first: u64,
    /// Last block of the group, inclusive.
    pub last: u64,
    /// Free ranges inside the group, in filesystem blocks.
    pub ranges: Vec<(u64, u64)>,
}

/// Everything `parse_dumpe2fs` extracts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ext4Dump {
    /// Superblock facts.
    pub facts: Ext4Facts,
    /// Free ranges in filesystem blocks, normalized.
    pub free: Vec<(u64, u64)>,
    /// Per-group free lists, in file order.
    pub groups: Vec<GroupFree>,
    /// Groups that were seen without a `Free blocks:` line.
    pub groups_without_free_list: usize,
}

impl Ext4Dump {
    /// Build the byte-level used-block map.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] when the parser's own consistency checks
    /// fail (see [`parse_dumpe2fs`]).
    pub fn used_map(&self) -> Result<ExtentMap> {
        let used_blocks = complement(self.facts.first_block, self.facts.block_count, &self.free)?;
        Ok(ExtentMap {
            extents: to_bytes(&used_blocks, self.facts.block_size),
            complete: true,
        })
    }

    /// Number of filesystem blocks considered used.
    #[must_use]
    pub fn used_blocks(&self) -> u64 {
        self.facts
            .block_count
            .saturating_sub(self.facts.free_blocks_total)
    }
}

/// Parse `dumpe2fs` output.
///
/// # Errors
/// Returns [`Error::Corrupt`] when a required field is missing, when a group
/// has no free-block line (a tool format change), when free ranges fall outside
/// their group or outside the filesystem, or when the sum of the free ranges
/// does not equal the superblock's free-block total.
pub fn parse_dumpe2fs(reader: &mut dyn BufRead) -> Result<Ext4Dump> {
    let mut block_size: Option<u64> = None;
    let mut block_count: Option<u64> = None;
    let mut first_block: Option<u64> = None;
    let mut free_blocks_total: Option<u64> = None;

    let mut groups: Vec<GroupFree> = Vec::new();
    let mut pending_group: Option<(u64, u64, u64)> = None; // (group, first, last)

    let mut line = String::new();
    loop {
        line.clear();
        let read = reader
            .read_line(&mut line)
            .map_err(|e| Error::Io(std::io::Error::other(format!("dumpe2fs output: {e}"))))?;
        if read == 0 {
            break;
        }
        let text = line.trim_end_matches(['\n', '\r']);

        if let Some(value) = field(text, "Block size:") {
            block_size = Some(value);
        } else if let Some(value) = field(text, "Block count:") {
            block_count = Some(value);
        } else if let Some(value) = field(text, "First block:") {
            first_block = Some(value);
        } else if let Some(value) = field(text, "Free blocks:") {
            // Column zero: the superblock total, not a group list.
            free_blocks_total = Some(value);
        } else if let Some((group, first, last)) = group_header(text) {
            if let Some((previous, from, to)) = pending_group.take() {
                return Err(Error::corrupt(format!(
                    "group {previous} ({from}-{to}) has no free-block list before group {group}"
                )));
            }
            pending_group = Some((group, first, last));
        } else if let Some(list) = text.strip_prefix("  Free blocks:") {
            let (group, first, last) = pending_group.take().ok_or_else(|| {
                Error::corrupt("free-block list without a preceding group header")
            })?;
            let ranges = parse_block_ranges(list)?;
            for (start, end) in &ranges {
                if *start < first || *end > last {
                    return Err(Error::corrupt(format!(
                        "group {group} free range {start}-{end} lies outside {first}-{last}"
                    )));
                }
            }
            groups.push(GroupFree {
                group,
                first,
                last,
                ranges,
            });
        }
    }

    let facts = Ext4Facts {
        block_size: block_size.ok_or_else(|| Error::corrupt("dumpe2fs: no Block size"))?,
        block_count: block_count.ok_or_else(|| Error::corrupt("dumpe2fs: no Block count"))?,
        first_block: first_block.ok_or_else(|| Error::corrupt("dumpe2fs: no First block"))?,
        free_blocks_total: free_blocks_total
            .ok_or_else(|| Error::corrupt("dumpe2fs: no superblock Free blocks total"))?,
    };
    if facts.block_size == 0 || !facts.block_size.is_power_of_two() {
        return Err(Error::corrupt(format!(
            "dumpe2fs: implausible block size {}",
            facts.block_size
        )));
    }

    let groups_without_free_list = usize::from(pending_group.is_some());
    if groups_without_free_list > 0 {
        let (group, first, last) = pending_group.expect("checked above");
        return Err(Error::corrupt(format!(
            "group {group} ({first}-{last}) has no free-block list"
        )));
    }

    let mut free: Vec<(u64, u64)> = groups
        .iter()
        .flat_map(|group| group.ranges.iter().copied())
        .collect();
    free = normalize(free)?;

    let free_from_lists: u64 = free.iter().map(|(start, end)| end - start + 1).sum();
    if free_from_lists != facts.free_blocks_total {
        return Err(Error::corrupt(format!(
            "dumpe2fs: free lists sum to {free_from_lists} blocks but the superblock reports {}",
            facts.free_blocks_total
        )));
    }
    if facts.first_block >= facts.block_count {
        return Err(Error::corrupt(
            "dumpe2fs: first block is past the filesystem end",
        ));
    }

    Ok(Ext4Dump {
        facts,
        free,
        groups,
        groups_without_free_list: 0,
    })
}

fn field(line: &str, name: &str) -> Option<u64> {
    let rest = line.strip_prefix(name)?;
    rest.trim().parse().ok()
}

/// Parse `Group 12: (Blocks 393216-425983) csum 0x... [FLAGS]`.
fn group_header(line: &str) -> Option<(u64, u64, u64)> {
    let rest = line.strip_prefix("Group ")?;
    let (number, rest) = rest.split_once(':')?;
    let group: u64 = number.trim().parse().ok()?;
    let rest = rest.trim_start().strip_prefix("(Blocks ")?;
    let (range, _) = rest.split_once(')')?;
    let (first, last) = range.split_once('-')?;
    Some((group, first.trim().parse().ok()?, last.trim().parse().ok()?))
}

/// Parse `1234-5678, 91011,` style inclusive block ranges.
fn parse_block_ranges(list: &str) -> Result<Vec<(u64, u64)>> {
    let mut ranges = Vec::new();
    for item in list.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let range = match item.split_once('-') {
            Some((start, end)) => {
                let start: u64 = start
                    .trim()
                    .parse()
                    .map_err(|_| Error::corrupt(format!("dumpe2fs: bad range '{item}'")))?;
                let end: u64 = end
                    .trim()
                    .parse()
                    .map_err(|_| Error::corrupt(format!("dumpe2fs: bad range '{item}'")))?;
                (start, end)
            }
            None => {
                let value: u64 = item
                    .parse()
                    .map_err(|_| Error::corrupt(format!("dumpe2fs: bad range '{item}'")))?;
                (value, value)
            }
        };
        ranges.push(range);
    }
    Ok(ranges)
}

#[cfg(test)]
mod tests {
    use super::{Ext4Provider, parse_dumpe2fs};
    use crate::UsedBlockProvider;
    use std::io::BufReader;

    const FRESH: &str = include_str!("../tests/fixtures/ext4-fresh.dumpe2fs.txt");
    const FRAGMENTED: &str = include_str!("../tests/fixtures/ext4-fragmented.dumpe2fs.txt");

    #[test]
    fn provider_is_named_ext4() {
        assert_eq!(Ext4Provider.fs_type(), "ext4");
    }

    #[test]
    fn fresh_filesystem_matches_the_independent_calculation() {
        let mut reader = BufReader::new(FRESH.as_bytes());
        let dump = parse_dumpe2fs(&mut reader).expect("parse");
        assert_eq!(dump.facts.block_size, 4096);
        assert_eq!(dump.facts.block_count, 65536);
        assert_eq!(dump.facts.first_block, 0);
        assert_eq!(dump.facts.free_blocks_total, 57268);
        assert_eq!(dump.free.len(), 2, "two free ranges");

        let map = dump.used_map().expect("used map");
        assert!(map.complete);
        assert_eq!(map.extents.len(), 2);
        assert_eq!(map.covered_bytes(), 33_865_728);
        assert_eq!(map.extents[0].0, 0, "the first extent starts at block 0");
    }

    #[test]
    fn fragmented_filesystem_matches_the_independent_calculation() {
        let mut reader = BufReader::new(FRAGMENTED.as_bytes());
        let dump = parse_dumpe2fs(&mut reader).expect("parse");
        assert_eq!(dump.facts.free_blocks_total, 56046);
        assert_eq!(dump.free.len(), 202, "202 free ranges");

        let map = dump.used_map().expect("used map");
        assert_eq!(map.extents.len(), 202);
        assert_eq!(map.covered_bytes(), 38_871_040);
    }

    #[test]
    fn free_ranges_are_sorted_and_disjoint() {
        for fixture in [FRESH, FRAGMENTED] {
            let mut reader = BufReader::new(fixture.as_bytes());
            let dump = parse_dumpe2fs(&mut reader).expect("parse");
            for pair in dump.free.windows(2) {
                assert!(pair[0].1 < pair[1].0, "ranges must be sorted and disjoint");
            }
        }
    }

    #[test]
    fn a_group_without_a_free_list_is_rejected() {
        let mut text = FRESH.replace("  Free blocks: 4139-32767\n", "");
        // Keep the superblock total consistent so the missing line is the only
        // difference.
        text = text.replace(
            "Free blocks:              57268\n",
            "Free blocks:              28639\n",
        );
        let mut reader = BufReader::new(text.as_bytes());
        let error = parse_dumpe2fs(&mut reader).expect_err("must fail");
        assert!(error.to_string().contains("free-block list"), "{error}");
    }

    #[test]
    fn a_free_list_that_disagrees_with_the_total_is_rejected() {
        let text = FRESH.replace(
            "Free blocks:              57268\n",
            "Free blocks:              1\n",
        );
        let mut reader = BufReader::new(text.as_bytes());
        assert!(parse_dumpe2fs(&mut reader).is_err());
    }

    #[test]
    fn an_overlapping_free_list_is_rejected() {
        let text = FRESH.replace("  Free blocks: 4139-32767\n", "  Free blocks: 4139-50000\n");
        let mut reader = BufReader::new(text.as_bytes());
        assert!(parse_dumpe2fs(&mut reader).is_err());
    }

    #[test]
    fn a_missing_superblock_field_is_rejected() {
        for needle in ["Block size:", "Block count:", "First block:"] {
            let text: String = FRESH
                .lines()
                .filter(|line| !line.starts_with(needle))
                .collect::<Vec<_>>()
                .join("\n");
            let mut reader = BufReader::new(text.as_bytes());
            assert!(parse_dumpe2fs(&mut reader).is_err(), "missing {needle}");
        }
    }
}
