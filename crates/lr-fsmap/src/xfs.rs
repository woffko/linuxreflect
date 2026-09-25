//! xfs used-block maps from `xfs_db` (spec §F).
//!
//! Geometry comes from the superblock (`blocksize`, `agblocks`, `agcount`,
//! `dblocks`, `logstart`, `rblocks`); free extents come from `freesp`. Used
//! space is every allocation-group block that is not free, which includes the
//! internal log (spec §F). Filesystems with an external log (`logstart = 0`) or
//! a realtime device (`rblocks > 0`) cannot be mapped completely, so the map is
//! returned with `complete = false` and the caller falls back to a raw read.

use std::io::BufRead;
use std::path::Path;

use lr_core::{Error, Result};

use crate::extents::{complement, normalize, to_bytes};
use crate::tool;
use crate::{ExtentMap, UsedBlockProvider};

/// Filesystem types this provider handles.
pub(crate) const FS_TYPES: [&str; 1] = ["xfs"];

/// Number of superblock fields the geometry query prints.
const GEOMETRY_FIELDS: [&str; 6] = [
    "blocksize",
    "agblocks",
    "agcount",
    "dblocks",
    "logstart",
    "rblocks",
];

/// The provider entry point.
#[derive(Debug, Default, Clone, Copy)]
pub struct XfsProvider;

impl UsedBlockProvider for XfsProvider {
    fn fs_type(&self) -> &'static str {
        "xfs"
    }

    fn used_extents(&self, dev: &Path) -> Result<ExtentMap> {
        let mut geometry_args: Vec<&str> = vec!["-r", "-c", "sb 0"];
        let prints: Vec<String> = GEOMETRY_FIELDS
            .iter()
            .map(|field| format!("print {field}"))
            .collect();
        for print in &prints {
            geometry_args.push("-c");
            geometry_args.push(print);
        }
        let geometry = tool::with_tool_output("xfs_db", &geometry_args, dev, |reader| {
            parse_geometry(reader)
        })?;
        let free = tool::with_tool_output(
            "xfs_db",
            &["-r", "-c", "freesp -d", "-c", "freesp -s"],
            dev,
            |reader| parse_freesp(reader, &geometry),
        )?;
        used_map(&geometry, &free)
    }
}

/// Superblock geometry needed to place extents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XfsGeometry {
    /// Filesystem block size in bytes.
    pub block_size: u64,
    /// Blocks per allocation group.
    pub ag_blocks: u64,
    /// Number of allocation groups.
    pub ag_count: u64,
    /// Data device size in blocks.
    pub data_blocks: u64,
    /// Start block of the internal log; 0 means the log is external.
    pub log_start: u64,
    /// Realtime device size in blocks; non-zero means a realtime device exists.
    pub realtime_blocks: u64,
}

/// Free space as reported by `freesp`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XfsFreeSpace {
    /// Free extents as `(absolute block, length)`.
    pub extents: Vec<(u64, u64)>,
    /// `total free extents` from the tool.
    pub total_extents: u64,
    /// `total free blocks` from the tool.
    pub total_blocks: u64,
}

/// Parse the `key = value` lines of `xfs_db -c "sb 0" -c "print ..."`.
///
/// # Errors
/// Returns [`Error::Corrupt`] when a field is missing or implausible.
pub fn parse_geometry(reader: &mut dyn BufRead) -> Result<XfsGeometry> {
    let mut values = std::collections::BTreeMap::new();
    let mut line = String::new();
    loop {
        line.clear();
        if reader
            .read_line(&mut line)
            .map_err(|e| Error::Io(std::io::Error::other(format!("xfs_db output: {e}"))))?
            == 0
        {
            break;
        }
        let text = line.trim();
        if let Some((key, value)) = text.split_once('=')
            && let Ok(value) = value.trim().parse::<u64>()
        {
            values.insert(key.trim().to_owned(), value);
        }
    }
    let get = |field: &str| -> Result<u64> {
        values
            .get(field)
            .copied()
            .ok_or_else(|| Error::corrupt(format!("xfs_db: no '{field}' in the superblock output")))
    };
    let geometry = XfsGeometry {
        block_size: get("blocksize")?,
        ag_blocks: get("agblocks")?,
        ag_count: get("agcount")?,
        data_blocks: get("dblocks")?,
        log_start: get("logstart")?,
        realtime_blocks: get("rblocks")?,
    };
    if !geometry.block_size.is_power_of_two() || geometry.block_size == 0 {
        return Err(Error::corrupt(format!(
            "xfs_db: implausible block size {}",
            geometry.block_size
        )));
    }
    if geometry.ag_count == 0 || geometry.ag_blocks == 0 || geometry.data_blocks == 0 {
        return Err(Error::corrupt("xfs_db: zero AG geometry"));
    }
    if geometry.data_blocks > geometry.ag_count * geometry.ag_blocks {
        return Err(Error::corrupt("xfs_db: dblocks exceeds agcount * agblocks"));
    }
    Ok(geometry)
}

/// Parse the `freesp -d` extent list and the `freesp -s` totals.
///
/// # Errors
/// Returns [`Error::Corrupt`] for an extent outside its AG, a missing totals
/// line, or totals that disagree with the extent list.
pub fn parse_freesp(reader: &mut dyn BufRead, geometry: &XfsGeometry) -> Result<XfsFreeSpace> {
    let mut extents: Vec<(u64, u64)> = Vec::new();
    let mut total_extents: Option<u64> = None;
    let mut total_blocks: Option<u64> = None;
    let mut line = String::new();

    loop {
        line.clear();
        if reader
            .read_line(&mut line)
            .map_err(|e| Error::Io(std::io::Error::other(format!("xfs_db output: {e}"))))?
            == 0
        {
            break;
        }
        let text = line.trim();

        if let Some(rest) = text.strip_prefix("total free extents ") {
            total_extents = rest.trim().parse().ok();
            continue;
        }
        if let Some(rest) = text.strip_prefix("total free blocks ") {
            total_blocks = rest.trim().parse().ok();
            continue;
        }

        // Extent rows are exactly three integers; the histogram has five and
        // the header has none.
        let fields: Vec<&str> = text.split_whitespace().collect();
        if fields.len() != 3 || !fields.iter().all(|field| field.parse::<u64>().is_ok()) {
            continue;
        }
        let agno: u64 = fields[0].parse().expect("checked");
        let agbno: u64 = fields[1].parse().expect("checked");
        let len: u64 = fields[2].parse().expect("checked");
        if len == 0 {
            return Err(Error::corrupt("xfs_db: zero-length free extent"));
        }
        if agno >= geometry.ag_count {
            return Err(Error::corrupt(format!("xfs_db: AG {agno} is out of range")));
        }
        if agbno + len > geometry.ag_blocks {
            return Err(Error::corrupt(format!(
                "xfs_db: extent {agno}/{agbno}+{len} exceeds the allocation group"
            )));
        }
        extents.push((agno * geometry.ag_blocks + agbno, len));
    }

    let total_extents =
        total_extents.ok_or_else(|| Error::corrupt("xfs_db: no 'total free extents' line"))?;
    let total_blocks =
        total_blocks.ok_or_else(|| Error::corrupt("xfs_db: no 'total free blocks' line"))?;
    if extents.len() as u64 != total_extents {
        return Err(Error::corrupt(format!(
            "xfs_db: parsed {} free extents but the tool reports {total_extents}",
            extents.len()
        )));
    }
    let blocks: u64 = extents.iter().map(|(_, len)| len).sum();
    if blocks != total_blocks {
        return Err(Error::corrupt(format!(
            "xfs_db: parsed {blocks} free blocks but the tool reports {total_blocks}"
        )));
    }
    extents.sort_unstable();
    Ok(XfsFreeSpace {
        extents,
        total_extents,
        total_blocks,
    })
}

/// Build the byte-level used-block map.
///
/// # Errors
/// Returns [`Error::Corrupt`] when the free extents overlap or fall outside the
/// data device.
pub(crate) fn used_map(geometry: &XfsGeometry, free: &XfsFreeSpace) -> Result<ExtentMap> {
    if geometry.log_start == 0 || geometry.realtime_blocks > 0 {
        // By design not completely mappable: the log lives on another device or
        // a realtime subvolume exists (spec §F).
        return Ok(ExtentMap {
            extents: vec![(0, geometry.data_blocks * geometry.block_size - 1)],
            complete: false,
        });
    }
    let ranges: Vec<(u64, u64)> = free
        .extents
        .iter()
        .map(|(start, len)| (*start, start + len - 1))
        .collect();
    let ranges = normalize(ranges)?;
    let used_blocks = complement(0, geometry.data_blocks, &ranges)?;
    Ok(ExtentMap {
        extents: to_bytes(&used_blocks, geometry.block_size),
        complete: true,
    })
}

#[cfg(test)]
mod tests {
    use super::{XfsProvider, parse_freesp, parse_geometry, used_map};
    use crate::UsedBlockProvider;
    use std::io::BufReader;

    const SB: &str = include_str!("../tests/fixtures/xfs-fresh.sb.txt");
    const FREESP: &str = include_str!("../tests/fixtures/xfs-fresh.freesp.txt");

    fn geometry() -> super::XfsGeometry {
        parse_geometry(&mut BufReader::new(SB.as_bytes())).expect("geometry")
    }

    fn free_space() -> super::XfsFreeSpace {
        parse_freesp(&mut BufReader::new(FREESP.as_bytes()), &geometry()).expect("freesp")
    }

    #[test]
    fn provider_is_named_xfs() {
        assert_eq!(XfsProvider.fs_type(), "xfs");
    }

    #[test]
    fn geometry_matches_the_captured_superblock() {
        let geometry = geometry();
        assert_eq!(geometry.block_size, 4096);
        assert_eq!(geometry.ag_blocks, 32768);
        assert_eq!(geometry.ag_count, 4);
        assert_eq!(geometry.data_blocks, 131072);
        assert_eq!(geometry.log_start, 65543);
        assert_eq!(geometry.realtime_blocks, 0);
    }

    #[test]
    fn freepace_matches_the_tool_totals() {
        let free = free_space();
        assert_eq!(free.total_extents, 29);
        assert_eq!(free.total_blocks, 114_652);
        assert_eq!(free.extents.len(), 29);
    }

    #[test]
    fn used_map_matches_the_independent_calculation() {
        let map = used_map(&geometry(), &free_space()).expect("used map");
        assert!(map.complete);
        assert_eq!(map.extents.len(), 5);
        assert_eq!(map.covered_bytes(), 67_256_320);
        // Free space starts at block 7 of AG 0, so blocks 0..6 (bytes 0..28671)
        // are used: the AG headers are not free.
        assert_eq!(map.extents[0], (0, 28_671));
    }

    #[test]
    fn an_external_log_makes_the_map_incomplete() {
        let mut geometry = geometry();
        geometry.log_start = 0;
        let map = used_map(&geometry, &free_space()).expect("used map");
        assert!(!map.complete);
        assert_eq!(map.extents, vec![(0, 131072 * 4096 - 1)]);
    }

    #[test]
    fn a_realtime_device_makes_the_map_incomplete() {
        let mut geometry = geometry();
        geometry.realtime_blocks = 1024;
        let map = used_map(&geometry, &free_space()).expect("used map");
        assert!(!map.complete);
    }

    #[test]
    fn inconsistent_totals_are_rejected() {
        let text = FREESP.replace("total free blocks 114652", "total free blocks 1");
        let mut reader = BufReader::new(text.as_bytes());
        assert!(parse_freesp(&mut reader, &geometry()).is_err());
    }

    #[test]
    fn an_out_of_range_extent_is_rejected() {
        let text = FREESP.replace("       3       13    32755", "       9       13    32755");
        let mut reader = BufReader::new(text.as_bytes());
        assert!(parse_freesp(&mut reader, &geometry()).is_err());
    }

    #[test]
    fn a_missing_geometry_field_is_rejected() {
        let text: String = SB
            .lines()
            .filter(|line| !line.starts_with("dblocks"))
            .collect::<Vec<_>>()
            .join("\n");
        let mut reader = BufReader::new(text.as_bytes());
        assert!(parse_geometry(&mut reader).is_err());
    }
}
