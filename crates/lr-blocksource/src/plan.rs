//! Turning a used-block map into chunk-aligned read plans (spec §G.2).
//!
//! Block-mode chunks are fixed size and aligned to chunk boundaries, so a used
//! extent that starts mid-chunk makes the whole chunk used: the extent map is
//! rounded outward first (spec §G.2 "used extents are rounded outward to chunk
//! boundaries"), and then every chunk inside a region is read whole.

use lr_core::{Error, Result};
use lr_fsmap::ExtentMap;

/// One chunk to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkPlan {
    /// Chunk number in the image (`offset / chunk_size`).
    pub index: u64,
    /// Byte offset of the chunk on the source.
    pub offset: u64,
    /// Bytes to read; shorter than the chunk size only for the last chunk.
    pub len: u32,
}

/// Iterates the used chunks of a source in ascending order.
#[derive(Debug, Clone)]
pub struct UsedChunks {
    chunk_size: u64,
    device_size: u64,
    chunk_count: u64,
    regions: Vec<(u64, u64)>,
    region: usize,
    next_offset: u64,
}

impl UsedChunks {
    /// Build a plan from a used-block map.
    ///
    /// # Errors
    /// Returns [`Error::Unsupported`] for a zero chunk size.
    pub fn new(map: &ExtentMap, chunk_size: u64, device_size: u64) -> Result<Self> {
        if chunk_size == 0 {
            return Err(Error::unsupported("chunk size must not be zero"));
        }
        let regions = map.chunk_aligned(chunk_size, device_size);
        let chunk_count = device_size.div_ceil(chunk_size);
        Ok(Self {
            chunk_size,
            device_size,
            chunk_count,
            regions,
            region: 0,
            next_offset: 0,
        })
    }

    /// Total chunks of the source, used or not.
    #[must_use]
    pub const fn chunk_count(&self) -> u64 {
        self.chunk_count
    }

    /// Chunk-aligned regions that will be read.
    #[must_use]
    pub fn regions(&self) -> &[(u64, u64)] {
        &self.regions
    }

    /// Number of chunks this plan will produce.
    #[must_use]
    pub fn planned_chunks(&self) -> u64 {
        self.regions
            .iter()
            .map(|(start, end)| (end - start + 1).div_ceil(self.chunk_size))
            .sum()
    }

    /// Bytes this plan will read.
    #[must_use]
    pub fn planned_bytes(&self) -> u64 {
        self.regions
            .iter()
            .map(|(start, end)| end - start + 1)
            .sum()
    }

    /// The next chunk, or `None` when the plan is exhausted.
    pub fn next_chunk(&mut self) -> Option<ChunkPlan> {
        loop {
            let (start, end) = *self.regions.get(self.region)?;
            let offset = self.next_offset.max(start);
            if offset > end {
                self.region += 1;
                self.next_offset = 0;
                continue;
            }
            let available = end - offset + 1;
            let len = available.min(self.chunk_size);
            let len = len.min(self.device_size - offset);
            self.next_offset = offset + self.chunk_size;
            return Some(ChunkPlan {
                index: offset / self.chunk_size,
                offset,
                len: u32::try_from(len).unwrap_or(u32::MAX),
            });
        }
    }
}

/// `true` when every byte is zero; such chunks are recorded as zero, not stored.
#[must_use]
pub fn is_all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use super::{ChunkPlan, UsedChunks, is_all_zero};
    use lr_fsmap::ExtentMap;

    fn map(extents: Vec<(u64, u64)>) -> ExtentMap {
        ExtentMap {
            extents,
            complete: true,
        }
    }

    #[test]
    fn walks_a_single_region() {
        let chunk = 4096;
        let mut plan =
            UsedChunks::new(&map(vec![(0, 3 * chunk - 1)]), chunk, 10 * chunk).expect("plan");
        assert_eq!(plan.chunk_count(), 10);
        assert_eq!(plan.planned_bytes(), 3 * chunk);
        let chunks: Vec<ChunkPlan> = std::iter::from_fn(|| plan.next_chunk()).collect();
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].index, 0);
        assert_eq!(chunks[2].offset, 2 * chunk);
        assert_eq!(chunks[2].len, chunk as u32);
    }

    #[test]
    fn rounds_partial_chunks_outward() {
        let chunk = 4096;
        // Used bytes 100..5000 touch chunks 0 and 1.
        let mut plan = UsedChunks::new(&map(vec![(100, 5000)]), chunk, 4 * chunk).expect("plan");
        let chunks: Vec<ChunkPlan> = std::iter::from_fn(|| plan.next_chunk()).collect();
        assert_eq!(chunks.len(), 2);
        assert_eq!(
            chunks[0],
            ChunkPlan {
                index: 0,
                offset: 0,
                len: chunk as u32
            }
        );
        assert_eq!(
            chunks[1],
            ChunkPlan {
                index: 1,
                offset: chunk,
                len: chunk as u32
            }
        );
    }

    #[test]
    fn the_last_chunk_is_short() {
        let chunk = 4096;
        let device = 2 * chunk + 1000;
        let mut plan =
            UsedChunks::new(&map(vec![(device - 2000, device - 1)]), chunk, device).expect("plan");
        let chunks: Vec<ChunkPlan> = std::iter::from_fn(|| plan.next_chunk()).collect();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].index, 1);
        assert_eq!(chunks[1].index, 2);
        assert_eq!(
            chunks[1].len, 1000,
            "the final chunk stops at the device end"
        );
    }

    #[test]
    fn several_regions_are_walked_in_order() {
        let chunk = 4096;
        let mut plan = UsedChunks::new(
            &map(vec![(0, chunk - 1), (2 * chunk, 4 * chunk - 1)]),
            chunk,
            8 * chunk,
        )
        .expect("plan");
        let indexes: Vec<u64> = std::iter::from_fn(|| plan.next_chunk())
            .map(|plan| plan.index)
            .collect();
        assert_eq!(indexes, vec![0, 2, 3]);
    }

    #[test]
    fn an_empty_map_needs_no_reads() {
        let mut plan = UsedChunks::new(&map(Vec::new()), 4096, 1 << 20).expect("plan");
        assert!(plan.next_chunk().is_none());
        assert_eq!(plan.planned_bytes(), 0);
    }

    #[test]
    fn zero_detection() {
        assert!(is_all_zero(&[0, 0, 0]));
        assert!(is_all_zero(&[]));
        assert!(!is_all_zero(&[0, 1, 0]));
    }

    #[test]
    fn a_zero_chunk_size_is_refused() {
        assert!(UsedChunks::new(&map(vec![(0, 1)]), 0, 4096).is_err());
    }
}
