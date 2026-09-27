//! The validated restore plan (remediation plan block 2.3).
//!
//! What a restore would write is checked from the manifests before a token is
//! issued and before any target is touched, and `verify` uses the same checks,
//! so an image that verifies can be restored and one that cannot be restored
//! is refused up front.

use lr_core::{Error, Result};
use lr_format::{ChunkState, Superblock};

/// The merged state of a block chain, counted without reading payloads.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BlockSummary {
    /// Chunks whose payload is stored in some member.
    pub stored: u64,
    /// Chunks recorded as zeros.
    pub zero: u64,
    /// Chunks the filesystem did not use.
    pub unused: u64,
    /// Chunks the source could not read (`--on-bad-sector record`).
    pub bad: u64,
    /// Byte offset of the first unreadable chunk.
    pub first_bad: Option<u64>,
}

/// Walk a block chain's merged manifest without reading payloads. The walk
/// validates the chain links, the geometry, every entry's range and the
/// complete consumption of every manifest.
///
/// # Errors
/// Returns [`Error::Corrupt`] for a malformed chain or manifest.
pub(crate) fn block_chain(
    members: Vec<crate::chain::OpenMember>,
    superblock: &Superblock,
) -> Result<BlockSummary> {
    let chunk_size = u64::from(superblock.chunk_size);
    let mut walk = crate::chain::ChainWalk::new(members)?;
    if walk.chunk_size() != superblock.chunk_size
        || walk.chunk_count() != superblock.source_size_bytes.div_ceil(chunk_size)
    {
        return Err(Error::corrupt(
            "the chain's chunk geometry does not match the image superblock",
        ));
    }
    let mut summary = BlockSummary::default();
    walk.walk(|index, state, _access| {
        match state {
            ChunkState::Stored { .. } => summary.stored += 1,
            ChunkState::Zero => summary.zero += 1,
            ChunkState::Unused => summary.unused += 1,
            ChunkState::BadSector => {
                summary.bad += 1;
                summary.first_bad.get_or_insert(index * chunk_size);
            }
        }
        Ok(())
    })?;
    Ok(summary)
}

/// The message for an image that records unreadable source chunks (R26).
#[must_use]
pub fn bad_sector_message(bad: u64, first: Option<u64>) -> String {
    format!(
        "the image records {bad} chunk(s) its source could not read (bad sectors{}); those \
         regions were never backed up, so the image cannot be restored completely",
        first.map_or_else(String::new, |offset| format!(
            ", the first at byte {offset}"
        ))
    )
}

/// Refuse a restore of an image with recorded bad sectors, before any
/// target write (R26).
///
/// # Errors
/// Returns [`Error::Unsupported`] naming the count and the first offset.
pub(crate) fn refuse_bad_sectors(summary: &BlockSummary) -> Result<()> {
    if summary.bad == 0 {
        return Ok(());
    }
    Err(Error::unsupported(format!(
        "{}; it is refused before the target is touched",
        bad_sector_message(summary.bad, summary.first_bad)
    )))
}
