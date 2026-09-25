//! Chain-based retention (spec §J.3, §K S14).
//!
//! Retention is whole-chain or nothing: every incremental depends on all of its
//! ancestors, so deleting one member would silently destroy the chain. The
//! algorithm loads the *validated* catalog (rebuilt from the members'
//! superblocks), treats a chain as complete only when its full is present and
//! every member is there, keeps the newest `keep_chains` complete chains, and
//! deletes the rest oldest-first. Incomplete chains are leftovers of a failed
//! or interrupted run: they cannot be restored, so they are deleted too — but
//! never a chain that is newer than the newest complete one.

use lr_core::catalog::ChainRecord;
use lr_core::{Error, Result};
use lr_store::{Destination, SetHandle};

use crate::backup::now_unix;

/// What retention should do.
#[derive(Debug, Clone)]
pub struct RetentionOptions {
    /// Complete chains to keep; the newest complete chain is always kept.
    pub keep_chains: usize,
    /// Report what would happen without deleting anything.
    pub dry_run: bool,
    /// Break an expired set lock instead of failing.
    pub break_stale_lock: bool,
    /// Set-lock lease in seconds; the spec default is 300.
    pub set_lock_ttl_secs: Option<u64>,
}

impl Default for RetentionOptions {
    fn default() -> Self {
        Self {
            keep_chains: 2,
            dry_run: false,
            break_stale_lock: false,
            set_lock_ttl_secs: None,
        }
    }
}

/// One chain retention removed (or would remove).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DeletedChain {
    /// Chain identifier.
    pub chain_id: String,
    /// Member files that were deleted.
    pub files: Vec<String>,
    /// Bytes those members occupied.
    pub bytes: u64,
    /// Why the chain went away.
    pub reason: String,
}

/// What retention did.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RetentionReport {
    /// Set name.
    pub set: String,
    /// Chains that remain, newest first.
    pub kept: Vec<String>,
    /// Chains that were deleted (or would be, in a dry run).
    pub deleted: Vec<DeletedChain>,
    /// `true` when nothing was written.
    pub dry_run: bool,
    /// Complete chains that were found before the run.
    pub complete_chains: u64,
    /// Non-fatal notes.
    pub warnings: Vec<String>,
}

impl RetentionReport {
    /// Bytes the run freed (or would free).
    #[must_use]
    pub fn freed_bytes(&self) -> u64 {
        self.deleted.iter().map(|chain| chain.bytes).sum()
    }
}

/// Apply retention to one set (spec §J.3).
///
/// # Errors
/// Returns [`Error::Unsupported`] when the destination is unreachable, and
/// propagates catalog and deletion errors. The catalog is written only after
/// every file of a chain was deleted, so an interrupted run leaves a catalog
/// that still describes the surviving files.
pub fn apply(
    destination: &dyn Destination,
    set: &SetHandle,
    set_name: &str,
    options: &RetentionOptions,
) -> Result<RetentionReport> {
    let ttl = options
        .set_lock_ttl_secs
        .unwrap_or(crate::backup::SET_LOCK_TTL_SECS);
    let _lock =
        crate::backup::acquire_set_lock_for(destination, set, ttl, options.break_stale_lock)?;
    let now = now_unix();
    let mut loaded = crate::catalog::load(destination, set, set_name, now)?;
    for warning in &loaded.warnings {
        tracing::warn!(%warning, "retention: catalog");
    }

    // Newest complete chain first; ties break on the chain id so a run is
    // reproducible.
    let mut complete: Vec<ChainRecord> = loaded
        .catalog
        .chains
        .iter()
        .filter(|chain| chain.is_complete())
        .cloned()
        .collect();
    complete.sort_by(|left, right| {
        right
            .created_unix
            .cmp(&left.created_unix)
            .then_with(|| right.chain_id.to_string().cmp(&left.chain_id.to_string()))
    });
    let mut warnings = Vec::new();
    if complete.is_empty() {
        warnings.push("the set has no complete chain; nothing to keep or delete".to_owned());
    }
    if options.keep_chains == 0 {
        warnings.push(
            "keep_chains is 0; the newest complete chain is kept anyway (spec §J.3)".to_owned(),
        );
    }

    let keep_count = options.keep_chains.max(1);
    let kept: Vec<String> = complete
        .iter()
        .take(keep_count)
        .map(|chain| chain.chain_id.to_string())
        .collect();
    let newest_kept_created = complete.first().map_or(0, |chain| chain.created_unix);

    let mut doomed: Vec<(ChainRecord, &'static str)> = Vec::new();
    for chain in complete.iter().skip(keep_count) {
        doomed.push((chain.clone(), "beyond keep_chains"));
    }
    for chain in &loaded.catalog.chains {
        if chain.is_complete() {
            continue;
        }
        // An incomplete chain cannot be restored. A chain created *after* the
        // newest complete one is not touched: it may be the next chain in
        // progress (retention runs under the lock, but being conservative here
        // costs nothing and avoids racing a fresh full).
        if chain.created_unix > newest_kept_created {
            warnings.push(format!(
                "chain {} is incomplete and newer than the newest complete chain; leaving it",
                chain.chain_id
            ));
            continue;
        }
        doomed.push((chain.clone(), "incomplete"));
    }
    // Oldest first, so a partial run removes the least valuable data first.
    doomed.sort_by_key(|(chain, _)| chain.created_unix);

    let mut deleted = Vec::new();
    for (chain, reason) in doomed {
        let mut files = Vec::new();
        let mut bytes = 0u64;
        for member in &chain.members {
            files.push(member.file_name.clone());
            bytes += member.size_bytes;
        }
        if !options.dry_run {
            for file in &files {
                destination.delete(set, file)?;
            }
            loaded
                .catalog
                .chains
                .retain(|candidate| candidate.chain_id != chain.chain_id);
        }
        deleted.push(DeletedChain {
            chain_id: chain.chain_id.to_string(),
            files,
            bytes,
            reason: reason.to_owned(),
        });
    }

    if !options.dry_run {
        loaded.catalog.updated_unix = now_unix();
        crate::catalog::write_catalog(destination, set, &loaded.catalog)?;
    }

    Ok(RetentionReport {
        set: set_name.to_owned(),
        kept,
        deleted,
        dry_run: options.dry_run,
        complete_chains: complete.len() as u64,
        warnings,
    })
}

/// `true` when another member may be appended to the newest chain.
///
/// A run that would exceed `max_incrementals_per_chain` starts a new chain
/// (spec §J.3); `None` or `Some(0)` means "no limit".
#[must_use]
pub fn may_extend_chain(chain: Option<&ChainRecord>, max_incrementals: Option<u64>) -> bool {
    let Some(max) = max_incrementals.filter(|max| *max > 0) else {
        return true;
    };
    let Some(chain) = chain else {
        return false;
    };
    if !chain.is_complete() {
        return false;
    }
    let incrementals = chain
        .members
        .iter()
        .filter(|member| member.seq_in_chain > 0)
        .count();
    (incrementals as u64) < max
}

/// Validate a `keep_chains` value from a config file.
///
/// # Errors
/// Returns [`Error::Unsupported`] when the value is not positive.
pub fn validate_keep_chains(value: i64) -> Result<usize> {
    if value < 0 {
        return Err(Error::unsupported(format!(
            "keep_chains must not be negative (got {value})"
        )));
    }
    Ok(usize::try_from(value).unwrap_or(0))
}
