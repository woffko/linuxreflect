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
    /// Verify every payload of the chains to keep before deleting anything;
    /// a chain that fails does not count as a backup (R20).
    pub verify_first: bool,
    /// How to unlock encrypted chains for `verify_first`.
    pub encryption: crate::keys::Encryption,
}

impl Default for RetentionOptions {
    fn default() -> Self {
        Self {
            keep_chains: 2,
            dry_run: false,
            break_stale_lock: false,
            set_lock_ttl_secs: None,
            verify_first: false,
            encryption: crate::keys::Encryption::NoEncrypt,
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
    let lock =
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

    // A complete chain counts as a backup only when every member is sound:
    // its footer and layout parse, so a newer image whose tail is missing
    // never displaces a restorable chain. A damaged chain is neither counted
    // nor deleted (R20).
    let mut usable: Vec<ChainRecord> = Vec::new();
    for chain in &complete {
        match damaged_member(destination, set, chain) {
            None => usable.push(chain.clone()),
            Some(problem) => warnings.push(format!(
                "chain {} is damaged ({problem}); it does not count as a backup and is left in \
                 place",
                chain.chain_id
            )),
        }
    }

    let keep_count = options.keep_chains.max(1);
    if options.verify_first {
        verify_newest(
            destination,
            set,
            &mut usable,
            keep_count,
            options,
            &mut loaded.catalog,
            &mut warnings,
        );
    }
    let mut kept_chains: Vec<ChainRecord> = usable.iter().take(keep_count).cloned().collect();
    // The newest chain known to be restorable is never given up for newer
    // chains that were not verified (R20).
    if !kept_chains.iter().any(is_verified)
        && let Some(verified) = usable
            .iter()
            .skip(keep_count)
            .find(|chain| is_verified(chain))
    {
        warnings.push(format!(
            "chain {} is kept as well: it is the newest verified chain, and no chain within \
             keep_chains has been verified (run verify --chain, or retention --verify-first)",
            verified.chain_id
        ));
        kept_chains.push(verified.clone());
    }
    let kept: Vec<String> = kept_chains
        .iter()
        .map(|chain| chain.chain_id.to_string())
        .collect();
    let newest_kept_created = usable.first().map_or(0, |chain| chain.created_unix);

    let mut doomed: Vec<(ChainRecord, &'static str)> = Vec::new();
    for chain in &usable {
        if !kept.contains(&chain.chain_id.to_string()) {
            doomed.push((chain.clone(), "beyond keep_chains"));
        }
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
                // A holder that lost its lease deletes nothing (R21).
                lock.verify()?;
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
        lock.verify()?;
        crate::catalog::write_catalog(destination, set, &loaded.catalog)?;
    }

    Ok(RetentionReport {
        set: set_name.to_owned(),
        kept,
        deleted,
        dry_run: options.dry_run,
        complete_chains: usable.len() as u64,
        warnings,
    })
}

/// `true` when every member of the chain was verified.
fn is_verified(chain: &ChainRecord) -> bool {
    !chain.members.is_empty()
        && chain
            .members
            .iter()
            .all(|member| member.verified_unix.is_some())
}

/// The first member of `chain` whose footer or layout does not parse.
fn damaged_member(
    destination: &dyn Destination,
    set: &SetHandle,
    chain: &ChainRecord,
) -> Option<String> {
    chain.members.iter().find_map(|member| {
        destination
            .open_ro(set, &member.file_name)
            .and_then(lr_format::ImageReader::open)
            .err()
            .map(|error| format!("{}: {error}", member.file_name))
    })
}

/// Verify the newest usable chains, every payload of every member, until
/// `keep_count` of them pass; a chain that fails is dropped from `usable`,
/// one that passes is marked verified in the catalog (R20).
#[allow(clippy::too_many_arguments)]
fn verify_newest(
    destination: &dyn Destination,
    set: &SetHandle,
    usable: &mut Vec<ChainRecord>,
    keep_count: usize,
    options: &RetentionOptions,
    catalog: &mut lr_core::catalog::Catalog,
    warnings: &mut Vec<String>,
) {
    let mut passed = 0usize;
    let mut index = 0usize;
    while index < usable.len() && passed < keep_count {
        let chain = &usable[index];
        let Some(newest) = chain.latest_member() else {
            index += 1;
            continue;
        };
        let request = crate::verify::VerifyRequest {
            image: newest.file_name.clone(),
            encryption: options.encryption.clone(),
            chain: true,
            destination_options: lr_store::DestinationOptions::default(),
            context: crate::progress::EngineContext::silent(),
        };
        match crate::verify::verify_in_set(destination, set, &newest.file_name, &request) {
            Ok(_) => {
                let files = chain
                    .members
                    .iter()
                    .map(|member| member.file_name.clone())
                    .collect();
                crate::verify::mark_verified(catalog, &files, now_unix());
                usable[index] = catalog
                    .chain(chain.chain_id)
                    .cloned()
                    .unwrap_or_else(|| usable[index].clone());
                passed += 1;
                index += 1;
            }
            Err(error) => {
                warnings.push(format!(
                    "chain {} failed verification ({error}); it does not count as a backup and \
                     is left in place",
                    chain.chain_id
                ));
                usable.remove(index);
            }
        }
    }
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
