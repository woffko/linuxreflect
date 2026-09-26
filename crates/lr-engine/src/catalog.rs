//! Set catalog: a plaintext cache validated against member superblocks
//! (spec §D.3, Slice S9).
//!
//! `catalog.json` is never authoritative. Every read scans the set's `.lrimg`
//! files, decodes their superblocks and rebuilds the chain/member records from
//! them; the cached file is used only when it agrees with that scan. A member
//! whose superblock fails its unkeyed integrity check is reported and skipped,
//! and `linuxreflect catalog rebuild` writes the validated result back.

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};

use lr_core::catalog::{Catalog, ChainRecord, MemberRecord};
use lr_core::{Error, ImageId, Result, SetId};
use lr_format::{SB_SIZE, Superblock};
use lr_store::{Destination, SetHandle};

/// Name of the catalog file inside a set.
pub const CATALOG_FILE: &str = "catalog.json";

/// One image found in the set.
#[derive(Debug, Clone)]
pub struct ScannedMember {
    /// File name relative to the set, e.g. `<chain_id>/000-full-<uuid>.lrimg`.
    pub file_name: String,
    /// Decoded superblock.
    pub superblock: Superblock,
    /// File size in bytes.
    pub size_bytes: u64,
}

/// The result of scanning a set.
#[derive(Debug, Clone, Default)]
pub struct Scan {
    /// Members in file-name order.
    pub members: Vec<ScannedMember>,
    /// Non-fatal problems found while scanning.
    pub warnings: Vec<String>,
}

/// A catalog plus how it was obtained.
#[derive(Debug, Clone)]
pub struct Loaded {
    /// The validated catalog.
    pub catalog: Catalog,
    /// Differences between the cache and the superblocks.
    pub warnings: Vec<String>,
    /// `true` when the cache was missing or disagreed with the scan.
    pub rebuilt: bool,
}

/// Scan a set for `*.lrimg` files and read their superblocks.
///
/// # Errors
/// Propagates destination I/O errors. A member with a damaged superblock is
/// reported in [`Scan::warnings`] and skipped, not returned as an error.
pub fn scan_set(destination: &dyn Destination, set: &SetHandle) -> Result<Scan> {
    let mut scan = Scan::default();
    for name in destination.list(set)? {
        if !is_image(&name) {
            continue;
        }
        let mut reader = destination.open_ro(set, &name)?;
        let mut bytes = [0u8; SB_SIZE];
        if let Err(error) = reader.read_exact(&mut bytes) {
            scan.warnings
                .push(format!("{name}: cannot read the superblock ({error})"));
            continue;
        }
        let superblock = match Superblock::decode(&bytes) {
            Ok(superblock) => superblock,
            Err(error) => {
                scan.warnings
                    .push(format!("{name}: damaged superblock ({error})"));
                continue;
            }
        };
        // The MAC needs a key; without one only the unkeyed hash inside
        // `decode` was checked, which is the documented limitation (D-040).
        if !superblock.is_encrypted() && superblock.verify_mac(&bytes, None).is_err() {
            scan.warnings
                .push(format!("{name}: superblock MAC does not verify"));
            continue;
        }
        let size_bytes = reader.seek(SeekFrom::End(0)).map_err(Error::Io)?;
        scan.members.push(ScannedMember {
            file_name: name,
            superblock,
            size_bytes,
        });
    }
    Ok(scan)
}

fn is_image(name: &str) -> bool {
    name.ends_with(".lrimg") && !name.ends_with(".tmp")
}

/// The kind of a member, derived from its sequence, kind and flags.
///
/// Defined once in [`crate::chain`] so the catalog and the chain reader can
/// never disagree.
pub use crate::chain::member_kind;

/// Build a catalog from a scan.
///
/// `source_label` is empty for scanned members: it is not part of a superblock
/// and so cannot be recovered without the image keys. A live catalog keeps the
/// label the backup wrote, which is why [`same_records`] ignores it.
#[must_use]
pub fn build_catalog(set_name: &str, now: u64, scan: &Scan) -> Catalog {
    let mut chains: BTreeMap<lr_core::ChainId, Vec<&ScannedMember>> = BTreeMap::new();
    for member in &scan.members {
        chains
            .entry(member.superblock.chain_id)
            .or_default()
            .push(member);
    }

    let set_id = scan
        .members
        .first()
        .map_or(SetId::ZERO, |member| member.superblock.set_id);
    let mut catalog = Catalog::new(set_id, set_name, now);

    for (chain_id, mut members) in chains {
        members.sort_by_key(|member| member.superblock.seq_in_chain);
        let created_unix = members
            .iter()
            .map(|member| member.superblock.created_unix)
            .min()
            .unwrap_or(0);
        let records = members
            .iter()
            .map(|member| MemberRecord {
                image_uuid: member.superblock.image_uuid,
                parent_uuid: member.superblock.parent_uuid,
                kind: member_kind(&member.superblock),
                seq_in_chain: member.superblock.seq_in_chain,
                image_kind: member.superblock.image_kind,
                consistency: member.superblock.consistency,
                created_unix: member.superblock.created_unix,
                source_label: String::new(),
                size_bytes: member.size_bytes,
                file_name: member.file_name.clone(),
            })
            .collect();
        catalog.upsert_chain(ChainRecord {
            chain_id,
            created_unix,
            source_label: String::new(),
            members: records,
        });
    }

    catalog
}

/// Structural problems that make a chain unusable, as warnings.
///
/// The catalog still lists what is present; the engine refuses to *extend* a
/// chain whose links are broken.
#[must_use]
pub fn chain_warnings(catalog: &Catalog) -> Vec<String> {
    let mut warnings = Vec::new();
    for chain in &catalog.chains {
        for pair in chain.members.windows(2) {
            let (previous, next) = (&pair[0], &pair[1]);
            if previous.seq_in_chain == next.seq_in_chain {
                warnings.push(format!(
                    "chain {}: two members at seq {}",
                    chain.chain_id, next.seq_in_chain
                ));
            }
            if next.parent_uuid != previous.image_uuid {
                warnings.push(format!(
                    "chain {}: member {} does not link to {}",
                    chain.chain_id, next.image_uuid, previous.image_uuid
                ));
            }
        }
    }
    warnings
}

/// `true` when two catalogs describe the same chains and members.
///
/// `updated_unix` and `source_label` are cache-only metadata and are ignored.
#[must_use]
pub fn same_records(left: &Catalog, right: &Catalog) -> bool {
    if left.version != right.version
        || left.set_id != right.set_id
        || left.chains.len() != right.chains.len()
    {
        return false;
    }
    for chain in &left.chains {
        let Some(other) = right.chain(chain.chain_id) else {
            return false;
        };
        if chain.created_unix != other.created_unix || chain.members.len() != other.members.len() {
            return false;
        }
        for member in &chain.members {
            let Some(mate) = other.member(member.image_uuid) else {
                return false;
            };
            let same = member.parent_uuid == mate.parent_uuid
                && member.kind == mate.kind
                && member.seq_in_chain == mate.seq_in_chain
                && member.image_kind == mate.image_kind
                && member.consistency == mate.consistency
                && member.created_unix == mate.created_unix
                && member.size_bytes == mate.size_bytes
                && member.file_name == mate.file_name;
            if !same {
                return false;
            }
        }
    }
    true
}

/// Read the cached `catalog.json`, if it exists and parses.
///
/// # Errors
/// Propagates destination I/O errors; an unparseable cache is reported as
/// `Ok(None)` with a warning by [`load`].
pub fn read_cached(destination: &dyn Destination, set: &SetHandle) -> Result<Option<Catalog>> {
    let bytes = match lr_store::read_to_vec(destination, set, CATALOG_FILE) {
        Ok(bytes) => bytes,
        Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    Ok(serde_json::from_slice(&bytes).ok())
}

/// Write the catalog atomically (`create_tmp` + `finalize`).
///
/// # Errors
/// Propagates serialization and destination errors.
pub fn write_catalog(
    destination: &dyn Destination,
    set: &SetHandle,
    catalog: &Catalog,
) -> Result<()> {
    use std::io::Write;
    let bytes = serde_json::to_vec_pretty(catalog)
        .map_err(|error| Error::corrupt(format!("catalog: {error}")))?;
    let mut file = destination.create_tmp(set, CATALOG_FILE)?;
    file.write_all(&bytes).map_err(Error::Io)?;
    file.sync_all().map_err(Error::Io)?;
    drop(file);
    destination.finalize(set, CATALOG_FILE, CATALOG_FILE)
}

/// Load the catalog, validating it against the members' superblocks.
///
/// # Errors
/// Propagates destination I/O errors.
pub fn load(
    destination: &dyn Destination,
    set: &SetHandle,
    set_name: &str,
    now: u64,
) -> Result<Loaded> {
    let scan = scan_set(destination, set)?;
    let built = build_catalog(set_name, now, &scan);
    let structural = chain_warnings(&built);
    let cached = match read_cached(destination, set) {
        Ok(cached) => cached,
        Err(error) => {
            return Ok(Loaded {
                catalog: built,
                warnings: vec![format!("catalog.json could not be read ({error})")],
                rebuilt: true,
            });
        }
    };
    let mut warnings = scan.warnings;
    warnings.extend(structural);
    match cached {
        Some(cached) if same_records(&cached, &built) => Ok(Loaded {
            catalog: cached,
            warnings,
            rebuilt: false,
        }),
        Some(_) => {
            warnings.push(
                "catalog.json disagrees with the member superblocks; using the scanned catalog"
                    .to_owned(),
            );
            Ok(Loaded {
                catalog: built,
                warnings,
                rebuilt: true,
            })
        }
        None => Ok(Loaded {
            catalog: built,
            warnings,
            rebuilt: true,
        }),
    }
}

/// The member file names of a chain, ordered by sequence.
///
/// # Errors
/// Returns [`Error::Corrupt`] when the chain is missing from the catalog.
pub fn chain_files(catalog: &Catalog, chain_id: lr_core::ChainId) -> Result<Vec<String>> {
    let chain = catalog
        .chain(chain_id)
        .ok_or_else(|| Error::corrupt(format!("chain {chain_id} is not in the catalog")))?;
    let mut members = chain.members.clone();
    members.sort_by_key(|member| member.seq_in_chain);
    Ok(members.into_iter().map(|member| member.file_name).collect())
}

/// The latest member of the newest complete chain (for `--parent latest`).
///
/// # Errors
/// Returns [`Error::Unsupported`] when two complete chains share the newest
/// creation second. The catalog records whole seconds only, so which one is
/// newer cannot be known, and a guess could extend the wrong chain (D-116).
pub fn latest_member(catalog: &Catalog) -> Result<Option<&MemberRecord>> {
    let complete: Vec<&ChainRecord> = catalog
        .chains
        .iter()
        .filter(|chain| chain.is_complete())
        .collect();
    let Some(newest) = complete.iter().map(|chain| chain.created_unix).max() else {
        return Ok(None);
    };
    let tied: Vec<&&ChainRecord> = complete
        .iter()
        .filter(|chain| chain.created_unix == newest)
        .collect();
    if let [only] = tied.as_slice() {
        return Ok(only.latest_member());
    }
    let ids: Vec<String> = tied
        .iter()
        .map(|chain| chain.chain_id.to_string())
        .collect();
    Err(Error::unsupported(format!(
        "--parent latest is ambiguous: chains {} were started in the same second; \
         name the parent image with --parent <uuid>",
        ids.join(" and ")
    )))
}

/// Resolve a `--parent` value against a catalog.
///
/// # Errors
/// Returns [`Error::Unsupported`] when the parent is unknown, is not the newest
/// member of its chain, or its chain is incomplete.
pub fn resolve_parent(catalog: &Catalog, parent: &str) -> Result<MemberRecord> {
    if parent == "latest" {
        return latest_member(catalog)?.cloned().ok_or_else(|| {
            Error::unsupported("--parent latest: the set has no complete chain yet")
        });
    }
    let wanted: ImageId = parent.parse().map_err(|_| {
        Error::unsupported(format!("--parent {parent} is not a latest|<uuid> value"))
    })?;
    for chain in &catalog.chains {
        if let Some(member) = chain.member(wanted) {
            if !chain.is_complete() {
                return Err(Error::unsupported(format!(
                    "--parent {parent}: chain {} is incomplete",
                    chain.chain_id
                )));
            }
            if let Some(latest) = chain.latest_member()
                && latest.image_uuid != wanted
            {
                return Err(Error::unsupported(format!(
                    "--parent {parent}: the chain already has a newer member ({}); use --parent latest",
                    latest.image_uuid
                )));
            }
            return Ok(member.clone());
        }
    }
    Err(Error::unsupported(format!(
        "--parent {parent}: no such member in this set"
    )))
}

#[cfg(test)]
mod tests {
    use super::{
        build_catalog, member_kind, read_cached, resolve_parent, same_records, scan_set,
        write_catalog,
    };
    use crate::keys::{Encryption, new_chain_keys};
    use lr_core::catalog::MemberKind;
    use lr_core::{ChainId, Consistency, Id, ImageId, ImageKind, SetId};
    use lr_format::{FORMAT_MAJOR, MIN_READER, Superblock, flags};
    use lr_store::{Destination, LocalDestination};

    fn superblock(chain: ChainId, uuid: u8, seq: u32, delta: bool, created: u64) -> Superblock {
        Superblock {
            format_major: FORMAT_MAJOR,
            min_reader: MIN_READER,
            flags: if delta { flags::DELTA_MANIFEST } else { 0 },
            image_kind: ImageKind::Block,
            consistency: Consistency::Offline,
            image_uuid: ImageId::new(Id::from_bytes([uuid; 16])),
            chain_id: chain,
            set_id: SetId::new(Id::from_bytes([0x77; 16])),
            parent_uuid: if seq == 0 {
                ImageId::ZERO
            } else {
                ImageId::new(Id::from_bytes([uuid - 1; 16]))
            },
            seq_in_chain: seq,
            created_unix: created,
            source_size_bytes: 1 << 20,
            logical_block_size: 512,
            chunk_size: 1024 * 1024,
            kdf_id: 0,
            aead_id: lr_crypto::AEAD_ID_AES_256_GCM,
            kdf_salt: [0u8; 16],
            argon2_m_cost_kib: 0,
            argon2_t_cost: 0,
            argon2_p_cost: 0,
            wrap_nonce: [0u8; 12],
            wrapped_chain_key: [0u8; 48],
        }
    }

    /// Write a minimal but valid image whose superblock describes a member.
    fn write_image(
        destination: &LocalDestination,
        set: &lr_store::SetHandle,
        name: &str,
        superblock: &Superblock,
    ) {
        use std::io::Write;
        // Encrypted superblocks need their metadata key; unencrypted ones use
        // the fixed public key, so `None` is correct for them.
        let key = superblock.is_encrypted().then_some([0x5Au8; 32]);
        let bytes = superblock.encode(key.as_ref()).expect("encode");
        let mut file = destination.create_tmp(set, name).expect("tmp");
        file.write_all(&bytes).expect("write");
        file.sync_all().expect("sync");
        drop(file);
        destination.finalize(set, name, name).expect("finalize");
    }

    fn set(destination: &LocalDestination) -> lr_store::SetHandle {
        destination
            .open_set(&SetId::new(Id::from_bytes([0x77; 16])))
            .expect("open set")
    }

    #[test]
    fn a_scanned_set_rebuilds_the_chain() {
        let dir = tempfile::tempdir().expect("tempdir");
        let destination = LocalDestination::new(dir.path(), "set");
        let set = set(&destination);
        let chain = ChainId::new(Id::from_bytes([0xAA; 16]));
        write_image(
            &destination,
            &set,
            "c/000-full-a.lrimg",
            &superblock(chain, 1, 0, false, 10),
        );
        write_image(
            &destination,
            &set,
            "c/001-incr-b.lrimg",
            &superblock(chain, 2, 1, true, 20),
        );

        let scan = scan_set(&destination, &set).expect("scan");
        assert!(scan.warnings.is_empty(), "{:?}", scan.warnings);
        let catalog = build_catalog("set", 99, &scan);
        assert_eq!(catalog.chains.len(), 1);
        let built = &catalog.chains[0];
        assert_eq!(built.members.len(), 2);
        assert!(built.is_complete());
        assert_eq!(built.members[0].kind, MemberKind::Full);
        assert_eq!(built.members[1].kind, MemberKind::Incremental);
        assert_eq!(built.created_unix, 10);
        assert_eq!(built.members[1].parent_uuid, built.members[0].image_uuid);
    }

    #[test]
    fn incremental_and_differential_kinds_follow_the_flag() {
        let chain = ChainId::new(Id::from_bytes([1; 16]));
        assert_eq!(
            member_kind(&superblock(chain, 1, 0, false, 1)),
            MemberKind::Full
        );
        assert_eq!(
            member_kind(&superblock(chain, 2, 1, true, 1)),
            MemberKind::Incremental
        );
        assert_eq!(
            member_kind(&superblock(chain, 3, 2, false, 1)),
            MemberKind::Differential
        );
    }

    #[test]
    fn the_cached_catalog_is_kept_when_it_agrees() {
        let dir = tempfile::tempdir().expect("tempdir");
        let destination = LocalDestination::new(dir.path(), "set");
        let set = set(&destination);
        let chain = ChainId::new(Id::from_bytes([0xBB; 16]));
        write_image(
            &destination,
            &set,
            "c/000-full-a.lrimg",
            &superblock(chain, 1, 0, false, 10),
        );

        let loaded = super::load(&destination, &set, "set", 100).expect("load");
        assert!(loaded.rebuilt, "no cache yet");
        let mut live = loaded.catalog.clone();
        live.chains[0].source_label = "label".to_owned();
        live.chains[0].members[0].source_label = "/dev/loop0".to_owned();
        write_catalog(&destination, &set, &live).expect("write catalog");

        let again = super::load(&destination, &set, "set", 200).expect("load");
        assert!(!again.rebuilt, "the cache agrees, so it is reused");
        assert_eq!(again.catalog, live, "the cached labels survive");

        // A new member invalidates the cache.
        write_image(
            &destination,
            &set,
            "c/001-incr-b.lrimg",
            &superblock(chain, 2, 1, true, 20),
        );
        let third = super::load(&destination, &set, "set", 300).expect("load");
        assert!(third.rebuilt);
        assert_eq!(third.catalog.chains[0].members.len(), 2);
        assert!(
            third.warnings.iter().any(|w| w.contains("disagrees")),
            "{:?}",
            third.warnings
        );
    }

    #[test]
    fn a_damaged_superblock_is_reported_and_skipped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let destination = LocalDestination::new(dir.path(), "set");
        let set = set(&destination);
        use std::io::Write;
        let mut file = destination
            .create_tmp(&set, "c/000-full-bad.lrimg")
            .expect("tmp");
        file.write_all(&[0u8; 4096]).expect("write");
        file.sync_all().expect("sync");
        drop(file);
        destination
            .finalize(&set, "c/000-full-bad.lrimg", "c/000-full-bad.lrimg")
            .expect("finalize");

        let scan = scan_set(&destination, &set).expect("scan");
        assert!(scan.members.is_empty());
        assert_eq!(scan.warnings.len(), 1);
        assert!(
            scan.warnings[0].contains("superblock"),
            "{:?}",
            scan.warnings
        );
    }

    #[test]
    fn parent_latest_picks_the_newest_complete_chain() {
        let dir = tempfile::tempdir().expect("tempdir");
        let destination = LocalDestination::new(dir.path(), "set");
        let set = set(&destination);
        let older = ChainId::new(Id::from_bytes([0x01; 16]));
        let newer = ChainId::new(Id::from_bytes([0x02; 16]));
        write_image(
            &destination,
            &set,
            "a/000-full.lrimg",
            &superblock(older, 1, 0, false, 10),
        );
        write_image(
            &destination,
            &set,
            "b/000-full.lrimg",
            &superblock(newer, 3, 0, false, 50),
        );
        write_image(
            &destination,
            &set,
            "b/001-incr.lrimg",
            &superblock(newer, 4, 1, true, 60),
        );

        let loaded = super::load(&destination, &set, "set", 1).expect("load");
        let latest = resolve_parent(&loaded.catalog, "latest").expect("latest");
        assert_eq!(latest.image_uuid, ImageId::new(Id::from_bytes([4; 16])));

        let by_uuid =
            resolve_parent(&loaded.catalog, &Id::from_bytes([4; 16]).to_string()).expect("by uuid");
        assert_eq!(by_uuid.seq_in_chain, 1);

        // An older member of a chain that has newer members is refused.
        let error = resolve_parent(&loaded.catalog, &Id::from_bytes([3; 16]).to_string())
            .expect_err("must refuse");
        assert!(error.to_string().contains("newer member"), "{error}");
    }

    #[test]
    fn parent_latest_refuses_chains_started_in_the_same_second() {
        let dir = tempfile::tempdir().expect("tempdir");
        let destination = LocalDestination::new(dir.path(), "set");
        let set = set(&destination);
        let first = ChainId::new(Id::from_bytes([0x01; 16]));
        let second = ChainId::new(Id::from_bytes([0x02; 16]));
        write_image(
            &destination,
            &set,
            "a/000-full.lrimg",
            &superblock(first, 1, 0, false, 10),
        );
        write_image(
            &destination,
            &set,
            "a/001-incr.lrimg",
            &superblock(first, 2, 1, true, 10),
        );
        write_image(
            &destination,
            &set,
            "b/000-full.lrimg",
            &superblock(second, 5, 0, false, 10),
        );
        let loaded = super::load(&destination, &set, "set", 1).expect("load");
        let error = resolve_parent(&loaded.catalog, "latest").expect_err("ambiguous");
        assert!(error.to_string().contains("ambiguous"), "{error}");
        // An explicit parent still works.
        let explicit = resolve_parent(&loaded.catalog, &Id::from_bytes([5; 16]).to_string())
            .expect("explicit parent");
        assert_eq!(explicit.seq_in_chain, 0);
    }

    #[test]
    fn same_records_ignores_cache_only_fields() {
        let dir = tempfile::tempdir().expect("tempdir");
        let destination = LocalDestination::new(dir.path(), "set");
        let set = set(&destination);
        let chain = ChainId::new(Id::from_bytes([0xCC; 16]));
        write_image(
            &destination,
            &set,
            "c/000-full.lrimg",
            &superblock(chain, 1, 0, false, 10),
        );
        let scan = scan_set(&destination, &set).expect("scan");
        let mut first = build_catalog("set", 1, &scan);
        let mut second = build_catalog("set", 2, &scan);
        second.chains[0].source_label = "x".to_owned();
        second.chains[0].members[0].source_label = "y".to_owned();
        assert!(same_records(&first, &second));
        first.chains[0].members[0].size_bytes += 1;
        assert!(!same_records(&first, &second));
    }

    #[test]
    fn an_empty_set_loads_an_empty_catalog() {
        let dir = tempfile::tempdir().expect("tempdir");
        let destination = LocalDestination::new(dir.path(), "set");
        let set = set(&destination);
        let loaded = super::load(&destination, &set, "set", 1).expect("load");
        assert!(loaded.catalog.chains.is_empty());
        assert!(loaded.rebuilt);
        assert_eq!(read_cached(&destination, &set).expect("cached"), None);
    }

    #[test]
    fn encrypted_members_are_scanned_without_a_passphrase() {
        // The scan must not need keys: the catalog's fields are plaintext.
        let dir = tempfile::tempdir().expect("tempdir");
        let destination = LocalDestination::new(dir.path(), "set");
        let set = set(&destination);
        let chain = ChainId::new(Id::from_bytes([0xDD; 16]));
        let new = new_chain_keys(
            &Encryption::Passphrase(crate::keystore::Passphrase::new(b"pw".to_vec())),
            &chain,
            &Id::from_bytes([1; 16]),
        )
        .expect("keys");
        let mut sb = superblock(chain, 1, 0, false, 10);
        sb.flags = flags::ENCRYPTED;
        sb.kdf_salt = new.kdf_salt;
        sb.wrap_nonce = new.wrap_nonce;
        sb.wrapped_chain_key = new.wrapped_chain_key;
        sb.argon2_m_cost_kib = new.params.m_cost_kib;
        sb.argon2_t_cost = new.params.t_cost;
        sb.argon2_p_cost = new.params.p_cost;
        sb.kdf_id = 1;
        write_image(&destination, &set, "c/000-full.lrimg", &sb);
        let _ = &new.keys.meta_key;

        let scan = scan_set(&destination, &set).expect("scan");
        assert_eq!(scan.members.len(), 1, "{:?}", scan.warnings);
        assert!(scan.members[0].superblock.is_encrypted());
    }
}
