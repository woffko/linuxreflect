//! Retention acceptance (spec §J.3, §K S14).
//!
//! The criterion is exact: retention keeps precisely `keep_chains` complete
//! chains, never deletes a chain member individually, and never touches the
//! newest complete chain. The tests build real chains through the engine, then
//! check the surviving files on disk.

use std::path::{Path, PathBuf};

use lr_engine::backup::{BackupRequest, MemberType};
use lr_engine::backup_block_full;
use lr_engine::keys::Encryption;
use lr_engine::retention::{RetentionOptions, apply, may_extend_chain};
use lr_store::{Destination, SetHandle};

/// A sparse file is a valid block source for the offline provider.
fn source_file(dir: &Path, name: &str, size: u64) -> PathBuf {
    let path = dir.join(name);
    let file = std::fs::File::create(&path).expect("create");
    file.set_len(size).expect("size");
    path
}

fn request(source: &Path, dest: &Path, set: &str, encryption: Encryption) -> BackupRequest {
    let mut request = BackupRequest::new(source, dest, set, encryption).expect("request");
    request.compression = lr_engine::backup::Compression::Zstd { level: 1 };
    request
}

fn open_dest(dest: &Path, set: &str) -> (std::sync::Arc<dyn Destination>, SetHandle) {
    let options = lr_store::DestinationOptions {
        set_name: set.to_owned(),
        ..lr_store::DestinationOptions::default()
    };
    let destination = lr_store::open(&dest.display().to_string(), &options).expect("destination");
    let handle = destination
        .open_set(&lr_core::SetId::ZERO)
        .expect("set handle");
    (destination, handle)
}

/// One full chain with `incrementals` incremental members, changing the source
/// between members so every incremental stores something.
fn build_chain(source: &Path, dest: &Path, set: &str, incrementals: u32, seed: u8) {
    let mut full = request(source, dest, set, Encryption::NoEncrypt);
    full.member_type = MemberType::Full;
    let report = backup_block_full(&full).expect("full");
    let mut parent = report.image_uuid.to_string();
    for index in 0..incrementals {
        // A different byte pattern per member makes each one a real change.
        let mut bytes = std::fs::read(source).expect("read source");
        bytes[0] = seed.wrapping_add(index as u8).wrapping_add(1);
        std::fs::write(source, &bytes).expect("write source");
        let mut incremental = request(source, dest, set, Encryption::NoEncrypt);
        incremental.member_type = MemberType::Incremental;
        incremental.parent = Some(parent.clone());
        let report = backup_block_full(&incremental).expect("incremental");
        parent = report.image_uuid.to_string();
    }
}

fn image_files(dest: &Path, set: &str) -> Vec<String> {
    let (destination, handle) = open_dest(dest, set);
    let mut files = destination
        .list(&handle)
        .expect("list")
        .into_iter()
        .filter(|name| name.ends_with(".lrimg"))
        .collect::<Vec<_>>();
    files.sort();
    files
}

#[test]
fn retention_keeps_exactly_keep_chains_and_deletes_whole_chains() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = source_file(dir.path(), "source.img", 8 * 1024 * 1024);
    let dest = dir.path().join("backups");
    let set = "retention";

    // Three separate chains; the middle one gets an incremental so a whole
    // chain (two files) has to disappear as a unit.
    build_chain(&source, &dest, set, 0, 1);
    std::thread::sleep(std::time::Duration::from_millis(1100));
    build_chain(&source, &dest, set, 1, 2);
    std::thread::sleep(std::time::Duration::from_millis(1100));
    build_chain(&source, &dest, set, 0, 3);

    let before = image_files(&dest, set);
    assert_eq!(
        before.len(),
        4,
        "3 chains, one with an extra member: {before:?}"
    );

    // A dry run reports the same decision but touches nothing.
    let (destination, handle) = open_dest(&dest, set);
    let dry = apply(
        &*destination,
        &handle,
        set,
        &RetentionOptions {
            keep_chains: 1,
            dry_run: true,
            ..RetentionOptions::default()
        },
    )
    .expect("dry run");
    assert!(dry.dry_run);
    assert_eq!(dry.deleted.len(), 2, "two chains beyond keep_chains=1");
    assert_eq!(
        image_files(&dest, set).len(),
        4,
        "a dry run deletes nothing"
    );
    drop(destination);

    let (destination, handle) = open_dest(&dest, set);
    let report = apply(
        &*destination,
        &handle,
        set,
        &RetentionOptions {
            keep_chains: 1,
            ..RetentionOptions::default()
        },
    )
    .expect("retention");
    assert_eq!(report.kept.len(), 1);
    assert_eq!(report.deleted.len(), 2);
    assert!(report.freed_bytes() > 0);

    let after = image_files(&dest, set);
    assert!(
        after.len() < before.len(),
        "retention removed files: {after:?}"
    );
    // The surviving file must be a member of the newest chain, and every file
    // of the deleted chains must be gone.
    for deleted in &report.deleted {
        for file in &deleted.files {
            assert!(!after.contains(file), "{} should have been deleted", file);
        }
    }
    // The kept chain is complete on disk.
    let reloaded = lr_engine::catalog::load(&*destination, &handle, set, 0).expect("reload");
    let catalog = reloaded.catalog;
    assert_eq!(catalog.chains.len(), 1, "{catalog:?}");
    assert!(catalog.chains[0].is_complete());
    assert_eq!(catalog.chains[0].members.len(), 1);
}

#[test]
fn retention_removes_an_incomplete_chain_but_keeps_the_newest_complete_one() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = source_file(dir.path(), "source.img", 8 * 1024 * 1024);
    let dest = dir.path().join("backups");
    let set = "incomplete";

    // The older chain gets incrementals; deleting its *full* leaves members
    // behind, so the chain is unrestorable and must go as a whole.
    build_chain(&source, &dest, set, 2, 1);
    std::thread::sleep(std::time::Duration::from_millis(1100));
    build_chain(&source, &dest, set, 0, 2);

    let (destination, handle) = open_dest(&dest, set);
    let loaded = lr_engine::catalog::load(&*destination, &handle, set, 0).expect("catalog");
    let mut chains = loaded.catalog.chains.clone();
    chains.sort_by_key(|chain| chain.created_unix);
    let oldest = chains.first().expect("oldest chain");
    assert_eq!(oldest.members.len(), 3, "the older chain has incrementals");
    let victim = oldest
        .members
        .iter()
        .find(|member| member.seq_in_chain == 0)
        .expect("full")
        .file_name
        .clone();
    destination.delete(&handle, &victim).expect("delete full");
    drop(destination);

    let (destination, handle) = open_dest(&dest, set);
    let report = apply(
        &*destination,
        &handle,
        set,
        &RetentionOptions {
            keep_chains: 1,
            ..RetentionOptions::default()
        },
    )
    .expect("retention");
    assert_eq!(report.kept.len(), 1, "the newest complete chain stays");
    let deleted_reasons = report
        .deleted
        .iter()
        .map(|chain| chain.reason.clone())
        .collect::<Vec<_>>();
    assert!(
        deleted_reasons.iter().any(|reason| reason == "incomplete"),
        "{deleted_reasons:?}"
    );

    let (destination, handle) = open_dest(&dest, set);
    let reloaded = lr_engine::catalog::load(&*destination, &handle, set, 0).expect("reload");
    assert!(
        reloaded
            .catalog
            .chains
            .iter()
            .all(|chain| chain.is_complete()),
        "{:?}",
        reloaded.catalog.chains
    );
}

#[test]
fn a_chain_is_only_extended_below_max_incrementals() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = source_file(dir.path(), "source.img", 4 * 1024 * 1024);
    let dest = dir.path().join("backups");
    let set = "split";
    build_chain(&source, &dest, set, 2, 5);

    let (destination, handle) = open_dest(&dest, set);
    let loaded = lr_engine::catalog::load(&*destination, &handle, set, 0).expect("catalog");
    let chain = loaded.catalog.chains.first().expect("chain");
    assert_eq!(chain.members.len(), 3);
    assert!(!may_extend_chain(Some(chain), Some(2)));
    assert!(may_extend_chain(Some(chain), Some(3)));
    assert!(
        may_extend_chain(Some(chain), None),
        "no limit means no limit"
    );
    assert!(
        may_extend_chain(Some(chain), Some(0)),
        "zero means no limit"
    );
    assert!(
        !may_extend_chain(None, Some(2)),
        "a missing chain cannot be extended"
    );
}

/// The deletion unit is the whole chain: `DeletedChain::files` always holds
/// every member the catalog knew, which the first test asserts by checking that
/// no deleted file survives. This test pins the *rule* so a future change that
/// starts deleting members has to change it deliberately.
#[test]
fn retention_never_deletes_a_member_individually() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = source_file(dir.path(), "source.img", 4 * 1024 * 1024);
    let dest = dir.path().join("backups");
    let set = "whole-chain";
    build_chain(&source, &dest, set, 2, 4);

    let (destination, handle) = open_dest(&dest, set);
    let report = apply(
        &*destination,
        &handle,
        set,
        &RetentionOptions {
            keep_chains: 0,
            ..RetentionOptions::default()
        },
    )
    .expect("retention");
    // keep_chains=0 still keeps the newest complete chain, so nothing may go.
    assert_eq!(report.deleted.len(), 0, "{report:?}");
    assert_eq!(image_files(&dest, set).len(), 3);
    drop(destination);

    // Chains are ordered by time, so the second one needs a later timestamp
    // than the first (as in the test above) for "keep the newest" to be
    // unambiguous.
    std::thread::sleep(std::time::Duration::from_millis(1100));

    // A chain that is deleted loses *every* member, never a subset.
    let (destination, _handle) = open_dest(&dest, set);
    build_chain(&source, &dest, set, 1, 6);
    drop(destination);
    let (destination, handle) = open_dest(&dest, set);
    let report = apply(
        &*destination,
        &handle,
        set,
        &RetentionOptions {
            keep_chains: 1,
            ..RetentionOptions::default()
        },
    )
    .expect("retention");
    assert_eq!(report.deleted.len(), 1, "{report:?}");
    let deleted = &report.deleted[0];
    assert_eq!(
        deleted.files.len(),
        3,
        "the whole chain is one unit: {deleted:?}"
    );
    for file in &deleted.files {
        assert!(
            !image_files(&dest, set).contains(file),
            "{file} survived a chain deletion"
        );
    }
}
