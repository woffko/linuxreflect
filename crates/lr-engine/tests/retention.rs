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

/// A source with real data, so every member stores payloads.
fn data_source(dir: &Path) -> PathBuf {
    let path = dir.join("source.img");
    let bytes: Vec<u8> = (0..8 * 1024 * 1024u32)
        .map(|index| (index.wrapping_mul(2_654_435_761) >> 24) as u8)
        .collect();
    std::fs::write(&path, bytes).expect("source");
    path
}

/// The newest image file of the set.
fn newest_image(dest: &Path, set: &str) -> PathBuf {
    let files = image_files(dest, set);
    let (_, handle) = open_dest(dest, set);
    let newest = files
        .iter()
        .max_by_key(|name| {
            std::fs::metadata(Path::new(&handle.path).join(name))
                .and_then(|metadata| metadata.modified())
                .expect("mtime")
        })
        .expect("an image");
    Path::new(&handle.path).join(newest)
}

/// A newer chain whose image has an intact superblock but no footer is not a
/// usable backup, so it never displaces the older chain (R20).
#[test]
fn retention_keeps_the_last_usable_chain_over_a_truncated_newer_one() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = data_source(dir.path());
    let dest = dir.path().join("backups");
    let set = "truncated";
    build_chain(&source, &dest, set, 0, 1);
    let older = image_files(&dest, set);
    std::thread::sleep(std::time::Duration::from_millis(1100));
    build_chain(&source, &dest, set, 0, 2);
    let damaged = newest_image(&dest, set);
    std::fs::File::options()
        .write(true)
        .open(&damaged)
        .expect("open")
        .set_len(64 * 1024)
        .expect("truncate after the superblock");

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
    let remaining = image_files(&dest, set);
    for file in &older {
        assert!(
            remaining.contains(file),
            "the only usable chain was deleted: {report:?}"
        );
    }
}

/// Verify a set's image with `--chain` semantics and record the result.
fn verify_and_record(image: &Path) {
    let request = lr_engine::verify::VerifyRequest {
        image: image.display().to_string(),
        encryption: Encryption::NoEncrypt,
        chain: true,
        destination_options: lr_store::DestinationOptions::default(),
        context: lr_engine::progress::EngineContext::silent(),
    };
    let report = lr_engine::verify::verify_image(&request).expect("verify");
    let note = lr_engine::verify::record_verification(&request, &report).expect("record");
    assert!(note.is_none(), "{note:?}");
}

/// A verified older chain is never given up for a newer chain that was not
/// verified, and verify-before-retention finds a newer chain's corrupted
/// payload before anything is deleted (R20).
#[test]
fn retention_never_gives_up_the_last_verified_chain_for_an_unverified_one() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = data_source(dir.path());
    let dest = dir.path().join("backups");
    let set = "verified";
    build_chain(&source, &dest, set, 0, 1);
    let older = image_files(&dest, set);
    verify_and_record(&newest_image(&dest, set));
    std::thread::sleep(std::time::Duration::from_millis(1100));
    build_chain(&source, &dest, set, 0, 2);
    // A corrupted payload behind an intact superblock and footer.
    let damaged = newest_image(&dest, set);
    let mut bytes = std::fs::read(&damaged).expect("image");
    bytes[256 * 1024] ^= 0xFF;
    std::fs::write(&damaged, bytes).expect("corrupt");

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
    assert!(report.deleted.is_empty(), "{report:?}");
    assert_eq!(report.kept.len(), 2, "{report:?}");
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("newest verified chain")),
        "{:?}",
        report.warnings
    );

    let checked = apply(
        &*destination,
        &handle,
        set,
        &RetentionOptions {
            keep_chains: 1,
            verify_first: true,
            ..RetentionOptions::default()
        },
    )
    .expect("retention with verification");
    assert!(
        checked
            .warnings
            .iter()
            .any(|warning| warning.contains("failed verification")),
        "{:?}",
        checked.warnings
    );
    let remaining = image_files(&dest, set);
    for file in &older {
        assert!(remaining.contains(file), "the verified chain was deleted");
    }
    assert!(damaged.exists(), "a failed chain is left in place");
}

/// A valid full image whose source had an unreadable sector, not a corrupt
/// image. Integrity verification succeeds with a bad-sector warning.
fn bad_sector_image(dest: &Path, set: &str, template: &Path) -> PathBuf {
    use lr_core::{ChainId, Id, ImageId};
    use lr_crypto::keys::{ChainKey, file_keys};
    use lr_format::{BlockEntry, BlockManifestHeader, ImageReader, ImageWriter, StreamId};

    let reader = ImageReader::open(std::fs::File::open(template).expect("template"))
        .expect("template reader");
    let mut sb = reader.superblock().clone();
    sb.chain_id = ChainId::new(Id::from_bytes([0xB1; 16]));
    sb.image_uuid = ImageId::new(Id::from_bytes([0xB2; 16]));
    sb.parent_uuid = ImageId::ZERO;
    sb.seq_in_chain = 0;
    sb.created_unix += 1;
    sb.flags = 0;
    sb.source_size_bytes = u64::from(sb.chunk_size);
    let chain = dest.join(set).join(sb.chain_id.to_string());
    std::fs::create_dir(&chain).expect("chain directory");
    let path = chain.join(format!("000-full-{}.lrimg", sb.image_uuid));
    let keys = file_keys(
        &ChainKey::from_bytes(lr_crypto::mac::fixed_public_mac_key()),
        sb.image_uuid.inner(),
    )
    .expect("public image keys");
    let kind = sb.aead_kind().expect("aead");
    let mut writer = ImageWriter::create(std::fs::File::create(&path).expect("image"), &sb, None)
        .expect("writer");
    {
        let mut manifest = writer.page_stream(StreamId::Manifest, kind, *keys.meta_key);
        BlockManifestHeader {
            chunk_size: sb.chunk_size,
            chunk_count: 1,
            entry_count: 1,
            used_extent_count: 1,
            used_bytes: sb.source_size_bytes,
            fs_type: String::new(),
            fs_uuid: String::new(),
            label: String::new(),
        }
        .write(&mut manifest, false)
        .expect("manifest header");
        BlockEntry::bad_sector(0, sb.chunk_size)
            .write(&mut manifest)
            .expect("record unreadable source");
        manifest.finish().expect("manifest");
    }
    {
        let mut extras = writer.page_stream(StreamId::Extras, kind, *keys.meta_key);
        lr_format::extras::write_chain_members(
            &mut extras,
            &[lr_format::ChainMember {
                index: 0,
                image_uuid: sb.image_uuid,
            }],
        )
        .expect("chain members");
        extras.finish().expect("extras");
    }
    writer.finish(&keys.meta_key, None, kind).expect("finish");
    path
}

fn verify_request(image: &Path) -> lr_engine::verify::VerifyRequest {
    lr_engine::verify::VerifyRequest {
        image: image.display().to_string(),
        encryption: Encryption::NoEncrypt,
        chain: true,
        destination_options: lr_store::DestinationOptions::default(),
        context: lr_engine::progress::EngineContext::silent(),
    }
}

#[test]
fn retention_does_not_replace_a_healthy_chain_with_recorded_bad_sectors() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = source_file(dir.path(), "source.img", 1024 * 1024);
    let dest = dir.path().join("backups");
    let set = "recorded-bad";
    build_chain(&source, &dest, set, 0, 1);
    let healthy = newest_image(&dest, set);
    let bad = bad_sector_image(&dest, set, &healthy);
    let report = lr_engine::verify::verify_image(&verify_request(&bad)).expect("valid image");
    assert_eq!(report.recorded_bad_chunks, 1);

    let (destination, handle) = open_dest(&dest, set);
    let retained = apply(
        &*destination,
        &handle,
        set,
        &RetentionOptions {
            keep_chains: 1,
            verify_first: true,
            ..RetentionOptions::default()
        },
    )
    .expect("retention");
    assert!(retained.deleted.is_empty(), "{retained:?}");
    assert!(healthy.exists(), "the healthy recovery chain was deleted");
    assert!(bad.exists(), "a degraded backup is left for the operator");
}

#[test]
fn recorded_bad_sectors_do_not_create_a_verified_catalog_record() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = source_file(dir.path(), "source.img", 1024 * 1024);
    let dest = dir.path().join("backups");
    let set = "bad-evidence";
    build_chain(&source, &dest, set, 0, 1);
    let bad = bad_sector_image(&dest, set, &newest_image(&dest, set));
    let request = verify_request(&bad);
    let report = lr_engine::verify::verify_image(&request).expect("valid image");
    let note = lr_engine::verify::record_verification(&request, &report).expect("record");
    assert!(
        note.is_some(),
        "incomplete recovery must not count as verified"
    );
    let (destination, handle) = open_dest(&dest, set);
    let loaded = lr_engine::catalog::load(&*destination, &handle, set, 0).expect("catalog");
    assert!(loaded.catalog.chains.iter().all(|chain| {
        chain
            .members
            .iter()
            .all(|member| member.verified_unix.is_none())
    }));
}

#[test]
fn retention_refuses_deletion_without_a_fresh_healthy_replacement() {
    for cache in ["missing", "corrupt", "stale"] {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = data_source(dir.path());
        let dest = dir.path().join("backups");
        let set = "fresh-evidence";
        build_chain(&source, &dest, set, 0, 1);
        std::thread::sleep(std::time::Duration::from_millis(1100));
        build_chain(&source, &dest, set, 0, 2);
        let newest = newest_image(&dest, set);
        verify_and_record(&newest);
        let mut bytes = std::fs::read(&newest).expect("image");
        bytes[256 * 1024] ^= 0xFF;
        std::fs::write(&newest, bytes).expect("same-size corruption");
        let catalog = dest.join(set).join("catalog.json");
        match cache {
            "missing" => std::fs::remove_file(&catalog).expect("remove test catalog"),
            "corrupt" => std::fs::write(&catalog, b"not json").expect("corrupt test catalog"),
            _ => {}
        }
        let before = image_files(&dest, set);
        let (destination, handle) = open_dest(&dest, set);
        for dry_run in [true, false] {
            let error = apply(
                &*destination,
                &handle,
                set,
                &RetentionOptions {
                    keep_chains: 1,
                    dry_run,
                    ..RetentionOptions::default()
                },
            )
            .expect_err("unchecked/corrupt replacement must refuse deletion");
            assert!(error.to_string().contains("retention refused"), "{error}");
            assert_eq!(image_files(&dest, set), before, "{cache}, dry={dry_run}");
        }
    }
}

#[test]
fn retention_requires_the_key_for_an_encrypted_replacement() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = source_file(dir.path(), "source.img", 1024 * 1024);
    let dest = dir.path().join("backups");
    let set = "encrypted-replacement";
    build_chain(&source, &dest, set, 0, 1);
    let old = newest_image(&dest, set);
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let encryption = Encryption::Passphrase(lr_engine::keystore::Passphrase::new(
        b"test-only retention fixture".to_vec(),
    ));
    let encrypted = backup_block_full(&request(&source, &dest, set, encryption.clone()))
        .expect("encrypted backup");
    let (destination, handle) = open_dest(&dest, set);
    let error = apply(
        &*destination,
        &handle,
        set,
        &RetentionOptions {
            keep_chains: 1,
            ..RetentionOptions::default()
        },
    )
    .expect_err("missing keys must not authorize deletion");
    assert!(error.to_string().contains("retention refused"), "{error}");
    assert!(old.exists() && encrypted.image_path.exists());

    let report = apply(
        &*destination,
        &handle,
        set,
        &RetentionOptions {
            keep_chains: 1,
            encryption,
            ..RetentionOptions::default()
        },
    )
    .expect("verified replacement authorizes retention");
    assert_eq!(report.deleted.len(), 1);
    assert!(!old.exists());
    assert!(encrypted.image_path.exists());
}

#[test]
fn an_incremental_uses_its_parents_set_identity_not_another_chains() {
    use lr_core::{ChainId, Id, SetId};

    let dir = tempfile::tempdir().expect("tempdir");
    let source = source_file(dir.path(), "source.img", 1024 * 1024);
    let dest = dir.path().join("backups");
    let set = "parent-identity";
    let mut older = request(&source, &dest, set, Encryption::NoEncrypt);
    older.chain_id = ChainId::new(Id::from_bytes([1; 16]));
    older.set_id = SetId::new(Id::from_bytes([11; 16]));
    backup_block_full(&older).expect("older chain");
    let mut parent = request(&source, &dest, set, Encryption::NoEncrypt);
    parent.chain_id = ChainId::new(Id::from_bytes([2; 16]));
    parent.set_id = SetId::new(Id::from_bytes([22; 16]));
    let full = backup_block_full(&parent).expect("parent chain");
    let mut incremental = request(&source, &dest, set, Encryption::NoEncrypt);
    incremental.member_type = MemberType::Incremental;
    incremental.parent = Some(full.image_uuid.to_string());
    let child = backup_block_full(&incremental).expect("incremental");
    let reader = lr_format::ImageReader::open(
        std::fs::File::open(&child.image_path).expect("incremental image"),
    )
    .expect("image reader");
    assert_eq!(reader.superblock().set_id, parent.set_id);
    lr_engine::verify::verify_image(&verify_request(&child.image_path))
        .expect("the newly created recovery chain must verify");
}
