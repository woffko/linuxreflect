//! Looking at backups does not change the destination (A9): preparing a
//! restore, verifying or listing an image in a set that does not exist fails
//! with "no such set" and creates nothing.

use lr_engine::keys::Encryption;
use lr_engine::restore::{PrepareRequest, prepare_restore};
use lr_engine::verify::{VerifyRequest, verify_image};

fn entries(dir: &std::path::Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .expect("destination")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect()
}

#[test]
fn read_paths_create_no_set_directory() {
    let dir = tempfile::tempdir().expect("tempdir");
    let dest = dir.path().join("dest");
    std::fs::create_dir_all(&dest).expect("destination");
    let image = dest.join("typo-set/chain/000-full-x.lrimg");
    let target = dir.path().join("target.img");
    std::fs::write(&target, vec![0u8; 1024 * 1024]).expect("target");

    let error = prepare_restore(&PrepareRequest::from_path(
        &image,
        &target,
        Encryption::NoEncrypt,
    ))
    .expect_err("there is no such set");
    assert!(error.to_string().contains("no backup set"), "{error}");
    assert!(
        entries(&dest).is_empty(),
        "prepare created {:?}",
        entries(&dest)
    );

    let error = verify_image(&VerifyRequest {
        image: image.display().to_string(),
        encryption: Encryption::NoEncrypt,
        chain: true,
        destination_options: lr_store::DestinationOptions::default(),
        context: lr_engine::progress::EngineContext::silent(),
    })
    .expect_err("there is no such set");
    assert!(error.to_string().contains("no backup set"), "{error}");
    assert!(
        entries(&dest).is_empty(),
        "verify created {:?}",
        entries(&dest)
    );
}
