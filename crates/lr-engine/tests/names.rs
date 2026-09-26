//! Set names that would leave their directory are refused before any work
//! (R02, D-115).
//!
//! A set name is a directory at the destination and below a Btrfs source's
//! `.linuxreflect/`. The name `..` used to point the Btrfs snapshot cleanup
//! at the filesystem's top level; now every entry point refuses it before a
//! destination is opened or a snapshot is taken.

use lr_engine::backup::BackupRequest;
use lr_engine::backup_image;
use lr_engine::keys::Encryption;

const INVALID: [&str; 5] = ["..", ".", "a/b", "", "../escape"];

#[test]
fn a_backup_request_refuses_an_invalid_set_name() {
    let dir = tempfile::tempdir().expect("tempdir");
    for name in INVALID {
        let Err(error) = BackupRequest::new(
            dir.path().join("source.img"),
            dir.path().join("out"),
            name,
            Encryption::NoEncrypt,
        ) else {
            panic!("{name:?}: an invalid set name must be refused");
        };
        assert!(
            error.to_string().contains("invalid set name"),
            "{name:?}: {error}"
        );
    }
}

#[test]
fn a_set_name_changed_after_the_request_is_refused_before_anything_is_written() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("source.img");
    std::fs::write(&source, vec![0u8; 1024 * 1024]).expect("source");
    let dest = dir.path().join("out");
    std::fs::create_dir(&dest).expect("dest");
    // A sentinel next to the destination, where `..` would lead.
    let sentinel = dir.path().join("sentinel");
    std::fs::write(&sentinel, b"untouched").expect("sentinel");
    for name in INVALID {
        let mut request =
            BackupRequest::new(&source, &dest, "valid", Encryption::NoEncrypt).expect("request");
        name.clone_into(&mut request.set_name);
        let error = backup_image(&request).expect_err("an invalid set name must be refused");
        assert!(
            error.to_string().contains("invalid set name"),
            "{name:?}: {error}"
        );
    }
    assert_eq!(
        std::fs::read_dir(&dest).expect("dest").count(),
        0,
        "nothing is created at the destination"
    );
    assert_eq!(std::fs::read(&sentinel).expect("sentinel"), b"untouched");
}

#[test]
fn a_destination_refuses_an_invalid_set_name() {
    let dir = tempfile::tempdir().expect("tempdir");
    for name in INVALID.into_iter().filter(|name| !name.is_empty()) {
        let options = lr_store::DestinationOptions::new(name);
        let Err(error) = lr_store::open(&dir.path().display().to_string(), &options) else {
            panic!("{name:?}: an invalid set name must be refused");
        };
        assert!(
            error.to_string().contains("invalid set name"),
            "{name:?}: {error}"
        );
    }
    // The empty name only lists sets (D-106); it cannot open one.
    let destination = lr_store::open(
        &dir.path().display().to_string(),
        &lr_store::DestinationOptions::new(""),
    )
    .expect("an empty name opens the destination for listing");
    assert!(destination.open_set(&lr_core::SetId::ZERO).is_err());
}
