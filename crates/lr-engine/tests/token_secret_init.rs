//! Explicit daemon key initialization without process-environment mutation.
//! This integration binary has its own process-global token key.

use std::os::unix::fs::PermissionsExt;

use lr_engine::restore::{init_token_secret, token_secret};

#[test]
fn explicit_key_is_validated_and_cannot_be_replaced() {
    let dir = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .expect("private directory");
    let unsafe_path = dir.path().join("unsafe.key");
    std::fs::write(&unsafe_path, [0_u8; 32]).expect("fixture");
    std::fs::set_permissions(&unsafe_path, std::fs::Permissions::from_mode(0o644))
        .expect("fixture permissions");
    assert!(init_token_secret(&unsafe_path).is_err());

    let path = dir.path().join("token.key");
    init_token_secret(&path).expect("initialize after rejected path");
    let stored = std::fs::read(&path).expect("persisted key");
    assert!(token_secret().as_slice() == stored.as_slice());
    assert_eq!(
        std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    let other = dir.path().join("other.key");
    assert!(init_token_secret(&other).is_err());
    assert!(
        !other.exists(),
        "reinitialization must not create another key"
    );
    assert!(token_secret().as_slice() == stored.as_slice());
    std::thread::scope(|scope| {
        for _ in 0..8 {
            let stored = &stored;
            scope.spawn(move || assert!(token_secret().as_slice() == stored.as_slice()));
        }
    });
}
