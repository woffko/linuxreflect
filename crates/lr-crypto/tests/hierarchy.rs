//! End-to-end key-hierarchy tests (spec §K S3, §G.4).
//!
//! These follow the real write/restore flow rather than a single primitive:
//! a chain key is generated with the full, wrapped under the KEK, and later
//! recovered on a "restore" that only has the passphrase, the salt and the
//! wrapped key from the superblock.

use lr_core::Id;
use lr_crypto::aead::{AeadKind, open, seal};
use lr_crypto::kdf::{KdfParams, derive_kek};
use lr_crypto::keys::{ChainKey, dedup_key, file_keys, unwrap_chain_key, wrap_chain_key};
use lr_crypto::nonce::NonceSeq;
use lr_crypto::page::{StreamId, open_page, seal_page};

const PASSPHRASE: &[u8] = b"correct horse battery staple";
const SALT: [u8; 16] = *b"linuxreflect-v1!";
/// Cheap parameters: the production cost is covered by the KAT vector.
const CHEAP: KdfParams = KdfParams::new(32, 3, 4);

fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

#[test]
fn key_types_zeroize_on_drop() {
    assert_zeroize_on_drop::<lr_crypto::kdf::Kek>();
    assert_zeroize_on_drop::<ChainKey>();
    assert_zeroize_on_drop::<lr_crypto::keys::FileKeys>();
}

/// What a superblock stores about the chain.
struct SuperblockKeyMaterial {
    salt: [u8; 16],
    params: KdfParams,
    wrap_nonce: [u8; 12],
    wrapped_key: [u8; 48],
}

#[test]
fn full_then_incremental_then_restore() {
    let chain_id = Id::generate().expect("chain id");
    let full_uuid = Id::generate().expect("image uuid");
    let incremental_uuid = Id::generate().expect("image uuid");

    // --- backup side: one KDF run for the whole chain -----------------------
    let kek = derive_kek(PASSPHRASE, &SALT, CHEAP).expect("kek");
    let chain_key = ChainKey::generate().expect("chain key");
    let (wrap_nonce, wrapped_key) = wrap_chain_key(&kek, &chain_key, &chain_id).expect("wrap");
    let superblock = SuperblockKeyMaterial {
        salt: SALT,
        params: CHEAP,
        wrap_nonce,
        wrapped_key,
    };

    let full_keys = file_keys(&chain_key, &full_uuid).expect("full keys");
    let incremental_keys = file_keys(&chain_key, &incremental_uuid).expect("incremental keys");
    // Different images, different keys; same chain, same dedup key so that
    // positional scan-and-diff can compare hashes across members.
    assert_ne!(
        full_keys.data_key.as_slice(),
        incremental_keys.data_key.as_slice()
    );
    assert_eq!(
        dedup_key(&chain_key, &chain_id).expect("dedup"),
        dedup_key(&chain_key, &chain_id).expect("dedup"),
    );

    // A chunk sealed with the incremental image's data key.
    let dedup = dedup_key(&chain_key, &chain_id).expect("dedup");
    let plaintext = b"1 MiB chunk of the incremental";
    let chunk_hash = lr_crypto::hash::content_hash(&dedup, plaintext);
    let mut ad = chunk_hash.to_vec();
    ad.push(1); // image kind: block
    let mut nonce_seq = NonceSeq::new();
    let nonce = nonce_seq.next_nonce().expect("nonce");
    let (ciphertext, tag) = seal(
        AeadKind::Aes256Gcm,
        &incremental_keys.data_key,
        &nonce,
        &ad,
        plaintext,
    )
    .expect("seal chunk");

    // A manifest page sealed with the metadata key.
    let mut meta_seq = NonceSeq::new();
    let mut page = Vec::new();
    seal_page(
        AeadKind::Aes256Gcm,
        &incremental_keys.meta_key,
        StreamId::Manifest,
        0,
        plaintext,
        &mut meta_seq,
        &mut page,
    )
    .expect("seal page");

    // --- restore side: only the passphrase and the superblock ---------------
    let restored_kek =
        derive_kek(PASSPHRASE, &superblock.salt, superblock.params).expect("kek again");
    let restored_chain_key = unwrap_chain_key(
        &restored_kek,
        &chain_id,
        &superblock.wrap_nonce,
        &superblock.wrapped_key,
    )
    .expect("unwrap");
    let restored_keys = file_keys(&restored_chain_key, &incremental_uuid).expect("restore keys");

    let opened = open(
        AeadKind::Aes256Gcm,
        &restored_keys.data_key,
        &nonce,
        &ad,
        &ciphertext,
        &tag,
    )
    .expect("chunk must decrypt after restore");
    assert_eq!(opened, plaintext);
    assert_eq!(
        lr_crypto::hash::content_hash(&dedup, &opened),
        chunk_hash,
        "the manifest hash must still match after restore"
    );

    let page_plaintext = open_page(
        AeadKind::Aes256Gcm,
        &restored_keys.meta_key,
        StreamId::Manifest,
        0,
        &page,
    )
    .expect("page must decrypt after restore");
    assert_eq!(page_plaintext, plaintext);
}

#[test]
fn wrong_passphrase_never_yields_a_usable_key() {
    let chain_id = Id::generate().expect("chain id");
    let kek = derive_kek(PASSPHRASE, &SALT, CHEAP).expect("kek");
    let chain_key = ChainKey::generate().expect("chain key");
    let (wrap_nonce, wrapped_key) = wrap_chain_key(&kek, &chain_key, &chain_id).expect("wrap");

    let wrong = derive_kek(b"Correct horse battery staple", &SALT, CHEAP).expect("kek");
    let error = unwrap_chain_key(&wrong, &chain_id, &wrap_nonce, &wrapped_key)
        .expect_err("a wrong passphrase must fail at unwrap");
    assert!(
        matches!(error, lr_core::Error::Aead),
        "expected Aead error, got {error:?}"
    );
}

#[test]
fn a_different_salt_yields_a_different_chain_key() {
    let chain_id = Id::generate().expect("chain id");
    let chain_key = ChainKey::generate().expect("chain key");
    let kek = derive_kek(PASSPHRASE, &SALT, CHEAP).expect("kek");
    let (wrap_nonce, wrapped_key) = wrap_chain_key(&kek, &chain_key, &chain_id).expect("wrap");

    let other_salt = *b"fedcba9876543210";
    let other_kek = derive_kek(PASSPHRASE, &other_salt, CHEAP).expect("kek");
    assert!(
        unwrap_chain_key(&other_kek, &chain_id, &wrap_nonce, &wrapped_key).is_err(),
        "the salt is part of the KEK"
    );
}

#[test]
fn incremental_of_another_chain_cannot_be_read() {
    // Two chains of the same set must not share keys even with one passphrase.
    let kek = derive_kek(PASSPHRASE, &SALT, CHEAP).expect("kek");
    let chain_a = Id::generate().expect("chain id");
    let chain_b = Id::generate().expect("chain id");
    let key_a = ChainKey::generate().expect("chain key");
    let key_b = ChainKey::generate().expect("chain key");
    let (nonce_a, wrapped_a) = wrap_chain_key(&kek, &key_a, &chain_a).expect("wrap");
    let (nonce_b, wrapped_b) = wrap_chain_key(&kek, &key_b, &chain_b).expect("wrap");

    let (recovered_b_nonce, recovered_b_wrapped) = (nonce_b, wrapped_b);
    assert!(unwrap_chain_key(&kek, &chain_a, &recovered_b_nonce, &recovered_b_wrapped).is_err());
    let recovered_a = unwrap_chain_key(&kek, &chain_a, &nonce_a, &wrapped_a).expect("unwrap a");
    let recovered_b = unwrap_chain_key(&kek, &chain_b, &nonce_b, &wrapped_b).expect("unwrap b");
    assert_ne!(recovered_a.as_bytes(), recovered_b.as_bytes());
}
