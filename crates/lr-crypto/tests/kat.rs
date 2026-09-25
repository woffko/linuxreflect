//! Known-answer tests for every `lr-crypto` primitive (spec §K S3).
//!
//! All expected values come from the generated `vectors` module, which is
//! produced by `tools/kats/generate.py` from independent implementations:
//! the reference Argon2 CLI, argon2-cffi, python3-cryptography and the
//! official BLAKE3 test vectors. Re-running the generator must reproduce this
//! file byte for byte.

mod vectors;

use lr_crypto::aead::{AeadKind, open, seal};
use lr_crypto::hash::{content_hash, unkeyed_hash};
use lr_crypto::kdf::{KdfParams, derive_kek};
use lr_crypto::keys::{ChainKey, dedup_key, file_keys};
use lr_crypto::nonce::NonceSeq;
use lr_crypto::page::{StreamId, open_page, seal_page};

use vectors::{AEAD_VECTORS, ARGON2ID_VECTORS, BLAKE3_KEY_HEX, BLAKE3_VECTORS, HKDF_VECTORS};

fn decode(hex: &str) -> Vec<u8> {
    hex::decode(hex).expect("vector hex must be valid")
}

fn decode_key(hex: &str) -> [u8; 32] {
    decode(hex).try_into().expect("32-byte key")
}

fn blake3_input(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

#[test]
fn argon2id_matches_the_reference_implementation() {
    assert!(!ARGON2ID_VECTORS.is_empty());
    for vector in ARGON2ID_VECTORS {
        let params = KdfParams::new(vector.m_cost_kib, vector.t_cost, vector.p_cost);
        let salt: [u8; 16] = vector.salt.try_into().expect("16-byte salt");
        let kek = derive_kek(vector.passphrase, &salt, params)
            .unwrap_or_else(|e| panic!("argon2 {}: {e}", vector.name));
        assert_eq!(
            hex::encode(kek.as_bytes()),
            vector.tag_hex,
            "argon2id vector '{}' must match the reference implementation",
            vector.name
        );
    }
}

#[test]
fn argon2id_production_vector_uses_the_spec_defaults() {
    let production = ARGON2ID_VECTORS
        .iter()
        .find(|v| v.name == "production")
        .expect("generated production vector");
    assert_eq!(production.m_cost_kib, 256 * 1024);
    assert_eq!(production.t_cost, 3);
    assert_eq!(production.p_cost, 4);
}

#[test]
fn aead_matches_the_reference_implementation() {
    let mut checked = 0;
    for vector in AEAD_VECTORS {
        let kind = match vector.cipher {
            "AES-256-GCM" => AeadKind::Aes256Gcm,
            "ChaCha20-Poly1305" => AeadKind::ChaCha20Poly1305,
            other => panic!("unexpected cipher {other}"),
        };
        let key = decode_key(vector.key_hex);
        let nonce: [u8; 12] = decode(vector.nonce_hex).try_into().expect("nonce");
        let aad = decode(vector.aad_hex);
        let plaintext = decode(vector.plaintext_hex);
        let expected_ct = decode(vector.ciphertext_hex);
        let expected_tag: [u8; 16] = decode(vector.tag_hex).try_into().expect("tag");

        let (ciphertext, tag) =
            seal(kind, &key, &nonce, &aad, &plaintext).expect("seal must succeed");
        assert_eq!(
            ciphertext, expected_ct,
            "{}/{} ciphertext must match",
            vector.cipher, vector.name
        );
        assert_eq!(
            tag, expected_tag,
            "{}/{} tag must match",
            vector.cipher, vector.name
        );

        let opened = open(kind, &key, &nonce, &aad, &ciphertext, &tag).expect("open must succeed");
        assert_eq!(opened, plaintext);
        // A different AAD must fail, proving the AAD is really authenticated.
        assert!(open(kind, &key, &nonce, b"wrong", &ciphertext, &tag).is_err());
        checked += 1;
    }
    assert_eq!(checked, 6, "two ciphers times three AAD shapes");
}

#[test]
fn hkdf_matches_rfc5869_and_this_projects_uses() {
    for vector in HKDF_VECTORS {
        let ikm = decode(vector.ikm_hex);
        let salt = decode(vector.salt_hex);
        let info = decode(vector.info_hex);
        let okm = match vector.name {
            "rfc5869-a1" | "rfc5869-a3" => {
                // A 22-byte IKM that is not a chain key: this is the raw
                // RFC 5869 vector, so it exercises the bare construction.
                lr_crypto::keys::hkdf_sha256(&ikm, &salt, &info, vector.okm_len).expect("hkdf")
            }
            "file-keys" | "file-keys-other-image" => {
                let chain_key = ChainKey::from_bytes(decode_key(vector.ikm_hex));
                let keys = file_keys(&chain_key, &id_from(&salt)).expect("file keys");
                let mut okm = Vec::with_capacity(64);
                okm.extend_from_slice(keys.data_key.as_slice());
                okm.extend_from_slice(keys.meta_key.as_slice());
                okm
            }
            "dedup-key" => {
                let chain_key = ChainKey::from_bytes(decode_key(vector.ikm_hex));
                dedup_key(&chain_key, &id_from(&salt))
                    .expect("dedup key")
                    .to_vec()
            }
            other => panic!("unexpected hkdf vector {other}"),
        };
        assert_eq!(
            hex::encode(&okm),
            vector.okm_hex,
            "hkdf vector {}",
            vector.name
        );
        assert_eq!(okm.len(), vector.okm_len);
    }
}

fn id_from(bytes: &[u8]) -> lr_core::Id {
    let array: [u8; 16] = bytes.try_into().expect("16-byte id");
    lr_core::Id::from_bytes(array)
}

#[test]
fn blake3_matches_the_official_vectors() {
    let key = decode_key(BLAKE3_KEY_HEX);
    assert_eq!(BLAKE3_VECTORS.len(), 4);
    for vector in BLAKE3_VECTORS {
        let input = blake3_input(vector.input_len);
        assert_eq!(
            hex::encode(unkeyed_hash(&input)),
            vector.unkeyed_hex,
            "unkeyed BLAKE3, input length {}",
            vector.input_len
        );
        assert_eq!(
            hex::encode(content_hash(&key, &input)),
            vector.keyed_hex,
            "keyed BLAKE3, input length {}",
            vector.input_len
        );
    }
}

#[test]
fn page_codec_round_trips_through_the_kats_material() {
    // Cross-check the page codec against an AEAD vector with the page AAD.
    let page_vector = AEAD_VECTORS
        .iter()
        .find(|v| v.name == "page" && v.cipher == "AES-256-GCM")
        .expect("page vector");
    let meta_key = decode_key(page_vector.key_hex);
    let plaintext = decode(page_vector.plaintext_hex);

    let mut seq = NonceSeq::new();
    let mut record = Vec::new();
    seal_page(
        AeadKind::Aes256Gcm,
        &meta_key,
        StreamId::Manifest,
        7,
        &plaintext,
        &mut seq,
        &mut record,
    )
    .expect("seal page");
    let opened = open_page(
        AeadKind::Aes256Gcm,
        &meta_key,
        StreamId::Manifest,
        7,
        &record,
    )
    .expect("open");
    assert_eq!(opened, plaintext);
}
