//! Cryptography for LinuxReflect: key hierarchy, AEAD and keyed hashing.
//!
//! Everything here follows spec §G.4 (key hierarchy and nonces) and §G.6
//! (metadata pages). The crate provides primitives only: it never decides
//! where ciphertext is stored, and it never sees a passphrase it does not
//! derive from immediately.
//!
//! Layer map:
//!
//! * [`kdf`] — Argon2id password stretching and its parameters.
//! * [`keys`] — the chain key, its wrapping under the KEK, and per-image keys.
//! * [`hash`] — keyed BLAKE3 content hashes used by manifests.
//! * [`mac`] — keyed/unkeyed BLAKE3 message authentication for headers.
//! * [`nonce`] — the monotonic 96-bit nonce counter.
//! * [`aead`] — AES-256-GCM and ChaCha20-Poly1305 with a runtime dispatcher.
//! * [`page`] — the metadata-page codec addressed by the footer's page table.
//! * [`rand`] — `/dev/urandom` reads, so no RNG crate can influence identity.
#![forbid(unsafe_code)]

pub mod aead;
pub mod hash;
pub mod kdf;
pub mod keys;
pub mod mac;
pub mod nonce;
pub mod page;
pub mod rand;

pub use aead::{AEAD_ID_AES_256_GCM, AEAD_ID_CHACHA20_POLY1305, AeadKind, TAG_LEN};
pub use hash::{ContentHasher, HASH_LEN, content_hash, unkeyed_hash};
pub use kdf::{
    DEFAULT_M_COST_KIB, DEFAULT_P_COST, DEFAULT_T_COST, KDF_ID_ARGON2ID, KEK_LEN, KdfParams, Kek,
    SALT_LEN, derive_kek,
};
pub use keys::{
    CHAIN_KEY_LEN, ChainKey, FILE_INFO, FileKeys, WRAP_AD_PREFIX, WRAP_NONCE_LEN, WRAPPED_KEY_LEN,
    dedup_key, file_keys, hkdf_sha256, unwrap_chain_key, wrap_chain_key,
};
pub use mac::{FIXED_PUBLIC_MAC_KEY_LEN, mac32, unkeyed_mac32, verify_mac32};
pub use nonce::{NONCE_LEN, NonceSeq};
pub use page::{MAX_PAGE_LEN, PAGE_MAGIC, StreamId, open_page, seal_page};
