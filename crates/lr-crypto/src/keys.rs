//! The key hierarchy (spec §G.4).
//!
//! ```text
//! passphrase --Argon2id(salt)--> KEK
//! KEK --AES-256-GCM--> chain_key            (wrapped in every member's superblock)
//! chain_key --HKDF("lrimg-v1/file", image_uuid)--> data_key || meta_key
//! chain_key --HKDF("lrimg-v1/dedup", chain_id)---> dedup_key
//! ```
//!
//! One Argon2id run per chain is enough: the chain key is generated with the
//! full and wrapped into every member, so restoring the tenth incremental costs
//! exactly one KDF invocation.

use hkdf::Hkdf;
use lr_core::{Error, Id, Result};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::aead::AeadKind;
use crate::kdf::Kek;
use crate::rand;

/// Length of a chain key.
pub const CHAIN_KEY_LEN: usize = 32;

/// Length of the wrapping nonce stored in the superblock.
pub const WRAP_NONCE_LEN: usize = 12;

/// Length of the wrapped chain key (`chain_key` plus GCM tag).
pub const WRAPPED_KEY_LEN: usize = CHAIN_KEY_LEN + 16;

/// Domain separation prefix for the chain-key wrapping AAD.
pub const WRAP_AD_PREFIX: &[u8] = b"lrimg-v1/wrap";

/// HKDF info string for per-image file keys.
pub const FILE_INFO: &[u8] = b"lrimg-v1/file";

/// HKDF info string for the chain's dedup key.
pub const DEDUP_INFO: &[u8] = b"lrimg-v1/dedup";

/// The random per-chain key. Generated with the full, unwrapped on restore.
pub struct ChainKey(Zeroizing<[u8; CHAIN_KEY_LEN]>);

impl ChainKey {
    /// Generate a fresh chain key from the kernel CSPRNG.
    ///
    /// # Errors
    /// Returns [`Error::Io`] when `/dev/urandom` cannot be read.
    pub fn generate() -> Result<Self> {
        Ok(Self(Zeroizing::new(rand::random_bytes::<CHAIN_KEY_LEN>()?)))
    }

    /// Wrap raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; CHAIN_KEY_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Borrow the raw key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; CHAIN_KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for ChainKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ChainKey(<redacted>)")
    }
}

// The inner `Zeroizing` zeroizes on drop; this marker makes the guarantee
// visible to callers and to the test suite.
impl zeroize::ZeroizeOnDrop for ChainKey {}

/// The two keys derived for one image file.
pub struct FileKeys {
    /// Encrypts chunk payloads.
    pub data_key: Zeroizing<[u8; 32]>,
    /// Encrypts metadata pages and authenticates headers.
    pub meta_key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for FileKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FileKeys(<redacted>)")
    }
}

// Both halves are `Zeroizing` buffers, zeroized on drop.
impl zeroize::ZeroizeOnDrop for FileKeys {}

fn wrap_ad(chain_id: &Id) -> Vec<u8> {
    let mut ad = Vec::with_capacity(WRAP_AD_PREFIX.len() + 16);
    ad.extend_from_slice(WRAP_AD_PREFIX);
    ad.extend_from_slice(chain_id.as_bytes());
    ad
}

/// Wrap a chain key under the KEK for one chain.
///
/// Returns the random `wrap_nonce` and the 48-byte wrapped key stored in the
/// superblock (spec §G.3).
///
/// # Errors
/// Returns [`Error::Io`] when `/dev/urandom` cannot be read, or [`Error::Aead`]
/// if the cipher rejects the request.
pub fn wrap_chain_key(
    kek: &Kek,
    chain_key: &ChainKey,
    chain_id: &Id,
) -> Result<([u8; WRAP_NONCE_LEN], [u8; WRAPPED_KEY_LEN])> {
    let nonce: [u8; WRAP_NONCE_LEN] = rand::random_bytes()?;
    let ad = wrap_ad(chain_id);
    let (ciphertext, tag) = crate::aead::seal(
        AeadKind::Aes256Gcm,
        kek.as_bytes(),
        &nonce,
        &ad,
        chain_key.as_bytes(),
    )?;
    let mut wrapped = [0u8; WRAPPED_KEY_LEN];
    wrapped[..CHAIN_KEY_LEN].copy_from_slice(&ciphertext);
    wrapped[CHAIN_KEY_LEN..].copy_from_slice(&tag);
    Ok((nonce, wrapped))
}

/// Unwrap a chain key with the KEK.
///
/// # Errors
/// Returns [`Error::Aead`] for a wrong passphrase, a different chain, or any
/// tampering with the wrapped key or nonce.
pub fn unwrap_chain_key(
    kek: &Kek,
    chain_id: &Id,
    nonce: &[u8; WRAP_NONCE_LEN],
    wrapped: &[u8; WRAPPED_KEY_LEN],
) -> Result<ChainKey> {
    let ad = wrap_ad(chain_id);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&wrapped[CHAIN_KEY_LEN..]);
    let plaintext = crate::aead::open(
        AeadKind::Aes256Gcm,
        kek.as_bytes(),
        nonce,
        &ad,
        &wrapped[..CHAIN_KEY_LEN],
        &tag,
    )?;
    let bytes: [u8; CHAIN_KEY_LEN] = plaintext.as_slice().try_into().map_err(|_| Error::Aead)?;
    Ok(ChainKey::from_bytes(bytes))
}

/// HKDF-SHA256 expansion, the construction §G.4 uses for every chain-level key.
///
/// `file_keys` and `dedup_key` are two instantiations of this call; exposing it
/// keeps a single, testable implementation of the derivation and lets the KAT
/// suite check it against RFC 5869 directly.
///
/// # Errors
/// Returns [`Error::Unsupported`] when `length` is out of range (HKDF-SHA256
/// allows at most 255 * 32 bytes).
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; length];
    hkdf.expand(info, &mut okm)
        .map_err(|_| Error::unsupported("hkdf output length"))?;
    Ok(okm)
}

fn expand(chain_key: &ChainKey, salt: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>> {
    hkdf_sha256(chain_key.as_bytes(), salt, info, length)
}

/// Derive the per-image data key and metadata key (spec §G.4).
///
/// # Errors
/// Returns [`Error::Unsupported`] if HKDF rejects the requested length, which
/// cannot happen for the fixed 64-byte expansion used here.
pub fn file_keys(chain_key: &ChainKey, image_uuid: &Id) -> Result<FileKeys> {
    let okm = expand(chain_key, image_uuid.as_bytes(), FILE_INFO, 64)?;
    let mut data_key = Zeroizing::new([0u8; 32]);
    let mut meta_key = Zeroizing::new([0u8; 32]);
    data_key.copy_from_slice(&okm[..32]);
    meta_key.copy_from_slice(&okm[32..]);
    Ok(FileKeys { data_key, meta_key })
}

/// Derive the chain's dedup key (spec §G.4).
///
/// # Errors
/// Returns [`Error::Unsupported`] if HKDF rejects the requested length.
pub fn dedup_key(chain_key: &ChainKey, chain_id: &Id) -> Result<[u8; 32]> {
    let okm = expand(chain_key, chain_id.as_bytes(), DEDUP_INFO, 32)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&okm);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::{ChainKey, dedup_key, file_keys, unwrap_chain_key, wrap_chain_key};
    use crate::kdf::{KdfParams, derive_kek};
    use lr_core::Id;

    fn kek() -> crate::kdf::Kek {
        derive_kek(b"passphrase", b"0123456789abcdef", KdfParams::new(32, 3, 4)).expect("kek")
    }

    #[test]
    fn wrap_unwrap_round_trip() {
        let chain_id = Id::from_bytes([0x11; 16]);
        let chain_key = ChainKey::generate().expect("chain key");
        let (nonce, wrapped) = wrap_chain_key(&kek(), &chain_key, &chain_id).expect("wrap");
        let unwrapped = unwrap_chain_key(&kek(), &chain_id, &nonce, &wrapped).expect("unwrap");
        assert_eq!(unwrapped.as_bytes(), chain_key.as_bytes());
    }

    #[test]
    fn wrong_passphrase_fails_at_unwrap() {
        let chain_id = Id::from_bytes([0x11; 16]);
        let chain_key = ChainKey::generate().expect("chain key");
        let (nonce, wrapped) = wrap_chain_key(&kek(), &chain_key, &chain_id).expect("wrap");
        let wrong =
            derive_kek(b"passphras3", b"0123456789abcdef", KdfParams::new(32, 3, 4)).expect("kek");
        assert!(unwrap_chain_key(&wrong, &chain_id, &nonce, &wrapped).is_err());
    }

    #[test]
    fn a_different_chain_id_fails() {
        let chain_id = Id::from_bytes([0x11; 16]);
        let other = Id::from_bytes([0x22; 16]);
        let chain_key = ChainKey::generate().expect("chain key");
        let (nonce, wrapped) = wrap_chain_key(&kek(), &chain_key, &chain_id).expect("wrap");
        assert!(unwrap_chain_key(&kek(), &other, &nonce, &wrapped).is_err());
    }

    #[test]
    fn tampering_with_the_wrapped_key_fails() {
        let chain_id = Id::from_bytes([0x11; 16]);
        let chain_key = ChainKey::generate().expect("chain key");
        let (nonce, mut wrapped) = wrap_chain_key(&kek(), &chain_key, &chain_id).expect("wrap");
        wrapped[0] ^= 0x01;
        assert!(unwrap_chain_key(&kek(), &chain_id, &nonce, &wrapped).is_err());
    }

    #[test]
    fn two_images_of_one_chain_never_share_keys() {
        let chain_key = ChainKey::generate().expect("chain key");
        let first = file_keys(&chain_key, &Id::from_bytes([0x01; 16])).expect("keys");
        let second = file_keys(&chain_key, &Id::from_bytes([0x02; 16])).expect("keys");
        assert_ne!(first.data_key.as_slice(), second.data_key.as_slice());
        assert_ne!(first.meta_key.as_slice(), second.meta_key.as_slice());
        assert_ne!(
            first.data_key.as_slice(),
            first.meta_key.as_slice(),
            "data and metadata keys must differ"
        );
    }

    #[test]
    fn dedup_key_is_per_chain() {
        let chain_key = ChainKey::generate().expect("chain key");
        let chain_a = Id::from_bytes([0x0a; 16]);
        let chain_b = Id::from_bytes([0x0b; 16]);
        assert_eq!(
            dedup_key(&chain_key, &chain_a).expect("dedup"),
            dedup_key(&chain_key, &chain_a).expect("dedup")
        );
        assert_ne!(
            dedup_key(&chain_key, &chain_a).expect("dedup"),
            dedup_key(&chain_key, &chain_b).expect("dedup")
        );
    }
}
