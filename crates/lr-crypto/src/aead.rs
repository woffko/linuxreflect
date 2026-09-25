//! AEAD primitives: AES-256-GCM and ChaCha20-Poly1305 (spec §B, §G.5).
//!
//! Both ciphers are exposed through one runtime dispatcher. The tag is always
//! handled separately from the ciphertext because the `.lrimg` chunk and page
//! records store it in their own field (spec §G.5, §G.6).

use aes_gcm::aead::{AeadInOut, KeyInit, consts::U12};
use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use lr_core::{Error, Result};

/// Length of an AEAD key.
pub const KEY_LEN: usize = 32;

/// Length of an AEAD nonce.
pub const NONCE_LEN: usize = 12;

/// Length of an authentication tag.
pub const TAG_LEN: usize = 16;

/// `aead_id` value for AES-256-GCM (spec §G.3).
pub const AEAD_ID_AES_256_GCM: u32 = 1;

/// `aead_id` value for ChaCha20-Poly1305 (spec §G.3).
pub const AEAD_ID_CHACHA20_POLY1305: u32 = 2;

/// The AEAD algorithm recorded in the superblock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AeadKind {
    /// AES-256-GCM; preferred when the CPU has AES-NI.
    Aes256Gcm,
    /// ChaCha20-Poly1305; constant-time fallback without AES-NI.
    ChaCha20Poly1305,
}

impl AeadKind {
    /// On-disk discriminant.
    #[must_use]
    pub const fn id(self) -> u32 {
        match self {
            Self::Aes256Gcm => AEAD_ID_AES_256_GCM,
            Self::ChaCha20Poly1305 => AEAD_ID_CHACHA20_POLY1305,
        }
    }

    /// Parse an on-disk discriminant.
    ///
    /// # Errors
    /// Returns [`Error::Unsupported`] for unknown algorithms; a reader must
    /// refuse to guess rather than silently downgrade.
    pub fn from_id(id: u32) -> Result<Self> {
        match id {
            AEAD_ID_AES_256_GCM => Ok(Self::Aes256Gcm),
            AEAD_ID_CHACHA20_POLY1305 => Ok(Self::ChaCha20Poly1305),
            other => Err(Error::unsupported(format!("aead_id {other}"))),
        }
    }
}

fn tag_to_array(tag: impl AsRef<[u8]>) -> [u8; TAG_LEN] {
    let slice = tag.as_ref();
    let mut out = [0u8; TAG_LEN];
    out.copy_from_slice(slice);
    out
}

/// Encrypt `buf` in place and return the authentication tag.
///
/// # Errors
/// Returns [`Error::Aead`] when the cipher rejects the request (in practice
/// only for absurd message lengths).
pub fn seal_in_place(
    kind: AeadKind,
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buf: &mut [u8],
) -> Result<[u8; TAG_LEN]> {
    match kind {
        AeadKind::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::Aead)?;
            let nonce = AesNonce::<U12>::from(*nonce);
            let tag = cipher
                .encrypt_inout_detached(&nonce, aad, buf.into())
                .map_err(|_| Error::Aead)?;
            Ok(tag_to_array(tag))
        }
        AeadKind::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::Aead)?;
            let nonce = ChaChaNonce::from(*nonce);
            let tag = cipher
                .encrypt_inout_detached(&nonce, aad, buf.into())
                .map_err(|_| Error::Aead)?;
            Ok(tag_to_array(tag))
        }
    }
}

/// Decrypt `buf` in place, verifying `tag`.
///
/// # Errors
/// Returns [`Error::Aead`] when the tag does not authenticate the ciphertext,
/// the AAD, or the nonce.
pub fn open_in_place(
    kind: AeadKind,
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8; TAG_LEN],
) -> Result<()> {
    match kind {
        AeadKind::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::Aead)?;
            let nonce = AesNonce::<U12>::from(*nonce);
            let tag = aes_gcm::Tag::from(*tag);
            cipher
                .decrypt_inout_detached(&nonce, aad, buf.into(), &tag)
                .map_err(|_| Error::Aead)
        }
        AeadKind::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::Aead)?;
            let nonce = ChaChaNonce::from(*nonce);
            let tag = chacha20poly1305::Tag::from(*tag);
            cipher
                .decrypt_inout_detached(&nonce, aad, buf.into(), &tag)
                .map_err(|_| Error::Aead)
        }
    }
}

/// Encrypt `plaintext`, returning `(ciphertext, tag)`.
///
/// # Errors
/// See [`seal_in_place`].
pub fn seal(
    kind: AeadKind,
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; TAG_LEN])> {
    let mut buf = plaintext.to_vec();
    let tag = seal_in_place(kind, key, nonce, aad, &mut buf)?;
    Ok((buf, tag))
}

/// Decrypt `ciphertext` with `tag`, returning the plaintext.
///
/// # Errors
/// See [`open_in_place`].
pub fn open(
    kind: AeadKind,
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; TAG_LEN],
) -> Result<Vec<u8>> {
    let mut buf = ciphertext.to_vec();
    open_in_place(kind, key, nonce, aad, &mut buf, tag)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::{AEAD_ID_AES_256_GCM, AEAD_ID_CHACHA20_POLY1305, AeadKind, open, seal};

    const KEY: [u8; 32] = [0x2bu8; 32];
    const NONCE: [u8; 12] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ];
    const AAD: &[u8] = b"lrimg-v1/wrap";

    #[test]
    fn ids_match_the_spec_table() {
        assert_eq!(AEAD_ID_AES_256_GCM, 1);
        assert_eq!(AEAD_ID_CHACHA20_POLY1305, 2);
        assert_eq!(AeadKind::Aes256Gcm.id(), AEAD_ID_AES_256_GCM);
        assert_eq!(
            AeadKind::from_id(AEAD_ID_AES_256_GCM).expect("known"),
            AeadKind::Aes256Gcm
        );
        assert_eq!(
            AeadKind::from_id(AEAD_ID_CHACHA20_POLY1305).expect("known"),
            AeadKind::ChaCha20Poly1305
        );
        assert!(AeadKind::from_id(99).is_err());
    }

    #[test]
    fn both_ciphers_round_trip() {
        for kind in [AeadKind::Aes256Gcm, AeadKind::ChaCha20Poly1305] {
            let (ciphertext, tag) = seal(kind, &KEY, &NONCE, AAD, b"payload").expect("seal");
            assert_ne!(&ciphertext, b"payload");
            let plaintext = open(kind, &KEY, &NONCE, AAD, &ciphertext, &tag).expect("open");
            assert_eq!(plaintext, b"payload");
        }
    }

    #[test]
    fn wrong_aad_nonce_or_tag_fails() {
        for kind in [AeadKind::Aes256Gcm, AeadKind::ChaCha20Poly1305] {
            let (ciphertext, tag) = seal(kind, &KEY, &NONCE, AAD, b"payload").expect("seal");
            assert!(open(kind, &KEY, &NONCE, b"other-aad", &ciphertext, &tag).is_err());
            let mut other_nonce = NONCE;
            other_nonce[0] ^= 0xff;
            assert!(open(kind, &KEY, &other_nonce, AAD, &ciphertext, &tag).is_err());
            let mut bad_tag = tag;
            bad_tag[0] ^= 0x01;
            assert!(open(kind, &KEY, &NONCE, AAD, &ciphertext, &bad_tag).is_err());
        }
    }

    #[test]
    fn flipping_a_ciphertext_bit_fails() {
        let (mut ciphertext, tag) =
            seal(AeadKind::Aes256Gcm, &KEY, &NONCE, AAD, b"payload").expect("seal");
        ciphertext[1] ^= 0x80;
        assert!(open(AeadKind::Aes256Gcm, &KEY, &NONCE, AAD, &ciphertext, &tag).is_err());
    }

    #[test]
    fn empty_plaintext_is_supported() {
        let (ciphertext, tag) =
            seal(AeadKind::ChaCha20Poly1305, &KEY, &NONCE, AAD, b"").expect("seal");
        assert!(ciphertext.is_empty());
        assert_eq!(
            open(
                AeadKind::ChaCha20Poly1305,
                &KEY,
                &NONCE,
                AAD,
                &ciphertext,
                &tag
            )
            .expect("open"),
            b""
        );
    }
}
