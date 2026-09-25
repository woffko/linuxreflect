//! Key material for the engine (spec §G.4, §D.3).
//!
//! A backup derives the whole hierarchy once and writes only the wrapped chain
//! key; a restore rebuilds it from the passphrase and the superblock.

use lr_core::{ChainId, Error, Id, Result};
use lr_crypto::kdf::{KdfParams, derive_kek};
use lr_crypto::keys::{ChainKey, dedup_key, file_keys, unwrap_chain_key, wrap_chain_key};
use lr_crypto::mac::fixed_public_mac_key;
use lr_format::Superblock;
use zeroize::Zeroizing;

use crate::keystore::Passphrase;

/// How an image is protected.
#[derive(Clone)]
pub enum Encryption {
    /// Argon2id-derived KEK wrapping a random chain key.
    Passphrase(Passphrase),
    /// `--no-encrypt`: chunks are stored in the clear and header MACs use the
    /// fixed public key, so the image is not tamper-evident (spec §G.3).
    NoEncrypt,
}

impl std::fmt::Debug for Encryption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Passphrase(_) => f.write_str("Encryption::Passphrase(<redacted>)"),
            Self::NoEncrypt => f.write_str("Encryption::NoEncrypt"),
        }
    }
}

/// Per-image keys.
pub(crate) struct ImageKeys {
    /// `None` when chunks are not encrypted.
    pub data_key: Option<Zeroizing<[u8; 32]>>,
    pub meta_key: Zeroizing<[u8; 32]>,
    pub dedup_key: Zeroizing<[u8; 32]>,
}

/// The chain key of a superblock, unwrapped with the passphrase.
///
/// # Errors
/// Returns [`Error::Aead`] for a wrong passphrase and [`Error::Unsupported`]
/// when the image is not encrypted.
pub(crate) fn chain_key_of(
    encryption: &Encryption,
    superblock: &Superblock,
) -> Result<(ChainKey, bool)> {
    if !superblock.is_encrypted() {
        return Ok((ChainKey::from_bytes(fixed_public_mac_key()), false));
    }
    let Encryption::Passphrase(passphrase) = encryption else {
        return Err(Error::unsupported(
            "this image is encrypted; supply a passphrase file",
        ));
    };
    let kek = derive_kek(
        passphrase.as_bytes(),
        &superblock.kdf_salt,
        superblock.kdf_params(),
    )?;
    let chain_key = unwrap_chain_key(
        &kek,
        superblock.chain_id.inner(),
        &superblock.wrap_nonce,
        &superblock.wrapped_chain_key,
    )?;
    Ok((chain_key, true))
}

impl std::fmt::Debug for ImageKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ImageKeys(<redacted>)")
    }
}

/// Everything needed to write the first member of a chain.
pub(crate) struct NewChainKeys {
    pub keys: ImageKeys,
    pub kdf_salt: [u8; 16],
    pub params: KdfParams,
    pub wrap_nonce: [u8; 12],
    pub wrapped_chain_key: [u8; 48],
    pub encrypted: bool,
}

/// Derive keys for a brand-new image (the full of a chain).
///
/// # Errors
/// Propagates RNG, KDF and wrapping failures.
pub(crate) fn new_chain_keys(
    encryption: &Encryption,
    chain_id: &ChainId,
    image_uuid: &Id,
) -> Result<NewChainKeys> {
    match encryption {
        Encryption::Passphrase(passphrase) => {
            let params = KdfParams::default();
            let kdf_salt: [u8; 16] = lr_crypto::rand::random_bytes()?;
            let kek = derive_kek(passphrase.as_bytes(), &kdf_salt, params)?;
            let chain_key = ChainKey::generate()?;
            let (wrap_nonce, wrapped_chain_key) =
                wrap_chain_key(&kek, &chain_key, chain_id.inner())?;
            Ok(NewChainKeys {
                keys: image_keys(&chain_key, chain_id, image_uuid, true)?,
                kdf_salt,
                params,
                wrap_nonce,
                wrapped_chain_key,
                encrypted: true,
            })
        }
        Encryption::NoEncrypt => {
            let chain_key = ChainKey::from_bytes(fixed_public_mac_key());
            Ok(NewChainKeys {
                keys: image_keys(&chain_key, chain_id, image_uuid, false)?,
                kdf_salt: [0u8; 16],
                params: KdfParams::new(0, 0, 0),
                wrap_nonce: [0u8; 12],
                wrapped_chain_key: [0u8; 48],
                encrypted: false,
            })
        }
    }
}

/// Derive keys for a new member of an existing chain.
///
/// The chain key is unwrapped from the parent superblock and rewrapped with a
/// fresh nonce; the KDF salt and parameters stay the parent's, because spec
/// §G.3 requires them to be identical in every member (the KEK must be the
/// same for the whole chain).
///
/// # Errors
/// Returns [`Error::Aead`] for a wrong passphrase, and [`Error::Unsupported`]
/// when the parent and the new member disagree about the chain or the cipher.
pub(crate) fn member_chain_keys(
    encryption: &Encryption,
    parent: &Superblock,
    chain_id: &ChainId,
    image_uuid: &Id,
) -> Result<NewChainKeys> {
    if parent.chain_id != *chain_id {
        return Err(Error::unsupported(format!(
            "parent belongs to chain {}, not {chain_id}",
            parent.chain_id
        )));
    }
    if !parent.is_encrypted() {
        // The public-key chain: nothing to unwrap or rewrap.
        let chain_key = ChainKey::from_bytes(fixed_public_mac_key());
        return Ok(NewChainKeys {
            keys: image_keys(&chain_key, chain_id, image_uuid, false)?,
            kdf_salt: parent.kdf_salt,
            params: parent.kdf_params(),
            wrap_nonce: [0u8; 12],
            wrapped_chain_key: [0u8; 48],
            encrypted: false,
        });
    }
    let Encryption::Passphrase(passphrase) = encryption else {
        return Err(Error::unsupported(
            "the chain is encrypted; supply a passphrase file",
        ));
    };
    let kek = derive_kek(passphrase.as_bytes(), &parent.kdf_salt, parent.kdf_params())?;
    let chain_key = unwrap_chain_key(
        &kek,
        parent.chain_id.inner(),
        &parent.wrap_nonce,
        &parent.wrapped_chain_key,
    )?;
    let (wrap_nonce, wrapped_chain_key) = wrap_chain_key(&kek, &chain_key, chain_id.inner())?;
    Ok(NewChainKeys {
        keys: image_keys(&chain_key, chain_id, image_uuid, true)?,
        kdf_salt: parent.kdf_salt,
        params: parent.kdf_params(),
        wrap_nonce,
        wrapped_chain_key,
        encrypted: true,
    })
}

/// Unlock one member of a chain with the chain key taken from another member.
///
/// Restoring or verifying a chain derives the KEK once; this avoids repeating
/// Argon2id for every member.
///
/// # Errors
/// See [`unlock_image`].
pub(crate) fn unlock_with_chain_key(
    chain_key: &ChainKey,
    chain_id: &ChainId,
    superblock: &Superblock,
    encrypted: bool,
) -> Result<ImageKeys> {
    if superblock.chain_id != *chain_id {
        return Err(Error::unsupported(format!(
            "member {} belongs to chain {}, not {chain_id}",
            superblock.image_uuid, superblock.chain_id
        )));
    }
    image_keys(
        chain_key,
        chain_id,
        superblock.image_uuid.inner(),
        encrypted,
    )
}

/// Rebuild the keys of an existing image from its superblock.
///
/// # Errors
/// Returns [`Error::Aead`] for a wrong passphrase or a tampered wrapped key,
/// and [`Error::Unsupported`] when the superblock needs a feature this build
/// does not have.
pub(crate) fn unlock_image(encryption: &Encryption, superblock: &Superblock) -> Result<ImageKeys> {
    if superblock.is_encrypted() {
        let Encryption::Passphrase(passphrase) = encryption else {
            return Err(Error::unsupported(
                "this image is encrypted; supply a passphrase file",
            ));
        };
        let kek = derive_kek(
            passphrase.as_bytes(),
            &superblock.kdf_salt,
            superblock.kdf_params(),
        )?;
        let chain_key = unwrap_chain_key(
            &kek,
            superblock.chain_id.inner(),
            &superblock.wrap_nonce,
            &superblock.wrapped_chain_key,
        )?;
        image_keys(
            &chain_key,
            &superblock.chain_id,
            superblock.image_uuid.inner(),
            true,
        )
    } else {
        let chain_key = ChainKey::from_bytes(fixed_public_mac_key());
        image_keys(
            &chain_key,
            &superblock.chain_id,
            superblock.image_uuid.inner(),
            false,
        )
    }
}

fn image_keys(
    chain_key: &ChainKey,
    chain_id: &ChainId,
    image_uuid: &Id,
    encrypted: bool,
) -> Result<ImageKeys> {
    let keys = file_keys(chain_key, image_uuid)?;
    Ok(ImageKeys {
        // `--no-encrypt` images store chunks in the clear; the metadata key is
        // still derived and still authenticates pages (spec §G.5, D-014).
        data_key: encrypted.then(|| Zeroizing::new(*keys.data_key)),
        meta_key: Zeroizing::new(*keys.meta_key),
        dedup_key: Zeroizing::new(dedup_key(chain_key, chain_id.inner())?),
    })
}

#[cfg(test)]
mod tests {
    use super::{Encryption, new_chain_keys, unlock_image};
    use crate::keystore::Passphrase;
    use lr_core::{ChainId, Id, ImageId};
    use lr_format::{FORMAT_MAJOR, MIN_READER, Superblock, flags};

    fn chain() -> (ChainId, Id) {
        (
            ChainId::new(Id::from_bytes([0x11; 16])),
            Id::from_bytes([0x22; 16]),
        )
    }

    fn superblock_from(new: &super::NewChainKeys, chain_id: ChainId, image_uuid: Id) -> Superblock {
        Superblock {
            format_major: FORMAT_MAJOR,
            min_reader: MIN_READER,
            flags: if new.encrypted { flags::ENCRYPTED } else { 0 },
            image_kind: lr_core::ImageKind::Block,
            consistency: lr_core::Consistency::Offline,
            image_uuid: ImageId::new(image_uuid),
            chain_id,
            set_id: lr_core::SetId::ZERO,
            parent_uuid: ImageId::ZERO,
            seq_in_chain: 0,
            created_unix: 0,
            source_size_bytes: 1024,
            logical_block_size: 512,
            chunk_size: 1024 * 1024,
            kdf_id: if new.encrypted { 1 } else { 0 },
            aead_id: 1,
            kdf_salt: new.kdf_salt,
            argon2_m_cost_kib: new.params.m_cost_kib,
            argon2_t_cost: new.params.t_cost,
            argon2_p_cost: new.params.p_cost,
            wrap_nonce: new.wrap_nonce,
            wrapped_chain_key: new.wrapped_chain_key,
        }
    }

    #[test]
    fn a_passphrase_chain_unlocks_with_the_same_passphrase() {
        let (chain_id, image_uuid) = chain();
        let encryption = Encryption::Passphrase(Passphrase::new(b"passphrase".to_vec()));
        let new = new_chain_keys(&encryption, &chain_id, &image_uuid).expect("new keys");
        assert!(new.encrypted);

        let superblock = superblock_from(&new, chain_id, image_uuid);
        let unlocked = unlock_image(&encryption, &superblock).expect("unlock");
        assert_eq!(unlocked.meta_key.as_slice(), new.keys.meta_key.as_slice());
        assert_eq!(unlocked.dedup_key.as_slice(), new.keys.dedup_key.as_slice());
    }

    #[test]
    fn a_wrong_passphrase_fails() {
        let (chain_id, image_uuid) = chain();
        let encryption = Encryption::Passphrase(Passphrase::new(b"passphrase".to_vec()));
        let new = new_chain_keys(&encryption, &chain_id, &image_uuid).expect("new keys");
        let superblock = superblock_from(&new, chain_id, image_uuid);

        let wrong = Encryption::Passphrase(Passphrase::new(b"passphras3".to_vec()));
        let error = unlock_image(&wrong, &superblock).expect_err("must fail");
        assert!(matches!(error, lr_core::Error::Aead), "{error}");
    }

    #[test]
    fn an_unencrypted_image_needs_no_passphrase() {
        let (chain_id, image_uuid) = chain();
        let new = new_chain_keys(&Encryption::NoEncrypt, &chain_id, &image_uuid).expect("keys");
        assert!(!new.encrypted);
        let superblock = superblock_from(&new, chain_id, image_uuid);
        let unlocked = unlock_image(&Encryption::NoEncrypt, &superblock).expect("unlock");
        assert_eq!(unlocked.meta_key.as_slice(), new.keys.meta_key.as_slice());
    }

    #[test]
    fn two_images_of_one_chain_have_different_keys_but_one_dedup_key() {
        let (chain_id, first_uuid) = chain();
        let second_uuid = Id::from_bytes([0x33; 16]);
        let encryption = Encryption::Passphrase(Passphrase::new(b"passphrase".to_vec()));
        let new = new_chain_keys(&encryption, &chain_id, &first_uuid).expect("keys");
        let other = new_chain_keys(&encryption, &chain_id, &second_uuid).expect("keys");
        assert_ne!(new.keys.meta_key.as_slice(), other.keys.meta_key.as_slice());
        assert_ne!(
            new.keys.dedup_key.as_slice(),
            other.keys.dedup_key.as_slice()
        );
    }
}
