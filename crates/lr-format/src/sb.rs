//! Image superblock codec (spec §G.3, `docs/format-lrimg-v1.md` §1).

use lr_core::{Consistency, Error, Id, ImageId, ImageKind, Result};
use lr_crypto::aead::AeadKind;
use lr_crypto::kdf::KdfParams;
use lr_crypto::mac::{fixed_public_mac_key, mac32, unkeyed_mac32, verify_mac32};

use crate::wire;

/// Size of the superblock.
pub const SB_SIZE: usize = 4096;

/// Superblock magic (`"LRIMG\x01\0\0"`).
pub const SB_MAGIC: [u8; 8] = *b"LRIMG\x01\0\0";

/// Format version written by this implementation.
pub const FORMAT_MAJOR: u32 = 1;

/// Oldest reader that can interpret this format version.
pub const MIN_READER: u32 = 1;

/// Offset of `sb_hash`; also the length of `superblock_copy` in the footer.
pub const SB_HASH_OFFSET: usize = 1024;

/// Offset of `sb_mac`.
pub const SB_MAC_OFFSET: usize = 1056;

/// Length of the verbatim superblock prefix copied into the footer.
pub const SUPERBLOCK_COPY_LEN: usize = SB_HASH_OFFSET;

/// Smallest allowed block-mode chunk size (spec §G.2).
pub const MIN_CHUNK_SIZE: u32 = 256 * 1024;

/// Largest allowed block-mode chunk size (spec §G.2).
pub const MAX_CHUNK_SIZE: u32 = 4 * 1024 * 1024;

/// Superblock `flags` bits (spec §G.3).
pub mod flags {
    /// Payloads are encrypted with the image's data key.
    pub const ENCRYPTED: u64 = 1 << 0;
    /// Compression was applied to at least one chunk.
    pub const COMPRESSED: u64 = 1 << 1;
    /// The manifest is a delta manifest.
    pub const DELTA_MANIFEST: u64 = 1 << 2;
    /// The image is a whole-disk image with a partition manifest.
    pub const WHOLE_DISK: u64 = 1 << 3;
    /// The image was taken from a live, mounted device (`--allow-inconsistent`).
    pub const INCONSISTENT: u64 = 1 << 4;
}

/// The `.lrimg` superblock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Superblock {
    /// Format major version.
    pub format_major: u32,
    /// Minimum reader version required.
    pub min_reader: u32,
    /// Feature/state flags, see [`flags`].
    pub flags: u64,
    /// Image kind.
    pub image_kind: ImageKind,
    /// Consistency level actually achieved.
    pub consistency: Consistency,
    /// This file's identifier; also derives its keys.
    pub image_uuid: ImageId,
    /// Chain identifier; shared by every member.
    pub chain_id: lr_core::ChainId,
    /// Backup set identifier.
    pub set_id: lr_core::SetId,
    /// Parent image UUID; zero for a full.
    pub parent_uuid: ImageId,
    /// Position in the chain; 0 is the full.
    pub seq_in_chain: u32,
    /// Creation time, seconds since the Unix epoch.
    pub created_unix: u64,
    /// Size of the source in bytes.
    pub source_size_bytes: u64,
    /// Logical block size of the source.
    pub logical_block_size: u32,
    /// Block-mode chunk size.
    pub chunk_size: u32,
    /// KDF identifier (1 = Argon2id).
    pub kdf_id: u32,
    /// AEAD identifier.
    pub aead_id: u32,
    /// Chain-wide KDF salt.
    pub kdf_salt: [u8; 16],
    /// Argon2id memory cost in KiB.
    pub argon2_m_cost_kib: u32,
    /// Argon2id time cost.
    pub argon2_t_cost: u32,
    /// Argon2id parallelism.
    pub argon2_p_cost: u32,
    /// Nonce used to wrap the chain key.
    pub wrap_nonce: [u8; 12],
    /// Wrapped chain key.
    pub wrapped_chain_key: [u8; 48],
}

impl Superblock {
    /// The AEAD algorithm recorded in this superblock.
    ///
    /// # Errors
    /// Returns [`Error::Unsupported`] for an unknown `aead_id`.
    pub fn aead_kind(&self) -> Result<AeadKind> {
        AeadKind::from_id(self.aead_id)
    }

    /// The Argon2id parameters recorded in this superblock.
    #[must_use]
    pub fn kdf_params(&self) -> KdfParams {
        KdfParams::new(
            self.argon2_m_cost_kib,
            self.argon2_t_cost,
            self.argon2_p_cost,
        )
    }

    /// `true` when payloads are encrypted.
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        self.flags & flags::ENCRYPTED != 0
    }

    /// `true` when the manifest is a delta manifest.
    #[must_use]
    pub const fn is_delta_manifest(&self) -> bool {
        self.flags & flags::DELTA_MANIFEST != 0
    }

    /// `true` for whole-disk images.
    #[must_use]
    pub const fn is_whole_disk(&self) -> bool {
        self.flags & flags::WHOLE_DISK != 0
    }

    /// `true` when the image was taken inconsistently.
    #[must_use]
    pub const fn is_inconsistent(&self) -> bool {
        self.flags & flags::INCONSISTENT != 0
    }

    /// The key that authenticates this superblock: the image's `meta_key`, or
    /// the fixed public key for `--no-encrypt` images.
    #[must_use]
    pub fn authentication_key(meta_key: Option<&[u8; 32]>) -> [u8; 32] {
        meta_key.copied().unwrap_or_else(fixed_public_mac_key)
    }

    /// Validate `format_major`, `min_reader` and every bounded field without
    /// touching the MAC, and verify the unkeyed `sb_hash`.
    fn validate_header(&self) -> Result<()> {
        if self.format_major > FORMAT_MAJOR {
            return Err(Error::unsupported(format!(
                "format_major {} (this reader knows {FORMAT_MAJOR})",
                self.format_major
            )));
        }
        if self.min_reader > FORMAT_MAJOR {
            return Err(Error::unsupported(format!(
                "min_reader {} means a newer reader is required",
                self.min_reader
            )));
        }
        if !is_power_of_two_in_range(self.chunk_size, MIN_CHUNK_SIZE, MAX_CHUNK_SIZE) {
            return Err(Error::corrupt(format!(
                "chunk_size {} is not a power of two in {MIN_CHUNK_SIZE}..={MAX_CHUNK_SIZE}",
                self.chunk_size
            )));
        }
        if !is_power_of_two_in_range(self.logical_block_size, 512, 4096) {
            return Err(Error::corrupt(format!(
                "logical_block_size {} is not a power of two in 512..=4096",
                self.logical_block_size
            )));
        }
        AeadKind::from_id(self.aead_id).map(|_| ())?;
        match self.kdf_id {
            // 0 = no KDF: the image is unencrypted (spec §G.3, D-014).
            0 if !self.is_encrypted() => {}
            1 if self.is_encrypted() => {}
            0 => {
                return Err(Error::corrupt(
                    "an encrypted image must record an Argon2id kdf_id",
                ));
            }
            other => return Err(Error::unsupported(format!("kdf_id {other}"))),
        }
        Ok(())
    }

    /// Encode the superblock, computing `sb_hash` and `sb_mac`.
    ///
    /// Pass the image's `meta_key` for encrypted images, or `None` for
    /// `--no-encrypt` images (which then use the fixed public key and are not
    /// tamper-evident).
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] when the header fields are out of range.
    pub fn encode(&self, meta_key: Option<&[u8; 32]>) -> Result<[u8; SB_SIZE]> {
        self.validate_header()?;
        let mut bytes = [0u8; SB_SIZE];
        bytes[0..8].copy_from_slice(&SB_MAGIC);
        bytes[8..12].copy_from_slice(&self.format_major.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.min_reader.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.flags.to_le_bytes());
        bytes[24] = self.image_kind.as_u8();
        bytes[25] = self.consistency.as_u8();
        bytes[26..42].copy_from_slice(self.image_uuid.inner().as_bytes());
        bytes[42..58].copy_from_slice(self.chain_id.inner().as_bytes());
        bytes[58..74].copy_from_slice(self.set_id.inner().as_bytes());
        bytes[74..90].copy_from_slice(self.parent_uuid.inner().as_bytes());
        bytes[90..94].copy_from_slice(&self.seq_in_chain.to_le_bytes());
        bytes[94..102].copy_from_slice(&self.created_unix.to_le_bytes());
        bytes[102..110].copy_from_slice(&self.source_size_bytes.to_le_bytes());
        bytes[110..114].copy_from_slice(&self.logical_block_size.to_le_bytes());
        bytes[114..118].copy_from_slice(&self.chunk_size.to_le_bytes());
        bytes[118..122].copy_from_slice(&self.kdf_id.to_le_bytes());
        bytes[122..126].copy_from_slice(&self.aead_id.to_le_bytes());
        bytes[126..142].copy_from_slice(&self.kdf_salt);
        bytes[142..146].copy_from_slice(&self.argon2_m_cost_kib.to_le_bytes());
        bytes[146..150].copy_from_slice(&self.argon2_t_cost.to_le_bytes());
        bytes[150..154].copy_from_slice(&self.argon2_p_cost.to_le_bytes());
        bytes[154..166].copy_from_slice(&self.wrap_nonce);
        bytes[166..214].copy_from_slice(&self.wrapped_chain_key);

        let hash = unkeyed_mac32(&bytes[..SB_HASH_OFFSET]);
        bytes[SB_HASH_OFFSET..SB_HASH_OFFSET + 32].copy_from_slice(&hash);
        let mac = mac32(&Self::authentication_key(meta_key), &bytes[..SB_MAC_OFFSET]);
        bytes[SB_MAC_OFFSET..SB_MAC_OFFSET + 32].copy_from_slice(&mac);
        Ok(bytes)
    }

    /// Decode a superblock from its raw bytes, verifying `sb_hash` only.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] for a bad magic, a bad hash, or an
    /// out-of-range field, and [`Error::Unsupported`] for a newer format.
    pub fn decode(bytes: &[u8; SB_SIZE]) -> Result<Self> {
        if bytes[0..8] != SB_MAGIC {
            return Err(Error::corrupt("superblock magic does not match LRIMG"));
        }
        let expected = unkeyed_mac32(&bytes[..SB_HASH_OFFSET]);
        if bytes[SB_HASH_OFFSET..SB_HASH_OFFSET + 32] != expected {
            return Err(Error::corrupt("superblock hash mismatch"));
        }
        let superblock = Self {
            format_major: wire::slice_u32(&bytes[8..])?,
            min_reader: wire::slice_u32(&bytes[12..])?,
            flags: wire::slice_u64(&bytes[16..])?,
            image_kind: ImageKind::from_u8(bytes[24])?,
            consistency: Consistency::from_u8(bytes[25])?,
            image_uuid: ImageId::new(Id::from_bytes(
                bytes[26..42]
                    .try_into()
                    .map_err(|_| Error::corrupt("image_uuid"))?,
            )),
            chain_id: lr_core::ChainId::new(Id::from_bytes(
                bytes[42..58]
                    .try_into()
                    .map_err(|_| Error::corrupt("chain_id"))?,
            )),
            set_id: lr_core::SetId::new(Id::from_bytes(
                bytes[58..74]
                    .try_into()
                    .map_err(|_| Error::corrupt("set_id"))?,
            )),
            parent_uuid: ImageId::new(Id::from_bytes(
                bytes[74..90]
                    .try_into()
                    .map_err(|_| Error::corrupt("parent_uuid"))?,
            )),
            seq_in_chain: wire::slice_u32(&bytes[90..])?,
            created_unix: wire::slice_u64(&bytes[94..])?,
            source_size_bytes: wire::slice_u64(&bytes[102..])?,
            logical_block_size: wire::slice_u32(&bytes[110..])?,
            chunk_size: wire::slice_u32(&bytes[114..])?,
            kdf_id: wire::slice_u32(&bytes[118..])?,
            aead_id: wire::slice_u32(&bytes[122..])?,
            kdf_salt: bytes[126..142]
                .try_into()
                .map_err(|_| Error::corrupt("kdf_salt"))?,
            argon2_m_cost_kib: wire::slice_u32(&bytes[142..])?,
            argon2_t_cost: wire::slice_u32(&bytes[146..])?,
            argon2_p_cost: wire::slice_u32(&bytes[150..])?,
            wrap_nonce: bytes[154..166]
                .try_into()
                .map_err(|_| Error::corrupt("wrap_nonce"))?,
            wrapped_chain_key: bytes[166..214]
                .try_into()
                .map_err(|_| Error::corrupt("wrapped_chain_key"))?,
        };
        superblock.validate_header()?;
        Ok(superblock)
    }

    /// Verify `sb_mac` with the image's authentication key (spec §G.3).
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] when the MAC does not match, which means the
    /// header was modified after it was written.
    pub fn verify_mac(&self, bytes: &[u8; SB_SIZE], meta_key: Option<&[u8; 32]>) -> Result<()> {
        let stored: [u8; 32] = bytes[SB_MAC_OFFSET..SB_MAC_OFFSET + 32]
            .try_into()
            .map_err(|_| Error::corrupt("sb_mac"))?;
        if verify_mac32(
            &Self::authentication_key(meta_key),
            &bytes[..SB_MAC_OFFSET],
            &stored,
        ) {
            Ok(())
        } else {
            Err(Error::corrupt("superblock MAC mismatch"))
        }
    }
}

fn is_power_of_two_in_range(value: u32, min: u32, max: u32) -> bool {
    value.is_power_of_two() && (min..=max).contains(&value)
}

#[cfg(test)]
mod tests {
    use super::{FORMAT_MAJOR, SB_MAGIC, SB_SIZE, Superblock, flags};
    use lr_core::{Consistency, Id, ImageId, ImageKind};
    use lr_crypto::aead::{AEAD_ID_AES_256_GCM, AeadKind};

    pub(crate) fn sample() -> Superblock {
        Superblock {
            format_major: FORMAT_MAJOR,
            min_reader: 1,
            flags: flags::ENCRYPTED,
            image_kind: ImageKind::Block,
            consistency: Consistency::Offline,
            image_uuid: ImageId::new(Id::from_bytes([0x01; 16])),
            chain_id: lr_core::ChainId::new(Id::from_bytes([0x02; 16])),
            set_id: lr_core::SetId::new(Id::from_bytes([0x03; 16])),
            parent_uuid: ImageId::ZERO,
            seq_in_chain: 0,
            created_unix: 1_800_000_000,
            source_size_bytes: 64 * 1024 * 1024 * 1024,
            logical_block_size: 512,
            chunk_size: 1024 * 1024,
            kdf_id: 1,
            aead_id: AEAD_ID_AES_256_GCM,
            kdf_salt: [0x04; 16],
            argon2_m_cost_kib: 256 * 1024,
            argon2_t_cost: 3,
            argon2_p_cost: 4,
            wrap_nonce: [0x05; 12],
            wrapped_chain_key: [0x06; 48],
        }
    }

    #[test]
    fn layout_matches_the_normative_offsets() {
        let bytes = sample().encode(Some(&[0xAB; 32])).expect("encode");
        assert_eq!(&bytes[0..8], &SB_MAGIC);
        assert_eq!(&bytes[8..12], &1u32.to_le_bytes());
        assert_eq!(bytes[24], 1, "image_kind block");
        assert_eq!(bytes[25], 2, "consistency offline");
        assert_eq!(&bytes[114..118], &(1024u32 * 1024).to_le_bytes());
        assert_eq!(&bytes[118..122], &1u32.to_le_bytes(), "kdf_id");
        assert_eq!(&bytes[122..126], &1u32.to_le_bytes(), "aead_id");
        assert_eq!(&bytes[126..142], &[0x04; 16]);
        assert_ne!(&bytes[1024..1056], &[0u8; 32], "sb_hash must be filled");
        assert_ne!(&bytes[1056..1088], &[0u8; 32], "sb_mac must be filled");
        assert_eq!(
            &bytes[1088..],
            &vec![0u8; SB_SIZE - 1088][..],
            "reserved zero"
        );
    }

    #[test]
    fn round_trips() {
        let key = [0x11u8; 32];
        let bytes = sample().encode(Some(&key)).expect("encode");
        let decoded = Superblock::decode(&bytes).expect("decode");
        assert_eq!(decoded, sample());
        decoded.verify_mac(&bytes, Some(&key)).expect("mac");
    }

    #[test]
    fn a_flipped_flag_byte_breaks_the_hash() {
        let key = [0x11u8; 32];
        let mut bytes = sample().encode(Some(&key)).expect("encode");
        bytes[16] ^= 0x01; // flags
        assert!(
            Superblock::decode(&bytes).is_err(),
            "sb_hash must catch this"
        );
    }

    #[test]
    fn tampering_with_a_mac_covered_field_breaks_the_mac() {
        let key = [0x11u8; 32];
        let mut bytes = sample().encode(Some(&key)).expect("encode");
        // repair the unkeyed hash so only the MAC can catch the change
        bytes[166] ^= 0x01;
        let fixed = lr_crypto::mac::unkeyed_mac32(&bytes[..1024]);
        bytes[1024..1056].copy_from_slice(&fixed);
        let decoded = Superblock::decode(&bytes).expect("hash is valid again");
        assert!(decoded.verify_mac(&bytes, Some(&key)).is_err());
        assert!(decoded.verify_mac(&bytes, Some(&[0x22; 32])).is_err());
    }

    #[test]
    fn wrong_key_fails_the_mac() {
        let bytes = sample().encode(Some(&[0x11; 32])).expect("encode");
        let decoded = Superblock::decode(&bytes).expect("decode");
        assert!(decoded.verify_mac(&bytes, Some(&[0x99; 32])).is_err());
    }

    #[test]
    fn unencrypted_images_use_the_public_key() {
        let bytes = sample().encode(None).expect("encode");
        let decoded = Superblock::decode(&bytes).expect("decode");
        decoded
            .verify_mac(&bytes, None)
            .expect("public key verifies");
        assert!(decoded.verify_mac(&bytes, Some(&[0x11; 32])).is_err());
    }

    #[test]
    fn rejects_out_of_range_fields() {
        let mut superblock = sample();
        superblock.chunk_size = 1000; // not a power of two
        assert!(superblock.encode(Some(&[0; 32])).is_err());

        let mut superblock = sample();
        superblock.logical_block_size = 1234;
        assert!(superblock.encode(Some(&[0; 32])).is_err());

        let mut superblock = sample();
        superblock.kdf_id = 7;
        assert!(superblock.encode(None).is_err());

        let mut superblock = sample();
        superblock.aead_id = AeadKind::ChaCha20Poly1305.id();
        assert!(superblock.encode(None).is_ok());
    }

    #[test]
    fn unencrypted_images_record_kdf_id_zero() {
        let mut superblock = sample();
        superblock.flags = 0; // no ENCRYPTED bit
        superblock.kdf_id = 0;
        superblock.argon2_m_cost_kib = 0;
        superblock.argon2_t_cost = 0;
        superblock.argon2_p_cost = 0;
        superblock.wrap_nonce = [0; 12];
        superblock.wrapped_chain_key = [0; 48];
        let bytes = superblock.encode(None).expect("encode");
        assert_eq!(Superblock::decode(&bytes).expect("decode"), superblock);

        // An encrypted image must keep kdf_id = 1.
        let mut encrypted = superblock.clone();
        encrypted.flags = flags::ENCRYPTED;
        assert!(encrypted.encode(None).is_err());
    }

    #[test]
    fn rejects_a_newer_format() {
        let mut superblock = sample();
        superblock.format_major = FORMAT_MAJOR + 1;
        // encode refuses too; craft the bytes by hand
        let mut bytes = sample().encode(None).expect("encode");
        bytes[8..12].copy_from_slice(&(FORMAT_MAJOR + 1).to_le_bytes());
        let fixed = lr_crypto::mac::unkeyed_mac32(&bytes[..1024]);
        bytes[1024..1056].copy_from_slice(&fixed);
        assert!(Superblock::decode(&bytes).is_err());
        assert!(superblock.encode(None).is_err());
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = sample().encode(None).expect("encode");
        bytes[0] = b'X';
        assert!(Superblock::decode(&bytes).is_err());
    }
}
