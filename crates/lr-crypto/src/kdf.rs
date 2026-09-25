//! Argon2id password stretching (spec §G.3 `kdf_id`, §G.4 `KEK`).
//!
//! The KEK is derived once per chain and never stored. Only the parameters and
//! the salt live in the superblock, so a reader can reproduce the KEK from the
//! passphrase alone.

use argon2::{Algorithm, Argon2, Params, Version};
use lr_core::{Error, Result};
use zeroize::Zeroizing;

/// `kdf_id` value for Argon2id (spec §G.3).
pub const KDF_ID_ARGON2ID: u32 = 1;

/// Length of `kdf_salt` in the superblock.
pub const SALT_LEN: usize = 16;

/// Length of the derived KEK.
pub const KEK_LEN: usize = 32;

/// Spec default memory cost in KiB (256 MiB, RFC 9106 §4 recommendation).
pub const DEFAULT_M_COST_KIB: u32 = 256 * 1024;

/// Spec default iteration count.
pub const DEFAULT_T_COST: u32 = 3;

/// Spec default parallelism.
pub const DEFAULT_P_COST: u32 = 4;

/// Argon2id cost parameters as stored in the superblock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost_kib: u32,
    /// Time cost (iterations).
    pub t_cost: u32,
    /// Parallelism (lanes).
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost_kib: DEFAULT_M_COST_KIB,
            t_cost: DEFAULT_T_COST,
            p_cost: DEFAULT_P_COST,
        }
    }
}

impl KdfParams {
    /// Explicit parameters.
    #[must_use]
    pub const fn new(m_cost_kib: u32, t_cost: u32, p_cost: u32) -> Self {
        Self {
            m_cost_kib,
            t_cost,
            p_cost,
        }
    }

    /// Validate the parameters against Argon2's own limits.
    ///
    /// # Errors
    /// Returns [`Error::Unsupported`] when the parameters are outside the
    /// range accepted by the Argon2 implementation.
    pub fn validate(&self) -> Result<()> {
        Params::new(self.m_cost_kib, self.t_cost, self.p_cost, Some(KEK_LEN))
            .map(|_| ())
            .map_err(|e| Error::unsupported(format!("argon2 parameters: {e}")))
    }

    /// Convert to the `argon2` crate's validated parameter type.
    fn to_argon2(self) -> Result<Params> {
        Params::new(self.m_cost_kib, self.t_cost, self.p_cost, Some(KEK_LEN))
            .map_err(|e| Error::unsupported(format!("argon2 parameters: {e}")))
    }
}

/// The passphrase-derived key-encryption key.
///
/// The value is zeroized on drop and never printed.
pub struct Kek(Zeroizing<[u8; KEK_LEN]>);

impl Kek {
    /// Borrow the raw key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; KEK_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for Kek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Kek(<redacted>)")
    }
}

// The inner `Zeroizing` zeroizes on drop; this marker makes the guarantee
// visible to callers and to the test suite.
impl zeroize::ZeroizeOnDrop for Kek {}

/// Derive the KEK from a passphrase and the chain's salt (spec §G.4).
///
/// # Errors
/// Returns [`Error::Unsupported`] for out-of-range parameters; the Argon2
/// implementation is otherwise infallible for valid inputs.
pub fn derive_kek(passphrase: &[u8], salt: &[u8; SALT_LEN], params: KdfParams) -> Result<Kek> {
    let params = params.to_argon2()?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; KEK_LEN]);
    argon2
        .hash_password_into(passphrase, salt, out.as_mut())
        .map_err(|e| Error::unsupported(format!("argon2: {e}")))?;
    Ok(Kek(out))
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_M_COST_KIB, DEFAULT_P_COST, DEFAULT_T_COST, KdfParams, derive_kek};

    #[test]
    fn defaults_match_the_spec() {
        let params = KdfParams::default();
        assert_eq!(params.m_cost_kib, DEFAULT_M_COST_KIB);
        assert_eq!(params.t_cost, DEFAULT_T_COST);
        assert_eq!(params.p_cost, DEFAULT_P_COST);
        assert_eq!(params.m_cost_kib, 256 * 1024);
        assert_eq!(params.t_cost, 3);
        assert_eq!(params.p_cost, 4);
        assert!(params.validate().is_ok());
    }

    #[test]
    fn derivation_is_deterministic_and_salt_sensitive() {
        let cheap = KdfParams::new(32, 3, 4);
        let kek_a = derive_kek(b"passphrase", b"0123456789abcdef", cheap).expect("derive");
        let kek_b = derive_kek(b"passphrase", b"0123456789abcdef", cheap).expect("derive");
        let kek_c = derive_kek(b"passphrase", b"fedcba9876543210", cheap).expect("derive");
        assert_eq!(kek_a.as_bytes(), kek_b.as_bytes());
        assert_ne!(kek_a.as_bytes(), kek_c.as_bytes());
    }

    #[test]
    fn rejects_impossible_parameters() {
        assert!(KdfParams::new(1, 3, 4).validate().is_err());
        assert!(KdfParams::new(32, 0, 4).validate().is_err());
        assert!(KdfParams::new(32, 3, 0).validate().is_err());
    }

    #[test]
    fn debug_does_not_leak_key_material() {
        let kek = derive_kek(b"passphrase", b"0123456789abcdef", KdfParams::new(32, 1, 1))
            .expect("derive");
        assert_eq!(format!("{kek:?}"), "Kek(<redacted>)");
    }
}
