//! Message authentication for image headers (spec §G.3 `sb_mac`, §G.6 `footer_mac`).
//!
//! Headers are authenticated with keyed BLAKE3 under the image's `meta_key`.
//! Unencrypted images (`--no-encrypt`) still carry a MAC, but under a fixed,
//! public key: that detects accidental corruption, not tampering, and the CLI
//! says so (spec §G.3).

/// Length of a MAC.
pub const FIXED_PUBLIC_MAC_KEY_LEN: usize = 32;

/// Keyed MAC over a buffer.
#[must_use]
pub fn mac32(key: &[u8; FIXED_PUBLIC_MAC_KEY_LEN], data: &[u8]) -> [u8; FIXED_PUBLIC_MAC_KEY_LEN] {
    *blake3::keyed_hash(key, data).as_bytes()
}

/// Unkeyed digest, used for `sb_hash`/`footer_hash` (corruption check only).
#[must_use]
pub fn unkeyed_mac32(data: &[u8]) -> [u8; FIXED_PUBLIC_MAC_KEY_LEN] {
    *blake3::hash(data).as_bytes()
}

/// Constant-time comparison of a computed MAC against an expected value.
#[must_use]
pub fn verify_mac32(
    key: &[u8; FIXED_PUBLIC_MAC_KEY_LEN],
    data: &[u8],
    expected: &[u8; FIXED_PUBLIC_MAC_KEY_LEN],
) -> bool {
    // blake3::Hash equality is constant time.
    blake3::Hash::from_bytes(*expected) == blake3::keyed_hash(key, data)
}

/// The fixed public MAC key used by `--no-encrypt` images.
///
/// It is derived once from a domain-separation string so that it is a
/// well-defined constant rather than an unexplained blob of bytes.
#[must_use]
pub fn fixed_public_mac_key() -> [u8; FIXED_PUBLIC_MAC_KEY_LEN] {
    blake3::derive_key("lrimg-v1/no-encrypt-mac", b"")
}

#[cfg(test)]
mod tests {
    use super::{fixed_public_mac_key, mac32, unkeyed_mac32, verify_mac32};

    #[test]
    fn mac_is_keyed() {
        let key = [0x7au8; 32];
        let other = [0x7bu8; 32];
        assert_eq!(mac32(&key, b"header"), mac32(&key, b"header"));
        assert_ne!(mac32(&key, b"header"), mac32(&other, b"header"));
        assert_ne!(mac32(&key, b"header"), unkeyed_mac32(b"header"));
    }

    #[test]
    fn verify_detects_a_flipped_bit() {
        let key = fixed_public_mac_key();
        let mut data = *b"superblock bytes";
        let expected = mac32(&key, &data);
        assert!(verify_mac32(&key, &data, &expected));
        data[0] ^= 0x01;
        assert!(!verify_mac32(&key, &data, &expected));
    }

    #[test]
    fn public_key_is_stable_and_not_all_zero() {
        let key = fixed_public_mac_key();
        assert_eq!(key, fixed_public_mac_key());
        assert_ne!(key, [0u8; 32]);
    }
}
