//! Nonce counters (spec §G.4).
//!
//! Images are write-once: a `.tmp` file is never resumed, and a retry creates a
//! new `image_uuid` and therefore new keys. Nonce reuse is impossible by
//! construction as long as at most one file is written per key. This type
//! enforces the remaining half of the contract: a single monotonic counter that
//! cannot be cloned, reset, or allowed to wrap around.

use lr_core::{Error, Result};

/// Length of an AEAD nonce.
pub const NONCE_LEN: usize = 12;

/// Largest counter value that still fits in 96 bits.
const MAX_COUNTER: u128 = (1u128 << 96) - 1;

/// A monotonic 96-bit big-endian nonce counter.
///
/// This type is deliberately **not** `Clone`, `Copy` or `Default` and exposes
/// no setter, so two independent writers cannot accidentally emit the same
/// nonce sequence:
///
/// ```compile_fail
/// let mut seq = lr_crypto::NonceSeq::new();
/// let _ = seq.clone();
/// ```
pub struct NonceSeq {
    counter: u128,
}

impl NonceSeq {
    /// Start a fresh sequence at zero.
    ///
    /// `Default` is deliberately **not** implemented: a default-constructed
    /// counter would invite accidental resets, which is exactly what the
    /// write-once nonce contract forbids.
    #[must_use]
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self { counter: 0 }
    }

    /// Number of nonces already handed out.
    #[must_use]
    pub const fn emitted(&self) -> u128 {
        self.counter
    }

    /// Return the next nonce, advancing the counter.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] if the 96-bit counter would overflow; a
    /// wrapped counter would repeat a nonce under the same key.
    pub fn next_nonce(&mut self) -> Result<[u8; NONCE_LEN]> {
        if self.counter > MAX_COUNTER {
            return Err(Error::corrupt("nonce counter exhausted (96-bit overflow)"));
        }
        let nonce = self.counter.to_be_bytes();
        let mut out = [0u8; NONCE_LEN];
        // The 96-bit nonce is the low three 32-bit words of the big-endian u128.
        out.copy_from_slice(&nonce[4..16]);
        self.counter += 1;
        Ok(out)
    }
}

impl std::fmt::Debug for NonceSeq {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NonceSeq(emitted = {})", self.counter)
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_COUNTER, NonceSeq};

    #[test]
    fn counts_up_in_big_endian() {
        let mut seq = NonceSeq::new();
        let first = seq.next_nonce().expect("nonce");
        let second = seq.next_nonce().expect("nonce");
        assert_eq!(first, [0u8; 12]);
        assert_eq!(&second[..], &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(seq.emitted(), 2);
    }

    #[test]
    fn one_counter_step_changes_the_last_byte() {
        let mut seq = NonceSeq::new();
        for _ in 0..255 {
            seq.next_nonce().expect("nonce");
        }
        let nonce = seq.next_nonce().expect("nonce");
        assert_eq!(nonce, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff]);
        let nonce = seq.next_nonce().expect("nonce");
        assert_eq!(nonce, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x00]);
    }

    #[test]
    fn separate_counters_do_not_share_state() {
        // The data and metadata keys each get their own counter, and both start
        // at zero. That is safe precisely because the keys differ and a file is
        // never resumed; what would be unsafe is cloning one counter, which the
        // type makes impossible.
        let mut data = NonceSeq::new();
        let mut meta = NonceSeq::new();
        for expected in 0..3u8 {
            let from_data = data.next_nonce().expect("nonce");
            let from_meta = meta.next_nonce().expect("nonce");
            assert_eq!(from_data[11], expected);
            assert_eq!(from_meta, from_data);
            assert_eq!(data.emitted(), u128::from(expected) + 1);
            assert_eq!(meta.emitted(), u128::from(expected) + 1);
        }
    }

    #[test]
    fn overflow_is_refused_instead_of_wrapping() {
        // Only reachable through the module's own test, never through the API.
        let mut seq = NonceSeq {
            counter: MAX_COUNTER,
        };
        assert!(seq.next_nonce().is_ok());
        assert!(seq.next_nonce().is_err(), "must refuse to wrap the counter");
    }
}
