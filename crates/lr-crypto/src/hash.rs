//! Keyed content hashing (spec §G.4 `dedup_key`, §G.2 manifest hashes).
//!
//! Content hashes are keyed with the chain's `dedup_key` so that an attacker
//! holding an image cannot fingerprint known plaintext by hashing it, and so
//! that two chains never share hash values.

/// Length of every content hash.
pub const HASH_LEN: usize = 32;

/// Hash a whole buffer with the chain's dedup key.
#[must_use]
pub fn content_hash(dedup_key: &[u8; HASH_LEN], data: &[u8]) -> [u8; HASH_LEN] {
    *blake3::keyed_hash(dedup_key, data).as_bytes()
}

/// Unkeyed hash, used only for structural integrity checks (`sb_hash`,
/// `footer_hash`) that must be verifiable before any key exists.
#[must_use]
pub fn unkeyed_hash(data: &[u8]) -> [u8; HASH_LEN] {
    *blake3::hash(data).as_bytes()
}

/// Streaming keyed hasher, for content that does not fit in one buffer.
pub struct ContentHasher {
    inner: blake3::Hasher,
}

impl ContentHasher {
    /// Start hashing with the chain's dedup key.
    #[must_use]
    pub fn new(dedup_key: &[u8; HASH_LEN]) -> Self {
        Self {
            inner: blake3::Hasher::new_keyed(dedup_key),
        }
    }

    /// Absorb more data.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finish and return the digest.
    #[must_use]
    pub fn finalize(&self) -> [u8; HASH_LEN] {
        *self.inner.finalize().as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::{ContentHasher, HASH_LEN, content_hash, unkeyed_hash};

    #[test]
    fn hash_is_keyed_and_stable() {
        let key_a = [0x11u8; HASH_LEN];
        let key_b = [0x22u8; HASH_LEN];
        assert_eq!(content_hash(&key_a, b"data"), content_hash(&key_a, b"data"));
        assert_ne!(content_hash(&key_a, b"data"), content_hash(&key_b, b"data"));
        assert_ne!(unkeyed_hash(b"data"), content_hash(&key_a, b"data"));
    }

    #[test]
    fn streaming_matches_one_shot() {
        let key = [0x33u8; HASH_LEN];
        let mut hasher = ContentHasher::new(&key);
        hasher.update(b"hello ");
        hasher.update(b"world");
        assert_eq!(hasher.finalize(), content_hash(&key, b"hello world"));
    }
}
