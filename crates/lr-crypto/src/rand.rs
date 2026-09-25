//! Random bytes from `/dev/urandom`.
//!
//! LinuxReflect deliberately does not depend on an RNG crate: identifiers and
//! keys come straight from the kernel CSPRNG, so no third-party RNG version can
//! change what lands on disk (see `docs/decisions.md` D-002).

use std::io::Read;

use lr_core::Result;

/// Path of the kernel CSPRNG.
pub const URANDOM: &str = "/dev/urandom";

/// Fill and return a fixed-size array of random bytes.
///
/// # Errors
/// Returns [`lr_core::Error::Io`] when `/dev/urandom` cannot be read.
pub fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    std::fs::File::open(URANDOM)?.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// Fill and return a vector of `len` random bytes.
///
/// # Errors
/// Returns [`lr_core::Error::Io`] when `/dev/urandom` cannot be read.
pub fn random_bytes_vec(len: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0u8; len];
    std::fs::File::open(URANDOM)?.read_exact(&mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::{random_bytes, random_bytes_vec};

    #[test]
    fn returns_requested_lengths() {
        let fixed: [u8; 32] = random_bytes().expect("urandom");
        let sized = random_bytes_vec(12).expect("urandom");
        assert_eq!(fixed.len(), 32);
        assert_eq!(sized.len(), 12);
    }

    #[test]
    fn does_not_repeat() {
        let first: [u8; 32] = random_bytes().expect("urandom");
        let second: [u8; 32] = random_bytes().expect("urandom");
        assert_ne!(first, second, "two 32-byte draws must not collide");
    }
}
