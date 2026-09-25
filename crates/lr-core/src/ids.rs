//! 128-bit identifiers used throughout the image format (spec §G.3).
//!
//! LinuxReflect deliberately avoids a UUID dependency: identifiers are stored
//! as raw 16-byte values in the superblock and rendered as canonical UUID
//! strings for humans and JSON.

use std::fmt;
use std::str::FromStr;

use crate::error::Error;

/// A 128-bit identifier (image UUID, chain id, set id, ...).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Id([u8; 16]);

impl Id {
    /// The all-zero identifier; used for "no parent" in the superblock.
    pub const ZERO: Self = Self([0u8; 16]);

    /// Wrap raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// `true` when this is [`Id::ZERO`].
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 16]
    }

    /// Generate a random version-4 identifier from `/dev/urandom`.
    ///
    /// # Errors
    /// Propagates I/O failures from opening or reading `/dev/urandom`.
    ///
    /// # Panics
    /// Panics if `/dev/urandom` yields fewer than 16 bytes, which indicates a
    /// broken kernel entropy source.
    pub fn generate() -> std::io::Result<Self> {
        use std::io::Read;

        let mut bytes = [0u8; 16];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
        bytes[8] = (bytes[8] & 0x3f) | 0x80; // RFC 4122 variant
        Ok(Self(bytes))
    }

    /// Canonical hyphenated UUID string.
    #[must_use]
    pub fn to_uuid_string(&self) -> String {
        let b = self.0;
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[0],
            b[1],
            b[2],
            b[3],
            b[4],
            b[5],
            b[6],
            b[7],
            b[8],
            b[9],
            b[10],
            b[11],
            b[12],
            b[13],
            b[14],
            b[15]
        )
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_uuid_string())
    }
}

impl fmt::Debug for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Id({})", self.to_uuid_string())
    }
}

impl FromStr for Id {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex: String = s.chars().filter(|c| *c != '-').collect();
        if hex.len() != 32 {
            return Err(Error::corrupt(format!(
                "identifier '{s}' is not 32 hex digits"
            )));
        }
        let mut bytes = [0u8; 16];
        for (i, byte) in bytes.iter_mut().enumerate() {
            let slice = &hex[i * 2..i * 2 + 2];
            *byte = u8::from_str_radix(slice, 16)
                .map_err(|_| Error::corrupt(format!("identifier '{s}' is not hexadecimal")))?;
        }
        Ok(Self(bytes))
    }
}

impl serde::Serialize for Id {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_uuid_string())
    }
}

impl<'de> serde::Deserialize<'de> for Id {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = <String as serde::Deserialize>::deserialize(deserializer)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

macro_rules! id_newtype {
    ($name:ident, $what:literal) => {
        #[doc = concat!("A ", $what, " identifier (spec §G.3).")]
        #[derive(
            Clone,
            Copy,
            PartialEq,
            Eq,
            Hash,
            PartialOrd,
            Ord,
            Default,
            serde::Serialize,
            serde::Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub Id);

        impl $name {
            /// The all-zero identifier.
            pub const ZERO: Self = Self(Id::ZERO);

            /// Wrap an [`Id`].
            #[must_use]
            pub const fn new(id: Id) -> Self {
                Self(id)
            }

            /// Borrow the inner [`Id`].
            #[must_use]
            pub const fn inner(&self) -> &Id {
                &self.0
            }
        }

        impl From<Id> for $name {
            fn from(id: Id) -> Self {
                Self(id)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.0)
            }
        }
    };
}

id_newtype!(ImageId, "image");
id_newtype!(ChainId, "chain");
id_newtype!(SetId, "backup set");

impl std::str::FromStr for ImageId {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.parse()?))
    }
}

impl std::str::FromStr for ChainId {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.parse()?))
    }
}

impl std::str::FromStr for SetId {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.parse()?))
    }
}

#[cfg(test)]
mod tests {
    use super::Id;

    #[test]
    fn uuid_round_trip() {
        let id = Id::generate().expect("/dev/urandom");
        let text = id.to_uuid_string();
        let parsed: Id = text.parse().expect("parse");
        assert_eq!(id, parsed);
        assert_eq!(text.len(), 36);
        assert_eq!(text.as_bytes()[14], b'4', "version 4 marker");
    }

    #[test]
    fn zero_is_zero() {
        assert!(Id::ZERO.is_zero());
        assert_eq!(Id::ZERO.to_string(), "00000000-0000-0000-0000-000000000000");
    }

    #[test]
    fn rejects_bad_input() {
        assert!("not-a-uuid".parse::<Id>().is_err());
        assert!(
            "00000000-0000-0000-0000-00000000000g"
                .parse::<Id>()
                .is_err()
        );
    }

    #[test]
    fn serde_is_string_based() {
        let id = Id::generate().expect("/dev/urandom");
        let json = serde_json::to_string(&id).expect("serialize");
        assert_eq!(json, format!("\"{id}\""));
        let back: Id = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(id, back);
    }
}
