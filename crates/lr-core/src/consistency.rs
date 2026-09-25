//! Consistency levels actually achieved by a backup (spec §D.2).
//!
//! The ordering is deliberate: [`Consistency::PointInTime`] is the strongest
//! level, [`Consistency::None`] the weakest. Whole-disk images report the
//! minimum across partitions, so `Ord` is implemented as strength ordering.

/// How consistent a produced image is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Consistency {
    /// All blocks/tree reflect one instant, filesystem quiesced at that instant.
    PointInTime,
    /// Filesystem frozen for the whole read; writers blocked for the duration.
    Frozen,
    /// Device was unmounted and holder-free during the read.
    Offline,
    /// Each file consistent as read; no cross-file point in time (file mode).
    PerFile,
    /// Live raw read of a mounted device; torn blocks possible.
    None,
}

impl Consistency {
    /// All levels from strongest to weakest.
    pub const ALL: [Self; 5] = [
        Self::PointInTime,
        Self::Frozen,
        Self::Offline,
        Self::PerFile,
        Self::None,
    ];

    /// Strength rank; higher is stronger.
    #[must_use]
    pub const fn strength(self) -> u8 {
        match self {
            Self::PointInTime => 4,
            Self::Frozen => 3,
            Self::Offline => 2,
            Self::PerFile => 1,
            Self::None => 0,
        }
    }

    /// `true` when the image reflects a single instant in time.
    #[must_use]
    pub const fn is_point_in_time(self) -> bool {
        matches!(self, Self::PointInTime)
    }

    /// The weaker of two levels. Used for whole-disk image summaries.
    #[must_use]
    pub fn minimum(self, other: Self) -> Self {
        if self.strength() <= other.strength() {
            self
        } else {
            other
        }
    }

    /// Short human-readable label for CLI output.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::PointInTime => "point-in-time",
            Self::Frozen => "frozen",
            Self::Offline => "offline",
            Self::PerFile => "per-file",
            Self::None => "none (inconsistent)",
        }
    }

    /// On-disk discriminant used by the image superblock (spec §G.3).
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::PointInTime => 0,
            Self::Frozen => 1,
            Self::Offline => 2,
            Self::PerFile => 3,
            Self::None => 4,
        }
    }

    /// Parse an on-disk discriminant.
    ///
    /// # Errors
    /// Returns [`crate::Error::Corrupt`] for an unknown value; a reader must
    /// not invent a consistency level it did not find on disk.
    pub fn from_u8(value: u8) -> crate::Result<Self> {
        match value {
            0 => Ok(Self::PointInTime),
            1 => Ok(Self::Frozen),
            2 => Ok(Self::Offline),
            3 => Ok(Self::PerFile),
            4 => Ok(Self::None),
            other => Err(crate::Error::corrupt(format!(
                "unknown consistency level {other}"
            ))),
        }
    }
}

impl std::fmt::Display for Consistency {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

impl PartialOrd for Consistency {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Consistency {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.strength().cmp(&other.strength())
    }
}

#[cfg(test)]
mod tests {
    use super::Consistency;

    #[test]
    fn ordering_is_strength_based() {
        assert!(Consistency::PointInTime > Consistency::Frozen);
        assert!(Consistency::Frozen > Consistency::Offline);
        assert!(Consistency::Offline > Consistency::PerFile);
        assert!(Consistency::PerFile > Consistency::None);
    }

    #[test]
    fn minimum_picks_weakest() {
        assert_eq!(
            Consistency::PointInTime.minimum(Consistency::None),
            Consistency::None
        );
        assert_eq!(
            Consistency::Frozen.minimum(Consistency::Offline),
            Consistency::Offline
        );
    }

    #[test]
    fn serde_uses_snake_case() {
        let json = serde_json::to_string(&Consistency::PointInTime).expect("serialize");
        assert_eq!(json, "\"point_in_time\"");
        let back: Consistency = serde_json::from_str("\"per_file\"").expect("deserialize");
        assert_eq!(back, Consistency::PerFile);
    }

    #[test]
    fn on_disk_discriminants_match_the_spec_table() {
        for (index, level) in Consistency::ALL.iter().enumerate() {
            assert_eq!(usize::from(level.as_u8()), index);
            assert_eq!(Consistency::from_u8(level.as_u8()).expect("known"), *level);
        }
        assert!(Consistency::from_u8(5).is_err());
    }
}
