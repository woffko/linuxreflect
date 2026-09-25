//! Catalog records for a backup set (spec §D.3).
//!
//! The catalog is a *plaintext cache* at `<set>/catalog.json`. It is never
//! authoritative: the engine validates it against member superblocks (which are
//! MAC'd) and can rebuild it with `linuxreflect catalog rebuild`.

use crate::{ChainId, Consistency, ImageId, ImageKind, SetId};

/// The role of a chain member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberKind {
    /// Sequence 0: carries a full manifest and all chunks.
    Full,
    /// Sequence n: delta manifest over the previous member.
    Incremental,
    /// A full manifest that reuses chunks stored in ancestors.
    Differential,
}

impl MemberKind {
    /// `true` for members that carry a complete manifest.
    #[must_use]
    pub const fn has_full_manifest(self) -> bool {
        matches!(self, Self::Full | Self::Differential)
    }
}

/// One member (image file) of a chain.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MemberRecord {
    /// Image UUID; also part of the file name.
    pub image_uuid: ImageId,
    /// Parent image UUID; zero for a full.
    pub parent_uuid: ImageId,
    /// Member role.
    pub kind: MemberKind,
    /// Position in the chain; 0 is the full.
    pub seq_in_chain: u32,
    /// Image kind stored in the file.
    pub image_kind: ImageKind,
    /// Consistency level achieved when this member was written.
    pub consistency: Consistency,
    /// Creation time, seconds since the Unix epoch.
    pub created_unix: u64,
    /// Source label recorded at backup time.
    pub source_label: String,
    /// File size in bytes.
    pub size_bytes: u64,
    /// File name inside the set directory.
    pub file_name: String,
}

/// One chain: a full plus its incrementals/differentials.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChainRecord {
    /// Chain identifier; identical for every member, embedded in `kdf_salt`.
    pub chain_id: ChainId,
    /// Creation time of the full, seconds since the Unix epoch.
    pub created_unix: u64,
    /// Source label for the whole chain.
    pub source_label: String,
    /// Members, ordered by `seq_in_chain`.
    pub members: Vec<MemberRecord>,
}

impl ChainRecord {
    /// Highest sequence number present in the chain.
    #[must_use]
    pub fn latest_seq(&self) -> Option<u32> {
        self.members.iter().map(|m| m.seq_in_chain).max()
    }

    /// The newest member by sequence number.
    #[must_use]
    pub fn latest_member(&self) -> Option<&MemberRecord> {
        self.members.iter().max_by_key(|m| m.seq_in_chain)
    }

    /// Look up a member by image UUID.
    #[must_use]
    pub fn member(&self, image_uuid: ImageId) -> Option<&MemberRecord> {
        self.members.iter().find(|m| m.image_uuid == image_uuid)
    }

    /// A chain is complete when it starts with a full at sequence 0 and has no
    /// gaps before the latest member (spec §J.3).
    #[must_use]
    pub fn is_complete(&self) -> bool {
        let mut seqs: Vec<u32> = self.members.iter().map(|m| m.seq_in_chain).collect();
        seqs.sort_unstable();
        if seqs.first() != Some(&0) {
            return false;
        }
        let contiguous = seqs
            .iter()
            .enumerate()
            .all(|(position, seq)| u32::try_from(position).unwrap_or(u32::MAX) == *seq);
        if !contiguous {
            return false;
        }
        self.members
            .iter()
            .find(|m| m.seq_in_chain == 0)
            .is_some_and(|m| m.kind == MemberKind::Full)
    }

    /// Number of incrementals/differentials after the full.
    #[must_use]
    pub fn incremental_count(&self) -> usize {
        self.members.iter().filter(|m| m.seq_in_chain > 0).count()
    }
}

/// Catalog for one backup set.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Catalog {
    /// Catalog schema version.
    pub version: u32,
    /// Backup set identifier.
    pub set_id: SetId,
    /// Human-readable set name.
    pub set_name: String,
    /// Last update time, seconds since the Unix epoch.
    pub updated_unix: u64,
    /// Chains known to this set.
    pub chains: Vec<ChainRecord>,
}

/// Current catalog schema version.
pub const CATALOG_VERSION: u32 = 1;

impl Catalog {
    /// Create an empty catalog for a set.
    #[must_use]
    pub fn new(set_id: SetId, set_name: impl Into<String>, updated_unix: u64) -> Self {
        Self {
            version: CATALOG_VERSION,
            set_id,
            set_name: set_name.into(),
            updated_unix,
            chains: Vec::new(),
        }
    }

    /// Find a chain by id.
    #[must_use]
    pub fn chain(&self, chain_id: ChainId) -> Option<&ChainRecord> {
        self.chains.iter().find(|c| c.chain_id == chain_id)
    }

    /// The newest chain by creation time.
    #[must_use]
    pub fn latest_chain(&self) -> Option<&ChainRecord> {
        self.chains.iter().max_by_key(|c| c.created_unix)
    }

    /// Insert or replace a chain record.
    pub fn upsert_chain(&mut self, chain: ChainRecord) {
        match self
            .chains
            .iter_mut()
            .find(|c| c.chain_id == chain.chain_id)
        {
            Some(existing) => *existing = chain,
            None => self.chains.push(chain),
        }
    }

    /// Chains ordered oldest first, ready for retention (spec §J.3).
    #[must_use]
    pub fn chains_oldest_first(&self) -> Vec<&ChainRecord> {
        let mut chains: Vec<&ChainRecord> = self.chains.iter().collect();
        chains.sort_by_key(|c| (c.created_unix, c.chain_id));
        chains
    }
}

#[cfg(test)]
mod tests {
    use super::{Catalog, ChainRecord, MemberKind, MemberRecord};
    use crate::{ChainId, Consistency, Id, ImageId, ImageKind, SetId};

    fn member(seq: u32, kind: MemberKind, created: u64) -> MemberRecord {
        MemberRecord {
            image_uuid: ImageId::new(Id::from_bytes([seq as u8; 16])),
            parent_uuid: ImageId::ZERO,
            kind,
            seq_in_chain: seq,
            image_kind: ImageKind::Block,
            consistency: Consistency::Offline,
            created_unix: created,
            source_label: "/dev/sda1".to_owned(),
            size_bytes: 1024,
            file_name: format!("{seq}-full.lrimg"),
        }
    }

    fn chain(created: u64, seqs: &[(u32, MemberKind)]) -> ChainRecord {
        ChainRecord {
            chain_id: ChainId::new(Id::from_bytes([created as u8; 16])),
            created_unix: created,
            source_label: "/dev/sda1".to_owned(),
            members: seqs.iter().map(|(s, k)| member(*s, *k, created)).collect(),
        }
    }

    #[test]
    fn complete_chain_detection() {
        let ok = chain(10, &[(0, MemberKind::Full), (1, MemberKind::Incremental)]);
        assert!(ok.is_complete());
        assert_eq!(ok.incremental_count(), 1);

        let gap = chain(11, &[(0, MemberKind::Full), (2, MemberKind::Incremental)]);
        assert!(!gap.is_complete());

        let missing_full = chain(12, &[(1, MemberKind::Incremental)]);
        assert!(!missing_full.is_complete());
    }

    #[test]
    fn retention_ordering_and_latest() {
        let mut catalog = Catalog::new(SetId::ZERO, "set", 0);
        catalog.upsert_chain(chain(20, &[(0, MemberKind::Full)]));
        catalog.upsert_chain(chain(10, &[(0, MemberKind::Full)]));
        assert_eq!(catalog.latest_chain().expect("latest").created_unix, 20);
        let order: Vec<u64> = catalog
            .chains_oldest_first()
            .iter()
            .map(|c| c.created_unix)
            .collect();
        assert_eq!(order, vec![10, 20]);
    }

    #[test]
    fn catalog_json_round_trip() {
        let mut catalog = Catalog::new(SetId::ZERO, "laptop-root", 42);
        catalog.upsert_chain(chain(10, &[(0, MemberKind::Full)]));
        let json = serde_json::to_string_pretty(&catalog).expect("serialize");
        let back: Catalog = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(catalog, back);
    }
}
