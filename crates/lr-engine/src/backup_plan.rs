//! Immutable resolution of one backup member after its set lock is acquired.

use lr_core::catalog::MemberKind;
use lr_core::{ChainId, Error, ImageId, Result, SetId};
use lr_store::{Destination, SetHandle};

use crate::backup::{BackupRequest, MemberType, ParentChain, resolve_parent_chain};

/// The producer whose on-disk encoding is selected by a resolved plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BackupMode {
    /// Fixed-size block chunks.
    Block,
    /// A complete file-tree manifest, irrespective of comparison policy.
    File,
    /// Btrfs send streams, optionally sent relative to a parent snapshot.
    BtrfsStream,
}

/// The physical manifest encoding, distinct from the requested chain role.
///
/// File incrementals and differentials both encode a complete file tree; v1
/// superblocks cannot recover which comparison policy produced that tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestEncoding {
    /// Complete block manifest, used by block fulls and differentials.
    BlockFull,
    /// Block delta manifest, used by block incrementals.
    BlockDelta,
    /// Full file-tree manifest, independent of incremental/differential policy.
    FileTree,
    /// Btrfs send-stream manifest.
    BtrfsSend,
}

/// Parent and effective policy selected for one backup member.
///
/// Call [`ResolvedBackupPlan::resolve`] only while the caller holds the set
/// lock. It resolves the catalog parent once and owns that result so producers
/// can share its ancestry without cloning parent vectors.
pub(crate) struct ResolvedBackupPlan {
    parent: Option<ParentChain>,
    member_type: MemberType,
    encoding: ManifestEncoding,
    set_id: SetId,
    chain_id: ChainId,
    seq_in_chain: u32,
    parent_uuid: ImageId,
}

impl ResolvedBackupPlan {
    /// Resolve the selected parent and effective member policy under the set lock.
    ///
    /// # Errors
    /// Returns [`Error::Unsupported`] for a stream differential or sequence
    /// overflow, and propagates parent/catalog resolution failures.
    pub(crate) fn resolve(
        request: &BackupRequest,
        mode: BackupMode,
        destination: &dyn Destination,
        set: &SetHandle,
        now: u64,
    ) -> Result<Self> {
        Self::validate_mode(mode, request.member_type)?;
        let parent = resolve_parent_chain(request, destination, set, now)?;
        Self::from_parent(
            mode,
            request.member_type,
            request.chain_id,
            request.set_id,
            parent,
        )
    }

    /// Refuse a mode/policy combination before source discovery or snapshots.
    pub(crate) fn validate_mode(mode: BackupMode, member_type: MemberType) -> Result<()> {
        if mode == BackupMode::BtrfsStream && member_type == MemberType::Differential {
            return Err(Error::unsupported(
                "btrfs Stream images are incremental or full; a differential would need the \
                 chain's first snapshot, which is not kept",
            ));
        }
        Ok(())
    }

    fn from_parent(
        mode: BackupMode,
        requested_type: MemberType,
        requested_chain_id: ChainId,
        requested_set_id: SetId,
        parent: Option<ParentChain>,
    ) -> Result<Self> {
        Self::validate_mode(mode, requested_type)?;
        if requested_type == MemberType::Full && parent.is_some() {
            return Err(Error::unsupported(
                "a full image cannot use a resolved parent",
            ));
        }

        let member_type = if parent.is_some() {
            requested_type
        } else {
            // A limit rollover resolves to no parent and starts a fresh full,
            // regardless of the requested incremental/differential policy.
            MemberType::Full
        };
        let (set_id, chain_id, seq_in_chain, parent_uuid) = match parent.as_ref() {
            Some(parent) => (
                parent.set_id,
                parent.chain_id,
                parent
                    .member
                    .seq_in_chain
                    .checked_add(1)
                    .ok_or_else(|| Error::unsupported("backup chain sequence overflow"))?,
                parent.member.image_uuid,
            ),
            None => (requested_set_id, requested_chain_id, 0, ImageId::ZERO),
        };
        let encoding = match (mode, member_type) {
            (BackupMode::Block, MemberType::Incremental) => ManifestEncoding::BlockDelta,
            (BackupMode::Block, MemberType::Full | MemberType::Differential) => {
                ManifestEncoding::BlockFull
            }
            (BackupMode::File, _) => ManifestEncoding::FileTree,
            (BackupMode::BtrfsStream, _) => ManifestEncoding::BtrfsSend,
        };

        Ok(Self {
            parent,
            member_type,
            encoding,
            set_id,
            chain_id,
            seq_in_chain,
            parent_uuid,
        })
    }

    /// The selected parent chain, borrowed so its member vectors are not cloned.
    #[must_use]
    pub(crate) fn parent(&self) -> Option<&ParentChain> {
        self.parent.as_ref()
    }

    /// Effective role after parent resolution and any chain-limit rollover.
    #[must_use]
    pub(crate) const fn member_type(&self) -> MemberType {
        self.member_type
    }

    /// Manifest bytes to write; this is not the chain comparison policy.
    #[must_use]
    pub(crate) const fn manifest_encoding(&self) -> ManifestEncoding {
        self.encoding
    }

    /// File-name role tag derived from the effective member type.
    #[must_use]
    pub(crate) const fn file_tag(&self) -> &'static str {
        self.member_type.file_tag()
    }

    /// Logical comparison/report role, derived from the effective member type.
    ///
    /// This is not interchangeable with the legacy catalog's structural
    /// classification from superblock flags: File incrementals and
    /// differentials both store full file-tree manifests.
    #[must_use]
    pub(crate) const fn member_kind(&self) -> MemberKind {
        match self.member_type {
            MemberType::Full => MemberKind::Full,
            MemberType::Incremental => MemberKind::Incremental,
            MemberType::Differential => MemberKind::Differential,
        }
    }

    /// Set identity, taken from the resolved parent when one exists.
    #[must_use]
    pub(crate) const fn set_id(&self) -> SetId {
        self.set_id
    }

    /// Chain identity, taken from the resolved parent when one exists.
    #[must_use]
    pub(crate) const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    /// Sequence number assigned to this member.
    #[must_use]
    pub(crate) const fn seq_in_chain(&self) -> u32 {
        self.seq_in_chain
    }

    /// Parent image UUID; zero for a fresh chain.
    #[must_use]
    pub(crate) const fn parent_uuid(&self) -> ImageId {
        self.parent_uuid
    }
}

#[cfg(test)]
mod tests {
    use super::{BackupMode, ManifestEncoding, ResolvedBackupPlan};
    use crate::backup::{MemberType, ParentChain};
    use lr_core::catalog::{MemberKind, MemberRecord};
    use lr_core::{ChainId, Consistency, Id, ImageId, ImageKind, SetId};
    use lr_format::{FORMAT_MAJOR, MIN_READER, Superblock};

    const REQUEST_CHAIN_ID: ChainId = ChainId::new(Id::from_bytes([0x11; 16]));
    const REQUEST_SET_ID: SetId = SetId::new(Id::from_bytes([0x12; 16]));
    const PARENT_CHAIN_ID: ChainId = ChainId::new(Id::from_bytes([0x21; 16]));
    const PARENT_SET_ID: SetId = SetId::new(Id::from_bytes([0x22; 16]));
    const PARENT_IMAGE_ID: ImageId = ImageId::new(Id::from_bytes([0x23; 16]));

    fn parent_chain(mode: BackupMode, seq_in_chain: u32) -> ParentChain {
        let image_kind = match mode {
            BackupMode::Block => ImageKind::Block,
            BackupMode::File => ImageKind::File,
            BackupMode::BtrfsStream => ImageKind::Stream,
        };
        let member = MemberRecord {
            image_uuid: PARENT_IMAGE_ID,
            parent_uuid: ImageId::ZERO,
            kind: if seq_in_chain == 0 {
                MemberKind::Full
            } else {
                MemberKind::Incremental
            },
            seq_in_chain,
            image_kind,
            consistency: Consistency::Offline,
            created_unix: 10,
            source_label: String::new(),
            size_bytes: 1,
            file_name: "parent.lrimg".to_owned(),
            verified_unix: None,
        };
        let superblock = Superblock {
            format_major: FORMAT_MAJOR,
            min_reader: MIN_READER,
            flags: 0,
            image_kind,
            consistency: Consistency::Offline,
            image_uuid: PARENT_IMAGE_ID,
            chain_id: PARENT_CHAIN_ID,
            set_id: PARENT_SET_ID,
            parent_uuid: ImageId::ZERO,
            seq_in_chain,
            created_unix: 10,
            source_size_bytes: 1,
            logical_block_size: 512,
            chunk_size: 1024 * 1024,
            kdf_id: 0,
            aead_id: lr_crypto::AEAD_ID_AES_256_GCM,
            kdf_salt: [0; 16],
            argon2_m_cost_kib: 0,
            argon2_t_cost: 0,
            argon2_p_cost: 0,
            wrap_nonce: [0; 12],
            wrapped_chain_key: [0; 48],
        };
        ParentChain {
            member,
            chain_id: PARENT_CHAIN_ID,
            set_id: PARENT_SET_ID,
            prefix: Vec::new(),
            files: Vec::new(),
            superblock,
        }
    }

    #[test]
    fn resolved_mode_policy_and_rollover_matrix_keeps_encoding_separate() {
        let cases = [
            (
                BackupMode::Block,
                MemberType::Incremental,
                true,
                MemberType::Incremental,
                ManifestEncoding::BlockDelta,
                MemberKind::Incremental,
                "incr",
            ),
            (
                BackupMode::Block,
                MemberType::Differential,
                true,
                MemberType::Differential,
                ManifestEncoding::BlockFull,
                MemberKind::Differential,
                "diff",
            ),
            (
                BackupMode::File,
                MemberType::Incremental,
                true,
                MemberType::Incremental,
                ManifestEncoding::FileTree,
                MemberKind::Incremental,
                "incr",
            ),
            (
                BackupMode::File,
                MemberType::Differential,
                true,
                MemberType::Differential,
                ManifestEncoding::FileTree,
                MemberKind::Differential,
                "diff",
            ),
            (
                BackupMode::BtrfsStream,
                MemberType::Incremental,
                true,
                MemberType::Incremental,
                ManifestEncoding::BtrfsSend,
                MemberKind::Incremental,
                "incr",
            ),
            (
                BackupMode::Block,
                MemberType::Incremental,
                false,
                MemberType::Full,
                ManifestEncoding::BlockFull,
                MemberKind::Full,
                "full",
            ),
            (
                BackupMode::File,
                MemberType::Differential,
                false,
                MemberType::Full,
                ManifestEncoding::FileTree,
                MemberKind::Full,
                "full",
            ),
            (
                BackupMode::BtrfsStream,
                MemberType::Incremental,
                false,
                MemberType::Full,
                ManifestEncoding::BtrfsSend,
                MemberKind::Full,
                "full",
            ),
        ];

        for (mode, requested, has_parent, effective, encoding, kind, file_tag) in cases {
            let parent = has_parent.then(|| parent_chain(mode, 7));
            let plan = ResolvedBackupPlan::from_parent(
                mode,
                requested,
                REQUEST_CHAIN_ID,
                REQUEST_SET_ID,
                parent,
            )
            .expect("resolve mode/policy row");
            assert_eq!(plan.member_type(), effective);
            assert_eq!(plan.manifest_encoding(), encoding);
            assert_eq!(plan.member_kind(), kind);
            assert_eq!(plan.file_tag(), file_tag);
            if has_parent {
                assert_eq!(plan.set_id(), PARENT_SET_ID);
                assert_eq!(plan.chain_id(), PARENT_CHAIN_ID);
                assert_eq!(plan.seq_in_chain(), 8);
                assert_eq!(plan.parent_uuid(), PARENT_IMAGE_ID);
                assert!(plan.parent().is_some());
            } else {
                assert_eq!(plan.set_id(), REQUEST_SET_ID);
                assert_eq!(plan.chain_id(), REQUEST_CHAIN_ID);
                assert_eq!(plan.seq_in_chain(), 0);
                assert_eq!(plan.parent_uuid(), ImageId::ZERO);
                assert!(plan.parent().is_none());
            }
        }

        let mut zero_set_parent = parent_chain(BackupMode::File, 0);
        zero_set_parent.set_id = SetId::ZERO;
        zero_set_parent.superblock.set_id = SetId::ZERO;
        let plan = ResolvedBackupPlan::from_parent(
            BackupMode::File,
            MemberType::Incremental,
            REQUEST_CHAIN_ID,
            REQUEST_SET_ID,
            Some(zero_set_parent),
        )
        .expect("retain the parent's exact identity, including a zero set ID");
        assert_eq!(plan.set_id(), SetId::ZERO);

        assert!(
            ResolvedBackupPlan::from_parent(
                BackupMode::BtrfsStream,
                MemberType::Differential,
                REQUEST_CHAIN_ID,
                REQUEST_SET_ID,
                Some(parent_chain(BackupMode::BtrfsStream, 1)),
            )
            .is_err(),
            "stream differentials remain unsupported"
        );
        assert!(
            ResolvedBackupPlan::from_parent(
                BackupMode::Block,
                MemberType::Incremental,
                REQUEST_CHAIN_ID,
                REQUEST_SET_ID,
                Some(parent_chain(BackupMode::Block, u32::MAX)),
            )
            .is_err(),
            "sequence overflow must refuse the extension"
        );
    }
}
