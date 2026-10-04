//! Bounded, content-bound facts from one captured verification attempt.

use lr_core::{ChainId, Consistency, Error, ImageId, ImageKind, MemberKind, SetId};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use std::fmt;

use super::VerifyReport;

fn deserialize_required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    <Option<T> as serde::Deserialize>::deserialize(deserializer)
}

/// The requested recovery scope. This records what was asked, not restore
/// readiness or current image health.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryScope {
    /// Verify the selected member's recovery point.
    SelectedRecoveryPoint,
    /// Verify every member's stored recovery-point content.
    EveryMember,
}

/// Bounded verification phase that stopped or completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptStage {
    /// Source ancestry was being resolved.
    ResolveAncestry,
    /// Caller limits, scratch ownership, and available headroom were checked.
    ScratchPreflight,
    /// Raw source bytes were being copied and hashed.
    Capture,
    /// Captured headers and ancestry topology were being validated.
    IdentityValidation,
    /// Image headers, footer, and metadata pages were being checked.
    Structure,
    /// Requested mode-specific payload references and layouts were checked.
    Content,
}

/// Bounded classification of an incomplete attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    /// Cooperative cancellation was requested.
    Cancelled,
    /// Caller supplied an invalid capture limit or option.
    InvalidOptions,
    /// Full raw ancestry exceeds the caller's explicit cap.
    RawCapExceeded,
    /// Caller-required headroom is not available on scratch storage.
    HeadroomUnavailable,
    /// Scratch path ownership, permissions, or ancestry was unsafe.
    ScratchUntrusted,
    /// Source length changed while the raw bytes were captured.
    SourceChanged,
    /// Captured logical identity or topology differed from the resolved source.
    IdentityChanged,
    /// Key or authenticated decryption checks failed.
    KeyOrAuthenticationFailure,
    /// Image structure or payload content was corrupt.
    Corrupt,
    /// Requested mode or format behavior is unsupported.
    Unsupported,
    /// An I/O or remote operation was unavailable.
    Unavailable,
}

/// Outcome of the checks actually requested.
///
/// `IntegrityVerified` does not claim complete recoverability, source
/// consistency, target readiness, durability, or current remote health. A
/// recorded bad source region is represented separately so it never appears
/// as an unqualified successful recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AttemptOutcome {
    /// The requested integrity checks finished and the report has no recorded
    /// source-loss chunks.
    IntegrityVerified,
    /// The requested integrity checks finished, but the report records source
    /// regions that were unreadable when the image was created.
    IntegrityVerifiedWithRecordedLoss,
    /// The attempt did not complete the requested checks.
    Incomplete {
        /// Last phase reached.
        stage: AttemptStage,
        /// Typed reason; diagnostic strings stay outside the observation.
        reason: FailureKind,
    },
}

/// Capture/read/verification progress for one ordered ancestry member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberStage {
    /// This member was outside the per-member content scope of the request.
    NotRequested,
    /// The attempt has no completion fact for this stage.
    NotStarted,
    /// This stage began but has no completion fact yet.
    InProgress,
    /// The requested per-member stage completed.
    Complete,
    /// The stage failed for this member.
    Failed,
}

/// Bounded notice emitted by a specific verifier branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StructureNotice {
    /// An encrypted legacy image reuses metadata-page nonces.
    RepeatedEncryptedMetadataPageNonce,
}

/// Actual content branch used by the verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentCoverage {
    /// Block recovery point's merged references across its ancestry.
    BlockSelectedMergedReferences,
    /// Every stored block payload in every ancestry member.
    BlockEveryStoredPayload,
    /// Selected file tree references and their referenced chunk payloads.
    FileSelectedTreeReferences,
    /// Every file tree's references and referenced chunk payloads.
    FileEveryTreeReferences,
    /// Selected stream member's payloads, sections, and layout.
    StreamSelectedMemberPayloadsSectionsAndLayout,
    /// Every stream member's payloads, sections, and layout.
    StreamEveryMemberPayloadsSectionsAndLayout,
    /// Selected whole-disk regions and layout.
    WholeDiskRegionsAndLayout,
}

/// Versioned algorithm label for raw-member byte digests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DigestAlgorithm {
    /// BLAKE3 over every raw image byte, without a framing prefix.
    #[serde(rename = "blake3-raw-v1")]
    Blake3RawV1,
}

/// Captured logical identity decoded from the raw member's superblock.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberIdentity {
    /// Member's stable image identifier.
    pub image_uuid: ImageId,
    /// Shared chain identifier.
    pub chain_id: ChainId,
    /// Immediate parent image identifier, or zero for the full member.
    pub parent_uuid: ImageId,
    /// Backup set identifier recorded by the member.
    pub set_id: SetId,
    /// Position in ancestry, starting at zero.
    pub seq_in_chain: u32,
    /// Block, file, or stream mode.
    pub image_kind: ImageKind,
    /// Header-derived member label; it does not recover the original selection policy.
    /// File-mode non-full members are classified as differential by legacy headers (D-130).
    pub legacy_header_kind: MemberKind,
    /// Whether this member carries whole-disk layout.
    pub whole_disk: bool,
    /// Consistency recorded by the image writer; this is not capture-time consistency.
    pub consistency: Consistency,
}

/// Per-member content facts. These components describe verifier work, not
/// general restore readiness or unreferenced stored-payload health.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberContentStages {
    /// Recovery-point selection structure: block manifest state, file tree,
    /// stream sections/layout, or whole-disk layout, depending on mode.
    recovery_point: MemberStage,
    /// Stored payloads owned by this member that were reached through the
    /// requested block/file recovery-point references.
    referenced_payloads: MemberStage,
    /// Every stored payload physically present in this member, only when the
    /// active verifier branch enumerates all of them.
    every_stored_payload: MemberStage,
    /// Whole-disk region payloads; distinct from the region/layout checks.
    disk_region_payloads: MemberStage,
}

impl MemberContentStages {
    const fn pending() -> Self {
        Self {
            recovery_point: MemberStage::NotRequested,
            referenced_payloads: MemberStage::NotRequested,
            every_stored_payload: MemberStage::NotRequested,
            disk_region_payloads: MemberStage::NotRequested,
        }
    }

    /// Recovery-point selection or layout stage.
    #[must_use]
    pub const fn recovery_point(self) -> MemberStage {
        self.recovery_point
    }

    /// Referenced payloads stored in this member.
    #[must_use]
    pub const fn referenced_payloads(self) -> MemberStage {
        self.referenced_payloads
    }

    /// Whether all stored payloads in this member were enumerated.
    #[must_use]
    pub const fn every_stored_payload(self) -> MemberStage {
        self.every_stored_payload
    }

    /// Whole-disk region payload stage.
    #[must_use]
    pub const fn disk_region_payloads(self) -> MemberStage {
        self.disk_region_payloads
    }
}

/// Bounded facts for one member. A missing digest or incomplete stage is
/// explicit and cannot be confused with a fully captured member.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberObservation {
    #[serde(deserialize_with = "deserialize_required_option")]
    pub(super) identity: Option<MemberIdentity>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub(super) raw_length: Option<u64>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub(super) blake3_bytes: Option<[u8; 32]>,
    pub(super) capture: MemberStage,
    pub(super) structure: MemberStage,
    /// No notice was recorded; interpret this with `structure` completion.
    #[serde(deserialize_with = "deserialize_required_option")]
    pub(super) structure_notice: Option<StructureNotice>,
    pub(super) content: MemberContentStages,
}

impl MemberObservation {
    pub(crate) const fn pending() -> Self {
        Self {
            identity: None,
            raw_length: None,
            blake3_bytes: None,
            capture: MemberStage::NotStarted,
            structure: MemberStage::NotStarted,
            structure_notice: None,
            content: MemberContentStages::pending(),
        }
    }

    /// Captured identity, absent until the complete copied member is bound.
    #[must_use]
    pub const fn identity(&self) -> Option<&MemberIdentity> {
        self.identity.as_ref()
    }

    /// Source byte length, when preflight obtained it.
    #[must_use]
    pub const fn raw_length(&self) -> Option<u64> {
        self.raw_length
    }

    /// BLAKE3 of all raw bytes copied, present only after a complete capture.
    #[must_use]
    pub const fn blake3_bytes(&self) -> Option<&[u8; 32]> {
        self.blake3_bytes.as_ref()
    }

    /// Capture stage.
    #[must_use]
    pub const fn capture(&self) -> MemberStage {
        self.capture
    }

    /// Structural verification stage.
    #[must_use]
    pub const fn structure(&self) -> MemberStage {
        self.structure
    }

    /// Content verification stage.
    #[must_use]
    pub const fn content(&self) -> MemberContentStages {
        self.content
    }

    /// Typed structural notice from the actual verifier branch, if any.
    #[must_use]
    pub const fn structure_notice(&self) -> Option<StructureNotice> {
        self.structure_notice
    }
}

/// Serializable projection of one engine-owned attempt.
///
/// It intentionally contains no URI, warning/error text, keys, file names,
/// file trees, or aggregate report counters. Run/provenance authority and time
/// are deferred until a recorder contract is selected.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct VerificationObservation {
    schema_version: u16,
    digest_algorithm: DigestAlgorithm,
    coverage_contract_version: u16,
    outcome: AttemptOutcome,
    requested_scope: RecoveryScope,
    content_coverage: Option<ContentCoverage>,
    members: Vec<MemberObservation>,
}

/// Strict, member-bounded deserializer used by the local receipt reader.
pub(super) struct ObservationSeed {
    max_members: usize,
}

impl ObservationSeed {
    pub(super) const fn new(max_members: usize) -> Self {
        Self { max_members }
    }
}

impl<'de> DeserializeSeed<'de> for ObservationSeed {
    type Value = VerificationObservation;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_struct(
            "VerificationObservation",
            &[
                "schema_version",
                "digest_algorithm",
                "coverage_contract_version",
                "outcome",
                "requested_scope",
                "content_coverage",
                "members",
            ],
            ObservationVisitor {
                max_members: self.max_members,
            },
        )
    }
}

struct ObservationVisitor {
    max_members: usize,
}

impl<'de> Visitor<'de> for ObservationVisitor {
    type Value = VerificationObservation;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a strict verification observation")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut schema_version = None;
        let mut digest_algorithm = None;
        let mut coverage_contract_version = None;
        let mut outcome = None;
        let mut requested_scope = None;
        let mut content_coverage: Option<Option<ContentCoverage>> = None;
        let mut members = None;

        while let Some(field) = map.next_key::<String>()? {
            match field.as_str() {
                "schema_version" => {
                    if schema_version.is_some() {
                        return Err(de::Error::duplicate_field("schema_version"));
                    }
                    schema_version = Some(map.next_value()?);
                }
                "digest_algorithm" => {
                    if digest_algorithm.is_some() {
                        return Err(de::Error::duplicate_field("digest_algorithm"));
                    }
                    digest_algorithm = Some(map.next_value()?);
                }
                "coverage_contract_version" => {
                    if coverage_contract_version.is_some() {
                        return Err(de::Error::duplicate_field("coverage_contract_version"));
                    }
                    coverage_contract_version = Some(map.next_value()?);
                }
                "outcome" => {
                    if outcome.is_some() {
                        return Err(de::Error::duplicate_field("outcome"));
                    }
                    outcome = Some(map.next_value()?);
                }
                "requested_scope" => {
                    if requested_scope.is_some() {
                        return Err(de::Error::duplicate_field("requested_scope"));
                    }
                    requested_scope = Some(map.next_value()?);
                }
                "content_coverage" => {
                    if content_coverage.is_some() {
                        return Err(de::Error::duplicate_field("content_coverage"));
                    }
                    content_coverage = Some(map.next_value()?);
                }
                "members" => {
                    if members.is_some() {
                        return Err(de::Error::duplicate_field("members"));
                    }
                    members = Some(map.next_value_seed(MemberListSeed {
                        max_members: self.max_members,
                    })?);
                }
                _ => {
                    return Err(de::Error::unknown_field(
                        &field,
                        &[
                            "schema_version",
                            "digest_algorithm",
                            "coverage_contract_version",
                            "outcome",
                            "requested_scope",
                            "content_coverage",
                            "members",
                        ],
                    ));
                }
            }
        }

        Ok(VerificationObservation {
            schema_version: schema_version
                .ok_or_else(|| de::Error::missing_field("schema_version"))?,
            digest_algorithm: digest_algorithm
                .ok_or_else(|| de::Error::missing_field("digest_algorithm"))?,
            coverage_contract_version: coverage_contract_version
                .ok_or_else(|| de::Error::missing_field("coverage_contract_version"))?,
            outcome: outcome.ok_or_else(|| de::Error::missing_field("outcome"))?,
            requested_scope: requested_scope
                .ok_or_else(|| de::Error::missing_field("requested_scope"))?,
            content_coverage: content_coverage
                .ok_or_else(|| de::Error::missing_field("content_coverage"))?,
            members: members.ok_or_else(|| de::Error::missing_field("members"))?,
        })
    }
}

struct MemberListSeed {
    max_members: usize,
}

impl<'de> DeserializeSeed<'de> for MemberListSeed {
    type Value = Vec<MemberObservation>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(MemberListVisitor {
            max_members: self.max_members,
        })
    }
}

struct MemberListVisitor {
    max_members: usize,
}

impl<'de> Visitor<'de> for MemberListVisitor {
    type Value = Vec<MemberObservation>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "at most {} captured members", self.max_members)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut members = Vec::new();
        while let Some(member) = sequence.next_element()? {
            if members.len() >= self.max_members {
                return Err(de::Error::invalid_length(
                    members.len().saturating_add(1),
                    &self,
                ));
            }
            members.push(member);
        }
        Ok(members)
    }
}

impl VerificationObservation {
    pub(crate) fn new(requested_scope: RecoveryScope) -> Self {
        Self {
            schema_version: 1,
            digest_algorithm: DigestAlgorithm::Blake3RawV1,
            coverage_contract_version: 1,
            outcome: AttemptOutcome::Incomplete {
                stage: AttemptStage::ResolveAncestry,
                reason: FailureKind::Unavailable,
            },
            requested_scope,
            content_coverage: None,
            members: Vec::new(),
        }
    }

    pub(crate) fn members_mut(&mut self) -> &mut Vec<MemberObservation> {
        &mut self.members
    }

    pub(crate) fn set_incomplete(&mut self, stage: AttemptStage, reason: FailureKind) {
        self.outcome = AttemptOutcome::Incomplete { stage, reason };
    }

    pub(crate) fn set_verified(&mut self, recorded_bad_chunks: u64) {
        self.outcome = if recorded_bad_chunks == 0 {
            AttemptOutcome::IntegrityVerified
        } else {
            AttemptOutcome::IntegrityVerifiedWithRecordedLoss
        };
    }

    pub(crate) fn set_coverage(&mut self, coverage: ContentCoverage) {
        self.content_coverage = Some(coverage);
    }

    /// Observation schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Raw-member byte-digest algorithm/version.
    #[must_use]
    pub const fn digest_algorithm(&self) -> DigestAlgorithm {
        self.digest_algorithm
    }

    /// Version of the mode-specific coverage semantics.
    #[must_use]
    pub const fn coverage_contract_version(&self) -> u16 {
        self.coverage_contract_version
    }

    /// Typed outcome of the requested checks.
    #[must_use]
    pub const fn outcome(&self) -> AttemptOutcome {
        self.outcome
    }

    /// Requested recovery scope.
    #[must_use]
    pub const fn requested_scope(&self) -> RecoveryScope {
        self.requested_scope
    }

    /// Content-verification branch, absent if the verifier did not reach it.
    #[must_use]
    pub const fn content_coverage(&self) -> Option<ContentCoverage> {
        self.content_coverage
    }

    /// Members in ancestry order, with missing stages/digests left explicit.
    #[must_use]
    pub fn members(&self) -> &[MemberObservation] {
        &self.members
    }
}

/// Typed stage recorder used only by the captured-verification branch.
pub(crate) struct VerificationRecorder {
    observation: VerificationObservation,
    stage: AttemptStage,
}

impl VerificationRecorder {
    pub(crate) fn new(observation: VerificationObservation) -> Self {
        Self {
            observation,
            stage: AttemptStage::Structure,
        }
    }

    pub(crate) fn begin_structure(&mut self, member: usize) {
        self.stage = AttemptStage::Structure;
        if let Some(member) = self.observation.members_mut().get_mut(member) {
            member.structure = MemberStage::InProgress;
        }
    }

    pub(crate) fn complete_structure(&mut self, member: usize) {
        if let Some(member) = self.observation.members_mut().get_mut(member) {
            member.structure = MemberStage::Complete;
        }
    }

    pub(crate) fn fail_structure(&mut self, member: usize) {
        if let Some(member) = self.observation.members_mut().get_mut(member) {
            member.structure = MemberStage::Failed;
        }
    }

    pub(crate) fn note_structure(&mut self, member: usize, notice: StructureNotice) {
        if let Some(member) = self.observation.members_mut().get_mut(member) {
            member.structure_notice = Some(notice);
        }
    }

    pub(crate) fn enter_content_phase(&mut self) {
        self.stage = AttemptStage::Content;
    }

    pub(crate) fn begin_content(&mut self, coverage: ContentCoverage, member_count: usize) {
        self.stage = AttemptStage::Content;
        self.observation.set_coverage(coverage);
        let selected = member_count.saturating_sub(1);
        for (index, member) in self.observation.members_mut().iter_mut().enumerate() {
            let content = &mut member.content;
            match coverage {
                ContentCoverage::BlockSelectedMergedReferences => {
                    content.referenced_payloads = MemberStage::NotStarted;
                    if index == selected {
                        content.recovery_point = MemberStage::NotStarted;
                    }
                }
                ContentCoverage::BlockEveryStoredPayload => {
                    content.referenced_payloads = MemberStage::NotStarted;
                    content.every_stored_payload = MemberStage::NotStarted;
                    if index == selected {
                        content.recovery_point = MemberStage::NotStarted;
                    }
                }
                ContentCoverage::FileSelectedTreeReferences => {
                    content.referenced_payloads = MemberStage::NotStarted;
                    if index == selected {
                        content.recovery_point = MemberStage::NotStarted;
                    }
                }
                ContentCoverage::FileEveryTreeReferences => {
                    content.referenced_payloads = MemberStage::NotStarted;
                    content.recovery_point = MemberStage::NotStarted;
                }
                ContentCoverage::StreamSelectedMemberPayloadsSectionsAndLayout => {
                    if index == selected {
                        content.recovery_point = MemberStage::NotStarted;
                        content.every_stored_payload = MemberStage::NotStarted;
                    }
                }
                ContentCoverage::StreamEveryMemberPayloadsSectionsAndLayout => {
                    content.recovery_point = MemberStage::NotStarted;
                    content.every_stored_payload = MemberStage::NotStarted;
                }
                ContentCoverage::WholeDiskRegionsAndLayout => {
                    if index == selected {
                        content.recovery_point = MemberStage::NotStarted;
                        content.disk_region_payloads = MemberStage::NotStarted;
                    }
                }
            }
        }
    }

    pub(crate) fn begin_recovery_point(&mut self, member: usize) {
        if let Some(member) = self.observation.members_mut().get_mut(member) {
            member.content.recovery_point = MemberStage::InProgress;
        }
    }

    pub(crate) fn complete_recovery_point(&mut self, member: usize) {
        if let Some(member) = self.observation.members_mut().get_mut(member) {
            member.content.recovery_point = MemberStage::Complete;
        }
    }

    pub(crate) fn begin_referenced_payload(&mut self, member_index: usize) {
        if let Some(member) = self.observation.members_mut().get_mut(member_index)
            && member.content.referenced_payloads != MemberStage::Complete
        {
            member.content.referenced_payloads = MemberStage::InProgress;
        }
    }

    pub(crate) fn complete_referenced_payloads(&mut self) {
        for member in self.observation.members_mut() {
            if matches!(
                member.content.referenced_payloads,
                MemberStage::NotStarted | MemberStage::InProgress
            ) {
                member.content.referenced_payloads = MemberStage::Complete;
            }
        }
    }

    pub(crate) fn begin_member_stored_payloads(&mut self, member_index: usize) {
        if let Some(member) = self.observation.members_mut().get_mut(member_index) {
            member.content.every_stored_payload = MemberStage::InProgress;
        }
    }

    pub(crate) fn complete_member_stored_payloads(&mut self, member_index: usize) {
        if let Some(member) = self.observation.members_mut().get_mut(member_index) {
            member.content.every_stored_payload = MemberStage::Complete;
        }
    }

    pub(crate) fn begin_all_stored_payloads(&mut self) {
        for member in self.observation.members_mut() {
            member.content.every_stored_payload = MemberStage::InProgress;
        }
    }

    pub(crate) fn complete_all_stored_payloads(&mut self) {
        for member in self.observation.members_mut() {
            member.content.every_stored_payload = MemberStage::Complete;
        }
    }

    pub(crate) fn begin_disk_region_payloads(&mut self, member_index: usize) {
        if let Some(member) = self.observation.members_mut().get_mut(member_index) {
            member.content.disk_region_payloads = MemberStage::InProgress;
        }
    }

    pub(crate) fn complete_disk_region_payloads(&mut self, member_index: usize) {
        if let Some(member) = self.observation.members_mut().get_mut(member_index) {
            member.content.disk_region_payloads = MemberStage::Complete;
        }
    }

    pub(crate) fn finish(mut self, report: VerifyReport) -> VerificationAttempt {
        self.observation.set_verified(report.recorded_bad_chunks);
        VerificationAttempt {
            report: Some(report),
            observation: self.observation,
            diagnostic: None,
        }
    }

    pub(crate) fn fail(mut self, error: Error) -> VerificationAttempt {
        for member in self.observation.members_mut() {
            if member.capture == MemberStage::InProgress {
                member.capture = MemberStage::Failed;
            }
            if member.structure == MemberStage::InProgress {
                member.structure = MemberStage::Failed;
            }
            for stage in [
                &mut member.content.recovery_point,
                &mut member.content.referenced_payloads,
                &mut member.content.every_stored_payload,
                &mut member.content.disk_region_payloads,
            ] {
                if *stage == MemberStage::InProgress {
                    *stage = MemberStage::Failed;
                }
            }
        }
        self.observation
            .set_incomplete(self.stage, classify_error(&error));
        VerificationAttempt {
            report: None,
            observation: self.observation,
            diagnostic: Some(error),
        }
    }
}

pub(crate) fn classify_error(error: &Error) -> FailureKind {
    match error {
        Error::Cancelled => FailureKind::Cancelled,
        Error::Aead => FailureKind::KeyOrAuthenticationFailure,
        Error::Corrupt { .. } => FailureKind::Corrupt,
        Error::Unsupported { .. } => FailureKind::Unsupported,
        Error::Io(io_error) if io_error.raw_os_error() == Some(libc::ENOSPC) => {
            FailureKind::HeadroomUnavailable
        }
        Error::NoSpace => FailureKind::HeadroomUnavailable,
        Error::Io(_) | Error::NetworkTimeout(_) => FailureKind::Unavailable,
        Error::BadSector { .. }
        | Error::SnapshotOverflow
        | Error::FreezeTimeout
        | Error::StreamParentMissing { .. }
        | Error::NoConsistentMethod { .. }
        | Error::SetLocked { .. }
        | Error::TargetChanged
        | Error::TargetBusy { .. }
        | Error::Denied { .. } => FailureKind::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AttemptOutcome, ContentCoverage, MemberObservation, MemberStage, RecoveryScope,
        StructureNotice, VerificationObservation, VerificationRecorder,
    };
    use crate::verify::VerifyReport;
    use lr_core::ImageKind;

    #[test]
    fn recorded_source_loss_never_becomes_unqualified_integrity_success() {
        let observation = VerificationObservation::new(RecoveryScope::SelectedRecoveryPoint);
        let attempt = VerificationRecorder::new(observation).finish(VerifyReport {
            image_uri: "diagnostic-only".to_owned(),
            image_kind: ImageKind::Block,
            members: 1,
            pages: 0,
            chunks: 0,
            bytes_checked: 0,
            warnings: Vec::new(),
            recorded_bad_chunks: 1,
            every_member: false,
        });
        assert_eq!(
            attempt.observation().outcome(),
            AttemptOutcome::IntegrityVerifiedWithRecordedLoss
        );
        let serialized =
            serde_json::to_string(attempt.observation()).expect("serialize typed outcome");
        assert!(serialized.contains("integrity_verified_with_recorded_loss"));
        assert!(
            !serialized.contains("recorded_bad_chunks"),
            "schema-v1 observation does not duplicate aggregate report counters"
        );
    }

    #[test]
    fn structure_notice_serializes_as_a_bounded_typed_fact() {
        let mut observation = VerificationObservation::new(RecoveryScope::SelectedRecoveryPoint);
        observation.members_mut().push(MemberObservation::pending());
        let mut recorder = VerificationRecorder::new(observation);
        recorder.begin_structure(0);
        recorder.note_structure(0, StructureNotice::RepeatedEncryptedMetadataPageNonce);
        recorder.complete_structure(0);
        let attempt = recorder.finish(VerifyReport {
            image_uri: "diagnostic-only".to_owned(),
            image_kind: ImageKind::Block,
            members: 1,
            pages: 0,
            chunks: 0,
            bytes_checked: 0,
            warnings: vec!["not included in observation".to_owned()],
            recorded_bad_chunks: 0,
            every_member: false,
        });
        assert_eq!(
            attempt.observation().members()[0].structure_notice(),
            Some(StructureNotice::RepeatedEncryptedMetadataPageNonce)
        );
        let serialized = serde_json::to_value(attempt.observation()).expect("serialize facts");
        assert_eq!(
            serialized["members"][0]["structure_notice"],
            "repeated_encrypted_metadata_page_nonce"
        );
        let serialized = serialized.to_string();
        assert!(!serialized.contains("diagnostic-only"));
        assert!(!serialized.contains("not included in observation"));
    }

    #[test]
    fn content_stages_start_only_for_the_actual_mode_and_scope() {
        fn recorder(coverage: ContentCoverage, member_count: usize) -> VerificationRecorder {
            let mut observation =
                VerificationObservation::new(RecoveryScope::SelectedRecoveryPoint);
            observation
                .members_mut()
                .resize_with(member_count, MemberObservation::pending);
            let mut recorder = VerificationRecorder::new(observation);
            recorder.begin_content(coverage, member_count);
            recorder
        }

        let block = recorder(ContentCoverage::BlockSelectedMergedReferences, 2);
        let block_members = block.observation.members();
        assert_eq!(
            block_members[0].content.referenced_payloads,
            MemberStage::NotStarted,
            "selected block references may be held by an ancestor"
        );
        assert_eq!(
            block_members[0].content.recovery_point,
            MemberStage::NotRequested
        );
        assert_eq!(
            block_members[1].content.recovery_point,
            MemberStage::NotStarted
        );

        let block_chain = recorder(ContentCoverage::BlockEveryStoredPayload, 2);
        let block_chain_members = block_chain.observation.members();
        assert_eq!(
            block_chain_members[0].content.referenced_payloads,
            MemberStage::NotStarted
        );
        assert_eq!(
            block_chain_members[0].content.every_stored_payload,
            MemberStage::NotStarted
        );
        assert_eq!(
            block_chain_members[0].content.recovery_point,
            MemberStage::NotRequested,
            "the block branch labels all stored payloads, not each member as a separate point"
        );

        let stream = recorder(
            ContentCoverage::StreamSelectedMemberPayloadsSectionsAndLayout,
            2,
        );
        let stream_members = stream.observation.members();
        assert_eq!(
            stream_members[0].content.every_stored_payload,
            MemberStage::NotRequested,
            "selected stream verification does not claim ancestor payloads"
        );
        assert_eq!(
            stream_members[1].content.every_stored_payload,
            MemberStage::NotStarted
        );

        let stream_chain = recorder(
            ContentCoverage::StreamEveryMemberPayloadsSectionsAndLayout,
            2,
        );
        for member in stream_chain.observation.members() {
            assert_eq!(member.content.recovery_point, MemberStage::NotStarted);
            assert_eq!(member.content.every_stored_payload, MemberStage::NotStarted);
        }

        let files = recorder(ContentCoverage::FileEveryTreeReferences, 2);
        for member in files.observation.members() {
            assert_eq!(member.content.recovery_point, MemberStage::NotStarted);
            assert_eq!(member.content.referenced_payloads, MemberStage::NotStarted);
            assert_eq!(
                member.content.every_stored_payload,
                MemberStage::NotRequested
            );
        }

        let disk = recorder(ContentCoverage::WholeDiskRegionsAndLayout, 1);
        let disk_member = &disk.observation.members()[0].content;
        assert_eq!(disk_member.recovery_point, MemberStage::NotStarted);
        assert_eq!(disk_member.disk_region_payloads, MemberStage::NotStarted);
        assert_eq!(disk_member.every_stored_payload, MemberStage::NotRequested);
    }
}

/// One immutable verification attempt. The aggregate legacy report is stored
/// exactly once; the observation is its bounded, content-bound projection.
#[derive(Debug)]
pub struct VerificationAttempt {
    report: Option<VerifyReport>,
    observation: VerificationObservation,
    diagnostic: Option<lr_core::Error>,
}

impl VerificationAttempt {
    pub(crate) fn incomplete(
        observation: VerificationObservation,
        stage: AttemptStage,
        reason: FailureKind,
        diagnostic: lr_core::Error,
    ) -> Self {
        let mut observation = observation;
        observation.set_incomplete(stage, reason);
        Self {
            report: None,
            observation,
            diagnostic: Some(diagnostic),
        }
    }

    /// Aggregate diagnostic report, present only when the verifier completed.
    #[must_use]
    pub fn report(&self) -> Option<&VerifyReport> {
        self.report.as_ref()
    }

    /// Bounded observation suitable for serialization.
    #[must_use]
    pub const fn observation(&self) -> &VerificationObservation {
        &self.observation
    }

    /// Non-serialized diagnostic for callers that need the legacy error text.
    #[must_use]
    pub const fn diagnostic(&self) -> Option<&lr_core::Error> {
        self.diagnostic.as_ref()
    }
}
