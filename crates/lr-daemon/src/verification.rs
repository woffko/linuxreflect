//! Immutable retained captured-verification result and bounded wire projections.

use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use lr_core::{Error, Result};
use lr_engine::verify as v;
use lr_proto::v1 as p;
use prost::Message;

use crate::jobs::JobState;
use crate::verification_policy::DaemonVerificationPolicy;

/// One canonical terminal result shared by job retention and event delivery.
/// Receipt files store the observation, never this transient acknowledgement.
#[derive(Debug)]
pub struct CapturedVerificationResult {
    observation: v::VerificationObservation,
    recording: v::RecordingOutcome,
    report_json: Option<String>,
    _reservation: ResultReservation,
}

impl PartialEq for CapturedVerificationResult {
    fn eq(&self, other: &Self) -> bool {
        self.observation == other.observation
            && self.recording == other.recording
            && self.report_json == other.report_json
    }
}
impl Eq for CapturedVerificationResult {}

/// Non-queued admission for active and retained captured results.
#[derive(Debug)]
pub(crate) struct ResultBudget {
    used: Mutex<(usize, usize)>,
    max_results: usize,
    max_bytes: usize,
}

impl ResultBudget {
    pub(crate) fn new(max_results: usize, max_bytes: usize) -> Self {
        Self {
            used: Mutex::new((0, 0)),
            max_results,
            max_bytes,
        }
    }

    pub(crate) fn try_reserve(self: &Arc<Self>, bytes: usize) -> Option<ResultReservation> {
        let mut used = self
            .used
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let next_bytes = used.1.checked_add(bytes)?;
        if used.0 >= self.max_results || next_bytes > self.max_bytes {
            return None;
        }
        used.0 += 1;
        used.1 = next_bytes;
        Some(ResultReservation {
            budget: Arc::clone(self),
            bytes,
        })
    }
}

#[derive(Debug)]
pub(crate) struct ResultReservation {
    budget: Arc<ResultBudget>,
    bytes: usize,
}

impl Drop for ResultReservation {
    fn drop(&mut self) {
        let mut used = self
            .budget
            .used
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        used.0 -= 1;
        used.1 -= self.bytes;
    }
}

impl CapturedVerificationResult {
    pub(crate) fn from_attempt(
        attempt: &v::VerificationAttempt,
        recording: v::RecordingOutcome,
        policy: &DaemonVerificationPolicy,
        reservation: ResultReservation,
    ) -> Result<Self> {
        let observation = attempt.observation();
        if observation.members().len() > policy.history().max_members() {
            return Err(result_limit_error());
        }
        let observation_bytes = check_observation_size(observation, policy.max_result_bytes())?;
        let report_capacity =
            report_capacity(observation_bytes, &recording, policy.max_result_bytes())?;
        let report_json = attempt
            .report()
            .map(|report| {
                let mut writer = BoundedJson {
                    bytes: Vec::new(),
                    limit: report_capacity,
                };
                serde_json::to_writer(&mut writer, report).map_err(|_| result_limit_error())?;
                String::from_utf8(writer.bytes).map_err(|_| result_limit_error())
            })
            .transpose()?;
        // Validate the complete wire size, including the outer stream envelope,
        // before retaining the owned observation. Nothing is truncated.
        let wire = wire_result_parts(observation, &recording, report_json.as_deref());
        check_size(
            &p::VerificationProgress {
                step: Some(p::verification_progress::Step::Result(wire)),
            },
            policy.max_result_bytes(),
        )?;
        Ok(Self {
            observation: observation.clone(),
            recording,
            report_json,
            _reservation: reservation,
        })
    }

    pub(crate) fn wire(&self) -> p::VerificationResult {
        wire_result_parts(
            &self.observation,
            &self.recording,
            self.report_json.as_deref(),
        )
    }

    pub(crate) fn job_outcome(&self) -> (JobState, Option<(String, String)>) {
        let failure = match self.observation.outcome() {
            v::AttemptOutcome::Incomplete {
                reason: v::FailureKind::Cancelled,
                ..
            } => Some((
                JobState::Cancelled,
                "E_CANCELLED",
                "verification was cancelled",
            )),
            v::AttemptOutcome::Incomplete { .. } => Some((
                JobState::Failed,
                "E_VERIFY_INCOMPLETE",
                "verification did not complete",
            )),
            v::AttemptOutcome::IntegrityVerified
            | v::AttemptOutcome::IntegrityVerifiedWithRecordedLoss => match self.recording {
                v::RecordingOutcome::Recorded { .. } => None,
                v::RecordingOutcome::NotRecorded { .. } => Some((
                    JobState::Failed,
                    "E_HISTORY_NOT_RECORDED",
                    "receipt was not recorded",
                )),
                v::RecordingOutcome::PublicationUnconfirmed { .. } => Some((
                    JobState::Failed,
                    "E_HISTORY_PUBLICATION_UNCONFIRMED",
                    "receipt publication was not confirmed",
                )),
            },
        };
        match failure {
            None => (JobState::Finished, None),
            Some((state, code, message)) => (state, Some((code.to_owned(), message.to_owned()))),
        }
    }

    pub(crate) fn legacy_progress(&self) -> p::Progress {
        let (_, error) = self.job_outcome();
        let step = match error {
            Some((code, message)) => p::progress::Step::Failure(p::Failure { code, message }),
            None => p::progress::Step::Finished(p::Finished {
                summary_json: self.report_json.clone().unwrap_or_default(),
            }),
        };
        p::Progress { step: Some(step) }
    }
}

struct BoundedJson {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for BoundedJson {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let length = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .filter(|length| *length <= self.limit)
            .ok_or_else(|| io::Error::other("result limit exceeded"))?;
        self.bytes
            .try_reserve(length - self.bytes.len())
            .map_err(io::Error::other)?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn result_limit_error() -> Error {
    Error::unsupported("captured verification result exceeds daemon response policy")
}

pub(crate) fn check_size<T: Message>(value: &T, limit: usize) -> Result<()> {
    if value.encoded_len() > limit {
        Err(result_limit_error())
    } else {
        Ok(())
    }
}

fn wire_result_parts(
    observation: &v::VerificationObservation,
    recording: &v::RecordingOutcome,
    report: Option<&str>,
) -> p::VerificationResult {
    p::VerificationResult {
        schema_version: 1,
        observation: Some(wire_observation(observation)),
        recording: Some(wire_recording(recording)),
        report_json: report.map(str::to_owned),
    }
}

fn wire_recording(recording: &v::RecordingOutcome) -> p::VerificationRecordingOutcome {
    use p::verification_recording_outcome::Outcome;
    let outcome = match recording {
        v::RecordingOutcome::Recorded { receipt_id } => {
            Outcome::Recorded(p::VerificationRecorded {
                receipt_id: receipt_id.clone(),
            })
        }
        v::RecordingOutcome::NotRecorded { reason } => {
            Outcome::NotRecorded(p::VerificationNotRecorded {
                reason: history_failure(*reason),
            })
        }
        v::RecordingOutcome::PublicationUnconfirmed { receipt_id, reason } => {
            Outcome::PublicationUnconfirmed(p::VerificationPublicationUnconfirmed {
                receipt_id: receipt_id.clone(),
                reason: publication_failure(*reason),
            })
        }
    };
    p::VerificationRecordingOutcome {
        outcome: Some(outcome),
    }
}

// All these fields use one-byte tags. Account for length prefixes and the
// progress envelope before allowing report serialization or full projection.
fn framed_length(bytes: usize) -> Result<usize> {
    bytes
        .checked_add(1 + prost::encoding::encoded_len_varint(bytes as u64))
        .ok_or_else(result_limit_error)
}

fn report_capacity(
    observation_bytes: usize,
    recording: &v::RecordingOutcome,
    limit: usize,
) -> Result<usize> {
    let skeleton = p::VerificationResult {
        schema_version: 1,
        observation: None,
        recording: Some(wire_recording(recording)),
        report_json: None,
    };
    let base = skeleton
        .encoded_len()
        .checked_add(framed_length(observation_bytes)?)
        .ok_or_else(result_limit_error)?;
    if framed_length(base)? > limit {
        return Err(result_limit_error());
    }
    let fits = |bytes: usize| -> Result<bool> {
        let body = base
            .checked_add(framed_length(bytes)?)
            .ok_or_else(result_limit_error)?;
        Ok(framed_length(body)? <= limit)
    };
    let (mut low, mut high) = (0, limit);
    while low < high {
        let mid = low + (high - low).div_ceil(2);
        if fits(mid)? {
            low = mid;
        } else {
            high = mid - 1;
        }
    }
    Ok(low)
}

pub(crate) fn wire_receipt(receipt: &v::VerificationReceipt) -> p::VerificationHistoryItem {
    p::VerificationHistoryItem {
        item: Some(p::verification_history_item::Item::Receipt(
            p::VerificationReceipt {
                schema_version: 1,
                receipt_id: receipt.receipt_id().to_owned(),
                recorded_effective_uid: receipt.recorded_effective_uid(),
                recorded_unix_seconds: receipt.recorded_unix_seconds(),
                observation: Some(wire_observation(receipt.observation())),
            },
        )),
    }
}

pub(crate) fn history_state(
    availability: p::VerificationHistoryAvailability,
) -> p::VerificationHistoryItem {
    p::VerificationHistoryItem {
        item: Some(p::verification_history_item::Item::State(
            p::VerificationHistoryState {
                availability: availability as i32,
            },
        )),
    }
}

fn wire_observation(value: &v::VerificationObservation) -> p::VerificationObservation {
    let mut wire = wire_observation_header(value);
    wire.members = value.members().iter().map(wire_member).collect();
    wire
}

// One bounded member at a time: validate before allocating the whole wire vector.
pub(crate) fn check_observation_size(
    value: &v::VerificationObservation,
    limit: usize,
) -> Result<usize> {
    let mut length = wire_observation_header(value).encoded_len();
    for member in value.members() {
        let member_bytes = wire_member(member).encoded_len();
        let framed = 1 + prost::encoding::encoded_len_varint(member_bytes as u64) + member_bytes;
        length = length.checked_add(framed).ok_or_else(result_limit_error)?;
        if length > limit {
            return Err(result_limit_error());
        }
    }
    if length > limit {
        return Err(result_limit_error());
    }
    Ok(length)
}

fn wire_observation_header(value: &v::VerificationObservation) -> p::VerificationObservation {
    use p::verification_observation::Outcome;
    let outcome = match value.outcome() {
        v::AttemptOutcome::IntegrityVerified => {
            Outcome::Integrity(p::VerificationIntegrity::IntegrityVerified as i32)
        }
        v::AttemptOutcome::IntegrityVerifiedWithRecordedLoss => {
            Outcome::Integrity(p::VerificationIntegrity::IntegrityVerifiedWithRecordedLoss as i32)
        }
        v::AttemptOutcome::Incomplete { stage, reason } => {
            Outcome::Incomplete(p::VerificationIncomplete {
                stage: attempt_stage(stage),
                reason: failure_kind(reason),
            })
        }
    };
    p::VerificationObservation {
        schema_version: u32::from(value.schema_version()),
        digest_algorithm: digest_algorithm(value.digest_algorithm()),
        coverage_contract_version: u32::from(value.coverage_contract_version()),
        outcome: Some(outcome),
        requested_scope: recovery_scope(value.requested_scope()),
        content_coverage: value.content_coverage().map(content_coverage),
        members: Vec::new(),
    }
}

fn wire_member(member: &v::MemberObservation) -> p::VerificationMemberObservation {
    let content = member.content();
    p::VerificationMemberObservation {
        identity: member.identity().map(|id| p::VerificationMemberIdentity {
            image_uuid: id.image_uuid.to_string(),
            chain_id: id.chain_id.to_string(),
            parent_uuid: id.parent_uuid.to_string(),
            set_id: id.set_id.to_string(),
            seq_in_chain: id.seq_in_chain,
            image_kind: image_kind(id.image_kind),
            legacy_header_kind: member_kind(id.legacy_header_kind),
            whole_disk: id.whole_disk,
            consistency: consistency(id.consistency),
        }),
        raw_length: member.raw_length(),
        raw_digest: member.blake3_bytes().map(|digest| digest.to_vec()),
        capture: member_stage(member.capture()),
        structure: member_stage(member.structure()),
        structure_notice: member.structure_notice().map(structure_notice),
        content: Some(p::VerificationMemberContentStages {
            recovery_point: member_stage(content.recovery_point()),
            referenced_payloads: member_stage(content.referenced_payloads()),
            every_stored_payload: member_stage(content.every_stored_payload()),
            disk_region_payloads: member_stage(content.disk_region_payloads()),
        }),
    }
}

fn attempt_stage(value: v::AttemptStage) -> i32 {
    match value {
        v::AttemptStage::ResolveAncestry => p::VerificationAttemptStage::ResolveAncestry as i32,
        v::AttemptStage::ScratchPreflight => p::VerificationAttemptStage::ScratchPreflight as i32,
        v::AttemptStage::Capture => p::VerificationAttemptStage::Capture as i32,
        v::AttemptStage::IdentityValidation => {
            p::VerificationAttemptStage::IdentityValidation as i32
        }
        v::AttemptStage::Structure => p::VerificationAttemptStage::Structure as i32,
        v::AttemptStage::Content => p::VerificationAttemptStage::Content as i32,
    }
}

fn failure_kind(value: v::FailureKind) -> i32 {
    match value {
        v::FailureKind::Cancelled => p::VerificationFailureKind::Cancelled as i32,
        v::FailureKind::InvalidOptions => p::VerificationFailureKind::InvalidOptions as i32,
        v::FailureKind::RawCapExceeded => p::VerificationFailureKind::RawCapExceeded as i32,
        v::FailureKind::HeadroomUnavailable => {
            p::VerificationFailureKind::HeadroomUnavailable as i32
        }
        v::FailureKind::ScratchUntrusted => p::VerificationFailureKind::ScratchUntrusted as i32,
        v::FailureKind::SourceChanged => p::VerificationFailureKind::SourceChanged as i32,
        v::FailureKind::IdentityChanged => p::VerificationFailureKind::IdentityChanged as i32,
        v::FailureKind::KeyOrAuthenticationFailure => {
            p::VerificationFailureKind::KeyOrAuthenticationFailure as i32
        }
        v::FailureKind::Corrupt => p::VerificationFailureKind::Corrupt as i32,
        v::FailureKind::Unsupported => p::VerificationFailureKind::Unsupported as i32,
        v::FailureKind::Unavailable => p::VerificationFailureKind::Unavailable as i32,
    }
}

fn member_stage(value: v::MemberStage) -> i32 {
    match value {
        v::MemberStage::NotRequested => p::VerificationMemberStage::NotRequested as i32,
        v::MemberStage::NotStarted => p::VerificationMemberStage::NotStarted as i32,
        v::MemberStage::InProgress => p::VerificationMemberStage::InProgress as i32,
        v::MemberStage::Complete => p::VerificationMemberStage::Complete as i32,
        v::MemberStage::Failed => p::VerificationMemberStage::Failed as i32,
    }
}

fn recovery_scope(value: v::RecoveryScope) -> i32 {
    match value {
        v::RecoveryScope::SelectedRecoveryPoint => {
            p::VerificationRecoveryScope::SelectedRecoveryPoint as i32
        }
        v::RecoveryScope::EveryMember => p::VerificationRecoveryScope::EveryMember as i32,
    }
}

fn content_coverage(value: v::ContentCoverage) -> i32 {
    match value {
        v::ContentCoverage::BlockSelectedMergedReferences => {
            p::VerificationContentCoverage::BlockSelectedMergedReferences as i32
        }
        v::ContentCoverage::BlockEveryStoredPayload => {
            p::VerificationContentCoverage::BlockEveryStoredPayload as i32
        }
        v::ContentCoverage::FileSelectedTreeReferences => {
            p::VerificationContentCoverage::FileSelectedTreeReferences as i32
        }
        v::ContentCoverage::FileEveryTreeReferences => {
            p::VerificationContentCoverage::FileEveryTreeReferences as i32
        }
        v::ContentCoverage::StreamSelectedMemberPayloadsSectionsAndLayout => {
            p::VerificationContentCoverage::StreamSelectedMemberPayloadsSectionsAndLayout as i32
        }
        v::ContentCoverage::StreamEveryMemberPayloadsSectionsAndLayout => {
            p::VerificationContentCoverage::StreamEveryMemberPayloadsSectionsAndLayout as i32
        }
        v::ContentCoverage::WholeDiskRegionsAndLayout => {
            p::VerificationContentCoverage::WholeDiskRegionsAndLayout as i32
        }
    }
}

fn digest_algorithm(value: v::DigestAlgorithm) -> i32 {
    match value {
        v::DigestAlgorithm::Blake3RawV1 => p::VerificationDigestAlgorithm::Blake3RawV1 as i32,
    }
}

fn structure_notice(value: v::StructureNotice) -> i32 {
    match value {
        v::StructureNotice::RepeatedEncryptedMetadataPageNonce => {
            p::VerificationStructureNotice::RepeatedEncryptedMetadataPageNonce as i32
        }
    }
}

fn image_kind(value: lr_core::ImageKind) -> i32 {
    match value {
        lr_core::ImageKind::Block => p::VerificationImageKind::Block as i32,
        lr_core::ImageKind::Stream => p::VerificationImageKind::Stream as i32,
        lr_core::ImageKind::File => p::VerificationImageKind::File as i32,
    }
}

fn member_kind(value: lr_core::MemberKind) -> i32 {
    match value {
        lr_core::MemberKind::Full => p::VerificationLegacyHeaderKind::Full as i32,
        lr_core::MemberKind::Incremental => p::VerificationLegacyHeaderKind::Incremental as i32,
        lr_core::MemberKind::Differential => p::VerificationLegacyHeaderKind::Differential as i32,
    }
}

fn consistency(value: lr_core::Consistency) -> i32 {
    match value {
        lr_core::Consistency::PointInTime => p::VerificationConsistency::PointInTime as i32,
        lr_core::Consistency::Frozen => p::VerificationConsistency::Frozen as i32,
        lr_core::Consistency::Offline => p::VerificationConsistency::Offline as i32,
        lr_core::Consistency::PerFile => p::VerificationConsistency::PerFile as i32,
        lr_core::Consistency::None => p::VerificationConsistency::None as i32,
    }
}

fn history_failure(value: v::HistoryFailure) -> i32 {
    match value {
        v::HistoryFailure::InvalidOptions => p::VerificationHistoryFailure::InvalidOptions as i32,
        v::HistoryFailure::InvalidAttempt => p::VerificationHistoryFailure::InvalidAttempt as i32,
        v::HistoryFailure::UntrustedDirectory => {
            p::VerificationHistoryFailure::UntrustedDirectory as i32
        }
        v::HistoryFailure::UnsupportedFilesystem => {
            p::VerificationHistoryFailure::UnsupportedFilesystem as i32
        }
        v::HistoryFailure::QuotaExceeded => p::VerificationHistoryFailure::QuotaExceeded as i32,
        v::HistoryFailure::ReceiptIdCollision => {
            p::VerificationHistoryFailure::ReceiptIdCollision as i32
        }
        v::HistoryFailure::Busy => p::VerificationHistoryFailure::Busy as i32,
        v::HistoryFailure::Unavailable => p::VerificationHistoryFailure::Unavailable as i32,
    }
}

fn publication_failure(value: v::PublicationFailure) -> i32 {
    match value {
        v::PublicationFailure::LinkUnconfirmed => {
            p::VerificationPublicationFailure::LinkUnconfirmed as i32
        }
        v::PublicationFailure::TemporaryNameRemovalUnconfirmed => {
            p::VerificationPublicationFailure::TemporaryNameRemovalUnconfirmed as i32
        }
        v::PublicationFailure::DirectorySyncUnconfirmed => {
            p::VerificationPublicationFailure::DirectorySyncUnconfirmed as i32
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn report_capacity_accounts_for_both_varint_boundaries_and_recording_variants() {
        let observation = p::VerificationObservation {
            schema_version: 1,
            members: vec![p::VerificationMemberObservation::default(); 3],
            ..p::VerificationObservation::default()
        };
        let recording_variants = [
            v::RecordingOutcome::Recorded {
                receipt_id: "a".repeat(32),
            },
            v::RecordingOutcome::NotRecorded {
                reason: v::HistoryFailure::QuotaExceeded,
            },
            v::RecordingOutcome::PublicationUnconfirmed {
                receipt_id: "b".repeat(32),
                reason: v::PublicationFailure::DirectorySyncUnconfirmed,
            },
        ];
        for recording in recording_variants {
            for report_bytes in [0, 127, 128, 16383, 16384] {
                let message = |bytes: usize| p::VerificationProgress {
                    step: Some(p::verification_progress::Step::Result(
                        p::VerificationResult {
                            schema_version: 1,
                            observation: Some(observation.clone()),
                            recording: Some(wire_recording(&recording)),
                            report_json: Some("x".repeat(bytes)),
                        },
                    )),
                };
                // Size the whole-message cap using actual inner lengths so
                // fixed framing cannot hide the varint transitions under test.
                let limit = message(report_bytes).encoded_len();
                let capacity = report_capacity(observation.encoded_len(), &recording, limit)
                    .expect("base fits");
                assert_eq!(capacity, report_bytes);
                assert!(
                    message(capacity).encoded_len() <= limit,
                    "remaining budget fits exactly"
                );
                assert!(
                    message(capacity + 1).encoded_len() > limit,
                    "one more byte refuses"
                );
            }
        }
    }

    #[test]
    fn result_reservations_bound_counts_bytes_and_outlive_shared_owners() {
        let count = Arc::new(ResultBudget::new(1, 4096));
        let first = Arc::new(count.try_reserve(1024).expect("first reservation"));
        assert!(count.try_reserve(1).is_none(), "count cap");
        let alias = Arc::clone(&first);
        drop(first);
        assert!(count.try_reserve(1).is_none(), "shared result still alive");
        drop(alias);
        assert!(
            count.try_reserve(4096).is_some(),
            "last owner returns budget"
        );

        let bytes = Arc::new(ResultBudget::new(4, 1024));
        let first = bytes.try_reserve(768).expect("bytes reservation");
        assert!(bytes.try_reserve(257).is_none(), "aggregate bytes cap");
        let second = bytes.try_reserve(256).expect("exact boundary");
        assert!(bytes.try_reserve(usize::MAX).is_none(), "overflow refuses");
        drop((first, second));
        assert!(bytes.try_reserve(1024).is_some());
    }
}
