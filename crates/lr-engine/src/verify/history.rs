//! Host-local, bounded receipts for captured verification attempts.

use std::ffi::OsStr;
use std::fs::{File, OpenOptions, ReadDir};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use lr_core::{Error, Id, Result};
use serde::de::{self, DeserializeSeed, MapAccess, Visitor};
use std::fmt;

use super::VerificationAttempt;
use super::observation::{
    AttemptOutcome, ContentCoverage, MemberObservation, MemberStage, ObservationSeed,
    RecoveryScope, VerificationObservation,
};

const RECEIPT_SCHEMA_VERSION: u16 = 1;
const LOCK_NAME: &str = ".history.lock";
const RECEIPT_PREFIX: &str = "receipt-";
const RECEIPT_SUFFIX: &str = ".json";
const TEMP_PREFIX: &str = ".tmp-";
const PRIVATE_FILE_MODE: u32 = 0o600;
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const EXT4_MAGIC: i64 = 0xef53;
const XFS_MAGIC: i64 = 0x5846_5342;
const BTRFS_MAGIC: i64 = 0x9123_683e;
const BTRFS_MAGIC_SIGNED_32: i64 = 0x9123_683e_u32 as i32 as i64;

/// Explicit limits and location for one host-local verification ledger.
///
/// The directory must already exist, be owned by the effective UID with mode
/// 0700, and live on ext4, XFS, or Btrfs. No default limits are supplied.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationHistoryOptions {
    history_directory: PathBuf,
    max_receipt_bytes: u64,
    max_members: usize,
    max_entries: usize,
    max_total_ledger_bytes: u64,
}

impl VerificationHistoryOptions {
    /// Choose every resource limit and the existing local history directory.
    #[must_use]
    pub fn new(
        history_directory: impl Into<PathBuf>,
        max_receipt_bytes: u64,
        max_members: usize,
        max_entries: usize,
        max_total_ledger_bytes: u64,
    ) -> Self {
        Self {
            history_directory: history_directory.into(),
            max_receipt_bytes,
            max_members,
            max_entries,
            max_total_ledger_bytes,
        }
    }

    /// The caller-selected existing ledger directory.
    #[must_use]
    pub fn history_directory(&self) -> &Path {
        &self.history_directory
    }

    /// Maximum serialized size of one receipt.
    #[must_use]
    pub const fn max_receipt_bytes(&self) -> u64 {
        self.max_receipt_bytes
    }

    /// Maximum number of ordered members accepted in one receipt.
    #[must_use]
    pub const fn max_members(&self) -> usize {
        self.max_members
    }

    /// Maximum number of non-lock directory entries, including debris.
    #[must_use]
    pub const fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Maximum total size of receipts, temporary files, and unknown files.
    #[must_use]
    pub const fn max_total_ledger_bytes(&self) -> u64 {
        self.max_total_ledger_bytes
    }

    fn validate(&self) -> std::result::Result<(), HistoryError> {
        if !self.history_directory.is_absolute()
            || self.max_receipt_bytes == 0
            || self.max_members == 0
            || self.max_entries == 0
            || self.max_total_ledger_bytes == 0
        {
            return Err(HistoryError::InvalidOptions);
        }
        Ok(())
    }
}

/// Why a receipt was not confirmed as recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryFailure {
    /// Limits or path did not satisfy the explicit history contract.
    InvalidOptions,
    /// The supplied value was not a consistent engine-owned attempt.
    InvalidAttempt,
    /// The final directory or one of its ancestors was not trusted.
    UntrustedDirectory,
    /// The pinned directory is not on ext4, XFS, or Btrfs.
    UnsupportedFilesystem,
    /// A configured quota would be exceeded.
    QuotaExceeded,
    /// A receipt ID collided with an existing immutable name.
    ReceiptIdCollision,
    /// Another cooperating operation currently holds the permanent ledger lock.
    Busy,
    /// The ledger could not be safely opened, locked, scanned, or written.
    Unavailable,
}

/// Why the atomic name may exist but durability could not be confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationFailure {
    /// The no-replace hard-link operation returned an uncertain I/O error.
    LinkUnconfirmed,
    /// The temporary name could not be removed after publication.
    TemporaryNameRemovalUnconfirmed,
    /// The containing directory could not be synced after publication.
    DirectorySyncUnconfirmed,
}

/// Transient result of one call to record an attempt.
///
/// Only `Recorded` means the file and containing directory syncs both
/// completed. Reading an existing receipt never reconstructs this call result.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RecordingOutcome {
    /// The immutable receipt was published and its directory entry was synced.
    Recorded {
        /// Generated identifier of the confirmed local receipt.
        receipt_id: String,
    },
    /// No publication was confirmed.
    NotRecorded {
        /// Bounded reason publication did not start or was refused.
        reason: HistoryFailure,
    },
    /// Publication may have happened, but its directory sync was not confirmed.
    PublicationUnconfirmed {
        /// Generated identifier of the possibly published receipt.
        receipt_id: String,
        /// Boundary that prevented confirmation.
        reason: PublicationFailure,
    },
}

/// One locally stored historical observation.
///
/// This is not an authenticated statement, a current image-health result, or
/// proof that the original caller received a `Recorded` response.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct VerificationReceipt {
    schema_version: u16,
    receipt_id: String,
    recorded_effective_uid: u32,
    /// Unix recording-start clock sample before ledger I/O, not verification
    /// time or a sync-completion timestamp.
    recorded_unix_seconds: u64,
    observation: VerificationObservation,
}

impl VerificationReceipt {
    /// Generated receipt ID stored in the immutable filename and body.
    #[must_use]
    pub fn receipt_id(&self) -> &str {
        &self.receipt_id
    }

    /// Effective UID of the process that asked the engine to record it.
    #[must_use]
    pub const fn recorded_effective_uid(&self) -> u32 {
        self.recorded_effective_uid
    }

    /// Unix recording-start clock sample taken before ledger I/O, not
    /// verification time or a sync-completion timestamp.
    #[must_use]
    pub const fn recorded_unix_seconds(&self) -> u64 {
        self.recorded_unix_seconds
    }

    /// Bounded facts from the captured engine attempt.
    #[must_use]
    pub const fn observation(&self) -> &VerificationObservation {
        &self.observation
    }
}

/// A bounded in-memory index rebuilt only from valid local receipts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationHistory {
    receipts: Vec<VerificationReceipt>,
}

impl VerificationHistory {
    /// Valid receipts in deterministic record-time and ID order.
    #[must_use]
    pub fn receipts(&self) -> &[VerificationReceipt] {
        &self.receipts
    }

    /// Receipts naming the same exact ordered captured members as this attempt.
    ///
    /// Matching compares identity, byte length, and raw digest for every
    /// member. It does not use names, URIs, current file sizes, catalog data,
    /// scope, or outcome; each returned receipt retains its own scope/outcome.
    pub fn matching_receipts<'a>(
        &'a self,
        attempt: &'a VerificationAttempt,
    ) -> impl Iterator<Item = &'a VerificationReceipt> + 'a {
        self.receipts.iter().filter(move |receipt| {
            same_captured_members(receipt.observation(), attempt.observation())
        })
    }
}

/// Record one engine-produced captured attempt into the effective user's local
/// history directory.
///
/// The operation only reads `attempt`; it never opens original image paths.
/// Incomplete attempts and attempts with recorded source loss are retained as
/// distinct typed outcomes. A caller must use this return value to know whether
/// this call confirmed publication.
#[must_use]
pub fn record_verification_attempt(
    attempt: &VerificationAttempt,
    options: &VerificationHistoryOptions,
) -> RecordingOutcome {
    let id = match random_receipt_id() {
        Ok(id) => id,
        Err(_) => {
            return RecordingOutcome::NotRecorded {
                reason: HistoryFailure::Unavailable,
            };
        }
    };
    record_with_id(attempt, options, id, None)
}

/// Load all valid receipts and rebuild the in-memory history index.
///
/// Any invalid, unsupported, missing, or unavailable ledger returns an error;
/// callers must treat that result as unknown history, never as success.
pub fn load_verification_history(
    options: &VerificationHistoryOptions,
) -> Result<VerificationHistory> {
    options.validate().map_err(HistoryError::into_core)?;
    let directory =
        PinnedHistory::open(&options.history_directory).map_err(HistoryError::into_core)?;
    let _lock = directory.lock(false).map_err(HistoryError::into_core)?;
    let mut scan = scan_ledger(&directory, options, true).map_err(HistoryError::into_core)?;
    scan.receipts.sort_by(|left, right| {
        left.recorded_unix_seconds
            .cmp(&right.recorded_unix_seconds)
            .then_with(|| left.receipt_id.cmp(&right.receipt_id))
    });
    Ok(VerificationHistory {
        receipts: scan.receipts,
    })
}

fn record_with_id(
    attempt: &VerificationAttempt,
    options: &VerificationHistoryOptions,
    id: Id,
    fault: Option<PublicationFaultPoint>,
) -> RecordingOutcome {
    if let Err(error) = options.validate() {
        return not_recorded(error);
    }
    if attempt.observation().members().len() > options.max_members {
        return RecordingOutcome::NotRecorded {
            reason: HistoryFailure::QuotaExceeded,
        };
    }
    if !validate_attempt(attempt) {
        return RecordingOutcome::NotRecorded {
            reason: HistoryFailure::InvalidAttempt,
        };
    }
    let recorded_unix_seconds = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(time) => time.as_secs(),
        Err(_) => {
            return RecordingOutcome::NotRecorded {
                reason: HistoryFailure::Unavailable,
            };
        }
    };
    let recorded_effective_uid = lr_unsafe::effective_uid();
    let receipt_id = id.to_uuid_string();
    let receipt = VerificationReceipt {
        schema_version: RECEIPT_SCHEMA_VERSION,
        receipt_id: receipt_id.clone(),
        recorded_effective_uid,
        recorded_unix_seconds,
        observation: attempt.observation().clone(),
    };

    let directory = match PinnedHistory::open(&options.history_directory) {
        Ok(directory) => directory,
        Err(error) => return not_recorded(error),
    };
    let _lock = match directory.lock(true) {
        Ok(lock) => lock,
        Err(error) => return not_recorded(error),
    };
    let scan = match scan_ledger(&directory, options, false) {
        Ok(scan) => scan,
        Err(error) => return not_recorded(error),
    };
    if scan.entries >= options.max_entries {
        return RecordingOutcome::NotRecorded {
            reason: HistoryFailure::QuotaExceeded,
        };
    }

    let serialized_len = match serialized_receipt_len(&receipt, options.max_receipt_bytes) {
        Ok(length) => length,
        Err(error) => return not_recorded(error),
    };
    if scan
        .total_bytes
        .checked_add(serialized_len)
        .is_none_or(|total| total > options.max_total_ledger_bytes)
    {
        return RecordingOutcome::NotRecorded {
            reason: HistoryFailure::QuotaExceeded,
        };
    }

    let temporary_name = format!("{TEMP_PREFIX}{receipt_id}");
    let final_name = receipt_filename(&receipt_id);
    let temporary_path = match directory.entry_path(&temporary_name) {
        Ok(path) => path,
        Err(error) => return not_recorded(HistoryError::Io(error)),
    };
    let final_path = match directory.entry_path(&final_name) {
        Ok(path) => path,
        Err(error) => return not_recorded(HistoryError::Io(error)),
    };
    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&temporary_path)
    {
        Ok(file) => file,
        Err(_) => {
            return RecordingOutcome::NotRecorded {
                reason: HistoryFailure::Unavailable,
            };
        }
    };
    if validate_private_regular(&file, recorded_effective_uid, Some(0)).is_err() {
        return RecordingOutcome::NotRecorded {
            reason: HistoryFailure::Unavailable,
        };
    }

    let (serialization_failed, bytes_written, exceeded) = {
        let mut writer = BoundedFileWriter::new(&mut file, options.max_receipt_bytes);
        let serialized = serde_json::to_writer(&mut writer, &receipt);
        (serialized.is_err(), writer.written, writer.exceeded)
    };
    if serialization_failed || bytes_written != serialized_len {
        return RecordingOutcome::NotRecorded {
            reason: if exceeded {
                HistoryFailure::QuotaExceeded
            } else {
                HistoryFailure::Unavailable
            },
        };
    }
    if fault == Some(PublicationFaultPoint::BeforeReceiptSync) || file.sync_all().is_err() {
        return RecordingOutcome::NotRecorded {
            reason: HistoryFailure::Unavailable,
        };
    }

    match std::fs::hard_link(&temporary_path, &final_path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            return RecordingOutcome::NotRecorded {
                reason: HistoryFailure::ReceiptIdCollision,
            };
        }
        Err(_) => {
            return RecordingOutcome::PublicationUnconfirmed {
                receipt_id,
                reason: PublicationFailure::LinkUnconfirmed,
            };
        }
    }
    if std::fs::remove_file(&temporary_path).is_err() {
        return RecordingOutcome::PublicationUnconfirmed {
            receipt_id,
            reason: PublicationFailure::TemporaryNameRemovalUnconfirmed,
        };
    }
    if fault == Some(PublicationFaultPoint::BeforeDirectorySync) || directory.sync().is_err() {
        return RecordingOutcome::PublicationUnconfirmed {
            receipt_id,
            reason: PublicationFailure::DirectorySyncUnconfirmed,
        };
    }
    RecordingOutcome::Recorded { receipt_id }
}

fn random_receipt_id() -> Result<Id> {
    let mut bytes: [u8; 16] = lr_crypto::rand::random_bytes()?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(Id::from_bytes(bytes))
}

fn receipt_filename(receipt_id: &str) -> String {
    format!("{RECEIPT_PREFIX}{receipt_id}{RECEIPT_SUFFIX}")
}

fn not_recorded(error: HistoryError) -> RecordingOutcome {
    let reason = match error {
        HistoryError::InvalidOptions => HistoryFailure::InvalidOptions,
        HistoryError::UntrustedDirectory => HistoryFailure::UntrustedDirectory,
        HistoryError::UnsupportedFilesystem => HistoryFailure::UnsupportedFilesystem,
        HistoryError::QuotaExceeded => HistoryFailure::QuotaExceeded,
        HistoryError::Busy => HistoryFailure::Busy,
        HistoryError::Corrupt(_) | HistoryError::Io(_) => HistoryFailure::Unavailable,
    };
    RecordingOutcome::NotRecorded { reason }
}

fn validate_attempt(attempt: &VerificationAttempt) -> bool {
    let observation = attempt.observation();
    if !validate_observation_header(observation) || !validate_partial_observation(observation) {
        return false;
    }
    match observation.outcome() {
        AttemptOutcome::Incomplete { .. } => attempt.report().is_none(),
        AttemptOutcome::IntegrityVerified => {
            attempt
                .report()
                .is_some_and(|report| report.recorded_bad_chunks == 0)
                && validate_success_observation(observation)
        }
        AttemptOutcome::IntegrityVerifiedWithRecordedLoss => {
            attempt
                .report()
                .is_some_and(|report| report.recorded_bad_chunks > 0)
                && validate_success_observation(observation)
        }
    }
}

fn validate_observation_header(observation: &VerificationObservation) -> bool {
    observation.schema_version() == 1
        && observation.digest_algorithm() == super::observation::DigestAlgorithm::Blake3RawV1
        && observation.coverage_contract_version() == 1
}

fn validate_partial_observation(observation: &VerificationObservation) -> bool {
    let mut any_content_fact = false;
    for member in observation.members() {
        // A zero-length source can still be fully copied and hashed before
        // identity validation rejects it. Keep that incomplete fact; only a
        // successful observation requires a non-empty image.
        let has_length = member.raw_length().is_some();
        let has_digest = member.blake3_bytes().is_some();
        let has_identity = member.identity().is_some();
        match member.capture() {
            MemberStage::NotStarted | MemberStage::Failed => {
                if has_digest || has_identity {
                    return false;
                }
            }
            MemberStage::InProgress => return false,
            MemberStage::Complete => {
                if !has_length || !has_digest {
                    return false;
                }
            }
            MemberStage::NotRequested => return false,
        }
        if has_digest && (!has_length || member.capture() != MemberStage::Complete) {
            return false;
        }
        if has_identity && (member.capture() != MemberStage::Complete || !has_length || !has_digest)
        {
            return false;
        }
        match member.structure() {
            MemberStage::NotStarted => {}
            MemberStage::Complete | MemberStage::Failed => {
                if member.capture() != MemberStage::Complete || !has_identity {
                    return false;
                }
            }
            MemberStage::InProgress | MemberStage::NotRequested => return false,
        }
        if member.structure_notice().is_some() && member.structure() != MemberStage::Complete {
            return false;
        }
        let content = member.content();
        for stage in [
            content.recovery_point(),
            content.referenced_payloads(),
            content.every_stored_payload(),
            content.disk_region_payloads(),
        ] {
            if stage != MemberStage::NotRequested {
                any_content_fact = true;
                if stage == MemberStage::InProgress {
                    return false;
                }
            }
        }
    }
    match (observation.content_coverage(), any_content_fact) {
        (None, false) => true,
        (Some(_), true) => observation.members().iter().all(|member| {
            member.capture() == MemberStage::Complete
                && member.identity().is_some()
                && member.structure() == MemberStage::Complete
        }),
        _ => false,
    }
}

fn validate_success_observation(observation: &VerificationObservation) -> bool {
    let members = observation.members();
    if members.is_empty() || observation.content_coverage().is_none() {
        return false;
    }
    for member in members {
        if member.capture() != MemberStage::Complete
            || member.structure() != MemberStage::Complete
            || member.raw_length().is_none_or(|length| length == 0)
            || member.blake3_bytes().is_none()
            || member.identity().is_none()
            || (member.structure_notice().is_some() && member.structure() != MemberStage::Complete)
        {
            return false;
        }
    }
    if !valid_ancestry(members) {
        return false;
    }
    let Some(coverage) = observation.content_coverage() else {
        return false;
    };
    let Some(target) = members.last().and_then(MemberObservation::identity) else {
        return false;
    };
    let scope = observation.requested_scope();
    let coverage_matches = match coverage {
        ContentCoverage::BlockSelectedMergedReferences => {
            target.image_kind == lr_core::ImageKind::Block
                && !target.whole_disk
                && scope == RecoveryScope::SelectedRecoveryPoint
        }
        ContentCoverage::BlockEveryStoredPayload => {
            target.image_kind == lr_core::ImageKind::Block
                && !target.whole_disk
                && scope == RecoveryScope::EveryMember
        }
        ContentCoverage::FileSelectedTreeReferences => {
            target.image_kind == lr_core::ImageKind::File
                && !target.whole_disk
                && scope == RecoveryScope::SelectedRecoveryPoint
        }
        ContentCoverage::FileEveryTreeReferences => {
            target.image_kind == lr_core::ImageKind::File
                && !target.whole_disk
                && scope == RecoveryScope::EveryMember
        }
        ContentCoverage::StreamSelectedMemberPayloadsSectionsAndLayout => {
            target.image_kind == lr_core::ImageKind::Stream
                && !target.whole_disk
                && scope == RecoveryScope::SelectedRecoveryPoint
        }
        ContentCoverage::StreamEveryMemberPayloadsSectionsAndLayout => {
            target.image_kind == lr_core::ImageKind::Stream
                && !target.whole_disk
                && scope == RecoveryScope::EveryMember
        }
        ContentCoverage::WholeDiskRegionsAndLayout => {
            target.image_kind == lr_core::ImageKind::Block && target.whole_disk
        }
    };
    if !coverage_matches {
        return false;
    }
    for (index, member) in members.iter().enumerate() {
        let Some(actual_identity) = member.identity() else {
            return false;
        };
        let stages = member.content();
        let selected = index + 1 == members.len();
        let (recovery, referenced, stored, disk_regions) = match coverage {
            ContentCoverage::BlockSelectedMergedReferences => (selected, true, false, false),
            ContentCoverage::BlockEveryStoredPayload => (selected, true, true, false),
            ContentCoverage::FileSelectedTreeReferences => (selected, true, false, false),
            ContentCoverage::FileEveryTreeReferences => (true, true, false, false),
            ContentCoverage::StreamSelectedMemberPayloadsSectionsAndLayout => {
                (selected, false, selected, false)
            }
            ContentCoverage::StreamEveryMemberPayloadsSectionsAndLayout => {
                (true, false, true, false)
            }
            ContentCoverage::WholeDiskRegionsAndLayout => (selected, false, false, true),
        };
        if !matches_expected_stage(stages.recovery_point(), recovery)
            || !matches_expected_stage(stages.referenced_payloads(), referenced)
            || !matches_expected_stage(stages.every_stored_payload(), stored)
            || !matches_expected_stage(stages.disk_region_payloads(), disk_regions)
        {
            return false;
        }
        if actual_identity.whole_disk != target.whole_disk
            || actual_identity.image_kind != target.image_kind
        {
            return false;
        }
    }
    true
}

fn matches_expected_stage(actual: MemberStage, expected_complete: bool) -> bool {
    actual
        == if expected_complete {
            MemberStage::Complete
        } else {
            MemberStage::NotRequested
        }
}

fn valid_ancestry(members: &[MemberObservation]) -> bool {
    let mut seen = std::collections::BTreeSet::new();
    let Some(first) = members.first().and_then(MemberObservation::identity) else {
        return false;
    };
    if first.seq_in_chain != 0
        || first.parent_uuid != lr_core::ImageId::ZERO
        || first.legacy_header_kind != lr_core::MemberKind::Full
    {
        return false;
    }
    if first.whole_disk && (members.len() != 1 || first.image_kind != lr_core::ImageKind::Block) {
        return false;
    }
    for (index, member) in members.iter().enumerate() {
        let Some(identity) = member.identity() else {
            return false;
        };
        let Ok(sequence) = u32::try_from(index) else {
            return false;
        };
        let parent_matches = if index == 0 {
            identity.parent_uuid == lr_core::ImageId::ZERO
        } else {
            members[index - 1]
                .identity()
                .is_some_and(|parent| identity.parent_uuid == parent.image_uuid)
        };
        if identity.seq_in_chain != sequence
            || identity.chain_id != first.chain_id
            || identity.set_id != first.set_id
            || identity.image_kind != first.image_kind
            || identity.whole_disk != first.whole_disk
            || !parent_matches
            || (index > 0 && identity.legacy_header_kind == lr_core::MemberKind::Full)
            || !seen.insert(identity.image_uuid)
        {
            return false;
        }
    }
    true
}

fn same_captured_members(left: &VerificationObservation, right: &VerificationObservation) -> bool {
    let left_members = left.members();
    let right_members = right.members();
    if left_members.is_empty() || left_members.len() != right_members.len() {
        return false;
    }
    left_members.iter().zip(right_members).all(|(left, right)| {
        matches!(
            (left.identity(), right.identity(), left.raw_length(), right.raw_length(), left.blake3_bytes(), right.blake3_bytes()),
            (Some(left_identity), Some(right_identity), Some(left_length), Some(right_length), Some(left_digest), Some(right_digest))
                if left_identity == right_identity
                    && left_length == right_length
                    && left_digest == right_digest
        )
    })
}

struct PinnedHistory {
    directory: File,
}

impl PinnedHistory {
    fn open(path: &Path) -> std::result::Result<Self, HistoryError> {
        if !path.is_absolute() {
            return Err(HistoryError::UntrustedDirectory);
        }
        let relative = path
            .strip_prefix("/")
            .map_err(|_| HistoryError::UntrustedDirectory)?;
        let components = lr_unsafe::beneath::normal_components(relative)
            .map_err(|_| HistoryError::UntrustedDirectory)?;
        if components.is_empty() {
            return Err(HistoryError::UntrustedDirectory);
        }
        let uid = lr_unsafe::effective_uid();
        let mut current =
            File::from(lr_unsafe::beneath::open_root(Path::new("/")).map_err(HistoryError::Io)?);
        let mut final_metadata = None;
        for (index, component) in components.iter().enumerate() {
            let next = lr_unsafe::beneath::open_dir_beneath(&current, Path::new(component))
                .map_err(HistoryError::Io)?;
            let next = File::from(next);
            let metadata = next.metadata().map_err(HistoryError::Io)?;
            let final_component = index + 1 == components.len();
            let trusted_owner = metadata.uid() == uid || metadata.uid() == 0;
            let protected_sticky = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
            if !trusted_owner
                || (metadata.mode() & 0o022 != 0 && !protected_sticky)
                || (final_component
                    && (metadata.uid() != uid
                        || metadata.mode() & 0o7777 != PRIVATE_DIRECTORY_MODE))
            {
                return Err(HistoryError::UntrustedDirectory);
            }
            if final_component {
                final_metadata = Some(metadata);
            }
            current = next;
        }
        let pinned_path = lr_unsafe::beneath::self_path(&current);
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(pinned_path)
            .map_err(HistoryError::Io)?;
        let opened_metadata = directory.metadata().map_err(HistoryError::Io)?;
        let Some(pinned_metadata) = final_metadata else {
            return Err(HistoryError::UntrustedDirectory);
        };
        if !same_inode(&pinned_metadata, &opened_metadata)
            || opened_metadata.uid() != uid
            || opened_metadata.mode() & 0o7777 != PRIVATE_DIRECTORY_MODE
        {
            return Err(HistoryError::UntrustedDirectory);
        }
        let filesystem =
            lr_unsafe::filemeta::filesystem_type(&directory).map_err(HistoryError::Io)?;
        if !supported_local_filesystem(filesystem) {
            return Err(HistoryError::UnsupportedFilesystem);
        }
        Ok(Self { directory })
    }

    fn entry_path(&self, name: &str) -> io::Result<PathBuf> {
        lr_unsafe::beneath::entry_path(&self.directory, OsStr::new(name))
    }

    fn lock(&self, create: bool) -> std::result::Result<File, HistoryError> {
        let path = self.entry_path(LOCK_NAME).map_err(HistoryError::Io)?;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
        if create {
            options.create(true).mode(PRIVATE_FILE_MODE);
        }
        let file = options.open(path).map_err(HistoryError::Io)?;
        validate_private_regular(&file, lr_unsafe::effective_uid(), Some(0))
            .map_err(HistoryError::Io)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Err(HistoryError::Busy),
            Err(std::fs::TryLockError::Error(error)) => return Err(HistoryError::Io(error)),
        }
        Ok(file)
    }

    fn sync(&self) -> io::Result<()> {
        self.directory.sync_all()
    }
}

fn same_inode(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

fn validate_private_regular(
    file: &File,
    uid: u32,
    expected_size: Option<u64>,
) -> io::Result<std::fs::Metadata> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o7777 != PRIVATE_FILE_MODE
        || metadata.nlink() != 1
        || expected_size.is_some_and(|size| metadata.len() != size)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "history entry is not an owned private single-link regular file",
        ));
    }
    Ok(metadata)
}

struct LedgerScan {
    receipts: Vec<VerificationReceipt>,
    entries: usize,
    total_bytes: u64,
}

fn supported_local_filesystem(magic: i64) -> bool {
    matches!(
        magic,
        EXT4_MAGIC | XFS_MAGIC | BTRFS_MAGIC | BTRFS_MAGIC_SIGNED_32
    )
}

fn scan_ledger(
    directory: &PinnedHistory,
    options: &VerificationHistoryOptions,
    load_receipts: bool,
) -> std::result::Result<LedgerScan, HistoryError> {
    let entries = std::fs::read_dir(lr_unsafe::beneath::self_path(&directory.directory))
        .map_err(HistoryError::Io)?;
    scan_entries(entries, directory, options, load_receipts)
}

fn scan_entries(
    entries: ReadDir,
    directory: &PinnedHistory,
    options: &VerificationHistoryOptions,
    load_receipts: bool,
) -> std::result::Result<LedgerScan, HistoryError> {
    let uid = lr_unsafe::effective_uid();
    let mut receipts = Vec::new();
    let mut entry_count = 0usize;
    let mut total_bytes = 0u64;
    for entry in entries {
        let entry = entry.map_err(HistoryError::Io)?;
        let name = entry.file_name();
        if name == OsStr::new(LOCK_NAME) {
            continue;
        }
        entry_count = entry_count
            .checked_add(1)
            .ok_or(HistoryError::QuotaExceeded)?;
        if entry_count > options.max_entries {
            return Err(HistoryError::QuotaExceeded);
        }
        let entry_name = name.to_str().ok_or(HistoryError::Corrupt(
            "history contains a non-UTF-8 entry name",
        ))?;
        let path = directory.entry_path(entry_name).map_err(HistoryError::Io)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
            .map_err(HistoryError::Io)?;
        let metadata = validate_private_regular(&file, uid, None).map_err(HistoryError::Io)?;
        total_bytes = total_bytes
            .checked_add(metadata.len())
            .ok_or(HistoryError::QuotaExceeded)?;
        if total_bytes > options.max_total_ledger_bytes {
            return Err(HistoryError::QuotaExceeded);
        }
        if let Some(filename_id) = parse_receipt_filename(entry_name)? {
            if metadata.len() > options.max_receipt_bytes {
                return Err(HistoryError::QuotaExceeded);
            }
            if load_receipts {
                let receipt = read_receipt(file, metadata, &filename_id, options.max_members)?;
                if !validate_receipt(&receipt, &filename_id, uid, options.max_members) {
                    return Err(HistoryError::Corrupt("receipt fields are inconsistent"));
                }
                receipts.push(receipt);
            }
        }
    }
    Ok(LedgerScan {
        receipts,
        entries: entry_count,
        total_bytes,
    })
}

fn parse_receipt_filename(name: &str) -> std::result::Result<Option<String>, HistoryError> {
    let Some(value) = name.strip_prefix(RECEIPT_PREFIX) else {
        return Ok(None);
    };
    let Some(value) = value.strip_suffix(RECEIPT_SUFFIX) else {
        return Err(HistoryError::Corrupt("receipt filename schema is invalid"));
    };
    let id = value
        .parse::<Id>()
        .map_err(|_| HistoryError::Corrupt("receipt filename ID is invalid"))?;
    if id.to_uuid_string() != value || !is_v4_id(id) {
        return Err(HistoryError::Corrupt(
            "receipt filename ID is not canonical",
        ));
    }
    Ok(Some(value.to_owned()))
}

fn is_v4_id(id: Id) -> bool {
    id.as_bytes()[6] & 0xf0 == 0x40 && id.as_bytes()[8] & 0xc0 == 0x80
}

fn read_receipt(
    mut file: File,
    before: std::fs::Metadata,
    filename_id: &str,
    max_members: usize,
) -> std::result::Result<VerificationReceipt, HistoryError> {
    let capacity = usize::try_from(before.len()).map_err(|_| HistoryError::QuotaExceeded)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| HistoryError::QuotaExceeded)?;
    bytes.resize(capacity, 0);
    file.read_exact(&mut bytes).map_err(HistoryError::Io)?;
    let mut extra = [0u8; 1];
    if file.read(&mut extra).map_err(HistoryError::Io)? != 0 {
        return Err(HistoryError::Corrupt("receipt grew while being read"));
    }
    let after = validate_private_regular(&file, lr_unsafe::effective_uid(), Some(before.len()))
        .map_err(HistoryError::Io)?;
    if !same_inode(&before, &after) {
        return Err(HistoryError::Corrupt(
            "receipt identity changed while reading",
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
    let receipt = ReceiptSeed { max_members }
        .deserialize(&mut deserializer)
        .map_err(|_| HistoryError::Corrupt("receipt JSON or schema is invalid"))?;
    deserializer
        .end()
        .map_err(|_| HistoryError::Corrupt("receipt has trailing data"))?;
    if receipt.receipt_id != filename_id {
        return Err(HistoryError::Corrupt("receipt filename and ID differ"));
    }
    Ok(receipt)
}

fn validate_receipt(
    receipt: &VerificationReceipt,
    filename_id: &str,
    uid: u32,
    max_members: usize,
) -> bool {
    if receipt.schema_version != RECEIPT_SCHEMA_VERSION
        || receipt.recorded_effective_uid != uid
        || receipt.recorded_unix_seconds == 0
        || receipt.receipt_id != filename_id
        || receipt.observation.members().len() > max_members
        || !validate_observation_header(&receipt.observation)
        || !validate_partial_observation(&receipt.observation)
    {
        return false;
    }
    match receipt.observation.outcome() {
        AttemptOutcome::Incomplete { .. } => true,
        AttemptOutcome::IntegrityVerified | AttemptOutcome::IntegrityVerifiedWithRecordedLoss => {
            validate_success_observation(&receipt.observation)
        }
    }
}

struct ReceiptSeed {
    max_members: usize,
}

impl<'de> DeserializeSeed<'de> for ReceiptSeed {
    type Value = VerificationReceipt;

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_struct(
            "VerificationReceipt",
            &[
                "schema_version",
                "receipt_id",
                "recorded_effective_uid",
                "recorded_unix_seconds",
                "observation",
            ],
            ReceiptVisitor {
                max_members: self.max_members,
            },
        )
    }
}

struct ReceiptVisitor {
    max_members: usize,
}

impl<'de> Visitor<'de> for ReceiptVisitor {
    type Value = VerificationReceipt;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a strict local verification receipt")
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut schema_version = None;
        let mut receipt_id = None;
        let mut recorded_effective_uid = None;
        let mut recorded_unix_seconds = None;
        let mut observation = None;
        while let Some(field) = map.next_key::<String>()? {
            match field.as_str() {
                "schema_version" => {
                    if schema_version.is_some() {
                        return Err(de::Error::duplicate_field("schema_version"));
                    }
                    schema_version = Some(map.next_value()?);
                }
                "receipt_id" => {
                    if receipt_id.is_some() {
                        return Err(de::Error::duplicate_field("receipt_id"));
                    }
                    receipt_id = Some(map.next_value()?);
                }
                "recorded_effective_uid" => {
                    if recorded_effective_uid.is_some() {
                        return Err(de::Error::duplicate_field("recorded_effective_uid"));
                    }
                    recorded_effective_uid = Some(map.next_value()?);
                }
                "recorded_unix_seconds" => {
                    if recorded_unix_seconds.is_some() {
                        return Err(de::Error::duplicate_field("recorded_unix_seconds"));
                    }
                    recorded_unix_seconds = Some(map.next_value()?);
                }
                "observation" => {
                    if observation.is_some() {
                        return Err(de::Error::duplicate_field("observation"));
                    }
                    observation =
                        Some(map.next_value_seed(ObservationSeed::new(self.max_members))?);
                }
                _ => {
                    return Err(de::Error::unknown_field(
                        &field,
                        &[
                            "schema_version",
                            "receipt_id",
                            "recorded_effective_uid",
                            "recorded_unix_seconds",
                            "observation",
                        ],
                    ));
                }
            }
        }
        Ok(VerificationReceipt {
            schema_version: schema_version
                .ok_or_else(|| de::Error::missing_field("schema_version"))?,
            receipt_id: receipt_id.ok_or_else(|| de::Error::missing_field("receipt_id"))?,
            recorded_effective_uid: recorded_effective_uid
                .ok_or_else(|| de::Error::missing_field("recorded_effective_uid"))?,
            recorded_unix_seconds: recorded_unix_seconds
                .ok_or_else(|| de::Error::missing_field("recorded_unix_seconds"))?,
            observation: observation.ok_or_else(|| de::Error::missing_field("observation"))?,
        })
    }
}

struct CountWriter {
    limit: u64,
    bytes: u64,
    exceeded: bool,
}

impl CountWriter {
    fn new(limit: u64) -> Self {
        Self {
            limit,
            bytes: 0,
            exceeded: false,
        }
    }
}

impl Write for CountWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let next = self
            .bytes
            .checked_add(u64::try_from(buffer.len()).unwrap_or(u64::MAX));
        if next.is_none_or(|length| length > self.limit) {
            self.exceeded = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "receipt exceeds configured byte limit",
            ));
        }
        self.bytes = next.unwrap_or(self.limit);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct BoundedFileWriter<'a> {
    file: &'a mut File,
    limit: u64,
    written: u64,
    exceeded: bool,
}

impl<'a> BoundedFileWriter<'a> {
    fn new(file: &'a mut File, limit: u64) -> Self {
        Self {
            file,
            limit,
            written: 0,
            exceeded: false,
        }
    }
}

impl Write for BoundedFileWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let requested = u64::try_from(buffer.len()).unwrap_or(u64::MAX);
        if self
            .written
            .checked_add(requested)
            .is_none_or(|length| length > self.limit)
        {
            self.exceeded = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "receipt exceeds configured byte limit",
            ));
        }
        let written = self.file.write(buffer)?;
        self.written = self
            .written
            .checked_add(u64::try_from(written).unwrap_or(u64::MAX))
            .ok_or_else(|| io::Error::other("receipt byte count overflow"))?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

fn serialized_receipt_len(
    receipt: &VerificationReceipt,
    max_bytes: u64,
) -> std::result::Result<u64, HistoryError> {
    let mut writer = CountWriter::new(max_bytes);
    if serde_json::to_writer(&mut writer, receipt).is_err() {
        return Err(if writer.exceeded {
            HistoryError::QuotaExceeded
        } else {
            HistoryError::Corrupt("receipt serialization failed")
        });
    }
    Ok(writer.bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublicationFaultPoint {
    BeforeReceiptSync,
    BeforeDirectorySync,
}

#[derive(Debug)]
enum HistoryError {
    InvalidOptions,
    UntrustedDirectory,
    UnsupportedFilesystem,
    QuotaExceeded,
    Busy,
    Corrupt(&'static str),
    Io(io::Error),
}

impl HistoryError {
    fn into_core(self) -> Error {
        match self {
            Self::InvalidOptions => Error::unsupported("invalid verification history options"),
            Self::UntrustedDirectory => {
                Error::unsupported("verification history directory is not trusted")
            }
            Self::UnsupportedFilesystem => {
                Error::unsupported("verification history requires ext4, XFS, or Btrfs")
            }
            Self::QuotaExceeded => Error::unsupported("verification history quota exceeded"),
            Self::Busy => Error::Io(io::Error::new(
                io::ErrorKind::WouldBlock,
                "verification history is busy",
            )),
            Self::Corrupt(reason) => Error::corrupt(reason),
            Self::Io(error) => Error::Io(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        HistoryFailure, PublicationFailure, PublicationFaultPoint, RecordingOutcome,
        VerificationHistoryOptions, load_verification_history, parse_receipt_filename,
        record_with_id, supported_local_filesystem, validate_partial_observation,
    };
    use crate::verify::observation::{
        AttemptStage, FailureKind, RecoveryScope, VerificationObservation, VerificationRecorder,
    };
    use crate::verify::{
        ContentCoverage, MemberIdentity, MemberObservation, MemberStage, VerificationAttempt,
        VerifyReport,
    };
    use lr_core::{ChainId, Consistency, Error, Id, ImageId, ImageKind, MemberKind, SetId};
    use std::ffi::OsStr;
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::path::PathBuf;
    use std::sync::{Arc, Barrier};
    use std::thread;

    fn local_history_dir() -> tempfile::TempDir {
        let root = std::env::var_os("LR_TEST_HISTORY_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/var/tmp"));
        tempfile::Builder::new()
            .prefix("lr-verification-history-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(root)
            .expect("create history fixture on local persistent filesystem")
    }

    fn options(path: PathBuf) -> VerificationHistoryOptions {
        VerificationHistoryOptions::new(path, 64 * 1024, 8, 8, 512 * 1024)
    }

    fn test_id(seed: u8) -> Id {
        let mut bytes = [seed; 16];
        bytes[6] = 0x40 | (seed & 0x0f);
        bytes[8] = 0x80 | (seed & 0x3f);
        Id::from_bytes(bytes)
    }

    fn incomplete_attempt() -> VerificationAttempt {
        VerificationAttempt::incomplete(
            VerificationObservation::new(RecoveryScope::SelectedRecoveryPoint),
            AttemptStage::Capture,
            FailureKind::Unavailable,
            Error::unsupported("test diagnostic stays out of the receipt"),
        )
    }

    fn incomplete_attempt_with_members(member_count: usize) -> VerificationAttempt {
        let mut observation = VerificationObservation::new(RecoveryScope::SelectedRecoveryPoint);
        observation
            .members_mut()
            .resize_with(member_count, MemberObservation::pending);
        VerificationAttempt::incomplete(
            observation,
            AttemptStage::Capture,
            FailureKind::Cancelled,
            Error::Cancelled,
        )
    }

    fn recorded_loss_attempt() -> VerificationAttempt {
        let mut observation = VerificationObservation::new(RecoveryScope::SelectedRecoveryPoint);
        observation.members_mut().push(MemberObservation::pending());
        let member = &mut observation.members_mut()[0];
        member.capture = MemberStage::Complete;
        member.raw_length = Some(1234);
        member.blake3_bytes = Some([0x35; 32]);
        member.identity = Some(MemberIdentity {
            image_uuid: ImageId::new(test_id(0x71)),
            chain_id: ChainId::new(test_id(0x72)),
            parent_uuid: ImageId::ZERO,
            set_id: SetId::new(test_id(0x73)),
            seq_in_chain: 0,
            image_kind: ImageKind::Block,
            legacy_header_kind: MemberKind::Full,
            whole_disk: false,
            consistency: Consistency::Offline,
        });
        let mut recorder = VerificationRecorder::new(observation);
        recorder.begin_structure(0);
        recorder.complete_structure(0);
        recorder.begin_content(ContentCoverage::BlockSelectedMergedReferences, 1);
        recorder.begin_recovery_point(0);
        recorder.complete_recovery_point(0);
        recorder.begin_referenced_payload(0);
        recorder.complete_referenced_payloads();
        recorder.finish(VerifyReport {
            image_uri: "diagnostic-only".to_owned(),
            image_kind: ImageKind::Block,
            members: 1,
            pages: 1,
            chunks: 1,
            bytes_checked: 1234,
            warnings: Vec::new(),
            recorded_bad_chunks: 1,
            every_member: false,
        })
    }

    fn overwrite_receipt(path: &std::path::Path, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(path)
            .expect("open receipt fixture for replacement");
        file.write_all(bytes).expect("replace receipt fixture");
        file.sync_all().expect("sync receipt fixture");
    }

    fn write_private_file(path: &std::path::Path, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .expect("create private ledger fixture");
        file.write_all(bytes).expect("write private ledger fixture");
        file.sync_all().expect("sync private ledger fixture");
    }

    #[test]
    fn uncertain_publication_does_not_become_recorded_and_never_overwrites() {
        let history_dir = local_history_dir();
        let history_options = options(history_dir.path().to_owned());
        let attempt = incomplete_attempt();
        let id = Id::from_bytes([
            0x51, 0x72, 0x93, 0xb4, 0xd5, 0xf6, 0x47, 0x18, 0x89, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x10,
        ]);

        let first = record_with_id(
            &attempt,
            &history_options,
            id,
            Some(PublicationFaultPoint::BeforeDirectorySync),
        );
        let receipt_id = id.to_uuid_string();
        assert_eq!(
            first,
            RecordingOutcome::PublicationUnconfirmed {
                receipt_id: receipt_id.clone(),
                reason: PublicationFailure::DirectorySyncUnconfirmed,
            }
        );
        let final_path = history_dir
            .path()
            .join(format!("receipt-{receipt_id}.json"));
        assert!(
            final_path.is_file(),
            "a final name alone is still uncertain"
        );
        let original = std::fs::read(&final_path).expect("read published bytes");

        let collision = record_with_id(&attempt, &history_options, id, None);
        assert_eq!(
            collision,
            RecordingOutcome::NotRecorded {
                reason: HistoryFailure::ReceiptIdCollision,
            }
        );
        assert_eq!(
            std::fs::read(&final_path).expect("read immutable receipt"),
            original,
            "no-replace publication must preserve the existing receipt"
        );
        let loaded = load_verification_history(&history_options).expect("read historical data");
        assert_eq!(loaded.receipts().len(), 1);
        assert_eq!(loaded.receipts()[0].receipt_id(), receipt_id);
    }

    #[test]
    fn filesystem_allowlist_handles_btrfs_signed_and_unsigned_magic() {
        assert!(supported_local_filesystem(0xef53));
        assert!(supported_local_filesystem(0x5846_5342));
        assert!(supported_local_filesystem(0x9123_683e));
        assert!(supported_local_filesystem(0x9123_683e_u32 as i32 as i64));
        assert!(!supported_local_filesystem(0x0102_1994)); // tmpfs
        assert!(!supported_local_filesystem(0x6969)); // NFS
        assert!(!supported_local_filesystem(0));
    }

    #[test]
    fn untrusted_or_volatile_directories_are_refused_before_ledger_writes() {
        let leaf = local_history_dir();
        std::fs::set_permissions(leaf.path(), std::fs::Permissions::from_mode(0o755))
            .expect("make only the test directory non-private");
        assert_eq!(
            record_with_id(
                &incomplete_attempt(),
                &options(leaf.path().to_owned()),
                test_id(0x31),
                None
            ),
            RecordingOutcome::NotRecorded {
                reason: HistoryFailure::UntrustedDirectory
            }
        );
        assert_eq!(
            std::fs::read_dir(leaf.path())
                .expect("inspect refused leaf")
                .count(),
            0
        );

        let parent = local_history_dir();
        let child = parent.path().join("ledger");
        std::fs::create_dir(&child).expect("create owned ledger fixture");
        std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o700))
            .expect("make ledger private");
        let link = parent.path().join("link");
        std::os::unix::fs::symlink(&child, &link).expect("create fixture symlink");
        assert!(matches!(
            record_with_id(&incomplete_attempt(), &options(link), test_id(0x32), None),
            RecordingOutcome::NotRecorded { .. }
        ));
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o777))
            .expect("make only the test ancestor untrusted");
        assert_eq!(
            record_with_id(
                &incomplete_attempt(),
                &options(child.clone()),
                test_id(0x33),
                None
            ),
            RecordingOutcome::NotRecorded {
                reason: HistoryFailure::UntrustedDirectory
            }
        );
        assert_eq!(
            std::fs::read_dir(&child)
                .expect("inspect refused ledger")
                .count(),
            0
        );
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700))
            .expect("restore fixture privacy before cleanup");

        // This exercises the real fd-based filesystem gate when the host's
        // ordinary temporary directory is volatile (as it is on our test host).
        let temporary = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .expect("private ordinary temporary fixture");
        let directory = std::fs::File::open(temporary.path()).expect("open fixture directory");
        let magic =
            lr_unsafe::filemeta::filesystem_type(&directory).expect("query fixture filesystem");
        if !supported_local_filesystem(magic) {
            assert_eq!(
                record_with_id(
                    &incomplete_attempt(),
                    &options(temporary.path().to_owned()),
                    test_id(0x34),
                    None
                ),
                RecordingOutcome::NotRecorded {
                    reason: HistoryFailure::UnsupportedFilesystem
                }
            );
            assert_eq!(
                std::fs::read_dir(temporary.path())
                    .expect("inspect refused filesystem")
                    .count(),
                0
            );
        }
    }

    #[test]
    fn incomplete_partial_capture_and_complete_capture_without_identity_are_preserved() {
        let mut early = VerificationObservation::new(RecoveryScope::SelectedRecoveryPoint);
        early.members_mut().push(MemberObservation::pending());
        assert!(validate_partial_observation(&early));

        let mut copied = VerificationObservation::new(RecoveryScope::SelectedRecoveryPoint);
        copied.members_mut().push(MemberObservation::pending());
        let member = &mut copied.members_mut()[0];
        member.capture = MemberStage::Complete;
        member.raw_length = Some(1234);
        member.blake3_bytes = Some([0x12; 32]);
        assert!(validate_partial_observation(&copied));

        let history_dir = local_history_dir();
        let history_options = options(history_dir.path().to_owned());
        let early_attempt = VerificationAttempt::incomplete(
            early,
            AttemptStage::Capture,
            FailureKind::Cancelled,
            Error::Cancelled,
        );
        let identity_pending_attempt = VerificationAttempt::incomplete(
            copied,
            AttemptStage::IdentityValidation,
            FailureKind::IdentityChanged,
            Error::corrupt("identity mismatch stays outside the receipt"),
        );
        assert!(matches!(
            record_with_id(&early_attempt, &history_options, test_id(0x66), None),
            RecordingOutcome::Recorded { .. }
        ));
        assert!(matches!(
            record_with_id(
                &identity_pending_attempt,
                &history_options,
                test_id(0x67),
                None
            ),
            RecordingOutcome::Recorded { .. }
        ));
        let loaded = load_verification_history(&history_options).expect("load partial facts");
        assert_eq!(loaded.receipts().len(), 2);
        assert!(loaded.receipts().iter().any(|receipt| {
            let member = &receipt.observation().members()[0];
            member.capture() == MemberStage::Complete
                && member.raw_length() == Some(1234)
                && member.blake3_bytes() == Some(&[0x12; 32])
                && member.identity().is_none()
        }));
    }

    #[test]
    fn partial_fact_validator_rejects_facts_without_prerequisites() {
        let mut failed_with_digest =
            VerificationObservation::new(RecoveryScope::SelectedRecoveryPoint);
        failed_with_digest
            .members_mut()
            .push(MemberObservation::pending());
        failed_with_digest.members_mut()[0].capture = MemberStage::Failed;
        failed_with_digest.members_mut()[0].blake3_bytes = Some([0x11; 32]);
        assert!(!validate_partial_observation(&failed_with_digest));

        let mut structure_without_identity =
            VerificationObservation::new(RecoveryScope::SelectedRecoveryPoint);
        structure_without_identity
            .members_mut()
            .push(MemberObservation::pending());
        structure_without_identity.members_mut()[0].capture = MemberStage::Complete;
        structure_without_identity.members_mut()[0].raw_length = Some(10);
        structure_without_identity.members_mut()[0].blake3_bytes = Some([0x22; 32]);
        structure_without_identity.members_mut()[0].structure = MemberStage::Failed;
        assert!(!validate_partial_observation(&structure_without_identity));

        let mut content_without_prerequisites =
            VerificationObservation::new(RecoveryScope::SelectedRecoveryPoint);
        content_without_prerequisites
            .members_mut()
            .push(MemberObservation::pending());
        let mut recorder = VerificationRecorder::new(content_without_prerequisites);
        recorder.begin_content(ContentCoverage::BlockSelectedMergedReferences, 1);
        let attempt = recorder.finish(VerifyReport {
            image_uri: "diagnostic-only".to_owned(),
            image_kind: ImageKind::Block,
            members: 1,
            pages: 0,
            chunks: 0,
            bytes_checked: 0,
            warnings: Vec::new(),
            recorded_bad_chunks: 0,
            every_member: false,
        });
        assert!(!validate_partial_observation(attempt.observation()));
    }

    #[test]
    fn recording_outcomes_have_stable_tagged_serde_projection() {
        let value = serde_json::to_value(RecordingOutcome::NotRecorded {
            reason: HistoryFailure::Busy,
        })
        .expect("serialize recording result");
        assert_eq!(
            value,
            serde_json::json!({"status": "not_recorded", "reason": "busy"})
        );
    }

    #[test]
    fn history_options_require_every_explicit_limit_and_reject_unknown_fields() {
        let complete = serde_json::json!({
            "history_directory": "/var/tmp/lr-history",
            "max_receipt_bytes": 4096,
            "max_members": 4,
            "max_entries": 8,
            "max_total_ledger_bytes": 32768
        });
        let options: VerificationHistoryOptions =
            serde_json::from_value(complete.clone()).expect("deserialize explicit history policy");
        assert_eq!(options.max_receipt_bytes(), 4096);
        assert_eq!(options.max_members(), 4);
        assert_eq!(options.max_entries(), 8);
        assert_eq!(options.max_total_ledger_bytes(), 32768);

        let missing = serde_json::json!({
            "history_directory": "/var/tmp/lr-history",
            "max_receipt_bytes": 4096,
            "max_members": 4,
            "max_entries": 8
        });
        assert!(serde_json::from_value::<VerificationHistoryOptions>(missing).is_err());

        let mut unknown = complete;
        unknown["auto_prune"] = serde_json::json!(true);
        assert!(serde_json::from_value::<VerificationHistoryOptions>(unknown).is_err());
    }

    #[test]
    fn recorded_loss_and_incomplete_outcomes_remain_distinct_after_load() {
        let history_dir = local_history_dir();
        let history_options = options(history_dir.path().to_owned());
        let incomplete_id = test_id(0x51);
        let loss_id = test_id(0x52);

        assert!(matches!(
            record_with_id(&incomplete_attempt(), &history_options, incomplete_id, None),
            RecordingOutcome::Recorded { .. }
        ));
        assert!(matches!(
            record_with_id(&recorded_loss_attempt(), &history_options, loss_id, None),
            RecordingOutcome::Recorded { .. }
        ));

        let loaded = load_verification_history(&history_options).expect("load typed outcomes");
        assert_eq!(loaded.receipts().len(), 2);
        assert!(loaded.receipts().iter().any(|receipt| matches!(
            receipt.observation().outcome(),
            crate::verify::AttemptOutcome::Incomplete { .. }
        )));
        assert!(loaded.receipts().iter().any(|receipt| {
            receipt.observation().outcome()
                == crate::verify::AttemptOutcome::IntegrityVerifiedWithRecordedLoss
        }));
    }

    #[test]
    fn reader_is_read_only_when_the_permanent_lock_is_missing() {
        let history_dir = local_history_dir();
        let history_options = options(history_dir.path().to_owned());
        assert!(load_verification_history(&history_options).is_err());
        assert_eq!(
            std::fs::read_dir(history_dir.path())
                .expect("list untouched ledger")
                .count(),
            0,
            "read-only load must not create .history.lock"
        );

        let absent = history_dir.path().join("not-created");
        let absent_options = options(absent.clone());
        assert!(load_verification_history(&absent_options).is_err());
        assert!(!absent.exists(), "reader must not create a missing ledger");
    }

    #[test]
    fn lock_contention_is_bounded_and_recording_recovers_after_release() {
        let history_dir = local_history_dir();
        let history_options = options(history_dir.path().to_owned());
        let lock_path = history_dir.path().join(".history.lock");
        {
            let lock = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(lock_path)
                .expect("create permanent lock fixture");
            lock.try_lock().expect("hold lock fixture");
            assert_eq!(
                record_with_id(&incomplete_attempt(), &history_options, test_id(0x53), None),
                RecordingOutcome::NotRecorded {
                    reason: HistoryFailure::Busy,
                }
            );
        }
        assert!(matches!(
            record_with_id(&incomplete_attempt(), &history_options, test_id(0x54), None),
            RecordingOutcome::Recorded { .. }
        ));
        assert_eq!(
            load_verification_history(&history_options)
                .expect("load after lock release")
                .receipts()
                .len(),
            1
        );
    }

    #[test]
    fn concurrent_appends_respect_entry_quota_and_corrupt_old_receipts_are_not_decoded() {
        let history_dir = local_history_dir();
        let shared_options = Arc::new(VerificationHistoryOptions::new(
            history_dir.path(),
            64 * 1024,
            8,
            1,
            512 * 1024,
        ));
        let barrier = Arc::new(Barrier::new(3));
        let (first, second) = thread::scope(|scope| {
            let first_options = Arc::clone(&shared_options);
            let first_barrier = Arc::clone(&barrier);
            let first = scope.spawn(move || {
                first_barrier.wait();
                record_with_id(&incomplete_attempt(), &first_options, test_id(0x55), None)
            });
            let second_options = Arc::clone(&shared_options);
            let second_barrier = Arc::clone(&barrier);
            let second = scope.spawn(move || {
                second_barrier.wait();
                record_with_id(&incomplete_attempt(), &second_options, test_id(0x56), None)
            });
            barrier.wait();
            (
                first.join().expect("first append"),
                second.join().expect("second append"),
            )
        });
        let recorded = usize::from(matches!(first, RecordingOutcome::Recorded { .. }))
            + usize::from(matches!(second, RecordingOutcome::Recorded { .. }));
        assert_eq!(recorded, 1, "one append wins the one-entry quota");
        assert_eq!(
            load_verification_history(&shared_options)
                .expect("read concurrent append result")
                .receipts()
                .len(),
            1
        );

        let corrupt_dir = local_history_dir();
        let corrupt_options = options(corrupt_dir.path().to_owned());
        let corrupt_id = test_id(0x57).to_uuid_string();
        write_private_file(
            &corrupt_dir
                .path()
                .join(format!("receipt-{corrupt_id}.json")),
            b"not json",
        );
        assert!(
            matches!(
                record_with_id(&incomplete_attempt(), &corrupt_options, test_id(0x58), None),
                RecordingOutcome::Recorded { .. }
            ),
            "append counts old receipt metadata without decoding its body"
        );
        assert!(load_verification_history(&corrupt_options).is_err());
    }

    #[test]
    fn pre_sync_temp_is_not_evidence_but_consumes_quota() {
        let history_dir = local_history_dir();
        let history_options =
            VerificationHistoryOptions::new(history_dir.path(), 64 * 1024, 8, 1, 512 * 1024);
        let before_sync = record_with_id(
            &incomplete_attempt(),
            &history_options,
            test_id(0x59),
            Some(PublicationFaultPoint::BeforeReceiptSync),
        );
        assert!(matches!(
            before_sync,
            RecordingOutcome::NotRecorded {
                reason: HistoryFailure::Unavailable
            }
        ));
        assert_eq!(
            load_verification_history(&history_options)
                .expect("temp debris is not receipt evidence")
                .receipts()
                .len(),
            0
        );
        assert_eq!(
            record_with_id(&incomplete_attempt(), &history_options, test_id(0x5a), None),
            RecordingOutcome::NotRecorded {
                reason: HistoryFailure::QuotaExceeded,
            },
            "leftover temporary data is retained and counts toward entry quota"
        );
        assert_eq!(
            std::fs::read_dir(history_dir.path())
                .expect("list ledger debris")
                .count(),
            2,
            "permanent lock and failed temp remain in place"
        );
    }

    #[test]
    fn total_ledger_byte_quota_refuses_without_creating_a_receipt_temp() {
        let history_dir = local_history_dir();
        let history_options =
            VerificationHistoryOptions::new(history_dir.path(), 64 * 1024, 8, 8, 1);
        assert_eq!(
            record_with_id(&incomplete_attempt(), &history_options, test_id(0x5b), None),
            RecordingOutcome::NotRecorded {
                reason: HistoryFailure::QuotaExceeded,
            }
        );
        let entries = std::fs::read_dir(history_dir.path())
            .expect("list byte-quota refusal")
            .map(|entry| entry.expect("ledger entry").file_name())
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].as_os_str(), OsStr::new(".history.lock"));
    }

    #[test]
    fn bounded_reader_rejects_oversized_corrupt_unsupported_and_semantically_invalid_receipts() {
        let history_dir = local_history_dir();
        let write_attempt = incomplete_attempt_with_members(2);
        let write_options = options(history_dir.path().to_owned());
        assert!(matches!(
            record_with_id(&write_attempt, &write_options, test_id(0x61), None),
            RecordingOutcome::Recorded { .. }
        ));
        let narrow_options =
            VerificationHistoryOptions::new(history_dir.path(), 64 * 1024, 1, 8, 512 * 1024);
        assert!(load_verification_history(&narrow_options).is_err());
        let byte_limited = VerificationHistoryOptions::new(history_dir.path(), 1, 8, 8, 512 * 1024);
        assert!(load_verification_history(&byte_limited).is_err());
        let total_limited = VerificationHistoryOptions::new(history_dir.path(), 64 * 1024, 8, 8, 1);
        assert!(load_verification_history(&total_limited).is_err());
        assert!(matches!(
            record_with_id(&write_attempt, &write_options, test_id(0x60), None),
            RecordingOutcome::Recorded { .. }
        ));
        let entry_limited =
            VerificationHistoryOptions::new(history_dir.path(), 64 * 1024, 8, 1, 512 * 1024);
        assert!(load_verification_history(&entry_limited).is_err());

        for (seed, mutation) in [
            (
                0x62,
                Box::new(|value: &mut serde_json::Value| {
                    value["schema_version"] = serde_json::json!(2);
                }) as Box<dyn Fn(&mut serde_json::Value)>,
            ),
            (
                0x63,
                Box::new(|value: &mut serde_json::Value| {
                    value["observation"]["outcome"]["status"] = serde_json::json!("future_outcome");
                }),
            ),
            (
                0x64,
                Box::new(|value: &mut serde_json::Value| {
                    value["observation"]["members"][0]["blake3_bytes"] =
                        serde_json::json!(vec![0; 32]);
                }),
            ),
        ] {
            let case_dir = local_history_dir();
            let case_options = options(case_dir.path().to_owned());
            let id = test_id(seed);
            assert!(matches!(
                record_with_id(&incomplete_attempt_with_members(1), &case_options, id, None),
                RecordingOutcome::Recorded { .. }
            ));
            let path = case_dir
                .path()
                .join(format!("receipt-{}.json", id.to_uuid_string()));
            let mut value: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).expect("read receipt fixture"))
                    .expect("parse receipt fixture");
            mutation(&mut value);
            overwrite_receipt(
                &path,
                &serde_json::to_vec(&value).expect("serialize mutated fixture"),
            );
            assert!(load_verification_history(&case_options).is_err());
        }

        let corrupt_dir = local_history_dir();
        let corrupt_options = options(corrupt_dir.path().to_owned());
        let corrupt_id = test_id(0x65);
        assert!(matches!(
            record_with_id(&incomplete_attempt(), &corrupt_options, corrupt_id, None),
            RecordingOutcome::Recorded { .. }
        ));
        assert_eq!(
            load_verification_history(&corrupt_options)
                .expect("valid control")
                .receipts()
                .len(),
            1
        );
        overwrite_receipt(
            &corrupt_dir
                .path()
                .join(format!("receipt-{corrupt_id}.json")),
            b"{ truncated",
        );
        assert!(matches!(
            load_verification_history(&corrupt_options),
            Err(Error::Corrupt { .. })
        ));

        assert!(parse_receipt_filename(&format!("receipt-{}.json", "é".repeat(16))).is_err());
    }

    #[test]
    fn reader_rejects_success_receipts_with_inconsistent_coverage_facts() {
        let history_dir = local_history_dir();
        let history_options = options(history_dir.path().to_owned());
        let id = test_id(0x68);
        assert!(matches!(
            record_with_id(&recorded_loss_attempt(), &history_options, id, None),
            RecordingOutcome::Recorded { .. }
        ));
        let path = history_dir
            .path()
            .join(format!("receipt-{}.json", id.to_uuid_string()));
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("read success fixture"))
                .expect("parse success fixture");
        value["observation"]["members"][0]["identity"]["whole_disk"] = serde_json::json!(true);
        overwrite_receipt(
            &path,
            &serde_json::to_vec(&value).expect("serialize invalid success fixture"),
        );
        assert!(load_verification_history(&history_options).is_err());
    }
}
