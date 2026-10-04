//! Image verification (spec §G.8, Slice S11).
//!
//! Verification has two halves. The structural half (magic numbers, the
//! superblock/footer MACs, chunk framing and every metadata page tag) lives in
//! [`lr_format::verify_structure`]. The content half is recomputing each stored
//! chunk's keyed hash from its plaintext and comparing it with the manifest —
//! that is the only check that notices a chunk whose ciphertext was replaced
//! with valid-but-different data — plus reading every chain member so an
//! incremental that lost an ancestor is reported where it broke.
//!
//! Failures name the offender: the chunk index, the chain member and the file
//! offset, so a report is actionable without a debugger (spec §K S11).

use std::path::PathBuf;

use lr_core::{Error, ImageKind, Result};
use lr_format::{
    BlockEntry, BlockManifestHeader, ChunkState, DiskHeader, ImageReader, StreamId, Superblock,
    open_chunk, verify_structure, wire,
};
use lr_store::{Destination, DestinationOptions, SetHandle, uri};

use crate::keys::{self, Encryption};

mod capture;
mod history;
mod observation;

pub use capture::CaptureOptions;
pub use history::{
    HistoryFailure, PublicationFailure, RecordingOutcome, VerificationHistory,
    VerificationHistoryOptions, VerificationReceipt, load_verification_history,
    record_verification_attempt,
};
use observation::VerificationRecorder;
pub use observation::{
    AttemptOutcome, AttemptStage, ContentCoverage, DigestAlgorithm, FailureKind,
    MemberContentStages, MemberIdentity, MemberObservation, MemberStage, RecoveryScope,
    StructureNotice, VerificationAttempt, VerificationObservation,
};

/// Largest plaintext a stream chunk can hold (CDC's maximum).
const MAX_STREAM_CHUNK: usize = 256 * 1024;

/// What to verify.
pub struct VerifyRequest {
    /// Image URI: `<dest>/<set>/<chain>/<file>.lrimg`.
    pub image: String,
    /// How to unlock the image.
    pub encryption: Encryption,
    /// Walk every ancestor of the image, not just the image itself.
    pub chain: bool,
    /// How to reach the destination.
    pub destination_options: DestinationOptions,
    /// Live progress and cooperative cancellation (spec §I).
    pub context: crate::progress::EngineContext,
}

/// Result of a verification.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VerifyReport {
    /// Image that was verified.
    pub image_uri: String,
    /// Image kind found in the superblock.
    pub image_kind: ImageKind,
    /// Chain members whose structure was verified.
    pub members: u64,
    /// Metadata pages whose tags were verified.
    pub pages: u64,
    /// Stored chunks whose plaintext was re-hashed.
    pub chunks: u64,
    /// Plaintext bytes covered by those chunks.
    pub bytes_checked: u64,
    /// Findings that do not fail verification but need the user's attention.
    #[serde(default)]
    pub warnings: Vec<String>,
    /// Chunks the source could not read when the image was taken; a
    /// non-zero count means the image cannot be restored completely (R26).
    #[serde(default)]
    pub recorded_bad_chunks: u64,
    /// Whether every recovery point of the chain was read (every payload of
    /// every member), or only this image's own recovery point.
    #[serde(default)]
    pub every_member: bool,
}

impl VerifyReport {
    /// Require a recovery point without recorded unreadable source regions.
    ///
    /// Integrity verification can succeed for a faithfully recorded bad sector.
    /// Such a report must not qualify as a complete replacement backup (D-125).
    /// This does not establish source consistency, target readiness or durability.
    ///
    /// # Errors
    /// Returns [`Error::Unsupported`] when source data was not backed up.
    pub fn ensure_complete_recovery(&self) -> Result<()> {
        if self.recorded_bad_chunks != 0 {
            return Err(Error::unsupported(crate::plan::bad_sector_message(
                self.recorded_bad_chunks,
                None,
            )));
        }
        Ok(())
    }

    /// One line per verified member, for the CLI's summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{}: {:?}, {} member(s), {} page(s), {} chunk(s), {} bytes",
            self.image_uri,
            self.image_kind,
            self.members,
            self.pages,
            self.chunks,
            self.bytes_checked
        )
    }
}

/// The warning for an encrypted image written before D-110.
#[must_use]
pub fn legacy_nonce_warning(name: &str) -> String {
    format!(
        "{name} was written before the metadata nonce fix (D-110): its manifest and \
         extras reuse nonces under one key, so their confidentiality and integrity are \
         weakened (chunk data is not affected); create a new full backup to replace this chain"
    )
}

/// Verify an image, and with `chain` its whole ancestry.
///
/// # Errors
/// Returns [`Error::Corrupt`] naming the chunk or member that failed, and
/// propagates destination, key and I/O errors.
pub fn verify_image(request: &VerifyRequest) -> Result<VerifyReport> {
    let location = uri::split_image(&request.image)?;
    let mut options = request.destination_options.clone();
    options.set_name.clone_from(&location.set);
    let destination = lr_store::open(&location.dest, &options)?;
    let set = destination.open_existing_set(&lr_core::SetId::ZERO)?;
    verify_in_set(&*destination, &set, &location.name, request)
}

/// Verify one selected recovery point against a private, content-bound capture.
///
/// This opt-in entry point copies the resolved ancestry into anonymous scratch
/// files before invoking the same engine verifier used by [`verify_image`].
/// The supplied cap and headroom are mandatory, and the source destination is
/// never used as a verifier fallback after capture. The returned observation
/// describes only the integrity checks requested; it is not a restore,
/// retention, durability, source-consistency, or current-health decision.
///
/// Capture and verification failures are returned as an incomplete attempt;
/// their diagnostic error is available separately and is not serialized in
/// the observation.
pub fn verify_image_captured(
    request: &VerifyRequest,
    options: &CaptureOptions,
) -> VerificationAttempt {
    let scope = if request.chain {
        RecoveryScope::EveryMember
    } else {
        RecoveryScope::SelectedRecoveryPoint
    };
    let mut observation = VerificationObservation::new(scope);
    let captured = match capture::capture_chain(request, options, &mut observation) {
        Ok(captured) => captured,
        Err(failure) => {
            return VerificationAttempt::incomplete(
                observation,
                failure.stage,
                failure.reason,
                failure.error,
            );
        }
    };
    let (destination, set, members, name) = captured.into_verify_parts();
    let mut recorder = VerificationRecorder::new(observation);
    match verify_members_in_set_recorded(
        &destination,
        &set,
        &name,
        &members,
        request,
        &mut recorder,
    ) {
        Ok(report) => recorder.finish(report),
        Err(error) => recorder.fail(error),
    }
}

/// Record a successful whole-chain verification in the set's catalog, so
/// the UI can show historical verification (R20). Retention still performs
/// fresh verification before deletion; this timestamp is not deletion authority.
///
/// Only a report that read every member counts. The set lock is taken
/// briefly; when another job holds it, the record is skipped and the
/// returned note says so.
///
/// # Errors
/// Propagates destination and catalog errors other than a busy set.
pub fn record_verification(
    request: &VerifyRequest,
    report: &VerifyReport,
) -> Result<Option<String>> {
    if !report.every_member {
        return Ok(None);
    }
    if let Err(error) = report.ensure_complete_recovery() {
        return Ok(Some(format!("verification was not recorded: {error}")));
    }
    let location = uri::split_image(&request.image)?;
    let mut options = request.destination_options.clone();
    options.set_name.clone_from(&location.set);
    let destination = lr_store::open(&location.dest, &options)?;
    let set = destination.open_existing_set(&lr_core::SetId::ZERO)?;
    let lock = match crate::backup::acquire_set_lock_for(&*destination, &set, 60, false) {
        Ok(lock) => lock,
        Err(Error::SetLocked { owner }) => {
            return Ok(Some(format!(
                "the set is locked by {owner}; the verification was not recorded"
            )));
        }
        Err(error) => return Err(error),
    };
    let now = crate::backup::now_unix();
    let mut loaded = crate::catalog::load(&*destination, &set, &location.set, now)?;
    let verified: std::collections::HashSet<String> =
        crate::chain::resolve_chain(&*destination, &set, &location.name)?
            .into_iter()
            .map(|member| member.file_name)
            .collect();
    mark_verified(&mut loaded.catalog, &verified, now);
    lock.verify()?;
    crate::catalog::write_catalog(&*destination, &set, &loaded.catalog)?;
    Ok(None)
}

/// Mark the named members verified at `now`.
pub(crate) fn mark_verified(
    catalog: &mut lr_core::catalog::Catalog,
    files: &std::collections::HashSet<String>,
    now: u64,
) {
    for chain in &mut catalog.chains {
        for member in &mut chain.members {
            if files.contains(&member.file_name) {
                member.verified_unix = Some(now);
            }
        }
    }
}

/// [`verify_image`] on a destination that is already open; `request.image`
/// only names the image in the report.
///
/// # Errors
/// See [`verify_image`].
pub(crate) fn verify_in_set(
    destination: &dyn Destination,
    set: &SetHandle,
    name: &str,
    request: &VerifyRequest,
) -> Result<VerifyReport> {
    // The image's whole ancestry is always opened: a non-full member's
    // recovery point needs the payloads it inherits (R23). `--chain`
    // additionally reads every payload every member stores, including
    // superseded ones, which are recovery points of older members (R22).
    let members = crate::chain::resolve_chain(destination, set, name)?;
    verify_members_in_set(destination, set, name, &members, request)
}

/// Verify an already selected member order without resolving another chain.
/// The caller owns selection/identity validation; ordinary verification resolves
/// above, while restore compares these names and superblocks to its token.
/// Files remain mutable: this is not a lease or a snapshot of their contents.
pub(crate) fn verify_members_in_set(
    destination: &dyn Destination,
    set: &SetHandle,
    name: &str,
    members: &[crate::chain::ChainMemberFile],
    request: &VerifyRequest,
) -> Result<VerifyReport> {
    verify_members_in_set_inner(destination, set, name, members, request, None)
}

fn verify_members_in_set_recorded(
    destination: &dyn Destination,
    set: &SetHandle,
    name: &str,
    members: &[crate::chain::ChainMemberFile],
    request: &VerifyRequest,
    recorder: &mut VerificationRecorder,
) -> Result<VerifyReport> {
    verify_members_in_set_inner(destination, set, name, members, request, Some(recorder))
}

fn verify_members_in_set_inner(
    destination: &dyn Destination,
    set: &SetHandle,
    name: &str,
    members: &[crate::chain::ChainMemberFile],
    request: &VerifyRequest,
    mut recorder: Option<&mut VerificationRecorder>,
) -> Result<VerifyReport> {
    if members.last().map(|member| member.file_name.as_str()) != Some(name) {
        return Err(Error::corrupt(format!(
            "{name} is not the last member of the selected chain"
        )));
    }
    let target = crate::chain::read_superblock(destination, set, name)?;
    let every_member = request.chain;

    let mut reporter = request.context.clone().reporter(0)?;
    reporter.phase("structure");
    let mut report = VerifyReport {
        image_uri: request.image.clone(),
        image_kind: target.image_kind,
        members: 0,
        pages: 0,
        chunks: 0,
        bytes_checked: 0,
        warnings: Vec::new(),
        recorded_bad_chunks: 0,
        every_member: every_member || members.len() == 1,
    };

    // 1. Structure, MACs and page tags, member by member.
    for (member_index, member) in members.iter().enumerate() {
        if let Some(recorder) = recorder.as_deref_mut() {
            recorder.begin_structure(member_index);
        }
        let structure = (|| {
            request.context.check_cancel()?;
            let superblock = crate::chain::read_superblock(destination, set, &member.file_name)?;
            let keys = keys::unlock_image(&request.encryption, &superblock)?;
            let encrypted = superblock.is_encrypted();
            let page_report = verify_structure(
                destination.open_ro(set, &member.file_name)?,
                *keys.meta_key,
                encrypted,
            )
            .map_err(|error| {
                Error::corrupt(format!(
                    "{}: structure of {} failed: {error}",
                    member.file_name, superblock.image_uuid
                ))
            })?;
            Ok((page_report, encrypted))
        })();
        let (page_report, encrypted) = match structure {
            Ok(value) => value,
            Err(error) => {
                if let Some(recorder) = recorder.as_deref_mut() {
                    recorder.fail_structure(member_index);
                }
                return Err(error);
            }
        };
        if let Some(recorder) = recorder.as_deref_mut() {
            recorder.complete_structure(member_index);
        }
        report.pages += page_report.total_pages() as u64;
        report.members += 1;
        if encrypted && page_report.repeated_page_nonces {
            if let Some(recorder) = recorder.as_deref_mut() {
                recorder.note_structure(
                    member_index,
                    StructureNotice::RepeatedEncryptedMetadataPageNonce,
                );
            }
            report
                .warnings
                .push(legacy_nonce_warning(&member.file_name));
        }
    }

    // 2. Content: every stored chunk's plaintext must hash to the manifest.
    reporter.phase("content");
    if let Some(recorder) = recorder.as_deref_mut() {
        recorder.enter_content_phase();
    }
    request.context.check_cancel()?;
    match target.image_kind {
        ImageKind::Block if target.is_whole_disk() => {
            let target_index = members.len() - 1;
            if let Some(recorder) = recorder.as_deref_mut() {
                recorder.begin_content(
                    content_coverage(target.image_kind, true, every_member),
                    members.len(),
                );
            }
            verify_whole_disk(
                destination,
                set,
                name,
                &request.encryption,
                VerificationProgress {
                    reporter: &mut reporter,
                    report: &mut report,
                    recorder,
                },
                target_index,
            )?;
        }
        ImageKind::Block => {
            if let Some(recorder) = recorder.as_deref_mut() {
                recorder.begin_content(
                    content_coverage(target.image_kind, false, every_member),
                    members.len(),
                );
            }
            verify_block_chain(
                destination,
                set,
                members,
                &request.encryption,
                every_member,
                VerificationProgress {
                    reporter: &mut reporter,
                    report: &mut report,
                    recorder,
                },
            )?;
        }
        ImageKind::Stream => {
            // Stream members carry their own payloads; one recovery point is
            // its own member's streams.
            let own = if every_member {
                members
            } else {
                &members[members.len() - 1..]
            };
            if let Some(recorder) = recorder.as_deref_mut() {
                recorder.begin_content(
                    content_coverage(target.image_kind, false, every_member),
                    members.len(),
                );
            }
            verify_stream(
                destination,
                set,
                own,
                if every_member { 0 } else { members.len() - 1 },
                &request.encryption,
                VerificationProgress {
                    reporter: &mut reporter,
                    report: &mut report,
                    recorder,
                },
            )?;
        }
        ImageKind::File => {
            if let Some(recorder) = recorder.as_deref_mut() {
                recorder.begin_content(
                    content_coverage(target.image_kind, false, every_member),
                    members.len(),
                );
            }
            verify_file(
                destination,
                set,
                members,
                &request.encryption,
                every_member,
                VerificationProgress {
                    reporter: &mut reporter,
                    report: &mut report,
                    recorder,
                },
            )?;
        }
    }

    request.context.check_cancel()?;
    reporter.finish(report.chunks);
    Ok(report)
}

fn content_coverage(
    image_kind: ImageKind,
    whole_disk: bool,
    every_member: bool,
) -> ContentCoverage {
    if whole_disk {
        ContentCoverage::WholeDiskRegionsAndLayout
    } else {
        match (image_kind, every_member) {
            (ImageKind::Block, false) => ContentCoverage::BlockSelectedMergedReferences,
            (ImageKind::Block, true) => ContentCoverage::BlockEveryStoredPayload,
            (ImageKind::File, false) => ContentCoverage::FileSelectedTreeReferences,
            (ImageKind::File, true) => ContentCoverage::FileEveryTreeReferences,
            (ImageKind::Stream, false) => {
                ContentCoverage::StreamSelectedMemberPayloadsSectionsAndLayout
            }
            (ImageKind::Stream, true) => {
                ContentCoverage::StreamEveryMemberPayloadsSectionsAndLayout
            }
        }
    }
}

/// The shared mutable output for a mode-specific verifier branch.
struct VerificationProgress<'a> {
    reporter: &'a mut crate::progress::Reporter,
    report: &'a mut VerifyReport,
    recorder: Option<&'a mut VerificationRecorder>,
}

impl VerificationProgress<'_> {
    fn recorder(&mut self) -> Option<&mut VerificationRecorder> {
        self.recorder.as_deref_mut()
    }
}

/// Re-hash every chunk of a block chain, using the merged state walker.
fn verify_block_chain(
    destination: &dyn Destination,
    set: &SetHandle,
    members: &[crate::chain::ChainMemberFile],
    encryption: &Encryption,
    every_member: bool,
    mut progress: VerificationProgress<'_>,
) -> Result<()> {
    let target_index = members.len() - 1;
    if let Some(recorder) = progress.recorder() {
        recorder.begin_recovery_point(target_index);
    }
    let opened = crate::chain::open_chain(destination, set, members, encryption)?;
    let mut walk = crate::chain::ChainWalk::new(opened)?;
    let mut bad = 0u64;
    let mut first_bad = None;
    let chunk_size = u64::from(walk.chunk_size());
    walk.walk(|index, state, access| {
        progress.reporter.report(index)?;
        if state == ChunkState::BadSector {
            bad += 1;
            first_bad.get_or_insert(index * chunk_size);
        }
        let ChunkState::Stored {
            member,
            offset,
            stored_len,
            ..
        } = state
        else {
            return Ok(());
        };
        let owner_index = usize::from(member);
        if let Some(recorder) = progress.recorder() {
            recorder.begin_referenced_payload(owner_index);
        }
        let member_name = members
            .get(usize::from(member))
            .map_or("?", |file| file.file_name.as_str());
        let plaintext = access.read(&state).map_err(|error| {
            Error::corrupt(format!(
                "{member_name}: chunk {index} (member {member}, offset {offset}, {stored_len} \
                 stored bytes) failed: {error}"
            ))
        })?;
        progress.report.chunks += 1;
        progress.report.bytes_checked += plaintext.len() as u64;
        Ok(())
    })?;
    if let Some(recorder) = progress.recorder() {
        recorder.complete_referenced_payloads();
        recorder.complete_recovery_point(target_index);
    }
    // Recorded bad sectors are not corruption, but the image cannot be
    // restored completely, and `prepare` refuses it (R26).
    progress.report.recorded_bad_chunks += bad;
    if bad > 0 {
        progress
            .report
            .warnings
            .push(crate::plan::bad_sector_message(bad, first_bad));
    }
    if !every_member {
        return Ok(());
    }
    if let Some(recorder) = progress.recorder() {
        recorder.begin_all_stored_payloads();
    }
    // Every payload every member stores, superseded ones included (R22).
    walk.walk_own_payloads(|index, state, access| {
        progress.reporter.report(progress.report.chunks)?;
        let ChunkState::Stored {
            member,
            offset,
            stored_len,
            ..
        } = state
        else {
            return Ok(());
        };
        let member_name = members
            .get(usize::from(member))
            .map_or("?", |file| file.file_name.as_str());
        let plaintext = access.read(&state).map_err(|error| {
            Error::corrupt(format!(
                "{member_name}: its own chunk {index} (offset {offset}, {stored_len} stored \
                 bytes) failed: {error}"
            ))
        })?;
        progress.report.chunks += 1;
        progress.report.bytes_checked += plaintext.len() as u64;
        Ok(())
    })?;
    if let Some(recorder) = progress.recorder() {
        recorder.complete_all_stored_payloads();
    }
    Ok(())
}

/// Verify a file-mode chain: every reference resolves, every stored chunk
/// hashes to its manifest value, and the names are reported when one fails.
fn verify_file(
    destination: &dyn Destination,
    set: &SetHandle,
    members: &[crate::chain::ChainMemberFile],
    encryption: &Encryption,
    every_member: bool,
    mut progress: VerificationProgress<'_>,
) -> Result<()> {
    let mut opened = crate::chain::open_chain(destination, set, members, encryption)?;

    // Pass 1: the chain's hash index, so a reference to an ancestor resolves.
    let mut index: std::collections::HashMap<[u8; 32], (usize, u64, String)> =
        std::collections::HashMap::new();
    for (position, member) in opened.iter_mut().enumerate() {
        let bytes = member.stream_bytes(StreamId::HashIndex)?;
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        while (cursor.position() as usize) < bytes.len() {
            let mut wire = wire::Reader::new(&mut cursor);
            let entry = BlockEntry::read(&mut wire)?;
            if entry.is_stored() {
                index.insert(
                    entry.hash,
                    (position, entry.offset, member.file_name.clone()),
                );
            }
        }
    }

    // Pass 2: every reference of every tree read must resolve, and every
    // chunk it names is decoded and re-hashed. With every member, each tree
    // is read and each member decodes the chunks it stores; for one recovery
    // point, the newest tree is read and every chunk it references is decoded
    // wherever in the ancestry it lives (R23).
    let mut restored_files = 0u64;
    let last = opened.len().saturating_sub(1);
    let trees: Vec<usize> = if every_member {
        (0..opened.len()).collect()
    } else {
        vec![last]
    };
    for position in trees {
        if let Some(recorder) = progress.recorder() {
            recorder.begin_recovery_point(position);
        }
        let (file_name, records) = {
            let member = &mut opened[position];
            let bytes = member.stream_bytes(StreamId::Manifest)?;
            (member.file_name.clone(), lr_format::read_manifest(&bytes)?)
        };
        progress.reporter.phase(&format!("member {file_name}"));
        // The tree a restore of this recovery point would build (R25).
        // Borrow the records: cloning this view would duplicate every xattr,
        // ACL and chunk reference during restore's preverification pass.
        let tree: std::collections::BTreeMap<&[u8], &lr_format::FileRecord> = records
            .iter()
            .map(|record| (record.entry.path.as_slice(), record))
            .collect();
        crate::plan::file_tree(&tree)
            .map_err(|error| Error::corrupt(format!("{file_name}: {error}")))?;
        drop(tree);
        for record in &records {
            restored_files += 1;
            let mut position_in_file = 0u64;
            for hash in &record.entry.chunk_refs_here {
                let Some((owner, offset, _)) = index.get(hash) else {
                    return Err(Error::corrupt(format!(
                        "{file_name}: {} references a chunk no member of the chain stores",
                        String::from_utf8_lossy(&record.entry.path)
                    )));
                };
                if let Some(recorder) = progress.recorder() {
                    recorder.begin_referenced_payload(*owner);
                }
                let holder = &mut opened[*owner];
                let entry = BlockEntry::stored(
                    u16::try_from(*owner).unwrap_or(u16::MAX),
                    *hash,
                    *offset,
                    0,
                )?;
                let plaintext =
                    holder
                        .chunk_plaintext(&entry, MAX_STREAM_CHUNK)
                        .map_err(|error| {
                            Error::corrupt(format!(
                                "{}: {} (offset {}, member {}) failed: {error}",
                                holder.file_name,
                                String::from_utf8_lossy(&record.entry.path),
                                offset,
                                holder.superblock.image_uuid
                            ))
                        })?;
                crate::plan::holes_hold_zeros(
                    &record.entry.path,
                    &record.holes,
                    position_in_file,
                    &plaintext,
                )
                .map_err(|error| Error::corrupt(format!("{file_name}: {error}")))?;
                position_in_file += plaintext.len() as u64;
                progress.reporter.report(progress.report.bytes_checked)?;
                progress.report.chunks += 1;
                progress.report.bytes_checked += plaintext.len() as u64;
            }
            if record.entry.file_kind == lr_format::FILE_KIND_REGULAR
                && position_in_file != record.entry.size
            {
                return Err(Error::corrupt(format!(
                    "{file_name}: {} records {} bytes, its chunks hold {position_in_file}",
                    String::from_utf8_lossy(&record.entry.path),
                    record.entry.size
                )));
            }
        }
        if let Some(recorder) = progress.recorder() {
            recorder.complete_recovery_point(position);
        }
    }
    if let Some(recorder) = progress.recorder() {
        recorder.complete_referenced_payloads();
    }
    tracing::debug!(files = restored_files, "file manifest verified");
    Ok(())
}

/// Re-hash every chunk of every subvolume section of a stream image.
fn verify_stream(
    destination: &dyn Destination,
    set: &SetHandle,
    members: &[crate::chain::ChainMemberFile],
    member_offset: usize,
    encryption: &Encryption,
    mut progress: VerificationProgress<'_>,
) -> Result<()> {
    for (member_index, member) in members.iter().enumerate() {
        let member_index = member_offset + member_index;
        if let Some(recorder) = progress.recorder() {
            recorder.begin_recovery_point(member_index);
            recorder.begin_member_stored_payloads(member_index);
        }
        progress
            .reporter
            .phase(&format!("member {}", member.file_name));
        let mut reader = ImageReader::open(destination.open_ro(set, &member.file_name)?)?;
        let keys = keys::unlock_image(encryption, reader.superblock())?;
        let superblock = reader.superblock().clone();
        let kind = superblock.aead_kind()?;
        let mut manifest = Vec::new();
        {
            let mut page = reader.stream_reader(StreamId::Manifest, *keys.meta_key, kind)?;
            let mut buffer = vec![0u8; 64 * 1024];
            loop {
                let read = page.read_bytes_partial(&mut buffer)?;
                if read == 0 {
                    break;
                }
                manifest.extend_from_slice(&buffer[..read]);
            }
        }
        let mut cursor = std::io::Cursor::new(manifest.as_slice());
        let mut chunks = reader.chunk_reader_with(destination.open_ro(set, &member.file_name)?);
        while (cursor.position() as usize) < manifest.len() {
            let mut wire = wire::Reader::new(&mut cursor);
            let section = lr_format::StreamSection::read(&mut wire)?;
            for index in 0..section.entry_count {
                let entry = BlockEntry::read(&mut wire)?;
                if !entry.is_stored() {
                    continue;
                }
                let record = chunks.read_record(entry.offset)?;
                let plaintext = open_chunk(
                    kind,
                    keys.data_key.as_deref(),
                    &keys.dedup_key,
                    ImageKind::Stream,
                    &entry.hash,
                    MAX_STREAM_CHUNK,
                    &record,
                )
                .map_err(|error| {
                    Error::corrupt(format!(
                        "{}: chunk {index} of {} (offset {}) failed: {error}",
                        member.file_name, section.subvol_path, entry.offset
                    ))
                })?;
                progress.reporter.report(progress.report.chunks)?;
                progress.report.chunks += 1;
                progress.report.bytes_checked += plaintext.len() as u64;
            }
        }
        // What a restore needs, the section list and the Btrfs layout
        // record, must parse; a missing layout fails here, not at restore
        // time (R25).
        crate::stream::read_stream_image(destination, set, &member.file_name, encryption)
            .map_err(|error| Error::corrupt(format!("{}: {error}", member.file_name)))?;
        if let Some(recorder) = progress.recorder() {
            recorder.complete_recovery_point(member_index);
            recorder.complete_member_stored_payloads(member_index);
        }
    }
    Ok(())
}

/// Re-hash every chunk of every region of a whole-disk image.
fn verify_whole_disk(
    destination: &dyn Destination,
    set: &SetHandle,
    name: &str,
    encryption: &Encryption,
    mut progress: VerificationProgress<'_>,
    member_index: usize,
) -> Result<()> {
    if let Some(recorder) = progress.recorder() {
        recorder.begin_recovery_point(member_index);
    }
    let mut reader = ImageReader::open(destination.open_ro(set, name)?)?;
    let keys = keys::unlock_image(encryption, reader.superblock())?;
    let superblock: Superblock = reader.superblock().clone();
    // The restore plan's checks: counts, kinds, bounds, geometry and complete
    // consumption (R24), and recorded bad sectors (R26).
    let summary = crate::plan::whole_disk(&mut reader, &keys.meta_key, &superblock)?;
    if let Some(recorder) = progress.recorder() {
        recorder.complete_recovery_point(member_index);
        recorder.begin_disk_region_payloads(member_index);
    }
    progress.report.recorded_bad_chunks += summary.bad;
    if summary.bad > 0 {
        progress
            .report
            .warnings
            .push(crate::plan::bad_sector_message(
                summary.bad,
                summary.first_bad,
            ));
    }
    let kind = superblock.aead_kind()?;
    let chunk_size = u64::from(superblock.chunk_size);
    let mut chunks = reader.chunk_reader_with(destination.open_ro(set, name)?);

    let manifest = reader.stream_reader(StreamId::Manifest, *keys.meta_key, kind)?;
    let mut wire = wire::Reader::new(manifest);
    let disk_header = {
        let header = DiskHeader::read(&mut wire)?;
        header.validate()?;
        header
    };
    for region in &disk_header.regions {
        if !region.has_manifest() {
            continue;
        }
        let (header, _delta) = BlockManifestHeader::read(&mut wire)?;
        for index in 0..header.entry_count {
            progress.reporter.report(progress.report.bytes_checked)?;
            let entry = BlockEntry::read(&mut wire)?;
            if !entry.is_stored() {
                continue;
            }
            let record = chunks.read_record(entry.offset)?;
            let plaintext = open_chunk(
                kind,
                keys.data_key.as_deref(),
                &keys.dedup_key,
                ImageKind::Block,
                &entry.hash,
                chunk_size as usize,
                &record,
            )
            .map_err(|error| {
                Error::corrupt(format!(
                    "region {} chunk {index} (offset {}) failed: {error}",
                    region.index, entry.offset
                ))
            })?;
            progress.report.chunks += 1;
            progress.report.bytes_checked += plaintext.len() as u64;
        }
    }
    if let Some(recorder) = progress.recorder() {
        recorder.complete_disk_region_payloads(member_index);
    }
    Ok(())
}

/// The destination, set and name of an image URI, for callers that need them
/// before opening the image.
///
/// # Errors
/// See [`uri::split_image`].
pub fn locate(image: &str) -> Result<(String, String, String)> {
    let location = uri::split_image(image)?;
    Ok((location.dest, location.set, location.name))
}

/// A parsed chain member list, for the CLI's `--chain` summary.
///
/// # Errors
/// See [`crate::chain::resolve_chain`].
pub fn chain_names(image: &str, options: &DestinationOptions) -> Result<Vec<String>> {
    let (dest, set_name, name) = locate(image)?;
    let mut options = options.clone();
    options.set_name = set_name;
    let destination = lr_store::open(&dest, &options)?;
    let set = destination.open_existing_set(&lr_core::SetId::ZERO)?;
    Ok(crate::chain::resolve_chain(&*destination, &set, &name)?
        .into_iter()
        .map(|member| member.file_name)
        .collect())
}

/// The path a member name maps to, for diagnostics.
#[must_use]
pub fn member_label(dest: &str, set: &str, name: &str) -> PathBuf {
    PathBuf::from(format!("{dest}/{set}/{name}"))
}

#[cfg(test)]
mod captured_coverage_tests {
    use super::{ContentCoverage, content_coverage};
    use lr_core::ImageKind;

    #[test]
    fn coverage_labels_follow_the_actual_mode_and_requested_scope() {
        let cases = [
            (
                ImageKind::Block,
                false,
                false,
                ContentCoverage::BlockSelectedMergedReferences,
            ),
            (
                ImageKind::Block,
                false,
                true,
                ContentCoverage::BlockEveryStoredPayload,
            ),
            (
                ImageKind::File,
                false,
                false,
                ContentCoverage::FileSelectedTreeReferences,
            ),
            (
                ImageKind::File,
                false,
                true,
                ContentCoverage::FileEveryTreeReferences,
            ),
            (
                ImageKind::Stream,
                false,
                false,
                ContentCoverage::StreamSelectedMemberPayloadsSectionsAndLayout,
            ),
            (
                ImageKind::Stream,
                false,
                true,
                ContentCoverage::StreamEveryMemberPayloadsSectionsAndLayout,
            ),
            (
                ImageKind::Block,
                true,
                false,
                ContentCoverage::WholeDiskRegionsAndLayout,
            ),
            (
                ImageKind::Block,
                true,
                true,
                ContentCoverage::WholeDiskRegionsAndLayout,
            ),
        ];
        for (image_kind, whole_disk, every_member, expected) in cases {
            assert_eq!(
                content_coverage(image_kind, whole_disk, every_member),
                expected
            );
        }
    }
}
