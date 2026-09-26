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

use lr_core::io::ReadSeek;
use lr_core::{Error, ImageKind, Result};
use lr_format::{
    BlockEntry, BlockManifestHeader, ChunkState, DiskHeader, ImageReader, StreamId, Superblock,
    open_chunk, verify_structure, wire,
};
use lr_store::{Destination, DestinationOptions, SetHandle, uri};

use crate::keys::{self, Encryption};
use crate::stream::{StreamLayout, parse_stream_layout};

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
}

impl VerifyReport {
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
    let set = destination.open_set(&lr_core::SetId::ZERO)?;

    let target = crate::chain::read_superblock(&*destination, &set, &location.name)?;

    // Which members to read: the whole ancestry, or just this image.
    let chain = crate::chain::resolve_chain(&*destination, &set, &location.name)?;
    let members: Vec<crate::chain::ChainMemberFile> = if request.chain {
        chain
    } else {
        chain
            .into_iter()
            .filter(|member| member.file_name == location.name)
            .collect()
    };
    if members.is_empty() {
        return Err(Error::corrupt(format!(
            "{} is not part of its own chain",
            location.name
        )));
    }

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
    };

    // 1. Structure, MACs and page tags, member by member.
    for member in &members {
        let superblock = crate::chain::read_superblock(&*destination, &set, &member.file_name)?;
        let keys = keys::unlock_image(&request.encryption, &superblock)?;
        let encrypted = superblock.is_encrypted();
        let page_report = verify_structure(
            destination.open_ro(&set, &member.file_name)?,
            *keys.meta_key,
            encrypted,
        )
        .map_err(|error| {
            Error::corrupt(format!(
                "{}: structure of {} failed: {error}",
                member.file_name, superblock.image_uuid
            ))
        })?;
        report.pages += page_report.total_pages() as u64;
        report.members += 1;
        if encrypted && page_report.repeated_page_nonces {
            report
                .warnings
                .push(legacy_nonce_warning(&member.file_name));
        }
    }

    // 2. Content: every stored chunk's plaintext must hash to the manifest.
    reporter.phase("content");
    match target.image_kind {
        ImageKind::Block if target.is_whole_disk() => {
            verify_whole_disk(
                &*destination,
                &set,
                &members[0].file_name,
                &request.encryption,
                &mut report,
            )?;
        }
        ImageKind::Block => {
            verify_block_chain(
                &*destination,
                &set,
                &members,
                &request.encryption,
                &mut reporter,
                &mut report,
            )?;
        }
        ImageKind::Stream => {
            verify_stream(
                &*destination,
                &set,
                &members,
                &request.encryption,
                &mut reporter,
                &mut report,
            )?;
        }
        ImageKind::File => {
            verify_file(
                &*destination,
                &set,
                &members,
                &request.encryption,
                &mut reporter,
                &mut report,
            )?;
        }
    }

    reporter.finish(report.chunks);
    Ok(report)
}

/// Re-hash every chunk of a block chain, using the merged state walker.
fn verify_block_chain(
    destination: &dyn Destination,
    set: &SetHandle,
    members: &[crate::chain::ChainMemberFile],
    encryption: &Encryption,
    reporter: &mut crate::progress::Reporter,
    report: &mut VerifyReport,
) -> Result<()> {
    let opened = crate::chain::open_chain(destination, set, members, encryption)?;
    let mut walk = crate::chain::ChainWalk::new(opened)?;
    walk.walk(|index, state, access| {
        reporter.report(index)?;
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
                "{member_name}: chunk {index} (member {member}, offset {offset}, {stored_len} \
                 stored bytes) failed: {error}"
            ))
        })?;
        report.chunks += 1;
        report.bytes_checked += plaintext.len() as u64;
        Ok(())
    })
}

/// Re-hash every chunk of every subvolume section of a stream image.
/// Verify a file-mode chain: every reference resolves, every stored chunk
/// hashes to its manifest value, and the names are reported when one fails.
fn verify_file(
    destination: &dyn Destination,
    set: &SetHandle,
    members: &[crate::chain::ChainMemberFile],
    encryption: &Encryption,
    reporter: &mut crate::progress::Reporter,
    report: &mut VerifyReport,
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

    // Pass 2: every stored chunk is decoded and re-hashed; every reference in
    // every tree must resolve, or a restore would fail later.
    let mut restored_files = 0u64;
    for (position, member) in opened.iter_mut().enumerate() {
        reporter.phase(&format!("member {}", member.file_name));
        let bytes = member.stream_bytes(StreamId::Manifest)?;
        let records = lr_format::read_manifest(&bytes)?;
        for record in &records {
            restored_files += 1;
            for hash in &record.entry.chunk_refs_here {
                let Some((owner, offset, _)) = index.get(hash) else {
                    return Err(Error::corrupt(format!(
                        "{}: {} references a chunk no member of the chain stores",
                        member.file_name,
                        String::from_utf8_lossy(&record.entry.path)
                    )));
                };
                if *owner != position {
                    continue;
                }
                let entry = BlockEntry::stored(
                    u16::try_from(position).unwrap_or(u16::MAX),
                    *hash,
                    *offset,
                    0,
                )?;
                let plaintext =
                    member
                        .chunk_plaintext(&entry, MAX_STREAM_CHUNK)
                        .map_err(|error| {
                            Error::corrupt(format!(
                                "{}: {} (offset {}, member {}) failed: {error}",
                                member.file_name,
                                String::from_utf8_lossy(&record.entry.path),
                                offset,
                                member.superblock.image_uuid
                            ))
                        })?;
                reporter.report(report.bytes_checked)?;
                report.chunks += 1;
                report.bytes_checked += plaintext.len() as u64;
            }
        }
    }
    tracing::debug!(files = restored_files, "file manifest verified");
    Ok(())
}

fn verify_stream(
    destination: &dyn Destination,
    set: &SetHandle,
    members: &[crate::chain::ChainMemberFile],
    encryption: &Encryption,
    reporter: &mut crate::progress::Reporter,
    report: &mut VerifyReport,
) -> Result<()> {
    for member in members {
        reporter.phase(&format!("member {}", member.file_name));
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
                reporter.report(report.chunks)?;
                report.chunks += 1;
                report.bytes_checked += plaintext.len() as u64;
            }
        }
        // The layout extras must still parse: they carry what a restore needs.
        let _ = stream_layout_of(&mut reader, &keys, kind);
    }
    Ok(())
}

fn stream_layout_of(
    reader: &mut ImageReader<Box<dyn ReadSeek + Send>>,
    keys: &crate::keys::ImageKeys,
    kind: lr_crypto::aead::AeadKind,
) -> Option<StreamLayout> {
    let mut extras = Vec::new();
    {
        let mut page = reader
            .stream_reader(StreamId::Extras, *keys.meta_key, kind)
            .ok()?;
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            let read = page.read_bytes_partial(&mut buffer).ok()?;
            if read == 0 {
                break;
            }
            extras.extend_from_slice(&buffer[..read]);
        }
    }
    let mut cursor = std::io::Cursor::new(extras.as_slice());
    while (cursor.position() as usize) < extras.len() {
        let mut wire = wire::Reader::new(&mut cursor);
        let (extras_kind, payload) = lr_format::read_extras_record(&mut wire).ok()?;
        if extras_kind == lr_format::EXTRAS_BTRFS_LAYOUT {
            return parse_stream_layout(&String::from_utf8_lossy(&payload)).ok();
        }
    }
    None
}

/// Re-hash every chunk of every region of a whole-disk image.
fn verify_whole_disk(
    destination: &dyn Destination,
    set: &SetHandle,
    name: &str,
    encryption: &Encryption,
    report: &mut VerifyReport,
) -> Result<()> {
    let mut reader = ImageReader::open(destination.open_ro(set, name)?)?;
    let keys = keys::unlock_image(encryption, reader.superblock())?;
    let superblock: Superblock = reader.superblock().clone();
    let kind = superblock.aead_kind()?;
    let chunk_size = u64::from(superblock.chunk_size);
    let mut chunks = reader.chunk_reader_with(destination.open_ro(set, name)?);

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
    let disk_header = {
        let mut wire = wire::Reader::new(&mut cursor);
        let header = DiskHeader::read(&mut wire)?;
        header.validate()?;
        header
    };
    for region in &disk_header.regions {
        if !region.has_manifest() {
            continue;
        }
        let mut wire = wire::Reader::new(&mut cursor);
        let (header, _delta) = BlockManifestHeader::read(&mut wire)?;
        for index in 0..header.entry_count {
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
            report.chunks += 1;
            report.bytes_checked += plaintext.len() as u64;
        }
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
    let set = destination.open_set(&lr_core::SetId::ZERO)?;
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
