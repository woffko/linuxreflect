//! Private unnamed capture and a positional, read-only image resolver.

use std::collections::BTreeMap;
use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use lr_core::{Error, Result, SetId};
use lr_format::{SB_SIZE, Superblock};
use lr_store::{
    Destination, DestinationOptions, Durability, LockOwner, ReadSeek, SetHandle, SetLock, TempFile,
    uri,
};

use super::VerifyRequest;
use super::observation::{
    AttemptStage, FailureKind, MemberIdentity, MemberObservation, MemberStage,
    VerificationObservation, classify_error,
};

/// Fixed working-set size for every member, independent of raw ancestry size.
pub(super) const CAPTURE_BUFFER_BYTES: usize = 64 * 1024;

/// Required caller-supplied limits and scratch location for captured verify.
///
/// There is deliberately no `Default`: callers must choose both a raw-byte
/// limit and free-space headroom for every captured verification.
#[derive(Debug, Clone)]
pub struct CaptureOptions {
    /// Existing effective-user-owned mode-0700 directory on the scratch filesystem.
    pub scratch_directory: PathBuf,
    /// Maximum total raw bytes across the complete selected ancestry.
    pub max_raw_bytes: u64,
    /// Additional free bytes required at preflight beyond raw ancestry; not a reservation.
    pub headroom_bytes: u64,
}

impl CaptureOptions {
    /// Specify every resource and location choice; no limit is implicit.
    #[must_use]
    pub fn new(
        scratch_directory: impl Into<PathBuf>,
        max_raw_bytes: u64,
        headroom_bytes: u64,
    ) -> Self {
        Self {
            scratch_directory: scratch_directory.into(),
            max_raw_bytes,
            headroom_bytes,
        }
    }
}

#[derive(Debug)]
pub(super) struct CaptureFailure {
    pub stage: AttemptStage,
    pub reason: FailureKind,
    pub error: Error,
}

impl CaptureFailure {
    fn new(stage: AttemptStage, reason: FailureKind, error: Error) -> Self {
        Self {
            stage,
            reason,
            error,
        }
    }

    fn from_error(stage: AttemptStage, error: Error) -> Self {
        Self::new(stage, classify_error(&error), error)
    }
}

struct SourceMember {
    file: crate::chain::ChainMemberFile,
    raw_length: u64,
}

pub(super) struct CapturedChain {
    pub destination: CapturedDestination,
    pub set: SetHandle,
    pub members: Vec<crate::chain::ChainMemberFile>,
    pub name: String,
}

/// Read-only resolver over the captured anonymous file descriptions.
pub(super) struct CapturedDestination {
    files: BTreeMap<String, Arc<File>>,
}

impl CapturedDestination {
    fn new(files: BTreeMap<String, Arc<File>>) -> Self {
        Self { files }
    }
}

/// A reader with a logical cursor independent of all other readers over the
/// same anonymous inode. All reads use `pread` semantics through `read_at`.
struct PositionalReader {
    file: Arc<File>,
    cursor: u64,
}

impl Read for PositionalReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.file.read_at(buffer, self.cursor)?;
        self.cursor = self
            .cursor
            .checked_add(u64::try_from(read).map_err(io::Error::other)?)
            .ok_or_else(|| io::Error::other("captured reader cursor overflow"))?;
        Ok(read)
    }
}

impl Seek for PositionalReader {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let length = self.file.metadata()?.len();
        let next = match position {
            SeekFrom::Start(offset) => i128::from(offset),
            SeekFrom::Current(offset) => i128::from(self.cursor) + i128::from(offset),
            SeekFrom::End(offset) => i128::from(length) + i128::from(offset),
        };
        if !(0..=i128::from(u64::MAX)).contains(&next) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "captured reader seek is out of range",
            ));
        }
        self.cursor = u64::try_from(next).map_err(io::Error::other)?;
        Ok(self.cursor)
    }
}

impl Destination for CapturedDestination {
    fn open_set(&self, _set: &SetId) -> Result<SetHandle> {
        Err(Error::unsupported(
            "captured verification resolver is read-only",
        ))
    }

    fn open_existing_set(&self, set: &SetId) -> Result<SetHandle> {
        Ok(SetHandle {
            set_id: *set,
            path: "captured-anonymous-set".to_owned(),
        })
    }

    fn lock_set(
        &self,
        _set: &SetHandle,
        _owner: &LockOwner,
        _ttl: std::time::Duration,
    ) -> Result<SetLock> {
        Err(Error::unsupported(
            "captured verification resolver is read-only",
        ))
    }

    fn create_tmp(&self, _set: &SetHandle, _final_name: &str) -> Result<TempFile> {
        Err(Error::unsupported(
            "captured verification resolver is read-only",
        ))
    }

    fn publish_new(&self, _set: &SetHandle, _tmp: &str, _final_name: &str) -> Result<Durability> {
        Err(Error::unsupported(
            "captured verification resolver is read-only",
        ))
    }

    fn replace(&self, _set: &SetHandle, _tmp: &str, _final_name: &str) -> Result<Durability> {
        Err(Error::unsupported(
            "captured verification resolver is read-only",
        ))
    }

    fn open_ro(&self, set: &SetHandle, name: &str) -> Result<Box<dyn ReadSeek + Send>> {
        if set.set_id != SetId::ZERO || set.path != "captured-anonymous-set" {
            return Err(Error::corrupt("captured resolver set identity changed"));
        }
        let file = self
            .files
            .get(name)
            .ok_or_else(|| Error::corrupt("captured resolver member is unavailable"))?;
        Ok(Box::new(PositionalReader {
            file: Arc::clone(file),
            cursor: 0,
        }))
    }

    fn list(&self, set: &SetHandle) -> Result<Vec<String>> {
        if set.set_id != SetId::ZERO || set.path != "captured-anonymous-set" {
            return Err(Error::corrupt("captured resolver set identity changed"));
        }
        Ok(self.files.keys().cloned().collect())
    }

    fn list_set_names(&self) -> Result<Vec<String>> {
        Ok(vec!["captured-anonymous-set".to_owned()])
    }

    fn delete(&self, _set: &SetHandle, _name: &str) -> Result<()> {
        Err(Error::unsupported(
            "captured verification resolver is read-only",
        ))
    }
}

struct PinnedScratch {
    directory: File,
}

impl PinnedScratch {
    fn open(path: &Path) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "capture scratch directory must be absolute",
            ));
        }
        let relative = path.strip_prefix("/").map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid absolute scratch path")
        })?;
        let components = lr_unsafe::beneath::normal_components(relative)?;
        let mut current = File::from(lr_unsafe::beneath::open_root(Path::new("/"))?);
        let effective_uid = lr_unsafe::effective_uid();
        for (index, component) in components.iter().enumerate() {
            let next = lr_unsafe::beneath::open_dir_beneath(&current, Path::new(component))?;
            let next = File::from(next);
            let metadata = next.metadata()?;
            let final_component = index + 1 == components.len();
            let owner_is_trusted = metadata.uid() == effective_uid || metadata.uid() == 0;
            let writable_by_others = metadata.mode() & 0o022 != 0;
            let protected_sticky_directory = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
            if !owner_is_trusted
                || (writable_by_others && !protected_sticky_directory)
                || (final_component
                    && (metadata.uid() != effective_uid || metadata.mode() & 0o7777 != 0o700))
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "capture scratch ancestry component {} is untrusted (uid {}, mode {:o}, final {})",
                        component.to_string_lossy(),
                        metadata.uid(),
                        metadata.mode() & 0o7777,
                        final_component
                    ),
                ));
            }
            current = next;
        }
        if components.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "filesystem root cannot be a capture scratch directory",
            ));
        }
        Ok(Self { directory: current })
    }

    fn path(&self) -> PathBuf {
        lr_unsafe::beneath::self_path(&self.directory)
    }
}

/// Resolve once, preflight the entire ancestry, capture raw members, and
/// return only descriptors bound to those exact copied bytes.
pub(super) fn capture_chain(
    request: &VerifyRequest,
    options: &CaptureOptions,
    observation: &mut VerificationObservation,
) -> std::result::Result<CapturedChain, CaptureFailure> {
    if options.max_raw_bytes == 0 {
        return Err(CaptureFailure::new(
            AttemptStage::ScratchPreflight,
            FailureKind::InvalidOptions,
            Error::unsupported("captured verification requires a positive raw-byte cap"),
        ));
    }
    request
        .context
        .check_cancel()
        .map_err(|error| CaptureFailure::from_error(AttemptStage::ResolveAncestry, error))?;

    let location = uri::split_image(&request.image)
        .map_err(|error| CaptureFailure::from_error(AttemptStage::ResolveAncestry, error))?;
    let mut destination_options: DestinationOptions = request.destination_options.clone();
    destination_options.set_name.clone_from(&location.set);
    let source_destination = lr_store::open(&location.dest, &destination_options)
        .map_err(|error| CaptureFailure::from_error(AttemptStage::ResolveAncestry, error))?;
    let source_set = source_destination
        .open_existing_set(&SetId::ZERO)
        .map_err(|error| CaptureFailure::from_error(AttemptStage::ResolveAncestry, error))?;
    let members = crate::chain::resolve_chain(&*source_destination, &source_set, &location.name)
        .map_err(|error| CaptureFailure::from_error(AttemptStage::ResolveAncestry, error))?;
    if members.last().map(|member| member.file_name.as_str()) != Some(location.name.as_str()) {
        return Err(CaptureFailure::from_error(
            AttemptStage::ResolveAncestry,
            Error::corrupt("selected image is not the last member of its resolved ancestry"),
        ));
    }

    observation
        .members_mut()
        .resize_with(members.len(), MemberObservation::pending);
    let mut sources = Vec::with_capacity(members.len());
    let mut resolved_headers = Vec::with_capacity(members.len());
    let mut raw_total = 0u64;
    for (index, member) in members.iter().enumerate() {
        request
            .context
            .check_cancel()
            .map_err(|error| CaptureFailure::from_error(AttemptStage::ScratchPreflight, error))?;
        let mut reader = source_destination
            .open_ro(&source_set, &member.file_name)
            .map_err(|error| CaptureFailure::from_error(AttemptStage::ScratchPreflight, error))?;
        let raw_length = reader.seek(SeekFrom::End(0)).map_err(|error| {
            CaptureFailure::from_error(AttemptStage::ScratchPreflight, error.into())
        })?;
        reader.seek(SeekFrom::Start(0)).map_err(|error| {
            CaptureFailure::from_error(AttemptStage::ScratchPreflight, error.into())
        })?;
        if raw_length < SB_SIZE as u64 {
            return Err(CaptureFailure::new(
                AttemptStage::ResolveAncestry,
                FailureKind::IdentityChanged,
                Error::corrupt("source member is shorter than its superblock"),
            ));
        }
        let mut source_header_bytes = [0u8; SB_SIZE];
        reader
            .read_exact(&mut source_header_bytes)
            .map_err(|error| {
                CaptureFailure::from_error(AttemptStage::ResolveAncestry, error.into())
            })?;
        let resolved_header = Superblock::decode(&source_header_bytes)
            .map_err(|error| CaptureFailure::from_error(AttemptStage::ResolveAncestry, error))?;
        if resolved_header.image_uuid != member.image_uuid
            || resolved_header.seq_in_chain != member.seq_in_chain
        {
            return Err(CaptureFailure::new(
                AttemptStage::ResolveAncestry,
                FailureKind::IdentityChanged,
                Error::corrupt("resolved source member identity changed during preflight"),
            ));
        }
        raw_total = raw_total.checked_add(raw_length).ok_or_else(|| {
            CaptureFailure::new(
                AttemptStage::ScratchPreflight,
                FailureKind::RawCapExceeded,
                Error::unsupported("captured ancestry raw-byte total overflowed"),
            )
        })?;
        observation.members_mut()[index].raw_length = Some(raw_length);
        if raw_total > options.max_raw_bytes {
            return Err(CaptureFailure::new(
                AttemptStage::ScratchPreflight,
                FailureKind::RawCapExceeded,
                Error::unsupported("captured ancestry exceeds the caller's raw-byte cap"),
            ));
        }
        sources.push(SourceMember {
            file: member.clone(),
            raw_length,
        });
        resolved_headers.push(resolved_header);
    }

    let scratch = PinnedScratch::open(&options.scratch_directory).map_err(|error| {
        CaptureFailure::new(
            AttemptStage::ScratchPreflight,
            FailureKind::ScratchUntrusted,
            Error::Io(error),
        )
    })?;
    let available = lr_unsafe::filemeta::statvfs_bytes(&scratch.path())
        .map_err(|error| CaptureFailure::from_error(AttemptStage::ScratchPreflight, error.into()))?
        .0;
    let required = u128::from(raw_total) + u128::from(options.headroom_bytes);
    if required > u128::from(available) {
        return Err(CaptureFailure::new(
            AttemptStage::ScratchPreflight,
            FailureKind::HeadroomUnavailable,
            Error::NoSpace,
        ));
    }

    request.context.phase("capture");
    let mut copied_files = BTreeMap::new();
    let mut buffer = [0u8; CAPTURE_BUFFER_BYTES];
    for (index, source) in sources.iter().enumerate() {
        request
            .context
            .check_cancel()
            .map_err(|error| CaptureFailure::from_error(AttemptStage::Capture, error))?;
        observation.members_mut()[index].capture = MemberStage::InProgress;
        let captured = copy_member(
            request,
            &*source_destination,
            &source_set,
            source,
            &scratch.path(),
            &mut buffer,
        );
        let (read_only, digest) = match captured {
            Ok(captured) => captured,
            Err(failure) => {
                observation.members_mut()[index].capture = MemberStage::Failed;
                return Err(failure);
            }
        };
        observation.members_mut()[index].capture = MemberStage::Complete;
        observation.members_mut()[index].blake3_bytes = Some(digest);
        copied_files.insert(source.file.file_name.clone(), Arc::new(read_only));
    }

    request
        .context
        .check_cancel()
        .map_err(|error| CaptureFailure::from_error(AttemptStage::IdentityValidation, error))?;
    let mut headers = Vec::with_capacity(members.len());
    for (index, member) in members.iter().enumerate() {
        let file = copied_files.get(&member.file_name).ok_or_else(|| {
            CaptureFailure::new(
                AttemptStage::IdentityValidation,
                FailureKind::Unavailable,
                Error::corrupt("captured member disappeared before identity validation"),
            )
        })?;
        let mut reader = PositionalReader {
            file: Arc::clone(file),
            cursor: 0,
        };
        let mut bytes = [0u8; SB_SIZE];
        reader.read_exact(&mut bytes).map_err(|error| {
            CaptureFailure::from_error(AttemptStage::IdentityValidation, error.into())
        })?;
        let superblock = Superblock::decode(&bytes)
            .map_err(|error| CaptureFailure::from_error(AttemptStage::IdentityValidation, error))?;
        let source_header = &resolved_headers[index];
        if superblock.image_uuid != member.image_uuid
            || superblock.seq_in_chain != member.seq_in_chain
            || superblock.chain_id != source_header.chain_id
            || superblock.parent_uuid != source_header.parent_uuid
            || superblock.set_id != source_header.set_id
            || superblock.image_kind != source_header.image_kind
            || superblock.source_size_bytes != source_header.source_size_bytes
            || superblock.logical_block_size != source_header.logical_block_size
            || superblock.chunk_size != source_header.chunk_size
            || superblock.is_whole_disk() != source_header.is_whole_disk()
            || superblock.consistency != source_header.consistency
        {
            return Err(CaptureFailure::new(
                AttemptStage::IdentityValidation,
                FailureKind::IdentityChanged,
                Error::corrupt("captured member identity differs from the resolved ancestry"),
            ));
        }
        observation.members_mut()[index].identity = Some(MemberIdentity {
            image_uuid: superblock.image_uuid,
            chain_id: superblock.chain_id,
            parent_uuid: superblock.parent_uuid,
            set_id: superblock.set_id,
            seq_in_chain: superblock.seq_in_chain,
            image_kind: superblock.image_kind,
            legacy_header_kind: crate::chain::member_kind(&superblock),
            whole_disk: superblock.is_whole_disk(),
            consistency: superblock.consistency,
        });
        headers.push(superblock);
    }
    validate_captured_ancestry(&headers)?;
    let target = headers.last().ok_or_else(|| {
        CaptureFailure::from_error(
            AttemptStage::IdentityValidation,
            Error::corrupt("captured ancestry is empty"),
        )
    })?;
    if target.is_whole_disk() && headers.len() != 1 {
        return Err(CaptureFailure::new(
            AttemptStage::IdentityValidation,
            FailureKind::Unsupported,
            Error::unsupported("captured whole-disk ancestry must contain one member"),
        ));
    }
    let captured_destination = CapturedDestination::new(copied_files);
    let captured_set = SetHandle {
        set_id: SetId::ZERO,
        path: "captured-anonymous-set".to_owned(),
    };
    Ok(CapturedChain {
        destination: captured_destination,
        set: captured_set,
        members,
        name: location.name,
    })
}

fn copy_member(
    request: &VerifyRequest,
    source_destination: &dyn Destination,
    source_set: &SetHandle,
    source: &SourceMember,
    scratch_directory: &Path,
    buffer: &mut [u8; CAPTURE_BUFFER_BYTES],
) -> std::result::Result<(File, [u8; 32]), CaptureFailure> {
    let mut source_reader = source_destination
        .open_ro(source_set, &source.file.file_name)
        .map_err(|error| CaptureFailure::from_error(AttemptStage::Capture, error))?;
    let current_length = source_reader
        .seek(SeekFrom::End(0))
        .map_err(|error| CaptureFailure::from_error(AttemptStage::Capture, error.into()))?;
    if current_length != source.raw_length {
        return Err(CaptureFailure::new(
            AttemptStage::Capture,
            FailureKind::SourceChanged,
            Error::corrupt("source member length changed after capture preflight"),
        ));
    }
    source_reader
        .seek(SeekFrom::Start(0))
        .map_err(|error| CaptureFailure::from_error(AttemptStage::Capture, error.into()))?;
    let mut writer = new_anonymous_capture(scratch_directory)
        .map_err(|error| CaptureFailure::from_error(AttemptStage::Capture, Error::Io(error)))?;
    let mut hasher = blake3::Hasher::new();
    let mut remaining = source.raw_length;
    while remaining != 0 {
        request
            .context
            .check_cancel()
            .map_err(|error| CaptureFailure::from_error(AttemptStage::Capture, error))?;
        let read_len =
            usize::try_from(remaining.min(CAPTURE_BUFFER_BYTES as u64)).map_err(|error| {
                CaptureFailure::from_error(
                    AttemptStage::Capture,
                    Error::unsupported(format!("capture read size is invalid: {error}")),
                )
            })?;
        let read = source_reader
            .read(&mut buffer[..read_len])
            .map_err(|error| {
                if error.kind() == io::ErrorKind::UnexpectedEof {
                    CaptureFailure::new(
                        AttemptStage::Capture,
                        FailureKind::SourceChanged,
                        Error::Io(error),
                    )
                } else {
                    CaptureFailure::from_error(AttemptStage::Capture, Error::Io(error))
                }
            })?;
        if read == 0 {
            return Err(CaptureFailure::new(
                AttemptStage::Capture,
                FailureKind::SourceChanged,
                Error::corrupt("source member shrank after capture preflight"),
            ));
        }
        writer
            .write_all(&buffer[..read])
            .map_err(|error| CaptureFailure::from_error(AttemptStage::Capture, Error::Io(error)))?;
        hasher.update(&buffer[..read]);
        remaining -= u64::try_from(read).map_err(|error| {
            CaptureFailure::from_error(
                AttemptStage::Capture,
                Error::unsupported(format!("captured read length is invalid: {error}")),
            )
        })?;
    }
    request
        .context
        .check_cancel()
        .map_err(|error| CaptureFailure::from_error(AttemptStage::Capture, error))?;
    let mut extra = [0u8; 1];
    if source_reader
        .read(&mut extra)
        .map_err(|error| CaptureFailure::from_error(AttemptStage::Capture, error.into()))?
        != 0
    {
        return Err(CaptureFailure::new(
            AttemptStage::Capture,
            FailureKind::SourceChanged,
            Error::corrupt("source member grew after capture preflight"),
        ));
    }
    let read_only = into_read_only_capture(writer, source.raw_length)
        .map_err(|error| CaptureFailure::from_error(AttemptStage::Capture, Error::Io(error)))?;
    Ok((read_only, *hasher.finalize().as_bytes()))
}

fn into_read_only_capture(writer: File, expected_length: u64) -> io::Result<File> {
    let writer_metadata = private_anonymous_metadata(&writer, Some(expected_length))?;
    let read_only = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC)
        .open(lr_unsafe::beneath::object_path(&writer))?;
    let reader_metadata = read_only.metadata()?;
    if !reader_metadata.file_type().is_file()
        || reader_metadata.dev() != writer_metadata.dev()
        || reader_metadata.ino() != writer_metadata.ino()
        || reader_metadata.len() != expected_length
        || reader_metadata.nlink() != 0
        || reader_metadata.uid() != writer_metadata.uid()
        || reader_metadata.mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "read-only capture descriptor does not bind the private anonymous writer inode",
        ));
    }
    drop(writer);
    Ok(read_only)
}

fn new_anonymous_capture(directory: &Path) -> io::Result<File> {
    let mut builder = tempfile::Builder::new();
    builder.permissions(std::fs::Permissions::from_mode(0o600));
    let named = builder.tempfile_in(directory)?;
    let (writer, path) = named.into_parts();
    path.close()?;
    private_anonymous_metadata(&writer, Some(0))?;
    Ok(writer)
}

fn private_anonymous_metadata(file: &File, expected_length: Option<u64>) -> io::Result<Metadata> {
    let metadata = file.metadata()?;
    let length_matches = expected_length.is_none_or(|length| metadata.len() == length);
    if !metadata.file_type().is_file()
        || !length_matches
        || metadata.nlink() != 0
        || metadata.uid() != lr_unsafe::effective_uid()
        || metadata.mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "capture writer is not private anonymous regular data (file {}, len {}, expected {}, links {}, uid {}, effective uid {}, mode {:o})",
                metadata.file_type().is_file(),
                metadata.len(),
                expected_length.map_or_else(|| "any".to_owned(), |length| length.to_string()),
                metadata.nlink(),
                metadata.uid(),
                lr_unsafe::effective_uid(),
                metadata.mode() & 0o7777
            ),
        ));
    }
    Ok(metadata)
}

fn validate_captured_ancestry(headers: &[Superblock]) -> std::result::Result<(), CaptureFailure> {
    let Some(first) = headers.first() else {
        return Err(CaptureFailure::new(
            AttemptStage::IdentityValidation,
            FailureKind::IdentityChanged,
            Error::corrupt("captured ancestry is empty"),
        ));
    };
    if first.seq_in_chain != 0 || first.parent_uuid != lr_core::ImageId::ZERO {
        return Err(CaptureFailure::new(
            AttemptStage::IdentityValidation,
            FailureKind::IdentityChanged,
            Error::corrupt("captured ancestry does not start at a full member"),
        ));
    }
    for (index, header) in headers.iter().enumerate() {
        let index_u32 = u32::try_from(index).map_err(|error| {
            CaptureFailure::new(
                AttemptStage::IdentityValidation,
                FailureKind::IdentityChanged,
                Error::unsupported(format!("captured ancestry index is invalid: {error}")),
            )
        })?;
        if header.seq_in_chain != index_u32
            || header.chain_id != first.chain_id
            || header.set_id != first.set_id
            || header.image_kind != first.image_kind
            || (header.image_kind != lr_core::ImageKind::File
                && header.source_size_bytes != first.source_size_bytes)
            || header.logical_block_size != first.logical_block_size
            || header.chunk_size != first.chunk_size
            || header.is_whole_disk() != first.is_whole_disk()
            || (index != 0 && header.parent_uuid != headers[index - 1].image_uuid)
        {
            return Err(CaptureFailure::new(
                AttemptStage::IdentityValidation,
                FailureKind::IdentityChanged,
                Error::corrupt("captured ancestry topology or mode is inconsistent"),
            ));
        }
    }
    Ok(())
}

impl CapturedChain {
    pub(super) fn into_verify_parts(
        self,
    ) -> (
        CapturedDestination,
        SetHandle,
        Vec<crate::chain::ChainMemberFile>,
        String,
    ) {
        (self.destination, self.set, self.members, self.name)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs::OpenOptions;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};

    use super::{
        CapturedDestination, PinnedScratch, PositionalReader, into_read_only_capture,
        new_anonymous_capture, validate_captured_ancestry,
    };
    use lr_core::{ChainId, Consistency, Id, ImageId, ImageKind, SetId};
    use lr_format::Superblock;
    use lr_store::{Destination, SetHandle};

    fn header(sequence: u32, parent: ImageId, image_id: u8) -> Superblock {
        Superblock {
            format_major: lr_format::FORMAT_MAJOR,
            min_reader: lr_format::MIN_READER,
            flags: 0,
            image_kind: ImageKind::Block,
            consistency: Consistency::Offline,
            image_uuid: ImageId::new(Id::from_bytes([image_id; 16])),
            chain_id: ChainId::new(Id::from_bytes([0xC1; 16])),
            set_id: SetId::new(Id::from_bytes([0xC2; 16])),
            parent_uuid: parent,
            seq_in_chain: sequence,
            created_unix: u64::from(sequence),
            source_size_bytes: 4 * 256 * 1024,
            logical_block_size: 512,
            chunk_size: 256 * 1024,
            kdf_id: 0,
            aead_id: lr_crypto::AEAD_ID_AES_256_GCM,
            kdf_salt: [0; 16],
            argon2_m_cost_kib: 0,
            argon2_t_cost: 0,
            argon2_p_cost: 0,
            wrap_nonce: [0; 12],
            wrapped_chain_key: [0; 48],
        }
    }

    #[test]
    fn read_only_capture_has_independent_cursors_and_no_unknown_member_fallback() {
        let directory = tempfile::Builder::new()
            .prefix("lr-capture-unit-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .expect("private test directory");
        let mut writer = new_anonymous_capture(directory.path()).expect("anonymous writer");
        assert!(
            std::fs::read_dir(directory.path())
                .expect("read test directory")
                .next()
                .is_none()
        );
        writer.write_all(b"abcdef").expect("write fixture bytes");
        let read_only = into_read_only_capture(writer, 6).expect("read-only anonymous capture");
        let shared = std::sync::Arc::new(read_only);

        let mut first = PositionalReader {
            file: std::sync::Arc::clone(&shared),
            cursor: 0,
        };
        let mut second = PositionalReader {
            file: std::sync::Arc::clone(&shared),
            cursor: 0,
        };
        let mut first_bytes = [0u8; 2];
        first.read_exact(&mut first_bytes).expect("first read");
        assert_eq!(&first_bytes, b"ab");
        let mut second_bytes = [0u8; 3];
        second
            .read_exact(&mut second_bytes)
            .expect("second independent read");
        assert_eq!(&second_bytes, b"abc");
        first
            .read_exact(&mut first_bytes)
            .expect("first cursor continues");
        assert_eq!(&first_bytes, b"cd");
        second
            .read_exact(&mut second_bytes)
            .expect("second cursor continues");
        assert_eq!(&second_bytes, b"def");
        assert!(first.seek(SeekFrom::Current(-5)).is_err());
        assert!(first.seek(SeekFrom::End(-7)).is_err());

        let write_error = shared
            .write_at(b"x", 0)
            .expect_err("read-only descriptor must reject pwrite");
        assert_eq!(write_error.raw_os_error(), Some(libc::EBADF));

        let destination =
            CapturedDestination::new(BTreeMap::from([("known.lrimg".to_owned(), shared)]));
        let set = SetHandle {
            set_id: SetId::ZERO,
            path: "captured-anonymous-set".to_owned(),
        };
        assert!(destination.open_ro(&set, "unknown.lrimg").is_err());
        // Ensure the anonymous file itself stays unlinked after readers are made.
        assert!(
            std::fs::read_dir(directory.path())
                .expect("read directory after resolver use")
                .next()
                .is_none()
        );
    }

    #[test]
    fn anonymous_capture_checks_unlink_and_scratch_directory_pinning() {
        let root = tempfile::Builder::new()
            .prefix("lr-capture-pinning-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .expect("private test root");

        let linked_path = root.path().join("linked-writer");
        let mut linked_writer = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&linked_path)
            .expect("create linked writer");
        linked_writer
            .write_all(b"secret")
            .expect("write linked fixture");
        let error = into_read_only_capture(linked_writer, 6)
            .expect_err("named writer must be refused before resolver exposure");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(
            std::fs::read(&linked_path).expect("keep linked fixture"),
            b"secret"
        );

        let writable_ancestor = root.path().join("writable");
        let private_child = writable_ancestor.join("child");
        std::fs::create_dir_all(&private_child).expect("create scratch ancestry");
        std::fs::set_permissions(&writable_ancestor, std::fs::Permissions::from_mode(0o770))
            .expect("make ancestor group-writable");
        std::fs::set_permissions(&private_child, std::fs::Permissions::from_mode(0o700))
            .expect("keep final directory private");
        assert!(PinnedScratch::open(&private_child).is_err());

        let original = root.path().join("original");
        std::fs::create_dir(&original).expect("create private scratch directory");
        std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o700))
            .expect("set private scratch mode");
        lr_unsafe::filemeta::set_times_nofollow(&original, 1_600_000_000, 0, 1_600_000_000, 0)
            .expect("set deterministic original directory time");
        let symlink = root.path().join("scratch-link");
        std::os::unix::fs::symlink(&original, &symlink).expect("create scratch symlink");
        assert!(PinnedScratch::open(&symlink).is_err());

        let pinned = PinnedScratch::open(&original).expect("pin private scratch directory");
        let original_directory = root.path().join("renamed-original");
        std::fs::rename(&original, &original_directory).expect("rename pinned directory");
        std::fs::create_dir(&original).expect("replace original pathname");
        std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o700))
            .expect("set replacement private mode");
        lr_unsafe::filemeta::set_times_nofollow(
            &original_directory,
            1_600_000_000,
            0,
            1_600_000_000,
            0,
        )
        .expect("set deterministic moved directory time");
        lr_unsafe::filemeta::set_times_nofollow(&original, 1_600_000_000, 0, 1_600_000_000, 0)
            .expect("set deterministic replacement directory time");

        let pinned_metadata = std::fs::metadata(pinned.path()).expect("stat pinned path");
        let moved_metadata = std::fs::metadata(&original_directory).expect("stat moved dir");
        let replacement_metadata = std::fs::metadata(&original).expect("stat replacement");
        assert_eq!(pinned_metadata.dev(), moved_metadata.dev());
        assert_eq!(pinned_metadata.ino(), moved_metadata.ino());
        assert_ne!(pinned_metadata.ino(), replacement_metadata.ino());
        let moved_times_before = (moved_metadata.mtime(), moved_metadata.mtime_nsec());
        let replacement_times_before = (
            replacement_metadata.mtime(),
            replacement_metadata.mtime_nsec(),
        );

        let writer = new_anonymous_capture(&pinned.path()).expect("capture in pinned directory");
        assert_eq!(writer.metadata().expect("stat anonymous writer").nlink(), 0);
        let moved_after = std::fs::metadata(&original_directory).expect("restat moved dir");
        let replacement_after = std::fs::metadata(&original).expect("restat replacement");
        assert_ne!(
            (moved_after.mtime(), moved_after.mtime_nsec()),
            moved_times_before,
            "creating and unlinking the anonymous file changes the pinned directory"
        );
        assert_eq!(
            (replacement_after.mtime(), replacement_after.mtime_nsec()),
            replacement_times_before,
            "the replacement pathname was not touched"
        );
        drop(writer);
        assert_eq!(
            std::fs::read_dir(&original)
                .expect("list replacement")
                .count(),
            0
        );
    }

    #[test]
    fn captured_ancestry_refuses_a_broken_parent_link() {
        let full = header(0, ImageId::ZERO, 0x01);
        let child = header(1, full.image_uuid, 0x02);
        validate_captured_ancestry(&[full.clone(), child.clone()]).expect("valid ancestry");

        let mut broken = child;
        broken.parent_uuid = ImageId::new(Id::from_bytes([0xEE; 16]));
        assert!(validate_captured_ancestry(&[full, broken]).is_err());
    }
}
