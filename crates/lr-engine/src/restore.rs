//! Restore planning and execution (spec §H, §K S6).
//!
//! `prepare` reads the image header, captures the target's identity and returns
//! a MAC'd, short-lived token (spec §H.2). `apply` refuses to write anything
//! until it has re-read those facts and found them unchanged, so a target that
//! was repartitioned between the two steps is rejected instead of overwritten.
//!
//! The token also carries the image path and the target path: there is no
//! daemon yet to remember a job, and `restore apply --token <t>` must be able to
//! find both (D-018).

use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use lr_blocksource::DirectBlockTarget;
use lr_core::io::ReadSeek;
use lr_core::{Consistency, Error, ImageId, ImageKind, Result, discovery::discover_source};
use lr_crypto::mac::{mac32, unkeyed_mac32, verify_mac32};
use lr_format::{ImageReader, Superblock};
use serde::{Deserialize, Serialize};

use crate::backup::now_unix;
use crate::keys::{self, Encryption, ImageKeys};

mod secret_file;

/// Default token lifetime (spec §H.2 allows at most ten minutes).
pub const DEFAULT_TTL: Duration = Duration::from_secs(600);

/// Bytes hashed to bind a target's identity (spec §H.2: the first 1 MiB, which
/// contains the protective MBR and the primary GPT).
pub const TARGET_HASH_BYTES: usize = 1024 * 1024;

/// Token prefix, so a pasted token is recognisable.
pub const TOKEN_PREFIX: &str = "lrt1";

/// Facts that identify one target device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetFacts {
    /// Device number (`st_rdev`).
    pub dev_id: u64,
    /// WWID or serial, when sysfs reports one.
    pub wwid_or_serial: Option<String>,
    /// Device size in bytes.
    pub size_bytes: u64,
    /// BLAKE3 of the first [`TARGET_HASH_BYTES`] bytes, hex.
    pub pt_hash: String,
}

impl TargetFacts {
    /// Capture the facts of `device`.
    ///
    /// # Errors
    /// Returns [`Error::Io`] when the device cannot be inspected.
    pub fn read(device: &Path) -> Result<Self> {
        let metadata = std::fs::metadata(device).map_err(Error::Io)?;
        let layout = discover_source(device)?;
        let wwid_or_serial = layout
            .device_facts
            .wwid
            .clone()
            .or_else(|| layout.device_facts.serial.clone());
        Ok(Self {
            dev_id: metadata.rdev(),
            wwid_or_serial,
            size_bytes: layout.device_facts.size_bytes,
            pt_hash: hash_prefix(device)?,
        })
    }

    /// Facts of a directory target (file mode, spec §K S12).
    ///
    /// A directory has no device number and no partition table, so the identity
    /// is its `st_dev`/`st_ino` (carried in [`crate::target::DirectoryFacts`])
    /// and the hash covers the canonical path. `bytes` is how much the image
    /// will write, which is what the free-space check compares against.
    ///
    /// # Errors
    /// Returns [`Error::Unsupported`] when the path is not a directory.
    pub fn for_directory(path: &Path, bytes: u64) -> Result<Self> {
        let facts = crate::target::DirectoryFacts::read(path)?;
        Ok(Self {
            dev_id: facts.dev_id,
            wwid_or_serial: None,
            size_bytes: bytes,
            pt_hash: hex::encode(unkeyed_mac32(facts.path.as_os_str().as_bytes())),
        })
    }

    /// `true` when every fact still matches.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        self == other
    }
}

fn hash_prefix(device: &Path) -> Result<String> {
    let mut file = std::fs::File::open(device).map_err(Error::Io)?;
    let mut buffer = vec![0u8; TARGET_HASH_BYTES];
    let mut filled = 0usize;
    while filled < buffer.len() {
        match file.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Error::Io(e)),
        }
    }
    buffer.truncate(filled);
    Ok(hex::encode(unkeyed_mac32(&buffer)))
}

/// A signed, short-lived permission to write one image chain to one target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreToken {
    /// Destination URI the images live on (`/path` or `sftp://…`).
    pub dest: String,
    /// Set name inside the destination.
    pub set: String,
    /// Set-relative name of the newest member.
    pub image: String,
    /// Set-relative names of every member to apply, oldest first.
    #[serde(default)]
    pub chain: Vec<String>,
    /// SFTP identity file the destination was opened with (a path, never a key).
    #[serde(default)]
    pub identity: Option<PathBuf>,
    /// `known_hosts` file the destination was verified against.
    #[serde(default)]
    pub known_hosts: Option<PathBuf>,
    /// Whether host-key verification was skipped (tests only).
    #[serde(default)]
    pub insecure_ignore_host_key: bool,
    /// Image UUID the token was issued for.
    pub image_uuid: ImageId,
    /// Target device the token authorises writing.
    pub target_path: PathBuf,
    /// Target facts captured at prepare time.
    pub target: TargetFacts,
    /// Directory identity when the target is a directory (file mode).
    #[serde(default)]
    pub target_directory: Option<crate::target::DirectoryFacts>,
    /// Whether `restore apply` may write into a non-empty target directory.
    #[serde(default)]
    pub merge: bool,
    /// Expiry, seconds since the Unix epoch.
    pub expires_at: u64,
    /// Random nonce, so two tokens for the same plan differ.
    pub nonce: String,
    /// MAC over the payload, hex.
    pub mac: String,
}

/// Where a chain's images live, as the token records it.
#[derive(Debug, Clone, Default)]
pub struct TokenImage {
    /// Destination URI.
    pub dest: String,
    /// Set name.
    pub set: String,
    /// Set-relative name of the newest member.
    pub image: String,
    /// Set-relative names of every member, oldest first.
    pub chain: Vec<String>,
    /// SFTP identity file, when one was used.
    pub identity: Option<PathBuf>,
    /// `known_hosts` file, when one was used.
    pub known_hosts: Option<PathBuf>,
    /// Whether host-key verification was skipped.
    pub insecure_ignore_host_key: bool,
}

impl RestoreToken {
    /// Issue a token for a plan.
    ///
    /// # Errors
    /// Propagates RNG and serialization failures.
    pub fn issue(
        image: TokenImage,
        target_path: &Path,
        image_uuid: ImageId,
        target: TargetFacts,
        directory: Option<crate::target::DirectoryFacts>,
        merge: bool,
        ttl: Duration,
    ) -> Result<Self> {
        let nonce = hex::encode(lr_crypto::rand::random_bytes::<16>()?);
        let expires_at = now_unix() + ttl.as_secs();
        let mut token = Self {
            dest: image.dest,
            set: image.set,
            image: image.image,
            chain: image.chain,
            identity: image.identity,
            known_hosts: image.known_hosts,
            insecure_ignore_host_key: image.insecure_ignore_host_key,
            image_uuid,
            target_path: target_path.to_path_buf(),
            target,
            target_directory: directory,
            merge,
            expires_at,
            nonce,
            mac: String::new(),
        };
        token.mac = hex::encode(mac32(token_secret(), &token.payload()?));
        Ok(token)
    }

    /// Destination options that reach this token's images.
    #[must_use]
    pub fn destination_options(&self) -> lr_store::DestinationOptions {
        lr_store::DestinationOptions {
            set_name: self.set.clone(),
            identity: self.identity.clone(),
            known_hosts: self.known_hosts.clone(),
            insecure_ignore_host_key: self.insecure_ignore_host_key,
        }
    }

    /// Canonical payload bytes covered by the MAC.
    fn payload(&self) -> Result<Vec<u8>> {
        let mut copy = self.clone();
        copy.mac.clear();
        serde_json::to_vec(&copy).map_err(|e| Error::corrupt(format!("token payload: {e}")))
    }

    /// Verify the MAC and the expiry.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] for a bad MAC or an expired token.
    pub fn verify(&self) -> Result<()> {
        let expected: [u8; 32] = hex::decode(&self.mac)
            .map_err(|_| Error::corrupt("restore token MAC is not hex"))?
            .try_into()
            .map_err(|_| Error::corrupt("restore token MAC has the wrong length"))?;
        if !verify_mac32(token_secret(), &self.payload()?, &expected) {
            return Err(Error::corrupt("restore token MAC does not verify"));
        }
        if token_expired(self.expires_at, now_unix()) {
            return Err(Error::corrupt(format!(
                "restore token expired at {}",
                self.expires_at
            )));
        }
        Ok(())
    }

    /// Encode as text for `--token`.
    #[must_use]
    pub fn encode(&self) -> String {
        format!(
            "{TOKEN_PREFIX}:{}",
            serde_json::to_string(self).unwrap_or_default()
        )
    }

    /// Parse text produced by [`RestoreToken::encode`].
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] for a malformed token.
    pub fn decode(text: &str) -> Result<Self> {
        let json = text
            .trim()
            .strip_prefix(TOKEN_PREFIX)
            .and_then(|rest| rest.strip_prefix(':'))
            .ok_or_else(|| Error::corrupt("restore token must start with 'lrt1:'"))?;
        serde_json::from_str(json).map_err(|e| Error::corrupt(format!("restore token: {e}")))
    }

    /// Seconds until the token expires, saturating at zero.
    #[must_use]
    pub fn remaining_seconds(&self) -> u64 {
        self.expires_at.saturating_sub(now_unix())
    }
}

/// `true` when an expiry has passed.
#[must_use]
pub fn token_expired(expires_at: u64, now: u64) -> bool {
    now > expires_at
}

/// Per-boot token secret (spec §H.2).
///
/// The daemon keeps this in memory for its lifetime; before that exists, a
/// `prepare` and an `apply` are two separate processes, so the secret is
/// persisted in a 0600 file under `/run` (a tmpfs, so it disappears at reboot,
/// exactly like a daemon restart). Slice S11 hands the daemon the same file.
pub fn token_secret() -> &'static [u8; 32] {
    TOKEN_SECRET.get_or_init(|| {
        load_or_create_secret()
            .unwrap_or_else(|error| panic!("cannot establish the restore-token secret: {error}"))
    })
}

static TOKEN_SECRET: OnceLock<[u8; 32]> = OnceLock::new();

/// Load the process's token key from an explicit path before serving requests.
///
/// Uses the same ownership, mode and no-follow checks as lazy initialization.
/// Does not modify the environment. Once either initializer has published a
/// key, it cannot be replaced. Call at startup before other token users;
/// concurrent initialization may fail, but never changes the winning key.
///
/// # Errors
/// Returns filesystem validation errors or `AlreadyExists` if initialized.
pub fn init_token_secret(path: &Path) -> Result<()> {
    let already_initialized = || {
        Error::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "restore-token secret is already initialized",
        ))
    };
    if TOKEN_SECRET.get().is_some() {
        return Err(already_initialized());
    }
    let secret = secret_file::load(path)?;
    TOKEN_SECRET.set(secret).map_err(|_| already_initialized())
}

/// Resolve the environment/default token-secret location, not the path of a
/// key previously installed by [`init_token_secret`].
/// Root CLI and daemon normally share /run;
/// non-root callers use their own runtime directory. An invalid explicit
/// location is an error, never a reason to silently select a different key.
///
/// # Errors
/// Propagates filesystem errors.
pub fn token_secret_path() -> Result<PathBuf> {
    // An explicit override keeps a test (or a second daemon) away from the
    // machine-wide `/run` secret.
    if let Some(explicit) = std::env::var_os("LR_TOKEN_SECRET_FILE")
        && !explicit.is_empty()
    {
        let path = PathBuf::from(explicit);
        return Ok(path);
    }
    if lr_unsafe::effective_uid() == 0 {
        return Ok(PathBuf::from("/run/linuxreflect/token.key"));
    }
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        let runtime = PathBuf::from(runtime);
        if !runtime.is_absolute() {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "XDG_RUNTIME_DIR must be an absolute path",
            )));
        }
        return Ok(runtime.join("linuxreflect/token.key"));
    }
    Ok(PathBuf::from(format!(
        "/tmp/linuxreflect-{}/token.key",
        lr_unsafe::effective_uid()
    )))
}

fn load_or_create_secret() -> Result<[u8; 32]> {
    secret_file::load(&token_secret_path()?)
}

/// What `prepare` needs.
pub struct PrepareRequest {
    /// Image to restore, as a destination URI (spec §J.1).
    pub image: String,
    /// Target block device.
    pub target: PathBuf,
    /// How to unlock the image.
    pub encryption: Encryption,
    /// Token lifetime.
    pub ttl: Duration,
    /// SFTP identity file.
    pub identity: Option<PathBuf>,
    /// `known_hosts` file for an SFTP destination.
    pub known_hosts: Option<PathBuf>,
    /// Skip host-key verification (tests only).
    pub insecure_ignore_host_key: bool,
    /// Allow a file-mode restore into a non-empty directory.
    pub merge: bool,
}

impl PrepareRequest {
    /// A request for an image on a local path, for callers that never leave
    /// the machine (the CLI takes a destination URI instead).
    #[must_use]
    pub fn from_path(
        image: impl AsRef<Path>,
        target: impl Into<PathBuf>,
        encryption: Encryption,
    ) -> Self {
        Self::new(
            image.as_ref().to_string_lossy().into_owned(),
            target,
            encryption,
        )
    }

    /// A request with the default token lifetime.
    #[must_use]
    pub fn new(
        image: impl Into<String>,
        target: impl Into<PathBuf>,
        encryption: Encryption,
    ) -> Self {
        Self {
            image: image.into(),
            target: target.into(),
            encryption,
            ttl: DEFAULT_TTL,
            identity: None,
            known_hosts: None,
            insecure_ignore_host_key: false,
            merge: false,
        }
    }

    /// Allow writing into a non-empty target directory (file mode).
    #[must_use]
    pub fn with_merge(mut self, merge: bool) -> Self {
        self.merge = merge;
        self
    }
}

/// A human-readable plan plus the token that authorises it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestorePlan {
    /// Destination URI the images live on.
    pub dest: String,
    /// Set name.
    pub set: String,
    /// Set-relative name of the newest member.
    pub image: String,
    /// Set-relative names of every member to apply, oldest first.
    pub members: Vec<String>,
    /// Image UUID.
    pub image_uuid: ImageId,
    /// Consistency level recorded in the image.
    pub consistency: Consistency,
    /// Image kind.
    pub image_kind: ImageKind,
    /// Bytes the image covers.
    pub source_size_bytes: u64,
    /// Chunk size recorded in the image.
    pub chunk_size: u32,
    /// Target device.
    pub target: PathBuf,
    /// Target facts captured now.
    pub target_facts: TargetFacts,
    /// Target size in bytes.
    pub target_size_bytes: u64,
    /// Whether the image is encrypted.
    pub encrypted: bool,
    /// Non-fatal notes the user must see.
    pub warnings: Vec<String>,
    /// Encoded restore token.
    pub token: String,
}

/// An image opened through a destination, with its keys.
type OpenImage = (ImageReader<Box<dyn ReadSeek + Send>>, ImageKeys, Superblock);

/// Open an image's reader and unlock its keys.
fn open_image(
    destination: &dyn lr_store::Destination,
    set: &lr_store::SetHandle,
    name: &str,
    encryption: &Encryption,
) -> Result<OpenImage> {
    let reader = ImageReader::open(destination.open_ro(set, name)?)?;
    let keys = keys::unlock_image(encryption, reader.superblock())?;
    let mac_key = reader
        .superblock()
        .is_encrypted()
        .then_some(&*keys.meta_key);
    reader.authenticate(mac_key)?;
    let superblock = reader.superblock().clone();
    Ok((reader, keys, superblock))
}

/// Build the restore plan and token for one image and target.
///
/// The image may be one member of a chain: every ancestor is resolved from the
/// destination and validated here, and the token authorises applying the whole
/// chain (spec §D.3, §H.2).
///
/// # Errors
/// Returns [`Error::NoSpace`] when the target is smaller than the source,
/// [`Error::TargetBusy`] when the target is in use, [`Error::Unsupported`] for
/// image kinds this slice cannot restore, and propagates destination, chain and
/// decryption errors.
pub fn prepare_restore(request: &PrepareRequest) -> Result<RestorePlan> {
    let location = lr_store::uri::split_image(&request.image)?;
    let options = lr_store::DestinationOptions {
        set_name: location.set.clone(),
        identity: request.identity.clone(),
        known_hosts: request.known_hosts.clone(),
        insecure_ignore_host_key: request.insecure_ignore_host_key,
    };
    let destination = lr_store::open(&location.dest, &options)?;
    let set = destination.open_set(&lr_core::SetId::ZERO)?;
    let (mut reader, keys, superblock) =
        open_image(&*destination, &set, &location.name, &request.encryption)?;
    let repeated_page_nonces = superblock.is_encrypted()
        && reader.has_repeated_page_nonces(&keys.meta_key, superblock.aead_kind()?)?;

    // A whole-disk image is always a full image; block and stream images may be
    // chain members, and applying one needs every ancestor.
    let members: Vec<String> = if superblock.is_whole_disk() {
        vec![location.name.clone()]
    } else {
        let files = crate::chain::resolve_chain(&*destination, &set, &location.name)?;
        // Open and authenticate every member now: a missing or damaged
        // ancestor must fail before a token is issued.
        let _validated =
            crate::chain::open_chain(&*destination, &set, &files, &request.encryption)?;
        files.into_iter().map(|file| file.file_name).collect()
    };

    // File mode restores into an existing directory: the space check is about
    // free bytes, and there is no device to preflight.
    let (target_facts, target_directory) = if superblock.image_kind == ImageKind::File {
        let directory = crate::target::DirectoryFacts::read(&request.target)?;
        let free = directory.free_bytes()?;
        if free < superblock.source_size_bytes {
            return Err(Error::NoSpace);
        }
        (
            TargetFacts::for_directory(&request.target, superblock.source_size_bytes)?,
            Some(directory),
        )
    } else {
        let facts = TargetFacts::read(&request.target)?;
        if facts.size_bytes < superblock.source_size_bytes {
            return Err(Error::NoSpace);
        }
        crate::target::preflight_target(&request.target)?;
        (facts, None)
    };

    let mut warnings = Vec::new();
    if target_facts.size_bytes > superblock.source_size_bytes && target_directory.is_none() {
        warnings.push(format!(
            "target is {} bytes larger than the source; the extra space stays unallocated (spec §H.1)",
            target_facts.size_bytes - superblock.source_size_bytes
        ));
    }
    if target_directory.is_some() {
        warnings.push(format!(
            "file mode restores into the existing directory {}; content is written in place",
            request.target.display()
        ));
    }
    if !superblock.is_encrypted() {
        warnings.push("image is not encrypted and not tamper-evident".to_owned());
    }
    if repeated_page_nonces {
        warnings.push(crate::verify::legacy_nonce_warning(&location.name));
    }
    match superblock.consistency {
        Consistency::None => warnings.push(
            "image consistency is 'none' (a live read); applying it requires \
             --accept-inconsistent"
                .to_owned(),
        ),
        Consistency::PerFile => warnings.push(
            "image consistency is 'per-file': every file is consistent as read, but there is \
             no point in time across files (spec §D.2)"
                .to_owned(),
        ),
        _ => {}
    }
    if superblock.image_kind == ImageKind::Block
        && superblock.source_size_bytes % u64::from(superblock.chunk_size) != 0
    {
        warnings.push("the final chunk is partial; its tail is written as recorded".to_owned());
    }
    if members.len() > 1 {
        warnings.push(format!(
            "restoring a chain: {} members are applied in order, ending with {}",
            members.len(),
            superblock.image_uuid
        ));
    }

    let token = RestoreToken::issue(
        TokenImage {
            dest: location.dest.clone(),
            set: location.set.clone(),
            image: location.name.clone(),
            chain: members.clone(),
            identity: request.identity.clone(),
            known_hosts: request.known_hosts.clone(),
            insecure_ignore_host_key: request.insecure_ignore_host_key,
        },
        &request.target,
        superblock.image_uuid,
        target_facts.clone(),
        target_directory,
        request.merge,
        request.ttl,
    )?;

    Ok(RestorePlan {
        dest: location.dest,
        set: location.set,
        image: location.name,
        members,
        image_uuid: superblock.image_uuid,
        consistency: superblock.consistency,
        image_kind: superblock.image_kind,
        source_size_bytes: superblock.source_size_bytes,
        chunk_size: superblock.chunk_size,
        target: request.target.clone(),
        target_size_bytes: target_facts.size_bytes,
        target_facts,
        encrypted: superblock.is_encrypted(),
        warnings,
        token: token.encode(),
    })
}

/// What `apply` needs.
pub struct ApplyRequest {
    /// Encoded token from `prepare`.
    pub token: String,
    /// Must be true; the write is refused otherwise.
    pub confirm: bool,
    /// Allow applying an image flagged inconsistent.
    pub accept_inconsistent: bool,
    /// How to unlock the image.
    pub encryption: Encryption,
    /// Live progress and cooperative cancellation (spec §I).
    pub context: crate::progress::EngineContext,
}

/// Result of a restore.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreReport {
    /// Image that was applied (set-relative name).
    pub image: String,
    /// Target that was written.
    pub target: PathBuf,
    /// Image UUID.
    pub image_uuid: ImageId,
    /// Consistency level of the image.
    pub consistency: Consistency,
    /// Chunks written from the image.
    pub stored_chunks_written: u64,
    /// Chunks written as zeros.
    pub zero_chunks_written: u64,
    /// Chunks left untouched because the source had no data there.
    pub skipped_chunks: u64,
    /// Total bytes written.
    pub bytes_written: u64,
}

/// What a restore produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum RestoreOutcome {
    /// A block or whole-disk image.
    Block(RestoreReport),
    /// A Btrfs Stream image (spec §H.1).
    Stream(crate::stream::StreamRestoreReport),
    /// A file-mode tree restored into a directory (spec §K S12).
    File(crate::file::FileRestoreReport),
}

impl RestoreOutcome {
    /// The block or whole-disk report.
    ///
    /// # Errors
    /// Returns [`Error::Unsupported`] when a stream restore ran instead.
    pub fn block(self) -> Result<RestoreReport> {
        match self {
            Self::Block(report) => Ok(report),
            Self::Stream(_) => Err(Error::unsupported("the restore was a stream restore")),
            Self::File(_) => Err(Error::unsupported("the restore was a file restore")),
        }
    }

    /// The file-mode report.
    ///
    /// # Errors
    /// Returns [`Error::Unsupported`] when another kind of restore ran.
    pub fn file(self) -> Result<crate::file::FileRestoreReport> {
        match self {
            Self::File(report) => Ok(report),
            Self::Block(_) | Self::Stream(_) => {
                Err(Error::unsupported("the restore was not a file restore"))
            }
        }
    }

    /// The stream report.
    ///
    /// # Errors
    /// Returns [`Error::Unsupported`] when a block restore ran instead.
    pub fn stream(self) -> Result<crate::stream::StreamRestoreReport> {
        match self {
            Self::Stream(report) => Ok(report),
            Self::Block(_) | Self::File(_) => {
                Err(Error::unsupported("the restore was not a stream restore"))
            }
        }
    }
}

/// Apply a prepared restore.
///
/// # Errors
/// Returns [`Error::TargetChanged`] when the target's identity, size or first
/// megabyte changed since `prepare`, [`Error::TargetBusy`] when it is in use,
/// [`Error::Corrupt`] for an invalid or expired token, and [`Error::BadSector`]
/// when an image records an unreadable region (which cannot be reproduced).
pub fn apply_restore(request: &ApplyRequest) -> Result<RestoreOutcome> {
    if !request.confirm {
        return Err(Error::unsupported(
            "restore apply requires --confirm; nothing has been written",
        ));
    }
    let token = RestoreToken::decode(&request.token)?;
    token.verify()?;

    let destination = lr_store::open(&token.dest, &token.destination_options())?;
    let set = destination.open_set(&lr_core::SetId::ZERO)?;
    let (mut reader, keys, superblock) =
        open_image(&*destination, &set, &token.image, &request.encryption)?;
    if superblock.image_uuid != token.image_uuid {
        return Err(Error::TargetChanged);
    }
    if superblock.image_kind == ImageKind::File {
        // Re-read the directory immediately before writing (spec §H.2).
        let expected = token
            .target_directory
            .as_ref()
            .ok_or_else(|| Error::corrupt("the token authorises no directory target"))?;
        let current = crate::target::DirectoryFacts::read(&token.target_path)?;
        if !current.matches(expected) {
            return Err(Error::TargetChanged);
        }
        let chain = if token.chain.is_empty() {
            vec![token.image.clone()]
        } else {
            token.chain.clone()
        };
        let report = crate::file::restore_file(&crate::file::FileRestoreRequest {
            dest: token.dest.clone(),
            set: token.set.clone(),
            images: chain,
            destination_options: token.destination_options(),
            target: token.target_path.clone(),
            encryption: request.encryption.clone(),
            confirm: true,
            accept_inconsistent: request.accept_inconsistent,
            merge: token.merge,
            context: request.context.clone(),
        })?;
        return Ok(RestoreOutcome::File(report));
    }
    if superblock.is_inconsistent() && !request.accept_inconsistent {
        return Err(Error::unsupported(
            "image is flagged inconsistent; pass --accept-inconsistent to restore it",
        ));
    }

    // Re-read the target immediately before writing (spec §H.2).
    let current = TargetFacts::read(&token.target_path)?;
    if !current.matches(&token.target) {
        return Err(Error::TargetChanged);
    }
    crate::target::preflight_target(&token.target_path)?;

    let mut reporter = request
        .context
        .clone()
        .reporter(superblock.source_size_bytes)?;
    reporter.phase("restore");

    let chain = if token.chain.is_empty() {
        vec![token.image.clone()]
    } else {
        token.chain.clone()
    };

    if superblock.is_whole_disk() {
        // A whole-disk restore reads manifests and chunks at the same time, so
        // it needs its own second handle.
        let mut chunks = reader.chunk_reader_with(destination.open_ro(&set, &token.image)?);
        return write_image(
            &mut reader,
            &mut chunks,
            &keys,
            &superblock,
            &token,
            &mut reporter,
        )
        .map(RestoreOutcome::Block);
    }

    if superblock.image_kind == ImageKind::Stream {
        let report = crate::stream::restore_stream(&crate::stream::StreamRestoreRequest {
            dest: token.dest.clone(),
            set: token.set.clone(),
            images: chain,
            destination_options: token.destination_options(),
            target: token.target_path.clone(),
            encryption: request.encryption.clone(),
            mount_root: PathBuf::from("/run/linuxreflect"),
            confirm: true,
            accept_inconsistent: request.accept_inconsistent,
            context: request.context.clone(),
        })?;
        return Ok(RestoreOutcome::Stream(report));
    }

    let files: Vec<crate::chain::ChainMemberFile> = chain
        .iter()
        .map(|name| {
            let member = crate::chain::read_superblock(&*destination, &set, name)?;
            Ok(crate::chain::ChainMemberFile {
                file_name: name.clone(),
                seq_in_chain: member.seq_in_chain,
                image_uuid: member.image_uuid,
            })
        })
        .collect::<Result<_>>()?;
    let members = crate::chain::open_chain(&*destination, &set, &files, &request.encryption)?;
    write_block_chain(members, &superblock, &token, &mut reporter).map(RestoreOutcome::Block)
}

/// Restore a whole-disk image (which is always a single full image).
fn write_image(
    reader: &mut ImageReader<Box<dyn ReadSeek + Send>>,
    chunks: &mut lr_format::ChunkReader,
    keys: &ImageKeys,
    superblock: &Superblock,
    token: &RestoreToken,
    reporter: &mut crate::progress::Reporter,
) -> Result<RestoreReport> {
    if !superblock.is_whole_disk() {
        return Err(Error::corrupt(
            "a partition image must be restored through the chain walker",
        ));
    }
    crate::whole_disk::restore_whole_disk(reader, chunks, keys, superblock, token, reporter)
}

/// Restore a block image, merging every chain member's state.
///
/// The merged state of chunk `n` is the entry from the newest member that
/// mentions it, and its payload may live in any ancestor; the walker resolves
/// both streamingly, so a long chain never materialises a manifest in RAM
/// (spec §G.2).
fn write_block_chain(
    members: Vec<crate::chain::OpenMember>,
    superblock: &Superblock,
    token: &RestoreToken,
    reporter: &mut crate::progress::Reporter,
) -> Result<RestoreReport> {
    let chunk_size = u64::from(superblock.chunk_size);
    let mut walk = crate::chain::ChainWalk::new(members)?;
    if walk.chunk_size() != superblock.chunk_size
        || walk.chunk_count() != superblock.source_size_bytes.div_ceil(chunk_size)
    {
        return Err(Error::corrupt(
            "the chain's chunk geometry does not match the image superblock",
        ));
    }

    let mut target = DirectBlockTarget::open(&token.target_path)?;
    if target.size_bytes() < superblock.source_size_bytes {
        return Err(Error::NoSpace);
    }
    let mut buffer = target.buffer(chunk_size as usize)?;
    let mut zeros = target.buffer(chunk_size as usize)?;
    zeros.clear();

    let mut stored_chunks_written = 0u64;
    let mut zero_chunks_written = 0u64;
    let mut skipped_chunks = 0u64;
    let mut bytes_written = 0u64;

    walk.walk(|index, state, access| {
        reporter.report(index * chunk_size)?;
        let offset = index * chunk_size;
        if offset >= superblock.source_size_bytes {
            return Ok(());
        }
        let chunk_len = chunk_size.min(superblock.source_size_bytes - offset) as usize;
        match state {
            lr_format::ChunkState::Stored { .. } => {
                let plaintext = access.read(&state)?;
                if plaintext.len() != chunk_len {
                    return Err(Error::corrupt(format!(
                        "chunk {index} restored to {} bytes, expected {chunk_len}",
                        plaintext.len()
                    )));
                }
                buffer.as_mut_slice()[..chunk_len].copy_from_slice(&plaintext);
                target.write_at(offset, &buffer, chunk_len)?;
                stored_chunks_written += 1;
                bytes_written += chunk_len as u64;
            }
            lr_format::ChunkState::Zero => {
                target.write_at(offset, &zeros, chunk_len)?;
                zero_chunks_written += 1;
                bytes_written += chunk_len as u64;
            }
            lr_format::ChunkState::Unused => {
                // A hole is left untouched on purpose (D-019).
                skipped_chunks += 1;
            }
            lr_format::ChunkState::BadSector => {
                return Err(Error::BadSector {
                    offset,
                    len: chunk_len as u64,
                });
            }
        }
        Ok(())
    })?;

    reporter.finish(superblock.source_size_bytes);
    target.sync()?;
    Ok(RestoreReport {
        image: token.image.clone(),
        target: token.target_path.clone(),
        image_uuid: superblock.image_uuid,
        consistency: superblock.consistency,
        stored_chunks_written,
        zero_chunks_written,
        skipped_chunks,
        bytes_written,
    })
}

#[cfg(test)]
mod tests {
    use super::{RestoreToken, TARGET_HASH_BYTES, TOKEN_PREFIX, TargetFacts, TokenImage};
    use crate::backup::now_unix;
    use lr_core::ImageId;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    fn facts() -> TargetFacts {
        TargetFacts {
            dev_id: 0x801,
            wwid_or_serial: Some("naa.5000c500".to_owned()),
            size_bytes: 64 * 1024 * 1024,
            pt_hash: "aabb".repeat(32),
        }
    }

    #[test]
    fn tokens_round_trip_and_verify() {
        let token = RestoreToken::issue(
            TokenImage {
                dest: "/backups".to_owned(),
                set: "laptop-root".to_owned(),
                image: "chain-1/000-full-a.lrimg".to_owned(),
                chain: vec!["chain-1/000-full-a.lrimg".to_owned()],
                ..TokenImage::default()
            },
            Path::new("/dev/loop9"),
            ImageId::ZERO,
            facts(),
            None,
            false,
            Duration::from_secs(60),
        )
        .expect("issue");
        let encoded = token.encode();
        assert!(encoded.starts_with(TOKEN_PREFIX));

        let decoded = RestoreToken::decode(&encoded).expect("decode");
        decoded.verify().expect("verify");
        assert_eq!(decoded.dest, "/backups");
        assert_eq!(decoded.set, "laptop-root");
        assert_eq!(decoded.image, "chain-1/000-full-a.lrimg");
        assert_eq!(decoded.chain, vec!["chain-1/000-full-a.lrimg".to_owned()]);
        assert_eq!(decoded.target_path, PathBuf::from("/dev/loop9"));
        assert_eq!(decoded.target, facts());
        assert!(decoded.remaining_seconds() <= 60);
    }

    #[test]
    fn a_tampered_target_is_rejected() {
        let token = RestoreToken::issue(
            TokenImage {
                dest: "/backups".to_owned(),
                set: "laptop-root".to_owned(),
                image: "chain-1/000-full-a.lrimg".to_owned(),
                chain: vec!["chain-1/000-full-a.lrimg".to_owned()],
                ..TokenImage::default()
            },
            Path::new("/dev/loop9"),
            ImageId::ZERO,
            facts(),
            None,
            false,
            Duration::from_secs(60),
        )
        .expect("issue");
        let mut tampered = token.clone();
        tampered.target.size_bytes += 4096;
        assert!(
            tampered.verify().is_err(),
            "the MAC covers the target facts"
        );

        let mut moved = token;
        moved.target_path = PathBuf::from("/dev/loop8");
        assert!(moved.verify().is_err(), "the MAC covers the target path");
    }

    #[test]
    fn the_token_secret_lives_in_a_writable_runtime_directory() {
        let path = super::token_secret_path().expect("secret path");
        eprintln!("token secret path: {}", path.display());
        let secret = super::token_secret();
        assert!(path.parent().expect("parent").is_dir());
        assert_eq!(secret.len(), 32);
        assert_eq!(
            super::token_secret(),
            secret,
            "the secret is cached per boot"
        );
        let mode = std::fs::metadata(&path).expect("stat").mode() & 0o777;
        assert_eq!(mode, 0o600, "the secret must be private");
    }

    #[test]
    fn expiry_is_checked_against_the_current_time() {
        let now = now_unix();
        assert!(super::token_expired(now.saturating_sub(1), now));
        assert!(!super::token_expired(now, now));
        assert!(!super::token_expired(now + 600, now));
    }

    #[test]
    fn malformed_tokens_are_rejected() {
        assert!(RestoreToken::decode("nonsense").is_err());
        assert!(RestoreToken::decode("lrt1:{").is_err());
        const { assert!(TARGET_HASH_BYTES > 4096) };
    }
}
