//! Content-bound captured verification contract.

use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use lr_core::{ChainId, Consistency, Id, ImageId, ImageKind, SetId};
use lr_crypto::aead::AeadKind;
use lr_crypto::nonce::NonceSeq;
use lr_engine::BackupReport;
use lr_engine::backup::{BackupRequest, Compression, MemberType};
use lr_engine::backup_block_full;
use lr_engine::file::{FileBackupOptions, backup_file};
use lr_engine::keys::Encryption;
use lr_engine::keystore::Passphrase;
use lr_engine::progress::{EngineContext, ProgressSink};
use lr_engine::verify::{
    AttemptOutcome, AttemptStage, CaptureOptions, ContentCoverage, FailureKind, MemberStage,
    RecoveryScope, VerifyReport, VerifyRequest, verify_image_captured,
};
use lr_format::disk::{DiskHeader, PtType, RegionKind, RegionRecord};
use lr_format::{
    BlockEntry, BlockManifestHeader, ChainMember, ChunkOptions, ImageWriter, StreamId,
    StreamSection, Superblock, WriterKeys, flags,
};
use lr_store::DestinationOptions;

const IMAGE_SIZE: u64 = 2 * 1024 * 1024;
const CHUNK_SIZE: u32 = 256 * 1024;

struct FlipImageOnContent {
    image: PathBuf,
    flipped: AtomicBool,
}

impl ProgressSink for FlipImageOnContent {
    fn phase(&self, name: &str) {
        if name != "content" || self.flipped.swap(true, Ordering::Relaxed) {
            return;
        }
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.image)
            .expect("open source image for post-capture mutation");
        file.seek(SeekFrom::Start(lr_format::SB_SIZE as u64 + 20))
            .expect("seek to first captured payload");
        let mut byte = [0u8; 1];
        file.read_exact(&mut byte)
            .expect("read source payload byte");
        byte[0] ^= 0x01;
        file.seek(SeekFrom::Start(lr_format::SB_SIZE as u64 + 20))
            .expect("seek back to source payload");
        file.write_all(&byte).expect("mutate source payload byte");
        file.sync_all().expect("sync source mutation");
    }

    fn bytes(&self, _done: u64, _total: u64) {}
}

fn destination_tempdir() -> tempfile::TempDir {
    match std::env::var_os("LR_TEST_DESTINATION_ROOT") {
        Some(root) => tempfile::Builder::new()
            .prefix("lr-verify-observation-")
            .tempdir_in(root)
            .expect("create destination fixture under LR_TEST_DESTINATION_ROOT"),
        None => tempfile::tempdir().expect("create local destination fixture"),
    }
}

fn private_local_tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("lr-verify-private-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .expect("create private local temporary directory")
}

fn source_image(path: &Path) {
    let mut file = std::fs::File::create(path).expect("create source image");
    file.set_len(IMAGE_SIZE).expect("size source image");
    let mut payload = vec![0u8; CHUNK_SIZE as usize];
    let mut state = 0x8d26_5f13_6a90_b47du64;
    for byte in &mut payload {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *byte = (state >> 33) as u8;
    }
    file.write_all(&payload)
        .expect("write nonzero source payload");
    file.sync_all().expect("sync source image");
}

fn hash_file(path: &Path) -> [u8; 32] {
    let mut file = std::fs::File::open(path).expect("open image for digest");
    let mut buffer = [0u8; 64 * 1024];
    let mut hasher = blake3::Hasher::new();
    loop {
        let read = file.read(&mut buffer).expect("read image for digest");
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    *hasher.finalize().as_bytes()
}

fn block_fixture(
    set: &str,
    encryption: Encryption,
) -> (tempfile::TempDir, tempfile::TempDir, BackupReport) {
    let local = private_local_tempdir();
    let destination = destination_tempdir();
    let source = local.path().join("source.img");
    source_image(&source);
    let mut backup_request =
        BackupRequest::new(&source, destination.path(), set, encryption).expect("backup request");
    backup_request.chunk_size = CHUNK_SIZE;
    backup_request.compression = Compression::None;
    let report = backup_block_full(&backup_request).expect("create block fixture");
    (local, destination, report)
}

fn verify_request(
    image: impl Into<String>,
    set: &str,
    chain: bool,
    progress: Option<Arc<dyn ProgressSink>>,
    cancel: Option<Arc<AtomicBool>>,
) -> VerifyRequest {
    VerifyRequest {
        image: image.into(),
        encryption: Encryption::NoEncrypt,
        chain,
        destination_options: DestinationOptions::new(set),
        context: EngineContext { progress, cancel },
    }
}

struct CancelOnPhase {
    phase: &'static str,
    cancel: Arc<AtomicBool>,
}

impl ProgressSink for CancelOnPhase {
    fn phase(&self, phase: &str) {
        if phase == self.phase {
            self.cancel.store(true, Ordering::Relaxed);
        }
    }

    fn bytes(&self, _done: u64, _total: u64) {}
}

fn flip_byte(path: &Path, offset: u64) {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("open image to corrupt fixture");
    file.seek(SeekFrom::Start(offset)).expect("seek to byte");
    let mut byte = [0u8; 1];
    file.read_exact(&mut byte).expect("read byte");
    byte[0] ^= 0x01;
    file.seek(SeekFrom::Start(offset)).expect("seek back");
    file.write_all(&byte).expect("write changed byte");
    file.sync_all().expect("sync changed fixture");
}

fn assert_report_parity(legacy: VerifyReport, captured: &VerifyReport) {
    assert_eq!(
        &legacy, captured,
        "captured branch must use the same verifier"
    );
}

struct SyntheticMember {
    image_uuid: ImageId,
    chain_id: ChainId,
    set_id: SetId,
    parent_uuid: ImageId,
    seq_in_chain: u32,
    image_kind: ImageKind,
    source_size_bytes: u64,
    logical_block_size: u32,
    chunk_size: u32,
    whole_disk: bool,
}

fn synthetic_superblock(member: SyntheticMember) -> Superblock {
    Superblock {
        format_major: lr_format::FORMAT_MAJOR,
        min_reader: lr_format::MIN_READER,
        flags: if member.whole_disk {
            flags::WHOLE_DISK
        } else {
            0
        },
        image_kind: member.image_kind,
        consistency: Consistency::Offline,
        image_uuid: member.image_uuid,
        chain_id: member.chain_id,
        set_id: member.set_id,
        parent_uuid: member.parent_uuid,
        seq_in_chain: member.seq_in_chain,
        created_unix: 10,
        source_size_bytes: member.source_size_bytes,
        logical_block_size: member.logical_block_size,
        chunk_size: member.chunk_size,
        kdf_id: 0,
        aead_id: lr_crypto::aead::AEAD_ID_AES_256_GCM,
        kdf_salt: [0; 16],
        argon2_m_cost_kib: 0,
        argon2_t_cost: 0,
        argon2_p_cost: 0,
        wrap_nonce: [0; 12],
        wrapped_chain_key: [0; 48],
    }
}

fn synthetic_writer_keys(superblock: &Superblock) -> WriterKeys {
    let chain_key = lr_crypto::ChainKey::from_bytes(lr_crypto::mac::fixed_public_mac_key());
    let image_keys = lr_crypto::file_keys(&chain_key, superblock.image_uuid.inner())
        .expect("derive image fixture keys");
    WriterKeys {
        data_key: None,
        meta_key: *image_keys.meta_key,
        dedup_key: lr_crypto::dedup_key(&chain_key, superblock.chain_id.inner())
            .expect("derive chain fixture key"),
    }
}

fn write_synthetic_stream_member(
    path: &Path,
    superblock: &Superblock,
    chain_members: &[ChainMember],
    parent_snapshot_uuid: Option<Id>,
) {
    let keys = synthetic_writer_keys(superblock);
    let file = std::fs::File::create(path).expect("create stream member");
    let mut writer = ImageWriter::create(file, superblock, None).expect("stream writer");
    let mut nonce = NonceSeq::new();
    let reference = writer
        .append_chunk(
            ChunkOptions {
                kind: AeadKind::Aes256Gcm,
                level: 0,
                compress: false,
            },
            &keys,
            ImageKind::Stream,
            &mut nonce,
            &[0x33; 4096],
        )
        .expect("append stream chunk");
    {
        let mut manifest =
            writer.page_stream(StreamId::Manifest, AeadKind::Aes256Gcm, keys.meta_key);
        StreamSection {
            subvolid: 256,
            send_stream_bytes: 4096,
            parent_snapshot_uuid,
            subvol_path: "/@".to_owned(),
            entry_count: 1,
        }
        .write(&mut manifest)
        .expect("write stream section");
        BlockEntry::stored(0, reference.hash, reference.offset, reference.stored_len)
            .expect("stored stream entry")
            .write(&mut manifest)
            .expect("write stream entry");
        manifest.finish().expect("finish stream manifest");
    }
    {
        let mut extras = writer.page_stream(StreamId::Extras, AeadKind::Aes256Gcm, keys.meta_key);
        lr_format::write_chain_members(&mut extras, chain_members).expect("write chain members");
        lr_format::write_extras_record(
            &mut extras,
            lr_format::EXTRAS_BTRFS_LAYOUT,
            b"fs_uuid=00000000-0000-0000-0000-000000000001\nlabel=\ndefault_subvolid=256\ndefault_subvol_path=/@\nmount_options=\nsubvol=/@\t256\n",
        )
        .expect("write Btrfs layout");
        extras.finish().expect("finish stream extras");
    }
    let (mut file, _) = writer
        .finish(&keys.meta_key, None, AeadKind::Aes256Gcm)
        .expect("finish stream member");
    file.flush().expect("flush stream member");
}

fn synthetic_stream_fixture() -> (tempfile::TempDir, String, String) {
    let destination = destination_tempdir();
    let set = "captured-stream-runtime";
    let chain_id = ChainId::new(Id::from_bytes([0x63; 16]));
    let set_id = SetId::new(Id::from_bytes([0x64; 16]));
    let full_id = ImageId::new(Id::from_bytes([0x65; 16]));
    let incremental_id = ImageId::new(Id::from_bytes([0x66; 16]));
    let chain_directory = destination.path().join(set).join(chain_id.to_string());
    std::fs::create_dir_all(&chain_directory).expect("create stream fixture chain");

    let full_name = format!("000-full-{full_id}.lrimg");
    let incremental_name = format!("001-incr-{incremental_id}.lrimg");
    let full_superblock = synthetic_superblock(SyntheticMember {
        image_uuid: full_id,
        chain_id,
        set_id,
        parent_uuid: ImageId::ZERO,
        seq_in_chain: 0,
        image_kind: ImageKind::Stream,
        source_size_bytes: 4096,
        logical_block_size: 4096,
        chunk_size: lr_engine::stream::CDC_MAX,
        whole_disk: false,
    });
    let incremental_superblock = synthetic_superblock(SyntheticMember {
        image_uuid: incremental_id,
        chain_id,
        set_id,
        parent_uuid: full_id,
        seq_in_chain: 1,
        image_kind: ImageKind::Stream,
        source_size_bytes: 4096,
        logical_block_size: 4096,
        chunk_size: lr_engine::stream::CDC_MAX,
        whole_disk: false,
    });
    let full_member = ChainMember {
        index: 0,
        image_uuid: full_id,
    };
    let incremental_member = ChainMember {
        index: 1,
        image_uuid: incremental_id,
    };
    write_synthetic_stream_member(
        &chain_directory.join(&full_name),
        &full_superblock,
        &[full_member],
        None,
    );
    write_synthetic_stream_member(
        &chain_directory.join(&incremental_name),
        &incremental_superblock,
        &[full_member, incremental_member],
        Some(Id::from_bytes([0x67; 16])),
    );
    let image = destination
        .path()
        .join(set)
        .join(chain_id.to_string())
        .join(&incremental_name)
        .to_string_lossy()
        .into_owned();
    (destination, set.to_owned(), image)
}

fn synthetic_whole_disk_fixture() -> (tempfile::TempDir, String, String) {
    const DISK_BYTES: u64 = 4 * 1024 * 1024;
    const CHUNK_BYTES: u32 = 256 * 1024;

    let destination = destination_tempdir();
    let set = "captured-whole-disk-runtime";
    let chain_id = ChainId::new(Id::from_bytes([0x73; 16]));
    let set_id = SetId::new(Id::from_bytes([0x74; 16]));
    let image_id = ImageId::new(Id::from_bytes([0x75; 16]));
    let chain_directory = destination.path().join(set).join(chain_id.to_string());
    std::fs::create_dir_all(&chain_directory).expect("create disk fixture chain");
    let image_name = format!("000-full-{image_id}.lrimg");
    let image_path = chain_directory.join(&image_name);
    let superblock = synthetic_superblock(SyntheticMember {
        image_uuid: image_id,
        chain_id,
        set_id,
        parent_uuid: ImageId::ZERO,
        seq_in_chain: 0,
        image_kind: ImageKind::Block,
        source_size_bytes: DISK_BYTES,
        logical_block_size: 512,
        chunk_size: CHUNK_BYTES,
        whole_disk: true,
    });
    let keys = synthetic_writer_keys(&superblock);
    let file = std::fs::File::create(&image_path).expect("create whole-disk member");
    let mut writer = ImageWriter::create(file, &superblock, None).expect("whole-disk writer");
    let reference = writer
        .append_chunk(
            ChunkOptions {
                kind: AeadKind::Aes256Gcm,
                level: 0,
                compress: false,
            },
            &keys,
            ImageKind::Block,
            &mut NonceSeq::new(),
            &vec![0x44; CHUNK_BYTES as usize],
        )
        .expect("append nonzero region payload");
    let region = RegionRecord::new(RegionKind::PartitionRaw, 1, 2048, u64::from(CHUNK_BYTES));
    let disk = DiskHeader {
        disk_size: DISK_BYTES,
        logical_block_size: 512,
        pt_type: PtType::None,
        serial_wwid: String::new(),
        pt_raw: Vec::new(),
        regions: vec![region.clone()],
    };
    {
        let mut manifest =
            writer.page_stream(StreamId::Manifest, AeadKind::Aes256Gcm, keys.meta_key);
        disk.write(&mut manifest).expect("write disk header");
        BlockManifestHeader {
            chunk_size: CHUNK_BYTES,
            chunk_count: 1,
            entry_count: 1,
            used_extent_count: 1,
            used_bytes: region.size_bytes,
            fs_type: String::new(),
            fs_uuid: String::new(),
            label: String::new(),
        }
        .write(&mut manifest, false)
        .expect("write region manifest header");
        BlockEntry::stored(0, reference.hash, reference.offset, reference.stored_len)
            .expect("stored region entry")
            .write(&mut manifest)
            .expect("write stored region entry");
        manifest.finish().expect("finish whole-disk manifest");
    }
    {
        let mut extras = writer.page_stream(StreamId::Extras, AeadKind::Aes256Gcm, keys.meta_key);
        lr_format::write_chain_members(
            &mut extras,
            &[ChainMember {
                index: 0,
                image_uuid: image_id,
            }],
        )
        .expect("write whole-disk chain members");
        extras.finish().expect("finish whole-disk extras");
    }
    let (mut file, _) = writer
        .finish(&keys.meta_key, None, AeadKind::Aes256Gcm)
        .expect("finish whole-disk member");
    file.flush().expect("flush whole-disk member");
    let image = destination
        .path()
        .join(set)
        .join(chain_id.to_string())
        .join(image_name)
        .to_string_lossy()
        .into_owned();
    (destination, set.to_owned(), image)
}

#[test]
fn captured_verification_uses_independent_read_cursors_and_never_falls_back_to_changed_source() {
    let (_local, _destination, backup) = block_fixture("captured-verify", Encryption::NoEncrypt);
    assert!(
        backup.stored_chunks > 0,
        "fixture must contain stored payload"
    );
    let original_digest = hash_file(&backup.image_path);

    let scratch = private_local_tempdir();
    let sentinel = scratch.path().join("leave-in-place.txt");
    std::fs::write(&sentinel, b"unrelated user file").expect("create existing scratch entry");
    let mutation = Arc::new(FlipImageOnContent {
        image: backup.image_path.clone(),
        flipped: AtomicBool::new(false),
    });
    let progress: Arc<dyn ProgressSink> = mutation.clone();
    let request = verify_request(
        backup.image_uri.clone(),
        "captured-verify",
        false,
        Some(progress),
        None,
    );
    let captured = verify_image_captured(
        &request,
        &CaptureOptions::new(scratch.path(), 16 * 1024 * 1024, 0),
    );

    assert_eq!(
        captured.observation().outcome(),
        AttemptOutcome::IntegrityVerified,
        "diagnostic: {:?}",
        captured.diagnostic()
    );
    assert!(
        captured.report().is_some(),
        "verified report is retained once"
    );
    assert!(mutation.flipped.load(Ordering::Relaxed));
    assert_ne!(hash_file(&backup.image_path), original_digest);
    assert!(
        lr_engine::verify::verify_image(&request).is_err(),
        "legacy verification of the now-mutated source must fail"
    );
    let member = &captured.observation().members()[0];
    assert_eq!(member.capture(), MemberStage::Complete);
    assert_eq!(member.structure(), MemberStage::Complete);
    assert_eq!(member.content().recovery_point(), MemberStage::Complete);
    assert_eq!(
        member.content().referenced_payloads(),
        MemberStage::Complete
    );
    assert_eq!(
        captured.observation().digest_algorithm(),
        lr_engine::verify::DigestAlgorithm::Blake3RawV1
    );
    assert_eq!(captured.observation().coverage_contract_version(), 1);
    assert_eq!(member.blake3_bytes(), Some(&original_digest));
    assert_eq!(
        std::fs::read(&sentinel).expect("preserved scratch entry"),
        b"unrelated user file"
    );
    assert_eq!(
        std::fs::read_dir(scratch.path())
            .expect("list scratch after capture")
            .count(),
        1,
        "anonymous capture leaves no additional named entries"
    );

    // A refusal is typed and leaves no success report or named scratch files.
    let refused_scratch = private_local_tempdir();
    let refused =
        verify_image_captured(&request, &CaptureOptions::new(refused_scratch.path(), 1, 0));
    assert_eq!(
        refused.observation().outcome(),
        AttemptOutcome::Incomplete {
            stage: AttemptStage::ScratchPreflight,
            reason: FailureKind::RawCapExceeded,
        }
    );
    assert!(refused.report().is_none());
    assert_eq!(refused.observation().members()[0].blake3_bytes(), None);
    assert!(
        std::fs::read_dir(refused_scratch.path())
            .expect("read refused scratch")
            .next()
            .is_none()
    );
    let serialized = serde_json::to_string(refused.observation()).expect("serialize observation");
    assert!(!serialized.contains(&backup.image_uri));
    assert!(!serialized.contains("warnings"));
    assert!(!serialized.contains("diagnostic"));
    assert!(serialized.contains("blake3-raw-v1"));
}

#[test]
fn zero_cap_raw_cap_and_headroom_refusals_are_bounded_and_leave_scratch_untouched() {
    let (_local, _destination, backup) = block_fixture("capture-refusals", Encryption::NoEncrypt);
    let request = verify_request(
        backup.image_uri.clone(),
        "capture-refusals",
        false,
        None,
        None,
    );

    let zero_scratch = private_local_tempdir();
    let zero = verify_image_captured(&request, &CaptureOptions::new(zero_scratch.path(), 0, 0));
    assert_eq!(
        zero.observation().outcome(),
        AttemptOutcome::Incomplete {
            stage: AttemptStage::ScratchPreflight,
            reason: FailureKind::InvalidOptions,
        }
    );
    assert!(zero.observation().members().is_empty());

    let cap_scratch = private_local_tempdir();
    let capped = verify_image_captured(&request, &CaptureOptions::new(cap_scratch.path(), 1, 0));
    assert_eq!(
        capped.observation().outcome(),
        AttemptOutcome::Incomplete {
            stage: AttemptStage::ScratchPreflight,
            reason: FailureKind::RawCapExceeded,
        }
    );
    assert!(capped.report().is_none());
    assert!(capped.observation().members()[0].blake3_bytes().is_none());

    let headroom_scratch = private_local_tempdir();
    let sentinel = headroom_scratch.path().join("keep.txt");
    std::fs::write(&sentinel, b"untouched").expect("create headroom sentinel");
    let headroom = verify_image_captured(
        &request,
        &CaptureOptions::new(headroom_scratch.path(), u64::MAX, u64::MAX),
    );
    assert_eq!(
        headroom.observation().outcome(),
        AttemptOutcome::Incomplete {
            stage: AttemptStage::ScratchPreflight,
            reason: FailureKind::HeadroomUnavailable,
        }
    );
    assert!(headroom.observation().members()[0].blake3_bytes().is_none());
    assert_eq!(
        std::fs::read(sentinel).expect("preserved sentinel"),
        b"untouched"
    );
}

#[test]
fn cancellation_during_capture_and_structure_never_reports_success() {
    let (_local, _destination, backup) =
        block_fixture("capture-cancellation", Encryption::NoEncrypt);

    let capture_cancel = Arc::new(AtomicBool::new(false));
    let capture_progress: Arc<dyn ProgressSink> = Arc::new(CancelOnPhase {
        phase: "capture",
        cancel: Arc::clone(&capture_cancel),
    });
    let capture_request = verify_request(
        backup.image_uri.clone(),
        "capture-cancellation",
        false,
        Some(capture_progress),
        Some(Arc::clone(&capture_cancel)),
    );
    let capture_scratch = private_local_tempdir();
    let cancelled_capture = verify_image_captured(
        &capture_request,
        &CaptureOptions::new(capture_scratch.path(), 16 * 1024 * 1024, 0),
    );
    assert_eq!(
        cancelled_capture.observation().outcome(),
        AttemptOutcome::Incomplete {
            stage: AttemptStage::Capture,
            reason: FailureKind::Cancelled,
        }
    );
    assert!(
        cancelled_capture.observation().members()[0]
            .blake3_bytes()
            .is_none()
    );

    let verify_cancel = Arc::new(AtomicBool::new(false));
    let verify_progress: Arc<dyn ProgressSink> = Arc::new(CancelOnPhase {
        phase: "structure",
        cancel: Arc::clone(&verify_cancel),
    });
    let verify_request = verify_request(
        backup.image_uri.clone(),
        "capture-cancellation",
        false,
        Some(verify_progress),
        Some(Arc::clone(&verify_cancel)),
    );
    let verify_scratch = private_local_tempdir();
    let cancelled_verify = verify_image_captured(
        &verify_request,
        &CaptureOptions::new(verify_scratch.path(), 16 * 1024 * 1024, 0),
    );
    assert_eq!(
        cancelled_verify.observation().outcome(),
        AttemptOutcome::Incomplete {
            stage: AttemptStage::Structure,
            reason: FailureKind::Cancelled,
        }
    );
    let member = &cancelled_verify.observation().members()[0];
    assert!(member.blake3_bytes().is_some());
    assert_eq!(member.structure(), MemberStage::Failed);
    assert_eq!(cancelled_verify.observation().content_coverage(), None);
}

#[test]
fn content_and_structure_corruption_report_the_actual_incomplete_stage() {
    let (_local, _destination, content_backup) =
        block_fixture("capture-content-corrupt", Encryption::NoEncrypt);
    flip_byte(&content_backup.image_path, lr_format::SB_SIZE as u64 + 20);
    let content_request = verify_request(
        content_backup.image_uri.clone(),
        "capture-content-corrupt",
        false,
        None,
        None,
    );
    let content_scratch = private_local_tempdir();
    let content_failure = verify_image_captured(
        &content_request,
        &CaptureOptions::new(content_scratch.path(), 16 * 1024 * 1024, 0),
    );
    assert_eq!(
        content_failure.observation().outcome(),
        AttemptOutcome::Incomplete {
            stage: AttemptStage::Content,
            reason: FailureKind::Corrupt,
        }
    );
    assert_eq!(
        content_failure.observation().content_coverage(),
        Some(ContentCoverage::BlockSelectedMergedReferences)
    );
    assert_eq!(
        content_failure.observation().members()[0].structure(),
        MemberStage::Complete
    );
    assert_eq!(
        content_failure.observation().members()[0]
            .content()
            .recovery_point(),
        MemberStage::Failed
    );
    assert_eq!(
        content_failure.observation().members()[0]
            .content()
            .referenced_payloads(),
        MemberStage::Failed
    );

    let (_local, _destination, structure_backup) =
        block_fixture("capture-structure-corrupt", Encryption::NoEncrypt);
    let image_length = std::fs::metadata(&structure_backup.image_path)
        .expect("stat structure fixture")
        .len();
    flip_byte(&structure_backup.image_path, image_length - 4096 - 64);
    let structure_request = verify_request(
        structure_backup.image_uri.clone(),
        "capture-structure-corrupt",
        false,
        None,
        None,
    );
    let structure_scratch = private_local_tempdir();
    let structure_failure = verify_image_captured(
        &structure_request,
        &CaptureOptions::new(structure_scratch.path(), 16 * 1024 * 1024, 0),
    );
    assert_eq!(
        structure_failure.observation().outcome(),
        AttemptOutcome::Incomplete {
            stage: AttemptStage::Structure,
            reason: FailureKind::Corrupt,
        }
    );
    assert_eq!(structure_failure.observation().content_coverage(), None);
    assert_eq!(
        structure_failure.observation().members()[0].structure(),
        MemberStage::Failed
    );
}

#[test]
fn wrong_key_is_a_typed_structure_refusal() {
    let (_local, _destination, backup) = block_fixture(
        "capture-key-refusal",
        Encryption::Passphrase(Passphrase::new(b"capture-test-key".to_vec())),
    );
    let mut request = verify_request(
        backup.image_uri.clone(),
        "capture-key-refusal",
        false,
        None,
        None,
    );
    request.encryption = Encryption::Passphrase(Passphrase::new(b"wrong-capture-key".to_vec()));
    let scratch = private_local_tempdir();
    let refused = verify_image_captured(
        &request,
        &CaptureOptions::new(scratch.path(), 16 * 1024 * 1024, 0),
    );
    assert_eq!(
        refused.observation().outcome(),
        AttemptOutcome::Incomplete {
            stage: AttemptStage::Structure,
            reason: FailureKind::KeyOrAuthenticationFailure,
        }
    );
    assert_eq!(
        refused.observation().members()[0].structure(),
        MemberStage::Failed
    );
    assert!(refused.observation().members()[0].blake3_bytes().is_some());
}

#[test]
fn file_mode_reports_tree_and_referenced_payload_scope_separately() {
    let local = private_local_tempdir();
    let destination = destination_tempdir();
    let source = local.path().join("tree");
    std::fs::create_dir(&source).expect("create source tree");
    std::fs::write(source.join("ancestor.txt"), vec![b'a'; 64 * 1024])
        .expect("write ancestor file");

    let set = "captured-file-scope";
    let full_request = BackupRequest::new(&source, destination.path(), set, Encryption::NoEncrypt)
        .expect("file full request");
    let full = backup_file(&full_request, &FileBackupOptions::default()).expect("file full");
    std::fs::write(source.join("incremental.txt"), vec![b'b'; 64 * 1024])
        .expect("write incremental file");
    let mut incremental_request =
        BackupRequest::new(&source, destination.path(), set, Encryption::NoEncrypt)
            .expect("file incremental request");
    incremental_request.member_type = MemberType::Incremental;
    incremental_request.parent = Some(full.image_uuid.to_string());
    let incremental =
        backup_file(&incremental_request, &FileBackupOptions::default()).expect("file incremental");
    let image = incremental.image_path.to_string_lossy().into_owned();

    let selected_request = verify_request(image.clone(), set, false, None, None);
    let selected_scratch = private_local_tempdir();
    let selected = verify_image_captured(
        &selected_request,
        &CaptureOptions::new(selected_scratch.path(), 16 * 1024 * 1024, 0),
    );
    assert_eq!(
        selected.observation().outcome(),
        AttemptOutcome::IntegrityVerified
    );
    assert_eq!(
        selected.observation().requested_scope(),
        RecoveryScope::SelectedRecoveryPoint
    );
    assert_eq!(
        selected.observation().content_coverage(),
        Some(ContentCoverage::FileSelectedTreeReferences)
    );
    let selected_members = selected.observation().members();
    assert_eq!(selected_members.len(), 2);
    assert_eq!(
        selected_members[0].content().recovery_point(),
        MemberStage::NotRequested
    );
    assert_eq!(
        selected_members[1].content().recovery_point(),
        MemberStage::Complete
    );
    assert_eq!(
        selected_members[0].content().referenced_payloads(),
        MemberStage::Complete
    );
    assert_eq!(
        selected_members[1].content().referenced_payloads(),
        MemberStage::Complete
    );
    assert_eq!(
        selected_members[0].content().every_stored_payload(),
        MemberStage::NotRequested,
        "file coverage does not claim unreferenced payload checks"
    );

    let every_request = verify_request(image, set, true, None, None);
    let every_scratch = private_local_tempdir();
    let every = verify_image_captured(
        &every_request,
        &CaptureOptions::new(every_scratch.path(), 16 * 1024 * 1024, 0),
    );
    assert_eq!(
        every.observation().outcome(),
        AttemptOutcome::IntegrityVerified
    );
    assert_eq!(
        every.observation().requested_scope(),
        RecoveryScope::EveryMember
    );
    assert_eq!(
        every.observation().content_coverage(),
        Some(ContentCoverage::FileEveryTreeReferences)
    );
    assert!(
        every
            .observation()
            .members()
            .iter()
            .all(|member| { member.content().recovery_point() == MemberStage::Complete })
    );
}

#[test]
fn captured_stream_verifier_records_selected_and_every_member_coverage() {
    let (_destination, set, image) = synthetic_stream_fixture();

    let selected_request = verify_request(image.clone(), &set, false, None, None);
    let legacy_selected = lr_engine::verify::verify_image(&selected_request)
        .expect("legacy selected stream verification");
    let selected_scratch = private_local_tempdir();
    let selected = verify_image_captured(
        &selected_request,
        &CaptureOptions::new(selected_scratch.path(), 16 * 1024 * 1024, 0),
    );
    assert_eq!(
        selected.observation().outcome(),
        AttemptOutcome::IntegrityVerified
    );
    assert_report_parity(
        legacy_selected,
        selected.report().expect("captured selected report"),
    );
    assert_eq!(
        selected.observation().requested_scope(),
        RecoveryScope::SelectedRecoveryPoint
    );
    assert_eq!(
        selected.observation().content_coverage(),
        Some(ContentCoverage::StreamSelectedMemberPayloadsSectionsAndLayout)
    );
    assert_eq!(selected.observation().members().len(), 2);
    let parent = &selected.observation().members()[0];
    let child = &selected.observation().members()[1];
    assert_eq!(parent.capture(), MemberStage::Complete);
    assert_eq!(parent.structure(), MemberStage::Complete);
    assert_eq!(parent.content().recovery_point(), MemberStage::NotRequested);
    assert_eq!(
        parent.content().every_stored_payload(),
        MemberStage::NotRequested
    );
    assert_eq!(child.capture(), MemberStage::Complete);
    assert_eq!(child.structure(), MemberStage::Complete);
    assert_eq!(child.content().recovery_point(), MemberStage::Complete);
    assert_eq!(
        child.content().every_stored_payload(),
        MemberStage::Complete
    );

    let every_request = verify_request(image, &set, true, None, None);
    let legacy_every =
        lr_engine::verify::verify_image(&every_request).expect("legacy every-member stream verify");
    let every_scratch = private_local_tempdir();
    let every = verify_image_captured(
        &every_request,
        &CaptureOptions::new(every_scratch.path(), 16 * 1024 * 1024, 0),
    );
    assert_eq!(
        every.observation().outcome(),
        AttemptOutcome::IntegrityVerified
    );
    assert_report_parity(legacy_every, every.report().expect("captured every report"));
    assert_eq!(
        every.observation().requested_scope(),
        RecoveryScope::EveryMember
    );
    assert_eq!(
        every.observation().content_coverage(),
        Some(ContentCoverage::StreamEveryMemberPayloadsSectionsAndLayout)
    );
    assert!(every.observation().members().iter().all(|member| {
        member.capture() == MemberStage::Complete
            && member.structure() == MemberStage::Complete
            && member.content().recovery_point() == MemberStage::Complete
            && member.content().every_stored_payload() == MemberStage::Complete
    }));
}

#[test]
fn captured_whole_disk_verifier_records_regions_layout_and_report_parity() {
    let (_destination, set, image) = synthetic_whole_disk_fixture();
    let request = verify_request(image, &set, false, None, None);
    let legacy = lr_engine::verify::verify_image(&request).expect("legacy whole-disk verify");
    assert_eq!(
        legacy.chunks, 1,
        "fixture must exercise region payload reads"
    );
    assert_eq!(legacy.bytes_checked, 256 * 1024);
    let scratch = private_local_tempdir();
    let captured = verify_image_captured(
        &request,
        &CaptureOptions::new(scratch.path(), 16 * 1024 * 1024, 0),
    );
    assert_eq!(
        captured.observation().outcome(),
        AttemptOutcome::IntegrityVerified
    );
    assert_report_parity(
        legacy,
        captured.report().expect("captured whole-disk report"),
    );
    assert_eq!(
        captured.observation().requested_scope(),
        RecoveryScope::SelectedRecoveryPoint
    );
    assert_eq!(
        captured.observation().content_coverage(),
        Some(ContentCoverage::WholeDiskRegionsAndLayout)
    );
    let member = &captured.observation().members()[0];
    assert_eq!(member.capture(), MemberStage::Complete);
    assert_eq!(member.structure(), MemberStage::Complete);
    assert_eq!(member.content().recovery_point(), MemberStage::Complete);
    assert_eq!(
        member.content().disk_region_payloads(),
        MemberStage::Complete
    );
    assert_eq!(
        member.content().every_stored_payload(),
        MemberStage::NotRequested
    );
}
