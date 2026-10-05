//! Read-only planning for the source side of a backup.

use lr_core::{Consistency, Error, ImageKind, Result, discovery::discover_source};

use crate::backup::{BackupRequest, snapshot_opts};
use crate::backup_plan::{BackupMode, ResolvedBackupPlan};
use crate::file::FileBackupOptions;
use crate::options::Mode;

const EXECUTION_RECHECK_WARNING: &str = "this is a source-side plan; destination availability, chain resolution and snapshot creation are revalidated when the backup starts";

/// The source plan a client can review before starting a backup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupPlan {
    /// Provider the matching execution path will use.
    pub provider: String,
    /// Image representation the matching execution path will produce.
    pub image_kind: ImageKind,
    /// Consistency the execution path is expected to achieve.
    pub consistency: Consistency,
    /// Read-only estimate of source bytes represented by the image.
    pub estimated_bytes: u64,
    /// Notes surfaced by source discovery and provider selection.
    pub warnings: Vec<String>,
}

/// Refuse a forced mode that differs from the source's resolved representation.
pub(crate) fn validate_mode_selection(
    mode: Mode,
    image_kind: ImageKind,
    whole_disk: bool,
) -> Result<()> {
    match (mode, image_kind) {
        (Mode::Auto, _) => Ok(()),
        (Mode::Block, ImageKind::Stream) => Err(Error::unsupported(
            "block mode was requested, but this source resolves to Btrfs Stream mode",
        )),
        (Mode::Stream, ImageKind::Block) if whole_disk => Err(Error::unsupported(
            "stream mode was requested for a whole disk; whole-disk backups require block mode",
        )),
        (Mode::Stream, ImageKind::Block) => Err(Error::unsupported(
            "stream mode was requested, but this source resolves to block mode",
        )),
        (Mode::File, _) | (_, ImageKind::File) => Err(Error::unsupported(
            "the requested backup mode does not match the resolved source representation",
        )),
        (Mode::Block | Mode::Stream, _) => Ok(()),
    }
}

/// Resolve a backup source without opening its destination or creating a snapshot.
///
/// # Errors
/// Refuses invalid mode/provider combinations, unsupported or busy sources,
/// and propagates source discovery and size-estimation failures.
pub fn plan_backup(
    request: &BackupRequest,
    mode: Mode,
    file_options: &FileBackupOptions,
) -> Result<BackupPlan> {
    let mut plan = if mode == Mode::File {
        crate::file::plan_file_backup(request, file_options)?
    } else {
        let layout = discover_source(&request.source)?;
        plan_source_layout(request, &layout, mode)?
    };
    plan.warnings.push(EXECUTION_RECHECK_WARNING.to_owned());
    Ok(plan)
}

fn plan_source_layout(
    request: &BackupRequest,
    layout: &lr_core::SourceLayout,
    mode: Mode,
) -> Result<BackupPlan> {
    if layout.device_facts.size_bytes == 0 {
        return Err(Error::unsupported(format!(
            "{} reports a size of 0 bytes; is the source still present?",
            request.source.display()
        )));
    }

    if layout.is_whole_disk() {
        validate_mode_selection(mode, ImageKind::Block, true)?;
        crate::whole_disk::preflight(request, layout)?;
        return Ok(BackupPlan {
            provider: "offline".to_owned(),
            image_kind: ImageKind::Block,
            consistency: Consistency::Offline,
            estimated_bytes: layout.device_facts.size_bytes,
            warnings: Vec::new(),
        });
    }

    let opts = snapshot_opts(request);
    let source_plan = lr_snapshot::probe::probe(layout, &opts)?;
    validate_mode_selection(mode, source_plan.image_kind, false)?;
    match source_plan.image_kind {
        ImageKind::Stream => {
            ResolvedBackupPlan::validate_mode(BackupMode::BtrfsStream, request.member_type)?;
            if let lr_core::Support::No(reason) =
                lr_snapshot::btrfs::provider().supports(layout, &opts)
            {
                return Err(Error::unsupported(format!("btrfs provider: {reason}")));
            }
        }
        ImageKind::Block => {
            crate::backup::validate_chunk_size(request.chunk_size)?;
            let provider = lr_snapshot::probe::block_provider(&source_plan.provider)?;
            lr_snapshot::probe::confirm(provider, layout, &opts)?;
        }
        ImageKind::File => {
            return Err(Error::unsupported(
                "block source planning selected file mode unexpectedly",
            ));
        }
    }

    Ok(BackupPlan {
        provider: source_plan.provider,
        image_kind: source_plan.image_kind,
        consistency: source_plan.consistency,
        estimated_bytes: source_plan.estimated_bytes,
        warnings: source_plan.warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::{plan_source_layout, validate_mode_selection};
    use crate::backup::BackupRequest;
    use crate::keys::Encryption;
    use crate::options::Mode;
    use lr_core::ImageKind;
    use lr_core::discovery::{
        BlockDeviceType, DeviceFacts, FsFacts, PartitionLayout, PartitionTableInfo,
        PartitionTableKind, SourceLayout,
    };
    use std::path::PathBuf;

    fn source_layout(mountpoints: &[&str], with_partition: bool) -> SourceLayout {
        let device = PathBuf::from("/synthetic/lr-plan-source");
        let partition = PartitionLayout {
            index: 1,
            name: Some("lr-plan-source1".to_owned()),
            path: Some(PathBuf::from("/synthetic/lr-plan-source1")),
            start_lba: 2048,
            size_bytes: 8 * 1024 * 1024,
            type_guid: None,
            type_name: None,
            part_uuid: None,
            mbr_type: None,
            fs_type: Some("ext4".to_owned()),
            fs_uuid: None,
            fs_label: None,
            mountpoints: Vec::new(),
            holders: Vec::new(),
            bootable: false,
        };
        SourceLayout {
            device: device.clone(),
            device_facts: DeviceFacts {
                name: "lr-plan-source".to_owned(),
                path: device,
                dev_type: BlockDeviceType::Disk,
                size_bytes: 16 * 1024 * 1024,
                logical_block_size: 512,
                physical_block_size: 512,
                dev_id: Some("240:0".to_owned()),
                removable: false,
                read_only: false,
                model: None,
                serial: None,
                wwid: None,
            },
            partition_table: with_partition.then_some(PartitionTableInfo {
                kind: PartitionTableKind::Gpt,
                disk_guid: Some("fixture-disk".to_owned()),
                logical_block_size: 512,
                first_usable_lba: Some(34),
                last_usable_lba: Some(32_734),
                entry_count: Some(128),
                has_mbr_signature: true,
            }),
            partitions: if with_partition {
                vec![partition]
            } else {
                Vec::new()
            },
            fs: Some(FsFacts {
                fs_type: "ext4".to_owned(),
                uuid: Some("fixture-fs".to_owned()),
                label: None,
                block_size: Some(4096),
                usage: Some("filesystem".to_owned()),
            }),
            mountpoints: mountpoints.iter().map(PathBuf::from).collect(),
            holders: Vec::new(),
            lvm: None,
            btrfs: None,
            warnings: Vec::new(),
        }
    }

    fn request() -> BackupRequest {
        BackupRequest::new(
            "/synthetic/lr-plan-source",
            "/synthetic/lr-plan-destination",
            "plan-test",
            Encryption::NoEncrypt,
        )
        .expect("request")
    }

    #[test]
    fn no_consent_refuses_a_mounted_live_partition() {
        let mut request = request();
        request.snapshot_provider = Some("none".to_owned());
        let layout = source_layout(&["/mnt/data"], false);

        let error =
            plan_source_layout(&request, &layout, Mode::Auto).expect_err("consent is required");
        assert!(
            error.to_string().contains("--allow-inconsistent"),
            "{error}"
        );
    }

    #[test]
    fn forced_freeze_refuses_the_running_root_filesystem() {
        let mut request = request();
        request.snapshot_provider = Some("freeze".to_owned());
        request.allow_freeze = true;
        request.allow_inconsistent = true;
        let layout = source_layout(&["/"], false);

        let error =
            plan_source_layout(&request, &layout, Mode::Auto).expect_err("root cannot be frozen");
        assert!(
            error.to_string().contains("no consistent snapshot method"),
            "{error}"
        );
    }

    #[test]
    fn allow_inconsistent_does_not_bypass_whole_disk_offline_preflight() {
        let mut request = request();
        request.allow_inconsistent = true;
        let mut layout = source_layout(&[], true);
        layout.partitions[0]
            .mountpoints
            .push(PathBuf::from("/mnt/partition"));

        let error =
            plan_source_layout(&request, &layout, Mode::Auto).expect_err("whole disk must be idle");
        assert!(
            error.to_string().contains("offline read refused"),
            "{error}"
        );
        assert!(
            error.to_string().contains("partition 1 is mounted"),
            "{error}"
        );
    }

    #[test]
    fn forced_modes_must_match_the_resolved_representation() {
        assert!(validate_mode_selection(Mode::Block, ImageKind::Stream, false).is_err());
        assert!(validate_mode_selection(Mode::Stream, ImageKind::Block, false).is_err());
        let whole_disk = validate_mode_selection(Mode::Stream, ImageKind::Block, true)
            .expect_err("whole disks cannot use Stream mode");
        assert!(
            whole_disk.to_string().contains("whole disk"),
            "{whole_disk}"
        );
        assert!(validate_mode_selection(Mode::Auto, ImageKind::Block, true).is_ok());
    }
}
