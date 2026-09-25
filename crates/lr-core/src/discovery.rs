//! Source discovery: partition tables, filesystems, holders, mount points and
//! LVM/Btrfs facts (spec §C, Slice S2).
//!
//! Discovery is strictly read-only. It works both on real block devices (via
//! sysfs) and on plain image files (via the partition-table bytes and
//! `blkid`), which is what makes the S2 acceptance test runnable without
//! root when a loop device is unavailable.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::Error;
use crate::sysfs;

/// Kind of block device or file being inspected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockDeviceType {
    /// Whole disk (`/sys/block/*`).
    Disk,
    /// Partition of a whole disk.
    Partition,
    /// Loop device.
    Loop,
    /// Device-mapper device (LVM, LUKS, dm-crypt).
    DeviceMapper,
    /// Software RAID member or array.
    Md,
    /// RAM disk.
    Ram,
    /// Read-only optical/other device.
    Rom,
    /// A regular file holding a disk image.
    RegularFile,
    /// Anything else.
    Other,
}

impl BlockDeviceType {
    /// Stable identifier for JSON output and CLI display.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Disk => "disk",
            Self::Partition => "partition",
            Self::Loop => "loop",
            Self::DeviceMapper => "dm",
            Self::Md => "md",
            Self::Ram => "ram",
            Self::Rom => "rom",
            Self::RegularFile => "file",
            Self::Other => "other",
        }
    }
}

impl fmt::Display for BlockDeviceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

/// Facts about the device or file itself.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DeviceFacts {
    /// Kernel name (`sda`, `nvme0n1`, or the file name).
    pub name: String,
    /// Device node or file path.
    pub path: PathBuf,
    /// Device kind.
    pub dev_type: BlockDeviceType,
    /// Size in bytes.
    pub size_bytes: u64,
    /// Logical sector size in bytes.
    pub logical_block_size: u32,
    /// Physical sector size in bytes.
    pub physical_block_size: u32,
    /// `major:minor`, when known from sysfs.
    pub dev_id: Option<String>,
    /// Removable media.
    pub removable: bool,
    /// Read-only device.
    pub read_only: bool,
    /// Model string from sysfs, when available.
    pub model: Option<String>,
    /// Serial string from sysfs, when available.
    pub serial: Option<String>,
    /// WWID from sysfs, when available.
    pub wwid: Option<String>,
}

/// Filesystem facts as reported by `blkid -p -o export`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FsFacts {
    /// Filesystem type, e.g. `ext4`, `xfs`, `btrfs`, `swap`, `LVM2_member`.
    pub fs_type: String,
    /// Filesystem UUID.
    pub uuid: Option<String>,
    /// Filesystem label.
    pub label: Option<String>,
    /// Filesystem block size in bytes, when reported.
    pub block_size: Option<u32>,
    /// `blkid` USAGE field (`filesystem`, `raid`, `other`, ...).
    pub usage: Option<String>,
}

/// Partition table flavour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartitionTableKind {
    /// GUID Partition Table.
    Gpt,
    /// Legacy MBR/DOS table.
    Mbr,
    /// No recognisable table.
    None,
}

impl fmt::Display for PartitionTableKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gpt => f.write_str("gpt"),
            Self::Mbr => f.write_str("mbr"),
            Self::None => f.write_str("none"),
        }
    }
}

/// Summary of the partition table.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PartitionTableInfo {
    /// Table flavour.
    pub kind: PartitionTableKind,
    /// Disk GUID (GPT only).
    pub disk_guid: Option<String>,
    /// Logical block size used to interpret the table.
    pub logical_block_size: u32,
    /// First LBA usable by partitions (GPT only).
    pub first_usable_lba: Option<u64>,
    /// Last usable LBA (GPT only).
    pub last_usable_lba: Option<u64>,
    /// Number of partition entries in the table (GPT only).
    pub entry_count: Option<u32>,
    /// Whether a protective/legacy MBR signature is present.
    pub has_mbr_signature: bool,
}

/// One partition of the source.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PartitionLayout {
    /// Partition index (1-based).
    pub index: u32,
    /// Kernel name, when the partition node exists (`sda1`).
    pub name: Option<String>,
    /// Device node path, when the partition node exists.
    pub path: Option<PathBuf>,
    /// First sector (LBA).
    pub start_lba: u64,
    /// Size in bytes.
    pub size_bytes: u64,
    /// Partition type GUID (GPT) or `None` for MBR.
    pub type_guid: Option<String>,
    /// Human-readable type name (EFI System, BIOS boot, Linux filesystem, ...).
    pub type_name: Option<String>,
    /// Partition UUID/GUID.
    pub part_uuid: Option<String>,
    /// MBR partition type byte, when applicable.
    pub mbr_type: Option<u8>,
    /// Filesystem type detected on the partition.
    pub fs_type: Option<String>,
    /// Filesystem UUID detected on the partition.
    pub fs_uuid: Option<String>,
    /// Filesystem label detected on the partition.
    pub fs_label: Option<String>,
    /// Mount points currently holding this partition.
    pub mountpoints: Vec<PathBuf>,
    /// Kernel holders of this partition (dm/md/LVM mappings).
    pub holders: Vec<String>,
    /// Boot flag (MBR active flag or GPT legacy-BIOS bootable attribute).
    pub bootable: bool,
}

/// LVM facts for the device, when it participates in LVM.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LvmFacts {
    /// The device is an LVM physical volume.
    pub is_pv: bool,
    /// The device is a device-mapper device.
    pub is_dm: bool,
    /// Volume group name, when derivable from sysfs.
    pub vg_name: Option<String>,
    /// Logical volume name, when derivable from sysfs.
    pub lv_name: Option<String>,
    /// Raw device-mapper name (`vg-lv`).
    pub dm_name: Option<String>,
    /// Thin-pool membership, when known (`lvs` required).
    pub thin: Option<bool>,
}

/// One Btrfs subvolume found on the source filesystem.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BtrfsSubvolume {
    /// Subvolume id.
    pub id: u64,
    /// Parent subvolume id (5 for the top level).
    pub parent_id: Option<u64>,
    /// Subvolume path relative to the top level.
    pub path: String,
}

/// Btrfs facts for the source filesystem.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BtrfsFacts {
    /// Filesystem UUID.
    pub fs_uuid: Option<String>,
    /// Filesystem label.
    pub label: Option<String>,
    /// Mount points of this filesystem.
    pub mountpoints: Vec<PathBuf>,
    /// Subvolumes, when the `btrfs` tooling could be run.
    pub subvolumes: Vec<BtrfsSubvolume>,
    /// Default subvolume id, when known.
    pub default_subvolid: Option<u64>,
    /// Whether the `btrfs` tool was actually queried.
    pub probed: bool,
}

/// Everything the engine needs to know about a backup source.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SourceLayout {
    /// Source device or image file.
    pub device: PathBuf,
    /// Facts about the device itself.
    pub device_facts: DeviceFacts,
    /// Partition table, when present.
    pub partition_table: Option<PartitionTableInfo>,
    /// Partitions found in the table (and, when available, in sysfs).
    pub partitions: Vec<PartitionLayout>,
    /// Filesystem directly on the device (a partition, an LV, or an image file).
    pub fs: Option<FsFacts>,
    /// Mount points holding the device or file.
    pub mountpoints: Vec<PathBuf>,
    /// Kernel holders of the device.
    pub holders: Vec<String>,
    /// LVM facts, when applicable.
    pub lvm: Option<LvmFacts>,
    /// Btrfs facts, when applicable.
    pub btrfs: Option<BtrfsFacts>,
    /// Non-fatal issues encountered while probing.
    pub warnings: Vec<String>,
}

impl SourceLayout {
    /// `true` when nothing is mounted and no holder claims the device.
    #[must_use]
    pub fn is_offline(&self) -> bool {
        self.mountpoints.is_empty() && self.holders.is_empty()
    }

    /// `true` when the source carries a partition table with partitions, so it
    /// must be imaged as a whole disk (spec §G.7).
    ///
    /// This is deliberately based on the discovered layout rather than on the
    /// device class: a loop device attached with `--partscan` and a plain image
    /// file holding a partition table are whole-disk sources too.
    #[must_use]
    pub fn is_whole_disk(&self) -> bool {
        !self.partitions.is_empty()
    }
}

/// Discover everything LinuxReflect needs to know about `device`.
///
/// # Errors
/// Fails when the device cannot be inspected at all (missing file, no size).
/// Everything else is reported through [`SourceLayout::warnings`].
pub fn discover_source(device: &Path) -> crate::Result<SourceLayout> {
    let mut warnings = Vec::new();
    let device_facts = device_facts(device, &mut warnings)?;
    let logical_block_size = device_facts.logical_block_size;

    let mut sysfs_partitions = sysfs_partition_index(&device_facts.name);
    // A regular file cannot have sysfs children.
    if device_facts.dev_type == BlockDeviceType::RegularFile {
        sysfs_partitions.clear();
    }

    let table = probe_partition_table(device, logical_block_size, &mut warnings)?;
    let mut partitions = Vec::new();
    if let Some(info) = &table {
        partitions = match info.kind {
            PartitionTableKind::Gpt => gpt_partitions(
                device,
                logical_block_size,
                &mut warnings,
                &mut sysfs_partitions,
            ),
            PartitionTableKind::Mbr => mbr_partitions(device, 512, &sysfs_partitions),
            PartitionTableKind::None => Vec::new(),
        };
    }
    // Sysfs may know partitions the table parse missed (for example when the
    // table could not be read). Keep them in index order.
    for (index, sys) in &sysfs_partitions {
        if !partitions.iter().any(|p| p.index == *index) {
            partitions.push(PartitionLayout {
                index: *index,
                name: Some(sys.name.clone()),
                path: Some(sys.path.clone()),
                start_lba: sys.start_lba,
                size_bytes: sys.size_bytes,
                type_guid: None,
                type_name: None,
                part_uuid: None,
                mbr_type: None,
                fs_type: None,
                fs_uuid: None,
                fs_label: None,
                mountpoints: sys.mountpoints.clone(),
                holders: sys.holders.clone(),
                bootable: false,
            });
        }
    }
    for part in &mut partitions {
        let probed = partition_fs_probe(device, &device_facts, part);
        match probed {
            Ok(Some(facts)) => {
                part.fs_type = Some(facts.fs_type.clone());
                part.fs_uuid = facts.uuid.clone();
                part.fs_label = facts.label.clone();
            }
            Ok(None) => {}
            Err(reason) => warnings.push(format!("blkid on partition {}: {reason}", part.index)),
        }
        if part.mountpoints.is_empty()
            && let Some(path) = part.path.clone().filter(|p| p.exists())
        {
            part.mountpoints = sysfs::read_mountpoints(&path).unwrap_or_default();
        }
    }
    partitions.sort_by_key(|p| p.index);

    let fs = match blkid_probe(device) {
        Ok(facts) => facts,
        Err(reason) => {
            warnings.push(format!("blkid on {}: {reason}", device.display()));
            None
        }
    };

    let mountpoints = if device_facts.dev_type == BlockDeviceType::RegularFile {
        mounts_for_source(device)
    } else {
        sysfs::read_mountpoints(device).unwrap_or_else(|_| mounts_for_source(device))
    };
    let holders = sysfs::read_holders(&device_facts.name);

    let lvm = lvm_facts(&device_facts, fs.as_ref());
    let btrfs = match &fs {
        Some(facts) if facts.fs_type == "btrfs" => {
            Some(btrfs_facts(facts, &mountpoints, &mut warnings))
        }
        _ => None,
    };

    Ok(SourceLayout {
        device: device.to_path_buf(),
        device_facts,
        partition_table: table,
        partitions,
        fs,
        mountpoints,
        holders,
        lvm,
        btrfs,
        warnings,
    })
}

fn mounts_for_source(device: &Path) -> Vec<PathBuf> {
    sysfs::read_mounts()
        .map(|mounts| {
            mounts
                .into_iter()
                .filter(|m| Path::new(&m.source) == device || m.source == device.to_string_lossy())
                .map(|m| m.mountpoint)
                .collect()
        })
        .unwrap_or_default()
}

/// Local sysfs facts for one partition, keyed by partition index.
struct SysfsPartition {
    name: String,
    path: PathBuf,
    size_bytes: u64,
    /// First sector, from the sysfs `start` attribute (512-byte units).
    start_lba: u64,
    mountpoints: Vec<PathBuf>,
    holders: Vec<String>,
}

fn sysfs_partition_index(parent: &str) -> BTreeMap<u32, SysfsPartition> {
    let mut map = BTreeMap::new();
    let Ok(devices) = sysfs::list_all_block_devices() else {
        return map;
    };
    for device in devices {
        if device.parent.as_deref() != Some(parent) {
            continue;
        }
        let Some(index) = device.partition else {
            continue;
        };
        let mountpoints = sysfs::read_mountpoints(&device.path).unwrap_or_default();
        let start_lba = lr_unsafe::read_sysfs_u64(
            &sysfs::sysfs_root()
                .join("class/block")
                .join(&device.name)
                .join("start"),
        )
        .unwrap_or(0);
        map.insert(
            index,
            SysfsPartition {
                name: device.name.clone(),
                path: device.path.clone(),
                size_bytes: device.size_bytes,
                start_lba,
                mountpoints,
                holders: device.holders.clone(),
            },
        );
    }
    map
}

fn device_facts(device: &Path, warnings: &mut Vec<String>) -> crate::Result<DeviceFacts> {
    // A device can be reached through a symlink: `/dev/<vg>/<lv>` points at
    // `/dev/dm-N`, and sysfs only knows the latter. The layout keeps the
    // caller's path, but every probe uses the resolved node.
    let resolved = std::fs::canonicalize(device).unwrap_or_else(|_| device.to_path_buf());
    let name = sysfs::device_name(&resolved).map_err(Error::Io)?;
    let class_dir = sysfs::sysfs_root().join("class/block").join(&name);

    if class_dir.is_dir() {
        let size_bytes = match lr_unsafe::block_device_size_bytes(&resolved) {
            Ok(size) => size,
            Err(io_err) => {
                warnings.push(format!("BLKGETSIZE64 on {}: {io_err}", device.display()));
                lr_unsafe::read_sysfs_u64(&class_dir.join("size")).unwrap_or(0) * 512
            }
        };
        let logical_block_size = lr_unsafe::block_device_logical_sector_size(device)
            .unwrap_or_else(|_| {
                lr_unsafe::read_sysfs_u64(&class_dir.join("queue/logical_block_size"))
                    .unwrap_or(512) as u32
            });
        let physical_block_size =
            lr_unsafe::block_device_physical_sector_size(&resolved).unwrap_or(logical_block_size);
        let dev_type = classify_block_device(&name, &class_dir);
        let device_dir = class_dir.join("device");
        Ok(DeviceFacts {
            name,
            path: device.to_path_buf(),
            dev_type,
            size_bytes,
            logical_block_size,
            physical_block_size,
            dev_id: lr_unsafe::read_sysfs_string(&class_dir.join("dev")).ok(),
            removable: read_sysfs_bool(&class_dir.join("removable")),
            read_only: read_sysfs_bool(&class_dir.join("ro")),
            model: read_optional(&device_dir.join("model"))
                .or_else(|| read_optional(&device_dir.join("vendor"))),
            serial: read_optional(&device_dir.join("serial")),
            wwid: read_optional(&device_dir.join("wwid")),
        })
    } else {
        let metadata = std::fs::metadata(device).map_err(Error::Io)?;
        Ok(DeviceFacts {
            name,
            path: device.to_path_buf(),
            dev_type: if metadata.is_file() {
                BlockDeviceType::RegularFile
            } else {
                BlockDeviceType::Other
            },
            size_bytes: metadata.len(),
            logical_block_size: 512,
            physical_block_size: 512,
            dev_id: None,
            removable: false,
            read_only: metadata.permissions().readonly(),
            model: None,
            serial: None,
            wwid: None,
        })
    }
}

fn read_sysfs_bool(path: &Path) -> bool {
    lr_unsafe::read_sysfs_string(path)
        .map(|v| v != "0")
        .unwrap_or(false)
}

fn read_optional(path: &Path) -> Option<String> {
    lr_unsafe::read_sysfs_string(path)
        .ok()
        .filter(|v| !v.is_empty())
}

fn classify_block_device(name: &str, class_dir: &Path) -> BlockDeviceType {
    if class_dir.join("partition").exists() {
        return BlockDeviceType::Partition;
    }
    if name.starts_with("loop") {
        BlockDeviceType::Loop
    } else if name.starts_with("dm-") {
        BlockDeviceType::DeviceMapper
    } else if name.starts_with("md") {
        BlockDeviceType::Md
    } else if name.starts_with("ram") {
        BlockDeviceType::Ram
    } else if name.starts_with("sr") || name.starts_with("zram") {
        BlockDeviceType::Rom
    } else if class_dir.join("device").exists() {
        BlockDeviceType::Disk
    } else {
        BlockDeviceType::Other
    }
}

fn probe_partition_table(
    device: &Path,
    logical_block_size: u32,
    warnings: &mut Vec<String>,
) -> crate::Result<Option<PartitionTableInfo>> {
    let mut file = match std::fs::File::open(device) {
        Ok(file) => file,
        Err(e) => {
            warnings.push(format!("cannot read {}: {e}", device.display()));
            return Ok(None);
        }
    };
    let mut mbr_sector = [0u8; 512];
    if file.read_exact(&mut mbr_sector).is_err() {
        return Ok(None);
    }
    let has_mbr_signature = mbr_sector[510] == 0x55 && mbr_sector[511] == 0xAA;

    let mut gpt_header = [0u8; 92];
    let gpt_read_ok =
        file.seek(SeekFrom::Start(512)).is_ok() && file.read_exact(&mut gpt_header).is_ok();
    if gpt_read_ok && &gpt_header[0..8] == b"EFI PART" {
        let config = gpt::GptConfig::new()
            .writable(false)
            .logical_block_size(disk_block_size(logical_block_size))
            .only_valid_headers(false);
        return match config.open(device) {
            Ok(disk) => {
                let header = disk.header();
                Ok(Some(PartitionTableInfo {
                    kind: PartitionTableKind::Gpt,
                    disk_guid: Some(disk.guid().to_string()),
                    logical_block_size,
                    first_usable_lba: Some(header.first_usable),
                    last_usable_lba: Some(header.last_usable),
                    entry_count: Some(header.num_parts),
                    has_mbr_signature,
                }))
            }
            Err(e) => {
                warnings.push(format!("GPT parse of {} failed: {e}", device.display()));
                Ok(None)
            }
        };
    }

    if has_mbr_signature {
        return Ok(Some(PartitionTableInfo {
            kind: PartitionTableKind::Mbr,
            disk_guid: None,
            logical_block_size,
            first_usable_lba: None,
            last_usable_lba: None,
            entry_count: Some(4),
            has_mbr_signature: true,
        }));
    }
    Ok(None)
}

fn disk_block_size(logical_block_size: u32) -> gpt::disk::LogicalBlockSize {
    let bytes = u64::from(if logical_block_size == 0 {
        512
    } else {
        logical_block_size
    });
    gpt::disk::LogicalBlockSize::try_from(bytes).unwrap_or(gpt::disk::LogicalBlockSize::Lb512)
}

fn gpt_partitions(
    device: &Path,
    logical_block_size: u32,
    warnings: &mut Vec<String>,
    sysfs_partitions: &mut BTreeMap<u32, SysfsPartition>,
) -> Vec<PartitionLayout> {
    let lbs = u64::from(if logical_block_size == 0 {
        512
    } else {
        logical_block_size
    });
    let config = gpt::GptConfig::new()
        .writable(false)
        .logical_block_size(disk_block_size(logical_block_size))
        .only_valid_headers(false);
    let Ok(disk) = config.open(device) else {
        warnings.push(format!(
            "cannot enumerate GPT partitions of {}",
            device.display()
        ));
        return Vec::new();
    };
    let mut out = Vec::new();
    for (index, part) in disk.partitions() {
        let sectors = part.last_lba.saturating_sub(part.first_lba) + 1;
        let sys = sysfs_partitions.remove(index);
        out.push(PartitionLayout {
            index: *index,
            name: sys.as_ref().map(|s| s.name.clone()),
            path: sys.as_ref().map(|s| s.path.clone()),
            start_lba: part.first_lba,
            size_bytes: sectors * lbs,
            type_guid: Some(part.part_type_guid.guid.to_string()),
            type_name: Some(gpt_type_name(&part.part_type_guid)),
            part_uuid: Some(part.part_guid.to_string()),
            mbr_type: None,
            fs_type: None,
            fs_uuid: None,
            fs_label: None,
            mountpoints: sys
                .as_ref()
                .map(|s| s.mountpoints.clone())
                .unwrap_or_default(),
            holders: sys.as_ref().map(|s| s.holders.clone()).unwrap_or_default(),
            bootable: part.flags & gpt::partition::PartitionAttributes::BOOTABLE.bits() != 0
                || part.part_type_guid == gpt::partition_types::BIOS,
        });
    }
    out
}

fn gpt_type_name(partition_type: &gpt::partition_types::Type) -> String {
    use gpt::partition_types as types;
    let known: [(&gpt::partition_types::Type, &str); 9] = [
        (&types::EFI, "EFI System"),
        (&types::BIOS, "BIOS boot"),
        (&types::LINUX_FS, "Linux filesystem"),
        (&types::LINUX_SWAP, "Linux swap"),
        (&types::LINUX_LVM, "Linux LVM"),
        (&types::LINUX_LUKS, "Linux LUKS"),
        (&types::LINUX_RAID, "Linux RAID"),
        (&types::LINUX_ROOT_X64, "Linux root (x86-64)"),
        (&types::LINUX_HOME, "Linux home"),
    ];
    known
        .iter()
        .find(|(ty, _)| *ty == partition_type)
        .map_or_else(
            || format!("{:?}", partition_type.os),
            |(_, name)| (*name).to_owned(),
        )
}

fn mbr_partitions(
    device: &Path,
    sector_size: u32,
    sysfs_partitions: &BTreeMap<u32, SysfsPartition>,
) -> Vec<PartitionLayout> {
    let Ok(mut file) = std::fs::File::open(device) else {
        return Vec::new();
    };
    let Ok(mbr) = mbrman::MBR::read_from(&mut file, sector_size) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (slot, entry) in mbr.iter() {
        if entry.is_unused() {
            continue;
        }
        // mbrman numbers primary partitions 1..4 and logical ones from 5,
        // which is also how the kernel numbers them (`sda1`, `sda5`, ...).
        let index = u32::try_from(slot).unwrap_or(0);
        let sys = sysfs_partitions.get(&index);
        out.push(PartitionLayout {
            index,
            name: sys.map(|s| s.name.clone()),
            path: sys.map(|s| s.path.clone()),
            start_lba: u64::from(entry.starting_lba),
            size_bytes: u64::from(entry.sectors) * u64::from(sector_size),
            type_guid: None,
            type_name: Some(mbr_type_name(entry.sys).to_owned()),
            part_uuid: None,
            mbr_type: Some(entry.sys),
            fs_type: None,
            fs_uuid: None,
            fs_label: None,
            mountpoints: sys.map(|s| s.mountpoints.clone()).unwrap_or_default(),
            holders: sys.map(|s| s.holders.clone()).unwrap_or_default(),
            bootable: entry.is_active(),
        });
    }
    out
}

fn mbr_type_name(sys: u8) -> &'static str {
    match sys {
        0x05 | 0x0f | 0x85 => "Extended",
        0x07 => "NTFS/exFAT",
        0x0b | 0x0c => "FAT32",
        0x82 => "Linux swap",
        0x83 => "Linux",
        0x8e => "Linux LVM",
        0xee => "GPT protective",
        0xef => "EFI System",
        0xfd => "Linux RAID",
        _ => "unknown",
    }
}

/// Probe the filesystem of one partition.
///
/// For a real device the partition node is probed directly. For a whole-disk
/// *image file* there is no partition node, so the parent file is probed at the
/// partition's byte offset with `blkid -O <offset> --size <partition size>`
/// (this is what makes `disk map` on an image file report the same filesystems
/// `disk map` on the device would). Bounding the probe with `--size` is
/// required for signatures stored at the end of the region, such as swap.
fn partition_fs_probe(
    device: &Path,
    device_facts: &DeviceFacts,
    part: &PartitionLayout,
) -> Result<Option<FsFacts>, String> {
    if let Some(path) = part.path.as_ref().filter(|p| p.exists()) {
        return blkid_probe(path);
    }
    if device_facts.dev_type == BlockDeviceType::RegularFile && part.size_bytes > 0 {
        let offset = part.start_lba * u64::from(device_facts.logical_block_size);
        return blkid_probe_at(device, Some((offset, part.size_bytes)));
    }
    Ok(None)
}

/// Parse `blkid -p -o export` output for a path.
///
/// Returns `Ok(None)` when `blkid` recognises nothing.
fn blkid_probe(path: &Path) -> Result<Option<FsFacts>, String> {
    blkid_probe_at(path, None)
}

/// Parse `blkid -p -o export [-O <offset> --size <size>]` output for a path.
///
/// Returns `Ok(None)` when `blkid` recognises nothing.
fn blkid_probe_at(path: &Path, region: Option<(u64, u64)>) -> Result<Option<FsFacts>, String> {
    let mut command = Command::new("blkid");
    command.args(["-p", "-o", "export"]);
    if let Some((offset, size)) = region {
        command
            .arg("-O")
            .arg(offset.to_string())
            .arg("--size")
            .arg(size.to_string());
    }
    let output = command
        .arg(path)
        .output()
        .map_err(|e| format!("cannot run blkid: {e}"))?;
    // blkid exits 2 when nothing is detected; stderr is then informational.
    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() {
        return Ok(None);
    }
    let mut fields: BTreeMap<String, String> = BTreeMap::new();
    for line in stdout.lines() {
        if let Some((key, value)) = line.split_once('=') {
            fields.insert(key.trim().to_owned(), value.trim().to_owned());
        }
    }
    let Some(fs_type) = fields.get("TYPE").cloned() else {
        return Ok(None);
    };
    Ok(Some(FsFacts {
        fs_type,
        uuid: fields.get("UUID").cloned(),
        label: fields.get("LABEL").cloned(),
        block_size: fields.get("BLOCK_SIZE").and_then(|v| v.parse().ok()),
        usage: fields.get("USAGE").cloned(),
    }))
}

fn lvm_facts(device: &DeviceFacts, fs: Option<&FsFacts>) -> Option<LvmFacts> {
    let is_pv = fs.is_some_and(|f| f.fs_type.starts_with("LVM2_member"));
    let is_dm = device.dev_type == BlockDeviceType::DeviceMapper;
    if !is_pv && !is_dm {
        return None;
    }
    let dm_name = if is_dm {
        read_optional(
            &sysfs::sysfs_root()
                .join("class/block")
                .join(&device.name)
                .join("dm/name"),
        )
    } else {
        None
    };
    let (vg_name, lv_name) = dm_name
        .as_deref()
        .and_then(|name| name.split_once('-'))
        .map_or((None, None), |(vg, lv)| {
            (Some(vg.to_owned()), Some(lv.to_owned()))
        });
    Some(LvmFacts {
        is_pv,
        is_dm,
        vg_name,
        lv_name,
        dm_name,
        thin: None,
    })
}

fn btrfs_facts(facts: &FsFacts, mountpoints: &[PathBuf], warnings: &mut Vec<String>) -> BtrfsFacts {
    let mut result = BtrfsFacts {
        fs_uuid: facts.uuid.clone(),
        label: facts.label.clone(),
        mountpoints: mountpoints.to_vec(),
        ..BtrfsFacts::default()
    };
    let Some(mountpoint) = mountpoints.first() else {
        warnings.push("btrfs filesystem is not mounted; subvolume list skipped".to_owned());
        return result;
    };
    let output = Command::new("btrfs")
        .args(["subvolume", "list", "-u"])
        .arg(mountpoint)
        .output();
    let output = match output {
        Ok(output) if output.status.success() => output,
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warnings.push(format!("btrfs subvolume list failed: {}", stderr.trim()));
            return result;
        }
        Err(e) => {
            warnings.push(format!("btrfs tool unavailable: {e}"));
            return result;
        }
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if let Some(subvol) = parse_btrfs_subvolume_line(line) {
            result.subvolumes.push(subvol);
        }
    }
    result.probed = true;
    result
}

/// Parse a `btrfs subvolume list` line such as
/// `ID 256 gen 30 top level 5 uuid ... path @`.
#[must_use]
pub fn parse_btrfs_subvolume_line(line: &str) -> Option<BtrfsSubvolume> {
    let mut id = None;
    let mut parent_id = None;
    let mut path = None;
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let mut index = 0;
    while index < tokens.len() {
        match tokens[index] {
            "ID" => {
                id = tokens.get(index + 1).and_then(|v| v.parse().ok());
                index += 2;
            }
            "top" => {
                // "top level <n>"
                if tokens.get(index + 1) == Some(&"level") {
                    parent_id = tokens.get(index + 2).and_then(|v| v.parse().ok());
                    index += 3;
                } else {
                    index += 1;
                }
            }
            "path" => {
                path = tokens.get(index + 1).map(|v| (*v).to_owned());
                index += 2;
            }
            _ => index += 1,
        }
    }
    Some(BtrfsSubvolume {
        id: id?,
        parent_id,
        path: path?,
    })
}

#[cfg(test)]
mod tests {
    use super::{PartitionTableKind, parse_btrfs_subvolume_line};

    #[test]
    fn parses_btrfs_subvolume_line() {
        let subvol = parse_btrfs_subvolume_line(
            "ID 256 gen 30 top level 5 uuid 00000000-0000-0000-0000-000000000000 path @",
        )
        .expect("parse");
        assert_eq!(subvol.id, 256);
        assert_eq!(subvol.parent_id, Some(5));
        assert_eq!(subvol.path, "@");
    }

    #[test]
    fn table_kind_display() {
        assert_eq!(PartitionTableKind::Gpt.to_string(), "gpt");
        assert_eq!(PartitionTableKind::Mbr.to_string(), "mbr");
    }
}
