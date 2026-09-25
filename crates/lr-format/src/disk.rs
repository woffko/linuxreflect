//! Whole-disk manifest (spec §G.7, `docs/format-lrimg-v1.md` §8).
//!
//! A whole-disk image is a disk header plus one record per imaged region; the
//! data of a region is described by an ordinary block manifest (§5.2) whose
//! entries are positional within the region. Swap regions store only their
//! first 4 KiB and are recreated with `mkswap -U` on restore; gaps between
//! partitions and the backup GPT are not imaged.

use lr_core::{Consistency, Error, Result};

use crate::manifest::BlockManifestHeader;
use crate::wire::{self, ByteSink, ByteSource, Reader};

/// `section_kind` of the whole-disk header.
pub const SECTION_DISK_HEADER: u8 = 6;

/// Version of the disk header and region records.
pub const DISK_MANIFEST_VER: u16 = 1;

/// Largest leading region, matching spec §G.7's 16 MiB cap.
pub const MAX_LEADING_BYTES: u64 = 16 * 1024 * 1024;

/// Bytes of a partition table captured verbatim (protective MBR + primary GPT).
pub const PT_RAW_BYTES: usize = 1024 * 1024;

/// Bytes stored for a swap partition (spec §G.7).
pub const SWAP_HEADER_BYTES: usize = 4096;

/// Region flags.
pub mod region_flags {
    /// A block manifest follows for this region.
    pub const HAS_MANIFEST: u32 = 1 << 0;
    /// The partition is marked bootable (MBR active flag or GPT BIOS boot).
    pub const BOOTABLE: u32 = 1 << 1;
}

/// Partition table flavour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtType {
    /// No partition table.
    None,
    /// GPT.
    Gpt,
    /// Legacy MBR.
    Mbr,
}

impl PtType {
    /// On-disk discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Gpt => 1,
            Self::Mbr => 2,
        }
    }

    /// Parse an on-disk discriminant.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] for an unknown value.
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Gpt),
            2 => Ok(Self::Mbr),
            other => Err(Error::corrupt(format!(
                "unknown partition table type {other}"
            ))),
        }
    }
}

/// What a region holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionKind {
    /// LBA 0 up to the first partition, capped at 16 MiB.
    Leading,
    /// A partition with a filesystem that has a used-block map.
    PartitionFs,
    /// A partition imaged whole (bios_grub, LVM PV, LUKS, unknown, ...).
    PartitionRaw,
    /// A swap partition: only its first 4 KiB are stored.
    Swap,
}

impl RegionKind {
    /// On-disk discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Leading => 1,
            Self::PartitionFs => 2,
            Self::PartitionRaw => 3,
            Self::Swap => 4,
        }
    }

    /// Parse an on-disk discriminant.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] for an unknown value.
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Leading),
            2 => Ok(Self::PartitionFs),
            3 => Ok(Self::PartitionRaw),
            4 => Ok(Self::Swap),
            other => Err(Error::corrupt(format!("unknown region kind {other}"))),
        }
    }

    /// `true` when a block manifest follows for this region.
    #[must_use]
    pub const fn has_manifest(self) -> bool {
        !matches!(self, Self::Swap)
    }
}

/// One imaged region of a disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionRecord {
    /// What the region holds.
    pub kind: RegionKind,
    /// Consistency level of this region (spec §D.2).
    pub consistency: Consistency,
    /// The partition is marked bootable.
    pub bootable: bool,
    /// Partition index; 0 for the leading region.
    pub index: u32,
    /// First LBA of the region.
    pub start_lba: u64,
    /// Region length in bytes.
    pub size_bytes: u64,
    /// GPT type GUID as a string, when applicable.
    pub type_guid: String,
    /// Partition UUID/GUID as a string, when applicable.
    pub partuuid: String,
    /// Filesystem type, when known.
    pub fs_type: String,
    /// Filesystem UUID, when known.
    pub fs_uuid: String,
    /// Filesystem label, when known.
    pub fs_label: String,
    /// First [`SWAP_HEADER_BYTES`] bytes of a swap partition.
    pub swap_header: Vec<u8>,
}

impl RegionRecord {
    /// A region with everything empty but the geometry.
    #[must_use]
    pub fn new(kind: RegionKind, index: u32, start_lba: u64, size_bytes: u64) -> Self {
        Self {
            kind,
            consistency: Consistency::Offline,
            bootable: false,
            index,
            start_lba,
            size_bytes,
            type_guid: String::new(),
            partuuid: String::new(),
            fs_type: String::new(),
            fs_uuid: String::new(),
            fs_label: String::new(),
            swap_header: Vec::new(),
        }
    }

    /// `true` when a block manifest follows this region.
    #[must_use]
    pub const fn has_manifest(&self) -> bool {
        self.kind.has_manifest()
    }

    /// Flags word as written on disk.
    #[must_use]
    pub const fn flags(&self) -> u32 {
        let mut flags = 0;
        if self.has_manifest() {
            flags |= region_flags::HAS_MANIFEST;
        }
        if self.bootable {
            flags |= region_flags::BOOTABLE;
        }
        flags
    }

    /// Write the record.
    ///
    /// # Errors
    /// Returns [`Error::Unsupported`] for oversized strings and propagates sink
    /// errors.
    pub fn write(&self, out: &mut impl ByteSink) -> Result<()> {
        wire::put_u16(out, DISK_MANIFEST_VER)?;
        wire::put_u8(out, self.kind.as_u8())?;
        wire::put_u8(out, self.consistency.as_u8())?;
        wire::put_u32(out, self.flags())?;
        wire::put_u32(out, self.index)?;
        wire::put_u64(out, self.start_lba)?;
        wire::put_u64(out, self.size_bytes)?;
        wire::put_u16_prefixed(out, self.type_guid.as_bytes())?;
        wire::put_u16_prefixed(out, self.partuuid.as_bytes())?;
        wire::put_u16_prefixed(out, self.fs_type.as_bytes())?;
        wire::put_u16_prefixed(out, self.fs_uuid.as_bytes())?;
        wire::put_u16_prefixed(out, self.fs_label.as_bytes())?;
        wire::put_u32(out, self.swap_header.len() as u32)?;
        wire::put_bytes(out, &self.swap_header)?;
        Ok(())
    }

    /// Read the record.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] for a wrong version, an unknown kind, a flag
    /// that disagrees with the kind, an oversized swap header, or truncation.
    pub fn read<S: ByteSource>(reader: &mut Reader<S>) -> Result<Self> {
        let ver = reader.u16()?;
        if ver != DISK_MANIFEST_VER {
            return Err(Error::corrupt(format!("region record version {ver}")));
        }
        let kind = RegionKind::from_u8(reader.u8()?)?;
        let consistency = Consistency::from_u8(reader.u8()?)?;
        let flags = reader.u32()?;
        if flags & !(region_flags::HAS_MANIFEST | region_flags::BOOTABLE) != 0 {
            return Err(Error::corrupt(format!(
                "unknown region flags 0x{flags:08X}"
            )));
        }
        if (flags & region_flags::HAS_MANIFEST != 0) != kind.has_manifest() {
            return Err(Error::corrupt(format!(
                "region kind {kind:?} disagrees with its manifest flag"
            )));
        }
        let index = reader.u32()?;
        let start_lba = reader.u64()?;
        let size_bytes = reader.u64()?;
        let type_guid = utf8(reader.u16_prefixed()?, "type_guid")?;
        let partuuid = utf8(reader.u16_prefixed()?, "partuuid")?;
        let fs_type = utf8(reader.u16_prefixed()?, "fs_type")?;
        let fs_uuid = utf8(reader.u16_prefixed()?, "fs_uuid")?;
        let fs_label = utf8(reader.u16_prefixed()?, "fs_label")?;
        let swap_len = reader.u32()? as usize;
        if swap_len > SWAP_HEADER_BYTES {
            return Err(Error::corrupt(format!(
                "region {index} declares a {swap_len} byte swap header, limit {SWAP_HEADER_BYTES}"
            )));
        }
        let swap_header = reader.bytes(swap_len)?;
        Ok(Self {
            kind,
            consistency,
            bootable: flags & region_flags::BOOTABLE != 0,
            index,
            start_lba,
            size_bytes,
            type_guid,
            partuuid,
            fs_type,
            fs_uuid,
            fs_label,
            swap_header,
        })
    }

    /// Series of `(start, len)` extents this region covers, in chunk order.
    ///
    /// The chunk size is validated against the superblock by the caller.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] for a zero chunk size.
    pub fn chunks(&self, chunk_size: u64, logical_block_size: u32) -> Result<Vec<(u64, u32)>> {
        if chunk_size == 0 {
            return Err(Error::corrupt("chunk size must not be zero"));
        }
        let start = self.start_lba * u64::from(logical_block_size);
        let mut chunks = Vec::new();
        let mut offset = 0u64;
        while offset < self.size_bytes {
            let len = chunk_size.min(self.size_bytes - offset);
            chunks.push((start + offset, u32::try_from(len).unwrap_or(u32::MAX)));
            offset += chunk_size;
        }
        Ok(chunks)
    }

    /// Number of chunks this region needs.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] for a zero chunk size.
    pub fn chunk_count(&self, chunk_size: u64) -> Result<u64> {
        if chunk_size == 0 {
            return Err(Error::corrupt("chunk size must not be zero"));
        }
        Ok(self.size_bytes.div_ceil(chunk_size))
    }
}

/// The whole-disk manifest header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskHeader {
    /// Disk size in bytes.
    pub disk_size: u64,
    /// Logical sector size.
    pub logical_block_size: u32,
    /// Partition table flavour.
    pub pt_type: PtType,
    /// Disk serial or WWID, when known.
    pub serial_wwid: String,
    /// First MiB of the disk (protective MBR plus primary GPT).
    pub pt_raw: Vec<u8>,
    /// Regions, in disk order.
    pub regions: Vec<RegionRecord>,
}

impl DiskHeader {
    /// Write the header and every region record.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] for an implausible block size or a region
    /// past the disk end, and propagates sink errors.
    pub fn write(&self, out: &mut impl ByteSink) -> Result<()> {
        if self.logical_block_size == 0 || !self.logical_block_size.is_power_of_two() {
            return Err(Error::corrupt(format!(
                "implausible logical block size {}",
                self.logical_block_size
            )));
        }
        if self.pt_raw.len() > PT_RAW_BYTES {
            return Err(Error::corrupt(format!(
                "pt_raw is {} bytes, at most {PT_RAW_BYTES} are allowed",
                self.pt_raw.len()
            )));
        }
        for region in &self.regions {
            let end = region.start_lba * u64::from(self.logical_block_size) + region.size_bytes;
            if end > self.disk_size + u64::from(self.logical_block_size) {
                return Err(Error::corrupt(format!(
                    "region {} ends at {end}, past the disk size {}",
                    region.index, self.disk_size
                )));
            }
            if region.swap_header.len() > SWAP_HEADER_BYTES {
                return Err(Error::corrupt("swap header larger than 4 KiB"));
            }
        }

        wire::put_u16(out, DISK_MANIFEST_VER)?;
        wire::put_u8(out, SECTION_DISK_HEADER)?;
        wire::put_u8(out, 0)?;
        wire::put_u64(out, self.disk_size)?;
        wire::put_u32(out, self.logical_block_size)?;
        wire::put_u8(out, self.pt_type.as_u8())?;
        wire::put_bytes(out, &[0u8; 3])?;
        wire::put_u16_prefixed(out, self.serial_wwid.as_bytes())?;
        wire::put_u32(out, self.pt_raw.len() as u32)?;
        wire::put_bytes(out, &self.pt_raw)?;
        wire::put_u64(out, self.regions.len() as u64)?;
        for region in &self.regions {
            region.write(out)?;
        }
        Ok(())
    }

    /// Read a disk header and its region records.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] for a wrong version or section kind, an
    /// oversized `pt_raw`, an implausible block size, or truncation.
    pub fn read<S: ByteSource>(reader: &mut Reader<S>) -> Result<Self> {
        let ver = reader.u16()?;
        if ver != DISK_MANIFEST_VER {
            return Err(Error::corrupt(format!("disk header version {ver}")));
        }
        let kind = reader.u8()?;
        if kind != SECTION_DISK_HEADER {
            return Err(Error::corrupt(format!(
                "expected a whole-disk header, got section kind {kind}"
            )));
        }
        let _reserved = reader.u8()?;
        let disk_size = reader.u64()?;
        let logical_block_size = reader.u32()?;
        if logical_block_size == 0 || !logical_block_size.is_power_of_two() {
            return Err(Error::corrupt(format!(
                "implausible logical block size {logical_block_size}"
            )));
        }
        let pt_type = PtType::from_u8(reader.u8()?)?;
        let _reserved = reader.array::<3>()?;
        let serial_wwid = utf8(reader.u16_prefixed()?, "serial_wwid")?;
        let pt_raw_len = reader.u32()? as usize;
        if pt_raw_len > PT_RAW_BYTES {
            return Err(Error::corrupt(format!(
                "pt_raw is {pt_raw_len} bytes, at most {PT_RAW_BYTES} are allowed"
            )));
        }
        let pt_raw = reader.bytes(pt_raw_len)?;
        let region_count = reader.u64()?;
        let mut regions = Vec::with_capacity(usize::try_from(region_count).unwrap_or(0).min(1024));
        for _ in 0..region_count {
            regions.push(RegionRecord::read(reader)?);
        }
        Ok(Self {
            disk_size,
            logical_block_size,
            pt_type,
            serial_wwid,
            pt_raw,
            regions,
        })
    }

    /// The regions that carry a block manifest, in disk order.
    pub fn manifest_regions(&self) -> impl Iterator<Item = &RegionRecord> {
        self.regions.iter().filter(|region| region.has_manifest())
    }

    /// Validate the region layout of a whole-disk image.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] when regions overlap, are out of order, or a
    /// leading region exceeds the spec's cap.
    pub fn validate(&self) -> Result<()> {
        let mut previous_end = 0u64;
        for region in &self.regions {
            if region.kind == RegionKind::Leading && region.size_bytes > MAX_LEADING_BYTES {
                return Err(Error::corrupt(format!(
                    "leading region is {} bytes, cap is {MAX_LEADING_BYTES}",
                    region.size_bytes
                )));
            }
            let start = region.start_lba * u64::from(self.logical_block_size);
            if start < previous_end {
                return Err(Error::corrupt(format!(
                    "region {} starts at {start}, before the previous region ends at {previous_end}",
                    region.index
                )));
            }
            previous_end = start + region.size_bytes;
        }
        Ok(())
    }

    /// Manifest header that a region's block manifest must carry.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] for a zero chunk size.
    pub fn region_manifest_header(
        &self,
        region: &RegionRecord,
        chunk_size: u32,
    ) -> Result<BlockManifestHeader> {
        let chunk_count = region.chunk_count(u64::from(chunk_size))?;
        Ok(BlockManifestHeader {
            chunk_size,
            chunk_count,
            entry_count: chunk_count,
            used_extent_count: 1,
            used_bytes: region.size_bytes,
            fs_type: region.fs_type.clone(),
            fs_uuid: region.fs_uuid.clone(),
            label: region.fs_label.clone(),
        })
    }
}

fn utf8(bytes: Vec<u8>, what: &str) -> Result<String> {
    String::from_utf8(bytes).map_err(|_| Error::corrupt(format!("{what} is not valid UTF-8")))
}

/// `true` when a manifest header belongs to a region of `chunk_count` chunks.
#[must_use]
pub fn manifest_matches_region(header: &BlockManifestHeader, chunk_count: u64) -> bool {
    header.chunk_count == chunk_count && header.entry_count <= header.chunk_count
}

#[cfg(test)]
mod tests {
    use super::{
        DiskHeader, PT_RAW_BYTES, PtType, RegionKind, RegionRecord, SECTION_DISK_HEADER,
        SWAP_HEADER_BYTES, region_flags,
    };
    use crate::wire::Reader;
    use lr_core::Consistency;
    use std::io::Cursor;

    fn sample() -> DiskHeader {
        DiskHeader {
            disk_size: 512 * 1024 * 1024,
            logical_block_size: 512,
            pt_type: PtType::Gpt,
            serial_wwid: "naa.5000c5001234".to_owned(),
            pt_raw: vec![0x5a; 4096],
            regions: vec![
                RegionRecord {
                    kind: RegionKind::Leading,
                    consistency: Consistency::Offline,
                    bootable: false,
                    index: 0,
                    start_lba: 0,
                    size_bytes: 1024 * 1024,
                    type_guid: String::new(),
                    partuuid: String::new(),
                    fs_type: String::new(),
                    fs_uuid: String::new(),
                    fs_label: String::new(),
                    swap_header: Vec::new(),
                },
                RegionRecord {
                    kind: RegionKind::PartitionFs,
                    consistency: Consistency::Offline,
                    bootable: true,
                    index: 1,
                    start_lba: 2048,
                    size_bytes: 64 * 1024 * 1024,
                    type_guid: "C12A7328-F81F-11D2-BA4B-00A0C93EC93B".to_owned(),
                    partuuid: "11111111-2222-3333-4444-555555555555".to_owned(),
                    fs_type: "ext4".to_owned(),
                    fs_uuid: "aaaa".to_owned(),
                    fs_label: "ROOT".to_owned(),
                    swap_header: Vec::new(),
                },
                RegionRecord {
                    kind: RegionKind::Swap,
                    consistency: Consistency::Offline,
                    bootable: false,
                    index: 2,
                    start_lba: 133120,
                    size_bytes: 16 * 1024 * 1024,
                    type_guid: String::new(),
                    partuuid: String::new(),
                    fs_type: "swap".to_owned(),
                    fs_uuid: "bbbb".to_owned(),
                    fs_label: "SWAP".to_owned(),
                    swap_header: vec![0x11; SWAP_HEADER_BYTES],
                },
            ],
        }
    }

    #[test]
    fn a_disk_header_round_trips() {
        let header = sample();
        let mut bytes = Vec::new();
        header.write(&mut bytes).expect("write");
        assert_eq!(bytes[0..2], 1u16.to_le_bytes());
        assert_eq!(bytes[2], SECTION_DISK_HEADER);

        let mut reader = Reader::new(Cursor::new(bytes));
        let decoded = DiskHeader::read(&mut reader).expect("read");
        assert_eq!(decoded, header);
        decoded.validate().expect("validate");
    }

    #[test]
    fn region_flags_follow_the_kind() {
        let header = sample();
        for region in &header.regions {
            assert_eq!(
                region.flags() & region_flags::HAS_MANIFEST != 0,
                region.has_manifest()
            );
        }
        assert!(!header.regions[2].has_manifest(), "swap has no manifest");
        assert_eq!(header.manifest_regions().count(), 2);
    }

    #[test]
    fn chunks_are_positional_within_the_region() {
        let region = RegionRecord::new(RegionKind::PartitionFs, 1, 2048, 3 * 4096);
        let chunks = region.chunks(4096, 512).expect("chunks");
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0], (2048 * 512, 4096));
        assert_eq!(chunks[2], (2048 * 512 + 8192, 4096));
        assert_eq!(region.chunk_count(4096).expect("count"), 3);

        let short = RegionRecord::new(RegionKind::PartitionRaw, 2, 0, 4096 + 100);
        let chunks = short.chunks(4096, 512).expect("chunks");
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[1].1, 100, "the last chunk is short");
    }

    #[test]
    fn a_swap_header_larger_than_4k_is_rejected() {
        let mut header = sample();
        header.regions[2].swap_header = vec![0; SWAP_HEADER_BYTES + 1];
        let mut bytes = Vec::new();
        assert!(header.write(&mut bytes).is_err());
    }

    #[test]
    fn an_oversized_pt_raw_is_rejected() {
        let mut header = sample();
        header.pt_raw = vec![0; PT_RAW_BYTES + 1];
        let mut bytes = Vec::new();
        assert!(header.write(&mut bytes).is_err());
    }

    #[test]
    fn overlapping_regions_are_rejected() {
        let mut header = sample();
        header.regions[2].start_lba = 2048; // inside region 1
        assert!(header.validate().is_err());
    }

    #[test]
    fn an_oversized_leading_region_is_rejected() {
        let mut header = sample();
        header.regions[0].size_bytes = super::MAX_LEADING_BYTES + 1;
        assert!(header.validate().is_err());
    }

    #[test]
    fn a_region_past_the_disk_end_is_rejected_on_write() {
        let mut header = sample();
        header.regions[2].size_bytes = header.disk_size;
        let mut bytes = Vec::new();
        assert!(header.write(&mut bytes).is_err());
    }

    #[test]
    fn a_region_record_version_mismatch_is_rejected() {
        let header = sample();
        let mut bytes = Vec::new();
        header.write(&mut bytes).expect("write");
        // Corrupt the first region record's version (header length varies, so
        // rebuild with a modified version instead).
        let mut bad = bytes.clone();
        let marker = 1u16.to_le_bytes();
        let first = bad
            .windows(2)
            .position(|w| w == marker)
            .expect("version present");
        bad[first] = 9;
        let mut reader = Reader::new(Cursor::new(bad));
        assert!(DiskHeader::read(&mut reader).is_err());
    }
}
