//! The extras stream (spec §G.6 stream 3, `docs/format-lrimg-v1.md` §7).
//!
//! Extras carry everything that is not chunk data: the chain member list that
//! manifests index into, partition-table dumps, `fstab`, Btrfs layout and image
//! metadata. Unknown kinds are skipped by length, which is what makes adding a
//! new one a compatible change (spec §G.8).

use lr_core::{Error, Id, ImageId, Result};

use crate::wire::{self, ByteSink, ByteSource, Reader};

/// Extras record version.
pub const EXTRAS_VER: u16 = 1;

/// Kind: chain member list.
pub const EXTRAS_CHAIN_MEMBERS: u8 = 1;
/// Kind: partition-table dump (or whole-disk image extras).
pub const EXTRAS_PARTITION_TABLE: u8 = 2;
/// Kind: `/etc/fstab` for the backed-up system.
pub const EXTRAS_FSTAB: u8 = 3;
/// Kind: Btrfs filesystem layout.
pub const EXTRAS_BTRFS_LAYOUT: u8 = 4;
/// Kind: image metadata (source label, tool version, ...).
pub const EXTRAS_IMAGE_METADATA: u8 = 5;
/// Kind: content-defined chunking parameters (stream/file images).
pub const EXTRAS_CDC_PARAMS: u8 = 6;

/// Largest accepted extras payload, bounding allocations on corrupt input.
pub const MAX_EXTRAS_PAYLOAD: usize = 16 * 1024 * 1024;

/// One entry of the chain member list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainMember {
    /// Index referenced by manifest entries.
    pub index: u8,
    /// Image UUID of that member.
    pub image_uuid: ImageId,
}

/// Encoded length of one chain member entry.
pub const CHAIN_MEMBER_LEN: usize = 19;

/// Content-defined chunking parameters (spec §G extras kind 6).
///
/// Recorded so a restore or a future chain can reproduce the boundaries and
/// explain the chunk sizes of an image without guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CdcParams {
    /// Minimum chunk size in bytes.
    pub min_size: u32,
    /// Target (average) chunk size in bytes.
    pub avg_size: u32,
    /// Maximum chunk size in bytes.
    pub max_size: u32,
    /// Normalization level, 1 for `fastcdc` level 1.
    pub normalization: u8,
}

/// Wire length of a [`CdcParams`] payload.
pub const CDC_PARAMS_LEN: usize = 13;

/// Write the CDC parameters record.
///
/// # Errors
/// Propagates sink errors.
pub fn write_cdc_params(out: &mut impl ByteSink, params: CdcParams) -> Result<()> {
    let mut payload = Vec::with_capacity(CDC_PARAMS_LEN);
    wire::put_u32(&mut payload, params.min_size)?;
    wire::put_u32(&mut payload, params.avg_size)?;
    wire::put_u32(&mut payload, params.max_size)?;
    wire::put_u8(&mut payload, params.normalization)?;
    write_record(out, EXTRAS_CDC_PARAMS, &payload)
}

/// Parse a [`CdcParams`] payload.
///
/// # Errors
/// Returns [`Error::Corrupt`] when the payload length is wrong.
pub fn read_cdc_params(payload: &[u8]) -> Result<CdcParams> {
    if payload.len() != CDC_PARAMS_LEN {
        return Err(Error::corrupt(format!(
            "cdc params payload of {} bytes, expected {CDC_PARAMS_LEN}",
            payload.len()
        )));
    }
    Ok(CdcParams {
        min_size: wire::slice_u32(&payload[0..])?,
        avg_size: wire::slice_u32(&payload[4..])?,
        max_size: wire::slice_u32(&payload[8..])?,
        normalization: payload[12],
    })
}

/// Write an extras record of any kind.
///
/// # Errors
/// Returns [`Error::Unsupported`] for an oversized payload and propagates sink
/// errors.
pub fn write_record(out: &mut impl ByteSink, kind: u8, payload: &[u8]) -> Result<()> {
    let len = u32::try_from(payload.len())
        .map_err(|_| Error::unsupported("extras payload larger than 4 GiB"))?;
    wire::put_u16(out, EXTRAS_VER)?;
    wire::put_u8(out, kind)?;
    wire::put_u8(out, 0)?;
    wire::put_u32(out, len)?;
    out.write_bytes(payload)
}

/// Read one extras record.
///
/// # Errors
/// Returns [`Error::Corrupt`] for a wrong version or an oversized payload, and
/// at end of input.
pub fn read_record<S: ByteSource>(reader: &mut Reader<S>) -> Result<(u8, Vec<u8>)> {
    let ver = reader.u16()?;
    if ver != EXTRAS_VER {
        return Err(Error::corrupt(format!("extras version {ver}")));
    }
    let kind = reader.u8()?;
    let _reserved = reader.u8()?;
    let len = reader.u32()? as usize;
    if len > MAX_EXTRAS_PAYLOAD {
        return Err(Error::corrupt(format!(
            "extras payload of {len} bytes exceeds {MAX_EXTRAS_PAYLOAD}"
        )));
    }
    Ok((kind, reader.bytes(len)?))
}

/// Serialize the chain member list.
///
/// # Errors
/// Propagates sink errors.
pub fn write_chain_members(out: &mut impl ByteSink, members: &[ChainMember]) -> Result<()> {
    let mut payload = Vec::with_capacity(members.len() * CHAIN_MEMBER_LEN);
    for member in members {
        wire::put_u8(&mut payload, member.index)?;
        wire::put_u16(&mut payload, 0)?;
        wire::put_id(&mut payload, member.image_uuid.inner())?;
    }
    write_record(out, EXTRAS_CHAIN_MEMBERS, &payload)
}

/// Parse the chain member list.
///
/// # Errors
/// Returns [`Error::Corrupt`] when the payload length is not a multiple of
/// [`CHAIN_MEMBER_LEN`].
pub fn read_chain_members(payload: &[u8]) -> Result<Vec<ChainMember>> {
    if !payload.len().is_multiple_of(CHAIN_MEMBER_LEN) {
        return Err(Error::corrupt(
            "chain member list length is not a multiple of 19",
        ));
    }
    let mut members = Vec::with_capacity(payload.len() / CHAIN_MEMBER_LEN);
    for chunk in payload.chunks_exact(CHAIN_MEMBER_LEN) {
        members.push(ChainMember {
            index: chunk[0],
            image_uuid: ImageId::new(Id::from_bytes(
                chunk[3..19]
                    .try_into()
                    .map_err(|_| Error::corrupt("chain member uuid"))?,
            )),
        });
    }
    Ok(members)
}

#[cfg(test)]
mod tests {
    use super::{
        CdcParams, ChainMember, EXTRAS_CDC_PARAMS, EXTRAS_CHAIN_MEMBERS, EXTRAS_FSTAB,
        read_cdc_params, read_chain_members, read_record, write_cdc_params, write_chain_members,
        write_record,
    };
    use crate::wire::Reader;
    use lr_core::{Id, ImageId};
    use std::io::Cursor;

    #[test]
    fn records_round_trip_and_unknown_kinds_are_skippable() {
        let mut bytes = Vec::new();
        write_record(&mut bytes, EXTRAS_FSTAB, b"/dev/sda1 / ext4 defaults 0 1\n").expect("write");
        write_record(&mut bytes, 200, b"a future kind").expect("write");

        let mut reader = Reader::new(Cursor::new(bytes));
        let (kind, payload) = read_record(&mut reader).expect("read");
        assert_eq!(kind, EXTRAS_FSTAB);
        assert_eq!(payload, b"/dev/sda1 / ext4 defaults 0 1\n");
        let (kind, payload) = read_record(&mut reader).expect("read");
        assert_eq!(kind, 200, "unknown kinds are returned, not rejected");
        assert_eq!(payload, b"a future kind");
    }

    #[test]
    fn chain_member_lists_round_trip() {
        let members = vec![
            ChainMember {
                index: 0,
                image_uuid: ImageId::new(Id::from_bytes([0x01; 16])),
            },
            ChainMember {
                index: 1,
                image_uuid: ImageId::new(Id::from_bytes([0x02; 16])),
            },
        ];
        let mut bytes = Vec::new();
        write_chain_members(&mut bytes, &members).expect("write");
        let mut reader = Reader::new(Cursor::new(bytes));
        let (kind, payload) = read_record(&mut reader).expect("read");
        assert_eq!(kind, EXTRAS_CHAIN_MEMBERS);
        assert_eq!(read_chain_members(&payload).expect("parse"), members);
    }

    #[test]
    fn cdc_params_round_trip() {
        let params = CdcParams {
            min_size: 16 * 1024,
            avg_size: 64 * 1024,
            max_size: 256 * 1024,
            normalization: 1,
        };
        let mut bytes = Vec::new();
        write_cdc_params(&mut bytes, params).expect("write");
        let mut reader = Reader::new(Cursor::new(bytes));
        let (kind, payload) = read_record(&mut reader).expect("read");
        assert_eq!(kind, EXTRAS_CDC_PARAMS);
        assert_eq!(read_cdc_params(&payload).expect("parse"), params);
        assert!(read_cdc_params(&payload[..12]).is_err());
    }

    #[test]
    fn a_truncated_member_list_is_rejected() {
        assert!(read_chain_members(&[0u8; 5]).is_err());
        assert!(read_chain_members(&[0u8; 19]).is_ok());
    }
}
