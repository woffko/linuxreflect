//! The `.lrimg` on-disk format (spec §G, Slice S4).
//!
//! The normative byte layout lives in `docs/format-lrimg-v1.md`; every module
//! here implements one section of it. Reading is always bounds checked and
//! never trusts a length or offset before `sb_mac`/`footer_mac` have been
//! verified by [`reader::ImageReader::authenticate`].
//!
//! Typical use:
//!
//! ```no_run
//! # use lr_format::{ImageWriter, Superblock};
//! # fn main() -> lr_core::Result<()> {
//! // let writer = ImageWriter::create(file, &superblock, Some(&meta_key))?;
//! // let mut stream = writer.page_stream(StreamId::Manifest, kind, meta_key);
//! // header.write(&mut stream)?;
//! // stream.finish()?;
//! // let (file, footer) = writer.finish(&meta_key, Some(&meta_key), kind)?;
//! # Ok(())
//! # }
//! ```
#![forbid(unsafe_code)]

pub mod chunk;
pub mod compress;
pub mod disk;
pub mod extras;
pub mod file_manifest;
pub mod footer;
pub mod manifest;
pub mod reader;
pub mod sb;
pub mod stream;
pub mod verify;
pub mod wire;
pub mod writer;

pub use chunk::{
    CHUNK_FLAG_ENCRYPTED, CHUNK_FLAG_ZSTD, CHUNK_HEADER_LEN, CHUNK_MAGIC, CHUNK_OVERHEAD_ENCRYPTED,
    CHUNK_OVERHEAD_PLAIN, ChunkHeader, ChunkOptions, ChunkRecord, chunk_ad, decode_header,
    open_chunk, seal_chunk,
};
pub use compress::{
    DEFAULT_LEVEL, MAX_LEVEL as MAX_ZSTD_LEVEL, MIN_LEVEL as MIN_ZSTD_LEVEL, compress,
    compress_if_smaller, decompress,
};
pub use disk::{
    DISK_MANIFEST_VER, DiskHeader, MAX_LEADING_BYTES, PT_RAW_BYTES, PtType, RegionKind,
    RegionRecord, SECTION_DISK_HEADER, SWAP_HEADER_BYTES, region_flags,
};
pub use extras::{
    CDC_PARAMS_LEN, CdcParams, ChainMember, EXTRAS_BTRFS_LAYOUT, EXTRAS_CDC_PARAMS,
    EXTRAS_CHAIN_MEMBERS, EXTRAS_FSTAB, EXTRAS_IMAGE_METADATA, EXTRAS_PARTITION_TABLE,
    read_cdc_params, read_chain_members, read_record as read_extras_record, write_cdc_params,
    write_chain_members, write_record as write_extras_record,
};
pub use file_manifest::{
    FILE_KIND_DIRECTORY, FILE_KIND_HARDLINK, FILE_KIND_REGULAR, FILE_KIND_SPECIAL,
    FILE_KIND_SYMLINK, FILE_REFS_PER_SECTION, FileEntry, FileRecord, Xattr,
    read_entry_with_continuations, read_holes, read_manifest, write_continuation, write_holes,
    write_record,
};
pub use footer::{
    FLAG_PAGE_TABLE_IN_STREAM4, FOOTER_MAGIC, FOOTER_SIZE, Footer, INLINE_PAGE_TABLE_SLOTS,
    PAGE_ENTRY_SIZE, PageEntry,
};
pub use lr_crypto::page::StreamId;
pub use manifest::{
    BlockEntry, BlockManifestHeader, ChunkState, DELTA_ENTRY_LEN, DeltaEntry, ENTRY_LEN,
    MANIFEST_VER, SECTION_BLOCK_DELTA, SECTION_BLOCK_FULL, SECTION_FILE_CONTINUATION,
    SECTION_FILE_ENTRY, SECTION_STREAM_SUBVOL, STATE_BAD_SECTOR, STATE_STORED, STATE_UNUSED,
    STATE_ZERO, StreamSection, apply_delta,
};
pub use reader::{ChunkReader, ImageReader, MAX_PAGE_TABLE_BYTES};
pub use sb::{
    FORMAT_MAJOR, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE, MIN_READER, SB_MAGIC, SB_SIZE, Superblock, flags,
};
pub use stream::{DEFAULT_PAGE_LEN, PageSink, PageStream, PageStreamReader};
pub use verify::{VerifyReport, verify_structure};
pub use writer::{ChunkRef, ImageWriter, WriterKeys, parse_table, serialize_table};
