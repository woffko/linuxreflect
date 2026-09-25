//! Backup, restore and verify orchestration (spec §D, §H, Slices S6–S9).
//!
//! Slice S6 provides full block-mode backups and restores: a used-block map
//! from `lr-fsmap`, aligned reads from `lr-blocksource`, `.lrimg` writing from
//! `lr-format`, a destination from `lr-store`, and the restore token and target
//! checks from spec §H. Slice S7 adds whole-disk images, Slice S8 adds the
//! LVM/freeze/live-none providers, the Btrfs tree provider and Stream mode.
//! Chains, scan-and-diff and the catalog arrive with Slice S9.
#![forbid(unsafe_code)]

pub mod backup;
pub mod catalog;
pub mod chain;
pub mod file;
pub mod inspect;
pub mod keys;
pub mod keystore;
pub mod options;
pub mod progress;
pub mod restore;
pub mod retention;
pub mod schedule;
pub mod stream;
pub mod target;
pub mod tree;
pub mod verify;
pub mod whole_disk;

pub use backup::{
    BackupReport, BackupRequest, BadSectorPolicy, Compression, ImageReport, backup_block_full,
    backup_image,
};
pub use file::{FileBackupOptions, FileReport, FileRestoreReport, FileRestoreRequest};
pub use keys::Encryption;
pub use keystore::{
    PASSPHRASE_FILE_ENV, Passphrase, load_passphrase_file, passphrase_file_path, resolve_passphrase,
};
pub use restore::{
    ApplyRequest, DEFAULT_TTL, PrepareRequest, RestorePlan, RestoreReport, RestoreToken,
    TargetFacts, apply_restore, prepare_restore,
};
pub use whole_disk::{RegionReport, WholeDiskReport, backup_whole_disk};
