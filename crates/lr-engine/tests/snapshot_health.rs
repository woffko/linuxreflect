//! A snapshot whose health expires while its last chunk is read never
//! yields an image that claims the snapshot's consistency (R29).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use lr_core::{Consistency, Error, Result, SnapshotOpts, SourceLayout, Support};
use lr_engine::backup::{BackupRequest, Compression, backup_block_with};
use lr_engine::keys::Encryption;
use lr_snapshot::{BlockSnapshot, BlockSnapshotProvider, SnapshotHealth};

const CHUNK: u32 = 256 * 1024;
const CHUNKS: u64 = 4;

/// Healthy for `remaining` more checks, then timed out, like a freeze whose
/// deadline passes while the last read is still running.
struct Countdown(AtomicU64);

impl SnapshotHealth for Countdown {
    fn check(&self) -> Result<()> {
        let remaining = self.0.load(Ordering::SeqCst);
        if remaining == 0 {
            return Err(Error::FreezeTimeout);
        }
        self.0.store(remaining - 1, Ordering::SeqCst);
        Ok(())
    }
}

/// A provider whose snapshot is the source itself, "frozen", with a health
/// that expires after as many checks as the backup has chunks to read.
struct Expiring;

impl BlockSnapshotProvider for Expiring {
    fn id(&self) -> &'static str {
        "expiring"
    }

    fn supports(&self, _src: &SourceLayout, _opts: &SnapshotOpts) -> Support {
        Support::Yes
    }

    fn create(&self, src: &SourceLayout, _opts: &SnapshotOpts) -> Result<BlockSnapshot> {
        Ok(
            BlockSnapshot::new(src.device.clone(), Consistency::Frozen, ())
                .with_health(Arc::new(Countdown(AtomicU64::new(CHUNKS)))),
        )
    }
}

#[test]
fn a_health_deadline_passed_during_the_last_read_fails_the_backup() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("source.img");
    // Data in every chunk, and no filesystem, so every chunk is read.
    let bytes: Vec<u8> = (0..CHUNKS * u64::from(CHUNK))
        .map(|index| (index % 251) as u8 | 1)
        .collect();
    std::fs::write(&source, bytes).expect("source");
    let dest = dir.path().join("backups");
    let mut request =
        BackupRequest::new(&source, &dest, "health", Encryption::NoEncrypt).expect("request");
    request.chunk_size = CHUNK;
    request.compression = Compression::None;

    let outcome = backup_block_with(&request, &Expiring);
    assert!(
        matches!(outcome, Err(Error::FreezeTimeout)),
        "an image read past the snapshot's deadline was accepted: {outcome:?}"
    );
}
