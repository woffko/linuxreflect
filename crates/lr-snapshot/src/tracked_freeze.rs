//! The tracked-freeze provider (spec v2.2 §E.7, Slice 18 phase 2).
//!
//! A live, write-tracked, converging copy of a mounted ext4 filesystem that
//! sits directly on a partition or disk, ended by one short freeze during
//! which only the remaining dirty chunks are read, into memory. The engine
//! drives the passes and the final read through [`TrackedCopy`]; this module
//! owns the tracking, the freezes, the budgets and the integrity checks.
//!
//! Phase 2 covers one non-root filesystem and full images, and is selected
//! only by an explicit `--snapshot tracked-freeze`. The running root and
//! whole disks follow in phase 3 (`docs/live-backup-plan.md`).

use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use lr_core::{Consistency, Error, Result, SnapshotOpts, SourceLayout, Support};

use crate::freeze::{Deadman, FreezeLog, frozen_filesystem_refusal};
use crate::probe::is_running_root;
use crate::tracking::{self, DevNumber, DirtyMap, TrackedRegion, Tracker};
use crate::{BlockSnapshot, BlockSnapshotProvider};

/// Provider identifier.
pub const ID: &str = "tracked-freeze";
/// Default limit on the final freeze (spec §E.7 `freeze_max`).
pub const DEFAULT_FREEZE_MAX: Duration = Duration::from_secs(3);
/// The hard cap on the final freeze, whatever is configured.
pub const HARD_FREEZE_MAX: Duration = Duration::from_secs(30);
/// Default limit on the bytes read under the final freeze (`final_max`).
pub const DEFAULT_FINAL_MAX_BYTES: u64 = 256 << 20;
/// Default number of passes before the copy gives up (`max_passes`).
pub const DEFAULT_MAX_PASSES: u32 = 10;
/// Default per-CPU ring buffer of the trace instance.
pub const DEFAULT_BUFFER_KB: u32 = 16 << 10;
/// Tracking granularity; engine chunks are multiples of it.
pub const TRACK_CHUNK_BYTES: u64 = 64 << 10;

const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);
const TMPFS_MAGIC: i64 = 0x0102_1994;
const RUNTIME_DIR: &str = "/run/linuxreflect";

static PROVIDER: TrackedFreezeProvider = TrackedFreezeProvider;
static JOB_COUNTER: AtomicU64 = AtomicU64::new(0);

/// The tracked-freeze provider.
#[derive(Debug, Default, Clone, Copy)]
pub struct TrackedFreezeProvider;

/// The shared instance.
#[must_use]
pub fn provider() -> &'static TrackedFreezeProvider {
    &PROVIDER
}

impl BlockSnapshotProvider for TrackedFreezeProvider {
    fn id(&self) -> &'static str {
        ID
    }

    fn supports(&self, src: &SourceLayout, opts: &SnapshotOpts) -> Support {
        match refusal(src, opts) {
            Some(reason) => Support::No(reason),
            None => Support::Yes,
        }
    }

    fn create(&self, src: &SourceLayout, opts: &SnapshotOpts) -> Result<BlockSnapshot> {
        if let Some(reason) = refusal(src, opts) {
            return Err(Error::no_consistent_method([
                format!("tracked-freeze refused: {reason}"),
                "unmount the filesystem for offline consistency".to_owned(),
                "boot rescue media for an offline image".to_owned(),
            ]));
        }
        let tracefs =
            tracking::tracefs_root().ok_or_else(|| Error::unsupported("tracefs is not mounted"))?;
        let mountpoint = mountpoint_of(src)
            .ok_or_else(|| Error::unsupported("tracked-freeze needs a mounted source"))?;

        // The self test writes its own loop image; it must live on a tmpfs,
        // never on a filesystem that could be the source.
        let workdir = Path::new(RUNTIME_DIR);
        std::fs::create_dir_all(workdir).map_err(Error::Io)?;
        let dir = lr_unsafe::open_dir_readonly(workdir).map_err(Error::Io)?;
        if lr_unsafe::filemeta::filesystem_type(&dir).map_err(Error::Io)? != TMPFS_MAGIC {
            return Err(Error::unsupported(format!(
                "{RUNTIME_DIR} is not a tmpfs; the write-tracking self test needs one"
            )));
        }
        drop(dir);
        let self_test = tracking::self_test(&tracefs, workdir)?;
        if !self_test.passed() {
            return Err(Error::TrackingLost {
                reason: format!(
                    "the write-tracking self test failed on this kernel: {self_test:?}"
                ),
            });
        }

        let region = region_of(src)?;
        let start = SourceFacts::read(&src.device, &region)?;
        let name = format!(
            "{}tf-{}-{}",
            tracking::INSTANCE_PREFIX,
            std::process::id(),
            JOB_COUNTER.fetch_add(1, Ordering::SeqCst)
        );
        let tracker = Tracker::start(
            &tracefs,
            &name,
            vec![region],
            TRACK_CHUNK_BYTES,
            DEFAULT_BUFFER_KB,
        )?;
        let pending = tracker.empty_map();
        let log = FreezeLog::default();
        let grace = Duration::from_secs(
            opts.deadman_grace_secs
                .unwrap_or(crate::freeze::DEFAULT_GRACE_SECS),
        );
        let freeze_max = opts
            .freeze_timeout_secs
            .map_or(DEFAULT_FREEZE_MAX, Duration::from_secs)
            .min(HARD_FREEZE_MAX);
        let mut copy = TrackedCopy {
            tracker,
            pending,
            mountpoints: vec![mountpoint],
            source: src.device.clone(),
            region,
            start,
            limits: Limits {
                freeze_max,
                final_max_bytes: DEFAULT_FINAL_MAX_BYTES,
                max_passes: DEFAULT_MAX_PASSES,
                grace,
            },
            engine_chunk_bytes: 0,
            log,
            summary: TrackedSummary::default(),
        };

        // The barrier: a freeze completes every write already submitted, so
        // none that predates tracking can land after the first pass reads.
        let began = Instant::now();
        copy.frozen(|| Ok(()))?;
        copy.summary.barrier_ms = elapsed_ms(began);
        copy.log.flush();
        Ok(BlockSnapshot::new(src.device.clone(), Consistency::Frozen, ()).with_tracked(copy))
    }
}

/// Why this source cannot be copied with tracked-freeze, if it cannot.
fn refusal(src: &SourceLayout, opts: &SnapshotOpts) -> Option<String> {
    if opts.provider.as_deref() != Some(ID) {
        return Some(format!("tracked-freeze is opt-in; pass --snapshot {ID}"));
    }
    if src.is_whole_disk() {
        return Some("whole disks follow in Slice 18 phase 3; image a partition".to_owned());
    }
    if src.fs.as_ref().is_none_or(|facts| facts.fs_type != "ext4") {
        return Some("tracked-freeze copies ext4 filesystems only".to_owned());
    }
    if src
        .lvm
        .as_ref()
        .is_some_and(|facts| facts.is_dm || facts.is_pv)
    {
        return Some("the source is on device-mapper; the LVM provider applies".to_owned());
    }
    let Some(mountpoint) = mountpoint_of(src) else {
        return Some("the source is not mounted; the offline provider applies".to_owned());
    };
    let mount_count = src.mountpoints.len();
    if mount_count > 1 {
        return Some(format!(
            "the filesystem is mounted {mount_count} times; phase 2 copies a single mount"
        ));
    }
    if is_running_root(src) {
        return Some(format!(
            "{} holds the running system; that follows in Slice 18 phase 3",
            mountpoint.display()
        ));
    }
    if let Some(reason) = frozen_filesystem_refusal(&mountpoint, opts) {
        return Some(reason);
    }
    let Some(tracefs) = tracking::tracefs_root() else {
        return Some("tracefs is not mounted".to_owned());
    };
    let format_path = tracefs
        .join("events")
        .join(tracking::TRACEPOINT)
        .join("format");
    match std::fs::read_to_string(&format_path) {
        Ok(format) => tracking::check_format(&format).err(),
        Err(error) => Some(format!(
            "the {} tracepoint is unavailable: {error}",
            tracking::TRACEPOINT
        )),
    }
}

fn mountpoint_of(src: &SourceLayout) -> Option<PathBuf> {
    src.mountpoints.first().cloned()
}

/// The tracked region of a partition (or of a whole device with a
/// filesystem directly on it), from sysfs.
fn region_of(src: &SourceLayout) -> Result<TrackedRegion> {
    let class = lr_core::sysfs::sysfs_root()
        .join("class/block")
        .join(&src.device_facts.name);
    let own = parse_dev(&read_sysfs(&class.join("dev"))?)?;
    let size = read_sysfs(&class.join("size"))?
        .parse::<u64>()
        .map_err(|_| Error::corrupt("sysfs size is not a number"))?;
    if class.join("partition").exists() {
        let real = std::fs::canonicalize(&class).map_err(Error::Io)?;
        let parent = real
            .parent()
            .ok_or_else(|| Error::corrupt("a partition without a parent disk in sysfs"))?;
        let whole = parse_dev(&read_sysfs(&parent.join("dev"))?)?;
        let start = read_sysfs(&class.join("start"))?
            .parse::<u64>()
            .map_err(|_| Error::corrupt("sysfs start is not a number"))?;
        Ok(TrackedRegion {
            whole,
            part: Some(own),
            start_sector: start,
            sectors: size,
        })
    } else {
        Ok(TrackedRegion {
            whole: own,
            part: None,
            start_sector: 0,
            sectors: size,
        })
    }
}

fn read_sysfs(path: &Path) -> Result<String> {
    std::fs::read_to_string(path)
        .map(|text| text.trim().to_owned())
        .map_err(|error| Error::unsupported(format!("{}: {error}", path.display())))
}

fn parse_dev(text: &str) -> Result<DevNumber> {
    let (major, minor) = text
        .split_once(':')
        .ok_or_else(|| Error::corrupt(format!("sysfs dev {text:?} is not major:minor")))?;
    Ok(DevNumber {
        major: major
            .parse()
            .map_err(|_| Error::corrupt("sysfs major is not a number"))?,
        minor: minor
            .parse()
            .map_err(|_| Error::corrupt("sysfs minor is not a number"))?,
    })
}

/// What must not change while the copy runs: the partition's place on the
/// disk and the filesystem's identity and size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SourceFacts {
    start_sector: u64,
    sectors: u64,
    fs_uuid: [u8; 16],
    fs_blocks: u64,
}

impl SourceFacts {
    fn read(device: &Path, region: &TrackedRegion) -> Result<Self> {
        let fd = lr_unsafe::open_o_direct(device, false).map_err(Error::Io)?;
        let mut buf = lr_unsafe::AlignedBuf::new(4096, 4096).map_err(Error::Io)?;
        let read = lr_unsafe::pread_into(&fd, &mut buf, 4096, 0).map_err(Error::Io)?;
        if read < 2048 {
            return Err(Error::corrupt("short read of the ext4 superblock"));
        }
        let sb = &buf.as_slice()[1024..2048];
        let le16 = |at: usize| u16::from_le_bytes([sb[at], sb[at + 1]]);
        let le32 = |at: usize| u32::from_le_bytes([sb[at], sb[at + 1], sb[at + 2], sb[at + 3]]);
        if le16(0x38) != 0xef53 {
            return Err(Error::unsupported("the source has no ext4 superblock"));
        }
        let incompat_64bit = le32(0x60) & 0x80 != 0;
        let high = if incompat_64bit {
            u64::from(le32(0x150))
        } else {
            0
        };
        let mut fs_uuid = [0u8; 16];
        fs_uuid.copy_from_slice(&sb[0x68..0x78]);
        Ok(Self {
            start_sector: region.start_sector,
            sectors: region.sectors,
            fs_uuid,
            fs_blocks: (high << 32) | u64::from(le32(0x04)),
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct Limits {
    freeze_max: Duration,
    final_max_bytes: u64,
    max_passes: u32,
    grace: Duration,
}

/// What a tracked copy did, for the backup report.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TrackedSummary {
    /// Passes over the source, the first full one included.
    pub passes: u32,
    /// Chunks read again after the first pass, the final read included.
    pub recopied_chunks: u64,
    /// Chunks read under the final freeze.
    pub final_chunks: u64,
    /// Length of the final freeze.
    pub final_freeze_ms: u64,
    /// Length of the barrier freeze.
    pub barrier_ms: u64,
}

/// The engine's handle on a tracked copy (see the module documentation).
pub struct TrackedCopy {
    tracker: Tracker,
    /// Dirty chunks (tracking granularity) not yet re-read.
    pending: DirtyMap,
    mountpoints: Vec<PathBuf>,
    source: PathBuf,
    region: TrackedRegion,
    start: SourceFacts,
    limits: Limits,
    engine_chunk_bytes: u64,
    log: FreezeLog,
    summary: TrackedSummary,
}

impl std::fmt::Debug for TrackedCopy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrackedCopy")
            .field("mountpoints", &self.mountpoints)
            .field("summary", &self.summary)
            .finish_non_exhaustive()
    }
}

impl TrackedCopy {
    /// Bind the engine's chunk size: a multiple of [`TRACK_CHUNK_BYTES`].
    pub fn bind(&mut self, chunk_bytes: u64) -> Result<()> {
        if chunk_bytes == 0 || !chunk_bytes.is_multiple_of(TRACK_CHUNK_BYTES) {
            return Err(Error::unsupported(format!(
                "a chunk of {chunk_bytes} bytes is not a multiple of the tracking chunk"
            )));
        }
        self.engine_chunk_bytes = chunk_bytes;
        Ok(())
    }

    /// Engine chunks still pending; the final read reads at least these.
    pub fn pending_count(&self) -> usize {
        self.pending_engine_chunks().len()
    }

    /// The pending dirty chunks, in engine chunks, ascending.
    fn pending_engine_chunks(&self) -> Vec<u64> {
        let ratio = self.engine_chunk_bytes / TRACK_CHUNK_BYTES;
        let mut chunks: Vec<u64> = Vec::new();
        for bits in self.pending.bits() {
            for chunk in bits.iter() {
                let engine = chunk / ratio;
                if chunks.last() != Some(&engine) {
                    chunks.push(engine);
                }
            }
        }
        chunks
    }

    /// After a pass that read `bytes` in `elapsed`: gather what was written
    /// meanwhile. `Ok(None)` means the rest fits the final freeze; otherwise
    /// the engine must read the returned chunks again and call this again.
    pub fn next_pass(&mut self, bytes: u64, elapsed: Duration) -> Result<Option<Vec<u64>>> {
        debug_assert!(self.engine_chunk_bytes != 0, "bind() first");
        self.tracker.drain(DRAIN_TIMEOUT)?;
        self.tracker.take_into(&mut self.pending);
        self.summary.passes += 1;
        let chunks = self.pending_engine_chunks();
        let dirty_bytes = chunks.len() as u64 * self.engine_chunk_bytes;
        // Read time for the rest at the rate the last pass reached; half the
        // freeze budget leaves room for the freeze itself and new writes.
        let rate = bytes as f64 / elapsed.as_secs_f64().max(1e-3);
        let estimate = Duration::from_secs_f64(dirty_bytes as f64 / rate.max(1.0));
        if dirty_bytes <= self.limits.final_max_bytes && estimate <= self.limits.freeze_max / 2 {
            return Ok(None);
        }
        if self.summary.passes >= self.limits.max_passes {
            return Err(Error::NoConvergence {
                dirty_bytes,
                passes: self.summary.passes,
            });
        }
        self.summary.recopied_chunks += chunks.len() as u64;
        Ok(Some(chunks))
    }

    /// The final read: freeze every tracked filesystem, gather the last
    /// writes, let `read` read the given engine chunks (into memory, nothing
    /// may be written), and thaw. A freeze longer than `freeze_max` fails the
    /// copy after the thaw.
    pub fn final_read<T>(&mut self, read: impl FnOnce(&[u64]) -> Result<T>) -> Result<T> {
        debug_assert!(self.engine_chunk_bytes != 0, "bind() first");
        let final_max = self.limits.final_max_bytes;
        let chunk_bytes = self.engine_chunk_bytes;
        let mut chunks_read = 0u64;
        let began = Instant::now();
        let outcome = self.frozen_with(|copy| {
            copy.tracker.drain(DRAIN_TIMEOUT)?;
            let mut late = copy.tracker.empty_map();
            copy.tracker.take_into(&mut late);
            copy.pending.union_with(&late);
            let chunks = copy.pending_engine_chunks();
            let dirty_bytes = chunks.len() as u64 * chunk_bytes;
            if dirty_bytes > final_max {
                return Err(Error::NoConvergence {
                    dirty_bytes,
                    passes: copy.summary.passes,
                });
            }
            chunks_read = chunks.len() as u64;
            read(&chunks)
        });
        let frozen_for = began.elapsed();
        self.summary.final_freeze_ms = u64::try_from(frozen_for.as_millis()).unwrap_or(u64::MAX);
        self.summary.final_chunks = chunks_read;
        self.summary.recopied_chunks += chunks_read;
        self.log.flush();
        let value = outcome?;
        if frozen_for > self.limits.freeze_max {
            return Err(Error::FreezeTimeout);
        }
        Ok(value)
    }

    /// After the copy: no event may have been lost, and the source must have
    /// kept its shape. Returns what the copy did.
    pub fn finish(&mut self) -> Result<TrackedSummary> {
        let losses = self.tracker.integrity()?;
        if !losses.is_clean() {
            return Err(Error::TrackingLost {
                reason: format!("{losses:?}"),
            });
        }
        let region = region_of_device(&self.source, &self.region)?;
        let now = SourceFacts::read(&self.source, &region)?;
        if now != self.start {
            return Err(Error::SourceChanged {
                what: format!("{:?} became {:?}", self.start, now),
            });
        }
        Ok(self.summary)
    }

    /// Freeze every tracked filesystem, run `inside`, thaw (always), with a
    /// deadman armed for each. Nothing is logged while frozen.
    fn frozen(&mut self, inside: impl FnOnce() -> Result<()>) -> Result<()> {
        self.frozen_with(|_| inside())
    }

    fn frozen_with<T>(&mut self, inside: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let after = HARD_FREEZE_MAX.max(self.limits.freeze_max) + self.limits.grace;
        let mut set = FrozenSet::default();
        for mountpoint in &self.mountpoints {
            let deadman = Deadman::arm(mountpoint, after, &self.log)?;
            let dir = match lr_unsafe::open_dir_readonly(mountpoint) {
                Ok(dir) => dir,
                Err(error) => {
                    deadman.disarm();
                    return Err(Error::Io(error));
                }
            };
            // FIFREEZE blocks writers first and then writes back every dirty
            // page; with much dirty data that alone can stall the system for
            // seconds (29 s seen in phase 0). Write back without blocking first.
            if let Err(error) = lr_unsafe::syncfs(&dir) {
                deadman.disarm();
                return Err(Error::Io(error));
            }
            if let Err(error) = lr_unsafe::freeze_fs(&dir) {
                deadman.disarm();
                return Err(Error::Io(std::io::Error::new(
                    error.kind(),
                    format!("FIFREEZE on {}: {error}", mountpoint.display()),
                )));
            }
            set.frozen.push((dir, deadman));
        }
        let outcome = inside(self);
        set.thaw()?;
        outcome
    }
}

/// The partition's current place on the disk, from sysfs.
fn region_of_device(device: &Path, before: &TrackedRegion) -> Result<TrackedRegion> {
    let name = lr_core::sysfs::device_name(device).map_err(Error::Io)?;
    let class = lr_core::sysfs::sysfs_root().join("class/block").join(name);
    let sectors = read_sysfs(&class.join("size"))?
        .parse()
        .map_err(|_| Error::corrupt("sysfs size is not a number"))?;
    let start_sector = if before.part.is_some() {
        read_sysfs(&class.join("start"))?
            .parse()
            .map_err(|_| Error::corrupt("sysfs start is not a number"))?
    } else {
        0
    };
    Ok(TrackedRegion {
        start_sector,
        sectors,
        ..*before
    })
}

/// Filesystems frozen together, thawed in reverse order exactly once.
#[derive(Default)]
struct FrozenSet {
    frozen: Vec<(OwnedFd, Deadman)>,
}

impl FrozenSet {
    fn thaw(&mut self) -> Result<()> {
        let mut first_error = None;
        while let Some((dir, deadman)) = self.frozen.pop() {
            match lr_unsafe::thaw_fs(&dir) {
                // Thawed by us: stand the deadman down.
                Ok(()) => deadman.disarm(),
                // Left armed: the deadman thaws it.
                Err(error) => {
                    first_error.get_or_insert(Error::Io(error));
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

impl Drop for FrozenSet {
    fn drop(&mut self) {
        let _ = self.thaw();
    }
}

fn elapsed_ms(since: Instant) -> u64 {
    u64::try_from(since.elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_layout;

    fn mounted_ext4() -> SourceLayout {
        let mut layout = test_layout::offline("/dev/sdq1");
        layout.mountpoints = vec![PathBuf::from("/srv/data")];
        layout
    }

    fn forced() -> SnapshotOpts {
        SnapshotOpts {
            provider: Some(ID.to_owned()),
            destination_remote: true,
            ..SnapshotOpts::default()
        }
    }

    #[test]
    fn it_is_opt_in() {
        let reason = refusal(&mounted_ext4(), &SnapshotOpts::default()).expect("refused");
        assert!(reason.contains("opt-in"), "{reason}");
        let auto = SnapshotOpts {
            allow_freeze: true,
            ..SnapshotOpts::default()
        };
        assert!(refusal(&mounted_ext4(), &auto).is_some());
    }

    #[test]
    fn other_filesystems_and_the_running_root_are_refused() {
        let mut xfs = mounted_ext4();
        if let Some(fs) = xfs.fs.as_mut() {
            fs.fs_type = "xfs".to_owned();
        }
        assert!(refusal(&xfs, &forced()).expect("xfs").contains("ext4"));
        let mut root = mounted_ext4();
        root.mountpoints = vec![PathBuf::from("/")];
        assert!(refusal(&root, &forced()).expect("root").contains("phase 3"));
        let unmounted = test_layout::offline("/dev/sdq1");
        assert!(refusal(&unmounted, &forced()).is_some());
    }

    #[test]
    fn engine_chunks_must_be_multiples_of_the_tracking_chunk() {
        // Exercised through the arithmetic only: binding needs no tracker.
        assert!(TRACK_CHUNK_BYTES.is_power_of_two());
        assert!((256u64 << 10).is_multiple_of(TRACK_CHUNK_BYTES));
    }

    #[test]
    fn device_numbers_are_parsed_from_sysfs() {
        assert_eq!(
            parse_dev("259:3").expect("dev"),
            DevNumber {
                major: 259,
                minor: 3
            }
        );
        assert!(parse_dev("259").is_err());
    }
}
