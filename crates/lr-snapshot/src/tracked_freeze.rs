//! The tracked-freeze provider (spec v2.2 §E.7, Slice 18).
//!
//! A live, write-tracked, converging copy of ext4 filesystems that sit
//! directly on a partition or disk, the running root included, ended by one
//! short freeze during which only the remaining dirty chunks are read, into
//! memory. The engine drives the passes and the final read through
//! [`TrackedCopy`]; this module owns the tracking, the freezes, the budgets
//! and the integrity checks.
//!
//! A copy has one or more regions of one disk. A mounted ext4 region is
//! frozen; every other region (a vfat ESP, a BIOS boot partition, the disk's
//! leading area, an unmounted partition) cannot be frozen and is held by the
//! quiet-window rule: it must not be written from its final read until the
//! thaw. Every frozen filesystem of the copy is frozen together, `/` last.
//!
//! The provider is opt-in until Slice 18 decides the default (spec §M.4): an
//! explicit `--snapshot tracked-freeze`, or the automatic choice with
//! `--allow-freeze` when every precondition holds (spec §E step 4, D-141).

use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use lr_core::{Consistency, Error, Result, SnapshotOpts, SourceLayout, Support};

use crate::freeze::{Deadman, FreezeLog};
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
/// Default number of passes that do not shrink the dirty set, or only wait
/// for a package transaction, before the copy gives up (`max_passes`).
pub const DEFAULT_MAX_PASSES: u32 = 10;
/// Default per-CPU ring buffer of the trace instance.
pub const DEFAULT_BUFFER_KB: u32 = 16 << 10;
/// Tracking granularity; engine chunks are multiples of it.
pub const TRACK_CHUNK_BYTES: u64 = 64 << 10;

const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);
const TMPFS_MAGIC: i64 = 0x0102_1994;
const RUNTIME_DIR: &str = "/run/linuxreflect";
/// dpkg's locks (spec §E.7 "Package transactions").
const DPKG_DIR: &str = "/var/lib/dpkg";
const DPKG_LOCKS: [&str; 2] = ["/var/lib/dpkg/lock-frontend", "/var/lib/dpkg/lock"];
const PACKAGE_WAIT: Duration = Duration::from_secs(1);
/// How long the final read waits for writes in flight to unfrozen regions.
const QUIET_IDLE_TIMEOUT: Duration = Duration::from_millis(500);

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
        support(src, opts, false)
    }

    fn create(&self, src: &SourceLayout, opts: &SnapshotOpts) -> Result<BlockSnapshot> {
        let (device, spec) = partition_route(src, opts)?;
        let copy = TrackedCopy::start(&device, vec![spec], opts)?;
        Ok(BlockSnapshot::new(src.device.clone(), Consistency::Frozen, ()).with_tracked(copy))
    }
}

/// The disk to trace and the one region of a partition (or of a device with
/// ext4 directly on it), after the partition route's refusals.
fn partition_route(src: &SourceLayout, opts: &SnapshotOpts) -> Result<(PathBuf, RegionSpec)> {
    if let Some(reason) = refusal(src, opts) {
        return Err(refused(&reason));
    }
    let region = region_of(src)?;
    let spec = RegionSpec {
        start_sector: region.start_sector,
        sectors: region.sectors,
        partition: Some(src.device.clone()),
        fs_type: src
            .fs
            .as_ref()
            .map(|facts| facts.fs_type.clone())
            .unwrap_or_default(),
        mountpoints: src.mountpoints.clone(),
    };
    let device = if region.part.is_some() {
        disk_of(&src.device)?
    } else {
        src.device.clone()
    };
    Ok((device, spec))
}

/// What a tracked copy would do, found with the checks it makes before it
/// traces or freezes anything (the backup plan, spec §E.7, D-136). The
/// write-tracking self test is not run: it needs a loop device of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackedPlan {
    /// Filesystems the final freeze holds together, `/` last.
    pub frozen: Vec<PathBuf>,
    /// Regions held by the quiet-window rule (an ESP, BIOS boot, the boot
    /// area before the first partition).
    pub quiet_regions: usize,
    /// The final-freeze budget (`--freeze-max`).
    pub freeze_max: Duration,
    /// Pre-freeze hooks that would run.
    pub pre_freeze_hooks: usize,
    /// Post-thaw hooks that would run.
    pub post_thaw_hooks: usize,
    /// Chosen by `auto` with `--allow-freeze` rather than by name.
    pub automatic: bool,
}

impl TrackedPlan {
    /// What the plan tells the operator before the backup starts.
    #[must_use]
    pub fn notes(&self) -> Vec<String> {
        let frozen: Vec<String> = self
            .frozen
            .iter()
            .map(|path| path.display().to_string())
            .collect();
        let mut notes = vec![format!(
            "tracked-freeze copies while the system runs, then freezes {} together for at \
             most {} s (--freeze-max) to read the last changes; programs writing there wait \
             during that freeze",
            frozen.join(", "),
            self.freeze_max.as_secs()
        )];
        if self.quiet_regions > 0 {
            notes.push(format!(
                "{} region(s) that cannot be frozen (an EFI system partition, BIOS boot, the \
                 boot area) are read under the same freeze; a write to one of them during \
                 that read fails the backup",
                self.quiet_regions
            ));
        }
        notes.push(if self.pre_freeze_hooks + self.post_thaw_hooks == 0 {
            "no hooks are installed (/etc/linuxreflect/hooks): applications are imaged as a \
             power cut would leave them on disk"
                .to_owned()
        } else {
            format!(
                "{} pre-freeze and {} post-thaw hook(s) run around the final freeze",
                self.pre_freeze_hooks, self.post_thaw_hooks
            )
        });
        notes.push(if self.automatic {
            "the write-tracking self test runs when the backup starts; on a kernel that fails \
             it, the automatic choice goes on to the next method"
                .to_owned()
        } else {
            "the write-tracking self test runs when the backup starts; a kernel that fails it \
             refuses the backup"
                .to_owned()
        });
        notes
    }
}

/// Plan the tracked copy of a partition (or of a device with ext4 directly
/// on it) without tracing or freezing anything.
///
/// # Errors
/// The refusals [`BlockSnapshotProvider::create`] would return before it
/// starts tracing.
pub fn plan_partition(src: &SourceLayout, opts: &SnapshotOpts) -> Result<TrackedPlan> {
    let (device, spec) = partition_route(src, opts)?;
    plan_regions(&device, &[spec], opts)
}

/// Plan the tracked copy of whole-disk `regions` of `disk` without tracing
/// or freezing anything.
///
/// # Errors
/// The refusals [`track_disk`] would return before it starts tracing.
pub fn plan_disk(disk: &Path, regions: &[RegionSpec], opts: &SnapshotOpts) -> Result<TrackedPlan> {
    if let Some(reason) = opt_in_refusal(opts).or_else(tracepoint_refusal) {
        return Err(refused(&reason));
    }
    plan_regions(disk, regions, opts)
}

/// Whether tracked-freeze can copy whole-disk `regions` of `disk`: the
/// preconditions of spec §E.7, and with `self_test` the write-tracking self
/// test (see [`support`]).
///
/// # Errors
/// What no method choice can work around: an out-of-range `--freeze-max`,
/// an unsafe hook, I/O errors. A precondition that does not hold is
/// [`Support::No`] with the reason.
pub fn disk_support(
    disk: &Path,
    regions: &[RegionSpec],
    opts: &SnapshotOpts,
    self_test: bool,
) -> Result<Support> {
    if let Some(reason) = opt_in_refusal(opts).or_else(tracepoint_refusal) {
        return Ok(Support::No(reason));
    }
    match TrackedCopy::check(disk, regions, opts) {
        Ok(_) => Ok(match self_test.then(self_test_refusal).flatten() {
            Some(reason) => Support::No(reason),
            None => Support::Yes,
        }),
        Err(Refusal::Precondition(reason)) => Ok(Support::No(reason)),
        Err(Refusal::Failed(error)) => Err(error),
    }
}

fn plan_regions(disk: &Path, regions: &[RegionSpec], opts: &SnapshotOpts) -> Result<TrackedPlan> {
    let checked = TrackedCopy::check(disk, regions, opts).map_err(Refusal::into_error)?;
    Ok(TrackedPlan {
        quiet_regions: checked
            .holds
            .iter()
            .filter(|hold| **hold == Hold::Quiet)
            .count(),
        frozen: checked.mountpoints,
        freeze_max: checked.freeze_max,
        pre_freeze_hooks: checked.hooks.of(crate::hooks::Stage::PreFreeze).len(),
        post_thaw_hooks: checked.hooks.of(crate::hooks::Stage::PostThaw).len(),
        automatic: opts.provider.as_deref() != Some(ID),
    })
}

fn refused(reason: &str) -> Error {
    Error::no_consistent_method([
        format!("tracked-freeze refused: {reason}"),
        "unmount the filesystem for offline consistency".to_owned(),
        "boot rescue media for an offline image".to_owned(),
    ])
}

/// Why [`TrackedCopy::check`] stopped.
enum Refusal {
    /// A precondition of spec §E.7 does not hold: the method does not apply
    /// to this source, and the automatic choice moves on.
    Precondition(String),
    /// The request cannot be honoured or the check failed.
    Failed(Error),
}

impl From<Error> for Refusal {
    fn from(error: Error) -> Self {
        Self::Failed(error)
    }
}

impl Refusal {
    fn into_error(self) -> Error {
        match self {
            Self::Precondition(reason) => refused(&reason),
            Self::Failed(error) => error,
        }
    }
}

/// Whether tracked-freeze can copy this partition (or a device with ext4
/// directly on it): the preconditions of spec §E.7. `self_test` also runs the
/// write-tracking self test, which needs root and a loop device of its own;
/// the automatic choice runs it when a backup starts, a plan does not.
#[must_use]
pub fn support(src: &SourceLayout, opts: &SnapshotOpts, self_test: bool) -> Support {
    let refusal = refusal(src, opts).or_else(|| self_test.then(self_test_refusal).flatten());
    match refusal {
        Some(reason) => Support::No(reason),
        None => Support::Yes,
    }
}

/// Why this partition (or device) cannot be copied with tracked-freeze.
fn refusal(src: &SourceLayout, opts: &SnapshotOpts) -> Option<String> {
    if let Some(reason) = opt_in_refusal(opts) {
        return Some(reason);
    }
    if src.is_whole_disk() {
        return Some("a whole disk is copied through the whole-disk route".to_owned());
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
    if src.mountpoints.is_empty() {
        return Some("the source is not mounted; the offline provider applies".to_owned());
    }
    job_writes_refusal(&src.mountpoints, opts)
        .or_else(tracepoint_refusal)
        .or_else(|| match disk_name(&src.device_facts.name) {
            Ok(disk) => blk_mq_refusal(&disk),
            Err(error) => Some(format!(
                "the disk of {} is not in sysfs: {error}",
                src.device.display()
            )),
        })
}

/// Whether a request opts in to tracked-freeze (spec §E step 4, §M.4): an
/// explicit `--snapshot tracked-freeze`, or the automatic choice with
/// `--allow-freeze`.
#[must_use]
pub fn opted_in(opts: &SnapshotOpts) -> bool {
    match opts.provider.as_deref() {
        Some(ID) => true,
        None | Some("auto") => opts.allow_freeze,
        Some(_) => false,
    }
}

/// Opt-in check shared by the partition and the whole-disk routes.
pub fn opt_in_refusal(opts: &SnapshotOpts) -> Option<String> {
    (!opted_in(opts)).then(|| {
        format!("tracked-freeze is opt-in; pass --snapshot {ID}, or --allow-freeze with auto")
    })
}

/// The kernel name of the disk a block device belongs to: its parent for a
/// partition, itself otherwise.
fn disk_name(name: &str) -> Result<String> {
    let class = lr_core::sysfs::sysfs_root().join("class/block").join(name);
    if !class.join("partition").exists() {
        return if class.exists() {
            Ok(name.to_owned())
        } else {
            Err(Error::unsupported(format!(
                "{} is missing",
                class.display()
            )))
        };
    }
    let real = std::fs::canonicalize(&class).map_err(Error::Io)?;
    real.parent()
        .and_then(Path::file_name)
        .map(|disk| disk.to_string_lossy().into_owned())
        .ok_or_else(|| Error::corrupt("a partition without a parent disk in sysfs"))
}

/// Why a disk cannot report write completions: only a blk-mq (request-based)
/// device does, and the copy tracks completions (spec §E.7 preconditions).
fn blk_mq_refusal(disk: &str) -> Option<String> {
    let mq = lr_core::sysfs::sysfs_root()
        .join("class/block")
        .join(disk)
        .join("mq");
    (!mq.is_dir()).then(|| {
        format!("{disk} is not a blk-mq device, so its write completions cannot be tracked")
    })
}

/// Why write tracking cannot be trusted on this kernel, found by running the
/// self test on a private loop device (spec §E.7 preconditions). The
/// automatic choice runs it before it settles on tracked-freeze.
#[must_use]
pub fn self_test_refusal() -> Option<String> {
    let Some(tracefs) = tracking::tracefs_root() else {
        return Some("tracefs is not mounted".to_owned());
    };
    match run_self_test(&tracefs) {
        Ok(test) if test.passed() => None,
        Ok(test) => Some(format!(
            "the write-tracking self test failed on this kernel: {test:?}"
        )),
        Err(error) => Some(format!(
            "the write-tracking self test could not run: {error}"
        )),
    }
}

/// The self test, with its loop image on a tmpfs: never on a filesystem that
/// could be a source.
fn run_self_test(tracefs: &Path) -> Result<tracking::SelfTest> {
    let workdir = Path::new(RUNTIME_DIR);
    std::fs::create_dir_all(workdir).map_err(Error::Io)?;
    let dir = lr_unsafe::open_dir_readonly(workdir).map_err(Error::Io)?;
    if lr_unsafe::filemeta::filesystem_type(&dir).map_err(Error::Io)? != TMPFS_MAGIC {
        return Err(Error::unsupported(format!(
            "{RUNTIME_DIR} is not a tmpfs; the write-tracking self test needs one"
        )));
    }
    drop(dir);
    tracking::self_test(tracefs, workdir)
}

/// Why this kernel cannot track writes, if it cannot.
pub fn tracepoint_refusal() -> Option<String> {
    let Some(tracefs) = tracking::tracefs_root() else {
        return Some("tracefs is not mounted".to_owned());
    };
    let format_path = tracefs
        .join("events")
        .join(tracking::TRACEPOINT)
        .join("format");
    let completion_path = tracefs
        .join("events")
        .join(tracking::COMPLETION_TRACEPOINT)
        .join("format");
    match (
        std::fs::read_to_string(&format_path),
        std::fs::read_to_string(&completion_path),
    ) {
        (Ok(format), Ok(completion)) => tracking::check_format(&format)
            .and_then(|()| tracking::check_completion_format(&completion))
            .err(),
        (Err(error), _) => Some(format!(
            "the {} tracepoint is unavailable: {error}",
            tracking::TRACEPOINT
        )),
        (_, Err(error)) => Some(format!(
            "the {} tracepoint is unavailable: {error}",
            tracking::COMPLETION_TRACEPOINT
        )),
    }
}

/// Why the job's own writes could reach a filesystem it will freeze: the
/// destination on it (the copy would track its own writes). Unlike the
/// whole-read freeze (§E.4), other processes' writes are fine, since they
/// wait out the short freeze, and so is the working directory: nothing is
/// written while frozen, and a daemon's working directory is `/`.
fn job_writes_refusal(mountpoints: &[PathBuf], opts: &SnapshotOpts) -> Option<String> {
    use std::os::unix::fs::MetadataExt as _;
    let frozen: Vec<u64> = mountpoints
        .iter()
        .filter_map(|mountpoint| std::fs::metadata(mountpoint).ok().map(|m| m.dev()))
        .collect();
    let on_frozen = |path: &Path| -> bool {
        let existing = path.ancestors().find(|p| p.exists()).unwrap_or(path);
        std::fs::metadata(existing).is_ok_and(|metadata| frozen.contains(&metadata.dev()))
    };
    if opts.destination_remote {
        return None;
    }
    match opts.destination.as_deref() {
        None => Some(
            "tracked-freeze needs the destination to prove it is on another filesystem".to_owned(),
        ),
        Some(destination) if on_frozen(destination) => Some(format!(
            "the destination {} is on a filesystem that will be frozen; the copy would \
             track its own writes",
            destination.display()
        )),
        Some(_) => None,
    }
}

/// One region of a source to copy (spec §E.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionSpec {
    /// First sector on the whole disk (512-byte units).
    pub start_sector: u64,
    /// Length in sectors.
    pub sectors: u64,
    /// The region's own device node (a partition, or a device with a
    /// filesystem directly on it); `None` for an area of the disk such as the
    /// leading region before the first partition.
    pub partition: Option<PathBuf>,
    /// Filesystem type from discovery (empty when none).
    pub fs_type: String,
    /// Where the filesystem is mounted, if anywhere.
    pub mountpoints: Vec<PathBuf>,
}

/// How a region is kept consistent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hold {
    /// A mounted ext4: frozen; the index is into the copy's mount points.
    Frozen(usize),
    /// Cannot be frozen: it must stay unwritten from its final read to the
    /// thaw (the quiet-window rule).
    Quiet,
}

/// Start a tracked copy of whole-disk `regions` of `disk` (the whole-disk
/// route; the engine checks the partition table itself).
pub fn track_disk(
    disk: &Path,
    regions: Vec<RegionSpec>,
    opts: &SnapshotOpts,
) -> Result<TrackedCopy> {
    if let Some(reason) = opt_in_refusal(opts).or_else(tracepoint_refusal) {
        return Err(refused(&reason));
    }
    TrackedCopy::start(disk, regions, opts)
}

/// The tracked region of a partition (or of a whole device with a
/// filesystem directly on it), from sysfs.
fn region_of(src: &SourceLayout) -> Result<TrackedRegion> {
    let class = lr_core::sysfs::sysfs_root()
        .join("class/block")
        .join(&src.device_facts.name);
    let own = parse_dev(&read_sysfs(&class.join("dev"))?)?;
    let size = read_number(&class.join("size"))?;
    if class.join("partition").exists() {
        let real = std::fs::canonicalize(&class).map_err(Error::Io)?;
        let parent = real
            .parent()
            .ok_or_else(|| Error::corrupt("a partition without a parent disk in sysfs"))?;
        let whole = parse_dev(&read_sysfs(&parent.join("dev"))?)?;
        Ok(TrackedRegion {
            whole,
            part: Some(own),
            start_sector: read_number(&class.join("start"))?,
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

/// The disk device node a partition node belongs to.
fn disk_of(partition: &Path) -> Result<PathBuf> {
    let name = lr_core::sysfs::device_name(partition).map_err(Error::Io)?;
    let class = lr_core::sysfs::sysfs_root().join("class/block").join(name);
    let real = std::fs::canonicalize(&class).map_err(Error::Io)?;
    let disk = real
        .parent()
        .and_then(Path::file_name)
        .ok_or_else(|| Error::corrupt("a partition without a parent disk in sysfs"))?;
    Ok(Path::new("/dev").join(disk))
}

fn read_sysfs(path: &Path) -> Result<String> {
    std::fs::read_to_string(path)
        .map(|text| text.trim().to_owned())
        .map_err(|error| Error::unsupported(format!("{}: {error}", path.display())))
}

fn read_number(path: &Path) -> Result<u64> {
    read_sysfs(path)?
        .parse()
        .map_err(|_| Error::corrupt(format!("{} is not a number", path.display())))
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

fn device_number(path: &Path) -> Result<DevNumber> {
    use std::os::unix::fs::MetadataExt as _;
    let rdev = std::fs::metadata(path).map_err(Error::Io)?.rdev();
    Ok(DevNumber {
        major: (((rdev >> 32) & 0xffff_f000) | ((rdev >> 8) & 0x0000_0fff)) as u32,
        minor: (((rdev >> 12) & 0xffff_ff00) | (rdev & 0x0000_00ff)) as u32,
    })
}

/// What must not change while the copy runs: a region's place on the disk
/// and, for ext4, the filesystem's identity and size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RegionFacts {
    start_sector: u64,
    sectors: u64,
    ext4: Option<([u8; 16], u64)>,
}

impl RegionFacts {
    fn read(spec: &RegionSpec) -> Result<Self> {
        let (start_sector, sectors) = match &spec.partition {
            Some(partition) => {
                let name = lr_core::sysfs::device_name(partition).map_err(Error::Io)?;
                let class = lr_core::sysfs::sysfs_root().join("class/block").join(name);
                let start = if class.join("partition").exists() {
                    read_number(&class.join("start"))?
                } else {
                    0
                };
                (start, read_number(&class.join("size"))?)
            }
            None => (spec.start_sector, spec.sectors),
        };
        let ext4 = match (&spec.partition, spec.fs_type.as_str()) {
            (Some(partition), "ext4") => Some(ext4_identity(partition)?),
            _ => None,
        };
        Ok(Self {
            start_sector,
            sectors,
            ext4,
        })
    }
}

fn ext4_identity(device: &Path) -> Result<([u8; 16], u64)> {
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
        return Err(Error::unsupported(format!(
            "{} has no ext4 superblock",
            device.display()
        )));
    }
    let high = if le32(0x60) & 0x80 != 0 {
        u64::from(le32(0x150))
    } else {
        0
    };
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&sb[0x68..0x78]);
    Ok((uuid, (high << 32) | u64::from(le32(0x04))))
}

#[derive(Debug, Clone, Copy)]
struct Limits {
    freeze_max: Duration,
    final_max_bytes: u64,
    max_passes: u32,
    grace: Duration,
}

/// What the copy does after a pass (spec §E.7 steps 5 and 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// The rest fits the final freeze.
    Final,
    /// Read the dirty chunks again.
    Again,
    /// The rest fits, but a package transaction runs: wait, then read again.
    WaitForPackages,
    /// `max_passes` passes did not converge: `E_NO_CONVERGENCE`.
    GiveUp,
}

/// The convergence rule, kept apart from the tracer.
#[derive(Debug, Clone, Copy, Default)]
struct Convergence {
    /// Dirty bytes the previous pass left, to tell a shrinking pass.
    last_dirty_bytes: Option<u64>,
    /// Passes counted against `max_passes`.
    stalled_passes: u32,
}

impl Convergence {
    /// Decide after a pass that read `read_bytes` in `elapsed` and left
    /// `dirty_bytes` behind. The rest fits when it is at most `final_max`
    /// and, at the rate this pass reached, can be read in half of
    /// `freeze_max` (the other half is room for the freeze itself and new
    /// writes). Only a pass that did not shrink the dirty set, or one that
    /// only waits for a package transaction, counts against `max_passes`: a
    /// copy that keeps converging is not given up.
    fn after_pass(
        &mut self,
        limits: &Limits,
        dirty_bytes: u64,
        read_bytes: u64,
        elapsed: Duration,
        packages: bool,
    ) -> Verdict {
        let rate = read_bytes as f64 / elapsed.as_secs_f64().max(1e-3);
        let estimate = Duration::from_secs_f64(dirty_bytes as f64 / rate.max(1.0));
        let fits = dirty_bytes <= limits.final_max_bytes && estimate <= limits.freeze_max / 2;
        if fits && !packages {
            return Verdict::Final;
        }
        let shrank = self.last_dirty_bytes.is_none_or(|last| dirty_bytes < last);
        self.last_dirty_bytes = Some(dirty_bytes);
        if !shrank || fits {
            self.stalled_passes += 1;
        }
        if self.stalled_passes >= limits.max_passes {
            Verdict::GiveUp
        } else if fits {
            Verdict::WaitForPackages
        } else {
            Verdict::Again
        }
    }
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
    /// Filesystems frozen together.
    #[serde(default)]
    pub frozen_filesystems: u32,
    /// Passes added because a package transaction held dpkg's lock.
    #[serde(default)]
    pub package_waits: u32,
}

/// Engine chunks of one region to read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionChunks {
    /// Index of the region, in the order the copy was started with.
    pub region: usize,
    /// Engine chunk numbers within the region, ascending.
    pub chunks: Vec<u64>,
}

/// The engine's handle on a tracked copy (see the module documentation).
pub struct TrackedCopy {
    tracker: Tracker,
    /// Dirty chunks (tracking granularity) not yet re-read.
    pending: DirtyMap,
    specs: Vec<RegionSpec>,
    holds: Vec<Hold>,
    facts: Vec<RegionFacts>,
    /// Filesystems to freeze, `/` last.
    mountpoints: Vec<PathBuf>,
    /// The disk's kernel name, for its in-flight counters.
    disk_name: String,
    /// Whether one of them holds dpkg's state.
    holds_dpkg: bool,
    limits: Limits,
    engine_chunk_bytes: u64,
    log: FreezeLog,
    summary: TrackedSummary,
    convergence: Convergence,
    hooks: crate::hooks::Hooks,
    /// Warnings for the report (failed post-thaw hooks).
    warnings: Vec<String>,
    inhibitor: Option<Child>,
}

impl std::fmt::Debug for TrackedCopy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrackedCopy")
            .field("specs", &self.specs)
            .field("mountpoints", &self.mountpoints)
            .field("summary", &self.summary)
            .finish_non_exhaustive()
    }
}

impl Drop for TrackedCopy {
    fn drop(&mut self) {
        if let Some(mut inhibitor) = self.inhibitor.take() {
            let _ = inhibitor.kill();
            let _ = inhibitor.wait();
        }
    }
}

/// What [`TrackedCopy::check`] established.
struct Checked {
    tracefs: PathBuf,
    whole: DevNumber,
    disk_name: String,
    holds: Vec<Hold>,
    /// Filesystems to freeze, `/` last.
    mountpoints: Vec<PathBuf>,
    freeze_max: Duration,
    hooks: crate::hooks::Hooks,
    holds_dpkg: bool,
}

impl TrackedCopy {
    /// Everything `start` checks before anything is traced or frozen; the
    /// backup plan runs the same checks ([`plan_disk`], [`plan_partition`]).
    fn check(
        disk: &Path,
        specs: &[RegionSpec],
        opts: &SnapshotOpts,
    ) -> std::result::Result<Checked, Refusal> {
        use std::os::unix::fs::MetadataExt as _;
        if specs.is_empty() {
            return Err(Error::unsupported("a tracked copy needs at least one region").into());
        }
        let tracefs = tracking::tracefs_root()
            .ok_or_else(|| Refusal::Precondition("tracefs is not mounted".to_owned()))?;
        let whole = device_number(disk)?;
        let disk_name = lr_core::sysfs::device_name(disk).map_err(Error::Io)?;
        // Completions are tracked per request: a bio-based driver reports none.
        if let Some(reason) = blk_mq_refusal(&disk_name) {
            return Err(Refusal::Precondition(reason));
        }

        // How each region is held, and the filesystems to freeze.
        let mut mountpoints: Vec<PathBuf> = Vec::new();
        let mut holds = Vec::with_capacity(specs.len());
        for spec in specs {
            let hold = match (spec.mountpoints.first(), spec.fs_type.as_str()) {
                (None, _) => Hold::Quiet,
                (Some(_), "vfat") => Hold::Quiet,
                (Some(mountpoint), "ext4") => {
                    mountpoints.push(mountpoint.clone());
                    Hold::Frozen(mountpoints.len() - 1)
                }
                (Some(mountpoint), fs_type) => {
                    return Err(Refusal::Precondition(format!(
                        "{} ({fs_type}) is mounted and tracked-freeze cannot hold it; \
                         unmount it or back it up separately",
                        mountpoint.display()
                    )));
                }
            };
            holds.push(hold);
        }
        // `/` last: every other freeze, and arming its deadman, may still
        // need to start programs from it.
        let order: Vec<usize> = {
            let mut order: Vec<usize> = (0..mountpoints.len()).collect();
            order.sort_by_key(|&index| mountpoints[index] == Path::new("/"));
            order
        };
        let sorted: Vec<PathBuf> = order
            .iter()
            .map(|&index| mountpoints[index].clone())
            .collect();
        for hold in &mut holds {
            if let Hold::Frozen(index) = hold {
                *index = order
                    .iter()
                    .position(|&original| original == *index)
                    .unwrap_or(*index);
            }
        }
        let mountpoints = sorted;
        if let Some(reason) = job_writes_refusal(&mountpoints, opts) {
            return Err(Refusal::Precondition(reason));
        }
        let freeze_max = freeze_max(opts)?;
        // Hooks run as root: unsafe ones refuse the job before tracing starts.
        let hooks = crate::hooks::Hooks::load(
            opts.hooks_dir
                .as_deref()
                .unwrap_or(Path::new(crate::hooks::DEFAULT_HOOKS_DIR)),
            crate::hooks::DEFAULT_HOOK_TIMEOUT,
        )?;
        let holds_dpkg = std::fs::metadata(DPKG_DIR).is_ok_and(|dpkg| {
            mountpoints.iter().any(|mountpoint| {
                std::fs::metadata(mountpoint).is_ok_and(|metadata| metadata.dev() == dpkg.dev())
            })
        });
        Ok(Checked {
            tracefs,
            whole,
            disk_name,
            holds,
            mountpoints,
            freeze_max,
            hooks,
            holds_dpkg,
        })
    }

    /// Start tracking `regions` of `disk`, run the self test, take the
    /// inhibitor lock and make the barrier freeze.
    fn start(disk: &Path, specs: Vec<RegionSpec>, opts: &SnapshotOpts) -> Result<Self> {
        let Checked {
            tracefs,
            whole,
            disk_name,
            holds,
            mountpoints,
            freeze_max,
            hooks,
            holds_dpkg,
        } = Self::check(disk, &specs, opts).map_err(Refusal::into_error)?;

        let self_test = run_self_test(&tracefs)?;
        if !self_test.passed() {
            return Err(Error::TrackingLost {
                reason: format!(
                    "the write-tracking self test failed on this kernel: {self_test:?}"
                ),
            });
        }

        let mut tracked = Vec::with_capacity(specs.len());
        let mut facts = Vec::with_capacity(specs.len());
        for spec in &specs {
            tracked.push(TrackedRegion {
                whole,
                part: spec.partition.as_deref().map(device_number).transpose()?,
                start_sector: spec.start_sector,
                sectors: spec.sectors,
            });
            facts.push(RegionFacts::read(spec)?);
        }
        // A killed job's instance keeps tracing into its buffers; remove those
        // whose owner is gone (spec §E.7; the daemon also sweeps at start).
        for leftover in tracking::sweep(&tracefs) {
            tracing::info!(instance = %leftover.display(), "removed a leftover trace instance");
        }
        let name = format!(
            "{}tf-{}-{}",
            tracking::INSTANCE_PREFIX,
            std::process::id(),
            JOB_COUNTER.fetch_add(1, Ordering::SeqCst)
        );
        let tracker = Tracker::start(
            &tracefs,
            &name,
            tracked,
            TRACK_CHUNK_BYTES,
            opts.tracked.buffer_kb.unwrap_or(DEFAULT_BUFFER_KB),
        )?;
        let pending = tracker.empty_map();
        let grace = Duration::from_secs(
            opts.deadman_grace_secs
                .unwrap_or(crate::freeze::DEFAULT_GRACE_SECS),
        );
        let mut copy = Self {
            tracker,
            pending,
            specs,
            holds,
            facts,
            mountpoints,
            disk_name,
            holds_dpkg,
            limits: Limits {
                freeze_max,
                final_max_bytes: opts
                    .tracked
                    .final_max_bytes
                    .unwrap_or(DEFAULT_FINAL_MAX_BYTES),
                max_passes: opts.tracked.max_passes.unwrap_or(DEFAULT_MAX_PASSES).max(1),
                grace,
            },
            engine_chunk_bytes: 0,
            log: FreezeLog::default(),
            summary: TrackedSummary::default(),
            convergence: Convergence::default(),
            hooks,
            warnings: Vec::new(),
            inhibitor: None,
        };
        copy.summary.frozen_filesystems = u32::try_from(copy.mountpoints.len()).unwrap_or(u32::MAX);
        copy.inhibitor = inhibit_sleep();

        // The barrier: a freeze completes every write already submitted, so
        // none that predates tracking can land after the first pass reads.
        let began = Instant::now();
        copy.frozen_with(|_| Ok(()))?;
        copy.summary.barrier_ms = elapsed_ms(began);
        copy.log.flush();
        Ok(copy)
    }

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

    /// The regions, in the order the copy was started with.
    pub fn regions(&self) -> &[RegionSpec] {
        &self.specs
    }

    /// Stop or resume the tracking reader, so the kernel loses events (tests).
    #[cfg(feature = "fault-injection")]
    pub fn pause_reader(&self, paused: bool) {
        self.tracker.pause_reader(paused);
    }

    /// The used-block map of region `region`'s live ext4 (spec §E.7 step 4),
    /// taken after the barrier. `dumpe2fs` reading a changing filesystem can
    /// see a bitmap and its checksum from different moments and refuse, so it
    /// is retried, and the last attempt runs with the filesystems frozen,
    /// where the metadata is consistent.
    pub fn used_map(&mut self, region: usize) -> Result<lr_fsmap::ExtentMap> {
        let device = self
            .specs
            .get(region)
            .and_then(|spec| spec.partition.clone())
            .ok_or_else(|| Error::unsupported("only a partition region has a used-block map"))?;
        for _ in 0..3 {
            if let Ok(map) = lr_fsmap::live_used_extents(&device) {
                return Ok(map);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        self.frozen_with(|_| lr_fsmap::live_used_extents(&device))
    }

    /// Engine chunks still pending, over all regions.
    pub fn pending_count(&self) -> usize {
        self.pending_engine_chunks()
            .iter()
            .map(|r| r.chunks.len())
            .sum()
    }

    /// The pending dirty chunks, in engine chunks, per region.
    fn pending_engine_chunks(&self) -> Vec<RegionChunks> {
        let ratio = self.engine_chunk_bytes / TRACK_CHUNK_BYTES;
        let mut all = Vec::with_capacity(self.specs.len());
        for (region, bits) in self.pending.bits().iter().enumerate() {
            let mut chunks: Vec<u64> = Vec::new();
            for chunk in bits.iter() {
                let engine = chunk / ratio;
                if chunks.last() != Some(&engine) {
                    chunks.push(engine);
                }
            }
            if !chunks.is_empty() {
                all.push(RegionChunks { region, chunks });
            }
        }
        all
    }

    /// A package transaction holds dpkg's lock on a filesystem this copy
    /// freezes: an image taken now could hold a half-installed system.
    fn package_transaction_running(&self) -> bool {
        self.holds_dpkg
            && DPKG_LOCKS
                .iter()
                .any(|lock| lr_unsafe::write_lock_conflicts(Path::new(lock)).unwrap_or(false))
    }

    /// After a pass that read `bytes` in `elapsed`: gather what was written
    /// meanwhile. `Ok(None)` means the rest fits the final freeze; otherwise
    /// the engine must read the returned chunks again and call this again.
    pub fn next_pass(
        &mut self,
        bytes: u64,
        elapsed: Duration,
    ) -> Result<Option<Vec<RegionChunks>>> {
        debug_assert!(self.engine_chunk_bytes != 0, "bind() first");
        self.tracker.drain(DRAIN_TIMEOUT)?;
        self.tracker.take_into(&mut self.pending);
        self.summary.passes += 1;
        let chunks = self.pending_engine_chunks();
        let count: u64 = chunks.iter().map(|r| r.chunks.len() as u64).sum();
        let dirty_bytes = count * self.engine_chunk_bytes;
        let packages = self.package_transaction_running();
        let verdict =
            self.convergence
                .after_pass(&self.limits, dirty_bytes, bytes, elapsed, packages);
        tracing::info!(
            pass = self.summary.passes,
            dirty_bytes,
            read_bytes = bytes,
            read_ms = elapsed.as_millis() as u64,
            packages,
            stalled = self.convergence.stalled_passes,
            ?verdict,
            "tracked-freeze pass"
        );
        match verdict {
            Verdict::Final => return Ok(None),
            Verdict::GiveUp => {
                return Err(Error::NoConvergence {
                    dirty_bytes,
                    passes: self.summary.passes,
                });
            }
            Verdict::WaitForPackages => {
                self.summary.package_waits += 1;
                std::thread::sleep(PACKAGE_WAIT);
            }
            Verdict::Again => {}
        }
        self.summary.recopied_chunks += count;
        Ok(Some(chunks))
    }

    /// The final read (spec §E.7 step 6): the pre-freeze hooks, the frozen
    /// read, then the post-thaw hooks. Once the pre-freeze hooks began, the
    /// post-thaw hooks run whatever happened; a failed pre-freeze hook ends
    /// the copy before anything is frozen, and a failed post-thaw hook is a
    /// warning ([`Self::warnings`]).
    pub fn final_read<T>(&mut self, read: impl FnOnce(&[RegionChunks]) -> Result<T>) -> Result<T> {
        let outcome = self
            .hooks
            .pre_freeze(&self.mountpoints)
            .and_then(|()| self.frozen_read(read));
        let failed = self.hooks.post_thaw(&self.mountpoints);
        self.warnings.extend(failed);
        outcome
    }

    /// Warnings for the backup report.
    #[must_use]
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Freeze every tracked filesystem, gather the last writes, let `read`
    /// read the given engine chunks (into memory, nothing may be written),
    /// check the quiet window, and thaw. A freeze longer than `freeze_max`
    /// fails the copy after the thaw.
    fn frozen_read<T>(&mut self, read: impl FnOnce(&[RegionChunks]) -> Result<T>) -> Result<T> {
        debug_assert!(self.engine_chunk_bytes != 0, "bind() first");
        let final_max = self.limits.final_max_bytes;
        let chunk_bytes = self.engine_chunk_bytes;
        let mut chunks_read = 0u64;
        let began = Instant::now();
        let outcome = self.frozen_with(|copy| {
            // A write still in flight to a region that cannot be frozen could
            // land under the read without a later event: wait it out first.
            copy.wait_for_quiet_regions()?;
            copy.tracker.drain(DRAIN_TIMEOUT)?;
            let mut late = copy.tracker.empty_map();
            copy.tracker.take_into(&mut late);
            copy.pending.union_with(&late);
            let chunks = copy.pending_engine_chunks();
            chunks_read = chunks.iter().map(|r| r.chunks.len() as u64).sum();
            let dirty_bytes = chunks_read * chunk_bytes;
            if dirty_bytes > final_max {
                return Err(Error::NoConvergence {
                    dirty_bytes,
                    passes: copy.summary.passes,
                });
            }
            let value = read(&chunks)?;
            // The quiet window: a region that cannot be frozen must not have
            // been written since its final read began.
            copy.tracker.drain(DRAIN_TIMEOUT)?;
            copy.tracker.take_into(&mut late);
            for (index, bits) in late.bits().iter().enumerate() {
                if bits.count() > 0 && copy.holds[index] == Hold::Quiet {
                    return Err(Error::SourceChanged {
                        what: format!(
                            "{} was written during the final read, and it cannot be frozen",
                            copy.describe(index)
                        ),
                    });
                }
            }
            Ok(value)
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

    /// After the copy: no event may have been lost, and every region must
    /// have kept its shape. Returns what the copy did.
    pub fn finish(&mut self) -> Result<TrackedSummary> {
        let losses = self.tracker.integrity()?;
        if !losses.is_clean() {
            return Err(Error::TrackingLost {
                reason: format!("{losses:?}"),
            });
        }
        for (index, spec) in self.specs.iter().enumerate() {
            let now = RegionFacts::read(spec)?;
            if now != self.facts[index] {
                return Err(Error::SourceChanged {
                    what: format!(
                        "{}: {:?} became {:?}",
                        self.describe(index),
                        self.facts[index],
                        now
                    ),
                });
            }
        }
        Ok(self.summary)
    }

    /// Writes in flight to the regions held by the quiet window: a quiet
    /// partition's own counter, and for an area of the disk outside every
    /// partition, the disk's counter less all of its partitions'.
    fn quiet_writes_in_flight(&self) -> Result<u64> {
        let class = lr_core::sysfs::sysfs_root().join("class/block");
        let writes = |name: &str| -> Result<u64> {
            let text = read_sysfs(&class.join(name).join("inflight"))?;
            text.split_ascii_whitespace()
                .nth(1)
                .and_then(|count| count.parse().ok())
                .ok_or_else(|| Error::corrupt(format!("{name}/inflight: {text:?}")))
        };
        let mut total = 0;
        let mut outside_partitions = None;
        for (index, spec) in self.specs.iter().enumerate() {
            if self.holds[index] != Hold::Quiet {
                continue;
            }
            match &spec.partition {
                Some(partition) => {
                    total += writes(&lr_core::sysfs::device_name(partition).map_err(Error::Io)?)?;
                }
                None => {
                    if outside_partitions.is_none() {
                        let mut partitions = 0;
                        let disk_dir = std::fs::canonicalize(class.join(&self.disk_name))
                            .map_err(Error::Io)?;
                        for entry in std::fs::read_dir(&disk_dir).map_err(Error::Io)?.flatten() {
                            if entry.path().join("partition").exists() {
                                partitions += writes(&entry.file_name().to_string_lossy())?;
                            }
                        }
                        outside_partitions =
                            Some(writes(&self.disk_name)?.saturating_sub(partitions));
                    }
                }
            }
        }
        Ok(total + outside_partitions.unwrap_or(0))
    }

    fn wait_for_quiet_regions(&self) -> Result<()> {
        if !self.holds.contains(&Hold::Quiet) {
            return Ok(());
        }
        let deadline = Instant::now() + QUIET_IDLE_TIMEOUT;
        while self.quiet_writes_in_flight()? > 0 {
            if Instant::now() >= deadline {
                return Err(Error::SourceChanged {
                    what: "a region that cannot be frozen kept being written".to_owned(),
                });
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        Ok(())
    }

    fn describe(&self, index: usize) -> String {
        let spec = &self.specs[index];
        match &spec.partition {
            Some(partition) => format!("{} ({})", partition.display(), spec.fs_type),
            None => format!("the disk area at sector {}", spec.start_sector),
        }
    }

    /// Freeze every tracked filesystem, `/` last, run `inside`, thaw (always),
    /// with a deadman armed for each. Nothing is logged while frozen.
    fn frozen_with<T>(&mut self, inside: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        // The deadman can only fire after `freeze_max`, and a freeze that long
        // fails the copy anyway, so an early thaw can never be published.
        let after = self.limits.freeze_max + self.limits.grace;
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

/// The final-freeze budget a request asks for: `freeze_max` defaults to 3 s
/// and may not exceed the 30 s hard cap (spec §E.7). An out-of-range value is
/// refused before tracing starts, never shortened.
///
/// # Errors
/// Returns [`Error::Unsupported`] for zero or more than 30 seconds.
fn freeze_max(opts: &SnapshotOpts) -> Result<Duration> {
    let Some(seconds) = opts.tracked.freeze_max_secs else {
        return Ok(DEFAULT_FREEZE_MAX);
    };
    let wanted = Duration::from_secs(seconds);
    if wanted.is_zero() || wanted > HARD_FREEZE_MAX {
        return Err(Error::unsupported(format!(
            "the final freeze may last 1 to {} seconds (--freeze-max), not {seconds}",
            HARD_FREEZE_MAX.as_secs()
        )));
    }
    Ok(wanted)
}

/// Hold a logind inhibitor lock (`sleep:shutdown`, block) for the copy, so
/// the machine is not suspended or shut down in the middle of a freeze. No
/// logind or no `systemd-inhibit`: nothing to hold.
fn inhibit_sleep() -> Option<Child> {
    Command::new("systemd-inhibit")
        .args([
            "--what=sleep:shutdown",
            "--who=LinuxReflect",
            "--why=a live backup is copying this disk",
            "--mode=block",
            "sleep",
            "infinity",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()
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

    /// Opt-in (spec §E step 4, §M.4): by name, or `auto` with
    /// `--allow-freeze`; never `auto` alone or another provider's name.
    #[test]
    fn it_is_opt_in() {
        let reason = refusal(&mounted_ext4(), &SnapshotOpts::default()).expect("refused");
        assert!(reason.contains("opt-in"), "{reason}");
        let other = SnapshotOpts {
            provider: Some("freeze".to_owned()),
            allow_freeze: true,
            ..SnapshotOpts::default()
        };
        assert!(!opted_in(&other));
        for provider in [None, Some("auto".to_owned())] {
            let auto = SnapshotOpts {
                provider,
                allow_freeze: true,
                ..SnapshotOpts::default()
            };
            assert!(opted_in(&auto));
            // Opted in, and refused for what it lacks (here a destination).
            let reason = refusal(&mounted_ext4(), &auto).expect("no destination");
            assert!(!reason.contains("opt-in"), "{reason}");
        }
        assert!(opted_in(&forced()));
    }

    /// Format files recorded from real kernels (`tests/fixtures/trace`).
    const QUEUE_FORMAT: &str = include_str!(
        "../tests/fixtures/trace/block_bio_queue-6.18.58.1-microsoft-standard-WSL2.format"
    );
    const COMPLETE_FORMAT: &str =
        include_str!("../tests/fixtures/trace/block_rq_complete-6.8.0-138-generic.format");

    /// What a fixture kernel's tracefs offers.
    #[derive(Clone, Copy)]
    enum Tracefs {
        Missing,
        WithoutQueue,
        WithoutCompletion,
        UnknownLayout,
        Complete,
    }

    /// A fixture kernel: a tracefs tree (`LR_TRACEFS_ROOT`) and a sysfs
    /// tree (`LR_SYSFS_ROOT`) with the disk `lrfx` and its partition `lrfx2`.
    fn fixture_kernel(tracefs: Tracefs, blk_mq: bool) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("fixture");
        let tracing = dir.path().join("tracing");
        std::fs::create_dir_all(&tracing).expect("tracing");
        let event = |name: &str, format: &str| {
            let path = tracing.join("events").join(name);
            std::fs::create_dir_all(&path).expect("event");
            std::fs::write(path.join("format"), format).expect("format");
        };
        if !matches!(tracefs, Tracefs::Missing) {
            std::fs::create_dir_all(tracing.join("instances")).expect("instances");
        }
        match tracefs {
            Tracefs::Missing => {}
            Tracefs::WithoutQueue => event(tracking::COMPLETION_TRACEPOINT, COMPLETE_FORMAT),
            Tracefs::WithoutCompletion => event(tracking::TRACEPOINT, QUEUE_FORMAT),
            Tracefs::UnknownLayout => {
                event(
                    tracking::TRACEPOINT,
                    &QUEUE_FORMAT.replace("print fmt: \"", "print fmt: \"queued "),
                );
                event(tracking::COMPLETION_TRACEPOINT, COMPLETE_FORMAT);
            }
            Tracefs::Complete => {
                event(tracking::TRACEPOINT, QUEUE_FORMAT);
                event(tracking::COMPLETION_TRACEPOINT, COMPLETE_FORMAT);
            }
        }
        let sys = dir.path().join("sys");
        let disk = sys.join("devices/virtual/block/lrfx");
        std::fs::create_dir_all(disk.join("lrfx2")).expect("partition");
        std::fs::write(disk.join("lrfx2/partition"), "2\n").expect("partition file");
        if blk_mq {
            std::fs::create_dir_all(disk.join("mq/0")).expect("mq");
        }
        let class = sys.join("class/block");
        std::fs::create_dir_all(&class).expect("class");
        std::os::unix::fs::symlink("../../devices/virtual/block/lrfx", class.join("lrfx"))
            .expect("disk link");
        std::os::unix::fs::symlink(
            "../../devices/virtual/block/lrfx/lrfx2",
            class.join("lrfx2"),
        )
        .expect("partition link");
        dir
    }

    /// Slice 18 AC (e): on a kernel without tracefs, without either
    /// tracepoint, with a tracepoint layout the parser does not know, or with
    /// a disk that is not blk-mq, the probe says `Support::No` with the
    /// reason and `auto` with `--allow-freeze` takes the next step instead.
    /// Each case runs in a child process that sees only its fixture.
    #[test]
    fn the_probe_refuses_a_kernel_that_cannot_track_writes() {
        let cases = [
            (Tracefs::Missing, true, "tracefs is not mounted"),
            (
                Tracefs::WithoutQueue,
                true,
                "the block/block_bio_queue tracepoint is unavailable",
            ),
            (
                Tracefs::WithoutCompletion,
                true,
                "the block/block_rq_complete tracepoint is unavailable",
            ),
            (Tracefs::UnknownLayout, true, "unrecognised print format"),
            (
                Tracefs::Complete,
                false,
                "lrfx is not a blk-mq device, so its write completions cannot be tracked",
            ),
            // The control: the same fixture with nothing missing.
            (Tracefs::Complete, true, "selected"),
        ];
        let exe = std::env::current_exe().expect("test binary");
        for (tracefs, blk_mq, expect) in cases {
            let kernel = fixture_kernel(tracefs, blk_mq);
            let output = std::process::Command::new(&exe)
                .args([
                    "--ignored",
                    "--exact",
                    "tracked_freeze::tests::fixture_kernel_child",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("LR_TRACEFS_ROOT", kernel.path().join("tracing"))
                .env("LR_SYSFS_ROOT", kernel.path().join("sys"))
                .env("LR_FIXTURE_EXPECT", expect)
                .output()
                .expect("child");
            let log = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(output.status.success(), "{expect}:\n{log}");
            assert!(
                log.contains("1 passed"),
                "{expect}: the child did not run:\n{log}"
            );
        }
    }

    /// Child process for [`the_probe_refuses_a_kernel_that_cannot_track_writes`].
    #[test]
    #[ignore = "internal helper for the fixture-kernel probe test"]
    fn fixture_kernel_child() {
        let Ok(expect) = std::env::var("LR_FIXTURE_EXPECT") else {
            return;
        };
        let mut layout = test_layout::offline("/dev/lrfx2");
        layout.mountpoints = vec![PathBuf::from("/srv/lr-fixture")];
        // A remote destination: whatever this host mounts at `/`, the job's
        // own writes never reach a filesystem it would freeze.
        let named = SnapshotOpts {
            provider: Some(ID.to_owned()),
            destination_remote: true,
            ..SnapshotOpts::default()
        };
        let auto = SnapshotOpts {
            allow_freeze: true,
            destination_remote: true,
            ..SnapshotOpts::default()
        };
        let support = provider().supports(&layout, &named);
        let decision = crate::probe::decide(&layout, &auto, crate::probe::Stage::Plan)
            .expect("a decision for a mounted non-root filesystem");
        if expect == "selected" {
            assert_eq!(support, Support::Yes);
            assert_eq!(decision.provider, ID);
            assert_eq!(decision.consistency, Consistency::Frozen);
            assert_eq!(decision.tracked_refusal, None);
            return;
        }
        match support {
            Support::No(reason) => assert!(reason.contains(&expect), "{reason}"),
            Support::Yes => panic!("{expect}: the probe accepted the fixture kernel"),
        }
        // Not tracked-freeze: the next step, the whole-read freeze, with the
        // reason among the warnings.
        assert_eq!(decision.provider, crate::probe::PROVIDER_FREEZE);
        assert!(
            decision
                .tracked_refusal
                .as_deref()
                .is_some_and(|reason| reason.contains(&expect)),
            "{decision:?}"
        );
        assert!(
            decision
                .warnings
                .iter()
                .any(|warning| warning.contains(&expect)),
            "{decision:?}"
        );
        // The root cannot be frozen for the whole read: no method, and the
        // refusal names the reason.
        layout.mountpoints = vec![PathBuf::from("/")];
        let error = crate::probe::decide(&layout, &auto, crate::probe::Stage::Plan)
            .expect_err("the running root has no other consistent method");
        assert!(error.to_string().contains(&expect), "{error}");
    }

    #[test]
    fn other_filesystems_and_unmounted_sources_are_refused() {
        let mut xfs = mounted_ext4();
        if let Some(fs) = xfs.fs.as_mut() {
            fs.fs_type = "xfs".to_owned();
        }
        assert!(refusal(&xfs, &forced()).expect("xfs").contains("ext4"));
        let unmounted = test_layout::offline("/dev/sdq1");
        assert!(
            refusal(&unmounted, &forced())
                .expect("unmounted")
                .contains("not mounted")
        );
    }

    #[test]
    fn the_running_root_is_no_longer_refused_for_being_root() {
        let mut root = mounted_ext4();
        root.mountpoints = vec![PathBuf::from("/")];
        let reason = refusal(&root, &forced());
        assert!(
            reason
                .as_deref()
                .is_none_or(|reason| !reason.contains("running system")),
            "{reason:?}"
        );
    }

    #[test]
    fn a_destination_on_a_frozen_filesystem_is_refused() {
        let dir = tempfile::tempdir().expect("dir");
        let opts = SnapshotOpts {
            provider: Some(ID.to_owned()),
            destination: Some(dir.path().join("backups")),
            ..SnapshotOpts::default()
        };
        let reason = job_writes_refusal(&[dir.path().to_path_buf()], &opts).expect("refused");
        assert!(reason.contains("track its own writes"), "{reason}");
        let remote = SnapshotOpts {
            destination_remote: true,
            ..opts
        };
        assert_eq!(
            job_writes_refusal(&[PathBuf::from("/nonexistent-mount")], &remote),
            None
        );
    }

    #[test]
    fn engine_chunks_must_be_multiples_of_the_tracking_chunk() {
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

    /// The convergence budget (spec §E.7 step 5): the rest must fit both
    /// `final_max` and half of `freeze_max` at the measured rate, and only
    /// passes that do not shrink the dirty set, or wait for a package
    /// transaction, count against `max_passes`.
    #[test]
    fn the_convergence_budget_counts_only_passes_that_do_not_converge() {
        const MIB: u64 = 1 << 20;
        let limits = Limits {
            freeze_max: Duration::from_secs(2),
            final_max_bytes: 64 * MIB,
            max_passes: 2,
            grace: Duration::from_secs(1),
        };
        let second = Duration::from_secs(1);
        // 100 MiB/s: 64 MiB needs 0.64 s, inside half of 2 s.
        let mut copy = Convergence::default();
        assert_eq!(
            copy.after_pass(&limits, 64 * MIB, 100 * MIB, second, false),
            Verdict::Final
        );
        // Over final_max, or too slow for half the freeze budget.
        let mut copy = Convergence::default();
        assert_eq!(
            copy.after_pass(&limits, 65 * MIB, 1000 * MIB, second, false),
            Verdict::Again
        );
        let mut copy = Convergence::default();
        assert_eq!(
            copy.after_pass(&limits, 32 * MIB, 20 * MIB, second, false),
            Verdict::Again
        );

        // Shrinking passes never give up, however many there are.
        let mut copy = Convergence::default();
        for dirty in (100..=1000).rev().step_by(100) {
            assert_eq!(
                copy.after_pass(&limits, dirty * MIB, 10 * MIB, second, false),
                Verdict::Again
            );
        }
        // Two passes that do not shrink it do.
        assert_eq!(
            copy.after_pass(&limits, 100 * MIB, 10 * MIB, second, false),
            Verdict::Again
        );
        assert_eq!(
            copy.after_pass(&limits, 120 * MIB, 10 * MIB, second, false),
            Verdict::GiveUp
        );

        // A package transaction postpones a final read that would fit, and
        // those waits count.
        let mut copy = Convergence::default();
        assert_eq!(
            copy.after_pass(&limits, MIB, 100 * MIB, second, true),
            Verdict::WaitForPackages
        );
        assert_eq!(
            copy.after_pass(&limits, MIB / 2, 100 * MIB, second, true),
            Verdict::GiveUp
        );
        let mut copy = Convergence::default();
        assert_eq!(
            copy.after_pass(&limits, MIB, 100 * MIB, second, true),
            Verdict::WaitForPackages
        );
        assert_eq!(
            copy.after_pass(&limits, MIB, 100 * MIB, second, false),
            Verdict::Final
        );
    }

    /// What the backup plan says about a tracked copy (D-136: the review
    /// shows what will happen, before anything does).
    #[test]
    fn the_plan_names_the_frozen_filesystems_the_budget_and_the_hooks() {
        let plan = TrackedPlan {
            frozen: vec![PathBuf::from("/boot"), PathBuf::from("/")],
            quiet_regions: 3,
            freeze_max: Duration::from_secs(3),
            pre_freeze_hooks: 0,
            post_thaw_hooks: 0,
            automatic: false,
        };
        let notes = plan.notes().join("\n");
        assert!(
            notes.contains("freezes /boot, / together for at most 3 s"),
            "{notes}"
        );
        assert!(
            notes.contains("3 region(s) that cannot be frozen"),
            "{notes}"
        );
        assert!(notes.contains("no hooks are installed"), "{notes}");
        assert!(
            notes.contains("self test runs when the backup starts"),
            "{notes}"
        );
        let hooked = TrackedPlan {
            quiet_regions: 0,
            pre_freeze_hooks: 2,
            post_thaw_hooks: 1,
            ..plan
        };
        let notes = hooked.notes().join("\n");
        assert!(
            notes.contains("2 pre-freeze and 1 post-thaw hook(s)"),
            "{notes}"
        );
        assert!(!notes.contains("cannot be frozen"), "{notes}");
        // The automatic choice moves on where the self test fails.
        let automatic = TrackedPlan {
            automatic: true,
            ..hooked
        };
        let notes = automatic.notes().join("\n");
        assert!(
            notes.contains("the automatic choice goes on to the next method"),
            "{notes}"
        );
    }

    /// `freeze_max` is its own budget (3 s by default, at most 30 s); the
    /// freeze provider's 300 s whole-read timeout never stretches it.
    #[test]
    fn the_final_freeze_budget_defaults_to_three_seconds_and_is_capped() {
        let with = |seconds: Option<u64>| SnapshotOpts {
            freeze_timeout_secs: Some(300),
            tracked: lr_core::TrackedTuning {
                freeze_max_secs: seconds,
                ..lr_core::TrackedTuning::default()
            },
            ..SnapshotOpts::default()
        };
        assert_eq!(
            freeze_max(&with(None)).expect("default"),
            DEFAULT_FREEZE_MAX
        );
        assert_eq!(
            freeze_max(&with(Some(30))).expect("the cap"),
            Duration::from_secs(30)
        );
        for refused in [0, 31, 300] {
            let error = freeze_max(&with(Some(refused))).expect_err("out of range");
            assert!(error.to_string().contains("1 to 30 seconds"), "{error}");
        }
    }
}
