//! Write tracking for the tracked-freeze provider (spec v2.2 §E.7).
//!
//! A private ftrace instance records the `block:block_bio_queue` tracepoint
//! for the source disk. A consumer thread reads its `trace_pipe` and turns
//! every event that can change data into dirty chunks of the tracked
//! regions (the source partitions). The provider copies, takes the dirty
//! chunks, copies them again, and finally reads the last ones under a freeze.
//!
//! Only reads and data-less flushes are ignored; every other operation
//! (write, discard, secure erase, write-zeroes, an operation this code does
//! not know) dirties its range. The instance is filtered by device number
//! only, never by operation, so a new operation letter cannot be dropped in
//! the kernel. An event line this code cannot parse, an overrun or a dropped
//! event make the copy untrustworthy, and [`Tracker::integrity`] reports them.
//!
//! Phase 1 of `docs/live-backup-plan.md`: nothing selects this yet.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead as _, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use lr_core::{Error, Result};

/// The bio submission tracepoint, relative to `events/`.
pub const TRACEPOINT: &str = "block/block_bio_queue";
/// The request completion tracepoint, relative to `events/`. A chunk is
/// dirtied when a write to it is submitted and again when it completes, so a
/// read that overlapped a write still in flight is always repeated.
pub const COMPLETION_TRACEPOINT: &str = "block/block_rq_complete";
/// The size of a sector in tracepoint events.
pub const SECTOR_BYTES: u64 = 512;
/// The prefix of every ftrace instance the provider creates.
pub const INSTANCE_PREFIX: &str = "lr-";

/// The textual layout this parser understands (`print fmt` of the event).
const PRINT_FORMAT: &str = "print fmt: \"%d,%d %s %llu + %u [%s]\"";
const EVENT_TAG: &str = "block_bio_queue: ";
/// The completion layout's common prefix (6.x kernels append ioprio fields).
const COMPLETE_PRINT_PREFIX: &str = "print fmt: \"%d,%d %s (%s) %llu + %u";
const COMPLETE_TAG: &str = "block_rq_complete: ";
const MARKER_TAG: &str = "tracing_mark_write: LR-DRAIN-";

/// A device number as the kernel reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DevNumber {
    /// Major number.
    pub major: u32,
    /// Minor number.
    pub minor: u32,
}

impl DevNumber {
    /// The kernel-internal `dev_t` (20 minor bits) that tracepoint filters compare.
    pub fn kernel(self) -> u64 {
        (u64::from(self.major) << 20) | u64::from(self.minor)
    }
}

/// What a bio does to the data on the device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BioKind {
    /// Reads data.
    Read,
    /// Carries no data (a pure flush, or a preflush with no payload).
    NoData,
    /// Can change data: write, discard, secure erase, write-zeroes, or an
    /// operation this code does not recognise.
    Dirtying,
}

/// One `block_bio_queue` event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BioEvent {
    /// The device the event names (the whole disk after partition remapping).
    pub dev: DevNumber,
    /// What the bio does.
    pub kind: BioKind,
    /// First sector, in 512-byte units.
    pub sector: u64,
    /// Length in sectors.
    pub sectors: u64,
}

/// One line of `trace_pipe`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Line {
    /// A bio event.
    Bio(BioEvent),
    /// A drain marker written by [`Tracker::drain`].
    Marker(u64),
    /// A line that names the tracepoint but could not be parsed.
    Malformed,
    /// Anything else (other events, blank lines).
    Other,
}

/// Classify a bio from its `rwbs` string and length.
pub fn classify(rwbs: &str, sectors: u64) -> BioKind {
    if sectors == 0 {
        return BioKind::NoData;
    }
    // A leading `F` is a preflush; the operation letter follows it.
    let op = if rwbs.len() > 1 && rwbs.starts_with('F') {
        &rwbs[1..]
    } else {
        rwbs
    };
    if op.starts_with('R') {
        BioKind::Read
    } else {
        BioKind::Dirtying
    }
}

/// Parse one `trace_pipe` line without allocating.
pub fn parse_line(line: &str) -> Line {
    if let Some(at) = line.find(EVENT_TAG) {
        return parse_event(&line[at + EVENT_TAG.len()..]).map_or(Line::Malformed, Line::Bio);
    }
    if let Some(at) = line.find(COMPLETE_TAG) {
        return parse_completion(&line[at + COMPLETE_TAG.len()..])
            .map_or(Line::Malformed, Line::Bio);
    }
    if let Some(at) = line.find(MARKER_TAG) {
        let digits = line[at + MARKER_TAG.len()..].trim_end();
        return digits.parse().map_or(Line::Other, Line::Marker);
    }
    Line::Other
}

fn parse_event(rest: &str) -> Option<BioEvent> {
    // "<major>,<minor> <rwbs> <sector> + <sectors> [<comm>]"
    let mut fields = rest.split_ascii_whitespace();
    let dev = fields.next()?;
    let rwbs = fields.next()?;
    let sector = fields.next()?;
    if fields.next()? != "+" {
        return None;
    }
    let sectors = fields.next()?;
    let (major, minor) = dev.split_once(',')?;
    let sectors: u64 = sectors.parse().ok()?;
    Some(BioEvent {
        dev: DevNumber {
            major: major.parse().ok()?,
            minor: minor.parse().ok()?,
        },
        kind: classify(rwbs, sectors),
        sector: sector.parse().ok()?,
        sectors,
    })
}

fn parse_completion(rest: &str) -> Option<BioEvent> {
    // "<major>,<minor> <rwbs> (<cmd>) <sector> + <sectors> ..." where the
    // command, empty for ordinary I/O, is skipped up to its closing bracket.
    let (dev, rest) = rest.split_once(' ')?;
    let (rwbs, rest) = rest.split_once(' ')?;
    let rest = rest.strip_prefix('(')?;
    let (_command, rest) = rest.split_once(") ")?;
    let mut fields = rest.split_ascii_whitespace();
    let sector = fields.next()?;
    if fields.next()? != "+" {
        return None;
    }
    let sectors: u64 = fields.next()?.parse().ok()?;
    let (major, minor) = dev.split_once(',')?;
    Some(BioEvent {
        dev: DevNumber {
            major: major.parse().ok()?,
            minor: minor.parse().ok()?,
        },
        kind: classify(rwbs, sectors),
        // A flush completes at sector -1 with no length; it carries no data.
        sector: if sectors == 0 {
            0
        } else {
            sector.parse().ok()?
        },
        sectors,
    })
}

/// Check that the completion tracepoint's `format` file has the layout
/// [`parse_line`] understands; refuse it otherwise.
pub fn check_completion_format(format: &str) -> std::result::Result<(), String> {
    for field in [
        "field:dev_t dev;",
        "field:sector_t sector;",
        "field:unsigned int nr_sector;",
        "field:char rwbs[",
    ] {
        if !format.contains(field) {
            return Err(format!("the completion tracepoint has no `{field}` field"));
        }
    }
    let Some(print) = format.lines().find(|line| line.starts_with("print fmt:")) else {
        return Err("the completion tracepoint has no print format".to_owned());
    };
    if !print.starts_with(COMPLETE_PRINT_PREFIX) {
        return Err(format!("unrecognised completion print format: {print}"));
    }
    if !print.contains("(REC->dev) >> 20") {
        return Err("device numbers are not printed with 20 minor bits".to_owned());
    }
    Ok(())
}

/// Check that the tracepoint's `format` file has the layout [`parse_line`]
/// understands; refuse it otherwise.
pub fn check_format(format: &str) -> std::result::Result<(), String> {
    for field in [
        "field:dev_t dev;",
        "field:sector_t sector;",
        "field:unsigned int nr_sector;",
        "field:char rwbs[",
    ] {
        if !format.contains(field) {
            return Err(format!("the tracepoint has no `{field}` field"));
        }
    }
    let Some(print) = format.lines().find(|line| line.starts_with("print fmt:")) else {
        return Err("the tracepoint has no print format".to_owned());
    };
    if !print.starts_with(PRINT_FORMAT) {
        return Err(format!("unrecognised print format: {print}"));
    }
    if !print.contains("(REC->dev) >> 20") {
        return Err("device numbers are not printed with 20 minor bits".to_owned());
    }
    Ok(())
}

/// One region whose writes are tracked: a source partition on a disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrackedRegion {
    /// The whole disk's device number (events name it after remapping).
    pub whole: DevNumber,
    /// The partition's own device number, when the region is a partition.
    pub part: Option<DevNumber>,
    /// First sector of the region on the whole disk.
    pub start_sector: u64,
    /// Length of the region in sectors.
    pub sectors: u64,
}

/// A bitmap of the chunks of one region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkBits {
    words: Vec<u64>,
    chunks: u64,
    set: u64,
}

impl ChunkBits {
    fn new(chunks: u64) -> Self {
        // x86_64 only (spec §A.4): a u64 word count fits in usize.
        Self {
            words: vec![0; chunks.div_ceil(64) as usize],
            chunks,
            set: 0,
        }
    }

    /// Set chunks `first..=last`; `last < self.chunks` is the caller's invariant.
    fn set_range(&mut self, first: u64, last: u64) {
        debug_assert!(first <= last && last < self.chunks);
        let mut index = first;
        while index <= last {
            let word = (index / 64) as usize;
            let bit = index % 64;
            let span = (64 - bit).min(last - index + 1);
            let mask = if span == 64 {
                u64::MAX
            } else {
                ((1u64 << span) - 1) << bit
            };
            let before = self.words[word].count_ones();
            self.words[word] |= mask;
            self.set += u64::from(self.words[word].count_ones() - before);
            index += span;
        }
    }

    fn clear(&mut self) {
        self.words.fill(0);
        self.set = 0;
    }

    /// Number of chunks in the region.
    pub fn chunks(&self) -> u64 {
        self.chunks
    }

    /// Number of chunks that are set.
    pub fn count(&self) -> u64 {
        self.set
    }

    /// Whether `chunk` is set.
    pub fn contains(&self, chunk: u64) -> bool {
        chunk < self.chunks && self.words[(chunk / 64) as usize] & (1 << (chunk % 64)) != 0
    }

    /// Add every chunk of `other` (a bitmap of the same region).
    pub fn union_with(&mut self, other: &Self) {
        debug_assert_eq!(self.chunks, other.chunks);
        let mut set = 0;
        for (mine, theirs) in self.words.iter_mut().zip(&other.words) {
            *mine |= *theirs;
            set += u64::from(mine.count_ones());
        }
        self.set = set;
    }

    /// The set chunks, ascending.
    pub fn iter(&self) -> impl Iterator<Item = u64> + '_ {
        self.words
            .iter()
            .enumerate()
            .flat_map(|(word_index, &word)| {
                let base = word_index as u64 * 64;
                let mut bits = word;
                std::iter::from_fn(move || {
                    if bits == 0 {
                        return None;
                    }
                    let bit = u64::from(bits.trailing_zeros());
                    bits &= bits - 1;
                    Some(base + bit)
                })
            })
    }
}

/// Dirty chunks of every tracked region, filled from bio events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirtyMap {
    chunk_sectors: u64,
    regions: Vec<TrackedRegion>,
    bits: Vec<ChunkBits>,
}

impl DirtyMap {
    /// A map for `regions` with chunks of `chunk_bytes`, all clean.
    pub fn new(regions: Vec<TrackedRegion>, chunk_bytes: u64) -> Result<Self> {
        if chunk_bytes == 0 || !chunk_bytes.is_multiple_of(SECTOR_BYTES) {
            return Err(Error::unsupported(format!(
                "a tracking chunk of {chunk_bytes} bytes is not a whole number of sectors"
            )));
        }
        let chunk_sectors = chunk_bytes / SECTOR_BYTES;
        let mut bits = Vec::with_capacity(regions.len());
        for region in &regions {
            if region.sectors == 0 || region.start_sector.checked_add(region.sectors).is_none() {
                return Err(Error::unsupported(format!(
                    "a tracked region of {} sectors at {} is not valid",
                    region.sectors, region.start_sector
                )));
            }
            bits.push(ChunkBits::new(region.sectors.div_ceil(chunk_sectors)));
        }
        Ok(Self {
            chunk_sectors,
            regions,
            bits,
        })
    }

    /// The regions, in the order they were given.
    pub fn regions(&self) -> &[TrackedRegion] {
        &self.regions
    }

    /// The chunk bitmaps, one per region.
    pub fn bits(&self) -> &[ChunkBits] {
        &self.bits
    }

    /// Dirty chunks over all regions.
    pub fn count(&self) -> u64 {
        self.bits.iter().map(ChunkBits::count).sum()
    }

    /// Mark the chunks an event can change. Reads and data-less bios, and
    /// events for other devices, change nothing.
    pub fn record(&mut self, event: &BioEvent) {
        if event.kind != BioKind::Dirtying {
            return;
        }
        for (region, bits) in self.regions.iter().zip(self.bits.iter_mut()) {
            let start = if event.dev == region.whole {
                event.sector
            } else if Some(event.dev) == region.part {
                region.start_sector.saturating_add(event.sector)
            } else {
                continue;
            };
            let end = start.saturating_add(event.sectors);
            let low = start.max(region.start_sector);
            let high = end.min(region.start_sector + region.sectors);
            if low >= high {
                continue;
            }
            let first = (low - region.start_sector) / self.chunk_sectors;
            let last = (high - region.start_sector - 1) / self.chunk_sectors;
            bits.set_range(first, last);
        }
    }

    /// Move every dirty chunk into `out` (a map of the same shape) and leave
    /// this map clean. `out`'s previous contents are discarded.
    pub fn take_into(&mut self, out: &mut DirtyMap) {
        debug_assert_eq!(self.regions, out.regions);
        for (mine, theirs) in self.bits.iter_mut().zip(out.bits.iter_mut()) {
            std::mem::swap(mine, theirs);
            mine.clear();
        }
    }

    /// Add every dirty chunk of `other` (a map of the same shape).
    pub fn union_with(&mut self, other: &DirtyMap) {
        debug_assert_eq!(self.regions, other.regions);
        for (mine, theirs) in self.bits.iter_mut().zip(&other.bits) {
            mine.union_with(theirs);
        }
    }

    /// A clean map of the same shape, for [`DirtyMap::take_into`].
    pub fn empty_like(&self) -> DirtyMap {
        let mut copy = self.clone();
        for bits in &mut copy.bits {
            bits.clear();
        }
        copy
    }
}

/// Events the kernel or the consumer lost: any nonzero count means the
/// tracked copy cannot be trusted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Losses {
    /// Events overwritten before they were read (ring buffer overrun).
    pub overrun: u64,
    /// Events the ring buffer dropped.
    pub dropped: u64,
    /// Events lost while being committed.
    pub commit_overrun: u64,
    /// Tracepoint lines the consumer could not parse.
    pub malformed: u64,
}

impl Losses {
    /// No event was lost or misread.
    pub fn is_clean(&self) -> bool {
        *self == Self::default()
    }
}

/// A private ftrace instance with the tracepoint enabled for some devices.
///
/// It is removed in `Drop`; [`sweep`] removes instances a killed process
/// left behind.
#[derive(Debug)]
pub struct TraceInstance {
    dir: PathBuf,
}

impl TraceInstance {
    /// Create `instances/<name>` under `tracefs`, size its per-CPU buffers,
    /// filter the tracepoint to `devices` and enable it.
    pub fn create(
        tracefs: &Path,
        name: &str,
        buffer_kb: u32,
        devices: &[DevNumber],
    ) -> Result<Self> {
        if !name.starts_with(INSTANCE_PREFIX)
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(Error::unsupported(format!(
                "trace instance name {name:?} must start with {INSTANCE_PREFIX:?} and use [a-z0-9-]"
            )));
        }
        if devices.is_empty() || buffer_kb == 0 {
            return Err(Error::unsupported(
                "a trace instance needs at least one device and a buffer",
            ));
        }
        let format = fs::read_to_string(tracefs.join("events").join(TRACEPOINT).join("format"))
            .map_err(|error| {
                Error::unsupported(format!(
                    "the {TRACEPOINT} tracepoint is unavailable: {error}"
                ))
            })?;
        check_format(&format).map_err(Error::unsupported)?;
        let completion = fs::read_to_string(
            tracefs
                .join("events")
                .join(COMPLETION_TRACEPOINT)
                .join("format"),
        )
        .map_err(|error| {
            Error::unsupported(format!(
                "the {COMPLETION_TRACEPOINT} tracepoint is unavailable: {error}"
            ))
        })?;
        check_completion_format(&completion).map_err(Error::unsupported)?;

        let dir = tracefs.join("instances").join(name);
        fs::create_dir(&dir).map_err(|error| {
            Error::unsupported(format!(
                "cannot create the trace instance {}: {error}",
                dir.display()
            ))
        })?;
        // From here on `Drop` removes the instance, whatever fails next.
        let instance = Self { dir };
        let filter = devices
            .iter()
            .map(|dev| format!("dev == {}", dev.kernel()))
            .collect::<Vec<_>>()
            .join(" || ");
        instance.write("tracing_on", "0")?;
        instance.write("buffer_size_kb", &buffer_kb.to_string())?;
        for event in [TRACEPOINT, COMPLETION_TRACEPOINT] {
            instance.write(&format!("events/{event}/filter"), &filter)?;
            instance.write(&format!("events/{event}/enable"), "1")?;
        }
        instance.write("tracing_on", "1")?;
        Ok(instance)
    }

    /// The instance directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn write(&self, relative: &str, value: &str) -> Result<()> {
        let path = self.dir.join(relative);
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(false)
            .open(&path)
            .map_err(|error| tracefs_error(&path, &error))?;
        file.write_all(value.as_bytes())
            .map_err(|error| tracefs_error(&path, &error))
    }

    /// Open the instance's consuming pipe (blocking reads).
    pub fn open_pipe(&self) -> Result<File> {
        let path = self.dir.join("trace_pipe");
        File::open(&path).map_err(|error| tracefs_error(&path, &error))
    }

    /// Write a drain marker; it reaches the pipe after every event committed
    /// before this call, because the pipe returns events in timestamp order.
    pub fn mark(&self, seq: u64) -> Result<()> {
        self.write("trace_marker", &format!("LR-DRAIN-{seq}\n"))
    }

    /// The ring buffer's loss counters, summed over every CPU.
    pub fn losses(&self) -> Result<Losses> {
        let per_cpu = self.dir.join("per_cpu");
        let entries = fs::read_dir(&per_cpu).map_err(|error| tracefs_error(&per_cpu, &error))?;
        let mut losses = Losses::default();
        for entry in entries {
            let entry = entry.map_err(|error| tracefs_error(&per_cpu, &error))?;
            let stats = entry.path().join("stats");
            let text = fs::read_to_string(&stats).map_err(|error| tracefs_error(&stats, &error))?;
            add_stats(&text, &mut losses);
        }
        Ok(losses)
    }
}

fn add_stats(text: &str, losses: &mut Losses) {
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let Some(value) = value
            .split_ascii_whitespace()
            .next()
            .and_then(|number| number.parse::<u64>().ok())
        else {
            continue;
        };
        match key.trim() {
            "overrun" => losses.overrun += value,
            "dropped events" => losses.dropped += value,
            "commit overrun" => losses.commit_overrun += value,
            _ => {}
        }
    }
}

impl Drop for TraceInstance {
    fn drop(&mut self) {
        let _ = self.write("tracing_on", "0");
        for event in [TRACEPOINT, COMPLETION_TRACEPOINT] {
            let _ = self.write(&format!("events/{event}/enable"), "0");
        }
        remove_instance_dir(&self.dir);
    }
}

fn remove_instance_dir(dir: &Path) {
    // The kernel refuses while a reader still holds the pipe open.
    for _ in 0..50 {
        match fs::remove_dir(dir) {
            Ok(()) => return,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return,
            Err(_) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    tracing::warn!("could not remove the trace instance {}", dir.display());
}

fn tracefs_error(path: &Path, error: &io::Error) -> Error {
    Error::unsupported(format!("tracefs {}: {error}", path.display()))
}

/// Remove the provider's instances that a killed process left behind; they
/// are named with [`INSTANCE_PREFIX`]. Returns the removed directories.
pub fn sweep(tracefs: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(tracefs.join("instances")) else {
        return Vec::new();
    };
    let mut removed = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        if !name.to_string_lossy().starts_with(INSTANCE_PREFIX) {
            continue;
        }
        let dir = entry.path();
        let _ = fs::write(dir.join("tracing_on"), "0");
        for event in [TRACEPOINT, COMPLETION_TRACEPOINT] {
            let _ = fs::write(dir.join("events").join(event).join("enable"), "0");
        }
        remove_instance_dir(&dir);
        if !dir.exists() {
            removed.push(dir);
        }
    }
    removed
}

/// The tracefs mount point: `LR_TRACEFS_ROOT` for tests, else
/// `/sys/kernel/tracing`, else the legacy `/sys/kernel/debug/tracing`.
pub fn tracefs_root() -> Option<PathBuf> {
    if let Some(root) = std::env::var_os("LR_TRACEFS_ROOT") {
        return Some(PathBuf::from(root));
    }
    ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"]
        .into_iter()
        .map(PathBuf::from)
        .find(|root| root.join("instances").is_dir())
}

#[derive(Debug)]
struct State {
    map: DirtyMap,
    marker: u64,
    malformed: u64,
    stop: bool,
    /// Test builds only can set it: the reader stops reading the pipe.
    paused: bool,
    reader_error: Option<String>,
}

#[derive(Debug)]
struct Shared {
    state: Mutex<State>,
    changed: Condvar,
}

impl Shared {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A trace instance plus the consumer thread that keeps its dirty map.
#[derive(Debug)]
pub struct Tracker {
    shared: Arc<Shared>,
    // The reader owns the pipe. `Drop` joins it before the instance is
    // removed, because the kernel keeps an instance whose pipe is open.
    reader: Option<JoinHandle<()>>,
    instance: TraceInstance,
    next_marker: u64,
}

impl Tracker {
    /// Start tracking `regions` with chunks of `chunk_bytes`, through a new
    /// instance `name` under `tracefs` with `buffer_kb` per CPU.
    pub fn start(
        tracefs: &Path,
        name: &str,
        regions: Vec<TrackedRegion>,
        chunk_bytes: u64,
        buffer_kb: u32,
    ) -> Result<Self> {
        let map = DirtyMap::new(regions, chunk_bytes)?;
        let mut devices: Vec<DevNumber> = Vec::new();
        for region in map.regions() {
            for dev in [Some(region.whole), region.part].into_iter().flatten() {
                if !devices.contains(&dev) {
                    devices.push(dev);
                }
            }
        }
        let instance = TraceInstance::create(tracefs, name, buffer_kb, &devices)?;
        let pipe = instance.open_pipe()?;
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                map,
                marker: 0,
                malformed: 0,
                stop: false,
                paused: false,
                reader_error: None,
            }),
            changed: Condvar::new(),
        });
        let consumer = Arc::clone(&shared);
        let reader = std::thread::Builder::new()
            .name(format!("{name}-reader"))
            .spawn(move || consume(pipe, &consumer))
            .map_err(Error::Io)?;
        Ok(Self {
            shared,
            reader: Some(reader),
            instance,
            next_marker: 0,
        })
    }

    /// Wait until every event committed before this call is in the dirty map.
    pub fn drain(&mut self, timeout: Duration) -> Result<()> {
        self.next_marker += 1;
        let seq = self.next_marker;
        self.instance.mark(seq)?;
        let deadline = Instant::now() + timeout;
        let mut state = self.shared.lock();
        loop {
            if state.marker >= seq {
                return Ok(());
            }
            if let Some(error) = &state.reader_error {
                return Err(Error::TrackingLost {
                    reason: format!("the trace reader stopped: {error}"),
                });
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(Error::TrackingLost {
                    reason: format!("the trace reader did not reach marker {seq} in time"),
                });
            }
            state = self
                .shared
                .changed
                .wait_timeout(state, deadline - now)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// Move the dirty chunks gathered so far into `out` (see
    /// [`DirtyMap::take_into`]). Call [`Tracker::drain`] first.
    pub fn take_into(&self, out: &mut DirtyMap) {
        self.shared.lock().map.take_into(out);
    }

    /// A clean map of the tracker's shape.
    pub fn empty_map(&self) -> DirtyMap {
        self.shared.lock().map.empty_like()
    }

    /// Stop or resume reading the pipe, so the ring buffer overflows (tests).
    #[cfg(feature = "fault-injection")]
    pub fn pause_reader(&self, paused: bool) {
        self.shared.lock().paused = paused;
    }

    /// Every loss so far; the copy is trustworthy only when it is clean.
    pub fn integrity(&self) -> Result<Losses> {
        let mut losses = self.instance.losses()?;
        losses.malformed = self.shared.lock().malformed;
        Ok(losses)
    }
}

impl Drop for Tracker {
    fn drop(&mut self) {
        {
            let mut state = self.shared.lock();
            state.stop = true;
            state.paused = false;
        }
        // Wake the reader with a marker while tracing is still on. If the
        // marker cannot be written the reader may never wake: leave it
        // detached rather than hang (the instance is then left for `sweep`).
        let woken = self.instance.mark(u64::MAX).is_ok();
        if let Some(reader) = self.reader.take()
            && woken
        {
            let _ = reader.join();
        }
    }
}

fn consume(pipe: File, shared: &Shared) {
    let mut reader = BufReader::with_capacity(1 << 16, pipe);
    let mut line = String::with_capacity(256);
    loop {
        line.clear();
        let failure = match reader.read_line(&mut line) {
            Ok(0) => Some("trace_pipe closed".to_owned()),
            Ok(_) => None,
            Err(error) => Some(error.to_string()),
        };
        let mut state = shared.lock();
        if let Some(failure) = failure {
            state.reader_error = Some(failure);
            shared.changed.notify_all();
            return;
        }
        match parse_line(&line) {
            Line::Bio(event) => state.map.record(&event),
            Line::Marker(seq) => {
                state.marker = state.marker.max(seq);
                shared.changed.notify_all();
            }
            Line::Malformed => state.malformed += 1,
            Line::Other => {}
        }
        if state.stop {
            return;
        }
        while state.paused && !state.stop {
            drop(state);
            std::thread::sleep(Duration::from_millis(20));
            state = shared.lock();
        }
    }
}

/// What [`self_test`] observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfTest {
    /// The kernel the test ran on.
    pub kernel: String,
    /// A data write was reported for the whole disk at its absolute sector.
    pub write_mapped: bool,
    /// A discard was issued and dirtied its range (`None`: the loop device
    /// could not discard, so it was not checked).
    pub discard_mapped: Option<bool>,
    /// A write-zeroes was issued and dirtied its range (`None` as above).
    pub write_zeroes_mapped: Option<bool>,
    /// The ring buffer lost nothing during the test.
    pub losses: Losses,
}

impl SelfTest {
    /// Every operation that was issued was tracked, and nothing was lost.
    pub fn passed(&self) -> bool {
        self.write_mapped
            && self.discard_mapped != Some(false)
            && self.write_zeroes_mapped != Some(false)
            && self.losses.is_clean()
    }
}

/// Check write tracking on this kernel with a private loop device backed by a
/// file in `workdir` (a tmpfs in production): a 4 KiB write, a discard and a
/// write-zeroes into its second partition must each dirty exactly the chunk
/// they hit, reported with the whole disk's device number. The backup source
/// is never touched. Needs root.
pub fn self_test(tracefs: &Path, workdir: &Path) -> Result<SelfTest> {
    const CHUNK: u64 = 64 * 1024;
    let image = workdir.join(format!("lr-tracking-self-test-{}.img", std::process::id()));
    let result = (|| {
        let file = File::create(&image).map_err(Error::Io)?;
        file.set_len(16 << 20).map_err(Error::Io)?;
        drop(file);
        run_with_input(
            "sfdisk",
            &["--quiet", &image.display().to_string()],
            "label: gpt\nstart=2048, size=4MiB\n,\n",
        )?;
        let device = SelfTestLoop::attach(&image)?;
        let tracked = device.region()?;
        let mut tracker = Tracker::start(
            tracefs,
            &format!("{INSTANCE_PREFIX}self-test-{}", std::process::id()),
            vec![tracked],
            CHUNK,
            256,
        )?;
        let mut taken = tracker.empty_map();
        tracker.drain(Duration::from_secs(5))?;
        tracker.take_into(&mut taken);

        // A 4 KiB write at 1 MiB into the partition: chunk 16.
        let fd = lr_unsafe::open_o_direct(&device.partition, true).map_err(Error::Io)?;
        let mut buf = lr_unsafe::AlignedBuf::new(4096, 4096).map_err(Error::Io)?;
        buf.as_mut_slice().fill(0xa5);
        lr_unsafe::pwrite_all(&fd, &buf, 4096, 1 << 20).map_err(Error::Io)?;
        lr_unsafe::fsync(&fd).map_err(Error::Io)?;
        drop(fd);
        tracker.drain(Duration::from_secs(5))?;
        tracker.take_into(&mut taken);
        let write_mapped = taken.bits()[0].iter().eq([16]);

        let partition = device.partition.display().to_string();
        let mut check = |args: &[&str], chunk: u64| -> Result<Option<bool>> {
            let issued = Command::new("blkdiscard")
                .args(args)
                .arg(&partition)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map_err(Error::Io)?
                .success();
            if !issued {
                return Ok(None);
            }
            tracker.drain(Duration::from_secs(5))?;
            tracker.take_into(&mut taken);
            Ok(Some(taken.bits()[0].iter().eq([chunk])))
        };
        // Discard and write-zeroes of 64 KiB at 2 MiB and 3 MiB: chunks 32, 48.
        let discard_mapped = check(&["-o", "2097152", "-l", "65536"], 32)?;
        let write_zeroes_mapped = check(&["-z", "-o", "3145728", "-l", "65536"], 48)?;
        let losses = tracker.integrity()?;
        drop(tracker);
        drop(device);
        Ok(SelfTest {
            kernel: fs::read_to_string("/proc/sys/kernel/osrelease")
                .map(|text| text.trim().to_owned())
                .unwrap_or_default(),
            write_mapped,
            discard_mapped,
            write_zeroes_mapped,
            losses,
        })
    })();
    let _ = fs::remove_file(&image);
    result
}

fn run_with_input(program: &str, args: &[&str], input: &str) -> Result<()> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| Error::unsupported(format!("{program}: {error}")))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input.as_bytes()).map_err(Error::Io)?;
    }
    let output = child.wait_with_output().map_err(Error::Io)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(Error::unsupported(format!(
            "{program} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

/// The self test's own loop device, detached in `Drop`.
struct SelfTestLoop {
    device: PathBuf,
    partition: PathBuf,
}

impl SelfTestLoop {
    fn attach(image: &Path) -> Result<Self> {
        // WSL and other udev-less hosts can briefly report no free device.
        let mut attached = None;
        for _ in 0..20 {
            let output = Command::new("losetup")
                .args(["--find", "--show", "--partscan"])
                .arg(image)
                .output()
                .map_err(|error| Error::unsupported(format!("losetup: {error}")))?;
            if output.status.success() {
                attached = Some(PathBuf::from(
                    String::from_utf8_lossy(&output.stdout).trim().to_owned(),
                ));
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let device = attached.ok_or_else(|| Error::unsupported("no free loop device"))?;
        let partition = PathBuf::from(format!("{}p2", device.display()));
        let looped = Self { device, partition };
        let _ = Command::new("blockdev")
            .arg("--rereadpt")
            .arg(&looped.device)
            .stderr(Stdio::null())
            .status();
        for _ in 0..100 {
            if looped.partition.exists() && looped.sysfs("start").is_some() {
                return Ok(looped);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Err(Error::unsupported(format!(
            "{} did not appear",
            looped.partition.display()
        )))
    }

    fn sysfs(&self, file: &str) -> Option<u64> {
        let name = self.partition.file_name()?.to_string_lossy().into_owned();
        fs::read_to_string(Path::new("/sys/class/block").join(name).join(file))
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    fn region(&self) -> Result<TrackedRegion> {
        use std::os::unix::fs::MetadataExt as _;
        let number = |path: &Path| -> Result<DevNumber> {
            let rdev = fs::metadata(path).map_err(Error::Io)?.rdev();
            Ok(DevNumber {
                major: (((rdev >> 32) & 0xffff_f000) | ((rdev >> 8) & 0x0000_0fff)) as u32,
                minor: (((rdev >> 12) & 0xffff_ff00) | (rdev & 0x0000_00ff)) as u32,
            })
        };
        Ok(TrackedRegion {
            whole: number(&self.device)?,
            part: Some(number(&self.partition)?),
            start_sector: self
                .sysfs("start")
                .ok_or_else(|| Error::unsupported("no partition start in sysfs"))?,
            sectors: self
                .sysfs("size")
                .ok_or_else(|| Error::unsupported("no partition size in sysfs"))?,
        })
    }
}

impl Drop for SelfTestLoop {
    fn drop(&mut self) {
        let _ = Command::new("losetup")
            .arg("--detach")
            .arg(&self.device)
            .status();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FORMAT: &str = include_str!(
        "../tests/fixtures/trace/block_bio_queue-6.18.58.1-microsoft-standard-WSL2.format"
    );
    const PIPE: &str = include_str!(
        "../tests/fixtures/trace/block_bio_queue-6.18.58.1-microsoft-standard-WSL2.pipe"
    );
    const EVENTS: &str =
        include_str!("../tests/fixtures/trace/block-events-6.18.58.1-microsoft-standard-WSL2.pipe");
    const COMPLETE_6_18: &str = include_str!(
        "../tests/fixtures/trace/block_rq_complete-6.18.58.1-microsoft-standard-WSL2.format"
    );
    const COMPLETE_6_8: &str =
        include_str!("../tests/fixtures/trace/block_rq_complete-6.8.0-138-generic.format");
    const LOOP: DevNumber = DevNumber { major: 7, minor: 0 };

    #[test]
    fn completion_formats_of_both_kernel_generations_are_accepted() {
        assert_eq!(check_completion_format(COMPLETE_6_18), Ok(()));
        assert_eq!(check_completion_format(COMPLETE_6_8), Ok(()));
        let reordered = COMPLETE_6_8.replace("%s (%s) %llu", "%s %llu (%s)");
        assert!(check_completion_format(&reordered).is_err());
    }

    #[test]
    fn completions_dirty_the_same_ranges_as_submissions() {
        // The capture: the same writes, discard and write-zeroes as the
        // queue-only fixture, now with their completions.
        let mut queued = Vec::new();
        let mut completed = Vec::new();
        for line in EVENTS.lines() {
            let Line::Bio(event) = parse_line(line) else {
                assert_ne!(parse_line(line), Line::Malformed, "{line}");
                continue;
            };
            if event.kind != BioKind::Dirtying {
                continue;
            }
            if line.contains("block_rq_complete") {
                completed.push((event.sector, event.sectors));
            } else {
                queued.push((event.sector, event.sectors));
            }
        }
        let expected = vec![
            (67584 + 2048, 8),
            (67584 + 8192, 128),
            (67584 + 16384, 2048),
            (67584 + 24576, 2048),
        ];
        assert_eq!(queued, expected);
        assert_eq!(completed, expected);
    }

    #[test]
    fn a_flush_completion_carries_no_data() {
        let flush = "ksoftirqd/1-181 [001] ..s.. 1.0: block_rq_complete: 7,0 FF () \
                     18446744073709551615 + 0 none,0,0 [0]";
        let Line::Bio(event) = parse_line(flush) else {
            panic!("not parsed");
        };
        assert_eq!(event.kind, BioKind::NoData);
        let old = "kworker-1 [002] ..s.. 1.0: block_rq_complete: 8,0 WS () 2048 + 8 [0]";
        assert_eq!(
            parse_line(old),
            Line::Bio(BioEvent {
                dev: DevNumber { major: 8, minor: 0 },
                kind: BioKind::Dirtying,
                sector: 2048,
                sectors: 8,
            })
        );
    }
    const LOOP_P2: DevNumber = DevNumber {
        major: 259,
        minor: 3,
    };

    #[test]
    fn the_recorded_format_is_accepted_and_changes_are_refused() {
        assert_eq!(check_format(FORMAT), Ok(()));
        let reordered = FORMAT.replace("%d,%d %s %llu + %u [%s]", "%d,%d %llu %s + %u [%s]");
        assert!(check_format(&reordered).is_err());
        let no_rwbs = FORMAT.replace("field:char rwbs[10]", "field:char flags[10]");
        assert!(check_format(&no_rwbs).is_err());
        let minor_bits = FORMAT.replace("(REC->dev) >> 20", "(REC->dev) >> 8");
        assert!(check_format(&minor_bits).is_err());
    }

    #[test]
    fn recorded_lines_parse_into_the_operations_the_kernel_issued() {
        // The capture: a 4 KiB write, a 64 KiB write, a read, an fsync flush,
        // a discard and a write-zeroes on loop0p2 (start 67584), udev's and
        // blkdiscard's own probing reads, then a marker.
        let mut dirtying = Vec::new();
        let mut reads = 0;
        let mut no_data = 0;
        let mut markers = Vec::new();
        for line in PIPE.lines() {
            match parse_line(line) {
                Line::Bio(event) => {
                    assert_eq!(event.dev, LOOP, "{line}");
                    match event.kind {
                        BioKind::Dirtying => dirtying.push((event.sector, event.sectors)),
                        BioKind::Read => reads += 1,
                        BioKind::NoData => no_data += 1,
                    }
                }
                Line::Marker(seq) => markers.push(seq),
                Line::Malformed => panic!("malformed: {line}"),
                Line::Other => {}
            }
        }
        assert_eq!(
            dirtying,
            vec![
                (67584 + 2048, 8),
                (67584 + 8192, 128),
                (67584 + 16384, 2048),
                (67584 + 24576, 2048),
            ],
            "write, write, discard (DS) and write-zeroes (NS) all dirty"
        );
        assert!(reads > 0);
        assert_eq!(no_data, 1, "the fsync preflush (FWS 0 + 0) carries no data");
        assert_eq!(markers, vec![9]);
    }

    #[test]
    fn classification_is_conservative() {
        assert_eq!(classify("R", 8), BioKind::Read);
        assert_eq!(classify("RAM", 8), BioKind::Read);
        assert_eq!(classify("W", 8), BioKind::Dirtying);
        assert_eq!(classify("FWFS", 8), BioKind::Dirtying);
        assert_eq!(classify("DE", 8), BioKind::Dirtying);
        assert_eq!(classify("N", 8), BioKind::Dirtying);
        assert_eq!(
            classify("X", 8),
            BioKind::Dirtying,
            "an unknown operation dirties"
        );
        assert_eq!(classify("F", 0), BioKind::NoData);
        assert_eq!(classify("FR", 8), BioKind::Read);
    }

    #[test]
    fn a_line_naming_the_tracepoint_that_does_not_parse_is_malformed() {
        assert_eq!(
            parse_line("x-1 [000] ..... 1.0: block_bio_queue: 7,0 W 12 - 8 [x]"),
            Line::Malformed
        );
        assert_eq!(
            parse_line("x-1 [000] ..... 1.0: block_bio_queue: 7 W 12 + 8 [x]"),
            Line::Malformed
        );
        assert_eq!(
            parse_line("x-1 [000] ..... 1.0: sched_switch: a"),
            Line::Other
        );
    }

    fn region() -> TrackedRegion {
        TrackedRegion {
            whole: LOOP,
            part: Some(LOOP_P2),
            start_sector: 67584,
            sectors: 8 * 2048, // 8 MiB
        }
    }

    fn write(dev: DevNumber, sector: u64, sectors: u64) -> BioEvent {
        BioEvent {
            dev,
            kind: BioKind::Dirtying,
            sector,
            sectors,
        }
    }

    #[test]
    fn events_map_to_chunks_of_the_region() {
        let mut map = DirtyMap::new(vec![region()], 1 << 20).expect("map");
        assert_eq!(map.bits()[0].chunks(), 8);
        // Whole-disk event, absolute sector: chunk 1.
        map.record(&write(LOOP, 67584 + 2048, 8));
        // Partition-relative event: chunk 3.
        map.record(&write(LOOP_P2, 3 * 2048 + 5, 1));
        // Spanning chunks 5..=6.
        map.record(&write(LOOP, 67584 + 5 * 2048 + 2040, 16));
        // Before the region, after it, another device, a read: nothing.
        map.record(&write(LOOP, 0, 2048));
        map.record(&write(LOOP, 67584 + 8 * 2048, 2048));
        map.record(&write(DevNumber { major: 8, minor: 0 }, 67584, 8));
        map.record(&BioEvent {
            kind: BioKind::Read,
            ..write(LOOP, 67584, 8)
        });
        // Straddling the region's start: chunk 0.
        map.record(&write(LOOP, 67584 - 4, 8));
        assert_eq!(
            map.bits()[0].iter().collect::<Vec<_>>(),
            vec![0, 1, 3, 5, 6]
        );
        assert_eq!(map.count(), 5);
    }

    #[test]
    fn a_large_discard_sets_whole_words_and_counts_once() {
        let big = TrackedRegion {
            sectors: 1000 * 2048,
            ..region()
        };
        let mut map = DirtyMap::new(vec![big], 1 << 20).expect("map");
        map.record(&write(LOOP, 67584 + 10 * 2048, 900 * 2048));
        map.record(&write(LOOP, 67584 + 10 * 2048, 900 * 2048));
        assert_eq!(map.count(), 900);
        assert!(map.bits()[0].contains(10) && map.bits()[0].contains(909));
        assert!(!map.bits()[0].contains(9) && !map.bits()[0].contains(910));
    }

    #[test]
    fn take_moves_the_dirty_chunks_and_union_merges_them() {
        let mut map = DirtyMap::new(vec![region()], 1 << 20).expect("map");
        let mut taken = map.empty_like();
        map.record(&write(LOOP, 67584, 8));
        map.take_into(&mut taken);
        assert_eq!(map.count(), 0);
        assert_eq!(taken.count(), 1);
        map.record(&write(LOOP, 67584 + 7 * 2048, 8));
        let mut last = map.empty_like();
        map.take_into(&mut last);
        last.union_with(&taken);
        assert_eq!(last.bits()[0].iter().collect::<Vec<_>>(), vec![0, 7]);
    }

    #[test]
    fn regions_and_chunks_are_validated() {
        assert!(DirtyMap::new(vec![region()], 0).is_err());
        assert!(DirtyMap::new(vec![region()], 1000).is_err());
        let empty = TrackedRegion {
            sectors: 0,
            ..region()
        };
        assert!(DirtyMap::new(vec![empty], 1 << 20).is_err());
        // A tail shorter than a chunk is its own chunk.
        let odd = TrackedRegion {
            sectors: 2048 + 1,
            ..region()
        };
        assert_eq!(
            DirtyMap::new(vec![odd], 1 << 20).expect("map").bits()[0].chunks(),
            2
        );
    }

    #[test]
    fn ring_buffer_stats_are_summed() {
        let mut losses = Losses::default();
        add_stats(
            "entries: 10\noverrun: 3\ncommit overrun: 0\nbytes: 4096\n\
             oldest event ts: 1.0\nnow ts: 2.0\ndropped events: 1\nread events: 9\n",
            &mut losses,
        );
        add_stats("overrun: 2\ndropped events: 0\n", &mut losses);
        assert_eq!(losses.overrun, 5);
        assert_eq!(losses.dropped, 1);
        assert!(!losses.is_clean());
        assert!(Losses::default().is_clean());
    }

    #[test]
    fn instance_names_are_restricted() {
        let root = tempfile::tempdir().expect("root");
        for bad in ["sneaky", "lr-../x", "lr-UPPER", "lr-a b"] {
            assert!(
                TraceInstance::create(root.path(), bad, 64, &[LOOP]).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_kernel_without_the_tracepoint_is_refused() {
        let root = tempfile::tempdir().expect("root");
        std::fs::create_dir(root.path().join("instances")).expect("instances");
        let error =
            TraceInstance::create(root.path(), "lr-test", 64, &[LOOP]).expect_err("no tracepoint");
        assert!(error.to_string().contains("unavailable"), "{error}");
        assert!(!root.path().join("instances/lr-test").exists());
    }

    #[test]
    fn dev_numbers_use_twenty_minor_bits() {
        assert_eq!(LOOP.kernel(), 7 << 20);
        assert_eq!(LOOP_P2.kernel(), (259 << 20) | 3);
    }
}
