//! The LVM snapshot provider (spec §E.2).
//!
//! Classic and thin snapshots are created with `lvcreate -s`; LVM suspends the
//! origin for the instant of creation, so the snapshot is a point-in-time image
//! (`Consistency::PointInTime`). A monitor thread watches the snapshot's COW
//! usage and aborts the job at 90 %, because an overflowed classic snapshot is
//! invalid. `Drop` always removes the snapshot LV, and a sweep at the start of
//! every job removes snapshots whose owning process is gone — that is what
//! keeps `kill -9` from leaking LVs.

use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use lr_core::{Consistency, Error, LvmFacts, Result, SnapshotOpts, SourceLayout, Support};

use crate::{BlockSnapshot, BlockSnapshotProvider, SnapshotHealth};

/// Provider identifier.
pub const ID: &str = "lvm";

/// Tag every snapshot gets, so the sweep can recognise them.
pub const SNAPSHOT_TAG: &str = "linuxreflect";

/// Tag carrying the owner as `<pid>:<starttime>`.
pub const OWNER_TAG_PREFIX: &str = "owner=";

/// Abort threshold for snapshot usage (spec §E.2).
pub const OVERFLOW_PERCENT: f64 = 90.0;

/// How often the snapshot usage is checked (spec §E.2).
pub const MONITOR_INTERVAL: Duration = Duration::from_secs(5);

/// Largest COW size that is still reasonable: 10 % of the origin.
pub const DEFAULT_COW_FRACTION: f64 = 0.10;

/// Smallest COW size the provider will create.
pub const MIN_COW_BYTES: u64 = 1024 * 1024 * 1024;

static PROVIDER: LvmProvider = LvmProvider;
static JOB_COUNTER: AtomicU64 = AtomicU64::new(0);

/// The LVM provider.
#[derive(Debug, Default, Clone, Copy)]
pub struct LvmProvider;

/// The shared instance.
#[must_use]
pub fn provider() -> &'static LvmProvider {
    &PROVIDER
}

impl BlockSnapshotProvider for LvmProvider {
    fn id(&self) -> &'static str {
        ID
    }

    fn supports(&self, src: &SourceLayout, opts: &SnapshotOpts) -> Support {
        if let Some(name) = opts.provider.as_deref().filter(|name| *name != "auto")
            && name != ID
        {
            return Support::No(format!("another provider ({name}) was requested"));
        }
        match volume_of(src) {
            Ok(_) if tools_available() => Support::Yes,
            Ok(_) => Support::No("lvm2 tools (lvcreate/lvs/lvremove) are not installed".to_owned()),
            Err(reason) => Support::No(reason),
        }
    }

    fn create(&self, src: &SourceLayout, opts: &SnapshotOpts) -> Result<BlockSnapshot> {
        let volume = volume_of(src).map_err(Error::unsupported)?;
        if !tools_available() {
            return Err(Error::unsupported("lvm2 tools are not installed"));
        }
        // Remove snapshots left behind by killed jobs before creating ours.
        if let Err(error) = sweep_stale(&volume.vg) {
            tracing::warn!(%error, "could not sweep stale snapshots");
        }

        let segtype = segment_type(&volume).unwrap_or_default();
        let thin = segtype.contains("thin");
        let job = format!(
            "lr-{}-{}",
            std::process::id(),
            JOB_COUNTER.fetch_add(1, Ordering::SeqCst)
        );

        if thin {
            run_lvm("lvcreate", &["-s", "-n", &job, &volume.path()])?;
            run_lvm(
                "lvchange",
                &["-K", "-ay", &format!("/dev/{}/{job}", volume.vg)],
            )?;
        } else {
            let size = cow_size(&volume, opts)?;
            run_lvm(
                "lvcreate",
                &["-s", "-n", &job, "-L", &format!("{size}B"), &volume.path()],
            )?;
        }

        let snapshot = format!("{}/{}", volume.vg, job);
        let owner = owner_tag()?;
        if let Err(error) = run_lvm(
            "lvchange",
            &[
                "--addtag",
                SNAPSHOT_TAG,
                "--addtag",
                &owner,
                &format!("/dev/{snapshot}"),
            ],
        ) {
            let _ = run_lvm("lvremove", &["-f", &format!("/dev/{snapshot}")]);
            return Err(error);
        }

        let block_path = device_path(&volume.vg, &job)
            .unwrap_or_else(|| PathBuf::from(format!("/dev/{snapshot}")));
        let monitor = Arc::new(Monitor::start(&volume, &job, thin)?);
        Ok(BlockSnapshot::new(
            block_path,
            Consistency::PointInTime,
            LvmGuard {
                vg: volume.vg.clone(),
                job,
                monitor: Some(Arc::clone(&monitor)),
            },
        )
        .with_health(monitor))
    }
}

/// The origin logical volume.
struct Volume {
    vg: String,
    lv: String,
}

impl Volume {
    fn path(&self) -> String {
        format!("/dev/{}/{}", self.vg, self.lv)
    }
}

fn volume_of(src: &SourceLayout) -> std::result::Result<Volume, String> {
    let Some(facts) = src.lvm.as_ref() else {
        return Err("the device is not a device-mapper LVM volume".to_owned());
    };
    if !facts.is_dm {
        return Err(facts_refusal(facts));
    }
    match (&facts.vg_name, &facts.lv_name) {
        (Some(vg), Some(lv)) => Ok(Volume {
            vg: vg.clone(),
            lv: lv.clone(),
        }),
        _ => Err("cannot determine the volume group and logical volume names".to_owned()),
    }
}

fn facts_refusal(facts: &LvmFacts) -> String {
    if facts.is_pv {
        "the device is an LVM physical volume; snapshot the logical volume instead".to_owned()
    } else {
        "the device is not an LVM logical volume".to_owned()
    }
}

fn tools_available() -> bool {
    ["lvcreate", "lvs", "lvremove", "lvchange"]
        .iter()
        .all(|tool| which(tool))
}

fn which(program: &str) -> bool {
    Command::new("which")
        .arg(program)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn run_lvm(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(Error::Io)?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::Io(std::io::Error::other(format!(
            "{program} {} failed: {}",
            args.join(" "),
            stderr.trim()
        ))));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Run `lvs`/`vgs` with a field list and return the trimmed stdout.
fn lvm_field(program: &str, fields: &str, target: &str) -> Result<String> {
    run_lvm(
        program,
        &[
            "--noheadings",
            "--units",
            "b",
            "--nosuffix",
            "--separator",
            "|",
            "-o",
            fields,
            target,
        ],
    )
}

fn segment_type(volume: &Volume) -> Option<String> {
    lvm_field("lvs", "segtype", &volume.path())
        .ok()
        .map(|text| text.trim().to_owned())
}

fn device_path(vg: &str, job: &str) -> Option<PathBuf> {
    let dm = lvm_field("lvs", "lv_dm_path", &format!("{vg}/{job}")).ok()?;
    let dm = dm.trim();
    if dm.is_empty() {
        None
    } else {
        Some(PathBuf::from(dm))
    }
}

/// COW size for a classic snapshot: the override, or 10 % of the origin with a
/// 1 GiB floor, capped by the volume group's free space.
fn cow_size(volume: &Volume, opts: &SnapshotOpts) -> Result<u64> {
    let origin: u64 = lvm_field("lvs", "lv_size", &volume.path())?
        .trim()
        .parse()
        .map_err(|_| Error::Io(std::io::Error::other("cannot read the origin size")))?;
    let free: u64 = lvm_field("vgs", "vg_free", &volume.vg)?
        .trim()
        .parse()
        .map_err(|_| {
            Error::Io(std::io::Error::other(
                "cannot read the volume group free space",
            ))
        })?;

    let requested = match opts.lvm_cow_size.as_deref() {
        // An explicit override is honoured as given (a percentage is relative
        // to the origin), so a test can build a snapshot small enough to
        // overflow on purpose.
        Some(text) => parse_size(text, origin)?,
        None => ((origin as f64 * DEFAULT_COW_FRACTION) as u64).max(MIN_COW_BYTES),
    };
    let size = requested.min(free);
    if size < 1024 * 1024 {
        return Err(Error::NoSpace);
    }
    Ok(size)
}

/// Parse `10%`, `512M`, `2G` or a plain byte count.
///
/// A percentage is taken of `origin` bytes.
///
/// # Errors
/// Returns [`Error::Unsupported`] for an unparseable size.
pub fn parse_size(text: &str, origin: u64) -> Result<u64> {
    let text = text.trim();
    if let Some(percent) = text.strip_suffix('%') {
        let percent: f64 = percent
            .trim()
            .parse()
            .map_err(|_| Error::unsupported(format!("bad COW size '{text}'")))?;
        return Ok((percent / 100.0 * origin as f64) as u64);
    }
    let (digits, multiplier) = if let Some(rest) = text.strip_suffix(['G', 'g']) {
        (rest, 1024u64 * 1024 * 1024)
    } else if let Some(rest) = text.strip_suffix(['M', 'm']) {
        (rest, 1024 * 1024)
    } else if let Some(rest) = text.strip_suffix(['K', 'k']) {
        (rest, 1024)
    } else {
        (text, 1)
    };
    digits
        .trim()
        .parse::<u64>()
        .map(|value| value.saturating_mul(multiplier))
        .map_err(|_| Error::unsupported(format!("bad COW size '{text}'")))
}

/// The current process's `pid:starttime`, so a sweep can tell whether an owner
/// is still alive.
fn owner_tag() -> Result<String> {
    let stat = std::fs::read_to_string("/proc/self/stat").map_err(Error::Io)?;
    // Field 22 is the start time; the command name may contain spaces, so count
    // from the last ')'.
    let after = stat
        .rsplit_once(')')
        .map(|(_, rest)| rest)
        .ok_or_else(|| Error::Io(std::io::Error::other("malformed /proc/self/stat")))?;
    let fields: Vec<&str> = after.split_whitespace().collect();
    let starttime = fields
        .get(19)
        .ok_or_else(|| Error::Io(std::io::Error::other("/proc/self/stat is too short")))?;
    Ok(format!(
        "{OWNER_TAG_PREFIX}{}:{starttime}",
        std::process::id()
    ))
}

/// `true` when the process recorded in an owner tag is still running.
fn owner_alive(tag: &str) -> bool {
    let Some(rest) = tag.strip_prefix(OWNER_TAG_PREFIX) else {
        return true;
    };
    let Some((pid, starttime)) = rest.split_once(':') else {
        return true;
    };
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    let Some((_, after)) = stat.rsplit_once(')') else {
        return false;
    };
    let fields: Vec<&str> = after.split_whitespace().collect();
    fields.get(19).is_some_and(|current| *current == starttime)
}

/// Remove snapshots this provider created whose owning process is gone.
///
/// # Errors
/// Propagates failures to list the volume group's logical volumes.
pub fn sweep_stale(vg: &str) -> Result<Vec<String>> {
    let listing = lvm_field("lvs", "lv_name,lv_tags", vg)?;
    let mut removed = Vec::new();
    for line in listing.lines() {
        let mut fields = line.split('|');
        let Some(name) = fields.next() else { continue };
        let tags = fields.next().unwrap_or_default();
        let name = name.trim();
        if !name.starts_with("lr-") {
            continue;
        }
        let tagged = tags.split(',').any(|tag| tag.trim() == SNAPSHOT_TAG);
        if !tagged || !name.starts_with("lr-") {
            continue;
        }
        let owner = tags
            .split(',')
            .map(str::trim)
            .find(|tag| tag.starts_with(OWNER_TAG_PREFIX));
        let alive = owner.is_some_and(owner_alive);
        if alive {
            continue;
        }
        let path = format!("/dev/{vg}/{name}");
        match run_lvm("lvremove", &["-f", &path]) {
            Ok(_) => {
                tracing::warn!(snapshot = %path, "removed a snapshot left by a killed job");
                removed.push(name.to_owned());
            }
            Err(error) => {
                tracing::warn!(snapshot = %path, %error, "cannot remove a stale snapshot")
            }
        }
    }
    Ok(removed)
}

/// Watches snapshot usage and reports overflow through [`SnapshotHealth`].
#[derive(Clone)]
struct Monitor {
    stop: Arc<AtomicBool>,
    overflow: Arc<AtomicBool>,
    handle: Arc<std::sync::Mutex<Option<std::thread::JoinHandle<()>>>>,
}

impl Monitor {
    fn start(volume: &Volume, job: &str, thin: bool) -> Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let overflow = Arc::new(AtomicBool::new(false));
        let target = if thin {
            lvm_field("lvs", "pool_lv", &volume.path())
                .ok()
                .map(|pool| format!("{}/{}", volume.vg, pool.trim()))
        } else {
            Some(format!("{}/{}", volume.vg, job))
        };
        let monitor = Self {
            stop: Arc::clone(&stop),
            overflow: Arc::clone(&overflow),
            handle: Arc::new(std::sync::Mutex::new(None)),
        };
        let Some(target) = target else {
            // Without a pool LV there is nothing to watch; the job is still
            // valid, it just cannot report overflow.
            return Ok(monitor);
        };
        let handle = std::thread::Builder::new()
            .name(format!("lr-lvm-monitor-{job}"))
            .spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    // Sleep in short slices so teardown is prompt.
                    for _ in 0..MONITOR_INTERVAL.as_millis() / 100 {
                        if stop.load(Ordering::Relaxed) {
                            return;
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    let usage = if thin {
                        lvm_field("lvs", "data_percent,metadata_percent", &target)
                            .ok()
                            .and_then(|text| max_percent(&text))
                    } else {
                        lvm_field("lvs", "snap_percent", &target)
                            .ok()
                            .and_then(|text| max_percent(&text))
                    };
                    if usage.is_some_and(|value| value >= OVERFLOW_PERCENT) {
                        overflow.store(true, Ordering::SeqCst);
                        tracing::error!(
                            snapshot = %target,
                            percent = usage.unwrap_or_default(),
                            "snapshot usage passed {OVERFLOW_PERCENT}%; aborting the job"
                        );
                        return;
                    }
                }
            })
            .map_err(Error::Io)?;
        if let Ok(mut slot) = monitor.handle.lock() {
            *slot = Some(handle);
        }
        Ok(monitor)
    }

    fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        let handle = self.handle.lock().ok().and_then(|mut slot| slot.take());
        if let Some(handle) = handle {
            let _ = handle.join();
        }
    }
}

impl SnapshotHealth for Monitor {
    fn check(&self) -> Result<()> {
        if self.overflow.load(Ordering::SeqCst) {
            return Err(Error::SnapshotOverflow);
        }
        Ok(())
    }
}

/// Largest percentage in `lvs` output such as `0.00|12.34`.
fn max_percent(text: &str) -> Option<f64> {
    text.split(['|', ' ', '\n'])
        .filter_map(|field| field.trim().parse::<f64>().ok())
        .reduce(f64::max)
}

/// Removes the snapshot on drop, always.
struct LvmGuard {
    vg: String,
    job: String,
    monitor: Option<Arc<Monitor>>,
}

impl Drop for LvmGuard {
    fn drop(&mut self) {
        if let Some(monitor) = self.monitor.take() {
            monitor.stop();
        }
        let path = format!("/dev/{}/{}", self.vg, self.job);
        if let Err(error) = run_lvm("lvremove", &["-f", &path]) {
            tracing::error!(snapshot = %path, %error, "failed to remove the snapshot LV");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{LvmProvider, max_percent, owner_alive, owner_tag, parse_size, sweep_stale};
    use crate::BlockSnapshotProvider;
    use crate::test_layout::offline;
    use lr_core::SnapshotOpts;

    #[test]
    fn sizes_parse_in_the_forms_the_cli_accepts() {
        let origin = 10 * 1024 * 1024 * 1024;
        assert_eq!(
            parse_size("2G", origin).expect("size"),
            2 * 1024 * 1024 * 1024
        );
        assert_eq!(parse_size("512M", origin).expect("size"), 512 * 1024 * 1024);
        assert_eq!(parse_size("1024", origin).expect("size"), 1024);
        assert_eq!(
            parse_size("20%", origin).expect("size"),
            2 * 1024 * 1024 * 1024
        );
        assert!(parse_size("lots", origin).is_err());
    }

    #[test]
    fn percentages_take_the_largest_field() {
        assert_eq!(max_percent("0.00"), Some(0.0));
        assert_eq!(max_percent("1.5|12.25"), Some(12.25));
        assert_eq!(max_percent("nonsense"), None);
    }

    #[test]
    fn the_owner_tag_identifies_this_process() {
        let tag = owner_tag().expect("owner tag");
        assert!(tag.starts_with("owner="));
        assert!(owner_alive(&tag), "this process is alive");
        assert!(!owner_alive("owner=999999999:1"), "no such process");
    }

    #[test]
    fn supports_requires_an_lvm_volume() {
        let layout = offline("/dev/lr-lvm");
        let support = LvmProvider.supports(&layout, &SnapshotOpts::default());
        assert!(
            support
                .reason()
                .is_some_and(|reason| reason.contains("LVM"))
        );
    }

    #[test]
    fn supports_an_active_logical_volume() {
        let mut layout = offline("/dev/lr-lvm");
        layout.lvm = Some(lr_core::LvmFacts {
            is_pv: false,
            is_dm: true,
            vg_name: Some("vg0".to_owned()),
            lv_name: Some("root".to_owned()),
            dm_name: Some("vg0-root".to_owned()),
            thin: None,
        });
        let support = LvmProvider.supports(&layout, &SnapshotOpts::default());
        if which("lvcreate") {
            assert!(support.is_yes(), "{support:?}");
        } else {
            assert!(
                support
                    .reason()
                    .is_some_and(|reason| reason.contains("lvm2"))
            );
        }
    }

    #[test]
    fn sweep_is_a_no_op_for_a_volume_group_that_does_not_exist() {
        // Sweeping an unknown VG fails, but it must not panic.
        if which("lvs") {
            assert!(sweep_stale("lr-no-such-vg").is_err());
        }
    }

    fn which(program: &str) -> bool {
        std::process::Command::new("which")
            .arg(program)
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }
}
