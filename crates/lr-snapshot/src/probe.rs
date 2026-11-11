//! Choosing a snapshot provider (spec §E, §K S8).
//!
//! Providers are evaluated in the order the specification fixes, and the first
//! one that supports the source wins unless `--snapshot` overrides it. The
//! decision reads nothing itself except tracked-freeze's preconditions, which
//! it asks for only under `auto` with `--allow-freeze` (spec §E step 4), so
//! it can be unit tested against synthetic layouts; [`probe`] adds the I/O the
//! CLI needs to show an estimated size.

use std::path::PathBuf;

use lr_core::{Consistency, Error, ImageKind, Result, SnapshotOpts, SourceLayout, Support};

/// Provider identifier for Btrfs tree snapshots.
pub const PROVIDER_BTRFS: &str = "btrfs";
/// Provider identifier for LVM snapshots.
pub const PROVIDER_LVM: &str = "lvm";
/// Provider identifier for the offline provider.
pub const PROVIDER_OFFLINE: &str = "offline";
/// Provider identifier for the freeze provider.
pub const PROVIDER_FREEZE: &str = "freeze";
/// Provider identifier for the live, inconsistent reader.
pub const PROVIDER_LIVE_NONE: &str = "live-none";
/// The tracked-freeze provider (spec v2.2 §E.7).
pub const PROVIDER_TRACKED_FREEZE: &str = "tracked-freeze";

const TRACKED_NOTE: &str = "writes are tracked while the source is copied live; the filesystem \
                            is frozen briefly at the end (frozen, not a snapshot)";

/// How a warning names why the automatic choice passed tracked-freeze over
/// (spec §E step 4); the backup report repeats it.
pub const TRACKED_REFUSED: &str = "tracked-freeze cannot copy this source live";

/// Normalize the documented `none` spelling to the provider's stable ID.
fn provider_id(name: &str) -> &str {
    if name == "none" {
        PROVIDER_LIVE_NONE
    } else {
        name
    }
}

/// What a source will be imaged with.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Plan {
    /// Provider that will be used.
    pub provider: String,
    /// Image kind the provider produces.
    pub image_kind: ImageKind,
    /// Consistency level the provider provides.
    pub consistency: Consistency,
    /// Device to read for block providers; `None` for tree providers, whose
    /// read paths only exist after the snapshot is created.
    pub block_path: Option<PathBuf>,
    /// Rough size of what will be imaged.
    pub estimated_bytes: u64,
    /// Notes the user must see before starting.
    pub warnings: Vec<String>,
    /// Why the automatic choice passed tracked-freeze over, when it
    /// considered it (also among `warnings`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tracked_refusal: Option<String>,
}

/// The part of a plan that needs no I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// Provider identifier.
    pub provider: &'static str,
    /// Image kind.
    pub image_kind: ImageKind,
    /// Consistency level.
    pub consistency: Consistency,
    /// Warnings collected while deciding.
    pub warnings: Vec<String>,
    /// Why the automatic choice passed tracked-freeze over, when it
    /// considered it (also among `warnings`).
    pub tracked_refusal: Option<String>,
}

/// When a decision is made, which decides how far tracked-freeze's
/// preconditions are checked (spec §E.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// A plan or a probe: every check that changes nothing. The
    /// write-tracking self test is left out; it needs a loop device.
    Plan,
    /// The backup itself: the plan's checks and the self test.
    Backup,
}

/// Pick a provider from a discovered layout (spec §E).
///
/// # Errors
/// Returns [`Error::NoConsistentMethod`] when no provider can produce a
/// consistent image and `--allow-inconsistent` was not given.
pub fn decide(layout: &SourceLayout, opts: &SnapshotOpts, stage: Stage) -> Result<Decision> {
    decide_with(layout, opts, |layout, opts| {
        crate::tracked_freeze::support(layout, opts, stage == Stage::Backup)
    })
}

/// [`decide`] with tracked-freeze's preconditions given by `tracked`, which
/// is asked only when the automatic choice reaches spec §E step 4.
fn decide_with(
    layout: &SourceLayout,
    opts: &SnapshotOpts,
    tracked: impl FnOnce(&SourceLayout, &SnapshotOpts) -> Support,
) -> Result<Decision> {
    let mut warnings = Vec::new();
    let mut tracked_refusal = None;
    let forced = opts
        .provider
        .as_deref()
        .filter(|name| *name != "auto")
        .map(provider_id);

    let btrfs = layout
        .fs
        .as_ref()
        .is_some_and(|facts| facts.fs_type == "btrfs");
    let lvm = layout
        .lvm
        .as_ref()
        .is_some_and(|facts| facts.is_dm || facts.is_pv);
    let partitions_busy = layout
        .partitions
        .iter()
        .any(|partition| !partition.mountpoints.is_empty() || !partition.holders.is_empty());
    let offline = layout.is_offline() && !partitions_busy;
    let mounted = !layout.mountpoints.is_empty()
        || layout
            .partitions
            .iter()
            .any(|partition| !partition.mountpoints.is_empty());
    let is_root = is_running_root(layout);

    let candidate = |provider: &'static str| forced.is_none_or(|name| name == provider);
    let decision = |provider, image_kind, consistency, warnings, tracked_refusal| Decision {
        provider,
        image_kind,
        consistency,
        warnings,
        tracked_refusal,
    };

    if btrfs && candidate(PROVIDER_BTRFS) {
        return Ok(decision(
            PROVIDER_BTRFS,
            ImageKind::Stream,
            Consistency::PointInTime,
            warnings,
            None,
        ));
    }
    if lvm && candidate(PROVIDER_LVM) {
        return Ok(decision(
            PROVIDER_LVM,
            ImageKind::Block,
            Consistency::PointInTime,
            warnings,
            None,
        ));
    }
    if offline && candidate(PROVIDER_OFFLINE) {
        return Ok(decision(
            PROVIDER_OFFLINE,
            ImageKind::Block,
            Consistency::Offline,
            warnings,
            None,
        ));
    }
    // Tracked-freeze is opt-in until Slice 18 decides the default (spec §M.4):
    // by name, or by the automatic choice with --allow-freeze when every
    // precondition holds (spec §E step 4). A provider asked for by name
    // reports its own refusal when the backup confirms it.
    if mounted && forced == Some(PROVIDER_TRACKED_FREEZE) {
        warnings.push(TRACKED_NOTE.to_owned());
        return Ok(decision(
            PROVIDER_TRACKED_FREEZE,
            ImageKind::Block,
            Consistency::Frozen,
            warnings,
            None,
        ));
    }
    if mounted && forced.is_none() && opts.allow_freeze {
        match tracked(layout, opts) {
            Support::Yes => {
                warnings.push(TRACKED_NOTE.to_owned());
                return Ok(decision(
                    PROVIDER_TRACKED_FREEZE,
                    ImageKind::Block,
                    Consistency::Frozen,
                    warnings,
                    None,
                ));
            }
            Support::No(reason) => {
                warnings.push(format!("{TRACKED_REFUSED}: {reason}"));
                tracked_refusal = Some(reason);
            }
        }
    }
    if mounted
        && candidate(PROVIDER_FREEZE)
        && (opts.allow_freeze || forced == Some(PROVIDER_FREEZE))
    {
        if is_root {
            warnings.push(
                "the freeze provider refuses the filesystem holding /; boot rescue media instead"
                    .to_owned(),
            );
        } else {
            warnings.push(
                "writers on the source filesystem block for the whole read (quiesced, not a snapshot)"
                    .to_owned(),
            );
            return Ok(decision(
                PROVIDER_FREEZE,
                ImageKind::Block,
                Consistency::Frozen,
                warnings,
                tracked_refusal,
            ));
        }
    }
    if opts.allow_inconsistent && candidate(PROVIDER_LIVE_NONE) {
        warnings.push(
            "reading a mounted device as-is: the image is flagged inconsistent (spec §D.2)"
                .to_owned(),
        );
        return Ok(decision(
            PROVIDER_LIVE_NONE,
            ImageKind::Block,
            Consistency::None,
            warnings,
            tracked_refusal,
        ));
    }

    // Spec §E step 7: the concrete options.
    let mut options = Vec::new();
    if let Some(name) = forced {
        options.push(format!(
            "the requested provider '{name}' cannot handle this source; omit --snapshot"
        ));
    }
    options.extend([
        "unmount the source and retry (offline consistency)".to_owned(),
        "install the source on LVM or Btrfs for point-in-time snapshots".to_owned(),
        "boot rescue media and run the statically linked CLI".to_owned(),
    ]);
    if mounted {
        match tracked_refusal {
            Some(reason) => {
                options.push(format!("tracked-freeze cannot copy it live: {reason}"));
            }
            None if !opts.allow_freeze => options.push(if is_root {
                "pass --allow-freeze to copy a mounted ext4 live with tracked-freeze (a short \
                 freeze at the end)"
                    .to_owned()
            } else {
                "pass --allow-freeze to copy a mounted ext4 live with tracked-freeze (a short \
                 freeze at the end), or to quiesce another filesystem for the whole read \
                 (writers block)"
                    .to_owned()
            }),
            None => {}
        }
        options.push("use file mode (--mode file) to copy the mounted files".to_owned());
    }
    options.push("pass --allow-inconsistent to accept a torn image".to_owned());
    Err(Error::no_consistent_method(options))
}

/// Whether any mount point in the layout is `/`, `/boot` or `/boot/efi`.
#[must_use]
pub fn is_running_root(layout: &SourceLayout) -> bool {
    const BOOT: [&str; 3] = ["/", "/boot", "/boot/efi"];
    layout
        .mountpoints
        .iter()
        .chain(
            layout
                .partitions
                .iter()
                .flat_map(|partition| partition.mountpoints.iter()),
        )
        .any(|mountpoint| BOOT.contains(&mountpoint.to_string_lossy().as_ref()))
}

/// Decide and add the estimated size.
///
/// # Errors
/// See [`decide`]; also propagates failures while measuring the source.
pub fn probe(layout: &SourceLayout, opts: &SnapshotOpts, stage: Stage) -> Result<Plan> {
    let decision = decide(layout, opts, stage)?;
    let mut warnings = decision.warnings;
    let estimated_bytes = match decision.provider {
        PROVIDER_OFFLINE | PROVIDER_LVM | PROVIDER_FREEZE | PROVIDER_LIVE_NONE => {
            let fs_type = layout
                .fs
                .as_ref()
                .map(|facts| facts.fs_type.clone())
                .unwrap_or_else(|| lr_fsmap::RAW_FS_TYPE.to_owned());
            match lr_fsmap::provider_for(&fs_type).used_extents(&layout.device) {
                Ok(map) => map.covered_bytes(),
                Err(error) => {
                    warnings.push(format!(
                        "cannot estimate the used bytes ({error}); assuming the whole device"
                    ));
                    layout.device_facts.size_bytes
                }
            }
        }
        PROVIDER_BTRFS => {
            warnings.push(
                "the size of a btrfs send stream is only known after it is produced; \
                 this estimate is the filesystem size"
                    .to_owned(),
            );
            layout.device_facts.size_bytes
        }
        // The first pass reads the live map; later passes re-read only what
        // changes, which the estimate cannot know.
        PROVIDER_TRACKED_FREEZE => match lr_fsmap::live_used_extents(&layout.device) {
            Ok(map) => map.covered_bytes(),
            Err(error) => {
                warnings.push(format!(
                    "cannot estimate the used bytes of the mounted filesystem now ({error}); \
                     assuming the whole device"
                ));
                layout.device_facts.size_bytes
            }
        },
        other => {
            warnings.push(format!("no size estimate for provider {other}"));
            layout.device_facts.size_bytes
        }
    };
    // A tracked copy maps the live filesystem on purpose and re-reads what
    // changes (spec §E.7), so the note does not apply to it.
    if !layout.is_offline()
        && decision.provider != PROVIDER_FREEZE
        && decision.provider != PROVIDER_TRACKED_FREEZE
    {
        warnings.push(
            "the source is mounted; a used-block map read now may not match the snapshot"
                .to_owned(),
        );
    }

    // Tree providers have no read path until the snapshot exists, so only
    // block providers name a device here.
    let block_path = (decision.image_kind == ImageKind::Block).then(|| layout.device.clone());
    Ok(Plan {
        provider: decision.provider.to_owned(),
        image_kind: decision.image_kind,
        consistency: decision.consistency,
        block_path,
        estimated_bytes,
        warnings,
        tracked_refusal: decision.tracked_refusal,
    })
}

/// Look up a block snapshot provider by identifier.
///
/// # Errors
/// Returns [`Error::Unsupported`] when the provider does not exist yet.
pub fn block_provider(id: &str) -> Result<&'static dyn crate::BlockSnapshotProvider> {
    match id {
        PROVIDER_OFFLINE => Ok(crate::offline_provider()),
        PROVIDER_LVM => Ok(crate::lvm::provider()),
        PROVIDER_FREEZE => Ok(crate::freeze::provider()),
        PROVIDER_LIVE_NONE => Ok(crate::live_none::provider()),
        PROVIDER_TRACKED_FREEZE => Ok(crate::tracked_freeze::provider()),
        other => Err(Error::unsupported(format!("provider {other}"))),
    }
}

/// Check that a provider's `supports` agrees with the probe decision.
///
/// # Errors
/// Returns [`Error::NoConsistentMethod`] with the provider's reason.
pub fn confirm(
    provider: &dyn crate::BlockSnapshotProvider,
    layout: &SourceLayout,
    opts: &SnapshotOpts,
) -> Result<()> {
    match provider.supports(layout, opts) {
        Support::Yes => Ok(()),
        Support::No(reason) => Err(Error::no_consistent_method([
            format!("{} refuses this source: {reason}", provider.id()),
            "see `linuxreflect probe` for the alternatives".to_owned(),
        ])),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Decision, PROVIDER_BTRFS, PROVIDER_FREEZE, PROVIDER_LIVE_NONE, PROVIDER_LVM,
        PROVIDER_OFFLINE, PROVIDER_TRACKED_FREEZE, decide_with,
    };
    use crate::test_layout::{offline, with_partition};
    use lr_core::{Consistency, ImageKind, SnapshotOpts, SourceLayout, Support};
    use std::path::PathBuf;

    fn mounted(mountpoint: &str) -> SourceLayout {
        let mut layout = offline("/dev/lr-probe");
        layout.mountpoints.push(PathBuf::from(mountpoint));
        layout
    }

    /// The choice must not reach tracked-freeze's preconditions.
    fn unasked(_: &SourceLayout, _: &SnapshotOpts) -> Support {
        panic!("tracked-freeze was considered");
    }

    fn decide(layout: &SourceLayout, opts: &SnapshotOpts) -> lr_core::Result<Decision> {
        decide_with(layout, opts, unasked)
    }

    fn allow_freeze() -> SnapshotOpts {
        SnapshotOpts {
            allow_freeze: true,
            ..SnapshotOpts::default()
        }
    }

    fn refused(_: &SourceLayout, _: &SnapshotOpts) -> Support {
        Support::No("the block/block_rq_complete tracepoint is unavailable".to_owned())
    }

    #[test]
    fn btrfs_wins_over_everything_else() {
        let mut layout = offline("/dev/lr-probe");
        if let Some(fs) = layout.fs.as_mut() {
            fs.fs_type = "btrfs".to_owned();
        }
        let decision = decide(&layout, &SnapshotOpts::default()).expect("decision");
        assert_eq!(decision.provider, PROVIDER_BTRFS);
        assert_eq!(decision.image_kind, ImageKind::Stream);
        assert_eq!(decision.consistency, Consistency::PointInTime);
    }

    #[test]
    fn an_lv_uses_the_lvm_provider() {
        let mut layout = offline("/dev/lr-probe");
        layout.lvm = Some(lr_core::LvmFacts {
            is_pv: false,
            is_dm: true,
            vg_name: Some("vg0".to_owned()),
            lv_name: Some("root".to_owned()),
            dm_name: Some("vg0-root".to_owned()),
            thin: None,
        });
        let decision = decide(&layout, &SnapshotOpts::default()).expect("decision");
        assert_eq!(decision.provider, PROVIDER_LVM);
        assert_eq!(decision.consistency, Consistency::PointInTime);
    }

    #[test]
    fn an_idle_device_is_offline() {
        let layout = offline("/dev/lr-probe");
        let decision = decide(&layout, &SnapshotOpts::default()).expect("decision");
        assert_eq!(decision.provider, PROVIDER_OFFLINE);
        assert_eq!(decision.consistency, Consistency::Offline);
    }

    #[test]
    fn a_mounted_non_root_device_needs_opt_in_for_freeze() {
        let layout = mounted("/mnt/data");
        let error = decide(&layout, &SnapshotOpts::default()).expect_err("must refuse");
        assert!(error.to_string().contains("--allow-freeze"), "{error}");

        // With --allow-freeze, tracked-freeze comes first (spec §E step 4);
        // where it does not apply, the freeze provider does.
        let decision = decide_with(&layout, &allow_freeze(), refused).expect("decision");
        assert_eq!(decision.provider, PROVIDER_FREEZE);
        assert_eq!(decision.consistency, Consistency::Frozen);
        assert!(decision.warnings.iter().any(|w| w.contains("block")));
    }

    #[test]
    fn the_root_filesystem_is_never_frozen() {
        let layout = mounted("/");
        let error = decide_with(&layout, &allow_freeze(), refused).expect_err("must refuse");
        let text = error.to_string();
        assert!(text.contains("--allow-inconsistent"), "{text}");
        // The options name why tracked-freeze could not copy it live.
        assert!(
            text.contains("tracked-freeze cannot copy it live: the block/block_rq_complete"),
            "{text}"
        );
    }

    #[test]
    fn a_mounted_device_can_be_read_inconsistently() {
        let layout = mounted("/");
        let opts = SnapshotOpts {
            allow_inconsistent: true,
            ..SnapshotOpts::default()
        };
        let decision = decide(&layout, &opts).expect("decision");
        assert_eq!(decision.provider, PROVIDER_LIVE_NONE);
        assert_eq!(decision.consistency, Consistency::None);
    }

    #[test]
    fn a_mounted_partition_counts_as_mounted() {
        let mut layout = offline("/dev/lr-probe");
        with_partition(&mut layout, 1, vec![PathBuf::from("/mnt/data")], Vec::new());
        let error = decide(&layout, &SnapshotOpts::default()).expect_err("must refuse");
        assert!(
            error.to_string().contains("no consistent snapshot method"),
            "{error}"
        );
    }

    #[test]
    fn an_explicit_provider_override_is_honoured() {
        let layout = offline("/dev/lr-probe");
        let opts = SnapshotOpts {
            provider: Some(PROVIDER_OFFLINE.to_owned()),
            ..SnapshotOpts::default()
        };
        assert_eq!(
            decide(&layout, &opts).expect("decision").provider,
            PROVIDER_OFFLINE
        );

        let opts = SnapshotOpts {
            provider: Some(PROVIDER_LVM.to_owned()),
            ..SnapshotOpts::default()
        };
        // A provider that cannot handle the source must be reported, not
        // silently replaced by another one.
        let error = decide(&layout, &opts).expect_err("must report the override");
        assert!(error.to_string().contains("lvm"), "{error}");
    }

    #[test]
    fn the_no_method_error_lists_concrete_options() {
        let layout = mounted("/");
        let error = decide(&layout, &SnapshotOpts::default()).expect_err("must refuse");
        let text = error.to_string();
        // Spec §E step 7: rescue media, tracked-freeze, file mode, or a torn image.
        for option in [
            "unmount",
            "LVM or Btrfs",
            "rescue media",
            "--allow-freeze to copy a mounted ext4 live with tracked-freeze",
            "file mode",
            "--allow-inconsistent",
        ] {
            assert!(text.contains(option), "missing '{option}' in: {text}");
        }
    }

    /// Spec §E step 4: `auto` with `--allow-freeze` copies a mounted ext4
    /// live, the running root included, ahead of the whole-read freeze.
    #[test]
    fn the_automatic_choice_with_allow_freeze_takes_tracked_freeze_when_it_applies() {
        let applies = |_: &SourceLayout, _: &SnapshotOpts| Support::Yes;
        for mountpoint in ["/", "/mnt/data"] {
            let decision =
                decide_with(&mounted(mountpoint), &allow_freeze(), applies).expect("decision");
            assert_eq!(decision.provider, PROVIDER_TRACKED_FREEZE, "{mountpoint}");
            assert_eq!(decision.image_kind, ImageKind::Block);
            assert_eq!(decision.consistency, Consistency::Frozen);
            assert_eq!(decision.tracked_refusal, None);
        }
        let named_auto = SnapshotOpts {
            provider: Some("auto".to_owned()),
            allow_freeze: true,
            ..SnapshotOpts::default()
        };
        let decision = decide_with(&mounted("/"), &named_auto, applies).expect("decision");
        assert_eq!(decision.provider, PROVIDER_TRACKED_FREEZE);
    }

    /// A precondition that does not hold sends the automatic choice to the
    /// next step, and the reason is reported.
    #[test]
    fn a_refused_tracked_freeze_passes_the_choice_on_with_its_reason() {
        let opts = SnapshotOpts {
            allow_freeze: true,
            allow_inconsistent: true,
            ..SnapshotOpts::default()
        };
        let decision = decide_with(&mounted("/"), &opts, refused).expect("decision");
        assert_eq!(decision.provider, PROVIDER_LIVE_NONE);
        assert_eq!(
            decision.tracked_refusal.as_deref(),
            Some("the block/block_rq_complete tracepoint is unavailable")
        );
        assert!(
            decision.warnings.iter().any(|warning| warning
                == "tracked-freeze cannot copy this source live: the block/block_rq_complete \
                    tracepoint is unavailable"),
            "{:?}",
            decision.warnings
        );
        let decision = decide_with(&mounted("/srv"), &allow_freeze(), refused).expect("decision");
        assert_eq!(decision.provider, PROVIDER_FREEZE);
        assert!(decision.tracked_refusal.is_some());
    }

    /// Earlier steps win, `--allow-freeze` alone is the opt-in, and a
    /// provider asked for by name is never replaced.
    #[test]
    fn tracked_freeze_is_considered_only_where_spec_step_4_applies() {
        // An idle device and a Btrfs filesystem come first.
        let decision = decide(&offline("/dev/lr-probe"), &allow_freeze()).expect("decision");
        assert_eq!(decision.provider, PROVIDER_OFFLINE);
        let mut btrfs = mounted("/");
        if let Some(fs) = btrfs.fs.as_mut() {
            fs.fs_type = "btrfs".to_owned();
        }
        assert_eq!(
            decide(&btrfs, &allow_freeze()).expect("decision").provider,
            PROVIDER_BTRFS
        );
        // Without --allow-freeze the automatic choice never takes it.
        assert!(decide(&mounted("/"), &SnapshotOpts::default()).is_err());
        // By name it is taken as asked; the backup confirms it.
        let named = SnapshotOpts {
            provider: Some(PROVIDER_TRACKED_FREEZE.to_owned()),
            ..SnapshotOpts::default()
        };
        assert_eq!(
            decide(&mounted("/"), &named).expect("decision").provider,
            PROVIDER_TRACKED_FREEZE
        );
        // Another provider by name skips it.
        let freeze = SnapshotOpts {
            provider: Some(PROVIDER_FREEZE.to_owned()),
            allow_freeze: true,
            ..SnapshotOpts::default()
        };
        assert_eq!(
            decide(&mounted("/srv"), &freeze)
                .expect("decision")
                .provider,
            PROVIDER_FREEZE
        );
    }
}
