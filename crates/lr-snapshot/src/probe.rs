//! Choosing a snapshot provider (spec §E, §K S8).
//!
//! Providers are evaluated in the order the specification fixes, and the first
//! one that supports the source wins unless `--snapshot` overrides it. The
//! decision itself is pure so it can be unit tested against synthetic layouts;
//! [`probe`] adds the I/O the CLI needs to show an estimated size.

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
}

/// Pick a provider from a discovered layout (spec §E).
///
/// # Errors
/// Returns [`Error::NoConsistentMethod`] when no provider can produce a
/// consistent image and `--allow-inconsistent` was not given.
pub fn decide(layout: &SourceLayout, opts: &SnapshotOpts) -> Result<Decision> {
    let mut warnings = Vec::new();
    let forced = opts.provider.as_deref().filter(|name| *name != "auto");

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

    if btrfs && candidate(PROVIDER_BTRFS) {
        return Ok(Decision {
            provider: PROVIDER_BTRFS,
            image_kind: ImageKind::Stream,
            consistency: Consistency::PointInTime,
            warnings,
        });
    }
    if lvm && candidate(PROVIDER_LVM) {
        return Ok(Decision {
            provider: PROVIDER_LVM,
            image_kind: ImageKind::Block,
            consistency: Consistency::PointInTime,
            warnings,
        });
    }
    if offline && candidate(PROVIDER_OFFLINE) {
        return Ok(Decision {
            provider: PROVIDER_OFFLINE,
            image_kind: ImageKind::Block,
            consistency: Consistency::Offline,
            warnings,
        });
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
            return Ok(Decision {
                provider: PROVIDER_FREEZE,
                image_kind: ImageKind::Block,
                consistency: Consistency::Frozen,
                warnings,
            });
        }
    }
    if opts.allow_inconsistent && candidate(PROVIDER_LIVE_NONE) {
        warnings.push(
            "reading a mounted device as-is: the image is flagged inconsistent (spec §D.2)"
                .to_owned(),
        );
        return Ok(Decision {
            provider: PROVIDER_LIVE_NONE,
            image_kind: ImageKind::Block,
            consistency: Consistency::None,
            warnings,
        });
    }

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
    if mounted && !is_root {
        options.push(
            "pass --allow-freeze to quiesce the filesystem instead (writers block)".to_owned(),
        );
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
pub fn probe(layout: &SourceLayout, opts: &SnapshotOpts) -> Result<Plan> {
    let decision = decide(layout, opts)?;
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
        other => {
            warnings.push(format!("no size estimate for provider {other}"));
            layout.device_facts.size_bytes
        }
    };
    if !layout.is_offline() && decision.provider != PROVIDER_FREEZE {
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
        PROVIDER_BTRFS, PROVIDER_FREEZE, PROVIDER_LIVE_NONE, PROVIDER_LVM, PROVIDER_OFFLINE, decide,
    };
    use crate::test_layout::{offline, with_partition};
    use lr_core::{Consistency, ImageKind, SnapshotOpts};
    use std::path::PathBuf;

    fn mounted(mountpoint: &str) -> lr_core::SourceLayout {
        let mut layout = offline("/dev/lr-probe");
        layout.mountpoints.push(PathBuf::from(mountpoint));
        layout
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

        let opts = SnapshotOpts {
            allow_freeze: true,
            ..SnapshotOpts::default()
        };
        let decision = decide(&layout, &opts).expect("decision");
        assert_eq!(decision.provider, PROVIDER_FREEZE);
        assert_eq!(decision.consistency, Consistency::Frozen);
        assert!(decision.warnings.iter().any(|w| w.contains("block")));
    }

    #[test]
    fn the_root_filesystem_is_never_frozen() {
        let layout = mounted("/");
        let opts = SnapshotOpts {
            allow_freeze: true,
            ..SnapshotOpts::default()
        };
        let error = decide(&layout, &opts).expect_err("must refuse");
        assert!(
            error.to_string().contains("--allow-inconsistent"),
            "{error}"
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
        for option in [
            "unmount",
            "LVM or Btrfs",
            "rescue media",
            "--allow-inconsistent",
        ] {
            assert!(text.contains(option), "missing '{option}' in: {text}");
        }
    }
}
