//! The live, inconsistent provider (spec §E.5).
//!
//! Reads a mounted device as-is. It exists so that a user who accepts the risk
//! can still get an image; the manifest records `flags.inconsistent`, the
//! superblock reports `Consistency::None`, and restore refuses the image unless
//! `--accept-inconsistent` is given (spec §H.1).

use lr_core::{Consistency, Error, Result, SnapshotOpts, SourceLayout, Support};

use crate::{BlockSnapshot, BlockSnapshotProvider};

/// Provider identifier.
pub const ID: &str = "live-none";

static PROVIDER: LiveNoneProvider = LiveNoneProvider;

/// The live reader.
#[derive(Debug, Default, Clone, Copy)]
pub struct LiveNoneProvider;

/// The shared instance.
#[must_use]
pub fn provider() -> &'static LiveNoneProvider {
    &PROVIDER
}

impl BlockSnapshotProvider for LiveNoneProvider {
    fn id(&self) -> &'static str {
        ID
    }

    fn supports(&self, src: &SourceLayout, opts: &SnapshotOpts) -> Support {
        if !opts.allow_inconsistent {
            return Support::No("requires --allow-inconsistent".to_owned());
        }
        if src.is_offline() {
            return Support::No(
                "the device is not mounted; the offline provider is consistent and faster"
                    .to_owned(),
            );
        }
        if opts
            .provider
            .as_deref()
            .is_some_and(|name| name != ID && name != "auto")
        {
            return Support::No("another provider was requested".to_owned());
        }
        Support::Yes
    }

    fn create(&self, src: &SourceLayout, opts: &SnapshotOpts) -> Result<BlockSnapshot> {
        if !opts.allow_inconsistent {
            return Err(Error::no_consistent_method([
                "a live read of a mounted device is torn unless --allow-inconsistent is given"
                    .to_owned(),
            ]));
        }
        Ok(BlockSnapshot::new(
            src.device.clone(),
            Consistency::None,
            LiveNoneGuard,
        ))
    }
}

/// Nothing is acquired; the guard keeps teardown uniform across providers.
struct LiveNoneGuard;

#[cfg(test)]
mod tests {
    use super::LiveNoneProvider;
    use crate::BlockSnapshotProvider;
    use crate::test_layout::offline;
    use lr_core::{Consistency, SnapshotOpts};
    use std::path::PathBuf;

    fn mounted() -> lr_core::SourceLayout {
        let mut layout = offline("/dev/lr-live");
        layout.mountpoints.push(PathBuf::from("/mnt/data"));
        layout
    }

    #[test]
    fn requires_the_opt_in() {
        let layout = mounted();
        assert!(
            !LiveNoneProvider
                .supports(&layout, &SnapshotOpts::default())
                .is_yes()
        );
        assert!(
            LiveNoneProvider
                .create(&layout, &SnapshotOpts::default())
                .is_err()
        );
    }

    #[test]
    fn refuses_an_idle_device() {
        let layout = offline("/dev/lr-live");
        let opts = SnapshotOpts {
            allow_inconsistent: true,
            ..SnapshotOpts::default()
        };
        let support = LiveNoneProvider.supports(&layout, &opts);
        assert!(
            support
                .reason()
                .is_some_and(|reason| reason.contains("offline"))
        );
    }

    #[test]
    fn creates_a_none_consistency_snapshot() {
        let layout = mounted();
        let opts = SnapshotOpts {
            allow_inconsistent: true,
            ..SnapshotOpts::default()
        };
        let snapshot = LiveNoneProvider.create(&layout, &opts).expect("snapshot");
        assert_eq!(snapshot.consistency, Consistency::None);
        assert_eq!(snapshot.block_path, layout.device);
        snapshot.check_health().expect("no health check");
    }
}
