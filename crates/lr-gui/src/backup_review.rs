//! Bind source inspection to the complete backup request shown for review.

use lr_proto::v1::BackupSpec;

#[derive(Default)]
pub(crate) struct Review {
    prepared: Option<BackupSpec>,
}

impl Review {
    pub(crate) fn begin(&mut self) {
        self.prepared = None;
    }

    pub(crate) fn accept(&mut self, requested: BackupSpec, current: &BackupSpec) -> bool {
        if requested != *current {
            self.prepared = None;
            return false;
        }
        self.prepared = Some(requested);
        true
    }

    pub(crate) fn take(&mut self, current: &BackupSpec) -> Result<BackupSpec, &'static str> {
        match self.prepared.take() {
            Some(spec) if spec == *current => Ok(spec),
            _ => {
                Err("Backup settings changed or have not been reviewed. Choose Next: review again.")
            }
        }
    }
}

pub(crate) fn validate(spec: &BackupSpec) -> Result<(), &'static str> {
    if spec.source.trim().is_empty() {
        return Err("Choose a disk, partition or source folder.");
    }
    if spec.dest.trim().is_empty() || spec.set.trim().is_empty() {
        return Err("Choose a backup destination and enter a backup name.");
    }
    if !spec.no_encrypt && spec.passphrase_file.is_empty() {
        return Err("Choose a passphrase file for the encrypted backup.");
    }
    if spec.snapshot == "freeze" && !spec.allow_freeze {
        return Err("Confirm the temporary filesystem freeze in Additional settings.");
    }
    if spec.snapshot == "none" && !spec.allow_inconsistent {
        return Err("Confirm the risk of changing source data in Additional settings.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> BackupSpec {
        BackupSpec {
            source: "/source".into(),
            dest: "/backups".into(),
            set: "test".into(),
            no_encrypt: true,
            ..BackupSpec::default()
        }
    }

    #[test]
    fn changing_options_during_inspection_rejects_the_response() {
        let old = spec();
        let mut current = old.clone();
        current.dest = "/different".into();
        let mut review = Review::default();
        assert!(!review.accept(old, &current));
        assert!(review.take(&current).is_err());
    }

    #[test]
    fn reviewed_request_is_single_use_and_mismatches_invalidate_it() {
        let original = spec();
        let mut review = Review::default();
        assert!(review.accept(original.clone(), &original));
        let mut changed = original.clone();
        changed.no_encrypt = false;
        changed.passphrase_file = "/passphrase-file".into();
        assert!(review.take(&changed).is_err());
        assert!(review.take(&original).is_err());
        assert!(review.accept(original.clone(), &original));
        assert!(review.take(&original).is_ok());
        assert!(review.take(&original).is_err());
        assert!(review.accept(original.clone(), &original));
        review.begin();
        assert!(review.take(&original).is_err());
    }

    #[test]
    fn live_backup_requires_the_corresponding_explicit_consent() {
        let mut spec = spec();
        assert!(validate(&spec).is_ok());
        spec.snapshot = "freeze".into();
        assert!(validate(&spec).is_err());
        spec.allow_freeze = true;
        assert!(validate(&spec).is_ok());
        spec.snapshot = "none".into();
        assert!(validate(&spec).is_err());
        spec.allow_inconsistent = true;
        assert!(validate(&spec).is_ok());
    }
}
