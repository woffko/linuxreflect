//! Required mount identities for named local destinations.

use std::path::{Component, Path, PathBuf};

use lr_core::{Error, Result};

/// A mount identity a local destination must match before it is accessed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RequiredMount {
    /// Absolute mount point expected to contain the destination.
    pub path: PathBuf,
    /// Exact source recorded in `/proc/self/mountinfo`.
    pub source: String,
    /// Exact filesystem type recorded in `/proc/self/mountinfo`.
    pub fs_type: String,
}

impl RequiredMount {
    /// Check the required mount against the process mount table for `path`.
    ///
    /// The check runs again for every local destination operation. It does not
    /// pin the mount for the lifetime of an operation.
    pub(crate) fn check_path(&self, path: &Path) -> Result<()> {
        validate(self)?;
        validate_destination_path(path)?;
        let required_path = resolve_existing_prefix(&self.path)?;
        let destination_path = resolve_existing_prefix(path)?;
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").map_err(Error::Io)?;
        check_mountinfo(self, &required_path, &destination_path, &mountinfo)
    }
}

/// Validate a mount policy before it is stored in the named-destination
/// registry.
///
/// # Errors
/// Returns [`Error::Unsupported`] when the mount path or identity fields are
/// malformed.
pub fn validate(policy: &RequiredMount) -> Result<()> {
    if !policy.path.is_absolute()
        || policy
            .path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(Error::unsupported(
            "required mount path must be an absolute, normalized path",
        ));
    }
    if policy.source.is_empty() {
        return Err(Error::unsupported(
            "required mount source must not be empty",
        ));
    }
    if policy.fs_type.is_empty() || policy.fs_type.chars().any(char::is_whitespace) {
        return Err(Error::unsupported(
            "required mount filesystem type must be a non-empty field",
        ));
    }
    Ok(())
}

fn validate_destination_path(path: &Path) -> Result<()> {
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(Error::unsupported(format!(
            "a destination with '..' is refused when a required mount is configured: {}",
            path.display()
        )));
    }
    Ok(())
}

fn check_mountinfo(
    policy: &RequiredMount,
    required_path: &Path,
    destination_path: &Path,
    text: &str,
) -> Result<()> {
    if !destination_path.starts_with(required_path) {
        return Err(Error::unsupported(format!(
            "local destination {} is not beneath required mount {}",
            destination_path.display(),
            required_path.display()
        )));
    }

    let mounts = parse_mountinfo(text)?;
    let expected =
        |mount: &MountInfo| mount.source == policy.source && mount.fs_type == policy.fs_type;

    let mut required_matches = mounts.iter().filter(|mount| mount.target == required_path);
    let required = required_matches.next().ok_or_else(|| {
        Error::unsupported(format!(
            "required mount {} is not mounted",
            required_path.display()
        ))
    })?;
    if required_matches.next().is_some() {
        return Err(ambiguous_mount(required_path));
    }
    if required.root != Path::new("/") {
        return Err(Error::unsupported(format!(
            "required mount {} is a non-root mount projection ({})",
            required_path.display(),
            required.root.display()
        )));
    }
    if !expected(required) {
        return Err(identity_mismatch(policy, required));
    }

    // A destination subdirectory can itself be a mount point. Validate the
    // deepest containing mount too, so a different nested mount cannot silently
    // replace the required share for this destination.
    let deepest_depth = mounts
        .iter()
        .filter(|mount| destination_path.starts_with(&mount.target))
        .map(|mount| mount.target.components().count())
        .max()
        .ok_or_else(|| {
            Error::unsupported(format!(
                "no mounted filesystem contains local destination {}",
                destination_path.display()
            ))
        })?;
    let mut containing_matches = mounts.iter().filter(|mount| {
        destination_path.starts_with(&mount.target)
            && mount.target.components().count() == deepest_depth
    });
    let containing = containing_matches.next().ok_or_else(|| {
        Error::unsupported(format!(
            "no mounted filesystem contains local destination {}",
            destination_path.display()
        ))
    })?;
    if containing_matches.next().is_some() {
        return Err(ambiguous_mount(&containing.target));
    }
    if containing.id != required.id {
        return Err(Error::unsupported(format!(
            "local destination {} is on a nested or overmounted filesystem at {}, not required mount {}",
            destination_path.display(),
            containing.target.display(),
            required_path.display()
        )));
    }
    if !expected(containing) {
        return Err(identity_mismatch(policy, containing));
    }
    Ok(())
}

fn ambiguous_mount(path: &Path) -> Error {
    Error::unsupported(format!(
        "mount table has ambiguous stacked mount records at {}",
        path.display()
    ))
}

fn identity_mismatch(policy: &RequiredMount, actual: &MountInfo) -> Error {
    Error::unsupported(format!(
        "required mount {} identity mismatch: expected {} source {} but found {} source {} at {}",
        policy.path.display(),
        policy.fs_type,
        policy.source,
        actual.fs_type,
        actual.source,
        actual.target.display()
    ))
}

#[derive(Debug)]
struct MountInfo {
    id: u64,
    root: PathBuf,
    target: PathBuf,
    fs_type: String,
    source: String,
}

fn parse_mountinfo(text: &str) -> Result<Vec<MountInfo>> {
    let mut mounts = Vec::new();
    for line in text.lines() {
        let (before, after) = line
            .split_once(" - ")
            .ok_or_else(|| Error::corrupt("could not parse /proc/self/mountinfo entry"))?;
        let before: Vec<&str> = before.split_whitespace().collect();
        let after: Vec<&str> = after.split_whitespace().collect();
        if before.len() < 6 || after.len() < 3 {
            return Err(Error::corrupt(
                "could not parse /proc/self/mountinfo fields",
            ));
        }
        let id = before[0]
            .parse()
            .map_err(|_| Error::corrupt("could not parse mount ID in mountinfo"))?;
        let root = PathBuf::from(decode_field(before[3])?);
        let target = PathBuf::from(decode_field(before[4])?);
        if !root.is_absolute() || !target.is_absolute() {
            return Err(Error::corrupt(
                "mountinfo root and mount point must be absolute paths",
            ));
        }
        mounts.push(MountInfo {
            id,
            root,
            target,
            fs_type: decode_field(after[0])?,
            source: decode_field(after[1])?,
        });
    }
    for index in 0..mounts.len() {
        if mounts[index + 1..]
            .iter()
            .any(|other| other.id == mounts[index].id)
        {
            return Err(Error::corrupt("duplicate mount ID in mountinfo"));
        }
    }
    Ok(mounts)
}

fn decode_field(field: &str) -> Result<String> {
    let bytes = field.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\'
            && index + 3 < bytes.len()
            && bytes[index + 1..index + 4]
                .iter()
                .all(|byte| (b'0'..=b'7').contains(byte))
        {
            let value = u16::from(bytes[index + 1] - b'0') * 64
                + u16::from(bytes[index + 2] - b'0') * 8
                + u16::from(bytes[index + 3] - b'0');
            let value = u8::try_from(value)
                .map_err(|_| Error::corrupt("mountinfo contains an invalid octal escape"))?;
            decoded.push(value);
            index += 4;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded)
        .map_err(|_| Error::corrupt("mountinfo contains a non-UTF-8 mount field"))
}

fn resolve_existing_prefix(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map_err(Error::Io)?.join(path)
    };
    let mut normalized = PathBuf::from("/");
    for component in absolute.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
            Component::Prefix(_) => {}
        }
    }

    let mut existing = normalized.clone();
    let mut missing = Vec::new();
    loop {
        match std::fs::symlink_metadata(&existing) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let Some(name) = existing.file_name().map(std::ffi::OsStr::to_owned) else {
                    return Err(Error::Io(error));
                };
                missing.push(name);
                if !existing.pop() {
                    return Err(Error::Io(error));
                }
            }
            Err(error) => return Err(Error::Io(error)),
        }
    }
    let mut resolved = std::fs::canonicalize(existing).map_err(Error::Io)?;
    for component in missing.iter().rev() {
        resolved.push(component);
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{RequiredMount, check_mountinfo, validate};

    const BASE: &str =
        "36 25 0:32 / /mnt/backup rw,relatime shared:1 - nfs4 nas:/exports/backups rw\n";
    const ROOT_MOUNT: &str = "25 1 0:1 / / rw - ext4 /dev/root rw\n";

    fn policy() -> RequiredMount {
        RequiredMount {
            path: "/mnt/backup".into(),
            source: "nas:/exports/backups".into(),
            fs_type: "nfs4".into(),
        }
    }

    #[test]
    fn required_mount_covers_destination_subdirectories() {
        assert!(
            check_mountinfo(
                &policy(),
                Path::new("/mnt/backup"),
                Path::new("/mnt/backup/deep/backup"),
                BASE,
            )
            .is_ok()
        );
    }

    #[test]
    fn nested_mount_with_different_identity_is_refused() {
        let nested = format!("{BASE}37 36 0:33 / /mnt/backup/sub rw - ext4 /dev/sdb1 rw\n");
        assert!(
            check_mountinfo(
                &policy(),
                Path::new("/mnt/backup"),
                Path::new("/mnt/backup/sub/backup"),
                &nested,
            )
            .is_err()
        );
    }

    #[test]
    fn missing_mount_is_refused() {
        assert!(
            check_mountinfo(
                &policy(),
                Path::new("/mnt/backup"),
                Path::new("/mnt/backup/subdir"),
                ROOT_MOUNT,
            )
            .is_err()
        );
    }

    #[test]
    fn wrong_mount_source_is_refused() {
        let text = BASE.replace("nas:/exports/backups", "nas:/wrong-share");
        assert!(
            check_mountinfo(
                &policy(),
                Path::new("/mnt/backup"),
                Path::new("/mnt/backup/subdir"),
                &text,
            )
            .is_err()
        );
    }

    #[test]
    fn wrong_mount_filesystem_type_is_refused() {
        let text = BASE.replace("nfs4", "cifs");
        assert!(
            check_mountinfo(
                &policy(),
                Path::new("/mnt/backup"),
                Path::new("/mnt/backup/subdir"),
                &text,
            )
            .is_err()
        );
    }

    #[test]
    fn destination_outside_required_mount_is_refused() {
        assert!(
            check_mountinfo(
                &policy(),
                Path::new("/mnt/backup"),
                Path::new("/mnt/other/backup"),
                BASE,
            )
            .is_err()
        );
    }

    #[test]
    fn nested_mount_with_same_identity_is_still_refused() {
        let nested =
            format!("{BASE}37 36 0:32 / /mnt/backup/sub rw - nfs4 nas:/exports/backups rw\n");
        assert!(
            check_mountinfo(
                &policy(),
                Path::new("/mnt/backup"),
                Path::new("/mnt/backup/sub/backup"),
                &nested,
            )
            .is_err()
        );
    }

    #[test]
    fn duplicate_records_at_required_mount_are_ambiguous() {
        let stacked = format!("{BASE}37 36 0:32 / /mnt/backup rw - nfs4 nas:/exports/backups rw\n");
        assert!(
            check_mountinfo(
                &policy(),
                Path::new("/mnt/backup"),
                Path::new("/mnt/backup/subdir"),
                &stacked,
            )
            .is_err()
        );
    }

    #[test]
    fn duplicate_records_at_deepest_destination_mount_are_ambiguous() {
        let stacked = format!(
            "{BASE}37 36 0:32 / /mnt/backup/sub rw - nfs4 nas:/exports/backups rw\n\
             38 37 0:32 / /mnt/backup/sub rw - nfs4 nas:/exports/backups rw\n"
        );
        assert!(
            check_mountinfo(
                &policy(),
                Path::new("/mnt/backup"),
                Path::new("/mnt/backup/sub/data"),
                &stacked,
            )
            .is_err()
        );
    }

    #[test]
    fn non_root_bind_projection_at_required_mount_is_refused() {
        let projected = BASE.replace("0:32 / /mnt/backup", "0:32 /private/subtree /mnt/backup");
        assert!(
            check_mountinfo(
                &policy(),
                Path::new("/mnt/backup"),
                Path::new("/mnt/backup/subdir"),
                &projected,
            )
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn parent_traversal_after_symlink_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("real/subdirectory");
        std::fs::create_dir_all(&target).expect("target");
        std::os::unix::fs::symlink(&target, dir.path().join("alias")).expect("symlink");
        let path = dir.path().join("alias/../backup");
        assert!(policy().check_path(&path).is_err());
    }

    #[test]
    fn mountinfo_escape_sequences_are_decoded() {
        let policy = RequiredMount {
            path: "/mnt/shared dir".into(),
            source: "nas:/exports/backup dir".into(),
            fs_type: "nfs4".into(),
        };
        let text = "36 25 0:32 / /mnt/shared\\040dir rw - nfs4 nas:/exports/backup\\040dir rw\n";
        assert!(
            check_mountinfo(
                &policy,
                Path::new("/mnt/shared dir"),
                Path::new("/mnt/shared dir/subdir"),
                text,
            )
            .is_ok()
        );
    }

    #[test]
    fn mount_policy_requires_an_absolute_normalized_path() {
        let mut policy = policy();
        assert!(validate(&policy).is_ok());
        policy.path = "mnt/backup".into();
        assert!(validate(&policy).is_err());
        policy.path = "/mnt/../backup".into();
        assert!(validate(&policy).is_err());
    }
}
