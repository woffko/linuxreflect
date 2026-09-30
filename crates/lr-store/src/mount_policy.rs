//! Required mount identities for named local destinations.

use std::os::fd::{AsRawFd, OwnedFd};
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
        // Retain both mount observations through the table comparison. This
        // does not pin the paths' visibility after this check.
        let (required_observation, visible_required_id) = visible_mount(&required_path)?;
        let (destination_observation, visible_destination_id) = visible_mount(&destination_path)?;
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").map_err(Error::Io)?;
        let result = check_mountinfo(
            self,
            &required_path,
            &destination_path,
            &mountinfo,
            visible_required_id,
            visible_destination_id,
        );
        drop(destination_observation);
        drop(required_observation);
        result
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
    visible_required_id: u64,
    visible_destination_id: u64,
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

    let target_is_mounted = mounts.iter().any(|mount| mount.target == required_path);
    let required = mounts
        .iter()
        .find(|mount| mount.target == required_path && mount.id == visible_required_id)
        .ok_or_else(|| {
            if target_is_mounted {
                unresolved_visible_mount(required_path)
            } else {
                Error::unsupported(format!(
                    "required mount {} is not mounted",
                    required_path.display()
                ))
            }
        })?;
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
    // replace the required share for this destination. Mountinfo may retain a
    // deeper hidden target; if its record wins this lexical lookup but does
    // not match the visible descriptor ID below, refuse rather than infer.
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
    let containing = mounts
        .iter()
        .find(|mount| {
            destination_path.starts_with(&mount.target)
                && mount.target.components().count() == deepest_depth
                && mount.id == visible_destination_id
        })
        .ok_or_else(|| unresolved_visible_mount(destination_path))?;
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

fn unresolved_visible_mount(path: &Path) -> Error {
    Error::unsupported(format!(
        "could not determine the visible mount record at {}",
        path.display()
    ))
}

fn visible_mount(path: &Path) -> Result<(OwnedFd, u64)> {
    let mut existing = path.to_path_buf();
    loop {
        match std::fs::metadata(&existing) {
            Ok(metadata) if metadata.is_dir() => break,
            Ok(_) => {
                if !existing.pop() {
                    return Err(unresolved_visible_mount(path));
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                if !existing.pop() {
                    return Err(Error::Io(error));
                }
            }
            Err(error) => return Err(Error::Io(error)),
        }
    }

    let directory = lr_unsafe::beneath::open_root(&existing).map_err(Error::Io)?;
    let fdinfo_path = format!("/proc/self/fdinfo/{}", directory.as_raw_fd());
    let fdinfo = std::fs::read_to_string(fdinfo_path).map_err(Error::Io)?;
    let mount_id = fdinfo_mount_id(path, &fdinfo)?;
    Ok((directory, mount_id))
}

fn fdinfo_mount_id(path: &Path, text: &str) -> Result<u64> {
    parse_fdinfo_mount_id(text)?.ok_or_else(|| unresolved_visible_mount(path))
}

fn parse_fdinfo_mount_id(text: &str) -> Result<Option<u64>> {
    let mut mount_id = None;
    for line in text.lines() {
        let Some(value) = line.strip_prefix("mnt_id:") else {
            continue;
        };
        if mount_id.is_some() {
            return Err(Error::corrupt("fdinfo has duplicate mount IDs"));
        }
        mount_id = Some(
            value
                .trim()
                .parse()
                .map_err(|_| Error::corrupt("could not parse mount ID in fdinfo"))?,
        );
    }
    Ok(mount_id)
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
    use std::os::fd::AsRawFd;
    use std::path::Path;

    use super::{RequiredMount, check_mountinfo, fdinfo_mount_id, validate, visible_mount};

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
                36,
                36,
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
                36,
                37,
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
                25,
                25,
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
                36,
                36,
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
                36,
                36,
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
                36,
                25,
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
                36,
                37,
            )
            .is_err()
        );
    }

    #[test]
    fn duplicate_records_without_a_visible_id_are_refused() {
        let stacked = format!("{BASE}37 36 0:32 / /mnt/backup rw - nfs4 nas:/exports/backups rw\n");
        assert!(
            check_mountinfo(
                &policy(),
                Path::new("/mnt/backup"),
                Path::new("/mnt/backup/subdir"),
                &stacked,
                99,
                99,
            )
            .is_err()
        );
    }

    #[test]
    fn duplicate_deepest_mount_records_without_visible_id_are_refused() {
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
                36,
                99,
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
                36,
                36,
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
                36,
                36,
            )
            .is_ok()
        );
    }

    #[test]
    fn hidden_matching_mount_does_not_override_visible_wrong_share() {
        let stacked = concat!(
            "36 25 0:32 / /mnt/backup rw - cifs nas:/exports/backups rw\n",
            "37 36 0:33 / /mnt/backup rw - cifs //wrong/share rw\n",
        );
        let expected = RequiredMount {
            path: "/mnt/backup".into(),
            source: "nas:/exports/backups".to_owned(),
            fs_type: "cifs".to_owned(),
        };
        let visible_required_id =
            super::parse_fdinfo_mount_id("pos:\t0\nflags:\t0100000\nmnt_id:\t37\n")
                .expect("parse fdinfo")
                .expect("mount ID");
        let visible_destination_id = visible_required_id;
        let error = check_mountinfo(
            &expected,
            Path::new("/mnt/backup"),
            Path::new("/mnt/backup/subdir"),
            stacked,
            visible_required_id,
            visible_destination_id,
        )
        .expect_err("the visible share is wrong despite a matching hidden record");
        assert!(
            error
                .to_string()
                .contains("found cifs source //wrong/share"),
            "{error}"
        );
    }

    #[test]
    fn systemd_autofs_and_cifs_stack_accepts_the_visible_share_independent_of_order() {
        let expected = RequiredMount {
            path: "/mnt/backup".into(),
            source: "//nas/backups".to_owned(),
            fs_type: "cifs".to_owned(),
        };
        let cases = [
            (
                concat!(
                    "640 25 0:32 / /mnt/backup rw - autofs systemd-1 rw\n",
                    "17 640 0:33 / /mnt/backup rw - cifs //nas/backups rw\n",
                ),
                17,
            ),
            (
                concat!(
                    "640 17 0:33 / /mnt/backup rw - cifs //nas/backups rw\n",
                    "17 25 0:32 / /mnt/backup rw - autofs systemd-1 rw\n",
                ),
                640,
            ),
        ];

        for (mountinfo, visible_id) in cases {
            assert!(
                check_mountinfo(
                    &expected,
                    Path::new("/mnt/backup"),
                    Path::new("/mnt/backup/linuxreflect_backups"),
                    mountinfo,
                    visible_id,
                    visible_id,
                )
                .is_ok(),
                "visible mount ID {visible_id} should select the configured CIFS row"
            );
        }
    }

    #[test]
    fn visible_mount_lookup_uses_existing_directory_for_missing_descendants() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("not-created/deeper");
        let (root_fd, root_id) = visible_mount(dir.path()).expect("observe temp directory");
        let (missing_fd, missing_id) =
            visible_mount(&missing).expect("observe nearest existing directory");

        assert_eq!(missing_id, root_id);
        let descriptor_path = format!("/proc/self/fd/{}", missing_fd.as_raw_fd());
        let opened_path = std::fs::read_link(descriptor_path).expect("read opened directory");
        assert_eq!(
            opened_path,
            dir.path().canonicalize().expect("canonical temp directory")
        );
        drop(missing_fd);
        drop(root_fd);
        assert!(!missing.exists());
    }

    #[test]
    fn fdinfo_missing_or_malformed_mount_ids_fail_closed() {
        let cases = [
            "pos:\t0\nflags:\t0100000\n",
            "pos:\t0\nflags:\t0100000\nmnt_id:\tnot-a-number\n",
            "pos:\t0\nflags:\t0100000\nmnt_id:\t17\nmnt_id:\t18\n",
        ];
        for text in cases {
            assert!(
                fdinfo_mount_id(Path::new("/mnt/backup"), text).is_err(),
                "fdinfo without one valid mount ID must fail closed: {text:?}"
            );
        }
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
