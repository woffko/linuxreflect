//! Destinations configured by name on this machine (A6).
//!
//! An administrator records a destination, typically SFTP, with its key and
//! `known_hosts` files in a root-owned registry. Clients name it as `@name`,
//! so the GUI and other unprivileged callers never send key paths for the
//! daemon to read, and the daemon has everything it needs without an
//! `ssh-agent`.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use lr_core::{Error, Result};

use crate::{DestinationOptions, RequiredMount};

/// Where the registry lives unless the daemon was told otherwise.
pub const DEFAULT_REGISTRY: &str = "/etc/linuxreflect/destinations.toml";

static REGISTRY: OnceLock<PathBuf> = OnceLock::new();

/// Use `path` as the registry for this process (the daemon's
/// `--destinations-file`). Only the first call has an effect.
pub fn set_registry_path(path: PathBuf) {
    let _ = REGISTRY.set(path);
}

/// The registry this process uses: the configured path, else
/// `$LR_DESTINATIONS_FILE`, else [`DEFAULT_REGISTRY`].
#[must_use]
pub fn registry_path() -> PathBuf {
    REGISTRY
        .get()
        .cloned()
        .or_else(|| std::env::var_os("LR_DESTINATIONS_FILE").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_REGISTRY))
}

/// One configured destination.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NamedDestination {
    /// Name clients use as `@name`.
    pub name: String,
    /// Destination URI: a local path or `sftp://…`.
    pub uri: String,
    /// Private key for an SFTP destination.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<PathBuf>,
    /// `known_hosts` file for an SFTP destination.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known_hosts: Option<PathBuf>,
    /// Required identity for the mount containing a local destination.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_mount: Option<RequiredMount>,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct RegistryFile {
    #[serde(default, rename = "destination")]
    destinations: Vec<NamedDestination>,
}

/// The name in `@name`, if `dest` is a named destination.
#[must_use]
pub fn name_of(dest: &str) -> Option<&str> {
    dest.strip_prefix('@')
}

/// Check an entry before it is stored.
///
/// # Errors
/// Returns [`Error::Unsupported`] for a name outside the set-name grammar
/// (D-115), a URI that does not parse or names another entry, or a key or
/// `known_hosts` path that is not absolute, or an invalid required mount.
pub fn validate(entry: &NamedDestination) -> Result<()> {
    lr_core::validate_set_name(&entry.name).map_err(|_| {
        Error::unsupported(format!("'{}' is not a valid destination name", entry.name))
    })?;
    if name_of(&entry.uri).is_some() {
        return Err(Error::unsupported(
            "a destination cannot point at another named one",
        ));
    }
    let uri = crate::uri::parse(&entry.uri)?;
    for path in [&entry.identity, &entry.known_hosts].into_iter().flatten() {
        if !path.is_absolute() {
            return Err(Error::unsupported(format!(
                "{} must be an absolute path",
                path.display()
            )));
        }
    }
    if let Some(required_mount) = &entry.required_mount {
        if !matches!(uri, crate::uri::DestinationUri::Local { .. }) {
            return Err(Error::unsupported(
                "a required mount can only be set for a local destination",
            ));
        }
        crate::mount_policy::validate(required_mount)?;
    }
    Ok(())
}

/// Every destination in the registry at `path`; a missing registry is empty.
///
/// # Errors
/// Returns [`Error::Corrupt`] for a registry that does not parse.
pub fn load(path: &Path) -> Result<Vec<NamedDestination>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(Error::Io(error)),
    };
    let file: RegistryFile = toml::from_str(&text)
        .map_err(|error| Error::corrupt(format!("{}: {error}", path.display())))?;
    Ok(file.destinations)
}

/// Add or replace an entry, retaining its mount guard when an older client
/// omits that field. Remove the entry before recreating it to clear the guard.
/// The caller persists the resulting registry with [`save`].
///
/// # Errors
/// Propagates validation errors without changing `entries`.
pub fn upsert(entries: &mut Vec<NamedDestination>, mut entry: NamedDestination) -> Result<()> {
    if entry.required_mount.is_none()
        && let Some(existing) = entries.iter().find(|item| item.name == entry.name)
    {
        entry.required_mount = existing.required_mount.clone();
    }
    validate(&entry)?;
    entries.retain(|existing| existing.name != entry.name);
    entries.push(entry);
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(())
}

/// Replace the registry at `path` with `destinations`, atomically.
///
/// # Errors
/// Propagates validation, serialization and I/O errors.
pub fn save(path: &Path, destinations: &[NamedDestination]) -> Result<()> {
    for entry in destinations {
        validate(entry)?;
    }
    let text = toml::to_string_pretty(&RegistryFile {
        destinations: destinations.to_vec(),
    })
    .map_err(|error| Error::corrupt(format!("destination registry: {error}")))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(Error::Io)?;
    }
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    std::fs::write(&tmp, text).map_err(Error::Io)?;
    std::fs::rename(&tmp, path).map_err(Error::Io)
}

/// Resolve `dest`: a named destination becomes its URI and its own key and
/// `known_hosts` files (anything the caller supplied is replaced); any other
/// destination is returned unchanged.
/// This descriptive helper does not carry the mount policy. Open storage via
/// [`crate::open`] with the original `@name`, not the returned URI.
///
/// # Errors
/// Returns [`Error::Unsupported`] for a name that is not configured, and
/// propagates registry errors.
pub fn resolve(dest: &str, options: &DestinationOptions) -> Result<(String, DestinationOptions)> {
    let (uri, options, _required_mount) = resolve_with_policy(dest, options)?;
    Ok((uri, options))
}

/// Resolve a destination and preserve any configured required mount policy.
///
/// # Errors
/// Returns [`Error::Unsupported`] for an unknown or invalid named destination
/// and propagates registry errors.
pub fn resolve_with_policy(
    dest: &str,
    options: &DestinationOptions,
) -> Result<(String, DestinationOptions, Option<RequiredMount>)> {
    let Some(name) = name_of(dest) else {
        return Ok((dest.to_owned(), options.clone(), None));
    };
    let path = registry_path();
    let entry = load(&path)?
        .into_iter()
        .find(|entry| entry.name == name)
        .ok_or_else(|| {
            Error::unsupported(format!(
                "no destination named @{name} is configured in {} \
                 (see linuxreflect destination list)",
                path.display()
            ))
        })?;
    validate(&entry)?;
    Ok((
        entry.uri,
        DestinationOptions {
            set_name: options.set_name.clone(),
            identity: entry.identity,
            known_hosts: entry.known_hosts,
            insecure_ignore_host_key: false,
        },
        entry.required_mount,
    ))
}

#[cfg(test)]
mod tests {
    use super::{NamedDestination, load, name_of, save, upsert, validate};
    use crate::RequiredMount;

    #[test]
    fn a_registry_round_trips_and_validates() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("destinations.toml");
        assert!(load(&path).expect("missing").is_empty());
        let nas = NamedDestination {
            name: "nas".to_owned(),
            uri: "sftp://backup@nas.local/srv/backups".to_owned(),
            identity: Some("/etc/linuxreflect/keys/nas".into()),
            known_hosts: Some("/etc/linuxreflect/known_hosts".into()),
            required_mount: None,
        };
        save(&path, std::slice::from_ref(&nas)).expect("save");
        assert_eq!(load(&path).expect("load"), vec![nas.clone()]);
        assert_eq!(name_of("@nas"), Some("nas"));
        assert_eq!(name_of("/srv/backups"), None);
        for bad in [
            NamedDestination {
                name: "..".to_owned(),
                ..nas.clone()
            },
            NamedDestination {
                uri: "@other".to_owned(),
                ..nas.clone()
            },
            NamedDestination {
                identity: Some("relative/key".into()),
                ..nas.clone()
            },
            NamedDestination {
                required_mount: Some(RequiredMount {
                    path: "/mnt/backup".into(),
                    source: "nas:/export".to_owned(),
                    fs_type: "nfs4".to_owned(),
                }),
                ..nas.clone()
            },
        ] {
            assert!(validate(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_local_required_mount_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("destinations.toml");
        let local = NamedDestination {
            name: "mounted-backups".to_owned(),
            uri: "/mnt/nas/backup-dir".to_owned(),
            identity: None,
            known_hosts: None,
            required_mount: Some(RequiredMount {
                path: "/mnt/nas".into(),
                source: "nas.local:/exports/backup".to_owned(),
                fs_type: "nfs4".to_owned(),
            }),
        };
        save(&path, std::slice::from_ref(&local)).expect("save");
        let text = std::fs::read_to_string(&path).expect("registry text");
        assert!(text.contains("[destination.required_mount]"), "{text}");
        assert_eq!(load(&path).expect("load"), vec![local]);
    }

    #[test]
    fn updating_without_a_mount_policy_preserves_it_and_rejects_incompatible_uris() {
        let original = NamedDestination {
            name: "nas".to_owned(),
            uri: "/mnt/nas/backups".to_owned(),
            identity: None,
            known_hosts: None,
            required_mount: Some(RequiredMount {
                path: "/mnt/nas".into(),
                source: "nas:/backups".to_owned(),
                fs_type: "nfs4".to_owned(),
            }),
        };
        let mut entries = vec![original.clone()];
        upsert(
            &mut entries,
            NamedDestination {
                required_mount: None,
                ..original.clone()
            },
        )
        .expect("legacy update");
        assert_eq!(entries, vec![original.clone()]);
        assert!(
            upsert(
                &mut entries,
                NamedDestination {
                    uri: "sftp://backup@nas/backups".to_owned(),
                    required_mount: None,
                    ..original.clone()
                },
            )
            .is_err()
        );
        assert_eq!(entries, vec![original]);
    }
}
