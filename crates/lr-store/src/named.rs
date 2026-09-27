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

use crate::DestinationOptions;

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
/// `known_hosts` path that is not absolute.
pub fn validate(entry: &NamedDestination) -> Result<()> {
    lr_core::validate_set_name(&entry.name).map_err(|_| {
        Error::unsupported(format!("'{}' is not a valid destination name", entry.name))
    })?;
    if name_of(&entry.uri).is_some() {
        return Err(Error::unsupported(
            "a destination cannot point at another named one",
        ));
    }
    crate::uri::parse(&entry.uri)?;
    for path in [&entry.identity, &entry.known_hosts].into_iter().flatten() {
        if !path.is_absolute() {
            return Err(Error::unsupported(format!(
                "{} must be an absolute path",
                path.display()
            )));
        }
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
///
/// # Errors
/// Returns [`Error::Unsupported`] for a name that is not configured, and
/// propagates registry errors.
pub fn resolve(dest: &str, options: &DestinationOptions) -> Result<(String, DestinationOptions)> {
    let Some(name) = name_of(dest) else {
        return Ok((dest.to_owned(), options.clone()));
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
    Ok((
        entry.uri,
        DestinationOptions {
            set_name: options.set_name.clone(),
            identity: entry.identity,
            known_hosts: entry.known_hosts,
            insecure_ignore_host_key: false,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::{NamedDestination, load, name_of, save, validate};

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
        ] {
            assert!(validate(&bad).is_err(), "{bad:?}");
        }
    }
}
