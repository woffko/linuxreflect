//! Destination URIs (spec §J.1, §J.2).
//!
//! A destination is a local path (`/srv/backups`, `file:///srv/backups`) or an
//! SFTP URL (`sftp://backup@nas.local/backups/laptop`). Credentials are never
//! part of a URI: a `user:password@host` form is rejected so a secret can never
//! reach a command line, a log line or the process list (§L.1).

use std::path::{Component, Path, PathBuf};

use lr_core::{Error, Result};

/// A parsed destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DestinationUri {
    /// A local directory (which may be a mounted network path).
    Local {
        /// Directory the sets live under.
        path: PathBuf,
    },
    /// An SFTP server.
    Sftp {
        /// Login user; the client's own user when absent.
        user: Option<String>,
        /// Host name or address.
        host: String,
        /// TCP port.
        port: u16,
        /// Absolute or `~`-relative path on the server.
        path: String,
    },
}

impl DestinationUri {
    /// `true` for a local directory.
    #[must_use]
    pub const fn is_local(&self) -> bool {
        matches!(self, Self::Local { .. })
    }

    /// The authority part of the URI, without any trailing path.
    #[must_use]
    pub fn authority(&self) -> String {
        match self {
            Self::Local { .. } => String::new(),
            Self::Sftp {
                user, host, port, ..
            } => {
                let user = user.as_deref().map_or(String::new(), |u| format!("{u}@"));
                format!("sftp://{user}{host}:{port}")
            }
        }
    }
}

/// Parse a destination URI.
///
/// # Errors
/// Returns [`Error::Unsupported`] for an unknown scheme, a missing host or
/// path, a password in the URI, or a non-numeric port.
pub fn parse(uri: &str) -> Result<DestinationUri> {
    let uri = uri.trim();
    if uri.is_empty() {
        return Err(Error::unsupported("the destination URI is empty"));
    }
    if let Some(rest) = uri.strip_prefix("sftp://") {
        return parse_sftp(rest);
    }
    if let Some(rest) = uri.strip_prefix("file://") {
        // `file:///srv/backups` and `file://srv/backups` both mean a path.
        let path = if rest.starts_with('/') { rest } else { uri };
        return Ok(DestinationUri::Local {
            path: PathBuf::from(path),
        });
    }
    if uri.contains("://") {
        let scheme = uri.split("://").next().unwrap_or_default();
        return Err(Error::unsupported(format!(
            "destination scheme '{scheme}' is not supported (use a path, file:// or sftp://)"
        )));
    }
    Ok(DestinationUri::Local {
        path: PathBuf::from(uri),
    })
}

fn parse_sftp(rest: &str) -> Result<DestinationUri> {
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, String::new()),
    };
    if path.is_empty() {
        return Err(Error::unsupported(
            "an sftp destination needs a path, e.g. sftp://host/srv/backups",
        ));
    }
    // Split the user first: a colon inside it is a password, not a port.
    let (user, host_port) = match authority.split_once('@') {
        Some((user, host)) => {
            if user.contains(':') {
                return Err(Error::unsupported(
                    "a password in a destination URI is refused; use --identity or ssh-agent",
                ));
            }
            (Some(user.to_owned()), host.to_owned())
        }
        None => (None, authority.to_owned()),
    };
    let (host, port) = split_port(&host_port)?;
    if host.is_empty() {
        return Err(Error::unsupported("an sftp destination needs a host"));
    }
    Ok(DestinationUri::Sftp {
        user,
        host,
        port,
        path,
    })
}

/// Split `[user@]host[:port]`, rejecting an empty or non-numeric port.
fn split_port(authority: &str) -> Result<(String, u16)> {
    // Only a port *after the host* counts; an `@`-separated user may not contain
    // a colon (that would be a password, caught by the caller).
    let Some((host_part, port)) = authority.rsplit_once(':') else {
        return Ok((authority.to_owned(), 22));
    };
    if port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
        return Err(Error::unsupported(format!("'{port}' is not an sftp port")));
    }
    let port: u16 = port
        .parse()
        .map_err(|_| Error::unsupported(format!("sftp port '{port}' is out of range")))?;
    Ok((host_part.to_owned(), port))
}

/// One image's place in a set: destination, set name and set-relative name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageLocation {
    /// Destination the set lives on, as a URI.
    pub dest: String,
    /// Set name (one path component).
    pub set: String,
    /// Set-relative name, e.g. `<chain_id>/000-full-<uuid>.lrimg`.
    pub name: String,
}

/// Split an image URI into its destination, set and name.
///
/// The layout is fixed by spec §D.3: `<dest>/<set-name>/<chain_id>/<file>`, so
/// the last three path components identify the file, the chain and the set.
///
/// # Errors
/// Returns [`Error::Unsupported`] when the URI is not deep enough to contain a
/// set, a chain and a file name.
pub fn split_image(uri: &str) -> Result<ImageLocation> {
    let parsed = parse(uri)?;
    /// Rebuilds the destination part from the leading path components.
    type Rebuild = Box<dyn Fn(&[String]) -> String>;
    let (components, rebuild): (Vec<String>, Rebuild) = match &parsed {
        DestinationUri::Local { path } => {
            let components = path_components(path)?;
            (
                components,
                Box::new(|prefix: &[String]| {
                    let joined = prefix.join("/");
                    if joined.is_empty() {
                        "/".to_owned()
                    } else {
                        format!("/{joined}")
                    }
                }),
            )
        }
        DestinationUri::Sftp { path, .. } => {
            let components = path
                .split('/')
                .filter(|part| !part.is_empty() && *part != ".")
                .map(str::to_owned)
                .collect::<Vec<_>>();
            let authority = parsed.authority();
            (
                components,
                Box::new(move |prefix: &[String]| format!("{authority}/{}", prefix.join("/"))),
            )
        }
    };
    if components.len() < 3 {
        return Err(Error::unsupported(format!(
            "'{uri}' must name a set, a chain and a member, e.g. <dest>/<set>/<chain>/<file>.lrimg"
        )));
    }
    let split = components.len() - 3;
    let dest = rebuild(&components[..split]);
    Ok(ImageLocation {
        dest,
        set: components[split].clone(),
        name: components[split + 1..].join("/"),
    })
}

fn path_components(path: &Path) -> Result<Vec<String>> {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => components.push(part.to_string_lossy().into_owned()),
            Component::RootDir => {}
            Component::CurDir => {}
            other => {
                return Err(Error::unsupported(format!(
                    "an image path may not contain {other:?}"
                )));
            }
        }
    }
    Ok(components)
}

#[cfg(test)]
mod tests {
    use super::{DestinationUri, parse, split_image};

    #[test]
    fn local_paths_and_file_urls_parse() {
        assert_eq!(
            parse("/srv/backups").expect("path"),
            DestinationUri::Local {
                path: "/srv/backups".into()
            }
        );
        assert_eq!(
            parse("file:///srv/backups").expect("file url"),
            DestinationUri::Local {
                path: "/srv/backups".into()
            }
        );
        assert!(parse("").is_err());
        assert!(parse("http://host/x").is_err());
    }

    #[test]
    fn sftp_urls_parse_with_defaults() {
        assert_eq!(
            parse("sftp://nas.local/backups/laptop").expect("sftp"),
            DestinationUri::Sftp {
                user: None,
                host: "nas.local".to_owned(),
                port: 22,
                path: "/backups/laptop".to_owned(),
            }
        );
        assert_eq!(
            parse("sftp://backup@nas.local:2222/backups").expect("sftp"),
            DestinationUri::Sftp {
                user: Some("backup".to_owned()),
                host: "nas.local".to_owned(),
                port: 2222,
                path: "/backups".to_owned(),
            }
        );
    }

    #[test]
    fn a_password_in_a_uri_is_refused() {
        let error = parse("sftp://backup:secret@nas.local/backups").expect_err("must refuse");
        assert!(error.to_string().contains("password"), "{error}");
        assert!(parse("sftp://nas.local").is_err(), "a path is required");
        assert!(parse("sftp://nas.local:abc/backups").is_err(), "bad port");
    }

    #[test]
    fn an_image_uri_splits_into_dest_set_and_name() {
        let location = split_image("/backups/laptop-root/chain-1/000-full-a.lrimg").expect("split");
        assert_eq!(location.dest, "/backups");
        assert_eq!(location.set, "laptop-root");
        assert_eq!(location.name, "chain-1/000-full-a.lrimg");

        let location =
            split_image("sftp://backup@nas.local/srv/backups/laptop-root/chain-1/001-incr-b.lrimg")
                .expect("split");
        assert_eq!(location.dest, "sftp://backup@nas.local:22/srv/backups");
        assert_eq!(location.set, "laptop-root");
        assert_eq!(location.name, "chain-1/001-incr-b.lrimg");

        assert!(split_image("/backups/a.lrimg").is_err());
    }
}
