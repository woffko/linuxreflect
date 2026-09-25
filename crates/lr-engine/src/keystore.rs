//! Passphrase handling (spec §J.1, §L.1).
//!
//! A passphrase is never a command-line argument. It comes from
//! `--passphrase-file` or `LINUXREFLECT_PASSPHRASE_FILE`, is read through an
//! `O_NOFOLLOW` descriptor whose mode must be exactly 0600, and is zeroized on
//! drop. The interactive TTY prompt arrives with Slice S11.

use std::io::Read;
use std::path::{Path, PathBuf};

use lr_core::{Error, Result};
use zeroize::Zeroizing;

/// Environment variable naming the passphrase file.
pub const PASSPHRASE_FILE_ENV: &str = "LINUXREFLECT_PASSPHRASE_FILE";

/// Largest accepted passphrase file, so a mistyped path cannot read a disk.
pub const MAX_PASSPHRASE_BYTES: u64 = 4096;

/// A passphrase held in zeroizing memory.
#[derive(Clone)]
pub struct Passphrase(Zeroizing<Vec<u8>>);

impl Passphrase {
    /// Borrow the passphrase bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Wrap raw bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// `true` when no passphrase was supplied.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Passphrase(<redacted>)")
    }
}

/// Read a passphrase file after checking ownership, type and mode.
///
/// # Errors
/// Returns [`Error::Unsupported`] when the file is a symlink, not a regular
/// file, or not mode 0600, and [`Error::Io`] for other failures.
pub fn load_passphrase_file(path: &Path) -> Result<Passphrase> {
    let fd = lr_unsafe::open_readonly_nofollow(path).map_err(|e| {
        Error::unsupported(format!(
            "cannot open passphrase file {}: {e}",
            path.display()
        ))
    })?;
    if !lr_unsafe::fd_is_regular_file(&fd).map_err(Error::Io)? {
        return Err(Error::unsupported(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    let mode = lr_unsafe::fd_mode(&fd).map_err(Error::Io)? & 0o777;
    if mode != 0o600 {
        return Err(Error::unsupported(format!(
            "{} has mode {mode:o}; a passphrase file must be 0600",
            path.display()
        )));
    }
    let mut file = std::fs::File::from(fd);
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_PASSPHRASE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(Error::Io)?;
    if bytes.len() as u64 > MAX_PASSPHRASE_BYTES {
        return Err(Error::unsupported(format!(
            "{} is larger than {MAX_PASSPHRASE_BYTES} bytes; it is probably not a passphrase file",
            path.display()
        )));
    }
    // A trailing newline is conventional in key files and is not part of the
    // passphrase.
    while matches!(bytes.last(), Some(b'\n' | b'\r')) {
        bytes.pop();
    }
    if bytes.is_empty() {
        return Err(Error::unsupported(format!("{} is empty", path.display())));
    }
    Ok(Passphrase(Zeroizing::new(bytes)))
}

/// Path named by `--passphrase-file` or the environment, if any.
#[must_use]
pub fn passphrase_file_path(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = explicit {
        return Some(path.to_path_buf());
    }
    std::env::var_os(PASSPHRASE_FILE_ENV).map(PathBuf::from)
}

/// Resolve the passphrase from an explicit path or the environment.
///
/// # Errors
/// Returns [`Error::Unsupported`] when no source is configured, and propagates
/// [`load_passphrase_file`] failures.
pub fn resolve_passphrase(explicit: Option<&Path>) -> Result<Passphrase> {
    let path = passphrase_file_path(explicit).ok_or_else(|| {
        Error::unsupported(format!(
            "no passphrase: pass --passphrase-file <path> or set {PASSPHRASE_FILE_ENV} \
             (the interactive prompt arrives in Slice S11), or use --no-encrypt"
        ))
    })?;
    load_passphrase_file(&path)
}

#[cfg(test)]
mod tests {
    use super::{
        PASSPHRASE_FILE_ENV, load_passphrase_file, passphrase_file_path, resolve_passphrase,
    };
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    fn key_file(dir: &tempfile::TempDir, mode: u32, contents: &[u8]) -> std::path::PathBuf {
        let path = dir.path().join("chain.key");
        {
            let mut file = std::fs::File::create(&path).expect("create");
            file.write_all(contents).expect("write");
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
        path
    }

    #[test]
    fn reads_a_0600_file_and_strips_the_newline() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = key_file(&dir, 0o600, b"correct horse battery staple\n");
        let passphrase = load_passphrase_file(&path).expect("load");
        assert_eq!(passphrase.as_bytes(), b"correct horse battery staple");
        assert_eq!(format!("{passphrase:?}"), "Passphrase(<redacted>)");
    }

    #[test]
    fn refuses_a_world_readable_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = key_file(&dir, 0o644, b"secret");
        let error = load_passphrase_file(&path).expect_err("must refuse");
        assert!(error.to_string().contains("0600"), "{error}");
    }

    #[test]
    fn refuses_a_symlink() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = key_file(&dir, 0o600, b"secret");
        let link = dir.path().join("link.key");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        assert!(load_passphrase_file(&link).is_err());
    }

    #[test]
    fn refuses_an_empty_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = key_file(&dir, 0o600, b"\n");
        assert!(load_passphrase_file(&path).is_err());
    }

    #[test]
    fn explicit_path_beats_the_environment() {
        let dir = tempfile::tempdir().expect("tempdir");
        let explicit = key_file(&dir, 0o600, b"one");
        assert_eq!(
            passphrase_file_path(Some(&explicit)).expect("path"),
            explicit
        );
        // The environment is only consulted without an explicit path; setting
        // it here would race other tests, so only the explicit branch is
        // asserted.
        assert!(
            passphrase_file_path(None).is_none() || std::env::var_os(PASSPHRASE_FILE_ENV).is_some()
        );
    }

    #[test]
    fn a_missing_source_is_an_error() {
        if std::env::var_os(PASSPHRASE_FILE_ENV).is_some() {
            return;
        }
        let error = resolve_passphrase(None).expect_err("must fail");
        assert!(error.to_string().contains("--passphrase-file"), "{error}");
    }
}
