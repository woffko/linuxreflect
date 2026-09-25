//! Remembered choices: the backup folders used most recently, so the wizard
//! can offer them with one click and the library opens on the last one.
//!
//! Stored per user as JSON in `$XDG_CONFIG_HOME/linuxreflect/gui.json`
//! (`~/.config/…` when the variable is unset). Only destination URIs are kept;
//! they never carry passwords (spec §J.1), and passphrase-file paths are not
//! remembered at all.

use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

/// How many folders are remembered.
const KEEP: usize = 5;

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct Stored {
    #[serde(default)]
    recent_destinations: Vec<String>,
}

/// The preferences file for this user, if a home or config directory exists.
pub(crate) fn location() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|value| !value.is_empty())
                .map(|home| PathBuf::from(home).join(".config"))
        })?;
    Some(base.join("linuxreflect").join("gui.json"))
}

/// The remembered folders, newest first. A missing or unreadable file is an
/// empty list: preferences are a convenience, never a reason to fail.
pub(crate) fn recent_destinations(file: &Path) -> Vec<String> {
    std::fs::read(file)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Stored>(&bytes).ok())
        .map(|stored| stored.recent_destinations)
        .unwrap_or_default()
}

/// Put `destination` first, keep at most [`KEEP`], and save. Returns the new
/// list; a failure to save is logged and otherwise ignored.
pub(crate) fn remember_destination(file: &Path, destination: &str) -> Vec<String> {
    let mut recent = recent_destinations(file);
    recent.retain(|known| known != destination);
    recent.insert(0, destination.to_owned());
    recent.truncate(KEEP);
    if let Err(error) = save(
        file,
        &Stored {
            recent_destinations: recent.clone(),
        },
    ) {
        tracing::warn!(%error, file = %file.display(), "cannot save GUI preferences");
    }
    recent
}

/// Write through a private temporary file and rename, so a crash never
/// leaves a half-written file behind.
fn save(file: &Path, stored: &Stored) -> std::io::Result<()> {
    let directory = file
        .parent()
        .ok_or_else(|| std::io::Error::other("the preferences path has no directory"))?;
    std::fs::create_dir_all(directory)?;
    let temporary = directory.join(format!(".gui.json.{}.tmp", std::process::id()));
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temporary)?;
    out.write_all(&serde_json::to_vec_pretty(stored).map_err(std::io::Error::other)?)?;
    out.sync_all()?;
    std::fs::rename(&temporary, file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn recent_folders_are_newest_first_unique_and_bounded() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("linuxreflect/gui.json");
        assert!(recent_destinations(&file).is_empty(), "no file yet");
        for index in 0..7 {
            remember_destination(&file, &format!("/backups/{index}"));
        }
        let recent = remember_destination(&file, "/backups/3");
        assert_eq!(
            recent,
            [
                "/backups/3",
                "/backups/6",
                "/backups/5",
                "/backups/4",
                "/backups/2"
            ]
        );
        assert_eq!(recent_destinations(&file), recent, "saved and reloaded");
        let mode = std::fs::metadata(&file).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn a_damaged_file_is_an_empty_list() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("gui.json");
        std::fs::write(&file, b"{not json").expect("write");
        assert!(recent_destinations(&file).is_empty());
        assert_eq!(remember_destination(&file, "/b"), ["/b"]);
    }
}
