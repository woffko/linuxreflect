//! Attaching an export with `nbd-client` and mounting it read-only
//! (spec §K S13).
//!
//! The kernel side is driven with the distribution's tools — `nbd-client` to
//! attach and `mount` to mount — because those already implement the ioctls and
//! the mount table correctly. The read-only options are the ones the spec
//! names: `ro,noload` for ext4 and `ro,nouuid,norecovery` for xfs, so a
//! journal is never replayed and a second xfs mount does not collide on the
//! UUID.

use std::path::{Path, PathBuf};
use std::process::Command;

use lr_core::{Error, Result};
use serde::{Deserialize, Serialize};

/// Where export state files live.
pub const STATE_DIR: &str = "/run/linuxreflect/exports";

/// One live export, as recorded on disk so `export umount` can clean up.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportState {
    /// Image URI that is being served.
    pub image: String,
    /// Mount point.
    pub mountpoint: PathBuf,
    /// Unix socket the NBD server listens on.
    pub socket: PathBuf,
    /// Attached kernel device (`/dev/nbdX`).
    pub device: PathBuf,
    /// Filesystem type recorded in the image.
    pub fs_type: String,
    /// Read-only mount options that were used.
    pub mount_options: Vec<String>,
    /// Process serving the socket.
    pub server_pid: u32,
    /// `true` when the daemon itself serves the export, rather than a child
    /// process started by the CLI.
    #[serde(default)]
    pub in_process: bool,
}

/// Resolve an image URI into the chain members an export serves.
///
/// # Errors
/// Returns [`Error::Unsupported`] for a URI that is not part of a chain, and
/// propagates destination errors.
pub fn resolve_image(
    image: &str,
    options: &lr_store::DestinationOptions,
) -> Result<(
    lr_store::uri::ImageLocation,
    lr_store::DestinationOptions,
    Vec<String>,
)> {
    let location = lr_store::uri::split_image(image)?;
    let mut destination_options = options.clone();
    destination_options.set_name.clone_from(&location.set);
    let destination = lr_store::open(&location.dest, &destination_options)?;
    let set = destination.open_set(&lr_core::SetId::ZERO)?;
    let chain = lr_engine::chain::resolve_chain(&*destination, &set, &location.name)?;
    if chain.is_empty() {
        return Err(Error::unsupported(format!(
            "{image} is not part of a chain"
        )));
    }
    Ok((
        location,
        destination_options,
        chain.into_iter().map(|member| member.file_name).collect(),
    ))
}

/// Mount options for a filesystem type (spec §K S13).
#[must_use]
pub fn mount_options(fs_type: &str) -> Vec<String> {
    let mut options = vec!["ro".to_owned()];
    match fs_type {
        "ext4" | "ext3" | "ext2" => options.push("noload".to_owned()),
        "xfs" => {
            options.push("nouuid".to_owned());
            options.push("norecovery".to_owned());
        }
        _ => {}
    }
    options
}

/// `true` when the running kernel has the tools the export needs.
#[must_use]
pub fn available() -> (bool, bool) {
    let nbd = which("nbd-client").is_some() && Path::new("/sys/module/nbd").is_dir();
    let mount = which("mount").is_some();
    (nbd, mount)
}

fn which(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
}

/// Kernel NBD devices that are not attached.
///
/// # Errors
/// Returns [`Error::Unsupported`] when `/sys/block` cannot be read.
pub fn free_devices() -> Result<Vec<PathBuf>> {
    let mut devices = Vec::new();
    let entries = std::fs::read_dir("/sys/block").map_err(Error::Io)?;
    for entry in entries {
        let entry = entry.map_err(Error::Io)?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("nbd") {
            continue;
        }
        // A device with a `pid` attribute is attached to a client.
        if entry.path().join("pid").exists() {
            continue;
        }
        let device = Path::new("/dev").join(name.as_ref());
        if device.exists() {
            devices.push(device);
        }
    }
    devices.sort();
    Ok(devices)
}

/// Attach `device` to the NBD server listening on `socket`.
///
/// # Errors
/// Returns [`Error::Unsupported`] when `nbd-client` is missing or fails.
pub fn attach(socket: &Path, device: &Path) -> Result<()> {
    let output = Command::new("nbd-client")
        .arg("-unix")
        .arg(socket)
        .arg(device)
        .output()
        .map_err(|error| Error::unsupported(format!("nbd-client could not be started: {error}")))?;
    if !output.status.success() {
        return Err(Error::unsupported(format!(
            "nbd-client {} failed: {}{}",
            device.display(),
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

/// Detach a kernel device from its NBD server.
///
/// # Errors
/// Returns [`Error::Unsupported`] when `nbd-client -d` fails.
pub fn detach(device: &Path) -> Result<()> {
    let output = Command::new("nbd-client")
        .arg("-d")
        .arg(device)
        .output()
        .map_err(|error| Error::unsupported(format!("nbd-client could not be started: {error}")))?;
    if !output.status.success() {
        return Err(Error::unsupported(format!(
            "nbd-client -d {} failed: {}",
            device.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

/// Mount `device` read-only at `mountpoint` with the options for `fs_type`.
///
/// # Errors
/// Returns [`Error::Unsupported`] when `mount` fails, and creates the mount
/// point when it does not exist.
pub fn mount_read_only(device: &Path, mountpoint: &Path, fs_type: &str) -> Result<Vec<String>> {
    std::fs::create_dir_all(mountpoint).map_err(Error::Io)?;
    let options = mount_options(fs_type);
    let output = Command::new("mount")
        .arg("-t")
        .arg(fs_type)
        .arg("-o")
        .arg(options.join(","))
        .arg(device)
        .arg(mountpoint)
        .output()
        .map_err(|error| Error::unsupported(format!("mount could not be started: {error}")))?;
    if !output.status.success() {
        return Err(Error::unsupported(format!(
            "mount -t {fs_type} -o {} failed: {}",
            options.join(","),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(options)
}

/// Unmount a mount point.
///
/// # Errors
/// Returns [`Error::Unsupported`] when `umount` fails.
pub fn unmount(mountpoint: &Path) -> Result<()> {
    let output = Command::new("umount")
        .arg(mountpoint)
        .output()
        .map_err(|error| Error::unsupported(format!("umount could not be started: {error}")))?;
    if !output.status.success() {
        return Err(Error::unsupported(format!(
            "umount {} failed: {}",
            mountpoint.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

/// Persist `state` so a later `export umount` finds it.
///
/// # Errors
/// Returns [`Error::Io`] when the state directory or file cannot be written.
pub fn save_state(state: &ExportState) -> Result<PathBuf> {
    std::fs::create_dir_all(STATE_DIR).map_err(Error::Io)?;
    let path = state_path(&state.mountpoint);
    let json = serde_json::to_vec_pretty(state)
        .map_err(|error| Error::corrupt(format!("export state json: {error}")))?;
    std::fs::write(&path, json).map_err(Error::Io)?;
    Ok(path)
}

/// Load the state for a mount point.
///
/// # Errors
/// Returns [`Error::Unsupported`] when no export is mounted there.
pub fn load_state(mountpoint: &Path) -> Result<ExportState> {
    let path = state_path(mountpoint);
    let bytes = std::fs::read(&path).map_err(|error| {
        Error::unsupported(format!(
            "no export is recorded for {} ({error})",
            mountpoint.display()
        ))
    })?;
    serde_json::from_slice(&bytes)
        .map_err(|error| Error::corrupt(format!("export state at {}: {error}", path.display())))
}

/// Remove the state file for a mount point.
///
/// # Errors
/// Returns [`Error::Io`] when the file exists but cannot be removed.
pub fn clear_state(mountpoint: &Path) -> Result<()> {
    let path = state_path(mountpoint);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Error::Io(error)),
    }
}

/// State files of every live export.
///
/// # Errors
/// Returns [`Error::Io`] when the state directory cannot be listed.
pub fn list_state() -> Result<Vec<ExportState>> {
    let mut states = Vec::new();
    let entries = match std::fs::read_dir(STATE_DIR) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(states),
        Err(error) => return Err(Error::Io(error)),
    };
    for entry in entries {
        let entry = entry.map_err(Error::Io)?;
        if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let bytes = std::fs::read(entry.path()).map_err(Error::Io)?;
        match serde_json::from_slice(&bytes) {
            Ok(state) => states.push(state),
            Err(error) => {
                tracing::warn!(path = %entry.path().display(), %error, "unreadable export state");
            }
        }
    }
    states.sort_by(|left, right| left.mountpoint.cmp(&right.mountpoint));
    Ok(states)
}

fn state_path(mountpoint: &Path) -> PathBuf {
    // The mount point identifies the export; a lossy hash-free encoding keeps
    // the file name readable and unique per path.
    let mut name = String::from("export-");
    for byte in mountpoint.as_os_str().as_encoded_bytes() {
        if byte.is_ascii_alphanumeric() {
            name.push(*byte as char);
        } else {
            name.push('_');
        }
    }
    name.push_str(".json");
    Path::new(STATE_DIR).join(name)
}

/// `true` when `mountpoint` currently has something mounted on it.
#[must_use]
pub fn is_mounted(mountpoint: &Path) -> bool {
    let output = Command::new("findmnt")
        .args(["-n", "-T"])
        .arg(mountpoint)
        .output();
    match output {
        Ok(output) => {
            output.status.success()
                && String::from_utf8_lossy(&output.stdout)
                    .trim()
                    .starts_with(&mountpoint.to_string_lossy().to_string())
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{mount_options, state_path};

    #[test]
    fn the_spec_mount_options_are_used() {
        assert_eq!(mount_options("ext4"), vec!["ro", "noload"]);
        assert_eq!(mount_options("ext3"), vec!["ro", "noload"]);
        assert_eq!(mount_options("xfs"), vec!["ro", "nouuid", "norecovery"]);
        // Something else still mounts read-only.
        assert_eq!(mount_options("vfat"), vec!["ro"]);
        assert_eq!(mount_options("btrfs"), vec!["ro"]);
    }

    #[test]
    fn state_files_are_named_after_the_mount_point() {
        let path = state_path(std::path::Path::new("/mnt/backup here"));
        let name = path.file_name().expect("name").to_string_lossy();
        assert!(name.starts_with("export-"), "{name}");
        assert!(name.ends_with(".json"), "{name}");
        assert!(!name.contains('/'), "{name}");
    }
}
