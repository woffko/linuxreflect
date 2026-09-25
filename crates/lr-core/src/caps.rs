//! Runtime capability probe (spec §A.4).
//!
//! LinuxReflect performs **no** hard kernel-version check. Instead it detects
//! what the running system can actually do and disables the corresponding
//! features with a clear error. `linuxreflect caps` prints this report.

use std::path::Path;
use std::process::Command;

/// One detected capability.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Capability {
    /// Whether the capability is usable right now.
    pub available: bool,
    /// Human-readable detail (version, reason, or probe method).
    pub detail: String,
}

impl Capability {
    /// Available capability with a detail string.
    #[must_use]
    pub fn yes(detail: impl Into<String>) -> Self {
        Self {
            available: true,
            detail: detail.into(),
        }
    }

    /// Unavailable capability with a reason.
    #[must_use]
    pub fn no(detail: impl Into<String>) -> Self {
        Self {
            available: false,
            detail: detail.into(),
        }
    }
}

/// The full capability report.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Capabilities {
    /// `uname -r` equivalent.
    pub kernel_release: String,
    /// NBD kernel module is loadable/present (baseline block export).
    pub nbd: Capability,
    /// `/dev/ublk-control` exists (optional, faster block export).
    pub ublk: Capability,
    /// `FIFREEZE`/`FITHAW` ioctls are supported by the running kernel.
    pub fsfreeze: Capability,
    /// `O_DIRECT` can be used on a regular file/target.
    pub o_direct: Capability,
    /// `btrfs` userspace tooling is present (stream mode).
    pub btrfs_send: Capability,
    /// LVM2 userspace tooling (`lvs`, `lvcreate`, `lvremove`) is present.
    pub lvm2: Capability,
    /// polkit is present; `pidfd` subjects require polkit >= 121.
    pub polkit: Capability,
    /// The process runs as uid 0 (required for backup/restore of devices).
    pub root: Capability,
}

impl Capabilities {
    /// Probe the running system.
    #[must_use]
    pub fn probe() -> Self {
        let kernel_release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .map(|s| s.trim().to_owned())
            .unwrap_or_else(|_| "unknown".to_owned());
        Self {
            kernel_release,
            nbd: probe_nbd(),
            ublk: probe_path("/dev/ublk-control", "ublk-control device"),
            fsfreeze: probe_fsfreeze(),
            o_direct: probe_o_direct(),
            btrfs_send: probe_command("btrfs", &["--version"], "btrfs-progs"),
            lvm2: probe_command("lvs", &["--version"], "lvm2"),
            polkit: probe_polkit(),
            root: probe_root(),
        }
    }

    /// Kernel major/minor parsed from [`Capabilities::kernel_release`].
    #[must_use]
    pub fn kernel_version(&self) -> Option<(u32, u32)> {
        parse_kernel_version(&self.kernel_release)
    }

    /// Warning that must be surfaced before using the freeze provider (spec §A.4).
    ///
    /// Kernels before 5.17 lack the upstream fix "vfs: make freeze_super abort
    /// when sync_filesystem returns error", so a freeze can outlive a failing
    /// writeback. The provider is still safe because of the deadman timer
    /// (spec §E.4), but the user is told. Returns `None` when freeze is
    /// unsupported or the kernel does not need the warning.
    #[must_use]
    pub fn freeze_provider_warning(&self) -> Option<String> {
        if !self.fsfreeze.available {
            return None;
        }
        let (major, minor) = self.kernel_version()?;
        if (major, minor) < (5, 17) {
            Some(format!(
                "kernel {major}.{minor} predates the freeze_super error-handling fix (5.17); \
                 --snapshot freeze is covered by the deadman timer but may block writers longer \
                 than expected"
            ))
        } else {
            None
        }
    }

    /// Require a capability, producing the standard error otherwise.
    ///
    /// # Errors
    /// Returns [`crate::Error::Unsupported`] when the capability is missing.
    pub fn require(&self, name: &str, capability: &Capability) -> crate::Result<()> {
        if capability.available {
            Ok(())
        } else {
            Err(crate::Error::unsupported(format!(
                "{name} unavailable: {}",
                capability.detail
            )))
        }
    }

    /// Iterate over `(name, capability)` pairs for reporting.
    #[must_use]
    pub fn entries(&self) -> [(&'static str, &Capability); 8] {
        [
            ("nbd", &self.nbd),
            ("ublk", &self.ublk),
            ("fsfreeze", &self.fsfreeze),
            ("o_direct", &self.o_direct),
            ("btrfs_send", &self.btrfs_send),
            ("lvm2", &self.lvm2),
            ("polkit", &self.polkit),
            ("root", &self.root),
        ]
    }
}

fn probe_path(path: &str, what: &str) -> Capability {
    if Path::new(path).exists() {
        Capability::yes(format!("{what} present at {path}"))
    } else {
        Capability::no(format!("{what} not found at {path}"))
    }
}

fn probe_nbd() -> Capability {
    if Path::new("/sys/module/nbd").is_dir() {
        return Capability::yes("nbd module is loaded");
    }
    if command_exists("modprobe") && command_succeeds("modprobe", &["-n", "nbd"]) {
        return Capability::yes("nbd module can be loaded (modprobe -n nbd)");
    }
    Capability::no("nbd module not loaded and not loadable")
}

fn probe_fsfreeze() -> Capability {
    let candidate = std::env::temp_dir();
    match lr_unsafe::open_dir_readonly(&candidate) {
        Ok(fd) => {
            if lr_unsafe::fs_freeze_supported(&fd) {
                Capability::yes("FIFREEZE/FITHAW ioctls supported")
            } else {
                Capability::no("FITHAW returned ENOTTY: kernel lacks freeze support")
            }
        }
        Err(e) => {
            // Fall back to the tool check when no directory is openable.
            if command_exists("fsfreeze") {
                Capability::yes(format!("fsfreeze tool present (probe ioctl failed: {e})"))
            } else {
                Capability::no(format!("cannot probe freeze ioctls: {e}"))
            }
        }
    }
}

fn probe_o_direct() -> Capability {
    let mut path = std::env::temp_dir();
    path.push(format!("lr-odirect-probe-{}", std::process::id()));
    let Ok(file) = std::fs::File::create(&path) else {
        return Capability::no(format!("cannot create probe file in {}", path.display()));
    };
    drop(file);
    let result = lr_unsafe::open_o_direct(&path, false);
    let _ = std::fs::remove_file(&path);
    match result {
        Ok(_) => Capability::yes("O_DIRECT open succeeded on a temp file"),
        Err(e) => Capability::no(format!("O_DIRECT open failed: {e}")),
    }
}

fn probe_polkit() -> Capability {
    match command_stdout("pkaction", &["--version"]) {
        Some(version) => {
            let numeric = version
                .trim()
                .rsplit(|c: char| !c.is_ascii_digit() && c != '.')
                .next()
                .unwrap_or_default();
            let major: u32 = numeric
                .split('.')
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            if major >= 121 {
                Capability::yes(format!("{version}; pidfd subjects supported"))
            } else {
                Capability::no(format!("{version}; pidfd subjects need polkit >= 121"))
            }
        }
        None => {
            if Path::new("/usr/lib/polkit-1").is_dir() {
                Capability::yes("polkit is installed; version unknown (pkaction missing)")
            } else {
                Capability::no("polkit not detected")
            }
        }
    }
}

fn probe_root() -> Capability {
    // SAFETY-free: `id -u` avoids an unsafe geteuid call.
    match command_stdout("id", &["-u"]) {
        Some(uid) if uid.trim() == "0" => Capability::yes("running as uid 0"),
        Some(uid) => Capability::no(format!("running as uid {}", uid.trim())),
        None => Capability::no("cannot determine effective uid"),
    }
}

fn command_exists(program: &str) -> bool {
    command_stdout("which", &[program]).is_some()
}

fn command_succeeds(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

fn command_stdout(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    let text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if text.is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        if stderr.is_empty() {
            None
        } else {
            Some(stderr)
        }
    } else {
        Some(text)
    }
}

fn probe_command(program: &str, args: &[&str], label: &str) -> Capability {
    match command_stdout(program, args) {
        Some(version) => Capability::yes(format!("{label}: {}", first_line(&version))),
        None => Capability::no(format!("{label} tool '{program}' not found")),
    }
}

fn first_line(text: &str) -> String {
    text.lines().next().unwrap_or_default().trim().to_owned()
}

/// Parse a kernel release string into `(major, minor)`.
///
/// Accepts upstream (`6.8.12-generic`), stable-queue (`6.6.30`) and vendor
/// strings (`5.14.0-427.el9.x86_64`, `6.18.40.1-microsoft-standard-WSL2`).
#[must_use]
pub fn parse_kernel_version(release: &str) -> Option<(u32, u32)> {
    let core = release.split(['-', '+']).next().unwrap_or(release);
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
    Some((major, minor))
}

#[cfg(test)]
mod tests {
    use super::{Capabilities, parse_kernel_version};

    #[test]
    fn probe_runs_and_reports_kernel() {
        let caps = Capabilities::probe();
        assert!(!caps.kernel_release.is_empty());
        assert_eq!(caps.entries().len(), 8);
    }

    #[test]
    fn require_reports_missing_capability() {
        let caps = Capabilities {
            ublk: super::Capability::no("not found"),
            ..Capabilities::probe()
        };
        let err = caps.require("ublk", &caps.ublk).expect_err("must fail");
        assert!(err.to_string().contains("ublk"));
    }

    #[test]
    fn parses_kernel_releases() {
        assert_eq!(parse_kernel_version("6.8.12-generic"), Some((6, 8)));
        assert_eq!(parse_kernel_version("6.6.30"), Some((6, 6)));
        assert_eq!(parse_kernel_version("5.14.0-427.el9.x86_64"), Some((5, 14)));
        assert_eq!(
            parse_kernel_version("6.18.40.1-microsoft-standard-WSL2"),
            Some((6, 18))
        );
        assert_eq!(parse_kernel_version("nonsense"), None);
    }

    #[test]
    fn freeze_warning_only_below_5_17_with_freeze_support() {
        let base = Capabilities::probe();
        let supported = super::Capability::yes("probe");
        let old = Capabilities {
            kernel_release: "5.14.0-427.el9.x86_64".to_owned(),
            fsfreeze: supported.clone(),
            ..base.clone()
        };
        assert!(old.freeze_provider_warning().is_some());

        let new = Capabilities {
            kernel_release: "6.8.0".to_owned(),
            fsfreeze: supported,
            ..base.clone()
        };
        assert!(new.freeze_provider_warning().is_none());

        let unsupported = Capabilities {
            kernel_release: "5.14.0".to_owned(),
            fsfreeze: super::Capability::no("no ioctl"),
            ..base
        };
        assert!(unsupported.freeze_provider_warning().is_none());
    }
}
