//! Job configuration and systemd unit generation (spec §J.2, §J.4, §K S14).
//!
//! The config file is the single description of what a scheduled job does, and
//! the daemon materializes it as `linuxreflect-job@<name>.timer` plus
//! `.service` units under `/etc/systemd/system/` (spec §J.4). `OnCalendar`,
//! `Persistent` and `RandomizedDelaySec` are copied verbatim; a network
//! destination adds `Wants=network-online.target`/`After=network-online.target`
//! so the job does not start before the network is up.
//!
//! Rendering and writing live here rather than in the daemon so the CLI's
//! in-process fallback and the daemon share exactly one implementation.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use lr_core::{Error, Result};
use serde::{Deserialize, Serialize};

/// Where units go by default.
pub const DEFAULT_SYSTEMD_DIR: &str = "/etc/systemd/system";
/// Where the config file lives by default.
pub const DEFAULT_CONFIG: &str = "/etc/linuxreflect/config.toml";
/// Unit name prefix; the spec names the units `linuxreflect-job@<name>`.
pub const UNIT_PREFIX: &str = "linuxreflect-job@";

/// The whole config file (spec §J.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Daemon settings.
    #[serde(default)]
    pub daemon: DaemonConfig,
    /// Scheduled jobs.
    #[serde(default, rename = "job")]
    pub jobs: Vec<JobConfig>,
    /// Named destinations.
    #[serde(default)]
    pub destinations: BTreeMap<String, DestinationConfig>,
}

/// `[daemon]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonConfig {
    /// Socket path.
    #[serde(default = "default_socket")]
    pub socket: String,
    /// Log level.
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// Default LVM snapshot COW size.
    #[serde(default)]
    pub lvm_cow_size: Option<String>,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            socket: default_socket(),
            log_level: default_log_level(),
            lvm_cow_size: None,
        }
    }
}

fn default_socket() -> String {
    "/run/linuxreflect/daemon.sock".to_owned()
}

fn default_log_level() -> String {
    "info".to_owned()
}

/// One `[[job]]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobConfig {
    /// Job name; used in the unit names.
    pub name: String,
    /// Sources (devices or directories).
    pub source: Vec<String>,
    /// Destination: a named destination, a path or a URI.
    pub dest: String,
    /// Set name.
    pub set: String,
    /// `full | incremental | differential`.
    #[serde(default = "default_type", rename = "type")]
    pub member_type: String,
    /// `latest | <uuid>`.
    #[serde(default)]
    pub parent: Option<String>,
    /// `auto | block | stream | file`.
    #[serde(default)]
    pub mode: Option<String>,
    /// `auto | btrfs | lvm | freeze | offline | none`.
    #[serde(default)]
    pub snapshot: Option<String>,
    /// Compression, `zstd:9` or `none`.
    #[serde(default)]
    pub compress: Option<String>,
    /// Encrypt with a passphrase file.
    #[serde(default = "default_true")]
    pub encrypt: bool,
    /// Passphrase file (0600 root).
    #[serde(default)]
    pub passphrase_file: Option<PathBuf>,
    /// systemd calendar expression, copied verbatim.
    pub on_calendar: String,
    /// `RandomizedDelaySec`, copied verbatim.
    #[serde(default)]
    pub randomized_delay: Option<String>,
    /// `Persistent=`.
    #[serde(default)]
    pub persistent: bool,
    /// Retention settings.
    #[serde(default)]
    pub retention: Option<RetentionConfig>,
}

fn default_type() -> String {
    "incremental".to_owned()
}

const fn default_true() -> bool {
    true
}

/// `[job.retention]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RetentionConfig {
    /// Whole chains to keep.
    #[serde(default)]
    pub keep_chains: Option<usize>,
    /// Start a new chain after this many incrementals.
    #[serde(default)]
    pub max_incrementals_per_chain: Option<u64>,
    /// Optional calendar expression that forces a new chain.
    #[serde(default)]
    pub new_chain_on_calendar: Option<String>,
}

/// One `[destinations.<name>]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationConfig {
    /// `sftp | local`.
    pub kind: String,
    /// Host for a network destination.
    #[serde(default)]
    pub host: Option<String>,
    /// User for a network destination.
    #[serde(default)]
    pub user: Option<String>,
    /// `known_hosts` file.
    #[serde(default)]
    pub known_hosts: Option<PathBuf>,
    /// Identity file.
    #[serde(default)]
    pub identity: Option<PathBuf>,
    /// Path on the destination.
    #[serde(default)]
    pub path: Option<String>,
}

impl DestinationConfig {
    /// The URI this destination describes.
    #[must_use]
    pub fn uri(&self) -> String {
        match (self.kind.as_str(), &self.host, &self.path) {
            ("sftp", Some(host), Some(path)) => {
                let user = self
                    .user
                    .as_ref()
                    .map_or_else(String::new, |user| format!("{user}@"));
                format!("sftp://{user}{host}{path}")
            }
            _ => self.path.clone().unwrap_or_default(),
        }
    }

    /// `true` when the destination needs the network.
    #[must_use]
    pub fn is_network(&self) -> bool {
        self.kind == "sftp"
    }
}

/// Parse a config file.
///
/// # Errors
/// Returns [`Error::Unsupported`] for unreadable files and [`Error::Corrupt`]
/// for invalid TOML or a job missing required fields.
pub fn parse(text: &str) -> Result<Config> {
    let config: Config =
        toml::from_str(text).map_err(|error| Error::corrupt(format!("config.toml: {error}")))?;
    validate(&config)?;
    Ok(config)
}

/// Read and parse a config file.
///
/// # Errors
/// Returns [`Error::Unsupported`] when the file cannot be read, and the parse
/// errors of [`parse`].
pub fn load(path: &Path) -> Result<Config> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| Error::unsupported(format!("cannot read {}: {error}", path.display())))?;
    parse(&text).map_err(|error| match error {
        Error::Corrupt { what } => Error::corrupt(format!("{}: {what}", path.display())),
        other => other,
    })
}

fn validate(config: &Config) -> Result<()> {
    let mut names = std::collections::BTreeSet::new();
    for job in &config.jobs {
        lr_core::validate_job_name(&job.name).map_err(|error| Error::corrupt(error.to_string()))?;
        lr_core::validate_set_name(&job.set)
            .map_err(|error| Error::corrupt(format!("job {}: {error}", job.name)))?;
        if !names.insert(job.name.clone()) {
            return Err(Error::corrupt(format!("duplicate job name {}", job.name)));
        }
        if job.source.is_empty() {
            return Err(Error::corrupt(format!("job {} has no source", job.name)));
        }
        if job.dest.is_empty() {
            return Err(Error::corrupt(format!(
                "job {} has no destination",
                job.name
            )));
        }
        if job.on_calendar.trim().is_empty() {
            return Err(Error::corrupt(format!(
                "job {} has an empty on_calendar",
                job.name
            )));
        }
        match job.member_type.as_str() {
            "full" | "incremental" | "differential" => {}
            other => {
                return Err(Error::corrupt(format!(
                    "job {} has an unknown type `{other}`",
                    job.name
                )));
            }
        }
        if job.encrypt && job.passphrase_file.is_none() {
            return Err(Error::corrupt(format!(
                "job {} encrypts but names no passphrase_file",
                job.name
            )));
        }
        if let Some(destination) = config.destinations.get(&job.dest)
            && destination.uri().is_empty()
        {
            return Err(Error::corrupt(format!(
                "job {} names destination {}, which has no path",
                job.name, job.dest
            )));
        }
    }
    Ok(())
}

/// The destination URI and network requirement of a job.
///
/// # Errors
/// Returns [`Error::Corrupt`] when a named destination is missing.
pub fn resolve_destination(config: &Config, job: &JobConfig) -> Result<(String, bool)> {
    if let Some(destination) = config.destinations.get(&job.dest) {
        let uri = destination.uri();
        if uri.is_empty() {
            return Err(Error::corrupt(format!(
                "destination {} has no path",
                job.dest
            )));
        }
        return Ok((uri, destination.is_network()));
    }
    // Not a named destination: a path or a URI written in place.
    Ok((job.dest.clone(), job.dest.contains("://")))
}

/// The rendered units of one job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobUnits {
    /// Job name.
    pub job: String,
    /// Service unit file name.
    pub service_name: String,
    /// Service unit contents.
    pub service: String,
    /// Timer unit file name.
    pub timer_name: String,
    /// Timer unit contents.
    pub timer: String,
    /// Destination URI the job writes to.
    pub destination: String,
}

/// Render the `.service` and `.timer` units of one job.
///
/// `cli` is the absolute path of the `linuxreflect` binary the service runs.
///
/// # Errors
/// Returns [`Error::Corrupt`] when a named destination is missing or a
/// passphrase file is used without encrypting.
pub fn render_job(config: &Config, job: &JobConfig, cli: &Path) -> Result<JobUnits> {
    let (destination, network) = resolve_destination(config, job)?;
    let mut service = String::new();
    service.push_str("[Unit]\n");
    service.push_str(&format!(
        "Description=LinuxReflect backup job {}\n",
        job.name
    ));
    if network {
        service.push_str("Wants=network-online.target\n");
        service.push_str("After=network-online.target\n");
    }
    service.push_str("\n[Service]\n");
    service.push_str("Type=oneshot\n");
    service.push_str("User=root\n");
    for source in &job.source {
        let mut command = format!(
            "{} backup create --source {} --dest {} --set {} --type {}",
            cli.display(),
            source,
            destination,
            job.set,
            job.member_type
        );
        if job.member_type != "full" {
            command.push_str(&format!(
                " --parent {}",
                job.parent.clone().unwrap_or_else(|| "latest".to_owned())
            ));
        }
        if let Some(mode) = &job.mode {
            command.push_str(&format!(" --mode {mode}"));
        }
        if let Some(snapshot) = &job.snapshot {
            command.push_str(&format!(" --snapshot {snapshot}"));
        }
        if let Some(compress) = &job.compress {
            command.push_str(&format!(" --compress {compress}"));
        }
        if !job.encrypt {
            command.push_str(" --no-encrypt");
        } else if let Some(passphrase) = &job.passphrase_file {
            command.push_str(&format!(" --passphrase-file {}", passphrase.display()));
        }
        if let Some(retention) = &job.retention
            && let Some(max) = retention.max_incrementals_per_chain
        {
            command.push_str(&format!(" --max-incrementals {max}"));
        }
        command.push_str(" --json");
        service.push_str(&format!("ExecStart={command}\n"));
    }
    // Retention runs right after the backup, against the same set, so
    // `keep_chains` holds without a second timer.
    if let Some(retention) = &job.retention
        && let Some(keep) = retention.keep_chains
    {
        service.push_str(&format!(
            "ExecStart={} retention apply --dest {} --set {} --keep-chains {}\n",
            cli.display(),
            destination,
            job.set,
            keep
        ));
    }

    let mut timer = String::new();
    timer.push_str("[Unit]\n");
    timer.push_str(&format!(
        "Description=LinuxReflect backup timer for {}\n",
        job.name
    ));
    timer.push_str("\n[Timer]\n");
    timer.push_str(&format!("OnCalendar={}\n", job.on_calendar));
    timer.push_str(&format!("Persistent={}\n", job.persistent));
    if let Some(delay) = &job.randomized_delay {
        timer.push_str(&format!("RandomizedDelaySec={delay}\n"));
    }
    timer.push_str(&format!("Unit={}\n", unit_name(&job.name, "service")));
    timer.push_str("\n[Install]\n");
    timer.push_str("WantedBy=timers.target\n");

    Ok(JobUnits {
        job: job.name.clone(),
        service_name: unit_name(&job.name, "service"),
        service,
        timer_name: unit_name(&job.name, "timer"),
        timer,
        destination,
    })
}

/// `linuxreflect-job@<name>.<kind>` (spec §J.4).
#[must_use]
pub fn unit_name(job: &str, kind: &str) -> String {
    format!("{UNIT_PREFIX}{job}.{kind}")
}

/// What materialization did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleReport {
    /// Config file that was read.
    pub config: String,
    /// Unit directory that was used.
    pub systemd_dir: String,
    /// `true` when nothing was written.
    pub dry_run: bool,
    /// The rendered jobs.
    pub jobs: Vec<JobUnits>,
    /// Files that were written.
    pub written: Vec<PathBuf>,
    /// `true` when `systemctl daemon-reload` was run.
    pub reloaded: bool,
    /// `true` when the timers were enabled and started.
    pub started: bool,
    /// Non-fatal notes.
    pub warnings: Vec<String>,
}

/// Read a config, render its units and write them.
///
/// `cli` is the binary the services run; `systemd_dir` defaults to
/// [`DEFAULT_SYSTEMD_DIR`]. `daemon_reload` and `start` are separate so a test
/// (or a dry run) can render and validate without touching systemd.
///
/// # Errors
/// Returns the config and rendering errors, and [`Error::Io`] when a unit
/// cannot be written or `systemctl` cannot be run.
pub fn materialize(
    config_path: &Path,
    cli: &Path,
    systemd_dir: Option<&Path>,
    dry_run: bool,
    daemon_reload: bool,
    start: bool,
) -> Result<ScheduleReport> {
    let config = load(config_path)?;
    let systemd_dir =
        systemd_dir.map_or_else(|| PathBuf::from(DEFAULT_SYSTEMD_DIR), Path::to_path_buf);
    let mut jobs = Vec::new();
    for job in &config.jobs {
        jobs.push(render_job(&config, job, cli)?);
    }
    let mut written = Vec::new();
    let mut warnings = Vec::new();
    if !dry_run {
        std::fs::create_dir_all(&systemd_dir).map_err(Error::Io)?;
        for units in &jobs {
            for (name, contents) in [
                (&units.service_name, &units.service),
                (&units.timer_name, &units.timer),
            ] {
                let path = systemd_dir.join(name);
                std::fs::write(&path, contents).map_err(Error::Io)?;
                written.push(path);
            }
        }
    }
    // A unit directory other than the system one cannot be reloaded: systemd
    // does not read it, so say so instead of pretending.
    let is_system_dir = systemd_dir == Path::new(DEFAULT_SYSTEMD_DIR);
    let mut reloaded = false;
    let mut started = false;
    if daemon_reload && !dry_run {
        if is_system_dir {
            reloaded = run_systemctl(&["daemon-reload"])?;
            if start {
                let mut args = vec!["enable", "--now"];
                let timers: Vec<String> =
                    jobs.iter().map(|units| units.timer_name.clone()).collect();
                for timer in &timers {
                    args.push(timer);
                }
                started = run_systemctl(&args)?;
            }
        } else {
            warnings.push(format!(
                "{} is not the system unit directory; systemd was not reloaded",
                systemd_dir.display()
            ));
        }
    }
    Ok(ScheduleReport {
        config: config_path.display().to_string(),
        systemd_dir: systemd_dir.display().to_string(),
        dry_run,
        jobs,
        written,
        reloaded,
        started,
        warnings,
    })
}

/// The jobs a config describes, with their rendered units.
///
/// # Errors
/// Returns the config and rendering errors.
pub fn list(config_path: &Path, cli: &Path) -> Result<Vec<JobUnits>> {
    let config = load(config_path)?;
    config
        .jobs
        .iter()
        .map(|job| render_job(&config, job, cli))
        .collect()
}

/// Remove the units of one job.
///
/// # Errors
/// Returns [`Error::Io`] when a unit exists but cannot be removed.
pub fn remove(job: &str, systemd_dir: Option<&Path>) -> Result<Vec<PathBuf>> {
    let systemd_dir =
        systemd_dir.map_or_else(|| PathBuf::from(DEFAULT_SYSTEMD_DIR), Path::to_path_buf);
    let is_system_dir = systemd_dir == Path::new(DEFAULT_SYSTEMD_DIR);
    let systemd_available = std::process::Command::new("systemctl")
        .arg("--version")
        .output()
        .is_ok();
    // Stop and disable first: deleting the files of a still-enabled timer
    // leaves a dangling `timers.target.wants` symlink behind.
    if is_system_dir && systemd_available {
        let _ = std::process::Command::new("systemctl")
            .args(["disable", "--now"])
            .arg(unit_name(job, "timer"))
            .output();
    }
    let mut removed = Vec::new();
    for kind in ["service", "timer"] {
        let path = systemd_dir.join(unit_name(job, kind));
        match std::fs::remove_file(&path) {
            Ok(()) => removed.push(path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(Error::Io(error)),
        }
    }
    if is_system_dir && systemd_available {
        let _ = run_systemctl(&["daemon-reload"])?;
    }
    Ok(removed)
}

fn run_systemctl(args: &[&str]) -> Result<bool> {
    let output = std::process::Command::new("systemctl")
        .args(args)
        .output()
        .map_err(|error| Error::unsupported(format!("systemctl could not be run: {error}")))?;
    if !output.status.success() {
        return Err(Error::unsupported(format!(
            "systemctl {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_SYSTEMD_DIR, JobConfig, materialize, parse, render_job, resolve_destination,
        unit_name,
    };
    use std::path::Path;

    /// The spec's §J.2 example, verbatim.
    const SPEC_EXAMPLE: &str = r#"
[daemon]
socket = "/run/linuxreflect/daemon.sock"
log_level = "info"
lvm_cow_size = "10%"

[[job]]
name = "root-nightly"
source = ["/dev/vg0/root"]
dest = "sftp://backup@nas.local/backups/laptop"
set = "laptop-root"
type = "incremental"
parent = "latest"
mode = "auto"
snapshot = "auto"
compress = "zstd:9"
encrypt = true
passphrase_file = "/etc/linuxreflect/laptop-root.key"
on_calendar = "*-*-* 02:00:00"
randomized_delay = "15m"
persistent = true
[job.retention]
keep_chains = 2
max_incrementals_per_chain = 14
new_chain_on_calendar = "Sun *-*-* 02:00:00"

[destinations.nas]
kind = "sftp"
host = "nas.local"
user = "backup"
known_hosts = "/etc/linuxreflect/known_hosts"
identity = "/etc/linuxreflect/id_ed25519"
"#;

    #[test]
    fn the_spec_example_parses() {
        let config = parse(SPEC_EXAMPLE).expect("config");
        assert_eq!(config.daemon.socket, "/run/linuxreflect/daemon.sock");
        assert_eq!(config.jobs.len(), 1);
        let job = &config.jobs[0];
        assert_eq!(job.name, "root-nightly");
        assert_eq!(job.member_type, "incremental");
        assert_eq!(job.on_calendar, "*-*-* 02:00:00");
        assert_eq!(job.randomized_delay.as_deref(), Some("15m"));
        assert!(job.persistent);
        let retention = job.retention.as_ref().expect("retention");
        assert_eq!(retention.keep_chains, Some(2));
        assert_eq!(retention.max_incrementals_per_chain, Some(14));
        assert_eq!(
            retention.new_chain_on_calendar.as_deref(),
            Some("Sun *-*-* 02:00:00")
        );
    }

    #[test]
    fn unknown_fields_and_bad_values_are_refused() {
        let error = parse("[daemon]\nsocket = \"/x\"\nunknown = 1\n").expect_err("unknown field");
        assert!(format!("{error}").contains("unknown"), "{error}");
        let error = parse(
            "[[job]]\nname = \"j\"\nsource = [\"/dev/x\"]\ndest = \"/d\"\nset = \"s\"\ntype = \"weird\"\non_calendar = \"daily\"\n",
        )
        .expect_err("bad type");
        assert!(format!("{error}").contains("unknown type"), "{error}");
        let error = parse(
            "[[job]]\nname = \"j\"\nsource = [\"/dev/x\"]\ndest = \"/d\"\nset = \"s\"\non_calendar = \"daily\"\nencrypt = true\n",
        )
        .expect_err("encrypt without a passphrase file");
        assert!(format!("{error}").contains("passphrase"), "{error}");
    }

    #[test]
    fn a_job_renders_a_service_and_a_timer() {
        let config = parse(SPEC_EXAMPLE).expect("config");
        let units = render_job(&config, &config.jobs[0], Path::new("/usr/bin/linuxreflect"))
            .expect("render");
        assert_eq!(units.timer_name, "linuxreflect-job@root-nightly.timer");
        assert_eq!(units.service_name, "linuxreflect-job@root-nightly.service");
        assert!(
            units
                .service
                .contains("ExecStart=/usr/bin/linuxreflect backup create"),
            "{}",
            units.service
        );
        assert!(units.service.contains("--type incremental"));
        assert!(units.service.contains("--parent latest"));
        assert!(units.service.contains("--max-incrementals 14"));
        assert!(units.service.contains("retention apply"));
        assert!(units.service.contains("--keep-chains 2"));
        // A network destination waits for the network.
        assert!(units.service.contains("Wants=network-online.target"));
        assert!(units.service.contains("After=network-online.target"));
        assert_eq!(units.destination, "sftp://backup@nas.local/backups/laptop");
        assert!(units.timer.contains("OnCalendar=*-*-* 02:00:00"));
        assert!(units.timer.contains("Persistent=true"));
        assert!(units.timer.contains("RandomizedDelaySec=15m"));
        assert!(
            units
                .timer
                .contains("Unit=linuxreflect-job@root-nightly.service")
        );
        assert!(units.timer.contains("WantedBy=timers.target"));
    }

    #[test]
    fn a_local_job_does_not_wait_for_the_network() {
        let text = r#"
[[job]]
name = "local"
source = ["/home"]
dest = "/mnt/backup"
set = "home"
type = "full"
encrypt = false
on_calendar = "daily"
"#;
        let config = parse(text).expect("config");
        let units =
            render_job(&config, &config.jobs[0], Path::new("/bin/linuxreflect")).expect("render");
        assert!(
            !units.service.contains("network-online"),
            "{}",
            units.service
        );
        assert!(units.service.contains("--no-encrypt"));
        assert!(!units.service.contains("--max-incrementals"));
        assert!(units.timer.contains("Persistent=false"));
    }

    #[test]
    fn named_destinations_resolve_and_missing_ones_are_reported() {
        // The spec's example names the destination inline; give the entry a
        // path so a job can refer to it by name.
        let mut config = parse(SPEC_EXAMPLE).expect("config");
        config.destinations.get_mut("nas").expect("nas").path = Some("/backups/laptop".to_owned());
        let mut job: JobConfig = config.jobs[0].clone();
        job.dest = "nas".to_owned();
        let (uri, network) = resolve_destination(&config, &job).expect("resolve");
        assert_eq!(uri, "sftp://backup@nas.local/backups/laptop");
        assert!(network);

        // A destination with no path cannot be resolved and says why.
        config.destinations.get_mut("nas").expect("nas").path = None;
        let error = resolve_destination(&config, &job).expect_err("no path");
        assert!(format!("{error}").contains("no path"), "{error}");

        // A path written in place is used as it is.
        job.dest = "/mnt/backup".to_owned();
        let (uri, network) = resolve_destination(&config, &job).expect("resolve");
        assert_eq!(uri, "/mnt/backup");
        assert!(!network);
    }

    #[test]
    fn remove_deletes_both_units_and_tolerates_missing_ones() {
        let dir = tempfile::tempdir().expect("tempdir");
        let units = dir.path().join("units");
        std::fs::create_dir_all(&units).expect("units");
        for kind in ["service", "timer"] {
            std::fs::write(units.join(unit_name("victim", kind)), "[Unit]\n").expect("write");
        }
        let removed = super::remove("victim", Some(&units)).expect("remove");
        assert_eq!(removed.len(), 2);
        assert!(!units.join(unit_name("victim", "timer")).exists());
        // Removing again is not an error.
        assert!(
            super::remove("victim", Some(&units))
                .expect("again")
                .is_empty()
        );
    }

    #[test]
    fn materialize_writes_units_into_any_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, SPEC_EXAMPLE).expect("write config");
        let units_dir = dir.path().join("units");
        let report = materialize(
            &config_path,
            Path::new("/usr/bin/linuxreflect"),
            Some(&units_dir),
            false,
            true,
            true,
        )
        .expect("materialize");
        assert_eq!(report.jobs.len(), 1);
        assert_eq!(report.written.len(), 2);
        // A non-system directory cannot be reloaded; that is reported, not
        // silently ignored.
        assert!(!report.reloaded);
        assert_eq!(report.warnings.len(), 1);
        assert!(units_dir.join(unit_name("root-nightly", "timer")).exists());
        assert!(
            units_dir
                .join(unit_name("root-nightly", "service"))
                .exists()
        );
        // A dry run writes nothing.
        let dry_dir = dir.path().join("dry");
        let dry = materialize(
            &config_path,
            Path::new("/usr/bin/linuxreflect"),
            Some(&dry_dir),
            true,
            true,
            true,
        )
        .expect("dry run");
        assert!(dry.dry_run);
        assert!(dry.written.is_empty());
        assert!(!dry_dir.exists());
        assert_eq!(DEFAULT_SYSTEMD_DIR, "/etc/systemd/system");
    }
}
