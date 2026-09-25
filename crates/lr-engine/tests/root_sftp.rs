//! Slice S10 acceptance test: an SFTP destination (spec §K S10).
//!
//! A throwaway `sshd` serves a temporary directory on the loopback interface.
//! Because the test runs as root inside the same machine, it can inspect the
//! served directory directly to prove what the protocol left behind.
//!
//! The acceptance scenario: kill the server mid-transfer, then check that no
//! image was finalised, that the set lock is still there (and expires), that
//! `--break-stale-lock` recovers, and that the resumed job writes a *new*
//! image UUID.
//!
//! Run with:
//!
//! ```text
//! LR_ROOT_TESTS=1 sudo -E cargo test -p lr-engine --test root_sftp -- --ignored --nocapture --test-threads=1
//! ```

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use lr_engine::backup::{BackupRequest, Compression};
use lr_engine::keys::Encryption;
use lr_engine::{ImageReport, backup_image};
use lr_store::DestinationOptions;

const SET_NAME: &str = "sftp-set";

fn root_tests_enabled() -> bool {
    if std::env::var("LR_ROOT_TESTS").as_deref() != Ok("1") {
        eprintln!("LR_ROOT_TESTS != 1; skipping root test");
        return false;
    }
    let uid = Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default();
    if uid != "0" {
        eprintln!("not running as root (uid {uid}); skipping root test");
        return false;
    }
    true
}

fn have(program: &str) -> bool {
    Command::new("which")
        .arg(program)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn run(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// A throwaway sshd serving one directory over the loopback.
struct Sshd {
    base: PathBuf,
    _owner: Option<tempfile::TempDir>,
    child: Child,
    port: u16,
}

impl Sshd {
    fn start() -> Option<Self> {
        let owner = tempfile::tempdir().expect("tempdir");
        let base = owner.path().to_path_buf();
        Self::start_in(base, Some(owner))
    }

    /// Start a server; reusing `base` keeps the served tree across a restart.
    fn start_in(base: PathBuf, owner: Option<tempfile::TempDir>) -> Option<Self> {
        if !have("sshd") {
            eprintln!("sshd missing (install openssh-server); skipping");
            return None;
        }
        if !have("ssh-keygen") {
            eprintln!("ssh-keygen missing; skipping");
            return None;
        }
        let _ = std::fs::create_dir_all(base.join("served"));
        let host_key = base.join("hostkey");
        let user_key = base.join("id_ed25519");
        for key in [&host_key, &user_key] {
            let _ = std::fs::remove_file(key);
            let _ = std::fs::remove_file(key.with_extension("pub"));
            if !run(
                "ssh-keygen",
                &[
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-f",
                    &key.display().to_string(),
                ],
            ) {
                eprintln!("ssh-keygen failed; skipping");
                return None;
            }
        }
        let authorized = base.join("authorized_keys");
        std::fs::copy(user_key.with_extension("pub"), &authorized).expect("authorized_keys");
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&user_key, std::fs::Permissions::from_mode(0o600));

        // OpenSSH insists on its privilege-separation directory even when
        // running in the foreground.
        let _ = std::fs::create_dir_all("/run/sshd");
        let port = free_port()?;
        let config = base.join("sshd_config");
        let log = base.join("sshd.log");
        let contents = format!(
            "Port {port}\n\
             ListenAddress 127.0.0.1\n\
             HostKey {host}\n\
             PidFile {pid}\n\
             AuthorizedKeysFile {authorized}\n\
             PasswordAuthentication no\n\
             KbdInteractiveAuthentication no\n\
             PubkeyAuthentication yes\n\
             PermitRootLogin yes\n\
             StrictModes no\n\
             UsePAM no\n\
             Subsystem sftp /usr/lib/openssh/sftp-server\n\
             LogLevel VERBOSE\n",
            host = host_key.display(),
            pid = base.join("sshd.pid").display(),
            authorized = authorized.display(),
        );
        std::fs::write(&config, contents).expect("sshd_config");

        let child = Command::new("/usr/sbin/sshd")
            .args([
                "-D",
                "-f",
                &config.display().to_string(),
                "-E",
                &log.display().to_string(),
            ])
            .stderr(Stdio::null())
            .spawn()
            .ok()?;

        let host_public =
            std::fs::read_to_string(host_key.with_extension("pub")).expect("host public key");
        let blob = host_public
            .split_whitespace()
            .nth(1)
            .expect("host key blob")
            .to_owned();
        let _ = blob;
        std::fs::write(
            base.join("known_hosts"),
            format!("[127.0.0.1]:{port} ssh-ed25519 {blob}\n"),
        )
        .expect("known_hosts");

        let mut server = Self {
            base,
            _owner: owner,
            child,
            port,
        };
        if !server.wait_until_ready() {
            eprintln!(
                "sshd did not start; skipping (log: {})",
                std::fs::read_to_string(server.base.join("sshd.log")).unwrap_or_default()
            );
            return None;
        }
        Some(server)
    }

    fn user_key(&self) -> PathBuf {
        self.base.join("id_ed25519")
    }

    fn known_hosts(&self) -> PathBuf {
        self.base.join("known_hosts")
    }

    fn root(&self) -> PathBuf {
        self.base.join("served")
    }

    /// The destination URI (the set is named separately, as `--set` does).
    fn destination(&self) -> String {
        format!(
            "sftp://root@127.0.0.1:{}/{}",
            self.port,
            self.root().display()
        )
    }

    fn options(&self, set: &str) -> DestinationOptions {
        DestinationOptions {
            set_name: set.to_owned(),
            identity: Some(self.user_key()),
            known_hosts: Some(self.known_hosts()),
            insecure_ignore_host_key: false,
        }
    }

    fn wait_until_ready(&mut self) -> bool {
        for _ in 0..50 {
            if let Ok(Some(_)) = self.child.try_wait() {
                return false;
            }
            if std::net::TcpStream::connect(("127.0.0.1", self.port)).is_ok() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
    }

    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // The listening process only accepts connections: each session is
        // served by a forked child, so live transfers need killing too. The
        // bracket keeps `pkill` from matching its own command line.
        for pattern in ["[s]ftp-server", "[s]shd: root"] {
            let _ = Command::new("pkill").args(["-9", "-f", pattern]).status();
        }
    }
}

impl Drop for Sshd {
    fn drop(&mut self) {
        self.stop();
    }
}

fn free_port() -> Option<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").ok()?;
    let port = listener.local_addr().ok()?.port();
    Some(port)
}

fn sparse(path: &Path, size: u64) {
    let file = std::fs::File::create(path).expect("create");
    file.set_len(size).expect("size");
}

fn payload(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as u8
        })
        .collect()
}

/// A 256 MiB ext4 image with ~40 MiB of data.
fn source_image(dir: &Path) -> Option<PathBuf> {
    if !have("mkfs.ext4") || !have("debugfs") {
        return None;
    }
    let source = dir.join("source.img");
    sparse(&source, 256 * 1024 * 1024);
    if !run("mkfs.ext4", &["-F", "-q", &source.display().to_string()]) {
        return None;
    }
    let payload_file = dir.join("payload");
    std::fs::write(&payload_file, payload(1, 40 * 1024 * 1024)).expect("payload");
    let script = dir.join("debugfs.cmds");
    std::fs::write(&script, format!("write {} /blob\n", payload_file.display())).expect("script");
    run(
        "debugfs",
        &[
            "-w",
            "-f",
            &script.display().to_string(),
            &source.display().to_string(),
        ],
    );
    Some(source)
}

fn request(server: &Sshd, source: &Path, dest_root: &Path) -> BackupRequest {
    let mut request =
        BackupRequest::new(source, dest_root, SET_NAME, Encryption::NoEncrypt).expect("request");
    request.dest = server.destination();
    request.dest_root = PathBuf::new();
    request.destination_options = server.options(SET_NAME);
    request.compression = Compression::None;
    request
}

#[test]
#[ignore = "requires root, sshd and openssh-server"]
fn an_sftp_destination_carries_a_chain() {
    if !root_tests_enabled() {
        return;
    }
    let work = tempfile::tempdir().expect("workdir");
    std::fs::create_dir_all(work.path().join("served")).expect("served");
    let Some(mut server) = Sshd::start() else {
        return;
    };
    let Some(source) = source_image(work.path()) else {
        return;
    };
    std::fs::create_dir_all(server.root()).expect("served");
    let local = work.path().join("local");

    let full = match backup_image(&request(&server, &source, &local)).expect("full backup") {
        ImageReport::Block(report) => report,
        other => panic!("expected a block image, got {other:?}"),
    };
    assert!(full.image_uri.starts_with("sftp://"), "{}", full.image_uri);
    // The image really landed on the served side.
    let served = server.root().join(SET_NAME);
    assert!(
        served.join(&full.image_path).exists(),
        "the image is on the server"
    );
    assert!(
        served.join("catalog.json").exists(),
        "the catalog was written through the lock"
    );

    // The set lock is released after a successful job.
    assert!(!served.join("set.lock").exists(), "no dangling lock");

    // An incremental through the same destination reads the parent remotely.
    let mut incremental = request(&server, &source, &local);
    incremental.member_type = lr_engine::backup::MemberType::Incremental;
    incremental.parent = Some("latest".to_owned());
    let report = match backup_image(&incremental).expect("incremental") {
        ImageReport::Block(report) => report,
        other => panic!("expected a block image, got {other:?}"),
    };
    assert_eq!(report.seq_in_chain, 1);

    server.stop();
}

#[test]
#[ignore = "requires root, sshd and openssh-server"]
fn killing_the_server_mid_transfer_leaves_nothing_finalized() {
    if !root_tests_enabled() {
        return;
    }
    let mut server = match Sshd::start() {
        Some(server) => server,
        None => return,
    };
    std::fs::create_dir_all(server.root()).expect("served");
    let served = server.root().join(SET_NAME);

    // Write a large file through the destination and kill the server while the
    // transfer is in flight.
    let destination = lr_store::open(&server.destination(), &server.options(SET_NAME))
        .expect("open sftp destination");
    let set = destination
        .open_set(&lr_core::SetId::ZERO)
        .expect("open set");
    let lock = destination
        .lock_set(&set, &lr_store::LockOwner::local(), Duration::from_secs(2))
        .expect("take the lock");
    let mut writer = destination.create_tmp(&set, "big.lrimg").expect("tmp");
    let block = vec![0xABu8; 1024 * 1024];
    let mut write_error = None;
    for attempt in 0..64 {
        if attempt == 1 {
            // The transfer has started; pull the plug.
            server.stop();
        }
        if let Err(error) = writer.write_all(&block) {
            write_error = Some(error);
            break;
        }
    }
    let killed_uuid = lr_core::ImageId::new(lr_core::Id::generate().expect("uuid"));
    assert!(
        write_error.is_some(),
        "the transfer must fail once the server is gone"
    );
    // The lock file must still be there: the job did not finish, so nobody
    // released it (spec §D.3's stale-lease rule).
    assert!(
        served.join("set.lock").exists(),
        "a killed job leaves the lock for its lease to expire"
    );
    assert!(!served.join("big.lrimg").exists(), "nothing was finalized");
    drop(writer);
    drop(lock);
    server.stop();

    // Let the short lease expire, restart the server on the same tree, and
    // resume: the stale lock is broken and the new job uses a new image UUID.
    std::thread::sleep(Duration::from_millis(2200));
    let work = tempfile::tempdir().expect("workdir");
    let Some(source) = source_image(work.path()) else {
        return;
    };
    let Some(mut restarted) = Sshd::start_in(server.base.clone(), None) else {
        return;
    };
    let mut resumed = request(&restarted, &source, work.path());
    resumed.set_lock_ttl_secs = Some(2);
    resumed.break_stale_lock = true;
    resumed.image_uuid = killed_uuid;
    let report = match backup_image(&resumed).expect("resumed backup") {
        ImageReport::Block(report) => report,
        other => panic!("expected a block image, got {other:?}"),
    };
    assert_eq!(
        report.image_uuid, killed_uuid,
        "the resumed job keeps its own UUID"
    );
    assert!(
        served.join(&report.image_path).exists(),
        "the resumed job finalised its image"
    );
    assert!(
        !served.join("big.lrimg").exists(),
        "the killed transfer never became an image"
    );
    assert!(
        !served.join("set.lock").exists(),
        "the resumed job released the broken lock"
    );
    restarted.stop();
}
