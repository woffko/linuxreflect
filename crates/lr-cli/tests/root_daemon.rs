//! Root-gated daemon acceptance tests (spec §K S11).
//!
//! Everything here needs root: loop devices, the real polkit daemon, creating
//! the socket group and socket activation. Run with:
//!
//! ```text
//! LR_ROOT_TESTS=1 wsl.exe -u root -- env LR_ROOT_TESTS=1 \
//!   ./target/debug/deps/root_daemon-<hash> --ignored --nocapture --test-threads=1
//! ```

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::Duration;

const CLI: &str = env!("CARGO_BIN_EXE_linuxreflect");

static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

fn root_tests_enabled() -> bool {
    if std::env::var("LR_ROOT_TESTS").as_deref() != Ok("1") {
        lr_testkit::unavailable!(return false; "LR_ROOT_TESTS != 1 - root test");
    }
    let uid = text(Command::new("id").arg("-u").output().ok());
    if uid.trim() != "0" {
        lr_testkit::unavailable!(return false; "not running as root (uid {})", uid.trim());
    }
    true
}

fn have(tool: &str) -> bool {
    Command::new("which")
        .arg(tool)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn text(output: Option<Output>) -> String {
    let Some(output) = output else {
        return String::new();
    };
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn run(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Install the daemon's polkit policy when the system does not have it yet.
///
/// The policy is how polkit learns about the `org.linuxreflect.*` actions; a
/// test machine that never deployed the daemon needs it to check the real
/// decision. The file is removed again when this test installed it.
struct SystemPolicy {
    path: PathBuf,
    remove: bool,
}

impl SystemPolicy {
    fn ensure() -> Option<Self> {
        let dir = Path::new("/usr/share/polkit-1/actions");
        if !dir.is_dir() {
            lr_testkit::unavailable!(return None; "{} is missing - the polkit test", dir.display());
        }
        let path = dir.join("org.linuxreflect.policy");
        if path.exists() {
            return Some(Self {
                path,
                remove: false,
            });
        }
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../contrib/polkit/org.linuxreflect.policy");
        std::fs::copy(&source, &path).expect("install the polkit policy");
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644));
        // polkitd watches the directory, but registration is not instantaneous.
        for _ in 0..50 {
            let known = Command::new("pkaction")
                .args(["--action-id", "org.linuxreflect.backup.create"])
                .output()
                .map(|output| output.status.success())
                .unwrap_or(false);
            if known {
                return Some(Self { path, remove: true });
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = std::fs::remove_file(&path);
        lr_testkit::fixture_failed!("polkitd did not register org.linuxreflect.backup.create")
    }
}

impl Drop for SystemPolicy {
    fn drop(&mut self) {
        if self.remove {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Resolve a user's numeric ids, for `setpriv`.
///
/// `runuser` is not used: in this environment it fails on WSL for unrelated
/// PAM reasons and reports the failure as a misleading exec error.
fn ids_of(user: &str) -> (String, String) {
    let uid = text(Some(
        Command::new("id")
            .arg("-u")
            .arg(user)
            .output()
            .expect("id -u"),
    ));
    let gid = text(Some(
        Command::new("id")
            .arg("-g")
            .arg(user)
            .output()
            .expect("id -g"),
    ));
    (uid.trim().to_owned(), gid.trim().to_owned())
}

fn daemon_binary() -> Option<PathBuf> {
    let candidate = PathBuf::from(CLI).parent()?.join("linuxreflect-daemon");
    candidate.exists().then_some(candidate)
}

/// Make a copy of the CLI that another user can execute.
///
/// The build directory lives under the developer's home, which `nobody` cannot
/// traverse, so the binary is copied to `/tmp` (world-traversable here). WSL
/// occasionally rejects the first exec right after a large copy, so the copy is
/// polled until it actually runs.
fn cli_for(dir: &Path, user: &str) -> PathBuf {
    // The copy lives next to the socket in the world-traversable daemon
    // directory: the build tree under the developer's home is not reachable by
    // other users.
    let copy = dir.join(format!("linuxreflect-for-{user}"));
    let source = Path::new(CLI);
    let stale = match (std::fs::metadata(&copy), std::fs::metadata(source)) {
        (Ok(copy_meta), Ok(source_meta)) => {
            copy_meta.len() != source_meta.len()
                || source_meta.modified().ok() > copy_meta.modified().ok()
        }
        _ => true,
    };
    if stale {
        // `cp` (rather than `fs::copy`) is used deliberately: files produced by
        // `copy_file_range` here were intermittently rejected on exec by WSL,
        // while plain `cp` output is reliably executable by other users.
        let status = Command::new("cp")
            .arg("-f")
            .arg(source)
            .arg(&copy)
            .status()
            .expect("run cp");
        assert!(status.success(), "cp failed");
        let _ = std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o755));
        assert_eq!(
            std::fs::metadata(&copy).expect("stat").permissions().mode() & 0o777,
            0o755,
            "the CLI copy must be executable by other users"
        );
    }
    let mut attempt = 0;
    while attempt < 30 {
        let (uid, gid) = ids_of(user);
        let probe = Command::new("setpriv")
            .current_dir("/")
            .args([
                format!("--reuid={uid}"),
                format!("--regid={gid}"),
                "--clear-groups".to_owned(),
                "--".to_owned(),
            ])
            .arg(&copy)
            .arg("--version")
            .output();
        if probe.as_ref().is_ok_and(|output| output.status.success()) {
            return copy;
        }
        let failure = match &probe {
            Ok(output) => format!(
                "status={}\nstdout={}\nstderr={}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
            Err(error) => format!("spawn failed: {error}"),
        };
        if attempt < 5 {
            eprintln!("probe {attempt} for {user}: {failure}");
        }
        if attempt == 0 {
            let _ = std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o755));
        }
        attempt += 1;
        std::thread::sleep(Duration::from_millis(300));
    }
    let (uid, gid) = ids_of(user);
    let last = text(Some(
        Command::new("setpriv")
            .current_dir("/")
            .args([
                format!("--reuid={uid}"),
                format!("--regid={gid}"),
                "--clear-groups".to_owned(),
                "--".to_owned(),
            ])
            .arg(&copy)
            .arg("--version")
            .output()
            .expect("probe the CLI copy"),
    ));
    panic!(
        "the CLI copy {} is not executable by {user}:\n{last}",
        copy.display()
    );
}

/// A daemon process started with explicit arguments.
struct Daemon {
    child: Child,
    socket: PathBuf,
    dir: tempfile::TempDir,
}

impl Daemon {
    /// Start with the given extra daemon arguments and wait for the socket.
    fn start(extra: &[&str]) -> Option<Self> {
        let binary = daemon_binary()?;
        let dir = tempfile::Builder::new()
            .prefix("lr-root-daemon-")
            .tempdir_in("/var/tmp")
            .expect("daemon dir");
        // Root-created directories are restrictive here, so the mode is set
        // explicitly: a non-root peer must be able to reach the socket and to
        // run the CLI copy inside.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755))
            .expect("daemon directory permissions");
        assert_eq!(
            std::fs::metadata(dir.path())
                .expect("stat")
                .permissions()
                .mode()
                & 0o777,
            0o755,
            "the daemon directory must be world-traversable"
        );
        let socket = dir.path().join(format!(
            "daemon-{}.sock",
            NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
        let _ = std::fs::remove_file(&socket);
        let mut args: Vec<String> = vec![
            "--socket".to_owned(),
            socket.display().to_string(),
            "--sd-notify=no".to_owned(),
            "--token-secret-file".to_owned(),
            dir.path().join("token.key").display().to_string(),
        ];
        args.extend(extra.iter().map(|value| (*value).to_owned()));
        let child = Command::new(binary)
            .args(&args)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn the daemon");
        let mut daemon = Self { child, socket, dir };
        for _ in 0..60 {
            if daemon.socket.exists()
                || std::os::unix::net::UnixStream::connect(&daemon.socket).is_ok()
            {
                return Some(daemon);
            }
            if let Ok(Some(_)) = daemon.child.try_wait() {
                lr_testkit::fixture_failed!(
                    "the daemon exited before listening: {}",
                    daemon.stderr()
                );
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        lr_testkit::fixture_failed!("the daemon did not listen within 6 s: {}", daemon.stderr())
    }

    fn stderr(&mut self) -> String {
        use std::io::Read;
        let mut text = String::new();
        if let Some(mut pipe) = self.child.stderr.take() {
            let _ = pipe.read_to_string(&mut text);
        }
        text
    }

    fn cli(&self, args: &[&str]) -> Output {
        Command::new(CLI)
            .arg("--socket")
            .arg(&self.socket)
            .args(args)
            .output()
            .expect("run the CLI")
    }

    /// Run the CLI as another user, to exercise polkit.
    fn cli_as(&self, user: &str, args: &[&str]) -> Output {
        let copy = cli_for(self.dir.path(), user);
        let (uid, gid) = ids_of(user);
        Command::new("setpriv")
            .current_dir("/")
            .args([
                format!("--reuid={uid}"),
                format!("--regid={gid}"),
                "--clear-groups".to_owned(),
                "--".to_owned(),
            ])
            .arg(&copy)
            .arg("--socket")
            .arg(&self.socket)
            .args(args)
            .output()
            .expect("run the CLI as another user")
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A loop device with an ext4 filesystem, detached on drop.
struct LoopDisk {
    device: PathBuf,
    mount_dir: tempfile::TempDir,
}

impl LoopDisk {
    fn ext4(size_mib: u64) -> Option<Self> {
        if !have("losetup") || !have("mkfs.ext4") {
            lr_testkit::unavailable!(return None; "losetup or mkfs.ext4 missing");
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let backing = dir.path().join("disk.img");
        let file = std::fs::File::create(&backing).expect("create");
        file.set_len(size_mib * 1024 * 1024).expect("size");
        drop(file);
        let free = text(Some(
            Command::new("losetup")
                .arg("-f")
                .output()
                .expect("losetup -f"),
        ));
        let device = PathBuf::from(free.trim());
        if !run(
            "losetup",
            &[
                "-P",
                &device.display().to_string(),
                &backing.display().to_string(),
            ],
        ) {
            lr_testkit::fixture_failed!("losetup failed");
        }
        if !run("mkfs.ext4", &["-F", "-q", &device.display().to_string()]) {
            let _ = run("losetup", &["-d", &device.display().to_string()]);
            lr_testkit::fixture_failed!("mkfs.ext4 failed");
        }
        let mount_dir = tempfile::tempdir().expect("mountdir");
        Some(Self { device, mount_dir })
    }

    fn mount(&self) -> bool {
        run(
            "mount",
            &[
                &self.device.display().to_string(),
                &self.mount_dir.path().display().to_string(),
            ],
        )
    }

    fn unmount(&self) {
        let _ = run("umount", &[&self.mount_dir.path().display().to_string()]);
    }
}

impl Drop for LoopDisk {
    fn drop(&mut self) {
        self.unmount();
        let _ = run("losetup", &["-d", &self.device.display().to_string()]);
    }
}

#[test]
#[ignore = "requires root, loop devices, mount and the daemon binary"]
fn a_loop_device_round_trips_through_the_daemon() {
    if !root_tests_enabled() {
        return;
    }
    for tool in ["losetup", "mount", "mkfs.ext4", "diff", "sha256sum"] {
        if !have(tool) {
            lr_testkit::unavailable!("{tool} missing");
        }
    }
    let Some(source) = LoopDisk::ext4(256) else {
        return;
    };
    let Some(target) = LoopDisk::ext4(256) else {
        return;
    };
    assert!(source.mount(), "mounting the source failed");
    std::fs::write(source.mount_dir.path().join("hello.txt"), b"hello\n").expect("write");
    std::fs::write(
        source.mount_dir.path().join("data.bin"),
        vec![0x5Au8; 4 * 1024 * 1024],
    )
    .expect("write");
    source.unmount();

    // The daemon creates the LinuxReflect group on its own (spec §I).
    let group = format!("lr-root-test-{}", std::process::id());
    let Some(daemon) =
        Daemon::start(&["--dev-mode", "--auth", "static:0", "--socket-group", &group])
    else {
        lr_testkit::fixture_failed!("the daemon did not start");
    };
    let mode = std::fs::metadata(&daemon.socket)
        .expect("socket stat")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o660, "the socket is group-accessible");
    assert!(
        text(Some(
            Command::new("getent")
                .arg("group")
                .arg(&group)
                .output()
                .expect("getent")
        ))
        .contains(&group),
        "the daemon created the socket group"
    );

    let work = tempfile::tempdir().expect("workdir");
    let dest = work.path().join("out");
    let created = daemon.cli(&[
        "backup",
        "create",
        "--source",
        &source.device.display().to_string(),
        "--dest",
        &dest.display().to_string(),
        "--set",
        "loop-set",
        "--no-encrypt",
        "--compress",
        "none",
        "--json",
    ]);
    assert!(created.status.success(), "{}", text(Some(created)));
    let report_line = text(Some(daemon.cli(&[
        "backup",
        "list",
        "--dest",
        &dest.display().to_string(),
        "--set",
        "loop-set",
        "--json",
    ])));
    assert!(report_line.contains("chain"), "{report_line}");

    // Find the image and verify it through the daemon.
    let chain = std::fs::read_dir(dest.join("loop-set"))
        .expect("set dir")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.is_dir())
        .expect("chain dir");
    let image = std::fs::read_dir(&chain)
        .expect("chain dir")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.extension().is_some_and(|ext| ext == "lrimg"))
        .expect("image");
    let verified = daemon.cli(&["verify", "--image", &image.display().to_string(), "--chain"]);
    assert!(verified.status.success(), "{}", text(Some(verified)));

    // Restore onto the second loop through the daemon and compare the trees.
    let prepared = daemon.cli(&[
        "restore",
        "prepare",
        "--image",
        &image.display().to_string(),
        "--target",
        &target.device.display().to_string(),
        "--json",
    ]);
    assert!(prepared.status.success(), "{}", text(Some(prepared)));
    let plan: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&prepared.stdout)).expect("plan json");
    let token = plan["token"].as_str().expect("token").to_owned();
    let applied = daemon.cli(&["restore", "apply", "--token", &token, "--confirm"]);
    assert!(applied.status.success(), "{}", text(Some(applied)));

    assert!(source.mount(), "mounting the restored source failed");
    assert!(target.mount(), "mounting the restored target failed");
    let same = run(
        "diff",
        &[
            "-r",
            &source.mount_dir.path().display().to_string(),
            &target.mount_dir.path().display().to_string(),
        ],
    );
    if !same {
        eprintln!(
            "diff output:\n{}",
            text(Some(
                Command::new("diff")
                    .args([
                        "-r",
                        &source.mount_dir.path().display().to_string(),
                        &target.mount_dir.path().display().to_string(),
                    ])
                    .output()
                    .expect("diff"),
            ))
        );
    }
    assert!(same, "the restored filesystem matches the source");
}

#[test]
#[ignore = "requires root, a running polkit daemon and the daemon binary"]
fn polkit_denies_a_non_root_peer_and_allows_root() {
    if !root_tests_enabled() {
        return;
    }
    for tool in ["setpriv"] {
        if !have(tool) {
            lr_testkit::unavailable!("{tool} missing");
        }
    }
    // polkit only works while its daemon answers on the system bus.
    let polkit_running =
        run("pgrep", &["-x", "polkitd"]) && Path::new("/run/dbus/system_bus_socket").exists();
    if !polkit_running {
        lr_testkit::unavailable!("polkitd or the system bus is not running - the polkit test");
    }
    let Some(_policy) = SystemPolicy::ensure() else {
        return;
    };

    // No --auth: the daemon uses polkit. The socket group is `nogroup` so the
    // unprivileged user can connect at all; the decision is polkit's.
    // A world-connectable socket lets the unprivileged peer reach the daemon
    // at all; the decision under test is polkit's, not the socket's.
    let Some(daemon) = Daemon::start(&["--socket-mode", "0666"]) else {
        lr_testkit::fixture_failed!("the daemon did not start");
    };
    let work = tempfile::tempdir().expect("workdir");
    let source = work.path().join("source.img");
    let file = std::fs::File::create(&source).expect("create");
    file.set_len(64 * 1024 * 1024).expect("size");
    drop(file);
    assert!(run(
        "mkfs.ext4",
        &["-F", "-q", &source.display().to_string()]
    ));
    let dest = work.path().join("out");

    // An unprivileged peer cannot create a backup.
    let denied = daemon.cli_as(
        "nobody",
        &[
            "backup",
            "create",
            "--source",
            &source.display().to_string(),
            "--dest",
            &dest.display().to_string(),
            "--set",
            "polkit-set",
            "--no-encrypt",
            "--compress",
            "none",
        ],
    );
    let denied_text = text(Some(denied));
    assert!(
        denied_text.contains("E_DENIED") || denied_text.contains("PermissionDenied"),
        "polkit must refuse a non-root peer: {denied_text}"
    );

    // Root is authorized without an agent.
    let allowed = daemon.cli(&[
        "backup",
        "create",
        "--source",
        &source.display().to_string(),
        "--dest",
        &dest.display().to_string(),
        "--set",
        "polkit-set",
        "--no-encrypt",
        "--compress",
        "none",
    ]);
    assert!(
        allowed.status.success(),
        "root must be allowed by polkit: {}",
        text(Some(allowed))
    );
}

#[test]
#[ignore = "requires root, systemd-socket-activate and the daemon binary"]
fn socket_activation_is_honoured() {
    if !root_tests_enabled() {
        return;
    }
    if !have("systemd-socket-activate") {
        lr_testkit::unavailable!("systemd-socket-activate missing");
    }
    let Some(binary) = daemon_binary() else {
        lr_testkit::unavailable!("the daemon binary is missing");
    };
    let dir = tempfile::tempdir_in("/tmp").expect("tempdir");
    let activated = dir.path().join("activated.sock");
    let decoy = dir.path().join("decoy.sock");

    // The daemon is told to bind `decoy`; only socket activation can explain a
    // working `activated` socket.
    let mut child = Command::new("systemd-socket-activate")
        .arg("-l")
        .arg(&activated)
        .arg("--")
        .arg(&binary)
        .args([
            "--socket",
            &decoy.display().to_string(),
            "--socket-group",
            "lr-activation-test",
            "--no-create-group",
            "--dev-mode",
            "--auth",
            "static:0",
            "--sd-notify=no",
            "--token-secret-file",
            &dir.path().join("token.key").display().to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("systemd-socket-activate");

    let mut ready = false;
    for _ in 0..60 {
        if std::os::unix::net::UnixStream::connect(&activated).is_ok() {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(ready, "the activated socket never appeared");

    let status = Command::new(CLI)
        .arg("--socket")
        .arg(&activated)
        .args(["daemon", "status", "--json"])
        .output()
        .expect("status");
    let status_text = text(Some(status));
    assert!(status_text.contains("\"running\": true"), "{status_text}");
    assert!(
        !decoy.exists(),
        "the daemon must not bind its own socket when one was passed"
    );

    let _ = child.kill();
    let _ = child.wait();
}
