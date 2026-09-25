//! GUI acceptance (spec §K S15): create and restore through the GUI on X11 and
//! Wayland.
//!
//! The GUI binary is started against a real daemon and driven by its automation
//! script, which sets the same fields a user types and invokes the same
//! callbacks a click invokes; the window is really mapped on the display server
//! under test (on X11 that is asserted with `xdotool`). The script performs a
//! full create and restore, and the test checks the restored files on disk.
//!
//! The tests need `Xvfb` (X11) or `weston` (Wayland) and the daemon binary; they
//! print why they skip when a tool is missing, so a bare CI run stays green
//! while the acceptance run on a machine with the tools proves the criterion.

use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const GUI: &str = env!("CARGO_BIN_EXE_linuxreflect-gui");

/// The GUI command for the Wayland run.
///
/// Slint's winit backend deliberately picks X11 whenever it sees WSL
/// (`/run/WSL` or the `WSLInterop` binfmt entry). On WSL the GUI therefore
/// runs in a bubblewrap mount namespace where those two paths do not exist,
/// so it really connects to the headless Weston. Everything the test uses
/// lives under `/tmp`, which stays shared.
fn wayland_gui_command() -> Command {
    let wsl =
        Path::new("/run/WSL").exists() || Path::new("/proc/sys/fs/binfmt_misc/WSLInterop").exists();
    if !wsl {
        return Command::new(GUI);
    }
    assert!(
        have("bwrap"),
        "on WSL the Wayland test needs bubblewrap to hide the WSL markers from Slint"
    );
    let mut command = Command::new("bwrap");
    command.args([
        "--dev-bind",
        "/",
        "/",
        "--tmpfs",
        "/run",
        "--tmpfs",
        "/proc/sys/fs/binfmt_misc",
        GUI,
    ]);
    command
}

fn private_test_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("lr-gui-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in("/tmp")
        .expect("private GUI test directory")
}

fn root_tests_enabled() -> bool {
    if std::env::var("LR_ROOT_TESTS").as_deref() != Ok("1") {
        eprintln!("LR_ROOT_TESTS != 1; skipping");
        return false;
    }
    true
}

fn have(program: &str) -> bool {
    Command::new("which")
        .arg(program)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn daemon_binary() -> Option<PathBuf> {
    let candidate = PathBuf::from(GUI).parent()?.join("linuxreflect-daemon");
    candidate.exists().then_some(candidate)
}

/// A daemon serving a temporary socket, killed on drop.
struct Daemon {
    child: Child,
    socket: PathBuf,
}

impl Daemon {
    fn start(dir: &Path) -> Option<Self> {
        let binary = daemon_binary()?;
        let socket = dir.join("daemon.sock");
        let child = Command::new(binary)
            .args([
                "--socket",
                &socket.display().to_string(),
                "--socket-group",
                "lr-gui-test",
                "--no-create-group",
                "--dev-mode",
                "--auth",
                "static:all",
                "--sd-notify=no",
                "--token-secret-file",
                &dir.join("token.key").display().to_string(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("start GUI-test daemon");
        let mut daemon = Self { child, socket };
        for _ in 0..100 {
            assert!(
                daemon
                    .child
                    .try_wait()
                    .expect("check daemon status")
                    .is_none(),
                "GUI-test daemon exited before creating its socket"
            );
            if daemon.socket.exists() {
                return Some(daemon);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("GUI-test daemon did not create its socket within 10 seconds");
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Collect a child when the test finishes (also when an assertion fails).
struct Reaper(Vec<Child>);

impl Reaper {
    fn push(&mut self, child: Child) {
        self.0.push(child);
    }
}

impl Drop for Reaper {
    fn drop(&mut self) {
        for child in &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn write_tree(root: &Path, marker: &str) {
    std::fs::create_dir_all(root.join("nested")).expect("dirs");
    std::fs::write(root.join("hello.txt"), marker).expect("file");
    std::fs::write(root.join("nested/data.bin"), vec![0x5Au8; 300 * 1024]).expect("file");
}

fn script(dir: &Path, source: &Path, restore: &Path, marker: &str) -> PathBuf {
    let path = dir.join("script.txt");
    std::fs::write(
        &path,
        format!(
            "refresh-disks\n\
             source {source}\n\
             dest {backups}\n\
             set gui-set\n\
             mode file\n\
             probe\n\
             backup\n\
             image-from-summary\n\
             target {restore}\n\
             prepare\n\
             restore\n\
             expect-file {restore}/hello.txt\n\
             expect-contains {restore}/hello.txt {marker}\n\
             expect-file {restore}/nested/data.bin\n\
             print\n\
             quit\n",
            source = source.display(),
            backups = dir.join("backups").display(),
            restore = restore.display(),
            marker = marker,
        ),
    )
    .expect("script");
    path
}

/// Run the GUI under X11 and check the window is mapped and the round trip
/// happened.
#[test]
#[ignore = "needs Xvfb and xdotool; runs create/restore through the GUI on X11"]
fn create_and_restore_through_the_gui_on_x11() {
    x11_round_trip(false);
}

#[test]
#[ignore = "needs Xvfb and xdotool; encrypted GUI round trip using a private generated key file"]
fn encrypted_create_and_restore_through_the_gui_on_x11() {
    x11_round_trip(true);
}

fn x11_round_trip(encrypted: bool) {
    if !root_tests_enabled() {
        return;
    }
    for tool in ["Xvfb", "xdotool"] {
        if !have(tool) {
            eprintln!("{tool} missing; skipping the X11 GUI test");
            return;
        }
    }
    let dir = private_test_dir();
    let Some(daemon) = Daemon::start(dir.path()) else {
        eprintln!("the daemon binary is not built next to the GUI; skipping");
        return;
    };

    // A private X server so the GUI and xdotool share one display.
    let mut reaper = Reaper(Vec::new());
    let mut xvfb = Command::new("Xvfb")
        .args([
            "-displayfd",
            "1",
            "-screen",
            "0",
            "1024x768x24",
            "-nolisten",
            "tcp",
            "-nolisten",
            "unix",
            "-noreset",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("Xvfb");
    let stdout = xvfb.stdout.take().expect("Xvfb readiness pipe");
    reaper.push(xvfb);
    let (send, receive) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        use std::io::BufRead as _;
        let mut line = String::new();
        let result = std::io::BufReader::new(stdout)
            .read_line(&mut line)
            .map(|_| line);
        let _ = send.send(result);
    });
    let number = receive
        .recv_timeout(Duration::from_secs(5))
        .expect("Xvfb readiness timeout")
        .expect("Xvfb readiness read");
    let number: u32 = number.trim().parse().expect("Xvfb display number");
    let display = format!(":{number}");
    let mut x11_ready = false;
    for _ in 0..50 {
        let probe = Command::new("xdotool")
            .env("DISPLAY", &display)
            .arg("getdisplaygeometry")
            .output();
        if probe.map(|output| output.status.success()).unwrap_or(false) {
            x11_ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(x11_ready, "Xvfb did not come up on {display}");

    // 1. The window is really mapped on X11.
    let mut smoke = Command::new(GUI)
        .env("DISPLAY", &display)
        .env_remove("WAYLAND_DISPLAY")
        .env("SLINT_BACKEND", "winit-software")
        .arg("--socket")
        .arg(&daemon.socket)
        .args(["--exit-after-ms", "4000"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("GUI smoke run");
    let mut window = None;
    for _ in 0..40 {
        let found = Command::new("xdotool")
            .env("DISPLAY", &display)
            .args(["search", "--name", "LinuxReflect"])
            .output();
        if let Ok(output) = found {
            let ids = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            if !ids.is_empty() {
                window = Some(ids);
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = smoke.kill();
    let _ = smoke.wait();
    assert!(
        window.is_some(),
        "no LinuxReflect window was mapped on {display}"
    );

    // 2. Create and restore through the GUI.
    let source = dir.path().join("source");
    let restore = dir.path().join("restore");
    std::fs::create_dir_all(&restore).expect("restore dir");
    write_tree(&source, "x11 marker\n");
    let script = script(dir.path(), &source, &restore, "x11");
    if encrypted {
        // Fresh test-only material; neither the secret nor its bytes enter
        // process arguments or the automation log. Only the file path does.
        let mut random = [0u8; 32];
        std::fs::File::open("/dev/urandom")
            .expect("OS random source")
            .read_exact(&mut random)
            .expect("test key entropy");
        let key = dir.path().join("passphrase");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&key)
            .expect("private passphrase file");
        for byte in random {
            write!(file, "{byte:02x}").expect("write test passphrase");
        }
        file.sync_all().expect("sync test passphrase");
        let wrong_key = dir.path().join("wrong-passphrase");
        let mut wrong_file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&wrong_key)
            .expect("private wrong passphrase file");
        for byte in random {
            write!(wrong_file, "{:02x}", !byte).expect("write wrong test passphrase");
        }
        wrong_file.sync_all().expect("sync wrong test passphrase");
        let original = std::fs::read_to_string(&script).expect("read script");
        let original = original.replace(
            "prepare\n",
            &format!(
                "expect-prepare-failure supply a passphrase file\n\
             expect-empty-directory {restore}\n\
             restore-passphrase-file {}\n\
             expect-prepare-failure authenticated decryption failed\n\
             expect-empty-directory {restore}\n\
             restore-passphrase-file {}\nprepare\n",
                wrong_key.display(),
                key.display(),
                restore = restore.display()
            ),
        );
        std::fs::write(
            &script,
            format!("backup-passphrase-file {}\n{original}", key.display()),
        )
        .expect("encrypted script");
    }
    let output = Command::new(GUI)
        .env("DISPLAY", &display)
        .env_remove("WAYLAND_DISPLAY")
        .env("SLINT_BACKEND", "winit-software")
        .arg("--socket")
        .arg(&daemon.socket)
        .arg("--script")
        .arg(&script)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("GUI run");
    assert!(output.status.success(), "{}", text(&output));
    // Scan the actual image header independently of the GUI's encryption
    // setting. LocalDestination resolves the set by name; this scan does not
    // use the handle's identifier to interpret the stored superblock.
    let destination = lr_store::LocalDestination::new(dir.path().join("backups"), "gui-set");
    let set = lr_store::Destination::open_set(
        &destination,
        &lr_core::SetId::new(lr_core::Id::from_bytes([0; 16])),
    )
    .expect("open created set");
    let scan = lr_engine::catalog::scan_set(&destination, &set).expect("scan created image");
    assert_eq!(scan.members.len(), 1, "{:?}", scan.warnings);
    assert_eq!(scan.members[0].superblock.is_encrypted(), encrypted);
    assert!(
        text(&output).contains("script: "),
        "the GUI reported its script:\n{}",
        text(&output)
    );
    assert_eq!(
        std::fs::read_to_string(restore.join("hello.txt")).expect("restored file"),
        "x11 marker\n"
    );
    assert_eq!(
        std::fs::read(restore.join("nested/data.bin")).expect("restored binary file"),
        std::fs::read(source.join("nested/data.bin")).expect("source binary file")
    );
}

/// The same round trip on a headless Wayland compositor.
#[test]
#[ignore = "needs weston with the headless backend; runs create/restore through the GUI on Wayland"]
fn create_and_restore_through_the_gui_on_wayland() {
    if !root_tests_enabled() {
        return;
    }
    if !have("weston") {
        eprintln!("weston missing; skipping the Wayland GUI test");
        return;
    }
    let dir = private_test_dir();
    let Some(daemon) = Daemon::start(dir.path()) else {
        eprintln!("the daemon binary is not built next to the GUI; skipping");
        return;
    };
    let runtime = dir.path().join("run");
    std::fs::create_dir_all(&runtime).expect("runtime dir");
    std::fs::set_permissions(
        &runtime,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .expect("runtime mode");

    let mut reaper = Reaper(Vec::new());
    let weston = Command::new("weston")
        .env("XDG_RUNTIME_DIR", &runtime)
        .args([
            "--backend=headless-backend.so",
            "--width=1024",
            "--height=768",
            "--socket=wayland-lr",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("weston");
    reaper.push(weston);
    let socket = runtime.join("wayland-lr");
    let mut ready = false;
    for _ in 0..50 {
        if socket.exists() {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(ready, "weston did not create its socket");

    let source = dir.path().join("source");
    let restore = dir.path().join("restore");
    std::fs::create_dir_all(&restore).expect("restore dir");
    write_tree(&source, "wayland marker\n");
    let script = script(dir.path(), &source, &restore, "wayland");
    let started = Instant::now();
    let output = wayland_gui_command()
        .env_remove("DISPLAY")
        .env("SLINT_BACKEND", "winit-software")
        .env("XDG_RUNTIME_DIR", &runtime)
        .env("WAYLAND_DISPLAY", "wayland-lr")
        .arg("--socket")
        .arg(&daemon.socket)
        .arg("--script")
        .arg(&script)
        .output()
        .expect("GUI run");
    assert!(output.status.success(), "{}", text(&output));
    assert!(
        started.elapsed() < Duration::from_secs(120),
        "the Wayland run took {:?}",
        started.elapsed()
    );
    assert_eq!(
        std::fs::read_to_string(restore.join("hello.txt")).expect("restored file"),
        "wayland marker\n"
    );
    assert_eq!(
        std::fs::read(restore.join("nested/data.bin")).expect("restored binary file"),
        std::fs::read(source.join("nested/data.bin")).expect("source binary file")
    );
    assert!(text(&output).contains("restore ok"), "{}", text(&output));
}
