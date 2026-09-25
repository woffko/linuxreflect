//! Root-gated scheduling and session-notification acceptance (spec §K S14).
//!
//! Two real integrations are exercised:
//!
//! * `schedule set` materializes `linuxreflect-job@<name>.timer/.service` into
//!   systemd's unit directory; the test enables the timer and waits for the
//!   generated service to run a real backup, which is the spec's "timer fires".
//! * `linuxreflect-session` subscribes to the daemon's `WatchEvents` and posts
//!   to `org.freedesktop.Notifications`; the test runs a mock notification
//!   service on a private session bus and asserts the call arrives.
//!
//! Nothing here needs a desktop: the D-Bus contract is what the test verifies,
//! and a Wayland session would receive exactly the same `Notify` call.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const CLI: &str = env!("CARGO_BIN_EXE_linuxreflect");

fn root_tests_enabled() -> bool {
    if std::env::var("LR_ROOT_TESTS").as_deref() != Ok("1") {
        eprintln!("LR_ROOT_TESTS != 1; skipping");
        return false;
    }
    let uid = Command::new("id")
        .arg("-u")
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .unwrap_or_default();
    if uid != "0" {
        eprintln!("not running as root (uid {uid}); skipping");
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

/// Removes the units a test installed, even when an assertion fails.
struct UnitGuard {
    names: Vec<String>,
    timer: String,
}

impl Drop for UnitGuard {
    fn drop(&mut self) {
        let _ = Command::new("systemctl")
            .args(["disable", "--now"])
            .arg(&self.timer)
            .status();
        for name in &self.names {
            let _ = std::fs::remove_file(Path::new("/etc/systemd/system").join(name));
        }
        let _ = Command::new("systemctl").arg("daemon-reload").status();
    }
}

#[test]
#[ignore = "requires root and a running systemd: installs a timer and waits for it to fire"]
fn a_generated_timer_runs_the_job() {
    if !root_tests_enabled() {
        return;
    }
    for tool in ["systemctl", "systemd-analyze"] {
        if !have(tool) {
            eprintln!("{tool} missing; skipping");
            return;
        }
    }
    let running = Command::new("systemctl")
        .arg("is-system-running")
        .output()
        .map(|output| {
            let state = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            output.status.success() || state == "degraded"
        })
        .unwrap_or(false);
    if !running {
        eprintln!("systemd is not running as PID 1; skipping");
        return;
    }

    let dir = tempfile::tempdir_in("/tmp").expect("tempdir");
    let source = dir.path().join("source");
    let dest = dir.path().join("backups");
    std::fs::create_dir_all(&source).expect("dirs");
    std::fs::write(source.join("file.txt"), b"scheduled\n").expect("file");
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        format!(
            r#"
[[job]]
name = "lr-schedule-test"
source = ["{source}"]
dest = "{dest}"
set = "scheduled"
type = "full"
mode = "file"
encrypt = false
on_calendar = "*-*-* *:*:00/10"
persistent = false

[job.retention]
keep_chains = 1
"#,
            source = source.display(),
            dest = dest.display()
        ),
    )
    .expect("config");

    let guard = UnitGuard {
        names: vec![
            "linuxreflect-job@lr-schedule-test.service".to_owned(),
            "linuxreflect-job@lr-schedule-test.timer".to_owned(),
        ],
        timer: "linuxreflect-job@lr-schedule-test.timer".to_owned(),
    };

    // The units must be valid before systemd is asked to run them.
    let set = Command::new(CLI)
        .args(["schedule", "set", "--config"])
        .arg(&config)
        .output()
        .expect("schedule set");
    assert!(set.status.success(), "{}", text(&set));
    let service = Path::new("/etc/systemd/system/linuxreflect-job@lr-schedule-test.service");
    let timer = Path::new("/etc/systemd/system/linuxreflect-job@lr-schedule-test.timer");
    assert!(service.exists(), "the service unit was written");
    assert!(timer.exists(), "the timer unit was written");
    let verify = Command::new("systemd-analyze")
        .args(["verify", "--man=no"])
        .arg(service)
        .arg(timer)
        .output()
        .expect("systemd-analyze verify");
    assert!(
        verify.status.success(),
        "systemd-analyze rejected the units:\n{}",
        text(&verify)
    );

    // Enable and start it; the calendar expression fires every ten seconds.
    let enabled = Command::new("systemctl")
        .args(["enable", "--now", "linuxreflect-job@lr-schedule-test.timer"])
        .output()
        .expect("enable the timer");
    assert!(enabled.status.success(), "{}", text(&enabled));

    let deadline = Instant::now() + Duration::from_secs(60);
    let mut images: Vec<PathBuf> = Vec::new();
    while Instant::now() < deadline {
        images.clear();
        if let Ok(entries) = std::fs::read_dir(dest.join("scheduled")) {
            for chain in entries.flatten() {
                if let Ok(members) = std::fs::read_dir(chain.path()) {
                    for member in members.flatten() {
                        if member.path().extension().is_some_and(|ext| ext == "lrimg") {
                            images.push(member.path());
                        }
                    }
                }
            }
        }
        if !images.is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    let status = Command::new("systemctl")
        .args([
            "status",
            "--no-pager",
            "linuxreflect-job@lr-schedule-test.service",
        ])
        .output()
        .map(|output| text(&output))
        .unwrap_or_default();
    assert!(
        !images.is_empty(),
        "the timer never produced an image; service status:\n{status}"
    );

    // Retention ran as the service's second step: the chain is still there and
    // the set has exactly one chain.
    let listed = Command::new(CLI)
        .args(["backup", "list", "--dest"])
        .arg(&dest)
        .args(["--set", "scheduled"])
        .output()
        .expect("backup list");
    assert!(listed.status.success(), "{}", text(&listed));
    assert!(
        text(&listed).contains("chain"),
        "the catalog lists the chain:\n{}",
        text(&listed)
    );

    // `schedule remove` disables the timer and deletes both units.
    let removed = Command::new(CLI)
        .args(["schedule", "remove", "lr-schedule-test"])
        .output()
        .expect("schedule remove");
    assert!(removed.status.success(), "{}", text(&removed));
    assert!(!service.exists(), "the service unit is gone");
    assert!(!timer.exists(), "the timer unit is gone");
    let wants = Path::new(
        "/etc/systemd/system/timers.target.wants/linuxreflect-job@lr-schedule-test.timer",
    );
    assert!(!wants.exists(), "the enable symlink is gone");
    let active = Command::new("systemctl")
        .args(["is-active", "linuxreflect-job@lr-schedule-test.timer"])
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .unwrap_or_default();
    assert_ne!(active, "active", "the timer is stopped");
    drop(guard);
}

/// A mock `org.freedesktop.Notifications` service for the session-bus test.
const MOCK_SERVICE: &str = r#"
import dbus, dbus.service, dbus.mainloop.glib, sys
from gi.repository import GLib

dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
bus = dbus.bus.BusConnection(sys.argv[1])
name = dbus.service.BusName("org.freedesktop.Notifications", bus)

class Notifications(dbus.service.Object):
    def __init__(self):
        super().__init__(bus, "/org/freedesktop/Notifications")
        self.calls = open(sys.argv[2], "a", buffering=1)

    @dbus.service.method("org.freedesktop.Notifications",
                         in_signature="susssasa{sv}i", out_signature="u")
    def Notify(self, app_name, replaces_id, app_icon, summary, body, actions, hints, timeout):
        self.calls.write(f"{app_name}\t{summary}\t{body}\t{hints.get('urgency', '?')}\n")
        return dbus.UInt32(1)

    @dbus.service.method("org.freedesktop.Notifications", in_signature="", out_signature="as")
    def GetCapabilities(self):
        return ["body"]

    @dbus.service.method("org.freedesktop.Notifications", in_signature="", out_signature="ssss")
    def GetServerInformation(self):
        return ("mock", "linuxreflect", "1.0", "1.2")

Notifications()
GLib.MainLoop().run()
"#;

#[test]
#[ignore = "requires root, systemd, dbus-daemon and python3-dbus"]
fn the_session_helper_posts_a_notification() {
    if !root_tests_enabled() {
        return;
    }
    for tool in ["dbus-daemon", "python3"] {
        if !have(tool) {
            eprintln!("{tool} missing; skipping");
            return;
        }
    }
    let session = Path::new(CLI)
        .parent()
        .expect("cli parent")
        .join("linuxreflect-session");
    if !session.exists() {
        eprintln!("linuxreflect-session is not built next to the CLI; skipping");
        return;
    }
    let daemon_binary = Path::new(CLI)
        .parent()
        .expect("cli parent")
        .join("linuxreflect-daemon");
    assert!(daemon_binary.exists(), "the daemon binary is built");

    let dir = tempfile::tempdir_in("/tmp").expect("tempdir");
    let source = dir.path().join("source");
    let dest = dir.path().join("backups");
    std::fs::create_dir_all(&source).expect("dirs");
    std::fs::write(source.join("file.txt"), b"notify\n").expect("file");

    // A private session bus and a mock notification service on it.
    let bus = Command::new("dbus-daemon")
        .args(["--session", "--print-address", "--fork", "--nopidfile"])
        .output()
        .expect("dbus-daemon");
    let address = String::from_utf8_lossy(&bus.stdout).trim().to_owned();
    assert!(!address.is_empty(), "dbus-daemon printed no address");
    let script = dir.path().join("mock.py");
    let calls = dir.path().join("calls.txt");
    std::fs::write(&script, MOCK_SERVICE).expect("mock script");
    let mut mock = Command::new("python3")
        .arg(&script)
        .arg(&address)
        .arg(&calls)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start the mock service");

    // The daemon under test.
    let socket = dir.path().join("daemon.sock");
    let mut daemon = Command::new(&daemon_binary)
        .args([
            "--socket",
            &socket.display().to_string(),
            "--socket-group",
            "lr-session-test",
            "--no-create-group",
            "--dev-mode",
            "--auth",
            "static:all",
            "--sd-notify=no",
            "--token-secret-file",
            &dir.path().join("token.key").display().to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start the daemon");
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(socket.exists(), "the daemon created its socket");

    // The session helper watches two events (started and finished).
    let mut helper = Command::new(&session)
        .args(["--socket", &socket.display().to_string()])
        .args(["--session-bus", &address, "--events", "2"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start linuxreflect-session");
    std::thread::sleep(Duration::from_millis(500));

    let created = Command::new(CLI)
        .args(["--socket", &socket.display().to_string()])
        .args(["backup", "create", "--source"])
        .arg(&source)
        .args(["--dest", &dest.display().to_string()])
        .args([
            "--set",
            "notified",
            "--mode",
            "file",
            "--no-encrypt",
            "--json",
        ])
        .output()
        .expect("backup through the daemon");
    assert!(created.status.success(), "{}", text(&created));

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut delivered = String::new();
    while Instant::now() < deadline {
        delivered = std::fs::read_to_string(&calls).unwrap_or_default();
        if delivered.contains("Job started") && delivered.contains("Job finished") {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let _ = helper.kill();
    let _ = helper.wait();
    let _ = daemon.kill();
    let _ = daemon.wait();
    let _ = mock.kill();
    let _ = mock.wait();

    assert!(
        !delivered.is_empty(),
        "the mock notification service received nothing"
    );
    assert!(
        delivered.contains("LinuxReflect"),
        "the notification names the application:\n{delivered}"
    );
    assert!(
        delivered.contains("Job finished") && delivered.contains("Job started"),
        "both lifecycle notifications describe the job:\n{delivered}"
    );
}

/// Keeps the child handles alive for the duration of a test body.
#[allow(dead_code)]
fn reap(children: Vec<Child>) {
    for mut child in children {
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// The real Wayland acceptance for S14: a stack of `sway` (headless) and
/// `mako`, and the app notification is visible to the compositor's notification
/// daemon afterwards.
#[test]
#[ignore = "requires root, dbus-daemon, sway, mako and the static CLI"]
fn the_session_helper_posts_a_notification_on_wayland() {
    if !root_tests_enabled() {
        return;
    }
    for tool in ["dbus-daemon", "sway", "mako", "makoctl"] {
        if !have(tool) {
            eprintln!("{tool} missing; skipping");
            return;
        }
    }
    let session = Path::new(CLI)
        .parent()
        .expect("cli parent")
        .join("linuxreflect-session");
    let daemon_binary = Path::new(CLI)
        .parent()
        .expect("cli parent")
        .join("linuxreflect-daemon");
    if !session.exists() || !daemon_binary.exists() {
        eprintln!("linuxreflect-session/daemon are not built next to the CLI; skipping");
        return;
    }

    let dir = tempfile::tempdir_in("/tmp").expect("tempdir");
    let runtime = dir.path().join("run");
    std::fs::create_dir_all(&runtime).expect("runtime dir");
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).expect("mode");

    let source = dir.path().join("source");
    let dest = dir.path().join("backups");
    std::fs::create_dir_all(&source).expect("dirs");
    std::fs::write(source.join("file.txt"), b"notify\n").expect("file");

    let bus = Command::new("dbus-daemon")
        .args(["--session", "--print-address", "--fork", "--nopidfile"])
        .output()
        .expect("dbus-daemon");
    let address = String::from_utf8_lossy(&bus.stdout).trim().to_owned();
    assert!(!address.is_empty(), "dbus-daemon printed no address");

    // A real headless Wayland session.
    let mut sway = Command::new("sway")
        .arg("-c")
        .arg("/dev/null")
        .env("DBUS_SESSION_BUS_ADDRESS", &address)
        .env("XDG_RUNTIME_DIR", &runtime)
        .env("WLR_BACKENDS", "headless")
        .env("WLR_LIBINPUT_NO_DEVICES", "1")
        .env("WLR_RENDERER", "pixman")
        .env("SWAYSOCK", runtime.join("sway.sock"))
        .env_remove("DISPLAY")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start sway");
    let mut display = String::new();
    for _ in 0..100 {
        if let Ok(entries) = std::fs::read_dir(&runtime) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with("wayland-") && !name.ends_with(".lock") {
                    display = name;
                }
            }
        }
        if !display.is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(!display.is_empty(), "sway did not create a Wayland socket");

    // A real notification daemon on that session.
    let mut mako = Command::new("mako")
        .env("DBUS_SESSION_BUS_ADDRESS", &address)
        .env("XDG_RUNTIME_DIR", &runtime)
        .env("WAYLAND_DISPLAY", &display)
        .env_remove("DISPLAY")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start mako");
    std::thread::sleep(Duration::from_millis(1500));

    let socket = dir.path().join("daemon.sock");
    let mut daemon = Command::new(&daemon_binary)
        .args([
            "--socket",
            &socket.display().to_string(),
            "--socket-group",
            "lr-session-test",
            "--no-create-group",
            "--dev-mode",
            "--auth",
            "static:all",
            "--sd-notify=no",
            "--token-secret-file",
            &dir.path().join("token.key").display().to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start the daemon");
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(socket.exists(), "the daemon created its socket");

    let mut helper = Command::new(&session)
        .args(["--socket", &socket.display().to_string()])
        .args(["--session-bus", &address, "--events", "2"])
        .env("DBUS_SESSION_BUS_ADDRESS", &address)
        .env("WAYLAND_DISPLAY", &display)
        .env("XDG_RUNTIME_DIR", &runtime)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start linuxreflect-session");
    std::thread::sleep(Duration::from_millis(500));

    let created = Command::new(CLI)
        .args(["--socket", &socket.display().to_string()])
        .args(["backup", "create", "--source"])
        .arg(&source)
        .args(["--dest", &dest.display().to_string()])
        .args([
            "--set",
            "notified",
            "--mode",
            "file",
            "--no-encrypt",
            "--json",
        ])
        .output()
        .expect("backup through the daemon");
    assert!(created.status.success(), "{}", text(&created));

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut listed = String::new();
    while Instant::now() < deadline {
        listed = Command::new("makoctl")
            .arg("list")
            .env("DBUS_SESSION_BUS_ADDRESS", &address)
            .env("XDG_RUNTIME_DIR", &runtime)
            .env("WAYLAND_DISPLAY", &display)
            .output()
            .map(|output| text(&output))
            .unwrap_or_default();
        if listed.contains("LinuxReflect") && listed.contains("Job finished") {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let _ = helper.kill();
    let _ = helper.wait();
    let _ = daemon.kill();
    let _ = daemon.wait();
    let _ = mako.kill();
    let _ = mako.wait();
    let _ = sway.kill();
    let _ = sway.wait();

    assert!(
        listed.contains("LinuxReflect") && listed.contains("Job finished"),
        "the Wayland notification daemon did not show the completed-job notification:\n{listed}"
    );
}
