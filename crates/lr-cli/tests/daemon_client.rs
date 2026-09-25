//! CLI ↔ daemon round trip (spec §K S11).
//!
//! The daemon runs as a separate process; the CLI is invoked as a real binary
//! with `--socket`, so client mode, the interceptor and the in-process fallback
//! are all exercised the way a user would exercise them.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::Duration;

const CLI: &str = env!("CARGO_BIN_EXE_linuxreflect");

/// The daemon binary sits next to the CLI binary when the workspace is built.
fn daemon_binary() -> Option<PathBuf> {
    let cli = PathBuf::from(CLI);
    let candidate = cli.parent()?.join("linuxreflect-daemon");
    candidate.exists().then_some(candidate)
}

struct Daemon {
    child: Child,
    socket: PathBuf,
    _dir: tempfile::TempDir,
}

impl Daemon {
    fn start(auth: &str) -> Option<Self> {
        let binary = daemon_binary()?;
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("daemon.sock");
        let child = Command::new(binary)
            .args([
                "--socket",
                &socket.display().to_string(),
                "--socket-group",
                "lr-cli-test",
                "--no-create-group",
                "--dev-mode",
                "--auth",
                auth,
                "--sd-notify=no",
                "--token-secret-file",
                &dir.path().join("token.key").display().to_string(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let mut daemon = Self {
            child,
            socket,
            _dir: dir,
        };
        for _ in 0..50 {
            if daemon.socket.exists() {
                return Some(daemon);
            }
            if let Ok(Some(_)) = daemon.child.try_wait() {
                return None;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        None
    }

    fn cli(&self, args: &[&str]) -> Output {
        Command::new(CLI)
            .arg("--socket")
            .arg(&self.socket)
            .args(args)
            .output()
            .expect("run the CLI")
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn uid() -> u32 {
    String::from_utf8_lossy(&Command::new("id").arg("-u").output().expect("id").stdout)
        .trim()
        .parse()
        .expect("uid")
}

fn have(tool: &str) -> bool {
    Command::new("which")
        .arg(tool)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn source_image(dir: &Path) -> Option<PathBuf> {
    if !have("mkfs.ext4") {
        eprintln!("mkfs.ext4 missing; skipping");
        return None;
    }
    let source = dir.join("source.img");
    let file = std::fs::File::create(&source).expect("create");
    file.set_len(64 * 1024 * 1024).expect("size");
    drop(file);
    assert!(
        Command::new("mkfs.ext4")
            .args(["-F", "-q", &source.display().to_string()])
            .status()
            .expect("mkfs.ext4")
            .success()
    );
    Some(source)
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn the_cli_round_trips_through_the_daemon() {
    let Some(daemon) = Daemon::start(&format!("static:{}", uid())) else {
        eprintln!("the daemon binary is not built next to the CLI; skipping");
        return;
    };
    let work = tempfile::tempdir().expect("workdir");
    let Some(source) = source_image(work.path()) else {
        return;
    };
    let dest = work.path().join("out");

    // status reports the daemon as running.
    let status = daemon.cli(&["daemon", "status", "--json"]);
    assert!(status.status.success(), "{}", stderr(&status));
    assert!(
        stdout(&status).contains("\"running\": true"),
        "{}",
        stdout(&status)
    );

    // backup create streams progress and ends with the report.
    let created = daemon.cli(&[
        "backup",
        "create",
        "--source",
        &source.display().to_string(),
        "--dest",
        &dest.display().to_string(),
        "--set",
        "cli-set",
        "--no-encrypt",
        "--compress",
        "none",
        "--json",
    ]);
    assert!(created.status.success(), "stderr: {}", stderr(&created));
    let report = stdout(&created);
    assert!(report.contains("phase:"), "progress is printed: {report}");
    // The report is the last line; the phase lines precede it.
    let json = report
        .lines()
        .rev()
        .find(|line| line.trim_start().starts_with('{'))
        .expect("the report line");
    let value: serde_json::Value = serde_json::from_str(json).expect("report json");
    let image_uri = value
        .get("image_uri")
        .and_then(|uri| uri.as_str())
        .expect("image_uri")
        .to_owned();
    assert!(!image_uri.is_empty());

    // the set lists its chain through the daemon.
    let listed = daemon.cli(&[
        "backup",
        "list",
        "--dest",
        &dest.display().to_string(),
        "--set",
        "cli-set",
    ]);
    assert!(listed.status.success(), "{}", stderr(&listed));
    assert!(stdout(&listed).contains("chain"), "{}", stdout(&listed));

    // and the catalog can be rebuilt through it.
    let rebuilt = daemon.cli(&[
        "catalog",
        "--dest",
        &dest.display().to_string(),
        "--set",
        "cli-set",
        "--json",
    ]);
    assert!(rebuilt.status.success(), "{}", stderr(&rebuilt));

    // verify succeeds, then names the chunk after a flipped byte.
    let verified = daemon.cli(&["verify", "--image", &image_uri, "--chain", "--json"]);
    assert!(verified.status.success(), "{}", stderr(&verified));
    assert!(
        stdout(&verified).contains("chunks"),
        "{}",
        stdout(&verified)
    );

    let image_path = image_uri
        .strip_prefix(&format!("{}/", dest.display()))
        .map(|rest| dest.join(rest))
        .expect("image path");
    {
        use std::io::{Read, Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&image_path)
            .expect("open image");
        let offset = lr_format::SB_SIZE as u64 + 20;
        file.seek(SeekFrom::Start(offset)).expect("seek");
        let mut byte = [0u8; 1];
        file.read_exact(&mut byte).expect("read");
        byte[0] ^= 1;
        file.seek(SeekFrom::Start(offset)).expect("seek");
        file.write_all(&byte).expect("write");
        file.sync_all().expect("sync");
    }
    let broken = daemon.cli(&["verify", "--image", &image_uri]);
    assert!(!broken.status.success(), "a corrupt image must fail");
    assert!(stderr(&broken).contains("chunk"), "{}", stderr(&broken));

    // restore prepare/apply through the daemon, on the intact copy.
    daemon.cli(&[
        "backup",
        "create",
        "--source",
        &source.display().to_string(),
        "--dest",
        &dest.display().to_string(),
        "--set",
        "cli-set2",
        "--no-encrypt",
        "--compress",
        "none",
        "--json",
    ]);
    let second = dest.join("cli-set2");
    let chain_dir = std::fs::read_dir(&second)
        .expect("set dir")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.is_dir())
        .expect("chain dir");
    let image = std::fs::read_dir(&chain_dir)
        .expect("chain dir")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.extension().is_some_and(|ext| ext == "lrimg"))
        .expect("image");
    let target = work.path().join("target.img");
    let file = std::fs::File::create(&target).expect("target");
    file.set_len(64 * 1024 * 1024).expect("size");
    drop(file);
    let prepared = daemon.cli(&[
        "restore",
        "prepare",
        "--image",
        &image.display().to_string(),
        "--target",
        &target.display().to_string(),
        "--json",
    ]);
    assert!(prepared.status.success(), "{}", stderr(&prepared));
    let plan: serde_json::Value = serde_json::from_str(&stdout(&prepared)).expect("plan json");
    let token = plan["token"].as_str().expect("token").to_owned();
    let applied = daemon.cli(&["restore", "apply", "--token", &token, "--confirm", "--json"]);
    assert!(applied.status.success(), "{}", stderr(&applied));
    assert!(stdout(&applied).contains("block"), "{}", stdout(&applied));

    // an unknown job is reported, not silently accepted.
    let missing = daemon.cli(&["job", "get", "no-such-job"]);
    assert!(!missing.status.success());
    assert!(stderr(&missing).contains("no job"), "{}", stderr(&missing));
}

/// File mode (spec §K S12) through the daemon: a directory tree is chunked,
/// verified and restored, and the restored file matches byte for byte.
#[test]
fn the_cli_round_trips_a_file_tree_through_the_daemon() {
    let Some(daemon) = Daemon::start(&format!("static:{}", uid())) else {
        eprintln!("the daemon binary is not built next to the CLI; skipping");
        return;
    };
    let work = tempfile::tempdir().expect("workdir");
    let source = work.path().join("tree");
    let dest = work.path().join("out");
    let target = work.path().join("restored");
    std::fs::create_dir_all(source.join("nested")).expect("dirs");
    std::fs::create_dir_all(&target).expect("target");
    std::fs::write(source.join("nested/data.bin"), vec![0x42u8; 200 * 1024]).expect("file");
    std::fs::write(source.join("note.txt"), b"through the daemon\n").expect("file");

    let created = daemon.cli(&[
        "backup",
        "create",
        "--source",
        &source.display().to_string(),
        "--dest",
        &dest.display().to_string(),
        "--set",
        "file-set",
        "--mode",
        "file",
        "--no-encrypt",
        "--compress",
        "none",
        "--json",
    ]);
    assert!(created.status.success(), "stderr: {}", stderr(&created));
    let report = stdout(&created);
    let json = report
        .lines()
        .rev()
        .find(|line| line.trim_start().starts_with('{'))
        .expect("the report line");
    let value: serde_json::Value = serde_json::from_str(json).expect("report json");
    assert_eq!(value["mode"], "file", "{json}");
    let image = value["image_path"].as_str().expect("image_path").to_owned();
    assert!(
        matches!(value["consistency"].as_str(), Some("per_file")),
        "{json}"
    );

    let verified = daemon.cli(&["verify", "--image", &image, "--chain"]);
    assert!(verified.status.success(), "{}", stderr(&verified));

    let prepared = daemon.cli(&[
        "restore",
        "prepare",
        "--image",
        &image,
        "--target",
        &target.display().to_string(),
        "--json",
    ]);
    assert!(prepared.status.success(), "{}", stderr(&prepared));
    let plan: serde_json::Value = serde_json::from_str(&stdout(&prepared)).expect("plan json");
    assert_eq!(plan["image_kind"], "File", "{plan}");
    let token = plan["token"].as_str().expect("token").to_owned();

    let applied = daemon.cli(&["restore", "apply", "--token", &token, "--confirm"]);
    assert!(applied.status.success(), "{}", stderr(&applied));
    assert_eq!(
        std::fs::read(target.join("note.txt")).expect("read"),
        b"through the daemon\n"
    );
    assert_eq!(
        std::fs::read(target.join("nested/data.bin"))
            .expect("read")
            .len(),
        200 * 1024
    );
}
