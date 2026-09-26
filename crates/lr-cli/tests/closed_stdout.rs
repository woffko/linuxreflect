//! Output into a closed pipe (`linuxreflect … | head`) ends quietly with the
//! conventional status 141 instead of a panic, which the release profile
//! turns into "Aborted".

use std::process::{Command, Stdio};

#[test]
fn a_closed_stdout_is_not_a_crash() {
    let (reader, writer) = std::io::pipe().expect("pipe");
    drop(reader);
    let output = Command::new(env!("CARGO_BIN_EXE_linuxreflect"))
        .arg("caps")
        .stdout(Stdio::from(writer))
        .stderr(Stdio::piped())
        .output()
        .expect("run the CLI");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(141), "stderr: {stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
}
