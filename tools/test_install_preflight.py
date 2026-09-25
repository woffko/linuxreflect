#!/usr/bin/env python3
"""Check installer input rejection without running privileged operations."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BINARIES = (
    "linuxreflect", "linuxreflect-daemon", "linuxreflect-gui",
    "linuxreflect-session", "linuxreflect-rescue",
)
RESOURCES = (
    "polkit/org.linuxreflect.policy", "applications/linuxreflect.desktop",
    "systemd/linuxreflect-daemon.socket", "systemd/linuxreflect-daemon.service",
    "systemd/linuxreflect-session.service",
    "install-binaries.sh",
)


class InstallerPreflight(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="lr-install-preflight-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.contrib = self.root / "contrib"
        self.contrib.mkdir()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.stub = self.root / "stub"
        self.stub.mkdir()
        self.marker = self.root / "mutation-attempt"
        shutil.copyfile(ROOT / "contrib/install-host.sh", self.contrib / "install-host.sh")
        for name in BINARIES:
            path = self.bin / name
            path.touch(mode=0o755)
        for name in RESOURCES:
            path = self.contrib / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("test fixture\n")
        # Every mutating command is blocked even if preflight regresses.
        for name in ("install", "groupadd", "systemctl", "systemd-tmpfiles"):
            path = self.stub / name
            path.write_text('#!/bin/sh\n: > "$MUTATION_MARKER"\nexit 99\n')
            path.chmod(0o755)

    def rejected_before_mutation(self, expected):
        env = dict(os.environ, BIN=str(self.bin), MUTATION_MARKER=str(self.marker))
        env["PATH"] = str(self.stub) + os.pathsep + os.environ["PATH"]
        result = subprocess.run(
            ["/bin/sh", str(self.contrib / "install-host.sh")], env=env,
            capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(expected, result.stderr)
        self.assertFalse(self.marker.exists(), "installer mutated before validating inputs")

    def test_each_missing_resource_is_rejected_before_installing(self):
        for name in RESOURCES:
            with self.subTest(resource=name):
                path = self.contrib / name
                path.unlink()
                self.rejected_before_mutation(str(path))
                path.write_text("test fixture\n")

    def test_each_missing_binary_is_rejected_before_installing(self):
        for name in BINARIES:
            with self.subTest(binary=name):
                path = self.bin / name
                path.unlink()
                self.rejected_before_mutation(str(path))
                path.touch(mode=0o755)

    def test_nonexecutable_binary_is_rejected_before_installing(self):
        (self.bin / "linuxreflect-gui").chmod(0o644)
        self.rejected_before_mutation("not executable:")


class BinaryPublication(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="lr-binary-publication-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.destination = self.root / "destination"
        self.source.mkdir()
        self.destination.mkdir()
        for name in BINARIES:
            (self.source / name).write_text("#!/bin/sh\nexit 0\n")
            (self.source / name).chmod(0o755)
            (self.destination / name).write_text("old binary\n")

    def publish(self, env=None):
        # Constant shell program; all paths are positional arguments, not code.
        return subprocess.run(
            ["/bin/sh", "-c", '. "$1"; install_binaries "$2" "$3"', "test",
             str(ROOT / "contrib/install-binaries.sh"), str(self.source), str(self.destination)],
            env=env, capture_output=True, text=True, timeout=5,
        )

    def test_replacement_preserves_a_running_executable(self):
        executable = self.destination / "linuxreflect-daemon"
        shutil.copyfile(shutil.which("sleep"), executable)
        executable.chmod(0o755)
        child = subprocess.Popen([str(executable), "10"])
        try:
            original_inode = executable.stat().st_ino
            result = self.publish()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIsNone(child.poll(), "publication terminated the running executable")
            self.assertEqual(Path(f"/proc/{child.pid}/exe").stat().st_ino, original_inode)
            self.assertNotEqual(executable.stat().st_ino, original_inode)
            subprocess.run([str(executable)], check=True, timeout=2)
            for name in BINARIES:
                self.assertEqual((self.source / name).read_bytes(), (self.destination / name).read_bytes())
                self.assertEqual((self.destination / name).stat().st_mode & 0o777, 0o755)
            self.assertEqual(list(self.destination.glob(".linuxreflect-install.*")), [])
        finally:
            child.terminate()
            child.wait(timeout=3)

    def test_copy_failure_leaves_all_installed_binaries_unchanged(self):
        stub = self.root / "stub"
        stub.mkdir()
        installer = stub / "install"
        real_install = shutil.which("install")
        installer.write_text(
            '#!/bin/sh\ncase "$3" in */linuxreflect-gui) exit 13;; esac\n'
            'exec "$REAL_INSTALL" "$@"\n'
        )
        installer.chmod(0o755)
        env = dict(os.environ, PATH=str(stub) + os.pathsep + os.environ["PATH"], REAL_INSTALL=real_install)
        result = self.publish(env)
        self.assertEqual(result.returncode, 13, result.stderr)
        for name in BINARIES:
            self.assertEqual((self.destination / name).read_text(), "old binary\n")
        self.assertEqual(list(self.destination.glob(".linuxreflect-install.*")), [])


if __name__ == "__main__":
    unittest.main()
