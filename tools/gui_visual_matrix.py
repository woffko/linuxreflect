#!/usr/bin/env python3
"""Capture initial GUI pages across the required size/scale matrix.

This drives real X11 clicks and resize cycles. Captures still require visual
inspection; this is not a backup/restore or dialog acceptance test. Stop at the
first failed invocation, retaining prior captures and a provenance manifest.
"""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.parent.is_dir() or output.exists():
        parser.error("Choose a new output directory inside an existing parent")
    project = Path(__file__).resolve().parents[1]
    binaries = project / "target/debug"
    manifest = {"binaries": {}, "cases": []}
    for name in ["linuxreflect-gui", "linuxreflect-daemon"]:
        with (binaries / name).open("rb") as binary:
            manifest["binaries"][name] = hashlib.file_digest(binary, "sha256").hexdigest()
    output.mkdir()
    manifest_path = output / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    for width, height in [(1024, 768), (1280, 720), (1920, 1080)]:
        for scale in ["1", "1.5", "2"]:
            for index, page in enumerate(["disks", "backup", "restore", "history"]):
                name = f"{width}x{height}-scale{scale}-{page}"
                argv = [sys.executable, str(project / "tools/gui_visual_smoke.py"),
                        "--width", str(width), "--height", str(height),
                        "--scale", scale, "--resize-cycle", "--output", str(output / f"{name}.png")]
                if index:
                    # The navigation row spans the window. Coordinates are
                    # physical pixels; Slint scale affects its vertical offset.
                    argv.extend(["--click", f"{int(width * (index + 0.5) / 4)},{int(82 * float(scale))}"])
                print(f"Capture {name}", flush=True)
                # The helper bounds every subprocess operation and owns cleanup.
                # Do not kill it from an outer timeout before its finally runs.
                result = subprocess.run(argv, cwd=project, capture_output=True, text=True, check=False)
                (output / f"{name}.log").write_text(result.stdout + result.stderr)
                manifest["cases"].append({"name": name, "argv": argv, "exit_code": result.returncode,
                                          "visual_review": "pending"})
                manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
                if result.returncode:
                    print(result.stdout + result.stderr, file=sys.stderr)
                    raise SystemExit(result.returncode)
    for name, expected in manifest["binaries"].items():
        with (binaries / name).open("rb") as binary:
            if hashlib.file_digest(binary, "sha256").hexdigest() != expected:
                raise SystemExit(f"Binary changed during capture: {name}; matrix must be repeated")
    print(f"Captured {len(manifest['cases'])} cases; visual inspection pending: {output}")


if __name__ == "__main__":
    main()
