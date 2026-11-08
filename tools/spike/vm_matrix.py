#!/usr/bin/env python3
"""Run the tracked-freeze spike inside the target distributions' own kernels.

Phase 0 of docs/live-backup-plan.md. For each distribution this downloads the
official cloud image once (checksum verified against the publisher's sums
file), boots a throwaway copy-on-write overlay under qemu with a NoCloud seed
whose cloud-init runs tools/spike/tracked_freeze_spike.py as root inside the
VM, reads the JSON result from the serial console and powers the VM off.

Runs as an ordinary user; nothing on the host is touched outside the cache
and run directories. KVM is used when /dev/kvm opens, TCG otherwise.

    python3 tools/spike/vm_matrix.py --out results/
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPIKE = HERE / "tracked_freeze_spike.py"

IMAGES = {
    "debian-12": (
        "https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2",
        "https://cloud.debian.org/images/cloud/bookworm/latest/SHA512SUMS",
        "sha512",
    ),
    "debian-13": (
        "https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2",
        "https://cloud.debian.org/images/cloud/trixie/latest/SHA512SUMS",
        "sha512",
    ),
    "ubuntu-22.04": (
        "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img",
        "https://cloud-images.ubuntu.com/jammy/current/SHA256SUMS",
        "sha256",
    ),
    "ubuntu-24.04": (
        "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img",
        "https://cloud-images.ubuntu.com/noble/current/SHA256SUMS",
        "sha256",
    ),
}
AGENT = "linuxreflect-spike/0.1"


def fetch(url: str, target: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": AGENT})
    partial = target.with_suffix(target.suffix + ".part")
    with urllib.request.urlopen(request, timeout=60) as response, open(partial, "wb") as out:
        shutil.copyfileobj(response, out, length=1 << 20)
    partial.rename(target)


def image(cache: Path, name: str) -> Path:
    """The verified base image for `name`, downloaded once into its own directory."""
    url, sums_url, algorithm = IMAGES[name]
    directory = cache / name
    directory.mkdir(parents=True, exist_ok=True)
    filename = url.rsplit("/", 1)[1]
    target = directory / filename
    sums = directory / "SUMS"
    fetch(sums_url, sums)
    expected = None
    for line in sums.read_text().splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip("*") == filename:
            expected = parts[0]
    if expected is None:
        raise RuntimeError(f"{filename} is not listed in {sums_url}")

    def digest() -> str:
        hasher = hashlib.new(algorithm)
        with open(target, "rb") as handle:
            for block in iter(lambda: handle.read(1 << 20), b""):
                hasher.update(block)
        return hasher.hexdigest()

    if not target.exists() or digest() != expected:
        print(f"[{name}] downloading {url}", flush=True)
        fetch(url, target)
        if digest() != expected:
            target.unlink()
            raise RuntimeError(f"{filename}: checksum mismatch")
    return target


def seed(directory: Path, name: str, spike_args: str) -> Path:
    """A NoCloud seed disk (vfat, label CIDATA) that runs the spike once."""
    payload = base64.b64encode(SPIKE.read_bytes()).decode()
    command = (
        f"python3 /root/spike.py {spike_args} --json /root/spike.json > /root/spike.log 2>&1; "
        "echo LR-SPIKE-RC $? > /dev/ttyS0; "
        "echo LR-SPIKE-BEGIN > /dev/ttyS0; base64 -w0 /root/spike.json > /dev/ttyS0; "
        "echo > /dev/ttyS0; echo LR-SPIKE-END > /dev/ttyS0; "
        "tail -c 4000 /root/spike.log > /dev/ttyS0; sync; poweroff"
    )
    user_data = (
        "#cloud-config\n"
        "write_files:\n"
        "  - path: /root/spike.py\n"
        "    permissions: '0755'\n"
        "    encoding: b64\n"
        f"    content: {payload}\n"
        "runcmd:\n"
        f"  - [sh, -c, {json.dumps(command)}]\n"
    )
    meta_data = f"instance-id: lr-spike-{name}-{int(time.time())}\nlocal-hostname: lr-spike\n"
    (directory / "user-data").write_text(user_data)
    (directory / "meta-data").write_text(meta_data)
    disk = directory / "seed.img"
    with open(disk, "wb") as handle:
        handle.truncate(4 * 1024 * 1024)
    subprocess.run(["mkfs.vfat", "-n", "CIDATA", str(disk)], check=True, capture_output=True)
    for item in ("user-data", "meta-data"):
        subprocess.run(["mcopy", "-i", str(disk), str(directory / item), f"::{item}"],
                       check=True, capture_output=True)
    return disk


def kvm_usable() -> bool:
    try:
        os.close(os.open("/dev/kvm", os.O_RDWR))
        return True
    except OSError:
        return False


def boot(name: str, base: Path, run_dir: Path, spike_args: str, timeout: int) -> dict:
    overlay = run_dir / "disk.qcow2"
    subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", "-b", str(base), "-F", "qcow2",
                    str(overlay), "20G"], check=True)
    seed_disk = seed(run_dir, name, spike_args)
    serial = run_dir / "serial.log"
    accel = ["-accel", "kvm", "-cpu", "host"] if kvm_usable() else \
        ["-accel", "tcg,thread=multi", "-cpu", "max"]
    command = [
        "qemu-system-x86_64", *accel, "-m", "3072", "-smp", "4",
        "-display", "none", "-no-reboot",
        "-serial", f"file:{serial}",
        "-drive", f"file={overlay},format=qcow2,if=virtio",
        "-drive", f"file={seed_disk},format=raw,if=virtio,readonly=on",
        "-nic", "user,model=virtio-net-pci,restrict=on",
    ]
    started = time.monotonic()
    qemu = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        qemu.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        qemu.kill()
        qemu.wait()
    elapsed = round(time.monotonic() - started, 1)
    text = serial.read_text(errors="replace") if serial.exists() else ""
    outcome = {"distribution": name, "accel": accel[1], "seconds": elapsed}
    if "LR-SPIKE-BEGIN" in text and "LR-SPIKE-END" in text:
        body = text.split("LR-SPIKE-BEGIN", 1)[1].split("LR-SPIKE-END", 1)[0].strip()
        try:
            outcome["results"] = json.loads(base64.b64decode(body))
        except (ValueError, json.JSONDecodeError) as error:
            outcome["error"] = f"undecodable result: {error}"
        tail = text.split("LR-SPIKE-END", 1)[1]
        outcome["log_tail"] = tail[-4000:]
    else:
        outcome["error"] = "no result on the serial console"
        outcome["serial_tail"] = text[-6000:]
    if qemu.stderr:
        outcome["qemu_stderr"] = qemu.stderr.read().decode(errors="replace")[-2000:]
    return outcome


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cache", type=Path,
                        default=Path.home() / ".cache/linuxreflect/vm-images")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--only", action="append", choices=sorted(IMAGES))
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument("--spike-args", default=(
        "--workdir /var/tmp --size-mib 512 --seconds 25 --vm-root-freeze 1.0"))
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    names = args.only or sorted(IMAGES)
    failures = 0
    for name in names:
        base = image(args.cache, name)
        run_dir = Path(tempfile.mkdtemp(prefix=f"lr-vm-{name}-"))
        try:
            print(f"[{name}] booting ({'KVM' if kvm_usable() else 'TCG'})", flush=True)
            outcome = boot(name, base, run_dir, args.spike_args, args.timeout)
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)
        (args.out / f"{name}.json").write_text(json.dumps(outcome, indent=2))
        status = "error: " + outcome["error"] if "error" in outcome else "ok"
        print(f"[{name}] {status} in {outcome['seconds']} s", flush=True)
        failures += "error" in outcome
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
