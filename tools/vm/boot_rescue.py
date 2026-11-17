#!/usr/bin/env python3
"""Boot a rescue image under SeaBIOS and OVMF with Secure Boot (release check).

The rescue session announces itself on the first serial port with
`LINUXREFLECT-RESCUE-READY graphical|tui` (contrib/rescue). Each boot runs on
a throw-away copy-on-write overlay, so the image itself is never written,
and passes when the marker appears before the timeout. Under OVMF the check
also requires the kernel's "Secure boot enabled" line, so a boot with Secure
Boot off cannot pass. KVM is used when /dev/kvm opens, TCG otherwise.

Usage: boot_rescue.py IMAGE[.zst] [--firmware bios|uefi-sb]... [--timeout S]
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

OVMF_CODE_SECBOOT = "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd"
OVMF_VARS_MS = "/usr/share/OVMF/OVMF_VARS_4M.ms.fd"
MARKER = "LINUXREFLECT-RESCUE-READY"
SECURE_BOOT = "Secure boot enabled"


def kvm_usable() -> bool:
    try:
        os.close(os.open("/dev/kvm", os.O_RDWR))
    except OSError:
        return False
    return True


def raw_image(image: Path, work: Path) -> Path:
    """The image as a raw file: decompressed into `work` when it is .zst."""
    if image.suffix != ".zst":
        return image
    raw = work / image.with_suffix("").name
    subprocess.run(["zstd", "-q", "-d", "-f", str(image), "-o", str(raw)], check=True)
    return raw


def boot(raw: Path, firmware: str, work: Path, timeout: int) -> tuple[bool, str, float]:
    """Boot once; return whether the checks passed, the marker line and the
    seconds until it appeared (or the timeout)."""
    overlay = work / f"overlay-{firmware}.qcow2"
    subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", "-F", "raw",
                    "-b", str(raw.resolve()), str(overlay)], check=True)
    serial = work / f"serial-{firmware}.log"
    accel = ["-accel", "kvm", "-cpu", "host"] if kvm_usable() else \
        ["-accel", "tcg,thread=multi", "-cpu", "max"]
    command = ["qemu-system-x86_64", *accel, "-m", "2048", "-smp", "4",
               "-display", "none", "-no-reboot", "-serial", f"file:{serial}",
               "-nic", "none",
               "-drive", f"file={overlay},format=qcow2,if=virtio"]
    if firmware == "uefi-sb":
        vars_file = work / "vars.fd"
        shutil.copy(OVMF_VARS_MS, vars_file)
        command += ["-machine", "q35,smm=on",
                    "-global", "driver=cfi.pflash01,property=secure,value=on",
                    "-drive", f"if=pflash,format=raw,readonly=on,file={OVMF_CODE_SECBOOT}",
                    "-drive", f"if=pflash,format=raw,file={vars_file}"]
    else:
        command += ["-machine", "q35"]
    started = time.monotonic()
    qemu = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    line = ""
    try:
        while time.monotonic() - started < timeout and qemu.poll() is None:
            text = serial.read_text(errors="replace") if serial.exists() else ""
            found = [l for l in text.splitlines() if MARKER in l]
            if found:
                line = found[-1].strip()
                break
            time.sleep(2)
    finally:
        qemu.kill()
        _, errors = qemu.communicate()
    seconds = round(time.monotonic() - started, 1)
    text = serial.read_text(errors="replace") if serial.exists() else ""
    passed = bool(line)
    if firmware == "uefi-sb" and SECURE_BOOT not in text:
        print(f"[{firmware}] the kernel did not report \"{SECURE_BOOT}\"", flush=True)
        passed = False
    if not line:
        print(f"[{firmware}] no {MARKER} line; qemu said: "
              f"{errors.decode(errors='replace')[-500:]}", flush=True)
    shutil.copy(serial, Path.cwd() / f"rescue-serial-{firmware}.log")
    return passed, line, seconds


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("image", type=Path)
    parser.add_argument("--firmware", action="append", choices=["bios", "uefi-sb"])
    parser.add_argument("--timeout", type=int, default=1800)
    args = parser.parse_args()
    failures = 0
    with tempfile.TemporaryDirectory(prefix="lr-rescue-boot-") as directory:
        work = Path(directory)
        raw = raw_image(args.image, work)
        for firmware in args.firmware or ["bios", "uefi-sb"]:
            passed, line, seconds = boot(raw, firmware, work, args.timeout)
            print(f"[{firmware}] {'PASS' if passed else 'FAIL'} after {seconds} s: {line}",
                  flush=True)
            failures += not passed
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
