#!/usr/bin/env python3
"""Slice 18 VM acceptance: a running system imaged live, restored, booted.

Spec v2.2 §K S18 AC (d). For each distribution and firmware:

1. boot the distribution's official cloud image (a copy-on-write overlay)
   with two blank disks and a seed disk; cloud-init runs `guest/run.sh`,
   which images the running system disk (`/dev/vda`) live with
   `--snapshot tracked-freeze` onto `/dev/vdb` and restores it onto
   `/dev/vdc`, while a writer keeps the root filesystem busy;
2. boot `/dev/vdc` alone, with fresh firmware variables; the restored
   system's `lr-restored-check` unit reports how it came up;
3. judge: the restored system reached `multi-user.target`, needed no journal
   recovery, and holds an exact prefix of the writer's log that ends inside
   the backup.

With `--incremental` (series B3, D-142) the writer keeps running after the
full image, a live incremental image of the disk follows, and the chain (the
full plus the incremental) is restored; the log must end inside the
incremental's backup.

Runs as an ordinary user. Images are verified downloads (tools/spike/
vm_matrix.py); every disk lives in a run directory that is removed at the end.

    python3 tools/vm/live_restore_matrix.py --cli target/.../linuxreflect.stripped --out results/
"""

from __future__ import annotations

import argparse
import base64
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
GUEST = HERE / "guest"
SPIKE = HERE.parent / "spike" / "vm_matrix.py"

OVMF_CODE = "/usr/share/OVMF/OVMF_CODE_4M.fd"
OVMF_VARS = "/usr/share/OVMF/OVMF_VARS_4M.fd"
OVMF_CODE_SECBOOT = "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd"
OVMF_VARS_MS = "/usr/share/OVMF/OVMF_VARS_4M.ms.fd"
DISK_SIZE = "8G"
MATRIX = [
    ("debian-12", "uefi-sb"),
    ("debian-13", "uefi-sb"),
    ("ubuntu-22.04", "uefi-sb"),
    ("ubuntu-24.04", "uefi-sb"),
    ("debian-12", "bios"),
    ("ubuntu-24.04", "bios"),
]


def load_vm_matrix():
    spec = importlib.util.spec_from_file_location("vm_matrix", SPIKE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def seed_disk(run: Path, name: str, cli: Path, mode: str) -> Path:
    command = "mkdir -p /mnt/seed && mount -o ro LABEL=CIDATA /mnt/seed && sh /mnt/seed/run.sh"
    (run / "user-data").write_text(
        "#cloud-config\nruncmd:\n" f"  - [sh, -c, {json.dumps(command)}]\n"
    )
    (run / "meta-data").write_text(
        f"instance-id: lr-s18-{name}-{int(time.time())}\nlocal-hostname: lr-s18\n"
    )
    (run / "mode").write_text(mode)
    disk = run / "seed.img"
    with open(disk, "wb") as handle:
        handle.truncate(64 * 1024 * 1024)
    subprocess.run(["mkfs.vfat", "-n", "CIDATA", str(disk)], check=True, capture_output=True)
    files = [run / "user-data", run / "meta-data", run / "mode", cli]
    files += [GUEST / item for item in
              ("run.sh", "lr-writer", "lr-chain-check", "lr-restored-check",
               "lr-restored-check.service")]
    for path in files:
        target = "linuxreflect" if path == cli else path.name
        subprocess.run(["mcopy", "-i", str(disk), str(path), f"::{target}"],
                       check=True, capture_output=True)
    return disk


def firmware_args(firmware: str, run: Path, label: str) -> list[str]:
    if firmware == "bios":
        return []
    secure = firmware == "uefi-sb"
    vars_file = run / f"vars-{label}.fd"
    shutil.copy(OVMF_VARS_MS if secure else OVMF_VARS, vars_file)
    code = OVMF_CODE_SECBOOT if secure else OVMF_CODE
    return [
        "-machine", "q35",
        "-drive", f"if=pflash,format=raw,readonly=on,file={code}",
        "-drive", f"if=pflash,format=raw,file={vars_file}",
    ]


def boot(drives: list[str], firmware: str, run: Path, label: str, timeout: int,
         accel: list[str]) -> tuple[str, str, float]:
    """Boot, and return the console, the result port (the guest's ttyS1,
    which only the guest scripts write) and the seconds it took."""
    serial = run / f"serial-{label}.log"
    result = run / f"result-{label}.log"
    command = ["qemu-system-x86_64", *accel, "-m", "3072", "-smp", "8",
               "-display", "none", "-no-reboot", "-serial", f"file:{serial}",
               "-serial", f"file:{result}",
               "-nic", "user,model=virtio-net-pci,restrict=on",
               *firmware_args(firmware, run, label)]
    for drive in drives:
        command += ["-drive", drive]
    started = time.monotonic()
    errors = run / f"qemu-{label}.err"
    with open(errors, "wb") as stderr:
        qemu = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=stderr)
        try:
            qemu.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            qemu.kill()
            qemu.wait()
    boot.last_exit = (qemu.returncode, errors.read_text(errors="replace")[-2000:])
    text = serial.read_text(errors="replace") if serial.exists() else ""
    results = result.read_text(errors="replace") if result.exists() else ""
    return text, results, round(time.monotonic() - started, 1)


def between(text: str, begin: str, end: str) -> str | None:
    if begin not in text or end not in text.split(begin, 1)[1]:
        return None
    return text.split(begin, 1)[1].split(end, 1)[0].strip()


def first_boot_results(text: str, console: str) -> dict:
    body = between(text, "LR-RESULT-BEGIN", "LR-RESULT-END")
    if body is None:
        return {"error": "no result from the first boot",
                "steps": [line for line in console.splitlines() if "LR-STEP" in line][-5:],
                "serial_tail": console[-4000:]}
    files = {}
    payload = base64.b64decode("".join(body.split()), validate=True)
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
        for member in archive.getmembers():
            handle = archive.extractfile(member)
            if handle:
                files[member.name] = handle.read().decode(errors="replace")
    return files


def member_report(files: dict, name: str) -> dict:
    """What the backup `name` (`lr-backup` or `lr-incremental`) reported."""
    try:
        report = json.loads(files.get(f"{name}.json", "{}"))
    except json.JSONDecodeError:
        report = {}
    rc = files.get(f"{name}.rc", "").strip()
    return {
        "rc": rc,
        "member_kind": report.get("member_kind"),
        "seq_in_chain": report.get("seq_in_chain"),
        "stored_chunks": sum(region.get("stored_chunks", 0)
                             for region in report.get("regions", [])),
        "changed_chunks": report.get("changed_chunks"),
        "inherited_chunks": report.get("inherited_chunks"),
        "tracked": report.get("tracked"),
        "regions": [(region.get("index"), region.get("fs_type"), region.get("consistency"))
                    for region in report.get("regions", [])],
        "error": files.get(f"{name}.err", "")[-1500:] if rc != "0" else "",
        # The pass log (`-v`): dirty bytes, read rate and verdict per pass.
        "passes": [line[line.find("tracked-freeze pass"):].strip()
                   for line in files.get(f"{name}.err", "").splitlines()
                   if "tracked-freeze pass" in line][-30:],
    }


def judge(files: dict, restored: str | None, incremental: bool) -> dict:
    verdict: dict = {}
    full = member_report(files, "lr-backup")
    backup_rc = full["rc"]
    apply_rc = files.get("lr-apply.rc", "").strip()
    verdict["backup_rc"] = backup_rc
    verdict["apply_rc"] = apply_rc
    verdict["tracked"] = full["tracked"]
    verdict["regions"] = full["regions"]
    verdict["backup_error"] = full["error"]
    verdict["passes"] = full["passes"]
    window = "lr-backup"
    member_ok = True
    if incremental:
        member = member_report(files, "lr-incremental")
        verdict["full"] = {key: full[key] for key in
                           ("member_kind", "seq_in_chain", "stored_chunks", "changed_chunks")}
        verdict["incremental"] = member
        window = "lr-incremental"
        # The member is an incremental of the full, stores less than it, and
        # every region was copied live.
        member_ok = (
            member["rc"] == "0"
            and member["seq_in_chain"] == 1
            and str(member["member_kind"]).lower() == "incremental"
            and 0 < member["stored_chunks"] < full["stored_chunks"]
            and all(consistency == "frozen" for _, _, consistency in member["regions"])
        )
    verdict["apply_error"] = files.get("lr-apply.err", "")[-1500:] if apply_rc != "0" else ""
    if restored is None:
        verdict["restored_boot"] = "no report from the restored disk"
        verdict["passed"] = False
        return verdict
    facts = {}
    for line in restored.splitlines():
        for item in line.split():
            key, sep, value = item.partition("=")
            if sep:
                facts[key] = value
    verdict["restored"] = facts
    # The log window: everything synced before the restored member's backup
    # started, nothing begun after it ended.
    start = float(files.get(f"{window}.start", "0") or 0)
    end = float(files.get(f"{window}.end", "0") or 0)
    synced_before = begun_before_end = 0
    for line in files.get("lr-writer.timeline", "").splitlines():
        parts = line.split()
        if len(parts) == 4 and parts[0] == "S":
            started, synced = float(parts[2]), float(parts[3])
            synced_before += synced < start
            begun_before_end += started < end
    count = int(facts.get("count", "-1"))
    verdict["log_window"] = [synced_before, count, begun_before_end]
    verdict["passed"] = (
        backup_rc == "0"
        and member_ok
        and apply_rc == "0"
        and facts.get("multi_user") == "active"
        and facts.get("journal_recoveries") == "0"
        and facts.get("valid") == "True"
        and facts.get("torn") == "False"
        and synced_before <= count <= begun_before_end
    )
    return verdict


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cli", type=Path, required=True, help="the static linuxreflect CLI")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cache", type=Path,
                        default=Path.home() / ".cache/linuxreflect/vm-images")
    parser.add_argument("--only", action="append",
                        help="distribution:firmware, e.g. debian-12:uefi-sb")
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument("--keep", action="store_true", help="keep the run directories")
    parser.add_argument("--incremental", action="store_true",
                        help="add a live incremental member and restore the chain (series B3)")
    args = parser.parse_args()
    vm = load_vm_matrix()
    accel = ["-accel", "kvm", "-cpu", "host"] if vm.kvm_usable() else \
        ["-accel", "tcg,thread=multi", "-cpu", "max"]
    args.out.mkdir(parents=True, exist_ok=True)
    plan = [(d, f) for d, f in MATRIX if not args.only or f"{d}:{f}" in args.only]
    failures = 0
    for distribution, firmware in plan:
        label = f"{distribution}-{firmware}"
        base = vm.image(args.cache, distribution)
        run = Path(tempfile.mkdtemp(prefix=f"lr-s18-{label}-"))
        try:
            system = run / "system.qcow2"
            dest = run / "dest.qcow2"
            target = run / "target.img"
            subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", "-b", str(base),
                            "-F", "qcow2", str(system), DISK_SIZE], check=True)
            subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", str(dest), DISK_SIZE],
                           check=True)
            with open(target, "wb") as handle:
                handle.truncate(8 * 1024 ** 3)
            seed = seed_disk(run, label, args.cli,
                             "incremental" if args.incremental else "full")
            print(f"[{label}] first boot: live image and restore ({accel[1]})", flush=True)
            first, first_results, first_seconds = boot(
                [f"file={system},format=qcow2,if=virtio",
                 f"file={dest},format=qcow2,if=virtio",
                 f"file={target},format=raw,if=virtio",
                 f"file={seed},format=raw,if=virtio,readonly=on"],
                firmware, run, "first", args.timeout, accel)
            files = first_boot_results(first_results, first)
            restored = None
            second_seconds = 0.0
            if "error" not in files and files.get("lr-apply.rc", "").strip() == "0":
                print(f"[{label}] second boot: the restored disk alone", flush=True)
                second, second_results, second_seconds = boot(
                    [f"file={target},format=raw,if=virtio"],
                    firmware, run, "restored", args.timeout, accel)
                restored = between(second_results, "LR-RESTORED-BOOT-BEGIN",
                                   "LR-RESTORED-BOOT-END")
                if restored is None:
                    files["restored_serial_tail"] = second[-4000:]
            verdict = judge(files, restored, args.incremental) if "error" not in files else {
                "passed": False, **files, "qemu_exit": boot.last_exit}
            verdict.update(distribution=distribution, firmware=firmware,
                           first_boot_seconds=first_seconds,
                           restored_boot_seconds=second_seconds)
            (args.out / f"{label}.json").write_text(json.dumps(verdict, indent=2))
            if args.keep or not verdict["passed"]:
                (args.out / f"{label}-first.serial").write_text(first[-200000:])
                (args.out / f"{label}-first.result").write_text(first_results[-400000:])
            shown = ("tracked", "incremental", "restored", "log_window")
            print(f"[{label}] {'PASSED' if verdict['passed'] else 'FAILED'}: "
                  f"{json.dumps({k: verdict.get(k) for k in shown if k in verdict})}",
                  flush=True)
            failures += not verdict["passed"]
        finally:
            if not args.keep:
                shutil.rmtree(run, ignore_errors=True)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
