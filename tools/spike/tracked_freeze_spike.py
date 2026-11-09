#!/usr/bin/env python3
"""Phase 0 spike for the tracked-freeze provider (spec v2.2 §E.7).

This is not product code. It checks, on throwaway loop disks only, the
mechanism `docs/live-backup-plan.md` phase 0 asks about:

* the `block:block_bio_queue` tracepoint reports writes to a partition with
  the whole disk's device number and absolute sectors (after remapping);
* a write-tracked converging copy of a mounted, busy ext4 filesystem, ended
  by one short freeze during which only the remaining dirty chunks are read,
  equals the filesystem at the frozen instant (a full-compare audit reads
  every chunk under the freeze and compares it with the copy);
* `e2fsck -fn` is clean on the copy and an fsync'd hash-chained log in it is
  an exact prefix of what the writer wrote, ending inside the freeze window;
* the ftrace instance's overrun counters reveal lost events.

Run as root (it creates and removes its own loop devices and mounts):

    sudo python3 tools/spike/tracked_freeze_spike.py --json result.json

Nothing outside the temporary directory it creates is written.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import mmap
import os
import random
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

TRACEFS = Path("/sys/kernel/tracing")
CHUNK = 1 << 20
SECTOR = 512
FIFREEZE = 0xC0045877
FITHAW = 0xC0045878
EVENT = re.compile(
    r"block_bio_queue: (\d+),(\d+) (\S+) (\d+) \+ (\d+) \["
)
MARKER = re.compile(r"tracing_mark_write: LR-DRAIN-(\d+)")

WRITER = r"""
import hashlib, os, random, struct, sys, time
root, seconds, rate, blocks = sys.argv[1], float(sys.argv[2]), float(sys.argv[3]), int(sys.argv[4])
os.makedirs(root, exist_ok=True)
log = os.open(os.path.join(root, "chain.log"), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
data = os.open(os.path.join(root, "random.bin"), os.O_RDWR | os.O_CREAT, 0o644)
os.ftruncate(data, blocks * 4096)
prev = b"genesis"
seq = 0
end = time.monotonic() + seconds
interval = 1.0 / rate
churn = 0
while time.monotonic() < end:
    start = time.monotonic()
    digest = hashlib.sha256(prev + str(seq).encode()).hexdigest()
    line = f"{seq} {digest}\n".encode()
    os.write(log, line)
    os.fsync(log)
    synced = time.monotonic()
    print(f"S {seq} {start:.6f} {synced:.6f}", flush=True)
    prev = digest.encode()
    seq += 1
    for _ in range(4):
        index = random.randrange(blocks)
        version = seq
        header = struct.pack("<QQ", index, version)
        body = hashlib.sha256(header).digest() * 127
        block = (header + body)[:4096].ljust(4096, b"\0")
        os.pwrite(data, block, index * 4096)
    if seq % 50 == 0:
        os.fdatasync(data)
        churn += 1
        path = os.path.join(root, f"churn-{churn % 20}.tmp")
        with open(path, "wb") as handle:
            handle.write(os.urandom(64 * 1024))
        if churn % 3 == 0:
            os.unlink(path)
    remaining = interval - (time.monotonic() - start)
    if remaining > 0:
        time.sleep(remaining)
"""


def run(*args: str, check: bool = True, capture: bool = True) -> str:
    result = subprocess.run(
        args, check=False, text=True, capture_output=capture
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"{' '.join(args)} failed ({result.returncode}): {result.stderr.strip()}"
        )
    return result.stdout if capture else ""


def kernel_dev(major: int, minor: int) -> int:
    """The kernel-internal dev_t (MKDEV), as tracepoint filters compare it."""
    return (major << 20) | minor


@dataclass
class Disk:
    image: Path
    device: str = ""
    esp: str = ""
    data: str = ""
    data_start: int = 0  # sectors
    data_sectors: int = 0

    def attach(self) -> None:
        for _ in range(20):
            free = run("losetup", "-f").strip()
            if subprocess.run(["losetup", "-P", free, str(self.image)]).returncode == 0:
                self.device = free
                break
            time.sleep(0.2)
        else:
            raise RuntimeError("no free loop device")
        self.esp = f"{self.device}p1"
        self.data = f"{self.device}p2"
        name = Path(self.data).name
        sys_block = Path("/sys/class/block") / name
        # Without udev the partitions may need an explicit re-read.
        subprocess.run(["blockdev", "--rereadpt", self.device], capture_output=True)
        subprocess.run(["partx", "-a", self.device], capture_output=True)
        for _ in range(100):
            if (sys_block / "start").exists() and os.path.exists(self.data):
                break
            time.sleep(0.1)
        else:
            raise RuntimeError(f"{self.data} did not appear")
        self.data_start = int((sys_block / "start").read_text())
        self.data_sectors = int((sys_block / "size").read_text())

    def detach(self) -> None:
        if self.device:
            subprocess.run(["losetup", "-d", self.device])
            self.device = ""


class Trace:
    """A private ftrace instance on block_bio_queue for one disk."""

    def __init__(self, name: str, dev_filter: str, buffer_kb: int) -> None:
        self.dir = TRACEFS / "instances" / name
        self.dir.mkdir()
        (self.dir / "tracing_on").write_text("0")
        (self.dir / "buffer_size_kb").write_text(str(buffer_kb))
        event = self.dir / "events/block/block_bio_queue"
        (event / "filter").write_text(dev_filter)
        (event / "enable").write_text("1")
        (self.dir / "tracing_on").write_text("1")
        self.lock = threading.Lock()
        self.ranges: list[tuple[int, int, int, str]] = []  # (major,minor,sector,count/rwbs)
        self.events: list[tuple[int, int, str, int, int]] = []
        self.markers: set[int] = set()
        self.seen = threading.Condition(self.lock)
        self.stopped = False
        self.paused = threading.Event()
        self.pipe = open(self.dir / "trace_pipe", "r", buffering=1)
        self.thread = threading.Thread(target=self._consume, daemon=True)
        self.thread.start()
        self.marker_seq = 0

    def _consume(self) -> None:
        for line in self.pipe:
            while self.paused.is_set() and not self.stopped:
                time.sleep(0.05)
            match = EVENT.search(line)
            if match:
                major, minor, rwbs, sector, count = match.groups()
                with self.lock:
                    self.events.append(
                        (int(major), int(minor), rwbs, int(sector), int(count))
                    )
                continue
            marker = MARKER.search(line)
            if marker:
                with self.seen:
                    self.markers.add(int(marker.group(1)))
                    self.seen.notify_all()
            if self.stopped:
                break

    def take(self) -> list[tuple[int, int, str, int, int]]:
        with self.lock:
            events, self.events = self.events, []
        return events

    def drain(self, timeout: float = 10.0) -> None:
        """Wait until every event committed before this call was consumed."""
        self.marker_seq += 1
        seq = self.marker_seq
        (self.dir / "trace_marker").write_text(f"LR-DRAIN-{seq}\n")
        with self.seen:
            if not self.seen.wait_for(lambda: seq in self.markers, timeout):
                raise RuntimeError("the trace consumer did not reach the drain marker")

    def losses(self) -> dict[str, int]:
        totals = {"overrun": 0, "dropped events": 0, "commit overrun": 0}
        for stats in sorted((self.dir / "per_cpu").glob("cpu*/stats")):
            for line in stats.read_text().splitlines():
                key, _, value = line.partition(":")
                key = key.strip()
                if key in totals:
                    totals[key] += int(value.strip().split()[0])
        return totals

    def close(self) -> None:
        # Wake the consumer with a marker while tracing is still on, so it
        # leaves trace_pipe before the instance is removed.
        self.stopped = True
        self.paused.clear()
        try:
            (self.dir / "trace_marker").write_text("LR-DRAIN-0\n")
        except OSError:
            pass
        self.thread.join(timeout=5)
        try:
            (self.dir / "tracing_on").write_text("0")
            (self.dir / "events/block/block_bio_queue/enable").write_text("0")
        except OSError:
            pass
        try:
            self.pipe.close()
        except OSError:
            pass
        for _ in range(20):
            try:
                self.dir.rmdir()
                return
            except OSError:
                time.sleep(0.1)


def is_dirtying(rwbs: str, count: int) -> bool:
    """Every operation that can change data: anything but reads and flushes."""
    if count == 0:
        return False
    op = rwbs[1:] if rwbs.startswith("F") and len(rwbs) > 1 else rwbs
    return not op.startswith("R")


def chunks_of(events, disk: Disk, whole: tuple[int, int], part: tuple[int, int],
              total_chunks: int) -> set[int]:
    """Dirty chunks of the data partition. Events normally name the whole
    disk with absolute sectors; one naming the partition is shifted."""
    dirty: set[int] = set()
    start = disk.data_start
    end = disk.data_start + disk.data_sectors
    for ev_major, ev_minor, rwbs, sector, count in events:
        if not is_dirtying(rwbs, count):
            continue
        if (ev_major, ev_minor) == part:
            sector += start
        elif (ev_major, ev_minor) != whole:
            continue
        lo = max(sector, start)
        hi = min(sector + count, end)
        if lo >= hi:
            continue
        first = ((lo - start) * SECTOR) // CHUNK
        last = ((hi - start) * SECTOR - 1) // CHUNK
        dirty.update(range(first, min(last, total_chunks - 1) + 1))
    return dirty


def freeze(mountpoint: Path) -> int:
    fd = os.open(mountpoint, os.O_RDONLY | os.O_DIRECTORY)
    fcntl.ioctl(fd, FIFREEZE, 0)
    return fd


def thaw(fd: int) -> None:
    fcntl.ioctl(fd, FITHAW, 0)
    os.close(fd)


class Reader:
    def __init__(self, device: str) -> None:
        self.fd = os.open(device, os.O_RDONLY | os.O_DIRECT)
        self.buf = mmap.mmap(-1, CHUNK)

    def chunk(self, index: int, size: int) -> bytes:
        length = min(CHUNK, size - index * CHUNK)
        aligned = (length + 4095) // 4096 * 4096
        view = memoryview(self.buf)[:aligned]
        got = os.preadv(self.fd, [view], index * CHUNK)
        view.release()
        return bytes(self.buf[: min(got, length)])

    def close(self) -> None:
        os.close(self.fd)
        self.buf.close()


@dataclass
class Result:
    scenario: str
    kernel: str = os.uname().release
    tracepoint_format: str = ""
    root_freeze: dict = field(default_factory=dict)
    mapping: dict = field(default_factory=dict)
    passes: list = field(default_factory=list)
    freeze_ms: float = 0.0
    barrier_ms: float = 0.0
    final_dirty_chunks: int = 0
    audit_mismatches: int = -1
    audit_ms: float = 0.0
    losses: dict = field(default_factory=dict)
    e2fsck_clean: bool = False
    e2fsck_output: str = ""
    log_prefix: dict = field(default_factory=dict)
    converged: bool = False
    notes: list = field(default_factory=list)


def mapping_check(disk: Disk, trace: Trace, disk_rdev, part_rdev) -> dict:
    """Write 4 KiB at 1 MiB into the (unformatted) data partition and see how
    the tracepoint reports it."""
    payload = mmap.mmap(-1, 4096)
    payload.write(b"\xa5" * 4096)
    fd = os.open(disk.data, os.O_WRONLY | os.O_DIRECT)
    os.pwritev(fd, [payload], CHUNK)
    os.fsync(fd)
    os.close(fd)
    payload.close()
    trace.drain()
    events = trace.take()
    writes = [e for e in events if is_dirtying(e[2], e[4])]
    expected_abs = disk.data_start + CHUNK // SECTOR
    return {
        "disk": f"{os.major(disk_rdev)},{os.minor(disk_rdev)}",
        "partition": f"{os.major(part_rdev)},{os.minor(part_rdev)}",
        "events": [f"{a},{b} {c} {d} + {e}" for a, b, c, d, e in writes],
        "absolute_sector_on_disk": any(
            (e[0], e[1]) == (os.major(disk_rdev), os.minor(disk_rdev))
            and e[3] == expected_abs
            and e[4] == 8
            for e in writes
        ),
        "partition_relative": any(e[3] == CHUNK // SECTOR for e in writes),
    }


def check_log(mounted: Path, writer_lines: list[str], frozen_at: float, thawed_at: float) -> dict:
    text = (mounted / "work/chain.log").read_text()
    lines = text.splitlines()
    prev = b"genesis"
    valid = 0
    for expected, line in enumerate(lines):
        seq_text, _, digest = line.partition(" ")
        if int(seq_text) != expected:
            break
        want = hashlib.sha256(prev + seq_text.encode()).hexdigest()
        if digest != want:
            break
        prev = digest.encode()
        valid += 1
    torn_tail = not text.endswith("\n") if text else False
    records = []
    for line in writer_lines:
        if line.startswith("S "):
            _, seq, started, synced = line.split()
            records.append((int(seq), float(started), float(synced)))
    synced_before = [seq for seq, _, synced in records if synced < frozen_at]
    started_after = [seq for seq, started, _ in records if started > thawed_at]
    low = max(synced_before) + 1 if synced_before else 0
    high = min(started_after) if started_after else len(records)
    return {
        "records_in_copy": len(lines),
        "valid_chain": valid == len(lines),
        "torn_tail": torn_tail,
        "must_contain_at_least": low,
        "may_contain_at_most": high,
        "prefix_inside_freeze_window": valid == len(lines)
        and low <= len(lines) <= high
        and not torn_tail,
    }


def scenario(args, name: str, *, writer_rate: float, buffer_kb: int, audit: bool,
             trim: bool, slow_consumer: bool, max_passes: int,
             bulk_mib: int = 0) -> Result:
    result = Result(scenario=name)
    work = Path(tempfile.mkdtemp(prefix="lr-tf-spike-", dir=args.workdir))
    disk = Disk(image=work / "disk.img")
    mnt = work / "mnt"
    mnt.mkdir()
    copy = work / "copy.img"
    trace = None
    writer = None
    bulk = None
    mounted = False
    try:
        with open(disk.image, "wb") as handle:
            handle.truncate(args.size_mib * 1024 * 1024)
        # sfdisk (util-linux) is on every target; sgdisk is not.
        layout = (
            "label: gpt\n"
            "start=2048, size=64MiB, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B\n"
            "type=0FC63DAF-8483-4772-8E79-3D69D8477DE4\n"
        )
        subprocess.run(["sfdisk", "-q", str(disk.image)], input=layout, text=True,
                       check=True, capture_output=True)
        disk.attach()
        disk_rdev = os.stat(disk.device).st_rdev
        part_rdev = os.stat(disk.data).st_rdev
        dev_filter = (
            f"dev == {kernel_dev(os.major(disk_rdev), os.minor(disk_rdev))} || "
            f"dev == {kernel_dev(os.major(part_rdev), os.minor(part_rdev))}"
        )
        trace = Trace(f"lr-spike-{os.getpid()}-{name}", dev_filter, buffer_kb)
        result.tracepoint_format = (
            TRACEFS / "events/block/block_bio_queue/format"
        ).read_text()
        result.mapping = mapping_check(disk, trace, disk_rdev, part_rdev)

        run("mkfs.ext4", "-q", "-F", disk.data)
        run("mount", disk.data, str(mnt))
        mounted = True
        size = disk.data_sectors * SECTOR
        total_chunks = (size + CHUNK - 1) // CHUNK
        whole = (os.major(disk_rdev), os.minor(disk_rdev))
        part = (os.major(part_rdev), os.minor(part_rdev))

        writer = subprocess.Popen(
            [sys.executable, "-c", WRITER, str(mnt / "work"), str(args.seconds),
             str(writer_rate), "4096"],
            stdout=subprocess.PIPE, text=True,
        )
        if bulk_mib:
            # A second, heavy writer: rewrite a file of bulk_mib MiB in a loop.
            bulk = subprocess.Popen(
                ["sh", "-c",
                 f"while :; do dd if=/dev/zero of={mnt}/bulk.bin bs=1M "
                 f"count={bulk_mib} conv=fsync status=none; done"],
            )
        writer_lines: list[str] = []
        reader_thread = threading.Thread(
            target=lambda: writer_lines.extend(writer.stdout), daemon=True
        )
        reader_thread.start()
        time.sleep(1.0)
        if slow_consumer:
            # Starve the consumer so the per-CPU buffers overflow.
            trace.paused.set()

        trace.take()
        began = time.monotonic()
        fd = freeze(mnt)
        thaw(fd)
        result.barrier_ms = (time.monotonic() - began) * 1000

        reader = Reader(disk.data)
        out = os.open(copy, os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o600)
        os.ftruncate(out, size)
        pending = set(range(total_chunks))
        trimmed = False
        for number in range(1, max_passes + 1):
            started = time.monotonic()
            for index in sorted(pending):
                os.pwrite(out, reader.chunk(index, size), index * CHUNK)
                if trim and not trimmed and index > total_chunks // 2:
                    run("fstrim", str(mnt), check=False)
                    trimmed = True
            if not slow_consumer:
                trace.drain()
            pending = chunks_of(trace.take(), disk, whole, part, total_chunks)
            result.passes.append({
                "pass": number,
                "chunks_read": len(pending) if number > 1 else total_chunks,
                "seconds": round(time.monotonic() - started, 3),
                "dirty_after": len(pending),
            })
            if len(pending) * CHUNK <= args.final_max_mib * 1024 * 1024:
                result.converged = True
                break

        # Final read under one freeze: only the dirty chunks, into memory.
        frozen_at = time.monotonic()
        fd = freeze(mnt)
        if not slow_consumer:
            trace.drain()
        pending |= chunks_of(trace.take(), disk, whole, part, total_chunks)
        final = {index: reader.chunk(index, size) for index in sorted(pending)}
        read_done = time.monotonic()
        mismatches = -1
        if audit:
            for index, data in final.items():
                os.pwrite(out, data, index * CHUNK)
            mismatches = 0
            audit_start = time.monotonic()
            for index in range(total_chunks):
                live = reader.chunk(index, size)
                if os.pread(out, len(live), index * CHUNK) != live:
                    mismatches += 1
            result.audit_ms = (time.monotonic() - audit_start) * 1000
        thaw(fd)
        thawed_at = time.monotonic()
        result.freeze_ms = (read_done - frozen_at) * 1000
        result.final_dirty_chunks = len(final)
        result.audit_mismatches = mismatches
        for index, data in final.items():
            os.pwrite(out, data, index * CHUNK)
        os.fsync(out)
        os.close(out)
        reader.close()
        result.losses = trace.losses()

        if bulk:
            bulk.kill()
            bulk.wait()
        writer.wait(timeout=args.seconds + 60)
        reader_thread.join(timeout=5)

        fsck = subprocess.run(["e2fsck", "-fn", str(copy)], text=True, capture_output=True)
        result.e2fsck_clean = fsck.returncode == 0
        result.e2fsck_output = (fsck.stdout + fsck.stderr)[-2000:]
        check_mnt = work / "check"
        check_mnt.mkdir()
        try:
            run("mount", "-o", "ro,loop", str(copy), str(check_mnt))
        except RuntimeError as error:
            # A copy whose journal still needs recovery is not the frozen
            # state: FIFREEZE leaves the journal clean.
            result.log_prefix = {"copy_mount_failed": str(error)[-300:]}
        else:
            try:
                result.log_prefix = check_log(check_mnt, writer_lines, frozen_at, thawed_at)
            finally:
                run("umount", str(check_mnt), check=False)
    finally:
        if bulk and bulk.poll() is None:
            bulk.kill()
            bulk.wait()
        if writer and writer.poll() is None:
            writer.kill()
        if trace:
            trace.close()
        if mounted:
            run("umount", str(mnt), check=False)
        disk.detach()
        shutil.rmtree(work, ignore_errors=True)
    return result


def root_freeze_probe(hold: float) -> dict:
    """Freeze `/` for `hold` seconds with a deadman armed, then check that the
    system still works. Only inside a throwaway VM: never on a workstation."""
    virt = subprocess.run(["systemd-detect-virt"], capture_output=True, text=True)
    kind = virt.stdout.strip()
    if kind in ("", "none", "wsl") or "container" in kind:
        raise RuntimeError(f"refusing to freeze / outside a VM (systemd-detect-virt: {kind!r})")
    unit = f"lr-spike-thaw-{os.getpid()}"
    run("systemd-run", "--on-active=30", f"--unit={unit}", "--quiet", "fsfreeze", "-u", "/")
    # Nothing below writes to / until the thaw: no prints, no logging.
    began = time.monotonic()
    fd = freeze(Path("/"))
    frozen = time.monotonic()
    time.sleep(hold)
    thaw(fd)
    thawed = time.monotonic()
    run("systemctl", "stop", f"{unit}.timer", check=False)
    state = subprocess.run(["systemctl", "is-system-running"], capture_output=True, text=True)
    tag = f"lr-spike-{os.getpid()}"
    subprocess.run(["logger", "-t", tag, "after-thaw"])
    time.sleep(2)
    journal = subprocess.run(["journalctl", "-t", tag, "--no-pager", "-q"],
                             capture_output=True, text=True)
    logind = subprocess.run(["loginctl", "list-sessions", "--no-legend"],
                            capture_output=True, text=True)
    return {
        "virt": kind,
        "freeze_ioctl_ms": round((frozen - began) * 1000, 1),
        "held_ms": round((thawed - frozen) * 1000, 1),
        "system_state_after": state.stdout.strip(),
        "journal_after_thaw": "after-thaw" in journal.stdout,
        "logind_answers": logind.returncode == 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--workdir", default="/var/tmp")
    parser.add_argument("--size-mib", type=int, default=2048)
    parser.add_argument("--seconds", type=float, default=40.0)
    parser.add_argument("--final-max-mib", type=int, default=64)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--only", help="run one scenario by name")
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--vm-root-freeze", type=float, default=0.0,
                        help="inside a throwaway VM only: also freeze / for this many seconds")
    args = parser.parse_args()
    if os.geteuid() != 0:
        print("run as root: the spike creates loop devices and mounts", file=sys.stderr)
        return 2
    if not (TRACEFS / "events/block/block_bio_queue").is_dir():
        print("block:block_bio_queue is not available on this kernel", file=sys.stderr)
        return 2
    plans = {
        "busy-writer-audit": dict(writer_rate=400, buffer_kb=16384, audit=True,
                                  trim=False, slow_consumer=False, max_passes=10),
        "busy-writer-trim-audit": dict(writer_rate=400, buffer_kb=16384, audit=True,
                                       trim=True, slow_consumer=False, max_passes=10),
        "no-audit-freeze-length": dict(writer_rate=400, buffer_kb=16384, audit=False,
                                       trim=False, slow_consumer=False, max_passes=10),
        "bulk-writer-audit": dict(writer_rate=400, buffer_kb=16384, audit=True,
                                  trim=False, slow_consumer=False, max_passes=10,
                                  bulk_mib=256),
        "overrun-detected": dict(writer_rate=2000, buffer_kb=4, audit=False,
                                 trim=False, slow_consumer=True, max_passes=2),
    }
    results = []
    if args.vm_root_freeze:
        probe = root_freeze_probe(args.vm_root_freeze)
        print(json.dumps({"root_freeze": probe}, indent=2), flush=True)
        results.append({"scenario": "root-freeze-probe", "kernel": os.uname().release,
                        "root_freeze": probe})
    for name, plan in [(n, p) for n, p in plans.items() for _ in range(args.repeat)]:
        if args.only and name != args.only:
            continue
        print(f"== {name}", flush=True)
        outcome = scenario(args, name, **plan)
        summary = {k: v for k, v in outcome.__dict__.items() if k != "e2fsck_output"}
        print(json.dumps(summary, indent=2), flush=True)
        if not outcome.e2fsck_clean:
            print(outcome.e2fsck_output, flush=True)
        results.append(outcome.__dict__)
    if args.json:
        args.json.write_text(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
