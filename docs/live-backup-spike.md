# Live backup spike: tracked-freeze phase 0 results

Phase 0 of `docs/live-backup-plan.md`, run on 2026-11-08. It validates the
tracked-freeze mechanism of spec v2.2 §E.7 before product code relies on it.
The tools are `tools/spike/tracked_freeze_spike.py` (one machine, root, loop
disks it creates) and `tools/spike/vm_matrix.py` (the official cloud images
of each target distribution under qemu, with the spike run inside by
cloud-init).

**Outcome: the mechanism holds; continue with phases 1 and 2.** Two changes
follow from the results: a `syncfs` before every freeze, and a journal check
in the acceptance tests (both below).

## What each run does

On an ext4 filesystem on a GPT partition of a loop disk, mounted and kept busy
by a writer (an fsync'd hash-chained log, random 4 KiB overwrites, file churn;
some scenarios add `fstrim` or a second writer rewriting 256 MiB in a loop):

1. start a private ftrace instance on `block:block_bio_queue`, filtered by
   device number only;
2. freeze and thaw the filesystem once (the barrier);
3. copy every chunk with `O_DIRECT`, then re-copy the 1 MiB chunks written
   meanwhile until at most 64 MiB are dirty (10 passes at most);
4. freeze, drain the trace to a marker, read the remaining dirty chunks, thaw;
5. **audit** (most scenarios): before the thaw, read every chunk again and
   compare it with the copy;
6. check the copy with `e2fsck -fn`, mount it read-only and check that the log
   is an exact prefix of what the writer wrote, ending inside the freeze.

A further scenario starves the trace consumer to see whether the per-CPU
overrun counters reveal lost events. Inside VMs only, a probe also freezes the
VM's own `/` for one second with a deadman armed.

## Kernels and the tracepoint

| Where | Kernel | Accel. |
|---|---|---|
| WSL 2 (development machine) | 6.18.58.1-microsoft-standard-WSL2 | native |
| Debian 12 genericcloud | 6.1.0-54-cloud-amd64 | TCG |
| Debian 13 genericcloud | 6.12.115+deb13.1-cloud-amd64 | TCG |
| Ubuntu 22.04 cloud image | 5.15.0-203-generic | TCG |
| Ubuntu 24.04 cloud image | 6.8.0-147-generic | TCG |
| Ubuntu 22.04 test host (VMware, GNOME on Wayland) | 6.8.0-138-generic | native |

On every kernel the event has the same fields and the same print format,
`"%d,%d %s %llu + %u [%s]"` with 20 minor bits, and a write to a partition is
reported with the **whole disk's** device number and the **absolute** sector
(for example `7,0 WS 135168 + 8` for 4 KiB at 1 MiB into a partition starting
at sector 133120). Recorded lines (`crates/lr-snapshot/tests/fixtures/trace`)
also show that write-zeroes arrives with the operation letter `N`, not `W` or
`D`: a filter that kept only writes and discards would have missed it.

**Choice:** `block:block_bio_queue`, filtered by device number only, with
every operation except reads and data-less flushes counted as dirtying. This
is what `lr_snapshot::tracking` implements.

## Correctness

| Where | Audited runs | Chunk mismatches | `e2fsck` | Log prefix |
|---|---|---|---|---|
| WSL 6.18 | 9 | 0 | clean | inside the freeze |
| Debian 12 | 3 | 0 | clean | inside the freeze |
| Debian 13 | 3 | 0 | clean | inside the freeze |
| Ubuntu 22.04 VM | 3 | 0 | clean | inside the freeze |
| Ubuntu 24.04 VM | 3 | 0 | clean | inside the freeze |
| Ubuntu 22.04 host | 3 | 0 | clean | inside the freeze |

24 audited runs, every chunk of every copy equal to the filesystem at the
frozen instant. The non-audited runs passed the same `e2fsck` and log checks.

**Lost events are detected, and they matter.** With the consumer starved the
overrun counters read 1620–3601 on every kernel. Those copies were really
broken: the kernel refused to mount them read-only because the journal still
needed recovery, which a copy of a frozen filesystem never does. In one of
them `e2fsck -fn` still exited 0, because `-n` does not replay a journal, so
**the acceptance tests also check that `needs_recovery` is clear** (spec
Slice 18 AC (b)).

## Freeze lengths and convergence

The final freeze is measured from the `FIFREEZE` call to the end of the reads
under it. TCG emulates the CPU and the disk, so its numbers are pessimistic;
the native rows are the representative ones.

| Where | Busy writer | Busy writer + `fstrim` | Heavy writer (256 MiB loop) |
|---|---|---|---|
| WSL 6.18 | 1 pass, 173–268 ms | 2 passes, 161–235 ms | no convergence to 64 MiB in 10 passes; 0.64–1.8 s for the rest |
| Ubuntu host (VMware) | 1 pass, 71 ms; 751 ms in an audited run | 2 passes, 108 ms | 2 passes, 862 ms |
| VMs (TCG) | 1 pass, 0.6–3.0 s | 2 passes, 0.44–0.66 s | 3–6 passes, 1.2–4.1 s |

A writer that rewrites data at disk speed can keep the copy from converging;
the budgets of spec §E.7 (`max_passes`, `final_max`, and the estimate against
`freeze_max`) end such a job with `E_NO_CONVERGENCE` instead of a long freeze.

## Freezing the running root

| Where | `FIFREEZE` on `/` | Held | After the thaw |
|---|---|---|---|
| Debian 12 VM | 162 ms | 1.0 s | journald writes, logind answers |
| Debian 13 VM | 172 ms | 1.0 s | journald writes, logind answers |
| Ubuntu 22.04 VM | **29 340 ms** | 1.0 s | journald writes, logind answers |
| Ubuntu 24.04 VM | 198 ms | 1.0 s | journald writes, logind answers |
| Ubuntu 22.04 host | 117 ms | 1.0 s | journald, logind; GNOME Shell kept its PID and answered a D-Bus ping |

`FIFREEZE` blocks new writes first and then writes back every dirty page.
The Ubuntu 22.04 VM was still writing heavily at the end of its boot (cloud-init
and snap seeding under TCG), so entering the freeze took 29 s, during which
writers on `/` were blocked. **Every freeze is therefore preceded by a
`syncfs`, which writes the dirty pages back without blocking anyone**, so the
freeze itself has little left to write (spec §E.7 steps 3 and 6; implemented
in `lr_snapshot::tracked_freeze`).

The VMs report `systemctl is-system-running` as `starting` because cloud-init
was still running; the host reports `degraded` because two VirtualBox units
fail on that VMware machine since boot. Neither is caused by the freeze.

## What phase 0 does not show

- Real disks: the native rows are a loop device on WSL and a VMware virtual
  disk. HDD timings are not measured.
- A full desktop under a long freeze: only one-second freezes were held.
- Whole disks and several filesystems frozen together (phase 3).
