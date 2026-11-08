# Live backup plan: running Debian and Ubuntu systems on ext4

Status, 2026-11-08: phase 0 is done (`docs/live-backup-spike.md`: the
mechanism holds on kernels 5.15 to 6.18), phase 1 is done
(`lr_snapshot::tracking`), and phase 2 is done except incremental members
(refused for now), and phase 3 is done: whole disks with the root
filesystem, a vfat ESP and other unfrozen regions under the quiet-window
rule are copied live with `--snapshot tracked-freeze`, writes are tracked on
submission and on completion, dpkg's lock postpones the final freeze and a
logind inhibitor blocks sleep, and the VM acceptance passed on Debian 12,
Debian 13, Ubuntu 22.04 and Ubuntu 24.04, UEFI with Secure Boot and BIOS
(`docs/live-backup-acceptance.md`: each running system imaged live, restored
onto another disk, and booted from it alone; re-run on `1986503` with the 3 s
budget). Phase 4 has begun: the
restore plan names an attached disk that shares the copy's UUIDs (CLI and
GUI), the operator guide describes tracked-freeze, and `--freeze-max` is its
own option (it had been taken from the freeze provider's `--freeze-timeout`,
whose 300 s default stretched the final-freeze budget to the 30 s cap); only
passes that do not shrink the dirty set count against `max_passes`, as §E.7
says; the pre-freeze and post-thaw hooks run (D-140); the daemon and every
tracked job sweep leftover trace instances of dead processes; and the
convergence budget uses the reads' own rate. Still open: incremental
members, the rest of phase 4 (`PlanBackup`, the wizard, the
GUI acceptance) and phase 5. It implements spec v2.2 §E.7 and Slice 18
(decision D-138).

## Goal

Back up a running Debian or Ubuntu system disk (ext4 root on a plain
partition, an ESP, optionally `/boot`, swap and a BIOS boot partition)
while it is in use, restore the image onto another disk, and boot that disk.
The source system is never written to, its boot chain is never changed, and no
kernel module is installed.

Debian and Ubuntu install exactly this layout by default, so this is the
common case. LVM installs already get point-in-time images (§E.2), and Btrfs
gets Stream images (§E.1).

## What already exists

These parts are reused unchanged:

- whole-disk images with the partition table, the leading region (GRUB
  `core.img`), swap headers and per-partition sub-manifests (S7), restored
  disks that boot under SeaBIOS and under OVMF with Secure Boot (S7, S16,
  S17);
- the ext4 used-block map (`dumpe2fs`, §F) and the `O_DIRECT` block source
  (`lr-blocksource`);
- the freeze provider's layered deadman (a `systemd-run` timer plus a
  detached helper) and ring-buffer logging while frozen (§E.4, R28);
- exclusive device claims and target re-validation on restore (D-117, §H.2);
- the `PlanBackup` review in the daemon and the GUI (D-136).

## The approach: tracked-freeze

Linux has no VSS, and stock device-mapper cannot slide a snapshot under a
filesystem that is already mounted (§A.1). Tracked-freeze gets the same result
for ext4 without a snapshot:

1. Start recording every write the block layer submits to the source disk,
   through a private ftrace instance on `block:block_bio_queue`.
2. Freeze and immediately thaw each filesystem once (the barrier), so no
   write submitted before tracing started can still land.
3. Copy all used blocks while the system keeps running (`O_DIRECT`).
4. Re-copy the chunks written meanwhile, pass after pass, until what is left
   is small.
5. Freeze the filesystems, read the last dirty chunks into memory, and thaw.
   The freeze lasts for that read only, typically well under a second and at
   most `freeze_max` (default 3 s). Nothing is written while frozen.
6. Write the last chunks, check that tracking lost nothing, and publish.

The image is the filesystem exactly as `FIFREEZE` left it at that instant,
with its journal flushed: the state an LVM snapshot captures. It is reported
as `Frozen`, never as a snapshot. The normative argument is in spec §E.7.

Precedent: the QEMU guest agent freezes every mounted filesystem, `/`
included, while a hypervisor takes a snapshot, and QEMU's drive-mirror makes
a converging copy of a disk that is being written. Tracked-freeze combines
the two inside the guest.

### Rejected alternatives

| Option | Why not |
|---|---|
| `blksnap` (Veeam) or `dattobd` kernel module | Out-of-tree code in the root I/O path, rebuilt by DKMS on every kernel update, MOK enrolment under Secure Boot. A module bug can corrupt or hang the running system. |
| Managed DM layer (`lr-dmwrap`) | Changes the boot chain (initramfs, kernel command line, udev identity of the root partition). A mistake leaves a system that does not boot. |
| Freeze `/` for the whole read (§E.4) | Every writer blocks for minutes; a desktop or server stalls. |
| `live-none` | Torn blocks; not consistent. |
| File-mode system backup | Per-file consistency only, and the restore must recreate the layout and reinstall the bootloader. It stays the fallback for smaller target disks (see Later). |
| Rescue medium (offline) | Needs a reboot, but is always available and stays the fallback. |

## Risks and their controls

Every control has a test in Slice 18 (spec §K S18, letters refer to its AC).

| # | Risk | Control | Test |
|---|---|---|---|
| 1 | A missed write gives a silently inconsistent image (the worst outcome) | Tracing starts before the barrier; a loop-device self-test runs before each job; per-CPU `overrun`/`dropped events` must stay zero, else `E_TRACKING_LOST` and nothing is published; discards and write-zeroes count as writes | (b) with a full-compare audit: in root tests, every chunk is re-read under the freeze and compared with the image; (b) log-prefix check under a heavy writer and `fstrim`; (c) forced overrun |
| 2 | The root freeze stalls the system | Freeze only for the final read, into memory; `freeze_max` default 3 s, hard cap 30 s, then thaw first and abort; the external deadman thaws even if the daemon is killed; nothing is written and nothing is logged to journald while frozen | (c) SIGKILL during the freeze; (c) exceeded `freeze_max`; (d) measured freeze in the VM matrix |
| 3 | The job writes to a frozen filesystem and deadlocks | Destination, spool and every job file must be on another filesystem and another device (`st_dev` and holder checks), checked before tracing starts | (c) destination on the source filesystem is refused |
| 4 | Buffered reads return stale block-device cache pages | `O_DIRECT` for every source read, asserted by the provider | (b) full-compare audit; a unit test on the open flags |
| 5 | A busy system never converges | Pass budget (`max_passes` 10, `final_max` 256 MiB, a throughput-based target); abort with `E_NO_CONVERGENCE` and the options; never degrade to `None` | (c) writer faster than the budget |
| 6 | A package upgrade is caught half-done and the copy does not boot | Postpone the final freeze while the dpkg lock is held (inspected with `F_OFD_GETLK`, never taken); abort after the pass budget | A root test that holds `lock-frontend` during the run |
| 7 | The ESP (vfat, cannot be frozen) changes during the copy | Quiet-window rule: its dirty set must stay empty from its last read until the thaw, else abort (or `None` for that partition with `--allow-inconsistent`) | A root test that writes to the ESP mid-run |
| 8 | The disk changes shape mid-job (`parted`, `resize2fs`) | Partition-table hash and filesystem UUID and block count rechecked after the thaw; `E_SOURCE_CHANGED` | (c) partition table changed mid-job |
| 9 | Kernel differences: tracepoint layout, missing tracefs, lockdown | The parser reads the event's `format` file; the probe runs the self-test; under `lockdown=confidentiality` tracefs is unavailable and the probe says so (`integrity`, which Debian and Ubuntu use with Secure Boot, allows it) | (e) probe on a kernel without the tracepoint; phase 0 matrix |
| 10 | Suspend or shutdown in the middle of a freeze | logind inhibitor lock (`sleep:shutdown`, block) for the job | A unit test on the inhibitor call; manual check in the VM matrix |
| 11 | A daemon crash leaves an ftrace instance or a frozen filesystem | `Drop` teardown; the deadman for freezes; a start-up sweep removes `instances/lr-*` | A root test that kills the daemon mid-pass and restarts it |
| 12 | Backup I/O makes the live system sluggish | Idle I/O priority for the passes; an optional rate limit | Measured in phase 0 and the VM matrix |
| 13 | Restoring to a second disk of the same machine duplicates UUIDs, so the next boot may mix disks | The restore plan and the GUI say so and require detaching the source or choosing the copy in firmware; a "new identity" restore is later work | A unit test on the plan text; a VM case that boots with only the copy attached |
| 14 | An unsupported layout (LUKS, md, dm between ext4 and the disk) | `Support::No` with the reason; the LVM, offline or file-mode routes stay available | Probe unit tests on sysfs fixtures |

## Phases

Each phase is its own pull request, lands with its tests written first, and
keeps `cargo xtask ci` and `cargo xtask root` green.

### Phase 0 — Spike in VMs (no product code)

Validate the mechanism before writing the provider:

- run a throwaway script in Debian 12 (6.1), Debian 13 (6.12), Ubuntu 22.04
  (5.15) and Ubuntu 24.04 (6.8) VMs: confirm the tracepoint's fields and that
  sectors are absolute disk sectors after partition remapping, on virtio and
  NVMe;
- measure overruns at 16 MiB per CPU under a desktop and a database
  workload, the number of passes to converge, and the length of the final
  freeze on SSD and HDD;
- confirm that `FIFREEZE` on `/` with the deadman armed leaves journald,
  logind and a GNOME session working after the thaw.

Exit: a short report in `docs/` with the numbers and the tracepoint choice.
If the mechanism does not hold, stop here and revisit D-138.

### Phase 1 — Tracking primitives

- `lr-unsafe`/`lr-core`: a safe tracefs instance type (create, size, filter,
  enable, read `trace_pipe`, read the per-CPU stats, remove in `Drop`), an
  event parser driven by the `format` file, and a dirty-range set mapped to
  partitions and chunks;
- the probe and the loop-device self-test;
- unit and fixture tests on recorded trace samples (AC a).

No behaviour change; nothing selects the provider yet.

### Phase 2 — One ext4 partition, not the root

- `lr-snapshot`: the tracked-freeze provider for a single mounted ext4
  partition: barrier, passes, final freeze into memory, deadman reuse,
  integrity checks, teardown and start-up sweep;
- `lr-engine`: superseding chunk records in one image; confirm that `verify`
  and restore use only the records the manifest references (no format change,
  §E.7);
- CLI `--snapshot tracked-freeze`, `--freeze-max`; the new errors;
- root tests on owned loop disks (AC b, c), including the full-compare audit.

### Phase 3 — The root filesystem and the whole disk

- freeze every tracked filesystem of the disk together, root last;
- the ESP quiet-window rule, the dpkg-lock postponement, the logind inhibitor;
- allow whole-disk reads when every filesystem partition is tracked-freeze
  (D-138 amends D-136);
- VM acceptance (AC d): Debian 12, Debian 13, Ubuntu 22.04 and Ubuntu 24.04
  on plain ext4, UEFI with Secure Boot for all and BIOS for one Debian and one
  Ubuntu; live whole-disk image of the running system disk to a second disk,
  restore to a third, boot only the third, `multi-user.target`, clean fsck,
  log-prefix check, `Frozen` for root, freeze within `freeze_max`.

The VM harness reuses the qemu boot helpers of the S16/S17 root suites; the
guest images are the distributions' official cloud images, which use plain
ext4 with an ESP and a BIOS boot partition.

### Phase 4 — Daemon, GUI and documentation

- `PlanBackup` predicts tracked-freeze and shows the freeze budget; the
  wizard offers it for a running system disk instead of refusing; the report
  shows passes, re-copied bytes and the freeze length;
- the restore plan's duplicate-UUID warning in the CLI and the GUI;
- the operator guide: what tracked-freeze guarantees, what it does not
  (application consistency needs hooks), and the fallbacks;
- GUI acceptance in a VM: back up the running system from the GUI, restore it
  from the rescue medium to another disk, boot it.

### Phase 5 — Field trial and the default

Ship tracked-freeze as opt-in in a pre-release, collect freeze lengths, pass
counts and refusals, and decide spec §M.4 (whether plain `auto` selects it).

## Release gate for Slice 18

- `cargo xtask ci` exits 0;
- `cargo xtask root` passes with no unavailable scenario, including the new
  suites, with nothing left behind;
- the VM matrix of phase 3 passes on all four distributions;
- `cargo xtask scale` stays within its budgets.

## Out of scope for Slice 18

LUKS-encrypted or md roots, xfs or Btrfs on plain partitions (Btrfs has its
own provider), restoring to a smaller disk, a "new identity" restore that
rewrites UUIDs, and cross-hardware restores (§H.5).

## Later

- **File-mode system backup** for smaller or differently laid-out target disks:
  record the layout (`sfdisk -d`), the filesystem UUIDs and labels, `fstab`
  and the firmware type with a file-mode backup of `/`, `/boot` and the ESP,
  then recreate the layout (`recreate-layout`, D-105), restore the files and
  reinstall the bootloader (`boot-repair`, §H.5) on the target. The building
  blocks exist from S12 and S16; the orchestration and the boot acceptance do
  not.
- **New identity restore**: new partition and filesystem UUIDs on the copy,
  with `fstab`, GRUB and the initramfs regenerated in a chroot.
- **xfs** through the same provider, with its own acceptance.
