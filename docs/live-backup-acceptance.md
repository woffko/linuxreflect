# Live backup acceptance: a running system imaged, restored, booted

Slice 18 acceptance criterion (d) (spec v2.2 §K), run on 2026-11-08 with
`tools/vm/live_restore_matrix.py` on commit `1986503` (the static CLI built
from it), with the default final-freeze budget `--freeze-max` of 3 s.

## What each run does

The official cloud image of the distribution boots in qemu with two blank
disks. Its cloud-init installs the static `linuxreflect` CLI and starts a
writer that keeps the root filesystem busy (an fsync'd hash-chained log,
random 4 KiB overwrites, file churn). Then, inside the running system:

```sh
linuxreflect backup create --source /dev/vda --dest /mnt/dest --set system \
    --snapshot tracked-freeze --no-encrypt --compress none --json -v
linuxreflect restore prepare --image <image> --target /dev/vdc --json
linuxreflect restore apply --token <token> --confirm --json
```

`/dev/vda` is the disk the system is running from; `/dev/vdb` (mounted at
`/mnt/dest`) receives the image; `/dev/vdc` is the restore target. The VM is
powered off, and **only `/dev/vdc`** is booted, with fresh firmware variables
and the same firmware. A unit installed before the backup reports how the
restored system came up. Results travel over a second serial port that only
the test scripts write to.

A run passes when all of the following hold:

- the backup and the restore succeed;
- the restored system reaches `multi-user.target` with no failed unit and
  no ext4 journal recovery;
- its copy of the writer's log is a whole hash chain, whose length lies
  between the records synced before the backup started and the records begun
  before it ended.

## Results

All six runs passed. qemu ran under TCG (no KVM on this host), so the
freeze lengths are pessimistic; the native numbers are in
`docs/live-backup-spike.md`.

| Distribution | Kernel | Firmware | Regions imaged | Frozen together | Chunks in the final read | Final freeze | Restored boot | Log records (window) |
|---|---|---|---|---|---|---|---|---|
| Debian 12 | 6.1.0-54-cloud | UEFI, Secure Boot on | leading area, BIOS boot, ESP (vfat), `/` (ext4) | 1 | 67 | 624 ms | `multi-user`, 0 failed, no recovery | 2351 (180–2591) |
| Debian 12 | 6.1.0-54-cloud | BIOS | same | 1 | 70 | 634 ms | `multi-user`, 0 failed, no recovery | 2684 (278–2988) |
| Debian 13 | 6.12.115-cloud | UEFI, Secure Boot on | same | 1 | 76 | 614 ms | `multi-user`, 0 failed, no recovery | 2178 (271–2421) |
| Ubuntu 22.04 | 5.15.0-203 | UEFI, Secure Boot on | same | 1 | 98 | 595 ms | `multi-user`, 0 failed, no recovery | 3878 (235–4185) |
| Ubuntu 24.04 | 6.8.0-147 | UEFI, Secure Boot on | same plus `/boot` (ext4) | 2 | 110 | 1262 ms | `multi-user`, 0 failed, no recovery | 4692 (214–5129) |
| Ubuntu 24.04 | 6.8.0-147 | BIOS | same plus `/boot` (ext4) | 2 | 106 | 1291 ms | `multi-user`, 0 failed, no recovery | 4569 (233–4847) |

Every copy converged in one pass. No package transaction held dpkg's lock
during these runs. Every region was reported `Frozen`: the ext4 filesystems
were frozen, and the leading area, the BIOS boot partition and the ESP held
the quiet-window rule.

The first Debian 13 attempt did not reach our code. qemu exited 25 s into
the boot, while the guest kernel was still enumerating PCI devices, before
cloud-init ran. qemu's error output was not kept then, so the cause is
unknown. The harness now keeps it, and the case passed when run again.

## Changes found by the acceptance

- **The job-write check.** It also refused a working directory on a
  filesystem to be frozen. cloud-init, like every systemd service, runs with
  `/` as its working directory, so every attempt would have been refused
  before it started. A tracked copy writes nothing while frozen, so only the
  destination is checked now (`lr_snapshot::tracked_freeze`).
- **The freeze budget.** Through the CLI, the final-freeze budget had been
  taken from the plain freeze provider's `--freeze-timeout` (300 s, capped at
  30 s), not from `freeze_max` (3 s). An earlier pass of this matrix, on
  `b204ea1`, therefore ran with 30 s. `--freeze-max` is now its own option.
- **The read-rate estimate.** With the real 3 s budget, Ubuntu 24.04 did not
  converge (21 passes, then `E_NO_CONVERGENCE`). Each pass's "read rate"
  included compressing and writing the image, which the final read does not
  do. The rate is now the reads' own (`DirectBlockSource::read_stats`); the
  same case then converged in one pass.
- **The result stream.** Kernel and systemd messages on the console had
  corrupted the base64 result stream. Results now use their own serial port.

## Not covered here

- Real disks and KVM speed: these are virtio disks under TCG.
- A desktop session: the cloud images have none (the GNOME check of a
  one-second root freeze is in `docs/live-backup-spike.md`).
- Restoring onto a disk of another size, or onto the same machine with the
  source disk still attached. The copy carries the source's UUIDs; the
  restore plan names the attached disk that shares them (root test
  `a_copy_next_to_its_source_names_the_disk_that_shares_its_uuids`).
- Encrypted images, remote destinations, hooks and jobs through the daemon
  were not part of these runs. Hooks and the daemon route are covered by the
  root suites (`hooks_run_around_the_final_freeze`,
  `a_mounted_ext4_is_imaged_live_through_the_daemon`).
