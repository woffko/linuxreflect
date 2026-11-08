# Live backup acceptance: a running system imaged, restored, booted

Slice 18 acceptance criterion (d) (spec v2.2 §K), run on 2026-11-08 with
`tools/vm/live_restore_matrix.py` on the tree of commit `b204ea1` plus the
working-directory change recorded with this report.

## What each run does

The official cloud image of the distribution boots in qemu with two blank
disks. Its cloud-init installs the static `linuxreflect` CLI and starts a
writer that keeps the root filesystem busy (an fsync'd hash-chained log,
random 4 KiB overwrites, file churn). Then, inside the running system:

```sh
linuxreflect backup create --source /dev/vda --dest /mnt/dest --set system \
    --snapshot tracked-freeze --no-encrypt --compress none --json
linuxreflect restore prepare --image <image> --target /dev/vdc --json
linuxreflect restore apply --token <token> --confirm --json
```

`/dev/vda` is the disk the system is running from; `/dev/vdb` (mounted at
`/mnt/dest`) receives the image; `/dev/vdc` is the restore target. The VM is
powered off, and **only `/dev/vdc`** is booted, with fresh firmware variables
and the same firmware. A unit installed before the backup reports how the
restored system came up.

A run passes when the backup and the restore succeed, the restored system
reaches `multi-user.target` with no failed unit and no ext4 journal
recovery, and its copy of the writer's log is a whole hash chain whose
length lies between the records synced before the backup started and the
records begun before it ended.

## Results

All six runs passed. qemu ran under TCG (no KVM on this host), so the
freeze lengths are pessimistic; the native numbers are in
`docs/live-backup-spike.md`.

| Distribution | Kernel | Firmware | Regions imaged | Frozen together | Final freeze | Restored boot | Log records (window) |
|---|---|---|---|---|---|---|---|
| Debian 12 | 6.1.0-54-cloud | UEFI, Secure Boot on | leading area, BIOS boot, ESP (vfat), `/` (ext4) | 1 | 630 ms | `multi-user`, 0 failed, no recovery | 2601 (244–2895) |
| Debian 12 | 6.1.0-54-cloud | BIOS | same | 1 | 633 ms | `multi-user`, 0 failed, no recovery | 2547 (229–2825) |
| Debian 13 | 6.12.115-cloud | UEFI, Secure Boot on | same | 1 | 692 ms | `multi-user`, 0 failed, no recovery | 2172 (249–2410) |
| Ubuntu 22.04 | 5.15.0-203 | UEFI, Secure Boot on | same | 1 | 578 ms | `multi-user`, 0 failed, no recovery | 4226 (244–4543) |
| Ubuntu 24.04 | 6.8.0-147 | UEFI, Secure Boot on | same plus `/boot` (ext4) | 2 | 1331 ms | `multi-user`, 0 failed, no recovery | 4876 (280–5338) |
| Ubuntu 24.04 | 6.8.0-147 | BIOS | same plus `/boot` (ext4) | 2 | 1411 ms | `multi-user`, 0 failed, no recovery | 4684 (232–5116) |

Every copy converged in one pass; no package transaction held dpkg's lock
during these runs. Every region was reported `Frozen`: the ext4 filesystems
were frozen, and the leading area, the BIOS boot partition and the ESP held
the quiet-window rule.

## Change found by the acceptance

The first attempt would have been refused before it started: the job-write
check also refused a working directory on a filesystem to be frozen, and
cloud-init, like every systemd service, runs with `/` as its working
directory. A tracked copy writes nothing while frozen, so only the
destination is checked now (`lr_snapshot::tracked_freeze`).

## Not covered here

- Real disks and KVM speed: these are virtio disks under TCG.
- A desktop session: the cloud images have none (the GNOME check of a
  one-second root freeze is in `docs/live-backup-spike.md`).
- Restoring onto a disk of another size, or onto the same machine with the
  source disk still attached. The copy carries the source's UUIDs; the
  restore plan names the attached disk that shares them (root test
  `a_copy_next_to_its_source_names_the_disk_that_shares_its_uuids`).
- Encrypted images and remote destinations were not part of these runs.
