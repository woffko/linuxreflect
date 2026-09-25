# LinuxReflect

A GUI-driven, system-level backup and disaster-recovery tool for Linux, in the
spirit of Macrium Reflect. The implementation follows the frozen specification
in [`docs/spec/linuxreflect-spec-v2.1.md`](docs/spec/linuxreflect-spec-v2.1.md).

> Status: bootstrap + slices S1–S2. The MVP is slices S1–S11 (spec §K).

## What "live backup" means here

Linux has no VSS. LinuxReflect therefore provides true point-in-time block or
tree snapshots where the platform allows it (LVM, Btrfs), quiesced/frozen or
offline backups where it does not, and always reports the **consistency level
actually achieved** instead of silently degrading. It never fakes a snapshot
(spec §A.1, §D.2).

## Layout

| Crate | Purpose | Slice |
|---|---|---|
| `lr-core` | errors, ids, geometry, consistency, capability probe, discovery | S1–S2 |
| `lr-unsafe` | every `unsafe` block: block ioctls, `pidfd_open` | S1 |
| `lr-crypto` | key hierarchy, AEAD, keyed BLAKE3, nonce counters | S3 |
| `lr-format` | `.lrimg`: superblock, footer, chunk records, manifests | S4 |
| `lr-fsmap` | used-block maps: ext4, xfs, raw zero-skip | S5 |
| `lr-snapshot` | LVM, freeze, offline, live-none, Btrfs providers | S8 |
| `lr-blocksource` | `O_DIRECT` aligned reads over a block path | S6 |
| `lr-store` | destinations (local, mounted, SFTP) and set locking | S10 |
| `lr-engine` | backup/restore/verify, chains, scan-and-diff | S6–S9 |
| `lr-proto` | gRPC schema (prost/tonic) | S11 |
| `lr-daemon` | root daemon, polkit authorization, restore tokens | S11 |
| `lr-cli` | the `linuxreflect` binary | S1–S2 |
| `xtask` | build automation and fixtures | — |

Every crate except `lr-unsafe` is `#![forbid(unsafe_code)]`.

## Build and test

```sh
cargo xtask ci          # fmt + clippy -D warnings + tests + cargo deny + cargo audit
cargo test --workspace  # unprivileged tests only
```

Acceptance tests that need a loop device, LVM, `fsfreeze` or qemu are marked
`#[ignore]` and require `LR_ROOT_TESTS=1` plus root:

```sh
LR_ROOT_TESTS=1 sudo -E cargo test --workspace -- --ignored --nocapture --test-threads=1
```

On this machine the same tests can be run through WSL interop root without
polluting the user's build cache — see `AGENTS.md` for the exact command.

Tests never touch a device unless they created it themselves.

## Usage (implemented so far)

```sh
linuxreflect disk list [--all] [--json]
linuxreflect disk map <device|image> [--json]
linuxreflect caps [--json]
linuxreflect backup create --source <device> --dest <uri> --set <name> [--chain full|incremental|differential] [...]
linuxreflect backup list --dest <uri> [--set <name>] [--json]
linuxreflect catalog --dest <uri> [--json]
linuxreflect verify --image <uri> [--chain] [--json]
linuxreflect restore prepare --image <uri> --target <device> [--json]
linuxreflect restore apply --token <token> --confirm
linuxreflect daemon run|status [--json]
linuxreflect job get|cancel <job-id>
```

File mode (Slice S12) backs up a directory tree instead of a device. A source
directory selects it automatically, or force it with `--mode file`; `--snapshot
btrfs` walks a read-only snapshot of the subvolume, which makes the backup
point-in-time instead of per-file:

```sh
linuxreflect backup create --source /home --dest sftp://nas/backups --set home --mode file
linuxreflect backup create --source / --dest /mnt/backup --set root --mode file --snapshot btrfs --one-file-system
linuxreflect restore prepare --image /mnt/backup/root/<chain>/000-full-*.lrimg --target /mnt/restore
linuxreflect restore apply --token <token> --confirm --json
linuxreflect restore mount --image /mnt/backup/root/<chain>/000-full-*.lrimg --at /mnt/view
```

A file restore writes into an existing directory (non-empty needs `--merge`),
and `restore mount` serves the image read-only through FUSE so
`sha256sum`/`diff` can check it without restoring.

Block images can be exported as read-only block devices (Slice S13): the CLI
runs a newstyle NBD server, attaches it with `nbd-client` and mounts the
filesystem with `ro,noload` (ext4) or `ro,nouuid,norecovery` (xfs):

```sh
linuxreflect export mount --image /mnt/backup/root/<chain>/000-full-*.lrimg --at /mnt/export
linuxreflect export list
linuxreflect export umount --at /mnt/export
```

The `export` commands go through the daemon when one is reachable, so a
non-root user can mount an image with polkit's `org.linuxreflect.export.manage`
authorization.

Chains are pruned whole (Slice S14): `retention apply` keeps the newest
`--keep-chains` complete chains and never deletes a single member of a chain.
Scheduled jobs live in `/etc/linuxreflect/config.toml` (spec §J.2) and are
materialized as systemd units:

```sh
linuxreflect retention apply --dest /mnt/backup --set home --keep-chains 2 [--dry-run]
linuxreflect schedule set --config /etc/linuxreflect/config.toml
linuxreflect schedule list --config /etc/linuxreflect/config.toml
linuxreflect schedule remove root-nightly
```

`schedule set` writes `linuxreflect-job@<name>.service` and `.timer`, reloads
systemd and enables the timers; `OnCalendar`, `Persistent` and
`RandomizedDelaySec` are copied from the config verbatim, and retention runs as
the service's second step. A user-session helper forwards daemon job events to
the desktop notification service:

```sh
linuxreflect-session --socket /run/linuxreflect/daemon.sock
```

Progress chatter is silent; only started, finished and failed jobs notify
(failed ones with `urgency=critical` and the `E_*` code).

A graphical client (Slice S15) drives the same daemon: a disk map, a backup
wizard that shows the `probe` plan and the achieved consistency before starting,
a restore wizard that shows the token plan, live progress and the job history.

```sh
linuxreflect-gui --socket /run/linuxreflect/daemon.sock
```

The GUI runs on X11 and Wayland (Slint's winit backend with the software
renderer). It is built with [Slint](https://slint.dev) under the Slint
Royalty-Free 2.0 licence; the attribution that licence asks for is shown in the
window's footer and here.

Rescue mode (Slice S16) boot-repairs a restored machine and recreates a disk
layout for a file-mode restore, and the same crate builds the rescue medium:

```sh
# After a whole-disk restore: make the machine bootable again.
linuxreflect-rescue boot-repair --disk /dev/sda --firmware uefi --esp-partition 1
linuxreflect-rescue boot-repair --disk /dev/sda --firmware bios --layout-changed

# Rebuild the partition table and filesystems of a file-mode restore.
linuxreflect-rescue recreate-layout --disk /dev/sda --dump /backups/sda.sfdisk \
    --filesystem 1:vfat:1234-ABCD:ESP --filesystem 2:ext4:1111-2222:ROOT

# Build a bootable rescue USB image (SeaBIOS and UEFI Secure Boot).
contrib/rescue/build-rescue.sh /tmp/rescue.img
```

Both operations plan before they act (`--dry-run` prints the exact commands).
`contrib/rescue/mkosi.conf` describes the larger distribution medium that adds
the graphical rescue session (`cage` + the GUI) with the TUI as console
fallback; see D-093 for which variant this repository verifies.

`--dest` accepts a local path, a mounted path or `sftp://[user@]host[:port]/path`
(no passwords in the URI; authentication is an SSH agent or an identity file).

## Daemon

The daemon serves the gRPC API from `proto/linuxreflect.proto` over a Unix
socket (default `/run/linuxreflect/daemon.sock`). It needs the polkit policy to
be installed, otherwise every privileged action is refused:

```sh
install -m 0644 contrib/polkit/org.linuxreflect.policy /usr/share/polkit-1/actions/
linuxreflect-daemon --socket /run/linuxreflect/daemon.sock --socket-group linuxreflect
```

The socket is created `0660 root:linuxreflect` and the group is created on first
start (`--no-create-group` and `--socket-group` change that); the socket
directory grants exactly the access the socket grants (D-057). The daemon also
accepts a socket passed by systemd (`LISTEN_FDS`, e.g.
`systemd-socket-activate`) and sends `READY=1` plus watchdog pings when
`NOTIFY_SOCKET` is set. Every command above talks to the daemon when its socket
is reachable and falls back to running in-process when it is not.

## License

Not chosen yet; see open question §M.1 of the specification.
