# LinuxReflect operator guide

This guide is for the person who installs LinuxReflect, decides where backups
go, schedules them and restores from them. It describes what the software
does and, as importantly, what it does not do. The design decisions it refers
to (`D-…`) are in [`decisions.md`](decisions.md); the specification is
[`spec/linuxreflect-spec-v2.1.md`](spec/linuxreflect-spec-v2.1.md).

## Contents

- [Components](#components)
- [Who may do what](#who-may-do-what)
- [Destinations](#destinations)
- [What an image contains](#what-an-image-contains)
- [Chains: full, incremental, differential](#chains-full-incremental-differential)
- [Retention](#retention)
- [Verification](#verification)
- [Restoring](#restoring)
- [Scheduling](#scheduling)
- [Running the daemon](#running-the-daemon)
- [Memory and scale](#memory-and-scale)

## Components

| Part | What it does |
|---|---|
| `linuxreflect` | The CLI. It talks to the daemon when its socket answers and otherwise does the work itself (then it needs root for devices). The static `x86_64-linux-musl` build runs on any Linux, including rescue systems. |
| `linuxreflect-daemon` | Runs every job as root on behalf of the users of the desktop session, checks each request with polkit, and is started by `linuxreflect-daemon.socket` on the first request. |
| `linuxreflect-gui` | The graphical client; it only talks to the daemon. |
| `linuxreflect-session` | A per-user service that shows desktop notifications for jobs. |
| Rescue medium | A bootable image with the CLI, the daemon, the GUI and a text menu, for bare-metal restores. |

## Who may do what

The daemon identifies the caller from the socket's peer credentials and asks
polkit (`/usr/share/polkit-1/actions/org.linuxreflect.policy`):

| Action | Default for the active session | Covers |
|---|---|---|
| `org.linuxreflect.disk.read` | allowed | listing disks, sets and jobs, verifying, cancelling one's own jobs |
| `org.linuxreflect.backup.create` | administrator, kept | backups, catalog rebuilds |
| `org.linuxreflect.restore.prepare` | administrator, kept | restore plans and tokens |
| `org.linuxreflect.restore.apply` | administrator, every time | writing a restore target |
| `org.linuxreflect.snapshot.manage`, `schedule.manage`, `destination.configure`, `export.manage` | administrator, kept | snapshots, timers and retention, named destinations, NBD exports |
| `org.linuxreflect.job.cancel-other` | administrator, kept | cancelling a job another user started |

Outside the active local session (an SSH login, a service) `disk.read` is
denied, and root may do everything.

Two rules protect the daemon from its own callers:

- **Files a request names must be the caller's.** A passphrase file, an SSH
  identity or a `known_hosts` file given in a request must be a regular file
  owned by the caller (root may name any file). For verification and set
  listing the file is pinned by its descriptor, so the path cannot be swapped
  after the check (A4).
- **Host-key checking cannot be switched off** through the daemon;
  `insecure_ignore_host_key` is honoured only by a daemon started in
  development mode.

## Destinations

A destination is a directory (a local path, possibly an NFS or SMB mount) or
an SFTP location. Each set is `<destination>/<set>/`, each chain a directory
in it, each backup one `.lrimg` file.

**Local and mounted directories.** Use a directory that only root and the
backup's owner can write to. Writes below it are opened beneath the pinned
directory without following symbolic links, temporary files get unpredictable
names, and an image appears under its final name only after it was flushed
(D-120). For NFS and SMB, mount with `soft` (and a timeout): on a `hard` mount
a vanished server blocks the job in the kernel, and nothing in user space can
interrupt it (D-113).

**Require a particular mounted share.** An administrator can register a guarded
local destination (replace these example values with the actual mount):

```sh
linuxreflect destination add --name archive --uri /mnt/nas/backups \
    --required-mount /mnt/nas --required-source nas:/exports/backups \
    --required-fs-type nfs4
```

Use `--dest @archive` for backups, retention and scheduled jobs. The three
required fields must match `/proc/self/mountinfo` in the executing process's
mount namespace. Missing or wrong mounts are refused before directory creation;
subdirectories of the required mount are supported. Nested/stacked mounts,
non-root bind projections and paths containing `..` are refused. A raw path
such as `--dest /mnt/nas/backups` does not inherit a named destination's guard.

The registry stores this under `[destination.required_mount]` with `path`,
`source` and `fs_type`. Listing destinations shows the guard. Updating a named
destination without those fields preserves its existing guard; remove and
recreate the entry to clear it. Checks run before storage operations but do not
atomically pin the mount, prove server durability, or distinguish every mount
with identical source/type. Test your actual NFS deployment before relying on
it (D-126).

**SFTP.** Configure SFTP destinations on the daemon, not per request:

```sh
sudo linuxreflect destination add --name nas \
    --uri sftp://backup@nas.local/srv/backups \
    --identity /etc/linuxreflect/id_ed25519 \
    --known-hosts /etc/linuxreflect/known_hosts
linuxreflect backup create --source /dev/vg0/root --dest @nas --set laptop-root …
```

The registry is `/etc/linuxreflect/destinations.toml`; `@nas/<set>/<chain>/<file>`
names an image on it. The host key must be in `known_hosts`, which is read the
way OpenSSH reads it: a line applies only through a positive host pattern, a
matching `!pattern` excludes the host, a key on a matching `@revoked` line is
refused wherever that line stands, `@cert-authority` lines trust no plain key
(certificates are not supported), and any other marker makes the file
unusable. A server without the `fsync@openssh.com` extension cannot confirm
that an image reached its disk; the report then warns "durability
unconfirmed".

## What an image contains

**Used-block images are not forensic copies.** A block or whole-disk image
holds the blocks the filesystem uses, found from its own allocation maps
(ext4 with `dumpe2fs`, xfs with `xfs_db`; spec §F), plus the partition table
and the first MiB of the disk. Free space, and with it the remains of deleted
files, is not imaged; a restore writes zeros or nothing there. A filesystem
LinuxReflect cannot map is read whole ("raw").

**xfs with an external log or a realtime subvolume** is read whole from its
data device (spec §F). The log and the realtime subvolume are on other
devices and are not in the image; the report says so (D-124). Back those
devices up separately, or avoid these layouts on systems that must be
restorable from one image.

**Consistency.** Every report states the consistency it achieved: a
snapshot (`point-in-time`), a frozen filesystem (`frozen`), an unmounted device
(`offline`), `per-file` for a live file backup, or `none` for a live block
read, which needs `--allow-inconsistent` to start and `--accept-inconsistent`
to restore. Nothing claims a snapshot that was not made.

**File mode** (`--mode file`) records the tree: content, ownership, mode,
timestamps, xattrs, ACLs, hard links, device nodes and sparse regions. A file
that keeps changing while it is read is recorded as it was last read and
named in the report. `--one-file-system` stays on one mount.

**Btrfs** sources are snapshotted per mounted subvolume and stored as
`btrfs send` streams. A subvolume nested in an included one but not mounted
itself stops the backup, because a snapshot would leave it out; mount it, or
accept its exclusion with `--exclude-nested-subvolumes` (D-112).

**Encryption** is chosen when a chain starts. A plaintext chain cannot be
continued encrypted; start a new chain. A passphrase only ever comes from a
file (`--passphrase-file`, mode 0600), never from an argument or a prompt.

**Disks with 4096-byte sectors** (4Kn) are read in their own block size. A
whole-disk image restores only to a disk with the same logical block size, or
to an image file (A14).

## Chains: full, incremental, differential

A chain is one full backup and the members that follow it.

- An **incremental** stores what changed since the newest member. In block
  mode every used block is read and compared (scan-and-diff); in file mode a
  file is read again only when its size, mtime, inode number or ctime
  changed (D-111). `--verify-content` reads every file anyway; unchanged
  content is still not stored twice.
- A **differential** stores a full manifest, so a restore reads one manifest
  instead of merging deltas. **It still needs every earlier member of its
  chain**: its unchanged blocks may be stored in any of them (D-114).
  Deleting incrementals to keep "the full and the last differential" is not
  possible; keep whole chains.
- `--max-incrementals N` starts a new chain after N incrementals, and a
  schedule's `new_chain_on_calendar` starts one on a calendar.

## Retention

`linuxreflect retention apply --keep-chains N` deletes whole chains only,
oldest first. Before any deletion, it requires fresh payload verification of
at least one retained chain whose recovery point has no recorded bad sectors.
If no retained chain qualifies, retention fails without deleting images. This
includes encrypted backups for which the required key is unavailable.

`--verify-first` checks candidate chains before choosing which to keep, leaving
failed chains in place. Without it, retention checks the selected retained
chains before deletion. Dry runs use the same rule. Cached verification times
are historical information, not authority to delete; a missing catalog or a
same-size payload change cannot bypass the fresh check (D-125).

## Verification

`linuxreflect verify --image <member>` checks that member and everything it
needs from its ancestry; `--chain` checks every payload of the whole chain,
older members included. A failure names the corrupted chunk or file. A
successful `--chain` verification without recorded bad sectors is recorded in
the catalog. Recorded bad sectors still appear as verification warnings, but
do not qualify the image as a complete recovery point. This history can be
lost when the catalog is rebuilt; retention checks current content before
deleting regardless.

## Restoring

A restore has two steps, so that the target is written only on purpose:

1. `linuxreflect restore prepare --image … --target …` checks the image and
   the target and prints the plan and a **token**. The token is valid for 10
   minutes, **once**, and only for the user who prepared it (A11).
2. `linuxreflect restore apply --token … --confirm` checks the target again
   (same device, same size, same partition table), admits the one-use operation,
   and verifies the selected recovery point's required payloads before writing.
   Through the daemon this asks for the administrator password every time.

Preverification covers block and file recovery points and every ancestor stream
that a Btrfs restore must replay. A failed or cancelled verification leaves the
target untouched and consumes the admitted token; prepare again to retry. The
ten-minute expiry limits admission, not the duration of an admitted restore.
Target identity and cancellation are checked again after verification (D-127).

This extra read pass detects existing corruption before destructive work. It
does not freeze the backup files or provide rollback: later source changes,
I/O failures or interruption can still leave a partial target. Integrity checks
remain active during writes. Keep a separate recovery copy and test restores.

Restores refuse what would go wrong: a target in use anywhere (`O_EXCL`, even
in another mount namespace), a whole-disk image onto a partition, an image
with recorded bad sectors, a manifest that does not cover the disk, and a
single-filesystem image onto a partitioned disk unless
`--replace-partition-table` is given (the plan lists the partitions that go).
A whole-disk restore keeps partition numbers and positions and moves the GPT's
backup copy to the end of a larger target.

**File restores** write into an existing directory. A directory that is not
empty needs `--merge` (the GUI's "restore into this folder" choice): files
with the same name are replaced, other files stay. Metadata that cannot be
restored (ownership as a normal user, xattrs on a filesystem without them) is
listed per file in the report and summed up in a warning;
`--strict-metadata` makes that a failure instead (D-123). Success is reported
only after the files are on stable storage.

## Scheduling

Jobs are described in `/etc/linuxreflect/config.toml` (spec §J.2) and turned
into systemd units with `sudo linuxreflect schedule set`:

- `linuxreflect-job@<name>.timer` runs the job's backups and then its
  retention.
- With `new_chain_on_calendar`, `linuxreflect-newchain@<name>.timer` runs the
  same sources as full backups on that calendar; the incremental timer's
  service is ordered after it, so when both are due the new chain comes
  first.

Encrypted jobs pass their configured `passphrase_file` to retention as well as
backup creation, because deletion requires fresh verification. Regenerate older
installed units with `schedule set` after upgrading; without a usable key,
retention preserves the backups and reports refusal.

A named destination's `identity` and `known_hosts`, and `[daemon]
lvm_cow_size`, are passed to the generated commands. Every argument is quoted
for systemd, and values that could break a unit line (control characters, and
`%` in calendar and delay values) are refused. `[daemon] socket` and
`log_level` are accepted only at their defaults: the daemon takes its socket
from `linuxreflect-daemon.socket` and its log level from `RUST_LOG`. Invalid
`mode`, `snapshot`, `compress` or `parent` values are refused when the config
is read, not when the timer fires.

## Running the daemon

- **Logs** go to the journal: `journalctl -u linuxreflect-daemon`.
- **Stopping** waits for running jobs. The unit's stop timeout is 10 minutes
  and is extended as long as some job makes progress; the unit's status line
  names each job being waited for. A job that stops progressing no longer
  holds a reboot (D-113).
- **A panic** in one job fails that job and nothing else (D-122).
- **Cancelling**: `linuxreflect job cancel <job-id>` cancels one's own job;
  another user's needs `job.cancel-other`.
- **Updates**: `contrib/install-host.sh` replaces the binaries and restarts the
  daemon through the same draining stop.

## Memory and scale

The measured peak memory for large inputs, and the budgets the scale suite
holds them to, are in [`performance.md`](performance.md).
