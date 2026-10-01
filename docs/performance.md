# Memory budgets and scale profiles

`cargo xtask scale` runs the profiles in `crates/lr-cli/tests/scale.rs`: each
runs the real CLI in release mode, in-process (no daemon), on a large input,
takes the process's peak resident set from `wait4(2)` (`ru_maxrss`, exact
however briefly the process runs), and fails when a peak exceeds its budget.
They need no root, but minutes and several gigabytes of scratch space
(`LR_SCALE_DIR` chooses where; the default is the temporary directory).

## Results and budgets

Measured on 2026-09-27 on the development machine (64 cores, ext4 on WSL 2,
kernel 6.18), with the changes below.

| Profile | Input | Step | Peak RSS | Time | Budget |
|---|---|---|---|---|---|
| Million-file tree | 1,000,000 files of 7–10 bytes in 1,000 directories | full backup | 750 MiB | 49 s | 1,024 MiB |
| | | unchanged incremental | 1,151 MiB | 26 s | 1,536 MiB |
| | | restore prepare | 545 MiB | 2 s | 1,280 MiB |
| | | restore apply | 1,007 MiB | 146 s | 1,280 MiB |
| Large xattr sets | 100,000 files, eight 400-byte `user.*` xattrs each (320 MB of values) | full backup | 450 MiB | 24 s | 640 MiB |
| | | restore prepare | 745 MiB | 1 s | 1,024 MiB |
| | | restore apply | 788 MiB | 71 s | 1,024 MiB |
| Long chain | one full and 199 incrementals of 2,000 files | any incremental | 11 MiB | 0.2 s | 64 MiB |
| | | restore of member 200 | 11 MiB | 0.5 s | 64 MiB |
| 16 TB virtual disk (root suite, D-099) | block image, 4 M chunks | full backup | 29 MiB | | 1,024 MiB |

The budgets leave 25–40 % over the measured peak, so a regression shows up as
a failure rather than as noise.

## What the profiles found

The first run of the million-file profile, on the code of `v0.1.0-beta.1`,
took 451 s for the full backup and peaked at about 800 MiB (sampled), and
1,297 MiB for the unchanged incremental. Three changes followed:

- **Small files skip the chunker's buffer.** The content-defined chunker
  allocates a zeroed buffer of the largest chunk size (256 KiB) for every
  file. A file shorter than the smallest chunk (16 KiB) is always one chunk,
  so it is now read directly; longer files still go through the chunker,
  with identical cut points. The full backup went from 451 s to 49 s.
- **The walk's entries are consumed, not cloned,** when they become manifest
  records, so each file's metadata is held once during a backup.
- **An incremental holds each reference entry once:** keyed by its path moved
  out of the entry, with its change token beside it instead of in a second
  map keyed by another copy of the path (1,297 → 1,151 MiB). A restore sorts
  its entries for the metadata pass by reference instead of cloning them.

## Restore preverification follow-up, 2026-10-01

The existing scale gate caught a regression after required-payload
preverification was added: the xattr restore peaked at 1,141 MiB, exceeding
its unchanged 1,024 MiB budget. File verification deep-cloned every decoded
record into a second tree for structural validation, including every xattr
value. Validation now borrows paths and records instead. It keeps the same
structural checks and still verifies every original record's payload.

All three release-mode profiles then passed on Linux 6.12.96, using local
ext4 scratch. No budget or allocator setting changed:

| Profile | Full backup | Incremental | Restore prepare | Restore apply |
|---|---|---|---|---|
| Million-file tree | 761 MiB | 1,153 MiB | 545 MiB | 1,011 MiB |
| Large xattr sets | 454 MiB | — | 748 MiB | 796 MiB |
| 200-member chain | 10 MiB | 12 MiB maximum | 11 MiB | 12 MiB |

These measurements cover the unprivileged profiles, not the privileged 16 TB
virtual-disk scenario. Keep validation views borrowed: required safety checks
must not introduce another owned copy of a large tree.

## Rules of thumb

- **Block and whole-disk images** stream their manifests: memory does not
  grow with the disk (29 MiB for 16 TB), nor with the length of a chain.
- **File mode keeps the tree's metadata in memory** while it backs up or
  restores: about 0.75 KiB per file for a full backup, 1.2 KiB per file for
  an incremental (it also holds the previous member's entries), and 1 KiB per
  file for a restore, plus the xattr values themselves. A ten-million-file
  tree therefore needs about 12 GiB for an incremental. Streaming the file
  manifest, as block mode does, would remove that limit; until then, split
  very large trees into several jobs.
- **Long chains** cost time to open (one superblock and index per member),
  not memory.
