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

## Verification-history capture experiment, 2026-10-03

This is a design experiment, not a history-store implementation or a new CI
gate. In the isolated Debian 13 client/storage VMs (8 GiB client RAM), compare
the pinned release CLI's `verify --chain` with raw BLAKE3 capture into private
local scratch followed by the same CLI verification. File-mode fixtures use
uncompressed, unencrypted images. Three alternating paired repeats per case
and backend passed (18 pairs); reports matched except the locator, original
image hashes stayed unchanged, and capture cleanup/quota refusal passed.

Times below are medians; RSS and allocated image-file scratch are maxima.
RSS is measured by a fresh Rust launcher using `wait_with_peak_rss`, avoiding
Python pre-exec memory contamination. It excludes page cache and retains a
roughly 2 MiB launcher floor. Candidate RSS is the maximum of its sequential
capture and verification processes, not their sum.

| Workload | Source | Direct verify (s) | Capture + verify (s) | Ratio | Scratch (MiB) | Direct / candidate peak RSS (MiB) |
| --- | --- | --- | --- | --- | --- | --- |
| 1 GiB + 128 MiB delta | Local ext4 | 1.08 | 2.91 | 2.69× | 1154.0 | 11.8 / 11.8 |
| 1 GiB + 128 MiB delta | NFSv4.2 | 1.17 | 2.87 | 2.45× | 1154.0 | 11.9 / 11.7 |
| 200 members / 2,000 files | Local ext4 | 2.34 | 4.72 | 2.02× | 70.0 | 10.3 / 10.5 |
| 200 members / 2,000 files | NFSv4.2 | 2.78 | 4.73 | 1.70× | 70.0 | 10.4 / 10.5 |
| 100,000 files / 8 × 400 B xattrs | Local ext4 | 1.39 | 1.99 | 1.44× | 334.9 | 747.9 / 748.4 |
| 100,000 files / 8 × 400 B xattrs | NFSv4.2 | 1.52 | 2.12 | 1.39× | 334.9 | 749.7 / 749.1 |

The 64 KiB-buffer copier peaked below 2.71 MiB; large-xattr verification still
needed about 750 MiB. Scratch follows raw ancestry size, not RAM buffer size.
The 200-member check covered 1,562.5 MiB of logical plaintext but copied only
69.6 MiB of raw images; neither counter measures NFS network traffic.

These are warm/cached virtual-storage attempts, not cold-NAS throughput or
physical power-loss evidence. The named-copy proxy includes per-file/directory
capture sync and the CLI's advisory catalog updates; disposable unnamed scratch
need not require the former. Capture timings exclude independent byte-equality
validation, performed after verification. At this experiment's baseline the
verifier had no public captured-reader entry point, so it did not validate the
then-future read-only
handle API, other image modes or receipt publication.

Suggested opt-in limits are 8 GiB raw capture with allocation headroom, a fixed
64 KiB buffer, and explicit history-unavailable on refusal. These are proposals,
not selected runtime defaults. Preserve existing scale budgets; remeasure the
integrated path before enabling history. See the design ownership discussion in
[redesign-ideas.md](redesign-ideas.md#verification-history-review-direction-2026-10-03).

## Captured-verification API, 2026-10-04

The integrated engine boundary (D-132) was measured on the same retained
File-mode fixtures and local/NFS backends. Both ordinary and captured calls use
one pinned release probe linked against the focused release tests' dependency
graph. Three alternating paired repeats per workload/backend passed (18 pairs).
Reports matched exactly; ordered observation identities, raw lengths, typed
coverage and complete stages matched the fixtures. Original SHA-256 inventories
were unchanged before/after, every capture descriptor was read-only at the
structure-phase sample, and no named scratch entries remained.

| Workload | Source | Ordinary API (s) | Captured API (s) | Ratio | Allocated scratch (MiB) | Ordinary / captured peak RSS (MiB) |
| --- | --- | --- | --- | --- | --- | --- |
| 1 GiB + 128 MiB delta | Local ext4 | 0.97 | 1.96 | 2.02× | 1154.0 | 8.7 / 8.8 |
| 1 GiB + 128 MiB delta | NFSv4.2 | 0.99 | 1.97 | 1.99× | 1154.0 | 8.6 / 8.7 |
| 200 members / 2,000 files | Local ext4 | 2.29 | 2.60 | 1.14× | 70.0 | 7.0 / 7.4 |
| 200 members / 2,000 files | NFSv4.2 | 2.45 | 2.62 | 1.07× | 70.0 | 7.1 / 7.3 |
| 100,000 files / 8 × 400 B xattrs | Local ext4 | 1.20 | 1.54 | 1.29× | 334.9 | 745.0 / 746.8 |
| 100,000 files / 8 × 400 B xattrs | NFSv4.2 | 1.23 | 1.51 | 1.23× | 334.9 | 745.2 / 745.8 |

Times are engine-call medians; RSS and sampled file allocation are maxima.
RSS covers the single capture-and-verify process, excludes page cache, and retains
the small Rust launcher's pre-exec floor. The 64 KiB copy buffer does not remove
the verifier's roughly 750 MiB xattr-metadata cost. Scratch allocation follows
raw ancestry, including per-file allocation rounding, not logical plaintext size.

These warm virtual-storage results exclude catalog recording, receipt publication
and disposable-scratch sync. They are not directly equivalent to the earlier
named-copy CLI proxy and do not establish cold-NAS throughput or physical durability.
Resource comparisons alone do not prove read binding: the same-build focused NFS
regression separately mutates its disposable source after capture, proves that
ordinary verification then fails, and confirms captured verification still passes.
Actual Stream and stored-payload whole-disk fixtures also pass that focused suite;
no OS-level restore or interruption scenario is claimed by these measurements.

The experiment explicitly used an 8 GiB raw cap and 10 GiB preflight headroom,
not engine defaults or an atomic space reservation. No permanent scale thresholds
changed. Evidence is retained outside Git in
`_handoff/artifacts/verification-observation-20261004/` under the project root
(`api-summary.json`, `api-evidence.tar.gz`, build provenance and `nfs-tests.log`).

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
