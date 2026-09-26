# Remediation plan

This plan merges two audits of revision `44fc8dd`:

- an external code review (findings **R01–R40**, dated 2026-09-26), and
- an independent audit by the project's implementing agent (findings
  **A1–A12**, dated 2026-09-26).

Together they report 52 findings. Many share a root cause, so the plan is
organised around the mechanisms that fix them rather than by finding number.
The [finding index](#finding-index) at the end maps every ID to its work item.

Status of this document: **plan, not started**. Tick items off in the index as
they land.

## Contents

- [Goal: v0.1.0-alpha.2](#goal-v010-alpha2)
- [Ground rules](#ground-rules)
- [Phase 0 — immediately](#phase-0--immediately)
- [Phase 1 — data destruction, false guarantees, cryptography](#phase-1--data-destruction-false-guarantees-cryptography)
- [Phase 2 — correctness, storage durability, security boundaries](#phase-2--correctness-storage-durability-security-boundaries)
- [Phase 3 — daemon boundary, metadata, scheduling](#phase-3--daemon-boundary-metadata-scheduling)
- [Phase 4 — structure and documentation](#phase-4--structure-and-documentation)
- [Shared mechanisms](#shared-mechanisms)
- [Decisions to record](#decisions-to-record)
- [Sequence and effort](#sequence-and-effort)
- [Finding index](#finding-index)

## Goal: v0.1.0-alpha.2

Complete phases 0 and 1 and publish `v0.1.0-alpha.2`. Done when all hold:

1. The `v0.1.0-alpha.1` release carries a "Known critical issues" section.
2. R40 is fixed: the root run reports executed, ignored and unavailable tests
   separately, and a fixture failure is a test failure, not a skip.
3. Every phase 1 finding (A1, A2, A3, R01, R02, R03, R04, R05, R06, R11, R14)
   has a regression test that failed before its fix and passes after it.
4. D-110 and D-115 are recorded in `docs/decisions.md`.
5. `cargo xtask ci` exits 0 and every root suite is green with no
   unavailable scenarios.
6. Installation and the GNOME/polkit check pass on the Ubuntu test host.
7. The finding index below is ticked for the completed items, and
   `v0.1.0-alpha.2` is published as a pre-release with artifacts and
   checksums.

Stop only on a genuine blocker.

## Ground rules

1. **Test first.** Every finding gets a regression test that fails on the
   current code and passes after the fix. The external review's probes are
   reused with their assertions inverted; the independent audit's probes
   become root tests.
2. **Honest test accounting comes first (R40).** Until a root run can no
   longer report a skipped scenario as a pass, a green gate proves nothing.
   A missing tool or a failed fixture fails the test in the root lane, and
   every run reports *executed*, *ignored* and *unavailable* separately.
3. **The specification stays frozen.** Where a fix changes behaviour the
   specification describes (differential semantics, nested Btrfs
   subvolumes), the choice is recorded in `docs/decisions.md` (D-110 onwards),
   never made silently.
4. **One finding, one commit,** carrying its test and its ID in the message.
5. **Destructive tests only on what the test created:** loop devices, images,
   qemu disks.

## Phase 0 — immediately

| # | Action | Why |
|---|---|---|
| 0.1 | Add a "Known critical issues" section to the `v0.1.0-alpha.1` release: do not rely on encryption (R01), Btrfs stream mode (R02, R04), whole-disk restore onto a previously partitioned disk (R05, A3), restores on hosts with containers or private mounts (A1), or SFTP destinations (R18, R19) | Users of the published build must know the risks now |
| 0.2 | Honest test accounting (R40): fixtures fail instead of returning `None`; `daemon_client` keeps the daemon's stderr and fails on an unexpected exit; a root lane with a mandatory tool list | Every later result depends on it |
| 0.3 | Regression scaffold: `crates/lr-engine/tests/review_probes.rs` (external probes, inverted) and the independent audit's root probes (target mounted in another mount namespace, source mounted there, restore onto a dirty target), each `#[ignore = "known defect <ID>"]` until its fix lands | Makes the remaining defect count visible |
| 0.4 | Feature freeze until phase 1 is done | — |

## Phase 1 — data destruction, false guarantees, cryptography

### 1.1 Exclusive device claims — A1, A2, R05

- **New primitive** in `lr-unsafe`: `open_block_exclusive(path, write)`,
  which opens with `O_EXCL` and maps `EBUSY` to `E_TARGET_BUSY`. On a block
  device `O_EXCL` is the kernel's authoritative "in use" check: it sees
  mounts in every mount namespace and md/dm/ZFS holders, which the sysfs and
  `mountinfo` checks cannot.
- **Restore (A1):** claim the target once per apply and keep that descriptor
  for the final target-fact check and every write. Never reopen the target
  by path during a restore.
- **Offline backup (A2):** open the source read-only *with* `O_EXCL` and hold
  the claim for the whole read. `EBUSY` means "not offline": try the next
  provider or return `E_NO_CONSISTENT_METHOD`.
- **Swap recreation (R05):** write the saved swap header through the
  whole-disk descriptor at the offset recorded in the image, instead of
  running `mkswap` on a partition node. If `mkswap` is ever kept, reread the
  table (`BLKRRPART`) and compare the node's offset and size with the plan
  first.
- **Tests:**
  - A target mounted in a private namespace gives `E_TARGET_BUSY`, and the
    target is byte-identical afterwards.
  - The same for a source: the backup is refused instead of being reported
    as `offline`.
  - A whole-disk restore onto a target with a *different* old partition
    layout leaves every non-swap region byte-identical to the image.

### 1.2 Metadata cryptography — R01 (with R11)

- **R01:** one nonce allocator per image and metadata key, shared by the
  Manifest, Extras and PageTable streams and every other page stream. Each
  page record already stores its nonce, so readers need no change and the
  format version does not change.
- **Existing images (D-110):** record the status of existing encrypted v1
  images. `verify` and `prepare` warn that their metadata confidentiality is
  weakened and recommend recreating encrypted chains.
- **R11:** caps on Argon2 memory, time and parallelism are checked *before*
  derivation, plus an aggregate KDF budget in the daemon.
- **Tests:**
  - Several pages in every stream, under both AEADs, yield globally unique
    `(key, nonce)` pairs.
  - An over-budget header is refused without allocating its requested
    memory.

### 1.3 Identifier validation — R02 (groundwork for R35)

- **A `SetName` type:** non-empty, bounded length, a restricted character
  set, no `/`, not `.` or `..`. It is validated at every entry point: CLI,
  protobuf and daemon, scheduler config, GUI and rescue tools.
- **Btrfs cleanup** deletes only snapshot IDs recorded in the set's own
  journal, under a pinned directory, never "every entry except `latest`".
- **Tests:**
  - `..`, `.`, `a/b` and the empty name are refused before anything is
    mounted or snapshotted.
  - Cleanup on a loop-backed Btrfs fixture never touches anything outside
    its own snapshots.

### 1.4 Sparse files — R03

- `ENOTSUP` or `EINVAL` from `SEEK_DATA`/`SEEK_HOLE` means "no hole
  information": copy the file densely. Only `ENXIO` means end of data.
- **Tests:** injected `EINVAL` and `ENOTSUP` on a non-zero file restore
  identical bytes; a genuine all-hole file still restores as holes.

### 1.5 Btrfs stream chains — R04

- The send parent is derived from the *resolved* member kind, not the
  requested one. An image with no parent is sent without `-p`.
- Retained snapshots are bound to the destination, set and chain. A missing
  or mismatched required parent is refused.
- **Tests:** a full written after a `max_incrementals` rollover restores on
  its own; alternating two destinations with the same set name.

### 1.6 Confined restores — R06 (with R14)

- **New primitive** in `lr-unsafe`: descriptor-relative traversal
  (`openat2` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`; per-component
  `O_NOFOLLOW` on older kernels). All creation, deletion and metadata calls
  go through it.
- **Before any write**, validate the manifest's whole path and hard-link
  graph: no absolute paths, no `..`, no duplicates, no conflicting ancestor
  types. Stream subvolume paths are validated the same way.
- **R14:** the live source walk uses pinned descriptors, and metadata, the
  sparse map and the content come from the same open file.
- **Tests:** external sentinel files stay unchanged for absolute paths, `..`,
  symlinked ancestors inside the image, and pre-existing symlinks with
  `--merge`.

### 1.7 Image kind against target kind — A3

- `prepare` reads `/sys/class/block/<dev>/partition`.
  - A whole-disk image onto a partition is refused.
  - A partition image onto a disk that has a partition table needs an
    explicit acknowledgement, and the plan names the partitions that will be
    lost.
  - The GUI's review step shows the same.
- **Tests:** both cases on loop devices.

**Exit criteria:** every phase 1 regression passes, the root run has no
unavailable scenarios (phase 0 rules), and the Ubuntu host passes install and
GNOME checks. Release **`v0.1.0-alpha.2`**.

## Phase 2 — correctness, storage durability, security boundaries

### 2.1 Storage contract — R07, R08, R18, R19, R21, R39, A9

An explicit `lr-store` API replaces the single retry wrapper, because these
operations have different idempotency:

| Operation | Rule |
|---|---|
| create-temp | Random name, `O_CREAT \| O_EXCL \| O_NOFOLLOW`, inside the pinned set directory (R07) |
| sync | Mandatory before publication; SFTP uses the `fsync` extension or reports "not durable" explicitly (R19) |
| publish-new | Idempotent: a retry never deletes an image that is already final, it reconciles what is there (R18) |
| replace-catalog | Its own atomic replacement protocol |
| open-existing-set | For read paths; creates nothing (A9) |
| lease | Unique acquisition token, owner-checked refresh, lease loss reported to the engine before every publish or delete (R21) |

- **Spools (R08, R39):** per-job private scratch directories, one descriptor
  through write, rewind and read, and cleanup owned by one object.
- **Tests:**
  - A pre-planted `catalog.json.tmp` symlink is refused and the sentinel is
    unchanged.
  - A disconnect after the server-side rename but before its
    acknowledgement leaves the image complete.
  - A failed sync prevents both publication and snapshot cleanup.
  - An expired and resumed lease holder can neither publish nor delete.

### 2.2 Backup fidelity — R15, R16, R17, R30

- **R15:** an encryption request against an unencrypted parent is refused,
  with an offer to start a new encrypted chain. Plaintext is never published
  when encryption was requested.
- **R16:** identity, size, mtime and ctime are compared on the same
  descriptor before and after reading. On a change, retry, then report an
  unstable file instead of claiming per-file consistency.
- **R17:** `unchanged()` also compares ctime and inode. Whether content
  verification becomes the default is decision D-111.
- **R30:** the plan lists the Btrfs subvolumes it includes and excludes. A
  nested subvolume without its own mount is refused or explicitly excluded
  (D-112, because this follows the specification today).

### 2.3 Verification and recoverability — R20, R22, R23, R24, R25, R26

- **One validated restore plan,** shared by `verify` and `apply`. It checks
  entry counts, kinds, region bounds, sector geometry, complete manifest
  consumption, paths and hard links, file sizes and holes, the Btrfs layout
  record, and recorded bad sectors.
- **R24, R26:** an image that cannot be restored is refused at `prepare`,
  before the first target write.
- **R22:** `verify --chain` authenticates every stored payload of every
  member, not only the latest logical state. Reports distinguish "latest
  state verified" from "every recovery point verified".
- **R23:** single-member verification is defined explicitly: the member's own
  payloads, plus loading ancestry for its references.
- **R20:** the catalog distinguishes present, structurally valid and
  verified members. Retention never evicts the last verified chain in favour
  of a newer unverified one, and offers verify-before-retention.

### 2.4 Snapshots — R27, R28, R29

- **R27:** classify the parsed destination type. For local paths, resolve the
  nearest existing ancestor and compare filesystem identity *before*
  freezing.
- **R28:** the thaw helper takes an argument vector, with no shell
  interpolation, and recovery stays armed until a thaw succeeds.
- **R29:** check snapshot health after the final read and before
  publication.
- **Tests:** apostrophes and spaces in the mountpoint, a killed parent, and a
  final read delayed past the deadline, which must fail.

### 2.5 One request model — R31, A6 (groundwork for R35, R36)

- One validated `BackupOptions`/`RestoreOptions` model with tested
  conversions: CLI, protobuf, scheduler, GUI. An option that a route cannot
  honour is refused, never dropped.
- **A6:** `ListSets` and `ListChains` forward the caller's SSH options. The
  GUI selects daemon-side named destinations (`destination.configure`)
  instead of typing key paths.
- **Parity test:** every non-default option behaves the same directly and
  through the daemon, including a source tree that spans filesystems.

### 2.6 Exports — R09, A12

- Mount with `nodev,nosuid`, and `noexec` by default.
- Create the NBD socket in a private 0700 directory; a chmod failure is
  fatal.
- **Test:** the real mount flags from `/proc/self/mountinfo`, with harmless
  setuid and device-node fixtures.

### 2.7 Daemon resilience — A7, A8, A5

- **A8:** build the daemon with `panic = "unwind"` and wrap every job in
  `catch_unwind`, recording a panic as a job failure. Run destructive restores
  in a separate process.
- **A7:** a finite, documented `TimeoutStopSec`; log and notify which job
  holds the stop; time out destination I/O; refuse new restores during
  shutdown (D-113, refining D-107).
- **A5:** unique IDs and a counting semaphore for verifications instead of
  the shared `"verify"` set.

### 2.8 GUI and polkit — R32, A10

- **R32:** add `RestoreApply` to `allows_interaction`. Verify on the Ubuntu
  GNOME host that the administrator dialog appears; this also closes the
  deferred "backup from the GUI in GNOME" check.
- **A10:** a "restore into this folder, replacing files with the same name"
  choice in the restore wizard, with its consequences in the summary. It
  lands only after 1.6.

**Exit criteria:** as for phase 1, plus the storage fault-injection tests.
Release **`v0.1.0-beta.1`**.

## Phase 3 — daemon boundary, metadata, scheduling

| ID | Work |
|---|---|
| A4 | Never open client-named secret files as root: receive a descriptor (`SCM_RIGHTS`) or open with the caller's credentials; at minimum require the owner to be the caller. Honour `insecure_ignore_host_key` only in dev mode |
| R12 | Open passphrase files non-blocking, validate the descriptor, reject FIFOs, and move file I/O off async request threads |
| R10 | Bind jobs to the initiating UID; cancelling another user's job is a separate administrator action |
| R13 | `known_hosts`: require a positive match with no matching negation; `@revoked` wins regardless of order; unknown directives fail closed |
| A11 | Single-use restore tokens (consumed nonces kept until expiry), bound to the preparing UID |
| R33 | A strict restore mode that fails on required metadata loss, and a best-effort mode with structured per-path warnings |
| R34 | Restore barriers: sync files, then directories, before reporting completion |
| R35 | systemd-specific escaping for `ExecStart` and unit values; strict job names |
| R36 | Forward identity and `known_hosts` to scheduled jobs; implement `new_chain_on_calendar` or reject it; audit every accepted field |
| R37 | Order whole-disk regions by LBA while keeping the original partition numbers |
| R38 | Drain or terminate helper tools on a parse failure, with a timeout |

## Phase 4 — structure and documentation

- **Operator documentation:**
  - Differential semantics, and that the whole chain must be kept (D-114).
  - Used-block images are not forensic copies.
  - XFS with an external log or realtime device is refused.
- **Scale:** profile million-file trees, large xattr sets and long chains,
  then set memory budgets.
- **Fault injection** at read, sync, rename, lease renewal, snapshot timeout
  and publication, as a permanent suite.
- **Stale comments** that promise protections the code lacks (sparse
  fallback, RestoreApply prompting) are corrected with their fixes.

## Shared mechanisms

Each is built first within its phase; the findings in the right column
depend on it.

| Mechanism | Crate | Findings |
|---|---|---|
| Exclusive device claim | `lr-unsafe`, `lr-blocksource` | A1, A2, R05 |
| Descriptor-relative file operations (`openat2`) | `lr-unsafe` | R06, R14, R07, R08, A4 |
| Image-wide nonce allocator | `lr-format`, `lr-crypto` | R01 |
| `SetName` and identifier validators | `lr-core` | R02, R35, R36 |
| Validated restore plan | `lr-engine` | A3, R06, R20, R22–R26 |
| Storage contract (create, sync, publish, replace, lease) | `lr-store` | R07, R08, R18, R19, R21, R39, A9 |
| One request model | `lr-core`, `lr-proto` | R31, A6, R27, R35, R36 |
| Job isolation (unwind or process) | `lr-daemon` | A8, A7 |

## Decisions to record

| ID | Question |
|---|---|
| D-110 | Status of existing encrypted v1 images after the R01 fix |
| D-111 | Default change detection for file incrementals: metadata with ctime, or content verification |
| D-112 | Nested Btrfs subvolumes: recursive enumeration or explicit refusal |
| D-113 | Daemon stop-timeout policy (refines D-107) |
| D-114 | Differential semantics: keep and document the specified behaviour, or adopt the conventional one |
| D-115 | Grammar for set, chain and job names |

## Sequence and effort

| Step | Content | Estimate |
|---|---|---|
| Phase 0 | Release warning, honest tests, regression scaffold | 1 session |
| Phase 1 | Seven P0 blocks; 1.6 (`openat2`) is the largest | 4–6 sessions |
| → `alpha.2` | | |
| Phase 2 | Storage contract, restore plan, request model, daemon resilience | 6–8 sessions |
| → `beta.1` | | |
| Phase 3 | Daemon boundary, metadata, scheduling | 3–4 sessions |
| Phase 4 | Documentation, scale, fault injection | 2–3 sessions |

**Acceptance for every phase:**

- The phase's regression tests pass.
- `cargo xtask ci` exits 0.
- A root run with no unavailable scenarios, reported as executed, ignored and
  unavailable counts.

Phases 1 and 2 also need an install and GNOME/polkit check on the Ubuntu
test host.

## Finding index

Priorities: P0 = fix before trusting the feature with irreplaceable data;
P1 = before production use of that workflow; P2 = next milestone;
P3 = cleanup.

| ID | Priority | Finding | Work item | Done |
|---|---|---|---|---|
| R01 | P0 | Metadata streams reuse AEAD nonces under one key | 1.2 | ☑ |
| R02 | P0 | A set name of `..` redirects Btrfs cleanup into the source | 1.3 | ☑ |
| R03 | P0 | Unsupported sparse seeking restores data as zeros | 1.4 | ☑ |
| R04 | P0 | Btrfs send parents do not match catalog parents | 1.5 | ☑ |
| R05 | P0 | Swap recreation can format a stale partition extent | 1.1 | ☑ |
| R06 | P1 | File and Stream restores are not confined to the target | 1.6 | ☑ |
| R07 | P1 | Catalog temporary-file symlink redirects root writes | 2.1 | ☐ |
| R08 | P1 | Shared scratch spool permits manifest substitution | 2.1 | ☐ |
| R09 | P1 | NBD inspection mounts keep setuid and device nodes | 2.6 | ☐ |
| R10 | P2 | Read permission can cancel another user's job | 3 | ☐ |
| R11 | P2 | Unauthenticated Argon2 parameters choose resource use | 1.2 | ☑ |
| R12 | P2 | A passphrase FIFO blocks request threads | 3 | ☐ |
| R13 | P2 | `known_hosts` negations and revocations not enforced | 3 | ☐ |
| R14 | P2 | Live file backup can follow replaced ancestors | 1.6 | ☑ |
| R15 | P1 | Requested encryption ignored on a plaintext chain | 2.2 | ☐ |
| R16 | P1 | Live file backups lack per-file stability checks | 2.2 | ☐ |
| R17 | P1 | Incrementals miss changes that keep size and mtime | 2.2 | ☐ |
| R18 | P1 | SFTP retry can delete an already published image | 2.1 | ☐ |
| R19 | P1 | SFTP success does not establish durability | 2.1 | ☐ |
| R20 | P1 | Retention can delete the last usable chain | 2.3 | ☐ |
| R21 | P1 | Lease refresh can overwrite a replacement lock | 2.1 | ☐ |
| R22 | P1 | `verify --chain` misses corrupted superseded payloads | 2.3 | ☐ |
| R23 | P2 | Default verification rejects valid non-full members | 2.3 | ☐ |
| R24 | P1 | Whole-disk manifests can restore an incomplete region | 2.3 | ☐ |
| R25 | P2 | File and Stream verification skip restore-required checks | 2.3 | ☐ |
| R26 | P1 | Known bad sectors are rejected only after target writes | 2.3 | ☐ |
| R27 | P1 | Local destinations bypass the freeze same-filesystem guard | 2.4 | ☐ |
| R28 | P1 | Apostrophes in mountpoints break both thaw deadmen | 2.4 | ☐ |
| R29 | P2 | The final source read can outlive snapshot health | 2.4 | ☐ |
| R30 | P1 | Unmounted nested Btrfs subvolumes are silently omitted | 2.2 | ☐ |
| R31 | P1 | Backup options disappear when the CLI uses the daemon | 2.5 | ☐ |
| R32 | P2 | Restore apply cannot request its polkit dialog | 2.8 | ☐ |
| R33 | P2 | File restore drops metadata failures | 3 | ☐ |
| R34 | P2 | File restore reports success without a durability barrier | 3 | ☐ |
| R35 | P2 | Generated systemd commands are not escaped | 3 | ☐ |
| R36 | P2 | Accepted scheduling fields are ignored | 3 | ☐ |
| R37 | P2 | Whole-disk backup rejects legal partition numbering | 3 | ☐ |
| R38 | P2 | Filesystem-tool parse errors can deadlock a job | 3 | ☐ |
| R39 | P3 | Block-backup failure cleanup targets the wrong spool | 2.1 | ☐ |
| R40 | P2 | Integration tests pass when setup fails | 0.2 | ☑ |
| A1 | P0 | Restore writes over a filesystem mounted in another mount namespace (no `O_EXCL`) | 1.1 | ☑ |
| A2 | P0 | A device mounted elsewhere is backed up as `consistency: offline` | 1.1 | ☑ |
| A3 | P0 | Image kind and target kind are not matched | 1.7 | ☑ |
| A4 | P2 | `VerifyImage` makes root read client-named secret files and skip host keys | 3 | ☐ |
| A5 | P1 | All verifications share one job set | 2.7 | ☐ |
| A6 | P1 | SFTP unusable through the daemon from the GUI; list calls drop SSH options | 2.5 | ☐ |
| A7 | P1 | Infinite stop timeout can hang shutdown | 2.7 | ☐ |
| A8 | P1 | One panic ends every job, including a running restore | 2.7 | ☐ |
| A9 | P2 | Read-only operations create set directories | 2.1 | ☐ |
| A10 | P2 | The GUI cannot restore files into a non-empty folder | 2.8 | ☐ |
| A11 | P2 | Restore tokens are reusable and not bound to the caller | 3 | ☐ |
| A12 | P3 | NBD socket chmod after bind, failure ignored | 2.6 | ☐ |
| A13 | P1 | `--parent latest` picks an arbitrary chain when two chains start in the same second (found while fixing R04, D-116) | 1.5 | ☑ |
