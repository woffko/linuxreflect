# Redesign ideas

These are proposals for discussion, not an approved implementation plan. They
come from the single-source-of-truth review of `99afcb5`, refreshed against
`553c2db` on 2026-09-28. Keep the frozen specification intact; record decisions
before changing format semantics or operator-visible guarantees.

## Implementation follow-up, 2026-10-02

The discussion below preserves the original review context. Subsequent work
has implemented these parts without claiming production acceptance for every
deployment:

- D-125 makes retention require fresh verification of a kept, complete-recovery
  chain before deletion. Catalog timestamps remain advisory; this is not the
  durable verification-history store proposed in idea 6.
- D-126 adds opt-in required-mount identity checks to named destinations. D-128
  identifies the visible kernel mount, including systemd automount stacks.
  Checks do not pin the mount against a later replacement.
- D-127 preverifies selected restore payloads before target mutation, retaining
  checks during writes. This reduces avoidable partial restores; it does not
  make a restore transactional or freeze the backing storage.
- D-129 makes achieved consistency authoritative for the redundant wire flag,
  controlled writer updates and reports. Contradictory image headers are
  rejected, addressing idea 3 without a format-layout change.
- D-130 introduces an immutable resolved backup plan for Block, File and
  Stream producers, addressing idea 2's repeated parent/policy resolution.
  Reports distinguish logical policy from encoding. A v1 header-only catalog
  still cannot recover a File member's historical comparison policy; its
  structural `kind` is not authority for that missing fact.

- D-131 makes terminal events and `GetJob` project the same retained outcome,
  including successful reports. GUI reconnect preserves result details and
  explicitly reports unavailable legacy/malformed reports. Results still last
  only for the daemon process's lifetime, addressing idea 5 below.

Durable content-bound verification history and SFTP stale-writer fencing remain
separate work. The history design compares fresh-only checks, a host-local
receipt ledger and portable per-set receipts. No store is implemented or selected;
the captured-byte approach needs an approved ancestry-sized scratch/I/O budget.
All choices retain D-125's fresh deletion gate. Historical maintainer acceptance
results below are not evidence that the current tree passed privileged tests
on this user's machine.

## One owner for each fact

Every property needs one authoritative meaning, an owner, and controlled
transitions. Other representations must be derived from it, with explicit
freshness and invalidation rules. This does not require one global state object
or the same struct for the protocol, engine and UI.

Requested behavior, resolved behavior and achieved behavior are different facts.
Preserve those distinctions instead of passing the original request wherever an
execution result is needed.

| Fact | Proposed owner | Adapters and derived views |
|---|---|---|
| Validated user intent | Validated domain request | CLI, protobuf, GUI and scheduler adapters |
| Effective backup choices | Resolved execution plan | Image names, writer settings and plan summaries |
| Achieved image facts | Finalized image model | Superblock fields, redundant flags, footer and reports |
| Image and chain semantic validity | Shared validation code | Verify results and restore preflight decisions |
| Runtime job outcome | Daemon job registry | Progress events, status responses and GUI views |
| Verification evidence | Record bound to the checked image content and scope | Catalog summaries and retention decisions |

Device identity and readiness remain live observations. A cached device list or
an approved plan does not replace checking the claimed target before writes.

## Changes since the original review

There are 50 commits between `99afcb5` and `553c2db`. The relevant improvements
include:

- `5831c91` added [`lr-request`](../crates/lr-request/src/lib.rs). CLI direct
  execution and daemon execution now use `backup_job` and `run_backup`.
  `max_incrementals` reaches the engine, so the earlier dropped-option finding
  is addressed.
- `26c383b`, `df44f37` and `2511629` introduced shared checks in
  [`plan.rs`](../crates/lr-engine/src/plan.rs). File-tree semantics and required
  Stream layout parsing are now checked across verification and restore paths.
  `c91feaa` adds ancestry-aware verification and checks superseded payloads.
- `a85d12a` adds retention protection for usable and previously verified chains.
  Its evidence ownership still needs the safeguards described below.
- `0830cae` makes a catalog-update failure a warning after successful image
  publication. This preserves the distinction between the image and its cache.
- `762e087` reduces duplicated file metadata in memory. Keep these ownership
  improvements when introducing shared models; avoid cloning a whole tree into
  each consumer. See the measured budgets in [performance.md](performance.md).

## 1. Finish request normalization

Build on `lr-request` rather than restoring separate CLI and daemon builders.
Resolve defaults and reject unsupported options at a single boundary. Extend
the same discipline to restore requests and scheduler configuration.

The current shared backup conversion takes protobuf `BackupSpec` directly, and
its `BackupJob` exposes mutable fields. If another API or execution system is
added, introduce a protocol-independent validated request where that separation
is useful. Keep wire compatibility and caller authorization in their adapters.
Prefer small types with private invariant-bearing fields over a general
configuration framework.

Acceptance: every non-default supported option produces equivalent engine
behavior through direct, daemon and scheduled routes. Invalid combinations are
refused by every route. Keep `every_option_reaches_the_job` and the daemon-route
test as regression coverage, and add equivalent checks for new fields.

## 2. Separate backup policy, chain role and manifest encoding

The distinction is still incomplete at the refreshed revision. Parent resolution
can turn an incremental request into a new full image, but filenames and some
descriptive metadata still use `request.member_type`. Reports use the resolved
kind. See [`backup.rs`](../crates/lr-engine/src/backup.rs),
[`file.rs`](../crates/lr-engine/src/file.rs) and
[`stream.rs`](../crates/lr-engine/src/stream.rs).

File mode also reports a non-rollover incremental as `Incremental`, while its
full-tree manifest has no delta flag. `chain::member_kind` classifies a
noninitial, non-Stream member without that flag as `Differential`. These labels
currently describe different concepts as though they were one property.

Create a resolved backup plan that owns the chosen parent, chain role and
encoding. Generate names, metadata and reports from those facts. Decide how to
represent logical backup policy independently of encoding, including what older
images can establish. Do not set a delta flag on a full-tree manifest merely to
change its catalog label. Preserve the differential semantics recorded in D-114
unless a separate decision changes them.

Acceptance: exercise ordinary incrementals, differentials and rollover to full
in each supported mode. Reports, catalog labels and filenames must follow the
documented interpretation of the same resolved plan.

## 3. Finalize achieved image facts once

`Superblock.consistency` and the `INCONSISTENT` flag remain independently
maintained. Prepare warnings inspect the enum; block apply checks the flag.
`Superblock::validate_header` does not require their agreement. The unstable-file
path updates a local consistency variable, the superblock field, the flag and
the writer's header copy separately.

Give achieved facts a controlled update path. Derive redundant wire fields and
reports from the finalized facts, and reject contradictory combinations when
decoding. Retain the existing format where possible: redundant fields are safe
when their agreement is enforced. Keep one owner for the metadata nonce sequence,
as [`ImageWriter`](../crates/lr-format/src/writer.rs) already does.

Acceptance: downgrading consistency updates every representation; a contradictory
header is refused. Verify, prepare and apply classify consistency the same way;
restore acceptance uses that shared classification.

## 4. Share validation results as well as helper functions

The new `plan` module is progress toward one definition of a restorable image.
Preserve it as the home for shared semantic checks. Consider a validated
image/chain representation that records which checks ran and which content they
covered, instead of letting each consumer assemble a different subset of checks.

Keep structural validity, payload integrity, source consistency and target
readiness distinct. A warning-bearing verification is not automatically evidence
that every recovery point can be restored. Bind validation to the actual members
checked, and define how reopened or changed images invalidate it. Full payload
checking and live target checks remain separate operations; neither makes a
destructive restore transactional.

Acceptance: malformed manifests and missing layout data receive consistent
decisions from verify and restore preflight. Changing an image after validation
must invalidate the result or trigger the required checks again before writing.

## 5. Make job status a complete projection

The daemon registry already owns runtime outcomes, but successful summaries are
still lost in its status projection. `Jobs::finish` stores `summary_json`, while
`service::job_state_of` builds `progress` only from errors. The GUI's successful
`GetJob` recovery expects a finished summary and substitutes an empty string
when it is absent. See [service.rs](../crates/lr-daemon/src/service.rs) and
[actions.rs](../crates/lr-gui/src/actions.rs).

Make the authoritative job snapshot sufficient to reconstruct the result after
an event-stream interruption. Treat progress events as updates to a projection,
not the only place where a result exists. Document the registry's process-lifetime
limit; durable history or restart recovery would require a separate decision.

Acceptance: normal completion and reconnect/status recovery display the same
result, warnings and image details. Test successful serialization, not only
internal summary retention and cancellation responses.

## 6. Separate verification evidence from rebuildable catalog data

Image headers are authoritative for catalog topology. Verification history is
different: it cannot be reconstructed by scanning those headers. The new
`verified_unix` field is stored only in `catalog.json`; a missing or unparseable
catalog loses it. Carry-forward identifies members by UUID, name and size, which
does not detect same-size content changes. Recording verification resolves names
again after verification rather than carrying exact checked-member identities
in the report. See [catalog.rs](../crates/lr-engine/src/catalog.rs) and
[verify.rs](../crates/lr-engine/src/verify.rs).

Define durable verification evidence separately from the catalog cache. Bind it
to content identity, member set, verification scope and outcome. Missing evidence
must be treated as unknown. Choose an explicit retention policy for that state,
including encrypted chains whose keys are unavailable. Keep unconfirmed storage
durability separate from successful content verification.

Acceptance: test missing and corrupt catalogs, same-size image replacement,
changes between verification and recording, and reports with recorded bad
sectors. Losing a cache must not silently remove the protection for the last
qualifying recovery chain.

## Remediation-plan follow-up

[remediation-plan.md](remediation-plan.md) now records phases 0-4 complete and
beta.2 released from `78ed1f4`. It reports 599 CI tests, 67 root scenarios and
passing scale profiles. Those are the maintainer's recorded results, not gates
rerun by this review. The architecture proposals above remain separate from the
original finding checklist.

Two acceptance contracts still need attention:

- R21 promises that an expired, resumed holder cannot publish or delete. Commit
  `10bd9bc` serializes a holder's own SFTP refresh and check, but its local mutex
  cannot fence another process replacing the remote lock. D-120 still documents
  the check/write race. Either require enforceable fencing or explicitly restrict
  stale takeover; add a deterministic cross-holder interleaving test. A lease
  check followed by a separate mutation is not an atomic ownership guarantee.
- R20 now protects a verified chain while its evidence remains available, but
  the catalog-loss and content-binding cases in idea 6 need explicit coverage.
  A green ordinary-retention test does not cover loss of the verification cache.

Update the plan's implementation references when next editing it: the shared
request conversion is in `lr-request`, not just `lr-core` and `lr-proto`.
D-122 explicitly declines process isolation; D-124 keeps the XFS data-device raw
fallback with warnings rather than refusing external-log/realtime layouts. Treat
those as recorded scope choices, not unimplemented original wording.

## Validation of this update

On `553c2db`, the following offline, unprivileged checks passed:

```sh
cargo test --offline --locked -p lr-request --lib
cargo test --offline --locked -p lr-engine --lib \
  --test retention --test fault_injection --test snapshot_health
```

Results: 103 passed, zero failed, one explicitly ignored root test. This was a
targeted review of the earlier design concerns, not a fresh audit of all 56
findings. No full CI, root, installed-GNOME, rescue or scale run was performed.
The residual R20 and R21 cases above were identified from source, not reproduced
by these tests.
No application code or remediation completion checkboxes were changed.

For each future feature, record its state owner, meaning, allowed transitions,
derived views, invalidation rules and boundary tests before adding another copy
of a property. Introduce the changes in small steps around the existing shared
request and validation code.
