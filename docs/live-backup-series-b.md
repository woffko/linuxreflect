# Live backup series B: incremental and differential live images

Status, 2026-11-12: B1–B4 are done (D-142). The B2 stop point did not
apply: the format already carries a full or delta manifest per region. The
VM acceptance of a live incremental passed on Debian 12 and Ubuntu 24.04
under UEFI with Secure Boot (`docs/live-backup-acceptance.md`).

Slice 18 follow-up to `docs/live-backup-plan.md` (phases 0–4 and the
automatic choice of D-141 are done). Goal: on a running Debian or Ubuntu
system, take a full live image of the system disk, keep the system running,
take an incremental live image that stores only the changed chunks, restore
the chain onto another disk, and boot it.

## Ground rules

- One branch `s18/incrementals` from `main`; commits per step (B1–B4); one
  pull request into `main` at the end. Merging is the maintainer's decision.
- The specification is frozen (`docs/spec/linuxreflect-spec-v2.1.md`, v2.2).
  Where it is silent, record a minimal decision in `docs/decisions.md`.
- Achieved consistency is always reported truthfully: a live member is
  `Frozen`, never `PointInTime`.
- Sources are read-only. Destructive commands only on devices a test created
  (loop images, dm targets, qemu disks).
- Never weaken a test to make it pass. Everything for GitHub is in English.

## B1 — Incremental and differential members of a partition

- Lift the interim refusal of tracked-freeze incrementals and differentials
  (`crates/lr-engine/src/backup.rs`, "tracked-freeze makes full images in this
  release").
- Pass 1 compares chunks with the parent's manifest (positional
  scan-and-diff, as the offline and LVM paths do). Later passes and the final
  read write delta entries; the manifest names the last copy of every
  changed chunk (§E.7 "a chunk may be stored more than once").
- Refused before tracing starts: a parent whose chunk size or source size
  (chunk count) differs, the existing chain rules. The chain is resolved
  under the set lock before the snapshot is made. (Images record no source
  device identity, and device paths change between boots, so a member of
  another device of the same size is not detectable; the positional diff
  stays correct for it, only larger.)
- Root tests (`crates/lr-engine/tests/root_tracked.rs`):
  - full → (writer keeps running) → incremental → differential, all live;
  - each member restores onto another loop disk: `e2fsck -fn` clean,
    `needs_recovery` clear, the writer's log is an exact prefix ending inside
    that member's backup window, every file whose last write completed
    before the freeze has its final content;
  - the incremental stores clearly fewer chunks than the full;
  - `verify` of the chain passes and finds a corrupted member;
  - the same through `auto` with `--allow-freeze`;
  - `an_incremental_is_refused_in_this_release` is replaced.

## B2 — Whole-disk chains (every provider)

Closes D-042 with a new decision (D-142) on region identity.

- An incremental or differential whole-disk member matches its parent's
  regions by index, start, size, type GUID and PARTUUID. Each region gets
  its own delta manifest; the leading area, BIOS boot and the ESP use the
  same positional delta.
- A partition table or region layout that differs from the parent's refuses
  the member with the advice to take a full image.
- `restore`, `verify`, retention and the catalog handle whole-disk chains.
- **Stop point.** First check that the format suffices (each region already
  has a `BlockManifestHeader` with a full/delta flag; the whole-disk reader
  currently refuses delta). If a change to the `.lrimg` format or to the
  specification is needed, stop: deliver B1 in the pull request, describe the
  problem and the options for B2 in it, and ask the maintainer. Reaching this
  stop point also completes the series goal.
- Root tests:
  - an offline whole-disk chain full → incremental → differential restores
    with matching data;
  - a live chain of a busy system disk (ESP + ext4) restores clean: the
    partition table matches, `e2fsck` is clean, the ESP matches;
  - a partition table changed between members is refused;
  - `verify` finds a corrupted member;
  - every existing whole-disk test stays green.

## B3 — VM acceptance

- `tools/vm/live_restore_matrix.py` gains a step: a full live image → the
  writer keeps running → an incremental live image → the chain is restored
  onto `/dev/vdc` → only `vdc` is booted.
- A run passes with `multi-user.target`, no failed unit, no ext4 journal
  recovery, and the writer's log a whole hash chain inside the incremental's
  window.
- At least Debian 12 UEFI and Ubuntu 24.04 UEFI; all six configurations when
  time allows (TCG: about 10 minutes per configuration and member).
- Results go into `docs/live-backup-acceptance.md`.

## B4 — GUI and documentation

- The backup wizard allows incremental and differential members with
  tracked-freeze and for whole disks (no refusal).
- The library shows whole-disk chains; a restore picks a chain member.
- A GUI root test: a live incremental through `auto` with the live-copy
  consent, then its restore.
- Update `docs/operator-guide.md`, `docs/live-backup-plan.md`, `AGENTS.md`
  and `docs/decisions.md`.

## Done when

- `cargo xtask ci` exits 0.
- Locally under WSL root, every root suite the changes touch is green with no
  unavailable markers: `root_tracked`, `root_whole_disk`, `root_gui`,
  `root_daemon`, `root_tracking`, the chain suites and any other touched one.
- The pull request is open; its checks and a CI run with the root lane on the
  branch (`gh workflow run ci.yml --ref s18/incrementals`) are green, and no
  new test is in the root lane's unavailable list.
- Or: work stopped at the B2 stop point, with B1 delivered and the question
  in the pull request.
