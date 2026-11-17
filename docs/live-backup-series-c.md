# Live backup series C: the Slice 18 release gate and a pre-release

Slice 18 follow-up to `docs/live-backup-plan.md` and
`docs/live-backup-series-b.md` (phases 0–4, the automatic choice of D-141
and the live chains of D-142 are done). Goal: pass the plan's "Release gate
for Slice 18" in full on one commit, and prepare the pre-release
`v0.2.0-beta.1` that ships tracked-freeze as an opt-in. That pre-release
starts phase 5, the field trial.

## Ground rules

- One branch `s18/release-gate` from `main`; commits per step (C1–C4); one
  pull request into `main`. Merging is the maintainer's decision, and so is
  publishing: no tag, release or upload happens before the maintainer says so
  in the conversation.
- The specification is frozen (`docs/spec/linuxreflect-spec-v2.1.md`, v2.2).
  Where it is silent, record a minimal decision in `docs/decisions.md`.
- The gate is not adjusted to pass. A failure is fixed in the code or in the
  test fixture's handling of the environment, in its own commit with a test
  that fails before the fix. A scenario is never marked unavailable to make a
  run clean. Never weaken a test.
- Sources are read-only. Destructive commands only on devices a test created
  (loop images, dm targets, qemu disks).
- The Ubuntu test host `192.168.189.142` is shared with other sessions. Before
  using it, ask the running sessions (`ListAgents`) whether it is busy, and
  wait if it is. Never reboot it without asking the maintainer.
- Everything for GitHub is in English.

## C1 — The root gate

- Prepare WSL: `modprobe nbd nbds_max=16 && systemctl start polkit`.
- `LR_ROOT_RUNNER="wsl.exe -u root --" cargo xtask root` reports every
  binary run, none failed, `unavailable: 0` and `leftovers: none`. This is the
  whole suite, including GRUB, NFS, SMB, sway and the rescue medium, not only
  the suites series B touched.
- `cargo xtask ci` exits 0.
- Fix stale records found on the way, for example `docs/versions.md` still
  pins russh 0.63.3, while 0.65.1 has been pinned since RUSTSEC-2026-0495.

## C2 — Scale

- `cargo xtask scale` passes with every profile within its budget.
- Add a profile for whole-disk chains, which have opened every member at once
  since D-142 (one cursor per member in `chain::DiskWalk`). A GPT disk in an
  image file gets one full and 199 incrementals, each changing a few chunks.
  The restore and the `verify --chain` of member 200 must stay within a
  budget. If the CLI cannot take an image file as a whole-disk source without
  root, put the profile in a root suite and say so.
- Record the measured peaks and the new budget in `docs/performance.md`. The
  budget leaves 25–40 % over the measured peak, as the other profiles do.

## C3 — The full VM matrix with a live incremental

- Build the static CLI from the branch head (musl, stripped).
- Run `python3 tools/vm/live_restore_matrix.py --cli … --out … --incremental`
  over all six configurations: Debian 12, Debian 13, Ubuntu 22.04 and
  Ubuntu 24.04 under UEFI with Secure Boot, and Debian 12 and Ubuntu 24.04
  under BIOS.
- Every configuration passes on the same CLI build. A pass means the restored
  chain boots alone to `multi-user.target`, with no failed unit and no ext4
  journal recovery. The writer's log must be a whole hash chain inside the
  incremental's window.
- Record the results in `docs/live-backup-acceptance.md`, replacing the
  two-configuration table of series B3: member sizes, passes and freeze
  lengths for each configuration, and the commit they ran on.

## C4 — The pre-release, prepared but not published

- Set the workspace version to `0.2.0` (with the lock file).
- Add a "Field trial" section to `docs/operator-guide.md`: how to opt in
  (`--snapshot tracked-freeze`, or `auto` with `--allow-freeze`), what to send
  back from the report (freeze length, passes, convergence, refusals and
  their reasons, kernel and disk type), and how to test a restore before
  relying on an image.
- Build the artifacts from the pull request's head commit, named as in
  `v0.1.0-beta.2`:
  - the stripped static musl CLI;
  - the glibc tarball (CLI, daemon, GUI, session notifier, rescue tool and
    `contrib/`), built on Ubuntu 22.04 (glibc 2.35), that is on the test host
    after asking the other sessions, as the earlier betas were;
  - the rescue image (`contrib/rescue/build-mkosi.sh`, zstd), which must boot
    to `LINUXREFLECT-RESCUE-READY graphical` under SeaBIOS and under OVMF
    with Secure Boot;
  - `SHA256SUMS` over the three files.
- On the test host, install the tarball (`contrib/install-host.sh`) and
  confirm that the running daemon is the packaged binary.
- Where the test host offers a destination off its system disk without
  changes to the VM, also take one live tracked-freeze image of its system
  disk through the installed daemon and verify it. That is a first data point
  outside qemu (VMware, a real desktop). If no such destination exists, say
  so in the notes instead.
- Draft the release notes in the format of `v0.1.0-beta.2` and put them in the
  pull request description:
  - what is new: live images, live chains, the automatic choice with
    consent, hooks, `--freeze-max`, and the GUI option;
  - Known issues:
    - tracked-freeze is opt-in;
    - the spec's `--allow-inconsistent` exception for a busy ESP is not
      implemented, so the job fails instead;
    - ext4 on plain partitions only (no LUKS, md, xfs or Btrfs through this
      provider);
    - restore to a disk of the same size or larger;
    - shared UUIDs on a second disk (D-139);
    - the GUI flow inside a VM with a boot of the restored disk is not run;
    - not yet tried on real hardware;
  - Tested: the C1–C4 evidence;
  - Assets.

## Stop point

If the gate cannot pass without a change to the `.lrimg` format or the
specification, stop: put what passed and the problem with its options in the
pull request, and ask the maintainer. Reaching this stop point also completes
the series goal.

## Done when

- `cargo xtask ci` exits 0 on the pull request's head.
- `cargo xtask root` on that head reports no failed binary, `unavailable: 0`
  and `leftovers: none`.
- `cargo xtask scale` passes, including the new whole-disk chain profile.
- The VM matrix passes 6 of 6 with `--incremental` on a CLI built from that
  head.
- The artifacts and `SHA256SUMS` are built from that head, the rescue image
  booted under SeaBIOS and OVMF with Secure Boot, and the tarball was installed
  on the test host.
- The pull request is open with the release notes draft. Its checks and a CI
  run with the root lane on the branch
  (`gh workflow run ci.yml --ref s18/release-gate`) are green, and no new test
  is in the root lane's unavailable list.
- The maintainer has been asked to merge and to approve publishing
  `v0.2.0-beta.1`.
- Or: work stopped at the stop point, with the question in the pull request.

## After the maintainer approves (not part of the goal)

- Tag the merge commit `v0.2.0-beta.1`, after checking that its tree is the
  tree the artifacts were built from (`git rev-parse <commit>^{tree}`);
  otherwise rebuild.
- Publish the pre-release with the four assets, and check that the downloaded
  assets verify against `SHA256SUMS`.
- Record the release in `AGENTS.md` and `docs/live-backup-plan.md` (phase 5
  started) in the next pull request.
