# Project agent instructions — LinuxReflect

## What this project is

LinuxReflect is a Rust implementation of the technical specification at
`docs/spec/linuxreflect-spec-v2.1.md`. The specification is frozen: implement it,
do not redesign it. Where the specification is silent, record the decision in
`docs/decisions.md` and keep it minimal.

The MVP is slices S1–S11 (spec §K). Slices are landed one pull request each.
Current state: S1 (workspace, `lr-core`, `lr-unsafe`, capability probe,
`disk list`/`caps`), S2 (partition discovery, `disk map --json`), S3/S4 (the
`.lrimg` codec), S5 (`lr-fsmap` used-block maps), S6 (block backup/restore with
the offline provider), S7 (whole-disk images and boot verification) and S8
(LVM/thin, freeze with deadman, live-none, Btrfs tree snapshots and Stream mode
with `btrfs send -p`) and S9 (full/incremental/differential chains with delta
manifests and positional scan-and-diff, the validated catalog, `parent=latest`
and the leased set lock). S10 (local, mounted and SFTP destinations with an
exclusive-create lock over SSH, retry with backoff and strict host-key
verification) is complete. S11a (`verify`, which names the corrupted chunk) is
complete, and S11b (the gRPC daemon over a Unix socket, polkit authorization
with pidfd-backed peer identity, in-memory jobs with `WatchEvents`, socket
activation, the polkit policy and the CLI client mode with an in-process
fallback) is complete: **the spec §K MVP boundary is reached**. Slice S12 (file
mode: tree walking with `O_NOFOLLOW`/`SEEK_HOLE`/xattrs/ACLs/hard links,
`--one-file-system`, Btrfs-snapshot sources, restore into an existing
directory, the read-only `lr-fuse` view, and file-aware `verify`) is complete
as well.

The acceptance evidence for S11b: `cargo xtask ci` = 0, every root suite green
(S1–S2, S5–S6, S7, S8a, S8b, S9, S10, S11), the static musl CLI builds, and the
root daemon suite covers the full CLI round trip through the daemon on loop
devices, real polkit 124 (a non-root peer is denied, root is allowed) and
`LISTEN_FDS` socket activation. For S12 the evidence is `rsync -naxci --delete`
reporting nothing between a source tree and its restored copy, `sha256sum`
matching through the FUSE mount, and root tests covering device nodes,
ownership, xattrs, `--one-file-system` and a Btrfs-snapshot (`PointInTime`)
source. For S13 the evidence is a root suite that exports an ext4 and an xfs
image through our newstyle NBD server, mounts both read-only with the spec's
options, reads files byte-identically, proves writes are refused and unmounts
and unexports cleanly — through the CLI and through the daemon. ublk stays
optional and unimplemented (D-078). S14 (scheduling, retention, session
notifications) is complete: retention keeps exactly `keep_chains` whole chains,
a generated `linuxreflect-job@<name>.timer` fires a real backup under systemd,
and `linuxreflect-session` posts a real `org.freedesktop.Notifications.Notify`
call on a session bus; that call is now verified against a real Wayland
notification daemon (`mako` on a headless `sway` session, D-103) as well as the
earlier mock service (D-087). S15 (the Slint
GUI: disk map, backup wizard with the plan and consistency, restore wizard with
the token, progress and history) is complete under Slint's Royalty-Free 2.0
option with attribution (D-090); create and restore were run through the GUI on
X11 (with `xdotool` proving the window is mapped) and on Wayland (weston's
headless backend), both verified against the restored files on disk. S16
(rescue media and boot repair): the assembled rescue medium boots
under SeaBIOS and under OVMF with Secure Boot (an unsigned loader is rejected as
a control), a restored ESP boots again after `boot-repair`, and a `sfdisk -d`
dump recreated on a fresh disk keeps the partition and filesystem UUIDs. The
`contrib/rescue/mkosi.conf` profile now also builds a real 3.1 GB image
(mkosi 28, built in a privileged ubuntu:24.04 container because mkosi's build
sandbox cannot resolve DNS in WSL) with the signed shim/GRUB chain, and that
image carries the static `linuxreflect` CLI plus the Slint GUI built for noble,
a rescue systemd session, `cage` with the Wayland software renderer and the TUI
fallback, and boots to `LINUXREFLECT-RESCUE-READY graphical` (running the GUI)
on SeaBIOS and on OVMF Secure Boot (D-101). The assembled medium also restores
an image to a bare disk with no human at the console (kernel-command-line
autorun) and the restored disk boots; that is the
`a_bare_metal_restore_from_the_medium_boots` root test (D-102).
S17 (the hardening matrix): ext4, xfs,
btrfs, fat32 and ntfs round trip and pass their own checkers; ext4, xfs and
btrfs roots boot under SeaBIOS and OVMF after a whole-disk restore; `dm-flakey`
bad sectors are recorded, verified and refused by a restore; NFS and SMB
destinations that vanish mid-backup are both exercised for real (D-098, D-100);
and a 16 TB virtual disk backs up in 29 MiB peak RSS (D-099). Two real bugs were
fixed on the way (D-096, D-097). The final gate is green (437 passed, 0 failed)
and every accumulated root suite passes with **zero skip markers** on this tree.
**The objective remains open.**
Earlier slice completion statements are historical reports, not a substitute for
a final requirement-to-evidence audit (`docs/gui-revision-audit.md`).

Work since the GUI revision started (see the audit and D-105..D-108): the GUI
is reorganised like Macrium Reflect (navigation sidebar, every disk with a
clickable partition map, wizards with step lists that pick devices in place,
a backup library of every set with Restore and Verify, an Activity page and a
job strip; `docs/gui-redesign.md`); rescue writes need `--confirm` and a
re-checked target, with per-formatter `mkfs` flags (D-105); `ListSets` without
a set name lists the sets (D-106); stopping the daemon drains its jobs and the
installer activates updates through that (D-107); file-mode restores and the
FUSE view use the newest member's tree, so deleted files no longer come back
(D-108). `cargo run -p lr-gui --example gallery -- DIR` renders every page at
1024x768/1280x720/1920x1080 and 100/150/200 % without a display. The GUI code
is split into `actions`, `models`, `callbacks` and `script_runner`.

The installed-Ubuntu/GNOME acceptance is done (real GNOME notifications,
the GUI on GNOME Wayland, the update handoff), the graphical rescue medium
boots to the GUI with its own daemon under SeaBIOS and Secure Boot, and
`v0.1.0-alpha.1` is published as a GitHub pre-release. Deferred by the
maintainer: completing a backup from the GUI inside GNOME (needs an
administrator at the polkit dialog). The test host `192.168.189.144` has a
NOPASSWD sudo rule for `codex` (`/etc/sudoers.d/90-codex-test`) for testing
only.

## Non-negotiable project rules

- Every crate except `lr-unsafe` starts with `#![forbid(unsafe_code)]`; all
  `unsafe` lives in `lr-unsafe` with a `SAFETY:` comment per block.
- Sources are opened read-only. Nothing in a backup path may write to a source
  device (spec §L.1). Writes to a device happen only in `restore apply` with a
  valid token, `--confirm`, polkit `auth_admin`, and re-validated target facts.
- Never log or store secrets. Passphrase files are opened `O_NOFOLLOW`, mode
  checked, and zeroized. Never pass a secret as a command-line argument.
- Achieved consistency is always reported; never claim a snapshot that was not
  made (spec §A.1, §D.2).
- All content intended for GitHub (code comments, docs, README, commit messages,
  PR text) is written in English.

## Build, lint, test

```sh
cargo xtask ci                    # fmt + clippy -D warnings + tests + cargo deny + cargo audit
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

# Static musl rescue CLI (Slice S11): `ring` compiles C, so musl-tools is
# required and cc must be pointed at musl-gcc.
CC_x86_64_unknown_linux_musl=musl-gcc cargo build -p lr-cli --target x86_64-unknown-linux-musl
```

`cargo xtask ci` is the gate; a slice is not done until it passes.

Acceptance tests that need a loop device, LVM, `fsfreeze`, xfs tools or qemu are
`#[ignore]`d and gated behind `LR_ROOT_TESTS=1` (spec §L.4):

```sh
LR_ROOT_TESTS=1 sudo -E cargo test --workspace -- --ignored --nocapture --test-threads=1
```

Privileged environments available for this machine, in order of preference:

1. **WSL interop root** — the loop module works and `wsl.exe -u root` needs no
   password. Build as the normal user, then run the test binary as root so the
   user's `target/` and cargo caches are never touched by root:

   ```sh
   cargo test -p lr-core --test root_loop --no-run
   wsl.exe -u root -- env PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
     LR_ROOT_TESTS=1 ./target/debug/deps/root_loop-<hash> --ignored --nocapture --test-threads=1
   ```

2. **Privileged container or VM** with `util-linux e2fsprogs xfsprogs lvm2 gdisk
   btrfs-progs dosfstools qemu-system-x86 ovmf` installed.
3. **Remote test host** `codex@192.168.189.144`, after key-based SSH is
   configured (`ssh-copy-id -i ~/.ssh/rustadmin_vm_ed25519.pub codex@192.168.189.144`).
   Never place a password in a command argument; ask the maintainer instead.

Never weaken a test to make it pass unprivileged. Never use destructive commands
on a device the test did not create itself (`losetup` images, `dm-flakey`, qemu
disks only). Note that WSL's loop driver can briefly report "no free loop
device" right after a detach: retry `losetup -f` instead of assuming failure.


## Semantic navigation with LSP MCP

- For definitions, references, call hierarchy, type-aware navigation, and
  diagnostics, use the `lsp_mcpls` MCP tools first when they are configured for
  the project.
- Do not present `rg`, `grep`, or other lexical search as semantic proof.
- If `lsp_mcpls` is unavailable or fails, state that explicitly before using
  lexical search as a fallback.
- On a cold language-server session, the first call may only open the document;
  retry the same read-only semantic query for a short bounded period before
  falling back.
- For JavaScript/TypeScript servers that publish diagnostics asynchronously,
  prefer `get_cached_diagnostics`; do not interpret an unsupported
  pull-diagnostics method as a clean result.
- LSP MCP is project-scoped: start Codex from the enrolled project root
  `/home/w0w/linuxreflect`, which contains `.lsp-mcp.toml` and the trusted
  project-local `.codex/config.toml`.
- Never use `/home/w0w` as one giant LSP workspace. Projects unsupported by the
  installed `lsp-mcp` backends must use an explicit lexical fallback.

## Long-running commands with Longrun MCP

- For a reviewed, trusted, non-interactive command expected to run longer than
  about 30 seconds, use `longrun.start_job` exactly once when it is available and
  the exact project root is enrolled.
- When Codex was launched through `codex-longrun` and the thread has an active
  durable Goal, pass `wake_policy="goal"` and require `automatic_wakeup=true`.
  Report the returned job ID/state and end the turn immediately; the bridge owns
  the Goal's `active -> paused -> active` transition.
- After a bridge-enabled `start_job` returns, never call `longrun.get_job`,
  `wait_agent`, a generic wait tool, `write_stdin`, log-tail tools, or any
  polling loop in that turn. In the automatically resumed turn, call
  `longrun.get_job` exactly once and continue from the terminal result.
- Use `wake_policy="none"` only with ordinary `codex` or an explicitly requested
  manual fallback. In that mode automatic wakeup is unavailable: end the turn
  without waiting, and use one `longrun.get_job` only in a later user-resumed
  turn.
- Treat `longrun.run_and_wait` as legacy compatibility mode because current
  Codex runtimes may convert a pending blocking call into model-driven wait
  cycles.
- Never put secret values in command arguments, MCP fields, prompts, or
  environment. For one reviewed non-interactive command that accepts one finite
  secret stdin payload, prefer `project_memory_stage_test_asset_for_longrun`
  when a suitable encrypted test-only asset exists, then pass only its one-time
  `stdin_secret_id` to Longrun.
- Keep project roots narrowly enrolled. Never broaden `LONGRUN_ALLOWED_ROOTS` to
  `/home/w0w`; this project's root is `/home/w0w/linuxreflect`.
- The global MCP configuration is loaded by new Codex processes. After
  installing, upgrading, or changing longrun configuration, start a new process
  or resume the session from a new process.

## Testing rules for slices

- Every slice lands with the acceptance criteria and tests from spec §K, and the
  next slice's CI run must stay green.
- Prefer fixture-based, unprivileged tests (sparse files, `sgdisk` images, sysfs
  fixture trees via `LR_SYSFS_ROOT`, mount tables via `LR_MOUNTINFO`) and keep
  true-root tests minimal and `#[ignore]`d.
- Tests must assert the security-relevant behaviour, not just the happy path:
  refusal without a token, `E_TARGET_CHANGED`, `E_SET_LOCKED`, tamper detection.
