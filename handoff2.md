# LinuxReflect handoff — paused at explicit token-key initialization

## Session status and authorization

- Project: `/home/w0w/linuxreflect`.
- The user explicitly requested **pause**, then requested this handoff. The
  durable Goal is **paused**. Do not resume it or continue implementation until
  the user authorizes resumption. Creating this document does not resume it.
- Conversation language: Russian. Repository documentation and code: English.
- No commits were requested or made. Current branch: `main`; `git rev-parse
  --verify HEAD` fails because there is no initial commit. The project directories
  are untracked. Do not treat the entire untracked tree as disposable or try to
  reconstruct a meaningful baseline from `git diff`.
- All known submitted Longrun commands have terminal results. No known command
  needs cancellation at this stopping point.
- Project Memory resolves this exact root to `linuxreflect`. Resolve and recall
  before substantive work; memory is advisory, files/results are authoritative.

## Full objective — not yet achieved

Audit and improve LinuxReflect, especially its GUI, into an understandable
mouse-driven backup/restore product with Macrium-like organization and correct
resizing. Ordinary operations must not require typing device paths. Validate
real X11/Wayland mouse, keyboard, dialogs and data round trips; pass current CI
and necessary root tests; install the tested version on Ubuntu `192.168.189.144`
and check the real GNOME session of `w0w`.

Required deliverables remain:

1. Correct disk discovery, error recovery, cancellation/job lifecycle,
   restore-plan invalidation and explicit confirmation; secure token/socket
   permissions.
2. Separated GUI data/wizard/job models, compatible automation, real UI tests.
3. Disk cards, actual device facts, partition map, contextual backup, folder
   backup, service-device filtering and loading/empty/error/retry states.
4. Guided backup and restore with clear steps, defaults, advanced settings,
   validation, concrete target review and safe encrypted restore.
5. Usable history/library, progress/results/cancel/retry, native dialogs,
   keyboard, focus and accessibility.
6. Accessible actions at 1024x768, 1280x720 and 1920x1080, at 100/150/200%,
   including long paths, scrolling, maximization and shrinking.
7. Review daemon/polkit/runtime, installer/update, notifier and rescue chains.
8. Current `cargo xtask ci = 0`, meaningful regressions, necessary root gates,
   test-device round trips, stale-target refusal, cancel/retry, and installed
   GNOME verification. Keep verified evidence separate from limitations.

Read `AGENTS.md`, `docs/spec/linuxreflect-spec-v2.1.md`, `docs/decisions.md`
and `docs/gui-revision-audit.md`. The specification is frozen; do not expand
unsupported operations. Historical S11b–S17 completion claims are not current
acceptance evidence. Do not close the Goal with unfinished acceptance criteria.

### Safety and execution constraints

- Backup sources are read-only. Device writes require the applicable reviewed
  target, token, confirmation and target revalidation. Destructive tests use
  only their own created devices.
- Never put secrets in arguments, logs, repository files or ordinary memory.
  Do not reuse historical plaintext credential helpers.
- `unsafe` belongs only in `lr-unsafe`, with SAFETY explanations. Preserve
  Slint attribution.
- Use native OpenCode LSP for semantic navigation. It successfully resolved
  engine token initialization and rescue apply definitions in this session.
- Read the current harness Longrun instructions. This OpenCode adapter uses
  native `longrun_*` tools and does not expose Codex `wake_policy`. Health
  reported `opencode_automatic_continuation=true` and the exact project enrolled,
  but `bridge_configured=false`. The Goal text still contains a Codex bridge
  contract. Do not invent bridge readiness or claim a wake policy was passed.
- After a successful native submission, report only job ID/state and end the
  turn. Do not poll pending jobs or submit duplicates. New user input can revoke
  wakeup. Keep OpenCode open for native delivery.

## Exact stopping point: latest security refactor

### Changed files

1. `crates/lr-engine/src/restore.rs`
   - Moved the process token-key `OnceLock<[u8; 32]>` to module scope as
     `TOKEN_SECRET`.
   - Added public `init_token_secret(path: &Path) -> Result<()>`.
   - It rejects an already initialized key, loads via the unchanged secure
     `secret_file::load`, and publishes using `OnceLock::set`; a losing
     initializer returns `AlreadyExists` rather than replacing the key.
   - Existing lazy `token_secret()` uses the same cell and retains its existing
     environment/default behavior.
   - Documented that public `token_secret_path()` resolves environment/default
     configuration, not the path of an explicitly initialized key.
2. `crates/lr-daemon/src/main.rs`
   - Added `#![forbid(unsafe_code)]`.
   - Replaced `unsafe std::env::set_var("LR_TOKEN_SECRET_FILE", path)` with
     `lr_engine::restore::init_token_secret(path)?`.
   - Existing eager `token_secret()` call remains before Tokio startup.
3. `crates/lr-engine/tests/token_secret_init.rs` — new integration test.
   - Rejects a mode-0644 key, then successfully initializes from a private path.
   - Checks persisted key equality without printing key bytes, mode 0600,
     refusal to replace the key/no second file creation, and concurrent reads.
4. `crates/lr-daemon/tests/daemon.rs`
   - Existing daemon fixture now passes a different environment key path and
     asserts that the CLI-selected key exists while the environment path does
     not. This checks CLI precedence in the existing real-process tests.
   - **Last edit before pause:** added
     `invalid_explicit_key_fails_before_serving_without_environment_fallback`.
     It starts the real daemon with a mode-0644 explicit key and another
     environment path, waits at most five seconds, and checks failure,
     mode-validation diagnostic, no socket and no fallback key.
   - **This last test has not been formatted, built or run.** There is also an
     accidentally duplicated/misplaced `/// A daemon process plus its temporary
     state.` comment above the new test; correct it on resumption.

### Results already obtained for this refactor

- `cargo test -p lr-engine --test token_secret_init -- --nocapture`: 1 passed,
  0.02 s; build 9.11 s.
- `cargo test -p lr-daemon --test daemon -- --nocapture`: 5 passed, 0.91 s;
  build 11.69 s. **This was before adding the sixth, invalid-key startup test.**
- `cargo fmt --all` was run before those tests, **not after the last edit**.
- No current full CI, clippy, root daemon rerun, Ubuntu rebuild or install for
  this security refactor. It is incomplete and must not be reported finished.
- Gemini read-only review job `4abe9dafbe594003a9bee31d0226eb44`: succeeded,
  exit 0, 80.089 s. It recommended explicit key initialization. Its claim that
  `token_secret_path()` was not public was incorrect and was independently
  corrected. Do not repeat its claims of lock-free initialization or newly
  introduced eager startup behavior: startup was already eager.
- No security-refactor evidence section has yet been added to the audit report.

### Immediate continuation sequence, after authorized resume

1. Inspect the four changed files, correct the misplaced comment and format.
2. Review single-assignment/race/error behavior; preserve the secure loader.
3. Run the new engine integration test and all six daemon integration tests.
4. Run appropriate clippy and full `cargo xtask ci`; record real terminal
   results. Do not count ignored root/UI tests as covered by CI.
5. Rebuild/rerun relevant root daemon/token/socket tests, including real
   permissions and socket activation. Inspect for skip markers.
6. Update the audit and memory with scoped verified results. Sync/rebuild on
   Ubuntu only after local checks; installed GNOME remains a separate gate.
7. Continue the full acceptance backlog below, not just this refactor.

## Last full CI and previous GUI changes

- Latest full CI: job `a17292215ea64320a0bf38790df74d37`, exit 0, 125.143 s.
  It includes interactive startup maximization and input-driver changes, but
  **predates the short GUI status fix and the current token refactor**.
- Allowed bincode/ttf-parser unmaintained warnings and dependency duplicates
  remain. Do not describe the audit as warning-free.
- `lr-gui/src/lib.rs::run` requests maximization for interactive startup.
  Local native Wayland initial-fit captures at 1280x720/100% and
  1024x768/200% were inspected successfully.
- Latest small GUI fix changes post-inspection status to
  `Device information loaded.` Previously a completed disk-map request told
  the user to choose a disk even after contextual backup had opened the wizard.
- The status fix built locally (7.87 s) and on Ubuntu (17.61 s); physical
  contextual-backup click and screenshot confirmed the correction.
- Ubuntu staged GUI hash for that fix:
  `834294bc707f1f4bf05f51867c382c7a8bf3daeb82dcf60507f4de991862450a`.
  It does not include the new engine token initializer.
- Current evidence: `/tmp/opencode/current-disk-select.png`,
  `current-disk-backup-entry.png`, `current-disk-backup-entry-fixed.png`.
  Disk row selection shows a map; contextual backup prepopulates `/dev/sda`
  without typing. These runs did not back up or write the VM system disk.
- The unprivileged fixture daemon shows permission-denied technical diagnostics
  for the VM system disk. This is partial sysfs layout evidence, not successful
  privileged inspection. Error presentation remains a follow-up.

## Important existing verified evidence

See `docs/gui-revision-audit.md` for exact scope and older artifacts.

- **Physical native Wayland folder round trip**:
  `be2ee6facbd540cd9d28d3ed58297002`, exit 0, 40.060 s, local Weston 13,
  1280x720/100%, native portals, real input. Empty target before consent,
  source unchanged, two restored files byte-identical; all five
  `/tmp/opencode/wayland13-first-roundtrip*.png` inspected.
  The working unprivileged bubblewrap/staged-portal argv is in job metadata.
  This is not GNOME, block-device, encrypted Wayland or full-matrix proof.
- **Physical X11 cancellation/retry/restore**:
  `0702372f82114e00a8f369d0c005e6a8`, exit 0, 53.091 s; 1024x768/100%,
  same window/set, three files including 1024 MiB, byte-identical restore.
- **Physical encrypted X11 round trip**:
  `549e84c4ce06497e8771478dc9f949dc`, exit 0, 67.099 s;
  1920x1080/150%, native credential dialogs and byte comparison.
- Current 100% populated matrix: `fc9dd23503224c0199ad492230b20946`,
  24 captures inspected at the three sizes. 150% and 200% have substantial
  earlier evidence, but the complete interaction/accessibility matrix is open.
- Real keyboard chooser Escape and selection passed after fixing
  `tools/gui_visual_smoke.py::focus_input`. The driver explicitly focuses
  windows; this does not prove natural GNOME focus restoration.
- Root core geometry/GPT discovery, dm-flakey refusal, file metadata/ACLs,
  one-filesystem exclusion, Btrfs full/incremental stream, eight substantive
  snapshot cases, and root daemon/polkit/socket-activation checks have current
  pre-refactor results in the audit. Do not silently transfer binary hashes
  across the engine change.
- Additional recent FUSE test: `cargo test -p lr-fuse --test mount --
  --nocapture`, 1 passed, 0.11 s; real mount, four path SHA-256 comparisons,
  links and write refusal. Binary `mount-c53ed1b552436ea1`, SHA-256
  `f0f9a4a4a57a243fadfea55ada0b6fed77a6a9e4d7875dbeb2fee01449a22418`.
- Root unaligned-tail regression passed in 0.02 s, no skips; owned
  1 MiB+512-byte loop, unaligned and aligned reads. Subsequent loop listing was
  empty. Binary `root_hardening-5dd071aac0c6c496`, SHA-256
  `4ba0a38a71c231deb41d0493b3306962e6122c059706006fd246140a00186801`.

## Newly documented rescue findings — unresolved

`docs/gui-revision-audit.md` contains a source-review section:

- `lr-rescue/src/main.rs` immediately applies recreation/boot-repair plans
  unless `--dry-run`; the CLI lacks explicit confirmation/token fields.
  `apply_layout_recreation` spawns planned commands without an application-level
  target-facts recheck. Normal engine restore guarantees do not cover this path.
- `plan_layout_recreation` constructs arbitrary nonempty `mkfs.<fs>` names with
  universal `-F/-U/-L` arguments. Supported filesystem types and each formatter's
  documented options need validation.
- No destructive command was run to investigate these findings. Reconcile
  changes with the frozen rescue specification before implementation.
- Memory record: `6262e322-45c0-4a19-bf60-c51f99253f55`.

## Remaining acceptance backlog and blockers

- Real GUI block backup/restore on owned test devices, stale-target refusal,
  block cancel/retry, physical transport-disconnect recovery.
- Full resize/scale interaction coverage, expanded technical details, long
  paths, maximize/unmaximize/shrink, keyboard-only operation and accessibility.
- Incremental/differential library workflows and remaining error-state flows.
- Remaining necessary root suites, including XFS/whole-disk boot/export,
  network interruption and large-image cases. An earlier XFS run timed out
  without terminal proof; its owned loop was cleaned up. Diagnose rather than
  counting it as passed or weakening the test.
- Installer/update activation race and installed runtime permissions, real
  GNOME notification delivery, current rescue build/boot/workflow.
- Installed Ubuntu validation is blocked by privilege/session access:
  `sudo -n true` as `codex` still requires a password; direct `w0w` SSH key
  access was previously denied. Do not expose credentials or weaken access.
- Ubuntu Weston 9 nested desktop-shell/pixman crashed; local Weston 13 solved
  the local physical Wayland test, not real Ubuntu GNOME acceptance.

## Environment and operational references

- SSH: `ssh -o BatchMode=yes -o ConnectTimeout=5 -i
  /home/w0w/.ssh/rustadmin_vm_ed25519 codex@192.168.189.144`.
- Ubuntu staging: `/home/codex/linuxreflect-gui-audit-20260923`.
- Ubuntu target: `/home/codex/linuxreflect/target`; cargo:
  `/home/codex/.cargo/bin/cargo`.
- Sync only intended files with `rsync -aR --checksum --no-times`; verify
  rebuild output and checksums. Staging is not installation.
- Reviewed short root test invocation pattern:
  `wsl.exe -u root -- env LR_ROOT_TESTS=1
  /home/w0w/linuxreflect/target/debug/deps/<test-binary>
  --ignored --exact <case> --nocapture --test-threads=1`.
  Build as the normal user; never manipulate devices not owned by the test.
- Longrun logs/metadata:
  `/home/w0w/.local/state/opencode-longrun/jobs-runtime/jobs/<job-id>.{log,json}`.
- Main test harness: `tools/gui_visual_smoke.py`; conversion:
  `tools/xwd_to_png.py`. XWD captures can include a larger black Xvfb desktop
  around the application; distinguish capture dimensions from window geometry.
- Staged local Wayland portals: `/tmp/opencode/lr-portals`; host packages were
  not installed. Temporary evidence may disappear; preserve required artifacts
  before relying on them for final delivery.

## Completion discipline

Maintain a requirement-to-artifact checklist. A build is not installation;
staging/private X11 is not the real GNOME session; scripted callbacks are not
physical input; ignored/skipped root tests are not acceptance. Mark the Goal
complete only when the original full requirements have direct current evidence.
