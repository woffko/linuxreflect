# GUI revision: acceptance and evidence

This audit tracks the GUI revision requested after the S11b–S17 work.
Historical green gates do not establish acceptance for the modified tree.
Items below remain open until their evidence is recorded.

## Latest daemon cancellation gate (2026-09-23)

- Full CI including the final cancelled-status presentation edit passed:
  `a9236ad1c3064a69a33baa5f730a4504`, exit 0 in 112.128 s. This retains
  the allowed dependency warnings and does not cover ignored/root/UI gates.
- Full CI including the portable daemon fixtures and terminal backup navigation
  correction passed: `6a5f9357879c405a927b58d749cd6fae`, exit 0 in 121.195 s.
  The dependency warnings listed below remain allowed. Ignored root suites,
  physical GUI checks, and installed GNOME acceptance are separate gates.
- Full CI after subscribing before job registration: job
  `92994d64c38b4756b7b2f0b5ac09831e`, exit 0 in 113.162 s. The existing
  allowed dependency warnings remain; this is not a warning-free claim.
- Ubuntu test build `b89a7a58b1d046f49f4d6480ad2aeb1c` exited 0 in 130.184 s.
  Its first test execution exposed a hard-coded `/tmp/opencode` dependency.
  Standard temporary directories then exposed the test daemon directory's
  group-writable mode under Ubuntu's umask. The fixture now explicitly creates
  its private daemon directory with mode 0700 and uses standard temporary
  directories for work data. Daemon startup failures now fail every test;
  previously four tests could return early and misleadingly report success.
- After those fixture corrections, all five daemon integration tests passed
  on Ubuntu in 1.84 s and locally in 2.27 s, with no startup/skip messages.
  This includes live byte progress, stream disconnect, reconnect/status,
  cancellation, terminal failure, unchanged source, and retry in the same set.
  Targeted `cargo clippy -p lr-daemon --test daemon -- -D warnings` also
  passed after the fixture corrections (6.66 s).
- Current Ubuntu staging daemon SHA-256:
  `6fbceef24ba693c5f8f901982dfa5027289afe7e30461210e9fb1629ae38feb0`.
  Staging GUI SHA-256:
  `5ea495051b280686a491e6af353b62060749210bfa33100e381d699b48d60f28`.
  These are staging binaries, not installation evidence.
- The physical input driver now supports bounded 512/1024 MiB allocated
  source fixtures and a 50 ms post-click interval for live cancellation.
  Source integrity is checked with SHA-256; restored files are compared
  directly in bounded blocks. Empty/equal/changed/truncated comparison cases
  passed. Physical GUI cancellation and retry still require observed results.
  The fixture corrections and driver extensions postdate the full CI above.
- First physical cancellation attempt `e4ad8d8dc0094477b66287d29b9389b4`
  exited 0 in 25.047 s and preserved all 1024 MiB of bulk source data.
  Inspected `cancel-bulk1024-first-click-12.png` shows live byte progress
  (201469879 / 1074049056) and enabled cancellation controls. Click 13 at
  (950,680) missed the status-bar Cancel job button (center near 950,645).
  Its screenshot shows normal completion, not cancellation. This run is
  timing/layout evidence only; it does not satisfy cancellation acceptance.
- Corrected-click run `82eaadf0bed2410298f7ec9669e371f7` exited 1 in 51.084 s.
  Inspected click-13 capture shows **Backup cancelled**, `E_CANCELLED`, and
  available terminal controls; the driver's integrity check passed for the
  1024 MiB source. Retry/restore did not pass: click-15 capture shows the
  stale-review rejection and a return to the destination settings. The
  terminal Back button had navigated to review step 2 even though start
  consumes that review. It now says **Review settings** and returns to step 1,
  requiring a fresh probe via Next: review. Build and physical retry evidence
  for this navigation correction are pending. No validation bypass was added.
- Ubuntu GUI build `0e092a14a7054cf4be0d2b790305b082` passed in 29.055 s;
  new staging GUI SHA-256 is
  `598797e0beafc5fb17b5bc4953c05c28dfe3b36bb74463c9a78fa1850f037591`.
  Physical run `234ab4ad5fb94821bd5f5f307147cd17` then demonstrated cancellation,
  Review settings returning to destination settings, and a successful new
  backup in the same window/set (inspected click-13/14/16 captures).
  All 1024 MiB of source data remained unchanged and one completed image existed.
  The overall run exited 1: the restore consent click used obsolete y=446;
  final capture shows the unchecked pinned checkbox at y=662 and disabled
  Restore now. No restore occurred and its destination remained empty after
  prepare. This is cancellation/retry evidence, not a successful round trip.
- Corrected consent run `0702372f82114e00a8f369d0c005e6a8` passed in 53.091 s
  using the same staging hashes: physical X11 cancellation, fresh review,
  successful retry in the same window/set, native destination chooser,
  prepare without destination writes, explicit consent, and restore.
  All three restored files matched byte for byte, including the 1024 MiB bulk
  file; source integrity passed. Inspected `cancel-bulk1024-confirmed-roundtrip`
  final and click-13 PNGs show Restore completed (3 files, 1.0 GiB) and Backup
  cancelled respectively. The private Xvfb window was 1024x768 at 100%.
  This completes this folder-mode cancellation/retry round trip only, not
  block cancellation, physical Wayland, the full scale matrix, or installed
  GNOME acceptance. The cancellation status bar still says "backup failed"
  while the wizard correctly says "Backup cancelled"; presentation follow-up
  remains open.
- Cancellation presentation follow-up now branches on the existing typed
  terminal cancellation classification: status, phase, and progress text say
  cancelled rather than failed/error. Internal terminal failure reporting and
  job cleanup remain unchanged. `cargo check -p lr-gui` and `cargo fmt --all
  -- --check` passed; this presentation edit postdates the full CI and Ubuntu
  screenshots above and needs rebuilt UI verification.
- That presentation check now passes on Ubuntu: GUI build
  `3013fdbcb4c046b2b93219554260918e` exited 0 in 15.038 s; staging GUI hash
  `00a863239be9b90eb19dafa73c3bbad186816f16be0b0870cfd0206c256a69ba`.
  A bounded 13-click physical X11 run exited 0 and preserved the 1024 MiB
  source fixture. Inspected `/tmp/opencode/cancel-consistent-status.png`
  shows Backup cancelled in the wizard and backup cancelled in the status
  bar, with Review settings and Done available. This closes the contradictory
  cancellation-status presentation finding; full CI for this last text edit
  has not yet been rerun.
- The WSL-root daemon suite was rerun after the Started fix: all three tests
  passed in 2.01 s, without skips (loop-device round trip, real polkit
  deny/allow, socket activation). Executable SHA-256:
  `91fe77fa3a205f0df531f8d3ac1cd672898429cc74d2b2b073510d30f2d67786`;
  local daemon SHA-256:
  `48ee30bc564558b02d06a5204e8764a462d40e4d2284201641c64890a300140b`.

## Current 100% populated resize inspection

Run `fc9dd23503224c0199ad492230b20946` completed successfully in 45.062 s
on the Ubuntu private X11 display with native portal dialogs. The log identifies
GUI `00a863239be9b90eb19dafa73c3bbad186816f16be0b0870cfd0206c256a69ba`
and daemon `6fbceef24ba693c5f8f901982dfa5027289afe7e30461210e9fb1629ae38feb0`.
It confirms the source remained unchanged and both restored fixture files
matched byte for byte. The destination was checked empty after prepare.

All 24 `current100-populated-matrix-click-{5,10,11,12,13,18,20,22}-`
captures at 1024x768, 1280x720, and 1920x1080 have now been visually inspected
(PNGs in `/tmp/opencode/`, original XWDs in the Ubuntu staging `visual/`
directory). The last 18 captures cover backup review/result and restore
image/destination/review/result. Their primary navigation and action buttons
remain within the window; restore consent remains visible above the pinned
action row, and Restore now is disabled before consent. The full image path
wraps on the review/result pages. Single-line image/target inputs show only
part of longer paths; these captures do not establish keyboard inspection of
their full contents. The reviewed destination is fully visible in this fixture.

This is populated folder-mode evidence at 100%, with collapsed technical
details. It does not establish expanded-detail scrolling, arbitrary long paths,
screen-reader/focus behavior, window-manager maximize, block-device workflows,
physical Wayland, or installed GNOME acceptance. Black pixels outside the
smaller windows belong to the 1920x1080 root display, not clipped app content.

### Bounded keyboard follow-up on the current Ubuntu GUI

Three private-X11 runs used the same GUI/daemon hashes as the 100% matrix,
1024x768, native portal dialogs, and physical xdotool input:

- Clicking Back up folder opens the native chooser immediately. The initial
  `current100-keyboard-source-tab` capture therefore does not establish Tab
  navigation within the source step.
- Clicking the chooser's Cancel, then pressing Tab, leaves the empty source
  step usable with Next: destination disabled. The inspected
  `current100-keyboard-after-dialog-tab.png` shows a clear focus outline on
  Refresh.
- Repeating dialog cancellation and then Tab, Tab, Return reopens the native
  folder chooser through the toolbar without another mouse activation.
  `current100-keyboard-reopen-dialog.png` confirms the chooser is visible.

PNG/XWD artifacts are in `/tmp/opencode/`; original XWDs are in staging
`visual/`. These runs establish visible toolbar focus and keyboard activation
after a cancelled dialog, not the complete keyboard workflow. The driver
explicitly focuses the app window before key sequences, including when a
portal dialog is open (`gui_visual_smoke.py` intermediate/final key handling).
Consequently these runs cannot establish native dialog keyboard navigation or
natural desktop focus restoration; a dialog-aware input target and a real
window-manager/session check are still needed. No source/destination writes
were requested in these follow-ups.

The driver now resolves the visible native chooser before each X11 key press,
rejects ambiguous chooser windows, and re-resolves after each key so closing a
dialog does not send subsequent input to a stale window. Wayland input still
targets the compositor output. This change passed CLI parsing and two physical
Ubuntu checks on the same binaries:

- `current100-dialog-aware-escape`: Escape targets the chooser, closes it,
  then Tab targets the app and visibly focuses Refresh. Before/after captures
  were inspected; source stays empty and Next stays disabled.
- `current100-dialog-aware-select`: after mouse selection of the source row,
  Tab, Tab, Return targets the chooser and accepts it. The inspected final PNG
  shows the selected `01 Source` path in the wizard and enabled Next.

This closes the incorrect keyboard-target harness finding for the exercised
X11 chooser. It still deliberately focuses windows on a private Xvfb display,
so natural GNOME focus restoration and full keyboard-only operation remain
separate acceptance checks. The harness change postdates CI
`a9236ad1c3064a69a33baa5f730a4504`; production binaries did not change.

The same Tab, Tab, Return sequence was also tried with native Wayland clients
and Weston 9 kiosk shell at 1280x720 (`wayland-kiosk-keyboard-accept`). The
driver completed, but inspected before/after captures show the selected source
row followed by navigation to the account's home bookmark, not an accepted
source. The fullscreen chooser still exposes no action buttons. Thus the X11
keyboard sequence is not a workaround for the kiosk-shell limitation; this
run is not Wayland backup/restore acceptance and issued no backup or restore.

### Native Wayland on local Weston 13: isolated startup and maximize

The local Slint 1.18 WSL fallback can be avoided without patching Slint or
changing host mounts: an isolated mount/PID namespace supplies a fresh `/proc`
and `/run`. Initial unprivileged bubblewrap attempts failed because root-owned
ancestors appeared as uid 65534; the token-directory trust check correctly
rejected them. A root-created mount namespace followed by `setpriv --reuid
1000 --regid 1000 --init-groups` preserves actual ownership and runs the test
GUI/daemon unprivileged. Its root filesystem is read-only, `/tmp` is writable,
and `/dev` contains only bubblewrap's private device set. The harness now prints
bounded daemon startup diagnostics rather than losing that error on cleanup.

With that setup, Weston 13 desktop-shell/pixman and the native Wayland GUI
start successfully with DISPLAY removed from GUI and portal activation.
Inspected artifacts in `/tmp/opencode/`:

- `wayland13-isolated-initial.png`: 1280x720 compositor output, app visible,
  but its initial window extends below the output. Double-clicking the
  panel-overlapped title at y=15 does not maximize it (separate
  `wayland13-isolated-maximized` capture, not counted as successful maximize).
- `wayland13-isolated-large.png`: complete decorated app at 1920x1080.
- `wayland13-max-native-dialog-click-1.png`: real click on the title-bar
  maximize button expands the app and leaves bottom controls visible.
- `wayland13-max-native-dialog.png`: clicking Back up folder enters the source
  step, but no chooser appears. Package inspection establishes that local
  `xdg-desktop-portal` and `xdg-desktop-portal-gtk` are not installed. Portal
  startup and a folder round trip remain unverified in this environment.

Local GUI SHA-256:
`397774b8752ec55a286ba4b9ad0681b68330e436bfa9fb3fd00d836de95e0602`;
daemon: `48ee30bc564558b02d06a5204e8764a462d40e4d2284201641c64890a300140b`.
This is local native-Wayland startup/maximize evidence, not Ubuntu VM or GNOME
installation acceptance. No backup/restore was requested. No host namespace
mounts or dependency source files were changed.

### Initial work-area fit and local portal preparation

Interactive startup now requests maximization before showing the window, so
the window manager determines the available work area including decorations
and scaling. Scripted startup retains its existing behavior. Local build
`14bac449b23845bb9b9395605c3ec12f` passed (6.033 s); GUI SHA-256 is
`5c441baa73d0dc8ac9e037aa31d1be2dac05123341e6fdf9df381a7413a3fc22`.
Inspected `wayland13-initial-fit-720.png` (1280x720/100%) and
`wayland13-initial-fit-200.png` (1024x768/200%) show the initial maximized
window with bottom controls and attribution visible, without a corrective
maximize click. Full CI and Ubuntu rebuild for this edit remain pending.

For native portal checks, Ubuntu packages were downloaded and extracted only
under `/tmp/opencode/lr-portals`: xdg-desktop-portal 1.18.4, GTK backend 1.15.1,
and its missing libjson-glib dependency 1.8.0. Staged D-Bus service Exec paths
point to those extracted binaries; host packages/services were not installed.
The private bus receives staged XDG data/portal directories and library path.
`wayland13-staged-portal.png` now shows a native chooser with visible Select
and Cancel actions on Weston 13 desktop-shell.

A fully unprivileged bubblewrap variant also works: a fresh tmpfs root and
tmp directory belong to the test user, system directories and the project
are bound read-only, and only `/tmp/opencode` is writable from the host.
Thus token ancestor ownership passes without weakening its checks or needing
a root-created namespace. With corrected row coordinates, inspected
`wayland13-userns-source.png` shows `01 Source` selected through real mouse
input and Next enabled. The preceding `wayland13-native-source-selected`
attempt selected the fixture home after clicking the table header; it is not
source-fixture acceptance. The subsequent round trip below verifies backup
and restore on this new Wayland setup.

### Physical native Wayland folder round trip: passed

Job `be2ee6facbd540cd9d28d3ed58297002` exited 0 in 40.060 s using the
unprivileged tmpfs-root bubblewrap setup and staged portals above. The local
GUI/daemon hashes match the initial-fit build. Both GUI and portal activation
had DISPLAY removed; xdotool input entered the nested Weston 13 X11 output
and was delivered to its native Wayland clients. No automation callbacks or
direct RPC setup replaced the mouse workflow.

At 1280x720/100%, 21 physical clicks selected the source, backup destination,
created the backup, selected the restore destination, reviewed the plan,
confirmed it and restored. The driver checked an empty restore destination
after click 19, source integrity, and byte-for-byte equality of both restored
files. All five captures were inspected:
`/tmp/opencode/wayland13-first-roundtrip{,-click-9,-click-11,-click-17,-click-19}.png`.
They show the selected backup/destination paths, Backup completed, explicit
unchecked consent with Restore now disabled, and Restore completed with two
files/300 KiB. Necessary actions remain visible in this maximized window.

This establishes a physical native-Wayland folder round trip on local Weston
13. It does not establish Ubuntu VM GNOME installation, Wayland block-device
flows/cancellation/encrypted restore, or the complete size/scale matrix. The
latest startup-maximization edit passed full CI as recorded below; an Ubuntu
rebuild and installed-session verification remain required.

### Current full CI after startup maximization

`cargo xtask ci` job `a17292215ea64320a0bf38790df74d37` exited 0 in
125.143 s on 2026-09-24. This includes the interactive startup-maximization
change and current physical-input harness changes. The gate completed with
the configured allowed unmaintained-crate warnings for bincode and ttf-parser
and dependency-duplicate warnings; it is not a warning-free audit. Ignored
root/UI tests and installed GNOME acceptance are separate requirements.

The updated GUI source and input driver were then checksum-synchronized to
Ubuntu staging. `cargo build --locked` for `lr-gui` completed there in 15.54 s.
The staged GUI SHA-256 is
`bb842a763503c2a5c4a4317a083f4cc8afa394ca235a02b40edf625806305212`.
Local and remote source hashes agree for `crates/lr-gui/src/lib.rs`
(`07e6bb0bc1fb6da2120cdd6996b923629a4d8eb9febd3ca7dcc59b9eaee24e3c`)
and `tools/gui_visual_smoke.py`
(`47694e495c813749e36ce5c6c4b0ff85734cb3d541b4b7bf9af323ab594fe8f5`).
A private X11 run resized the current window between 1280x720 and 1920x1080
twice and returned to 1280x720. Inspected
`/tmp/opencode/startup-max-current.png` shows real Ubuntu disk rows, actions,
status and attribution visible. The image includes the entire 1920x1080
Xvfb screen; the application occupies its upper-left 1280x720 area. This is
a resize smoke check, not window-manager maximize/restore or GNOME proof.
Installation remains blocked: a fresh `sudo -n true` over the configured
codex SSH connection still requires a password. No privileged installation
was performed.

## GUI redesign, stage 1 (2026-09-25)

Plan: `docs/gui-redesign.md`. The window is reorganised around a navigation
sidebar (Back up, Restore, Activity) that becomes a top bar below 760 px, with
wizard step lists hidden below 1000 px:

- **Back up** shows every disk as a panel with a proportional, clickable
  partition bar (filesystem colour, label, size, mounts; tiny partitions are
  widened so they can be clicked; unallocated space is shown), a hover detail
  line, and "Image this disk…" / "Image selected partition…". A disk the
  daemon cannot map still gets a panel from the device list, with the reason.
  Loading errors are a banner with Retry.
- **Wizards** list their steps; the source and the restore destination are
  picked on the same disk maps inside the wizard instead of on another tab.
  Restore destinations dim ineligible devices with the reason; backup sources
  do not (a mounted source is valid with a snapshot). Paths are text only
  behind "Enter a path instead" / "Enter the destination as text (SFTP)".
- **Restore** is a library of every set in the chosen folder, newest first,
  grouped by set, refreshed when a folder is chosen (D-106).
- **Activity** and a **job strip** with progress, percentage and Cancel on
  every page.

Evidence on this tree:

- `cargo xtask ci`: exit 0, 480 passed, 0 failed, 54 ignored.
- Root, `root_gui-10365b797d5b46f3`: X11, encrypted X11 and Wayland
  create/restore round trips passed (15.0 s), restored files compared. On WSL
  the Wayland run uses bubblewrap to hide `/run/WSL` and the `WSLInterop`
  binfmt entry, because Slint 1.18's winit backend forces X11 when it sees
  them; without that the "Wayland" test could not reach Weston at all.
- `lifecycle_tests::job_admission_lifecycle` passed on Xvfb, three runs in a
  row. The two scenarios used to be separate tests that could not share a
  process (Slint binds its platform to the first thread), so running both
  failed with "The Slint platform was initialized in another thread".
- `cargo run -p lr-gui --example gallery -- DIR` renders ten scenes at
  1024x768, 1280x720 and 1920x1080, each at 100/150/200% (90 PNGs, 21 s) with
  the software renderer; the disks, wizard, library and progress scenes were
  inspected at 1280x720@100, 1280x720@150 and 1024x768@200.

- Root, `block_backup_and_stale_target_refusal_through_the_gui_on_x11`
  (3.96 s, owned loop devices, detached afterwards): an ext4 partition on a
  GPT loop disk is imaged through the GUI in block mode; after the restore
  plan is prepared the test changes the target, the GUI's restore is refused
  with "target changed" and the target's first MiB is byte-identical before
  and after the refusal; a fresh review then restores, and the restored
  device mounts with byte-identical files. All four GUI root tests pass
  together in 18.5 s. The script gained `signal`, `wait-for-file` and
  `expect-restore-failure` so a test can act between review and restore.

- Physical input on the new layout (private Xvfb 1280x720, unprivileged
  dev-mode daemon on a private socket, real `xdotool` pointer and key
  events, every step inspected from a `scrot` capture): the daemon's real
  disk maps for the four WSL disks were shown ("Virtual Disk", read-only,
  no partition table; filesystems unknown because an unprivileged daemon
  cannot read the devices); a click on the Disk 2 tile selected `/dev/sdb`
  and showed its details; "Image this disk…" opened the backup wizard at
  Source with `/dev/sdb` selected; Next went to Destination with Next
  disabled until a folder exists; after focusing the window, Tab moved the
  focus ring from "Back up" to "Restore" and Space opened the library.
  Keys sent with `xdotool key --window` are synthetic and ignored by winit;
  only real key events count here.
- Dark scheme: `LR_GALLERY_DARK=1` renders the pages with the dark palette;
  the disks and restore-summary pages were inspected, and the step-number
  contrast was fixed after that inspection.

- Library "Verify" (VerifyImage of the whole chain, run as a job the strip
  and Activity follow): root test
  `verify_detects_a_corrupted_image_through_the_gui_on_x11` (3.68 s) verifies
  a fresh GUI backup, then flips 64 bytes in the middle of the image; the
  GUI's second verification fails with `E_CORRUPT` naming the image member.
  Expected-failure script steps now record a confirmed status, so a script
  that ends on an expected failure is not reported as failed.
- `cargo xtask ci`: exit 0, 483 passed, 0 failed, 56 ignored.
- Root, `a_backup_chain_made_and_restored_through_the_gui_on_x11` (2.94 s):
  full, incremental and differential file backups made through the GUI with
  source changes in between (a file changed, one added, one deleted); the
  library lists the newest first (ties within a second are ordered by chain
  position) and restoring it rebuilds the latest state. This test found a
  real engine bug, D-108: file-mode restores and the FUSE view merged every
  member's manifest, resurrecting deleted files. Fixed; the new engine test
  `a_file_deleted_before_a_later_member_stays_deleted` (incremental and
  differential) and FUSE test `a_mounted_incremental_does_not_show_deleted_files`
  both fail without the fix and pass with it. `cargo xtask ci`: exit 0,
  485 passed, 0 failed, 57 ignored.

- Native folder dialog on the new layout: `xdg-desktop-portal` 1.18.4 and
  `xdg-desktop-portal-gtk` 1.15.1 unpacked from the Ubuntu archive into the
  scratchpad (nothing installed on the host), a private session bus from
  `dbus-run-session`, Xvfb 1280x720 and a dev-mode daemon. A real click on
  "Back up a folder…" opened the GUI's backup wizard and the GTK "Choose a
  folder to back up" dialog; the folder chosen in that dialog arrived in the
  GUI ("Selected: …", status "source: …", Next enabled). Without a window
  manager the dialog had to be resized and moved with `xdotool` to reach its
  buttons; that is a harness limitation, not GUI behaviour.

Not yet covered: a real GNOME session (blocked on access to the Ubuntu host).

## Graphical rescue medium and the 0.1.0-alpha.1 release (2026-09-25)

The mkosi medium could not have worked as a graphical rescue system: the GUI
talks only to the daemon, and the image carried neither the daemon nor polkit;
the console menu also called commands that do not exist. `855dc59` stages the
daemon (socket-activated), `polkitd` with the policy, the group, the GUI and
the repair tool, and fixes the menu (prepare, show the plan, typed "yes",
apply). The image was built on the Ubuntu host in a privileged
`ubuntu:24.04` container (mkosi) and booted locally with KVM and a spare
8 GiB disk: under SeaBIOS and under OVMF with Secure Boot ("UEFI Secure Boot
is enabled", Canonical-signed kernel) the serial console reached
`LINUXREFLECT-RESCUE-READY graphical` and QMP screenshots show the GUI
listing the medium and the spare disk through the image's own daemon. Those
boots found three GUI issues (virtio PCI IDs shown as models, floppy and
optical drives listed as disks, a black strip from reserved decoration space
in the kiosk); fixed in `e0d5727` and `b775b10` and confirmed by booting the
rebuilt image (SHA-256 of the raw image `539a675f…`).

Release `v0.1.0-alpha.1` (pre-release, tag on `b01401e`, which adds the
MIT OR Apache-2.0 licence, D-109) carries the glibc tarball built on Ubuntu
22.04, the static musl CLI, the rescue image (zstd, decompresses to the
booted `539a675f…`) and `SHA256SUMS`. The tarball's documented install
(`sudo BIN=$PWD/bin ./contrib/install-host.sh`) was run on the Ubuntu host:
the running daemon's executable hash then matched the tarball's binary.
Downloaded assets verify against `SHA256SUMS`.

## Installed Ubuntu and the real GNOME session (2026-09-25)

Host `192.168.189.144`, Ubuntu 22.04.5, GNOME Shell 42.9 on Wayland, the
local active session of `w0w` (member of `linuxreflect`). `codex` got a
NOPASSWD sudo rule for this test host with the maintainer's approval.

- Release binaries of `51205cb` built there (15 min 43 s) and installed with
  `contrib/install-host.sh`. The update handoff (D-107) worked: the old daemon
  (PID 2715) exited, the next request started PID 167130, and the SHA-256 of
  `/proc/167130/exe` equals `/usr/local/bin/linuxreflect-daemon` and the fresh
  build. The installed unit carries `TimeoutStopSec=infinity`.
- Notifications: the per-user `linuxreflect-session` (running the installed
  binary) sent `Notify` for "Job started" and "Job finished" (with the image
  path) of a backup made through the daemon; `org.freedesktop.Notifications`
  was owned by `/usr/share/gnome-shell/org.gnome.Shell.Notifications`
  (gjs, running in the session for two days), which returned IDs 3 and 4.
  This is the real GNOME notification service, not a mock.
- GUI: the installed `linuxreflect-gui`, started in `w0w`'s user manager the
  way GNOME starts applications (`systemd-run --user`, `WAYLAND_DISPLAY`),
  ran as a native Wayland client, maximised, and showed the real disk map
  (screenshots with `gnome-screenshot`): "System disk · 162.7 GiB · MBR ·
  /dev/sda" with the ESP at `/boot/efi`, the ext4 root at `/` and the CD
  drive. Started from an SSH session instead, polkit refused `disk.read`
  (inactive session) and the GUI showed that as an error banner with Retry;
  that refusal is correct.
- That real MBR layout exposed a disk-map bug: the extended partition was
  drawn beside the logical root inside it. Fixed in `3e8e8df` (a regression
  test uses the captured layout); rebuilt, reinstalled (GUI SHA-256 prefix
  `f2f1b66680ddf310` in the build and in `/usr/local/bin`) and re-shot: ESP,
  root and 41.4 GiB unallocated.

Not done in GNOME: mouse and keyboard input (no input injection for Wayland
on that host) and completing a backup from the GUI there, which needs an
administrator to answer the polkit `auth_admin` dialog. Those flows are
covered by the X11/Wayland root tests and the physical X11 runs above.

## Accumulated root suites on `47cbd83` (2026-09-25)

Every root test binary of the workspace was rebuilt at `47cbd83` and run as
root (WSL interop) one at a time with `--ignored --test-threads=1`, together
with the static musl CLI built from the same tree (static-pie, `--version`
runs). All 13 binaries passed, 56 tests, no failures:

| binary | tests | time |
|---|---|---|
| root_daemon | 3 | 3.5 s |
| root_export (ext4/xfs over NBD, daemon export) | 3 | 12.5 s |
| root_file | 3 | 0.6 s |
| root_gui | 6 | 19.6 s |
| root_hardening (16 TB, dm-flakey, NFS/SMB, filesystems, boots) | 7 | 946.7 s |
| root_loop (lr-core, lr-engine) | 6 + 2 | 47.2 s + 1.1 s |
| root_rescue (media on SeaBIOS/OVMF SB, boot repair, bare metal, layout) | 5 | 371.0 s |
| root_schedule | 3 | 15.9 s |
| root_sftp | 2 | 6.2 s |
| root_snapshot | 10 | 20.5 s |
| root_stream | 1 | 0.9 s |
| root_whole_disk | 3 | 51.9 s |

The logs were searched for every early-return message the root tests print
(`skipping`, `unavailable`, `unproven`, `not available`, `never …`,
`could not be started`, `did not register`): none occurred. The earlier run
of `root_export` failed only because the `nbd` module was not loaded after a
WSL restart; loading it (`modprobe nbd`) is environment preparation.

On GitHub the privileged container job now runs every binary
(`--no-fail-fast`); `dm_flakey…` failed there because nothing creates
`/dev/mapper` nodes without udev, so the test now asks `dmsetup mknodes`.

GitHub Actions run `36100772272` on `b3fc812` is green in every job (lint,
test, deny, audit, root-tests). The container root job is not full
acceptance: it prints 21 skip messages (no grub-install, nbd-client, NFS
tools, system D-Bus or polkit in that container), so the complete root
evidence remains the local run above, which had none.

## Portability found on Ubuntu 22.04 (`192.168.189.144`, 2026-09-25)

A fresh clone of `47cbd83` built there (7 min 51 s, as `codex`, no sudo), but
unprivileged tests failed for reasons in the tests, not the product:

- umask 002 made `tempfile::tempdir()` group-writable, which the token-key
  loader rightly refuses (D-104); the key-file tests now create 0700
  directories, and the `lr-unsafe` open test sets the file mode it asserts.
- `cli_smoke` talked to the daemon installed on that host, whose polkit
  policy denies an inactive SSH session; the smoke tests now pass an absent
  socket so they test the in-process CLI they are about.

All unprivileged tests pass locally under both umask 022 and 002, and on the
Ubuntu host at `62cd898`: `cargo test --workspace --no-fail-fast` 488 passed,
0 failed, 57 ignored.

## Acceptance checklist

### Rescue command-boundary review: resolved (2026-09-25, D-105)

The two source findings from 2026-09-24 are fixed:

- **Confirmation boundary.** `linuxreflect-rescue boot-repair` and
  `recreate-layout` now print the plan and exit non-zero unless `--confirm`
  is given; `--dry-run` remains an explicit, successful preview.
  `apply_layout_recreation` takes the `TargetFacts` captured with the
  reviewed plan, re-reads them immediately before the first write
  (`E_TARGET_CHANGED` on mismatch) and runs the engine's H.3
  `preflight_target` (`E_TARGET_BUSY` for mounted, held, swap or running-root
  disks). Boot repair gets the confirmation gate only: it legitimately works
  on an ESP the operator may have mounted.
- **Formatter construction.** Only `ext2`, `ext3`, `ext4`, `xfs`, `btrfs`,
  `vfat` and `swap` are accepted, each with its own flags (`mkfs.xfs -f -m
  uuid=`, `mkfs.fat -i <serial> -n <label>`, `mkfs.btrfs -f -U`, `mkswap -U`).
  UUIDs, FAT serials and labels are validated; anything else, including a
  type containing `/`, is refused before any command runs.

Evidence on this tree:

- `cargo test -p lr-rescue`: 9 unit tests (including per-formatter argv and
  refusal of unknown or malformed types) and 2 CLI tests (preview without
  `--confirm` fails and leaves the disk byte-identical; an unsupported type is
  refused before touching the disk) passed.
- Root, owned loop devices only, binary
  `root_rescue-2919894b788e770e`:
  `recreating_a_layout_refuses_a_changed_or_busy_disk` passed in 3.39 s
  (changed disk → `E_TARGET_CHANGED` with the first MiB unchanged; mounted
  partition → `E_TARGET_BUSY` with its file intact) and
  `recreating_a_layout_keeps_the_partition_and_filesystem_uuids` passed in
  1.89 s. No skip output; `losetup -a` was empty afterwards.
- Each planned formatter argv was run against a scratch file: `mkfs.xfs`,
  `mkfs.fat`, `mkfs.ext4`, `mkfs.btrfs` and `mkswap` produced exactly the
  requested UUID/serial and label according to `blkid`.

Not covered: the rescue boot/medium root tests were not rerun for this change.

### Current file-mode root gate

Additional related checks on 2026-09-24:

- `cargo test -p lr-fuse --test mount -- --nocapture`: one test passed in
  0.11 s with no skip output. A real mounted file-image view returned matching
  SHA-256 for four paths, preserved directory entries/symlink/hard-link inode
  and link count, and refused a write. No busy-mount cleanup warning appeared.
  Executable `mount-c53ed1b552436ea1` SHA-256:
  `f0f9a4a4a57a243fadfea55ada0b6fed77a6a9e4d7875dbeb2fee01449a22418`.
- Rebuilt `root_hardening` and ran
  `an_unaligned_tail_reads_without_direct_io` explicitly as WSL root with
  `LR_ROOT_TESTS=1`: passed in 0.02 s, no skip output. The owned 1 MiB+512-byte
  loop permits its unaligned complete read and a subsequent aligned 4 KiB
  read. Executable hash matches the dm-flakey result below. A subsequent
  `losetup --list --output NAME,BACK-FILE,AUTOCLEAR` returned no devices.

### Current physical disk selection and contextual backup entry

On the current Ubuntu staged GUI (`bb842a76…`), private X11 at 1280x720/100%,
a click at (300,207) selected the `sda` row, highlighted it, populated Source
and displayed the selected-disk partition map. Inspected capture:
`/tmp/opencode/current-disk-select.png`. The unprivileged fixture daemon cannot
read the VM system disk: its BLKGETSIZE64/permission-denied diagnostics appear
in the selected-device heading. This is partial sysfs layout evidence, not
successful privileged disk inspection; ordinary-user error presentation
still needs refinement.

In a separate fresh window, clicking the card's Back up this disk action at
(600,427) entered backup step 1 with `/dev/sda` already populated and Next:
destination visible, without typing a device path. Inspected capture:
`/tmp/opencode/current-disk-backup-entry.png`. The bottom status still says
"Device layout loaded. Select a partition or back up the whole device."
while the wizard is already open; this is a confirmed stale-context status
message. The callback now reports the context-neutral "Device information
loaded." Local and Ubuntu locked GUI builds passed (7.87 s and 17.61 s),
and repeating the physical contextual-backup click confirmed the corrected
status in `/tmp/opencode/current-disk-backup-entry-fixed.png`. Ubuntu GUI
SHA-256: `834294bc707f1f4bf05f51867c382c7a8bf3daeb82dcf60507f4de991862450a`.
Formatting passes after rustfmt reformatted the enclosing async block.
This wording-only change postdates the latest full CI recorded above.
Neither run started a backup or wrote to a device.
Full block backup/restore acceptance remains open.

Additional current device gates were rebuilt and run through WSL root with
`LR_ROOT_TESTS=1`, without skip markers:

- `lr-engine/root_hardening::dm_flakey_bad_sectors_are_recorded_and_a_restore_refuses_them`
  passed in 1.82 s. The test creates its own 128 MiB source and target loops
  and an error-read mapper: abort mode returns BadSector, record mode retains
  bad-chunk markers, image verification accepts the structurally valid image,
  and confirmed restore refuses missing data with BadSector. This is a refusal
  check, not a guarantee that apply made no earlier writes. The initial
  mapper cleanup reports “No such device”; setup, assertions and final cleanup
  then succeed. Executable SHA-256:
  `4ba0a38a71c231deb41d0493b3306962e6122c059706006fd246140a00186801`.
- Both `lr-core/root_loop` cases passed in 1.18 s: 1 GiB geometry/sysfs
  discovery and real GPT partition discovery (ESP type, ext4 label, swap type
  and offline state). `partx` reports already-added partitions, but the actual
  node discovery and all assertions execute successfully. Executable SHA-256:
  `e2ceded12fd0566fc1f450805c48ceaee56b866a076f4b692dec5dd3e2d198a3`.

After these runs, root `losetup --list --output NAME,BACK-FILE,AUTOCLEAR`
returned no attached loops. These results do not cover the remaining XFS,
network-interruption, huge-image, whole-disk boot or export gates.

Related current snapshot/stream checks also pass as WSL root with
`LR_ROOT_TESTS=1` and no skip messages, after rebuilding both test targets:

- `root_stream::btrfs_full_then_incremental_round_trips`: 0.93 s; two owned
  512 MiB loop filesystems, two subvolumes, full then incremental stream,
  file additions/modifications/deletions, recursive restored-content comparison,
  filesystem UUID/default subvolume, and no extra restored subvolumes. This
  directly exercises the stream engine, not the GUI/token RPC boundary.
- `root_snapshot::live_none_marks_the_image_inconsistent`: 0.59 s; live read
  requires opt-in, report and restore plan expose inconsistency, and apply
  refuses until `accept_inconsistent` is explicitly supplied with the token.
- `root_snapshot::freeze_refuses_a_destination_on_the_frozen_filesystem`:
  0.12 s; same-filesystem freeze destination is rejected for deadlock risk.

Stream executable SHA-256:
`e7646a576e8304c9ec0a664a5ce1857c881eb92ee9b0e73a872dc6790a84c3ef`.
Snapshot executable SHA-256:
`3269b6510a104db3b5a55dddb6caae19628431396381edbf67f1d4dd03040d65`.
The six remaining substantive snapshot cases were subsequently run individually
with the same executable, `LR_ROOT_TESTS=1`, WSL root, `--ignored --exact`,
`--nocapture`, and one test thread. All passed without skip/unproven markers:

| Case | Seconds | Observed assertion coverage |
| --- | ---: | --- |
| `freeze_blocks_writers_and_thaws_on_drop` | 0.79 | Writer blocks during freeze and completes after snapshot drop |
| `kill_9_is_recovered_by_the_deadman` | 4.19 | Killed child cannot run cleanup; external deadman permits writing again |
| `lvm_snapshot_is_point_in_time` | 2.39 | Snapshot retains pre-write bytes while origin changes; snapshot removed on drop |
| `a_killed_job_leaves_a_snapshot_that_the_sweep_removes` | 2.49 | Orphan exists after SIGKILL and is removed by the VG-scoped sweep |
| `a_thin_snapshot_is_supported` | 3.89 | Thin snapshot retains old bytes and is removed on drop |
| `an_overflowing_snapshot_aborts_the_job` | 7.34 | COW overflow produces SnapshotOverflow and snapshot cleanup |

Together with the two checks above, all eight substantive snapshot tests now
have current results; the two child-helper entry points are exercised through
their parent tests rather than counted as separate acceptance cases. LVM emitted
inherited `/dev/ptmx` descriptor 7/10 warnings from this WSL invocation; these
are retained as warnings, not described as a warning-free run. Test-created
VG/origin/pool removal and PV-label cleanup were reported successful.

Rebuilt `cargo test -p lr-engine --test root_file --no-run` and ran each
ignored case explicitly as WSL root with `LR_ROOT_TESTS=1`, `--exact`,
`--nocapture`, and `--test-threads=1`. All three passed without skip messages:

- `device_nodes_ownership_and_xattrs_round_trip`: 0.13 s; restored ownership,
  user xattr, POSIX ACL, FIFO and character-device identity, plus empty
  `rsync -naxAci --delete` difference.
- `one_file_system_does_not_cross_a_mount`: 0.01 s; records the owned tmpfs
  mountpoint while excluding files inside the other filesystem.
- `a_btrfs_source_is_snapshotted_for_point_in_time`: 0.47 s; own 512 MiB loop
  filesystem, PointInTime report, restored pre-change content, preserved live
  post-backup change, and incremental parent/unchanged-file checks.

Executable SHA-256:
`0881da5dc6ece5aabfe3348086826ee223692f081572aa7c44b2712f092800c3`
(`target/debug/deps/root_file-aab4a83b650ab7de`). These are engine root tests,
not evidence for GUI block-device interaction or installed GNOME.

### Confirmed notifier presentation defect (fixed locally; desktop check open)

`lr-session/src/lib.rs::Notification::for_event` labels every started,
finished, and failed event as Backup. `lr-daemon/src/service.rs::watch_events`
forwards the shared job stream with only the job ID in `Event.message`, and
the same service runs restore jobs through `run_job`. Consequently restore
events are mislabeled as backups. Cancellation (`E_CANCELLED`) also takes
the generic critical-failure branch. Correct the presentation without
inventing operation information absent from the event, and verify restore
and cancellation payloads plus actual desktop delivery. This is confirmed
source behavior; installed GNOME notification acceptance remains open.

The local implementation now uses Job started/finished/failed, reports
`E_CANCELLED` as Job cancelled with normal urgency, and names a restore
destination instead of inventing a missing image. Missing failure payloads
are ignored. All seven `lr-session` library tests pass, including restore
completion and cancellation regressions; `cargo clippy -p lr-session
--all-targets -- -D warnings` exits 0. These changes postdate the full CI
below and still require delivery and desktop verification.

Current delivery checks now pass with rebuilt CLI/daemon/session binaries
(build job `9ff2553e12c649939f7610899aabbece`, exit 0). Executable
`root_schedule-eae63b23d28d5e63`, explicitly run as WSL root with
`LR_ROOT_TESTS=1`, passed `the_session_helper_posts_a_notification` in 0.70 s
and `the_session_helper_posts_a_notification_on_wayland` in 2.30 s, neither
with skip markers. The D-Bus mock assertion now requires both Job started
and Job finished; the real headless sway/mako check requires LinuxReflect
and Job finished in `makoctl list`. These exercise a real backup job;
restore/cancel payloads are covered by unit regressions, not yet actual
desktop delivery. Installed Ubuntu GNOME remains unverified.

| Requirement | Implementation surface | Required evidence | Status |
| --- | --- | --- | --- |
| Real disks and partitions appear | GUI disk parsing and daemon inspection | Daemon-shaped JSON regression; real-device UI screenshot | Typed null/numeric partition tests pass; real Ubuntu disk/partition screenshot inspected; final card interactions pending |
| Retry after errors | GUI action lifecycle | Failed request followed by successful request in the same window | Deterministic Xvfb completion/admission regression passes; actual missing/wrong-credential PrepareRestore refusals followed by successful restore pass in one scripted X11 GUI process; physical error/retry and transport recovery remain open |
| Cancellation preserves live job state | GUI cancellation and progress | Failed cancellation, successful cancellation, terminal-event races | Late terminal/GetJob/progress isolation passes deterministic Xvfb regression; real socket disconnect/cancel/retry and physical X11 folder cancellation/retry pass; physical transport recovery and block cancellation remain open |
| Stream EOF is not success | GUI RPC client | Missing terminal event rejected; real daemon disconnect | Terminal failure distinguished from lost transport; known jobs retained with status query; full integration tests open |
| Restore uses the reviewed selection | `lr-gui/src/review.rs`, restore callbacks and UI confirmation | Edit, edit-and-revert, delayed response, expired token, changed device | Pure state tests: 5 passed, including credential-path binding; full GUI integration and device checks remain open |
| Socket stays reachable | Engine secret storage and daemon socket | Permissions before/after token creation and service restart | Secret-file and root group-access regressions pass; daemon root suites pass; installed update/restart checks pending |
| Macrium-style disk overview | Disk cards, partition map, filters | Clicks across cards/partitions, actual device facts, empty/error states | Grouped cards and context backup implemented; selected-device map and geometry tests pass; one card resize point inspected; per-card maps/full interactions pending |
| Guided backup | Backup wizard and option mapping | Source → destination → review → execution without typed device paths | Physical folder backup passed on staged Ubuntu at 100%, 150% and 200% through native dialogs; block-device and advanced-option flows pending |
| Guided restore | Image library, target picker, restore wizard | Image → target → consequences → confirmation → execution | Current flattened review reaches Technical plan after scrolling at 1024×768/200%; physical file restore passes, destination empty before consent, two files byte-identical; expanded details and block-device flows pending |
| Encryption works end to end | GUI secret selection and RPC options | Encrypted backup/restore; missing/wrong secret; no secret disclosure | Scripted X11 missing/wrong-secret recovery passes; each refusal leaves an empty destination and clears approval. Physical encrypted X11 round trip at 1920×1080/150% passes with native credential dialogs, independent encrypted-header and byte comparison |
| Copy library is usable | History paths and metadata | Real full/incremental/differential entries open the correct image | Set-relative paths and timestamp regressions pass; a real full-copy row and Tab/Return selection into Restore verified; incremental/differential UI cases pending |
| Native dialogs work | Portal integration | Folder/image selection and cancellation in real desktop session | Source, backup destination and restore folder selected physically through GTK portal on Ubuntu/private X11; image/cancel/GNOME checks pending |
| Layout resizes | Slint layouts | 1024×768, 1280×720, 1920×1080; 100/150/200%; maximize/restore | Initial and populated captures exist at all three scales; seven populated stages visually inspected at all three sizes at 150%; physical folder restore after shrinking to 1024×768 and 1280×720 at 150% passes; complete interaction matrix and remaining 100/200% visual reviews pending |
| Keyboard and accessibility | Focus, labels, shortcuts | Keyboard-only navigation; visible focus; accessible control names | Library Restore selected with Tab/Return; focus and scroll to passphrase picker observed; small-window confirmation and full accessibility checks pending |
| Job results remain understandable | Operation-bound job presentation | Backup/restore reports stay distinct across tab changes; terminal Done navigation | Physical cross-tab reports and Done return to Disks verified; disconnected/cancelled/failed-job presentation acceptance pending |
| Project integration reviewed | Installer, polkit, session notifier, rescue GUI | Reproducible install/update; desktop authorization; notification and rescue checks | Open |
| Real GUI round trip | X11/Wayland UI and test-only devices | Mouse-driven backup/restore, data comparison, refusal, cancel/retry | Native X11/Wayland script round trips pass; physical X11 plain and encrypted folder round trips compare two files; physical Wayland, block, stale target and cancel/retry pending |
| Quality gates | Workspace and relevant root suites | `cargo xtask ci` exit 0; root results with no hidden skips | CI 26a8843439a241259c305d63016dea3e passed including encrypted negative/retry automation (105.109 s); Ubuntu encrypted X11 and native Wayland scripted round trips pass without skips; full required root accumulation pending |
| Updated test Ubuntu | Installed binaries and GNOME session | Build/install provenance and actual w0w desktop workflow | Open |

### Deployment provenance check (2026-09-23)

Read-only SHA256 checks confirm that installed binaries still differ from the
current staging build:

| Binary | `/usr/local/bin` SHA256 | Staging SHA256 |
| --- | --- | --- |
| `linuxreflect-gui` | `d6e05a0ee85247477c7d6e99b9296d7de0715709edd70acee5fc954528f103ee` | `fc1e8ca286db7f13be90813feba5acefc768821fb4c57cb0d330d33300bb7a1a` |
| `linuxreflect-daemon` | `85028c0d046824d2638c9f69f016e61c62566da2242e6fb03eea76fbeb8d59f1` | `d915f4ca76095e6bfd1afc17249777bd60c61e1b2c6d65954485173e3dc9c213` |
| `linuxreflect-session` | `76c3d0c33154b2bb1af1b8768fc17c16148a9878b39c55181586db5be77a408f` | `32168024de120e23075f9b44ee4d59bc18fd2e5f347401c9e39460c205b8613c` |

The current `codex` SSH account's `sudo -n true` still fails because a password
is required. Installation and real w0w GNOME acceptance need authorized host
access or maintainer participation. Staging tests are not installed acceptance.

## Encrypted GUI automation coverage

Added path-only `backup-passphrase-file` and `restore-passphrase-file` script
directives. Backup selects the same passphrase field and encryption flag as
the UI; restore invalidates its prior approval before setting the credential
path. Existing directives remain compatible. The new X11 root case generates
fresh OS-random test material in an exclusively created mode-0600 file inside
its mode-0700 fixture; secret contents never enter argv or script text.
`encrypted_create_and_restore_through_the_gui_on_x11` passed explicitly under
WSL root with `LR_ROOT_TESTS=1` (5.85 s, one passed, no ignored cases in the
selected run). It independently scans the written image superblock to require
encryption and compares the restored binary bytes and text marker. This is
scripted GUI/daemon coverage, not physical encrypted file-picker acceptance.
GUI unit tests passed 25 cases after the new directives. The later negative
credential checks, full CI and Ubuntu rebuild results are recorded below.

The encrypted X11 case now also attempts preparation with no passphrase and
with a distinct generated wrong passphrase before retrying with the correct
file in the same GUI process. The expected-failure directive requires the
specific diagnostic, idle/non-job state, empty token, and cleared consent;
timeouts or unexpected failures do not pass. An explicit filesystem assertion
requires the destination to remain empty after each refusal. The expanded
case passed (6.97 s, one passed, no ignored cases in the selected run), then
verified the encrypted image header and restored bytes. This provides actual
daemon-RPC credential-failure and same-window recovery coverage, driven by
automation rather than mouse input. Physical encrypted-picker coverage remains
pending.

### Latest validation provenance

The local `cargo xtask ci` job `26a8843439a241259c305d63016dea3e` completed
with exit 0 in 105.109 s. This includes the latest encrypted negative/retry
automation. The gate covers installer tests, fmt, clippy, workspace tests,
deny and audit; ignored root/display tests require separate explicit runs.
Audit reports two allowed unmaintained-dependency warnings (bincode and
ttf-parser), not a warning-free dependency inventory.

The Ubuntu staging build (`lr-gui`, `lr-daemon`, `lr-session`, bins and tests)
job `2984d7b0059c4896ad2a8bff777e9581` completed with exit 0 in 14.031 s.
The subsequent cargo-test invocation rebuilt the test profile and exceeded its
30-second SSH timeout after starting the test; that invocation is inconclusive.
A process check showed no surviving test, GUI or daemon before the ready test
binary was invoked directly. Explicit `LR_ROOT_TESTS=1` runs of
`/home/codex/linuxreflect/target/debug/deps/root_gui-7d10376a687023c6` passed:

- `encrypted_create_and_restore_through_the_gui_on_x11`: 1 passed, 7.99 s;
- `create_and_restore_through_the_gui_on_wayland`: 1 passed, 2.02 s.

Neither run emitted a skip marker. These ran as the unprivileged `codex` user
against a private dev-mode daemon and test-owned file trees. The Wayland test
removes DISPLAY and uses a private Weston compositor. They establish scripted
GUI/RPC data round trips, not privileged/polkit coverage, physical Wayland
interaction or installed w0w GNOME acceptance.

Before that Ubuntu build, SHA-256 checks matched the local and remote copies
under `/home/codex/linuxreflect-gui-audit-20260923`:

| Relative source path | SHA-256 |
| --- | --- |
| `crates/lr-gui/src/lib.rs` | `01a80d67d14564207a71bf3907afb267ee49f84cc468ad07ec3b3ada7a275877` |
| `crates/lr-gui/src/script.rs` | `b872ebce085ec936e5818aec75a40f0e62be601f0e0810462d3de262a7a048cd` |
| `crates/lr-gui/tests/root_gui.rs` | `2ab99c31cedc02f2d850876db02ad0d7a365047af3302918e0e5139a91d2b297` |

This comparison covers the three synchronized files, not an independent
whole-tree comparison. The installed-binary hashes above describe the earlier
deployment inspection and do not establish the identity of the new build.

## First runtime visual findings

### Current 150% source-step inspection

Using the rebuilt Ubuntu GUI with SHA-256
`5ea495051b280686a491e6af353b62060749210bfa33100e381d699b48d60f28`,
physical clicks on Back up folder and the native GTK portal selected the
test-owned `01 Source` folder without typing its path. The source step was
resized within the same GUI process to 1024×768, 1280×720 and 1920×1080 at
150%. All three captures were visually inspected: source selection, folder
button and Next: destination remained visible; the path and footer were
readable for this fixture. Captures are
`/tmp/opencode/scale150-source.png` and
`/tmp/opencode/scale150-source-click-4-{1024x768,1280x720}.png`.
The XWD root captures remain 1920×1080; the black area outside the resized
window is not application content.

A separate physical pass selected `02 Backups` and reached backup review;
`/tmp/opencode/scale150-review.png` shows the selected source/destination,
defaults and Create backup action at 1920×1080. This inspection alone does
not establish a backup or restore round trip. The populated-step matrix job
`c30ddcd4c1714180b1c111dc3b583a93` completed with exit 0 (36.048 s): one
nonempty image was created, source hashes remained unchanged, and the restore
destination was empty after review. It captured seven populated steps at all
three required sizes. Under
`/tmp/opencode/scale150-populated-matrix-click-N-SIZE.png`, all 18 captures
for backup destination (N=9), backup review (N=10), backup completed (N=11),
restore image (N=12), restore destination (N=17), and restore review (N=18)
have now been visually inspected at 1024×768, 1280×720 and 1920×1080.
Together with the earlier three source-step inspections, these cover seven
populated stages at 150%. Required navigation/actions remain visible. Long
image/target input values extend beyond the single-line fields; the review
wraps the complete source and target. Full keyboard inspection of those fields
is still open. Restore review at the two smaller sizes requires scrolling to
read the final warnings; physical scroll reachability is established at
1024×768 and 1280×720 by the round trips below.

The subsequent mouse-driven round trip `e95e7ba8989346ba9787e179929ceb6f`
passed with exit 0 (36.053 s) using the same GUI hash. It selected source,
backup destination and restore destination through native folder dialogs,
created a backup, verified an empty destination before consent, then shrank
from 1920×1080 to 1024×768 at 150%. Physical wheel input reached the final
review warnings and Technical plan toggle. Physical clicks on the pinned
confirmation and Restore now completed restoration; the complete two-file
fixture matched byte for byte and the source remained unchanged.
`/tmp/opencode/scale150-small-roundtrip-before-keys.png` was inspected and
shows final warnings, unchecked consent and disabled Restore now;
`/tmp/opencode/scale150-small-roundtrip.png` shows Restore completed, the
specific destination, two files, 300 KiB and visible Done. No keyboard input
was sent in this run despite the generic pre-keyboard capture filename.
This proves the tested folder workflow after shrinking; it does not prove
physical block-device/encrypted/Wayland workflows or every matrix case.

The 1280×720/150% counterpart `14567751d2bc4b0fbc3a19ef72b059cf` passed
(exit 0, 39.069 s), including an empty destination before consent, unchanged
source and byte-identical two-file restore. Both
`/tmp/opencode/scale150-720-roundtrip-before-keys.png` and
`/tmp/opencode/scale150-720-roundtrip.png` were visually inspected: wheel input
reaches the final review warnings and Technical plan, pinned consent/action
remain accessible, and the final report and Done are visible.

### Confirmed lost Started event: cancellation/reconnect regression

The real-socket test
`disconnected_backup_can_be_cancelled_and_the_set_reused` initially failed
with `Started precedes byte progress`: the client received byte progress but
never learned the daemon-generated job ID. Inspection confirmed an ordering
defect in `Service::run_job`: `Jobs::register` synchronously publishes Started,
but the RPC subscribed only after registration. This prevented clients that
did not supply an ID (including the GUI) from addressing cancellation or
status recovery during that job. The subscription now precedes registration;
the wire protocol and authorization checks are unchanged.

After the fix, the regression passed in 0.85 s. It starts a real private daemon,
copies an allocated 512 MiB fixture, observes Started and nonzero byte progress,
drops the stream/client, reconnects and verifies the job is still running,
requests cancellation and requires terminal `E_CANCELLED`, then successfully
backs up a small source into the same set on the same daemon. Every byte of the
original 512 MiB source is checked unchanged. A 20-second asynchronous deadline
bounds the RPC scenario. The complete daemon integration suite passed (5/5,
0.90 s), and `cargo clippy -p lr-daemon --all-targets -- -D warnings` passed.
Physical GUI cancellation and updated Ubuntu daemon deployment remain pending;
older Ubuntu hashes predate this production fix. Full CI must be rerun.

### Current root evidence

Current engine target-refusal evidence: rebuilt with
`cargo test -p lr-engine --test root_loop --no-run`, then ran
`root_loop-dc41da679980c50d` through `wsl.exe -u root -- env LR_ROOT_TESTS=1`.
The `--ignored restore_refuses --nocapture --test-threads=1` selection passed
both tests in 2.40 s: repartitioning the test-owned target after prepare gives
`TargetChanged`, while mounted and active-swap targets give `TargetBusy`.
The exact `a_tampered_token_is_rejected_on_a_real_device` case also passed
(1 test, 0.46 s). No skip markers appeared. Test executable SHA-256:
`aaa4213d9fab43a8c8130b8800578f3612b05befbaa739bdf4bbd2c06db62687`.
This proves engine refusal on owned devices, not physical GUI stale-target
interaction. Follow-up exact cases on the same executable passed:
`ext4_loop_completeness_and_size_bound` (2.47 s; 1 GiB source, 60,874,070-byte
image, used-region and file hashes match, fsck clean), and
`bad_sectors_abort_or_are_recorded` (0.69 s; truncated test-owned backing file
produces the required abort/record behavior). The XFS exact case exceeded
the shell's 25-second timeout and is inconclusive. A process inspection found
no surviving test or xfs_repair; the sole remaining loop backed by the
512 MiB file created at that test's start was not mounted and was detached.
Five of six root_loop cases now have current passing evidence; XFS remains open.

`cargo xtask ci` job `9084f9cb397042c889906c973b5a222e` passed with
exit 0 in 115.158 s, including the new unavailable-daemon lifecycle test's
compilation and linting. Display-gated tests were executed separately as
described below. The later nested-Wayland Python harness changes are outside
that gate's evidence. Allowed audit warnings for bincode and ttf-parser and
dependency-duplication warnings remain; this is not a warning-free inventory.

Native Wayland physical-input harness work is in progress. The optional
`--wayland --portal` path starts a private Weston X11 backend, removes
`DISPLAY` from the GUI and portal-activation environments, and sends physical
input to Weston's output window. On Ubuntu Weston 9, output windows do not
publish `_NET_WM_PID`; the harness instead reads the window ID announced by
its own compositor. The first attempt failed at window discovery, without
performing a round trip. The corrected discovery plus one physical click
opened a native folder chooser (`wayland-native-folder-step.png`). Inspection
showed kiosk-shell fullscreen treatment hid the dialog's header actions, so
the harness now requests desktop-shell instead. That variant remains to be
run; this experiment does not yet satisfy Wayland round-trip or resize AC.
The measured X11 geometry in this mode is the compositor output, not the
individual Wayland application window.

Desktop-shell follow-up on Ubuntu did not complete: its initial capture showed
only the desktop, and subsequent input runs lost the compositor output.
Added failure diagnostics establish that the owned Weston process exits with
signal 11 (`-11`) using the X11 backend, desktop-shell and pixman. Omitting
the redundant initial windowsize request produced the same signal. A separate
software-GL attempt returned exit 0 from the screenshot harness but its
inspected screenshot was entirely black, so it is not passing UI evidence.
The harness retains pixman and prints compositor exit/log diagnostics on
failure. No GUI or Wayland acceptance criterion is closed by these attempts;
root cause within Weston or its client interaction has not been isolated.

Disabling Weston's documented startup animation did not prevent signal 11;
that experimental setting was removed. Local Weston 13 cannot validate the
same binary's native Wayland path under WSL: Slint 1.18's winit backend
explicitly calls `with_x11()` when `/run/WSL` or WSLInterop is present, and
the GUI fails to connect when DISPLAY is removed. No dependency was patched
to bypass this platform behavior. The harness now allows an explicit kiosk
shell and bounded intermediate key presses. Ubuntu captures
`wayland-kiosk-home.png`, `wayland-kiosk-source-selected.png` and
`wayland-kiosk-source-confirm.png` show real mouse navigation to the private
home and Enter navigation into `01 Source`; a second Enter did not accept
the folder. They establish input routing only, not completed folder selection.

Batch GDB on the owned Ubuntu compositor localized the SIGSEGV to
`libpixman-1.so.0`, called by `pixman_image_composite32`, then
`libweston-9.so.0` and `libweston-9/x11-backend.so` during event-loop repaint.
The client subsequently reports Broken pipe. This establishes the crashing
process and stack, not whether a malformed client buffer triggered it.
Disabling Pixman's mmx/sse2/ssse3 implementations (confirmed by its diagnostics)
did not avoid signal 11; that experimental option was removed. A private GTK
`gtk-dialogs-use-header=false` setting also did not restore kiosk dialog actions
and was removed. The optional `--wayland-debugger` route retains batch GDB
backtraces and terminates only its newly created compositor process group.

An independent Gemini advisory suggested testing decoration/panel geometry.
Its proposed `decorations=false` setting was not found in the installed
Weston 9 documentation and was not used. Testing the documented
`panel-position=none` alone still produced signal 11; that setting was removed.
The advisory does not establish a root cause or a passing Wayland scenario.

The GUI regression
`lifecycle_tests::unavailable_daemon_does_not_release_a_job_after_cancel_or_status`
passed on private Xvfb (1 passed, 0.07 s). It runs the actual asynchronous
Cancel and GetJob connection attempts against an absent socket in a private
temporary directory, processes the errors through Slint's event loop, and
asserts that job identity, `has_job`, UI/shared busy and admission exclusion
survive both errors. The job identity is seeded by the test: this does not
establish cancellation of a real running daemon job or mouse acceptance.
The existing completion/stale-reply event-queue regression also passed in a
separate process (1 passed, 0.05 s). Both used the freshly built
`target/debug/deps/lr_gui-356815ee8adfa2c5` with `xvfb-run -a`,
`SLINT_BACKEND=winit-software`, `WINIT_UNIX_BACKEND=x11`, and
`--ignored --exact <test-name> --nocapture --test-threads=1`.

Rebuilt with `cargo test -p lr-cli --test root_daemon --no-run` and
`cargo build -p lr-daemon --bin linuxreflect-daemon`. Then ran:

```text
wsl.exe -u root -- env LR_ROOT_TESTS=1 /home/w0w/linuxreflect/target/debug/deps/root_daemon-d07ef497dba46494 --ignored --nocapture --test-threads=1
```

All three tests passed in 2.09 s with no skip markers: test-owned ext4 loop
backup/verify/prepare/confirmed restore with recursive data comparison,
real polkit rejection of an unprivileged peer and authorization of root,
and inherited socket activation with no decoy socket bound. This covers
these daemon acceptance paths, not GUI block selection or installed Ubuntu.
SHA-256 identities after the run:

- CLI: `9e843b0b467033b066309ea0348e40555e0ac6a5e3510e57713d301d2a3b948b`
- daemon: `9e917a635d033f03f2d4de38fe4824a6a387f3066bce0be63b0d0ab081d571e6`
- test: `91fe77fa3a205f0df531f8d3ac1cd672898429cc74d2b2b073510d30f2d67786`

Six negative visual-harness argument checks also returned argparse exit 2
before starting processes: passphrase fixture without portal, encrypted
assertion without a round-trip assertion, settling without an existing click,
more than ten seconds for one click, duplicate settling click, and more than
thirty seconds total settling. These checks validate argument bounds, not UI
readiness detection or cryptographic correctness.

### Physical encrypted-picker round trip

The visual harness now optionally creates `04 Passphrase` from OS randomness
inside the private fixture home with exclusive creation and mode 0600. Its
contents do not enter command arguments or screenshots; only its path is
selected in the GUI. The fixture is removed after owned child processes exit.
The initial encrypted run `a22e6ee1ea63470ca3307894946c0e3a` failed (exit 1,
52.08 s): no backup image was created. Inspection of
`/tmp/opencode/encrypted150-physical-roundtrip-click-16.png` shows that the
file picker was still open, with the key file selected. The test used the
folder dialog's confirmation coordinate; the file dialog's Open row is lower.
This is not evidence of a GUI encryption failure or a passing round trip.
The corrected run must also assert the produced format-v1 header's encrypted
flag independently of the GUI's selected option.

Run `16ac85f17b7e4ecfb38607e4f15d0d74` (exit 1, 52.084 s) subsequently
created a backup with the encrypted header flag and unchanged source. The
restore credential picker succeeded (inspected `encrypted150-file-picker-
roundtrip-click-22.png`). However, `...-click-28.png` shows the destination
folder chooser still open: GTK retained the larger dialog height from file
selection, so its confirmation row also moved from y=310 to y=356. The
file-set assertion correctly failed; this is partial encrypted-backup/picker
evidence, not a passing encrypted restore. The next run corrects that final
folder-dialog coordinate.

Run `5a861a42f6724847a174260f418f206d` (exit 1, 52.084 s) then reached
encrypted restore preparation, but the fixed 1.5-second input cadence was too
short. The click-28 screenshot shows preparation still busy with inputs
disabled; the final screenshot shows a ready review with unchecked consent
and disabled Restore now. No restore was authorized by those early clicks.
The harness now supports bounded extra settling after specified clicks (at
most ten seconds per click and thirty total), without invoking GUI callbacks
or daemon RPCs. The following physical attempt will allow time for backup,
encrypted plan preparation and restore before asserting the resulting state.

The settled run `549e84c4ce06497e8771478dc9f949dc` passed (exit 0,
67.099 s) on staged Ubuntu with private Xvfb/D-Bus at 1920×1080/150%.
Physical mouse input selected the source and destination folders, enabled
encryption, selected the credential through the native file chooser for both
operations, prepared the restore, and explicitly confirmed its destination.
Five additional seconds after each of backup, prepare and restore allowed
cryptographic work to settle. The driver used no GUI callbacks or RPCs.
The independent assertions confirmed format-v1 encrypted headers, an empty
destination after preparation (click 28), unchanged source bytes, and all two
restored fixture files matching byte for byte. Header inspection alone is not
a MAC verification; successful authenticated restore supplies separate
end-to-end evidence.

The final screenshot and click-16/17/22/28 captures at
`/tmp/opencode/encrypted150-settled-roundtrip*.png` were visually inspected.
They show backup review/completion, the selected restore credential, restore
review, and the final `Restore completed` report with two files/300.0 KiB and
accessible Done. The log records GUI SHA-256
`5ea495051b280686a491e6af353b62060749210bfa33100e381d699b48d60f28`
and daemon SHA-256
`d915f4ca76095e6bfd1afc17249777bd60c61e1b2c6d65954485173e3dc9c213`.
This closes physical encrypted folder/picker coverage for this X11 case;
installed GNOME, physical Wayland, block-device operations and cancellation
still require their own evidence.

The GUI and daemon binaries built successfully in Longrun job
`c57d10e6816246cdbca7917c57ada8b9` (`cargo build -p lr-gui -p lr-daemon
--tests`, exit 0). Real X11 screenshots were captured and inspected at
1024×768 with scale 1 and 2. Physical clicks on Refresh and New backup worked.

The screenshots exposed oversized backup controls, horizontal clipping at
200% scale, an initially unloaded disk list, and empty NBD devices cluttering
the default view. The current follow-up edits constrain wizard layout stretch,
reduce toolbar width, move job controls into their own conditional row, wrap
attribution, load disks on normal startup, and hide zero-capacity devices with
the service-device filter. These edits are awaiting rebuilt visual inspection;
the earlier screenshots do not verify the fixes.

`tools/gui_visual_smoke.py --resize-cycle` additionally enlarges and shrinks the
same window twice, asserting each actual X11 window size. This checks window
geometry only; screenshots still need inspection for clipping and usability.

The follow-up GUI build `9a99b4591a3b40308ef78780027aaff4` completed with exit 0.
The 200% X11 resize cycle confirmed 1024×768 → 1920×1080 → 1024×768 twice.
Inspection of `/tmp/opencode/lr-rebuilt-disks-scale2.png` confirmed that the
toolbar fits and disks load automatically, but the disk page still extends
beyond the right edge and the footer is below the visible area. Geometry
success is therefore **not** layout acceptance. The next changes isolate the
active page's layout from hidden forms and reduce wide option/history grids;
these changes require a fresh build and screenshots.

## Runtime token-key correction (focused tests verified)

The old `restore.rs` implementation unconditionally changed the socket's
parent directory to mode 0700, probed writability by truncating `.probe`, and
read the key through an unbounded, symlink-following filesystem read.

The replacement `restore/secret_file.rs` preserves existing directory modes,
traverses pinned directory descriptors with no-follow checks, rejects untrusted
owners/writable ancestors, and checks the opened key's type, owner, mode and
exact length. A complete mode-0600 temporary key is published without replacing
an existing key; concurrent creators then read the winner. Existing key bytes
and `/run/linuxreflect/token.key` remain unchanged. The shared directory's
group/0750 policy still belongs to daemon/socket provisioning.

Root now consistently chooses `/run/linuxreflect/token.key` unless explicitly
overridden. Non-root callers choose their XDG runtime directory or the UID-scoped
temporary directory when XDG_RUNTIME_DIR is unset. Invalid configured locations
are errors, not reasons to silently create a different signing key. Explicit
paths containing parent traversal or symlink directories are rejected. Existing
insecure key permissions are rejected without rewriting the file.

This uses the already locked `tempfile` dependency at runtime. An independent
Gemini design review supported bounded descriptor-based reads and atomic
no-clobber publication; the implementation additionally checks ancestors and
opens with O_NONBLOCK to avoid blocking on a FIFO before validating its type.
Regression tests cover directory/socket preservation, concurrent creation,
symlinks and untouched `.probe` targets, invalid file modes/sizes/types, and
writable directory rejection. Build/test results and privileged cross-user
socket access were initially pending; the focused results below supersede that
pending status. Real daemon activation/polkit and installed GNOME checks remain
separate acceptance gates.

Verified results:

- `cargo test -p lr-engine --lib restore::`, job
  `6af77245418b4deba878e90c6742ae33`: exit 0, 11 passed, one privileged test ignored.
- The exact ignored test was then run as WSL root with `LR_ROOT_TESTS=1`:
  `restore::secret_file::tests::socket_group_can_connect_after_key_creation_but_cannot_read_key`:
  one passed, zero failed, zero ignored. UID/GID 65534 connected to the test
  socket but could not open the key; directory mode remained 0750; changing
  the key's owner to that UID made the loader reject it. Only temporary test
  objects were modified. This tests filesystem access, not polkit.
- GUI/daemon build `c960a5e8e31542508acc786dafc8014d`: exit 0 with no reported
  warnings. `/tmp/opencode/lr-final-layout-restore-scale2.png` was inspected:
  the first restore page's image selection and pinned navigation fit at
  1024×768/200% after two resize cycles; the remaining fields require scrolling.

## Scroll-layout runtime evidence

GUI build `0080573b3b2c44e1afcb42134bb0895f` exited 0. Inspected captures:

- `/tmp/opencode/lr-scroll-disks-scale2.png`: 1024×768 at 200%, disk content
  scrolls separately; source/action row and attribution are visible without
  overlapping the status area.
- `/tmp/opencode/lr-scroll-backup-scale2.png`: same geometry and scale; the first
  wizard page's disk/folder choices and navigation actions are visible.
- `/tmp/opencode/lr-scroll-history-scale2.png`: destination/set controls fit.
- `/tmp/opencode/lr-scroll-restore-scale1.png`: 1024×768 at 100%; first restore
  page, image/passphrase controls and navigation fit.

Each successful capture included two enlargement/shrink cycles. These are
first-page checks, not full wizard/dialog/round-trip acceptance. Two other
invocations failed before mapping the window (including one of two concurrent
captures); a later diagnostic reported only `creating the Slint window`.
The harness now retains bounded GUI error output on failure, and GUI stderr
will include the error chain after the next rebuild. The startup failure's
cause is still unknown. Deprecated Slint `viewport-width` aliases have been
replaced by `content-width`; that cleanup also awaits the next build.

## Matrix and advisory target-selection follow-up

- `tools/gui_visual_matrix.py` records binary SHA-256 values and per-case logs,
  drives real page clicks and two resize cycles, and stops on the first failure.
  The initial attempt `7e5b9d5f417f45dd9912fd92ee4a02f5` failed connecting to X.
  After adding `-noreset` to the private Xvfb invocation, job
  `05f3d77d79bc49f7814e7f5123a6335a` captured all 36 initial-page cases with exit 0
  and unchanged binaries, in `/tmp/opencode/lr-matrix-20260923-b`.
- All four 1280×720/200% captures were inspected: pinned actions and attribution
  fit, while page content requires scrolling. Physical wheel input revealed the
  restore passphrase field and chooser; a Tab key produced a visible focus ring
  (`/tmp/opencode/lr-restore-scrolled-1280-scale2.png`). The other matrix captures
  still require inspection. This does not cover later wizard steps or dialogs.
- `devices.rs` now separates typed disk-list data, sorting/filtering and advisory
  restore eligibility from callbacks. Read-only, empty, mounted and held devices
  carry rejection reasons; a whole disk also checks its partitions. The map's
  restore selection delegates to the same row guard. Backend revalidation still
  authorizes writes. These newest changes postdate the matrix's binaries and
  still require tests and real target-chooser checks.
- CI `35523ad39bfd46eb9258d4e19813d500` failed Clippy's test-module ordering rule
  in `client.rs`; the test module was moved to the end. A subsequent targeted
  check found the new model needed a direct workspace `serde` dependency; it
  has been added. Neither failed check is a green CI result.

## Current integration gate and daemon regressions

`cargo xtask ci`, job `58abd23732e34daca498d213f5ba857a`, exited 0 after fmt,
Clippy with warnings denied, workspace tests, cargo-deny and cargo-audit.
Dependency checks reported their configured allowed warnings; this is not a
claim of zero dependency warnings. The preceding engine/GUI library run
`f7cb589153314be3abaa59853fb364ab` passed 64 engine and 18 GUI tests, with the
privileged key test separately passed using the freshly built engine executable.

The CI-built `root_daemon-2bbab19982d27e9a` then passed all three tests, invoked
individually as WSL root with `LR_ROOT_TESTS=1` and `--ignored --nocapture
--test-threads=1`, with no skip messages:

- `socket_activation_is_honoured`;
- `polkit_denies_a_non_root_peer_and_allows_root`;
- `a_loop_device_round_trips_through_the_daemon`.

Root GUI tests now use the same abstract-socket/no-reset Xvfb setup as the
visual harness, obtain an allocated display through a bounded readiness pipe,
and explicitly select X11 or Wayland software rendering. This test-harness
update postdates the successful CI run and still needs compilation/execution.
Its script-driven round trip will not replace physical mouse/dialog acceptance.

## Daemon stop drains jobs; installer activation (D-107, 2026-09-25)

The daemon now handles SIGTERM/SIGINT: admission closes, running jobs finish,
and the process exits 0; a second signal cancels the jobs. The unit sets
`TimeoutStopSec=infinity`, and `install-host.sh` requests
`systemctl --no-block stop` on an active daemon so the next request starts
the new binary through the socket unit.

Evidence: `jobs::tests::a_draining_registry_refuses_new_jobs_and_cancels_on_request`,
and two real-process tests in `lr-daemon/tests/daemon.rs`:
`sigterm_waits_for_the_running_job_and_refuses_new_ones` (a 1 GiB file
backup is copying when SIGTERM arrives; a new backup is refused with
"stopping"; the daemon stays alive, the running job finishes, then the daemon
exits 0) and `a_second_sigterm_cancels_the_running_job` (`E_CANCELLED`, exit
0). `cargo xtask ci`: exit 0, 483 passed, 0 failed, 55 ignored. Not yet run
under real systemd on the Ubuntu host (no passwordless sudo there).

## Installer/update findings (historical; activation resolved by D-107)

Inspection of `contrib/install-host.sh` confirms that it replaces the daemon
binary and enables the socket, but does not restart an already running daemon.
An update can therefore leave the old process serving requests. A safe update
procedure must account for running jobs before restarting; blindly restarting
to satisfy a version check could interrupt a backup or restore.

The preflight checks binaries and the polkit policy only; desktop and systemd
unit inputs are installed later without prior validation, allowing a missing
input to cause a partially applied installation. The session-notifier unit is
silently skipped if `/usr/lib/systemd/user` is absent. These are source-level
findings, not completed installer fixes or deployment acceptance.

## Native Wayland evidence correction and backup-review guard

The freshly compiled `root_gui-fc1a7d8ec280d3dd` passed its X11 round trip
under WSL root, including byte comparison. Its Wayland test failed: Slint
1.18.0's winit backend (`lib.rs`, WSL detection near lines 492–499) explicitly
forces X11 when WSL markers exist. With DISPLAY removed, it correctly fails to
connect to X even though Weston is running. Prior runs inheriting DISPLAY are
therefore not reliable evidence of native Wayland rendering. Native Ubuntu
testing is being prepared in `/home/codex/linuxreflect-gui-audit-20260923`;
this is a separate source staging area, not an installed update.

Local follow-up code adds `backup_review.rs`: source inspection captures the
whole BackupSpec, rejects responses for changed settings and consumes only the
reviewed request when starting. Freeze and unprotected live-copy choices require
their explicit consent flags. Script `backup` invokes normal inspection first,
preserving scripts that previously inspected before setting the destination.
These changes and their regression tests still await validation, and postdate
the initial Ubuntu staging snapshot. The technical source-inspection text is
optional in the review page rather than required reading for ordinary backup.

Follow-up validation: after correcting two calls to use `ActionsHandle::fail`,
`cargo test -p lr-gui --lib` passed all 21 tests, including the three new backup
review/consent tests. This is unit coverage, not mouse-driven acceptance.

The initial Ubuntu build completed successfully (job
`d30579c097d545a780db40640203edb1`). Running the staged Wayland test as `codex`
printed a skip message after 10 seconds, so no Wayland acceptance was achieved.
The harness incorrectly classified any daemon startup failure as a missing
binary and discarded stderr. It now exposes daemon stderr, fails on early exit
or startup timeout, and owns the child with RAII during readiness checks.
The staged GUI sources have been refreshed; the next build explicitly includes
both `--bins` and `--tests`. Passwordless `sudo -n` is unavailable on this VM;
no credential was supplied. Non-root file round trips, if successful, must be
reported separately from privileged root-suite acceptance.

## Installer preflight follow-up

`contrib/install-host.sh` now checks all five binaries, the polkit policy,
desktop entry and all three systemd units before any installation command.
It also rejects non-executable binaries. Required destination directories are
created explicitly; the session unit is no longer silently omitted when the
user-unit directory is absent.

`python3 tools/test_install_preflight.py` passed three tests (each missing
resource, each missing binary, and a non-executable binary). Mutating commands
are replaced with fail-fast sentinels in isolated fixtures; these are preflight
regressions, not a real installation test. `sh -n contrib/install-host.sh` also
passed. The Python regression suite is included in `cargo xtask ci`, which now
requires Python 3. Safe replacement of an already-running daemon remains open;
this preflight change does not resolve service update/lifecycle coordination.

## Validation checkpoint: 2026-09-23 17:45 UTC

`cargo xtask ci` exited 0 (job `9867bdb4e6dc4d419d062f20d366c1a3`),
covering the backup-review guard, installer preflight regressions, formatter,
Clippy, workspace tests, deny and audit. Audit reported the existing allowed
unmaintained-package warnings for bincode and ttf-parser. The exact CI-built
`root_gui-9ec7ccd2785c5954` then passed
`create_and_restore_through_the_gui_on_x11` as WSL root in 2.05 seconds, without
skip output, including the script-driven backup/restore byte comparison.
This still does not establish mouse/dialog acceptance.

The native Ubuntu clean GUI rebuild passed (job
`f575437adfe2400194b5422bdc8c7f1f`). The previous generated Slint API mismatch
disappeared after package-scoped `cargo clean -p lr-gui`. Source transfer with
preserved mtimes into a shared target cache can leave stale generated output;
future transfers should avoid relying on older timestamps as change signals.

The updated remote harness now exposes the daemon failure: its token-directory
validation rejects the test directory with the user's group-writable umask
(`0002`). `tempfile` uses the default DirBuilder mode unless explicitly
configured. The fixture now creates its directory with explicit mode 0700;
production validation remains unchanged. This test-only change postdates the
CI run above and awaits the updated native round trip. A remote test-only build
exceeded a 30-second foreground timeout after changing Cargo's feature graph;
the original cargo process was observed still running (PID 36063). Do not
start a duplicate build until its terminal state is established.

The remote Cargo process subsequently exited; the new
`root_gui-a7a45a192f5f26bd` passed both exact tests as `codex` with
`LR_ROOT_TESTS=1`: native Wayland in 2.02 seconds and X11 in 2.72 seconds,
with no skip markers. Both compare restored bytes. Wayland explicitly removes
DISPLAY and uses a private Weston runtime. These are non-root, script-driven
round trips on native Ubuntu, not physical interaction or installed GNOME
acceptance.

The next UI increment groups the ordered device rows into disk cards, retaining
the existing callback indices and advisory destination reasons. Disk and
partition selection use native buttons for keyboard focus, with a per-disk
backup action. The selected-device map remains below the cards; per-card maps
and physical interaction/resize validation are still pending. These edits
postdate the green CI and native round trips above.

## Physical native-dialog inspection on Ubuntu

The visual harness now supports a private D-Bus session and fixture HOME
(`--portal`), an explicit reviewed binary directory and XWD capture when scrot
is absent. The Ubuntu host has xdg-desktop-portal, its GTK/GNOME backends and
xwd installed. A bounded stdlib-only converter validates XWD headers and linear
DirectColor palettes before writing PNG, without installing dependencies.

Using the staged pre-card GUI at 1024x768, actual X11 mouse events opened Backup,
opened the native folder chooser, navigated Home, selected `01 Source`, accepted
it and advanced to the destination step. Visually inspected evidence:
`/tmp/opencode/lr-native-folder-home.png` and
`/tmp/opencode/lr-native-folder-selected-next.png`. The latter shows the fixture
source path and step 2. No manual source path or GUI automation callbacks were
used for this interaction. This is a private Xvfb session, not GNOME w0w, and
does not yet establish a physical backup/restore round trip. The screenshots
capture the full 1920x1080 private screen; xdotool separately confirmed the GUI
window itself was 1024x768.

Card-layout follow-up: `cargo test -p lr-gui --lib --test root_gui` passed
21 unit tests and built both ignored display tests (job
`354633b9d45540a08b1742a7b26a20cf`). A physical X11 capture at 1024x768,
scale 2, confirmed two enlarge/shrink cycles and visible pinned actions;
the cards scroll within the remaining viewport. The inspected image is
`/tmp/opencode/lr-cards-1024-scale2.png`. This is one matrix point, not the
complete matrix. It exposed an idle `list disks` progress line, prompting a
follow-up that hides the progress bar while idle. The toolbar now offers
explicit folder backup, and device counts distinguish disks and partitions.
Those final polish edits still require compilation and fresh capture.

The complete physical **backup** interaction on the staged Ubuntu GUI passed
(job `20193dff9cb3420ebee673c872398672`, exit 0, 20.04 seconds): source and
destination folder choosers, review, and Create backup. The harness found a
nonempty completed `.lrimg` in the fixture destination and verified the source
text was unchanged. The inspected `/tmp/opencode/lr-native-mouse-backup.png`
shows `backup ok`, file mode and the engine's per-file consistency warning.
The final result currently exposes raw JSON; a readable result summary remains
an open UX defect. This run covered one small file and did not restore it.
The next fixture includes a 300 KiB binary file and supports exact restored
file-set and byte comparison via `--expect-fixture-restore`.

The card/folder-toolbar/idle-progress tree passed `cargo xtask ci` (job
`a67349cb25024da5b57b0783f325f319`, exit 0). A later presentation change adds
`crates/lr-gui/src/result.rs`: successful results show destination/image paths,
reported counts/sizes, actual consistency limitations, encryption state and
warnings. Raw JSON remains unchanged in `progress-text` for automation and is
available under Technical report. All 23 GUI unit tests passed, including
regressions for preserving per-file limitations/warnings and not inventing
missing or unknown facts. This later change still needs physical UI validation
and the final CI gate.

The physical restore-review run passed its backup assertion (job
`3cd7b765bef9472bb5f12b70ddd2cbc7`, exit 0). Inspection of
`/tmp/opencode/lr-native-mouse-restore-review.png` shows the freshly created
image, the private `03 Restore` destination, an unchecked explicit consent box
and disabled Restore now. The review reports 307232 source bytes. No restore
was requested in that run. The next scenario attempts the disabled button,
asserts the fixture destination remains empty, then confirms and restores.
Binary SHA256 fingerprints are recorded and checked unchanged by the harness.

## Physical X11 file round trip: verified staged snapshot

Job `410ca9584cb2479c987717a2d288426c` exited 0 in 36.056 seconds on Ubuntu
as `codex`. The 22 physical mouse clicks selected source/backup/restore folders
through native GTK portal dialogs, created a backup, selected the resulting
image through the GUI's existing last-image state, reviewed the exact target,
attempted Restore now without consent, checked the target remained empty,
checked the consent box and restored. The harness verified the original source
bytes, the exact restored set of two files and byte equality for the text and
307200-byte binary payload. No automation callback script or test-side backup/
restore RPC was used. `/tmp/opencode/lr-native-mouse-roundtrip.png` was inspected
and shows `restore ok`, two files and 307232 restored bytes.

Unchanged binary SHA256 values recorded by that test:

- GUI: `c29843ed56ad521e1d843c7c5dfc0bbf068494c71c80876dbeac409a05ce4648`
- Daemon: `d915f4ca76095e6bfd1afc17249777bd60c61e1b2c6d65954485173e3dc9c213`

Scope: unencrypted folder backup/restore, private Xvfb/D-Bus, 1024x768 at scale
1, pre-card/pre-readable-result staged GUI. This is not installed GNOME, a
physical Wayland interaction, a block-device restore or final-tree acceptance.
The latest GUI sources have now been transferred with content checksums and
without preserving older timestamps for the next native build.

## Installer publication safety

An independent Gemini review (job `15fda908e5684932b52c6ea296211d21`) advised
preserving the legacy running daemon and explicitly deferring activation. Its
claims that ordinary GNU install is atomic and that socket activation removes
all admission races were not accepted. Idle exit and graceful drain are design
proposals, not implemented or verified behavior.

`contrib/install-binaries.sh` now stages all five executables in a private
directory on the destination filesystem before publishing each by rename.
Copy failure leaves existing executables untouched. Publication is atomic per
file, not a release-wide transaction or a power-loss durability guarantee.
The installer never stops/restarts an active daemon and reports pending daemon
activation rather than implying that the new process is already running.
Maintenance activation still requires completed jobs and quiesced clients and
schedules; an automatic race-free handoff remains open.

All five installer tests passed. In addition to preflight failures, they verify
that an actual running executable retains its original inode and stays alive
after publication, new launches see the new file, and an injected third-copy
failure leaves every old binary intact and cleans the private staging folder.
Both shell scripts passed `sh -n`. These tests are local unprivileged fixtures,
not installed systemd update acceptance.

## Updated staged GUI: physical round trip

Job `3de815b899364a9b9b4b1f324bad3b98` exited 0 in 36.050 seconds on
Ubuntu using the GUI built by `a1d3b9642a514b6e9dbf475740b5c31e` (exit 0).
This snapshot includes disk cards, the folder-backup toolbar, hidden idle
progress and readable results. Twenty-two physical X11 clicks with native
portal folder dialogs completed backup and restore at 1024x768, scale 1.
The destination remained empty after click 20 (without consent), and both
fixture files subsequently matched byte for byte; backup sources were unchanged.

- GUI SHA256: `1f8d0d1f7ac6e2d2398e7b3807bc8176a64d45d5d9d9340da5b4bcf17d266f8a`.
- Daemon SHA256: `d915f4ca76095e6bfd1afc17249777bd60c61e1b2c6d65954485173e3dc9c213`.
- Remote capture: `visual/native-current-mouse-roundtrip.xwd` in the staged
  `/home/codex/linuxreflect-gui-audit-20260923` workspace. Capture generation
  succeeded. Converted local capture
  `/tmp/opencode/lr-native-current-mouse-roundtrip.png` was visually reviewed:
  destination, file count, restored bytes, optional technical report and
  bottom actions are visible. The application window is 1024x768 within the
  larger 1920x1080 Xvfb capture.

Scope remains an unencrypted folder round trip on private Xvfb/D-Bus as
`codex`, not installed GNOME, physical Wayland or a block-device operation.
Later library presentation edits are not covered by this binary hash.

Confirmed remaining result-screen usability issue: the successful restore
still has a "Restoration progress" heading and only Back plus disabled Cancel
in its footer. Add an explicit completed state and Done navigation; retain
recovery actions for failed or disconnected jobs instead of treating every
non-busy state as success.

Source inspection through native LSP and the corresponding callback bodies
also identifies shared result-state leakage: both step-4 pages read the same
`result-text`, `progress-text`, `status` and `busy`, while starting a backup
or restore advances only that operation's wizard. After completing both
operations, returning to the other wizard can display the latest operation's
report under the wrong operation heading. This needs an operation-bound job
view, not merely a Done button or a test of `!busy`. The regression scenario
is backup success, restore success, then switching back to Backup; also test
switching tabs while the other operation is running. Runtime reproduction of
the cross-tab presentation is still pending.

The job-view acceptance states must distinguish starting (before job ID),
running, cancellation requested, connection lost with a potentially live job,
confirmed success, confirmed failure and confirmed cancellation. Cancellation
request failure and transport loss must preserve the live job and admission
lock. Only a terminal daemon result may release that lock after Started;
Done navigation must never imply that a disconnected job has stopped.

## Library presentation follow-up

The library now uses member creation timestamps (rather than displaying the
chain timestamp as a raw integer), formatted in explicit UTC. Missing or
out-of-range timestamps remain unknown. Backup types have readable names,
copy ordinals are one-based, paths wrap, and a native Restore button replaces
the mouse-only hit area. `cargo xtask ci` job
`fb65bc8dc35f4332ba6be6a0c51fd6dc` exited 0 in 129.138 seconds, including
compilation/tests of these edits and the earlier installer/result changes.
Keyboard interaction and narrow-window runtime checks remain pending.

## Operation-bound job presentation

Follow-up code adds separate Backup and Restore presentation records and
explicit starting/running/cancelling/disconnected/succeeded/failed/cancelled
stages. Each wizard renders its own report; global automation progress fields
remain compatible. Done is available only for a terminal presentation and
when no action is busy. Cancellation request failures retain the existing
job state, and transport loss after Started keeps the admission lock and
shows disconnected rather than completed. These changes postdate the CI
snapshot above. `cargo test -p lr-gui --all-targets` job
`60dc99a7224546f7bbb605b766f57936` exited 0: 24 unit tests passed and both
display integration executables compiled (their cases are ignored by default).
The resulting `root_gui-6a602627df9ed1d8` was then run explicitly through WSL
root with `LR_ROOT_TESTS=1`: the X11 create/restore test passed in 2.04 seconds,
with no skips. This remains script-driven integration evidence, not the
physical cross-tab regression check.

A physical X11 source-page capture at 1024x768 confirmed the single Next
action remains visible after removal of the inactive Cancel button:
`/tmp/opencode/lr-jobview-backup-source.png`, local GUI SHA256
`9815907e0484d4a31f904b0a33d2d928cb802fb31ded6027587cb2a91fbd2ff9`.
The physical full round trip, cross-tab report isolation and Done checks
remain pending for this version.

The physical-input harness now accepts bounded `--capture-after-click N`
checkpoints and up to 32 clicks, preserving each intermediate screenshot
without overwriting existing files. A short Ubuntu X11 run on the previous
staged GUI successfully captured after the first tab click and at the end;
both GUI/daemon hashes stayed unchanged. This verifies capture plumbing only,
not the new job presentation. Current GUI sources and workspace manifests
have been copied to the Ubuntu staging workspace for the next build; this
is not an installation.

## Latest physical interaction evidence

The updated staged Ubuntu build (`a7755b2eb2524323bab8ee667da8b297`, exit 0)
passed the 25-click native-dialog round trip in job
`356c390508f743b9a68fdd1242aab91f` (exit 0, 41.054 seconds). Destination
contents remained empty before consent; both restored files matched byte for
byte and sources were unchanged. GUI SHA256:
`54139c148f5a78ff314abad7bf2c10d002b6b700ee326c22acf6335e1208a10d`;
daemon SHA256: `d915f4ca76095e6bfd1afc17249777bd60c61e1b2c6d65954485173e3dc9c213`.

Visually reviewed local captures from this same process:

- `/tmp/opencode/native-jobview-roundtrip-click-23.png`: returning to Backup
  after Restore retains the backup image, statistics and consistency warning,
  with a Backup completed heading and Done action.
- `/tmp/opencode/native-jobview-roundtrip-click-24.png`: Restore retains its
  own destination and statistics with a Restore completed heading.
- `/tmp/opencode/native-jobview-roundtrip.png`: clicking Done returns to Disks.

An additional physical run on the same unchanged binaries created a backup,
loaded History using its Refresh button, then selected the row's Restore
action with twelve Tab presses and Return. The reviewed
`/tmp/opencode/native-library-keyboard-click-14.png` shows the backup's readable
type, UTC timestamp, size and catalog path; `native-library-keyboard.png` shows
the selected image in Restore with Next enabled and an image-from-history
status. The fixture-backup and unchanged-source assertions passed. This
verifies keyboard library selection, not a second full restore.

In the current local matrix, the four 1024x768 scale-2 initial-page captures
were visually reviewed: pinned actions and navigation remain visible. A
separate physical scroll and Tab capture,
`/tmp/opencode/lr-jobview-restore-scroll-scale2.png`, confirms access to the
passphrase-file picker and visible keyboard focus. Other matrix cases and
populated wizard steps still require review. These tests use private X11,
not the installed GNOME session or physical Wayland input.

## Current resize matrix status

Job `a5d5c42fd15a49cd813962a9bf4b6110` completed with exit 0: 36 initial-page
cases captured with exact requested dimensions and repeated enlarge/shrink
cycles; binary fingerprints stayed unchanged. Evidence is under
`/tmp/opencode/lr-matrix-jobview-20260923`. Visual review currently covers all
four pages at both 1024x768 and 1280x720 scale 2, plus the 1920x1080 scale-2
Backup/Restore pages.
Pinned navigation/actions fit in those captures; lower form fields require
scrolling. Remaining images are not yet accepted merely because capture passed.

`gui_visual_smoke.py --layout-after-click N` now captures all three required
window sizes at a physically reached wizard step, then restores the original
size before continuing input. A local scale-2 Restore-page smoke run verified
all three dimensions, four captures and unchanged binary fingerprints. This
adds populated-step resize coverage capability; full wizard runs using it
are still pending.

## Populated resize run and readable restore review

Job `51cfb18f07a04780a1b29ea4d94d58f5` exited 0 in 44.063 seconds:
eight physically reached wizard steps were resized through all three required
dimensions at scale 1, followed by an unchanged-source assertion and exact
two-file restore comparison. The destination remained empty before consent.
The 24 populated-step captures are in the Ubuntu staging `visual/` directory
with prefix `populated-scale1-click-`. The 1280x720 backup-review (click 11)
and restore-review (click 19) captures were downloaded, converted and visually
reviewed under `/tmp/opencode/`: source/destination text, review content,
confirmation checkbox and bottom actions fit. Restore now is visibly disabled
before consent. The other populated-step captures remain unreviewed.
The 1024x768 destination pages (clicks 10 and 18) were also visually reviewed:
the chosen locations and Next actions are available. The restore location is
horizontally clipped in its editable field but displayed in full by the
subsequent review; this does not establish arbitrary-long-path acceptance.
This is the same staged GUI fingerprint as the earlier job-view round trip.

A subsequent source change replaces mandatory internal restore-plan labels
with a readable operation, formatted source size, required image count and
an explanation of the recorded consistency. Engine warnings remain visible;
the previous detailed plan is available behind Technical plan. Unknown values
are not promoted to stronger consistency or a known format. A regression
test checks warning retention and omission of the authorization token from
the readable summary. Editing restore inputs clears both summary and details
expansion along with the existing approval invalidation. Compilation and
physical review of this later presentation change were initially pending.
`cargo xtask ci` job `75109bc89ebe4db8b7f9ec361a702aae` subsequently exited 0
in 131.136 seconds, covering the operation-bound job view and readable restore
summary. The new GUI sources have been sent to Ubuntu staging; its new build
and physical review remain pending. Earlier screenshots do not cover the
updated summary.

## Current 200% review and scrolling coverage

Full CI `7a9d6e94ae064d84a5b446a466d239ff` exited 0 in 102.114 s, including
the pinned confirmation and notifier changes. Flattening the Restore review's
conditional nested layout postdates that gate: the scroll content layout now
measures its wrapped text directly. Ubuntu build
`f2478a75a93e4685a6dc195d4a27a31c` exited 0. Physical job
`02de72bbf4d1442eb840df7f3f429e28` exited 0 (37.053 s) with GUI SHA256
`c0aed99b183004836a0c9bd97b500eda2545812aada0ebec4ffcf2e181c88ce9`
and daemon SHA256
`d915f4ca76095e6bfd1afc17249777bd60c61e1b2c6d65954485173e3dc9c213`.
The native-dialog backup/restore scenario shrank from 1920x1080 to 1024x768
at 200%, scrolled thirty wheel ticks, and then confirmed and restored.
The destination was empty before consent; source contents remained unchanged;
both restored files matched byte for byte. Visually inspected captures
`/tmp/opencode/scale2-flat-review-roundtrip-before-keys.png` and
`/tmp/opencode/scale2-flat-review-roundtrip.png` show the end of the wrapped
warnings and Technical plan control, accessible unchecked confirmation with
disabled Restore, then Restore completed (two files, 300.0 KiB) and Done.
This establishes reaching the end of the collapsed review in this fixture.
Expanded technical details, arbitrary long paths, keyboard-only use, the
remaining populated size/scale matrix, and installed GNOME remain unverified.
The captures use a private Xvfb/session bus on Ubuntu, not the installed desktop.
Full CI `03aedd7133c74285b5efeabc0b7ee281` subsequently exited 0
(111.146 s), covering the flattened layout. A display-only lifecycle
regression was added after that CI started and is not counted as verified by
this result. Its separate Xvfb execution must establish the lifecycle result.

**Pinned confirmation verified:** Ubuntu build
`3766caa587d94755bea944fe705fb0aa` exited 0. Physical job
`3f5d15d60aba466bb161288512530e4e` then exited 0 in 34.048 seconds on GUI
SHA256 `515668866f025916f62e53d651364532254305ab160085f6fa26a21bb320ec4d`.
The test created a backup through native folder dialogs at 200%, reviewed
the restore, asserted the destination was still empty, shrank the window
from 1920x1080 to 1024x768, and clicked the pinned confirmation and Restore.
Both restored fixture files matched byte for byte; source contents remained
unchanged. Inspected `/tmp/opencode/scale2-pinned-consent-roundtrip-before-keys.png`
shows the exact destination, unchecked accessible confirmation, and disabled
Restore action. The final corresponding PNG shows Restore completed, two
files, 300.0 KiB, and visible Done. This establishes the small-window action
path, not full review scrolling, keyboard-only acceptance, or the remaining
size/scale and installed-GNOME matrix.

After pinned consent, the `root_gui-85f4a90ef86159f6` executable named by the
successful full CI `f19e6ee0f9754dfd8ff1291e3cd2c320` also passed the explicitly
enabled X11 create/restore case as WSL root (2.04 s, one passed, zero ignored
in the selected case). This adds current scripted X11 data-round-trip
coverage to the physical small-window result above.

The preferred-height experiment did not fix the physical scenario:
`02d00fb5fbb9491daae02db0cb1f7399` exited 1, with the same clipped pre-input
review on GUI SHA256
`ae7537dcaf67c3f0d05fabfd127a53646a1e1507bddab20c01103135865e71b1`.
The ineffective height binding was removed. Explicit confirmation is now
placed outside the scrolling review, immediately before the pinned action
row. Its existing reviewed-plan/busy binding is unchanged. The subsequent
pinned-consent and flattened-review results above supersede the initial
pending build and physical-verification status.

Job `b811d27f99ac4bf3b84f45df13b2a908` also failed the restored-file-set
assertion (exit 1, 37.052 seconds). Thirty wheel ticks stopped at the same
visible summary position as ten ticks, with confirmation still below the
viewport. This supersedes the assumption that more wheel input alone would
reach consent. The proposed layout change binds the Restore ScrollView's
content height and its content layout height to the layout's preferred
height. It compiles: `8c4e3c58f8d04362ab014196b05b822c` passed 25 GUI unit tests
(two display tests ignored). Subsequent physical verification failed as
recorded above, and this height-binding experiment was removed.

The newly built `root_gui-6a602627df9ed1d8` also passed
`create_and_restore_through_the_gui_on_x11` explicitly as WSL root with
`LR_ROOT_TESTS=1` (2.04 seconds, one passed, no ignored tests in the selected
case). This checks the scripted data round trip after the layout change;
it does not check physical scrolling or the confirmation control position.

### Lifecycle inspection follow-up

**Admission ordering regression reproduced and fixed:** Xvfb job
`b1b96afd22f745589404c1d1d6e3c733` built successfully, then failed exactly at
`completion must not release admission before UI cleanup` (one failed, no
ignored tests in the selected run). `ActionsHandle::finish` now releases
`shared.busy` at the end of its UI closure, after clearing the old identity.
The expanded `completion_keeps_admission_closed_until_ui_cleanup` test passed
under Xvfb/software rendering (one passed, 0.05 s) after this change. It checks
closed admission before processing completion, then drains the actual Slint
event queue and verifies cleared identity, successful presentation, and new
operation admission. `cargo fmt --all` and targeted all-target GUI Clippy with
`-D warnings` passed. This is a deterministic in-process ordering regression,
not physical RPC/cancellation acceptance. The full CI result above predates
this lifecycle fix; duplicate terminal delivery and delayed GetJob handling
remain separate open items.

The next change binds GetJob's terminal handler to its expected job ID and
rechecks it inside the eventual UI closure. Stale failure text is also rejected
before updating shared failure state. The expanded Xvfb regression queues both
old success and old cancellation after replacement-job admission and verifies
that the new identity, busy flags, previous successful report, and empty failure
state survive (one passed, 0.04 s). GUI unit tests passed 25 cases (the display
case was run separately), and targeted all-target Clippy passed with warnings
denied. Nonterminal/error GetJob replies now update the operation panel as well
as the status line, preserving its disconnected stage and admission state.
This does not reconnect the event stream. Real RPC disconnect/cancel/retry and
late stream-terminal races remain unverified; this regression directly drives
terminal UI handlers. Current full CI and Ubuntu rebuild remain pending.

The same regression was then extended to deliver the original stream's late
completion and disconnect after replacement admission. It failed on the new
job's shared busy assertion. Each admitted action now increments a checked
generation, captured by its ActionsHandle; finish/fail reject obsolete
generations before changing UI or shared failure state. The expanded Xvfb
case then passed (one passed, 0.05 s), as did 25 GUI unit cases and all-target
GUI Clippy with `-D warnings`. This verifies terminal-handler isolation in a
controlled event-queue interleaving. Late progress messages and actual RPC
disconnect/cancellation recovery still require coverage. These lifecycle
changes are local and have not yet been rebuilt or installed on Ubuntu.

Late Started/Bytes delivery was subsequently added to the deterministic Xvfb
regression. Before the fix, Started overwrote the replacement job ID, allowing
an old-ID terminal reply to clear its busy state; the test failed on that
assertion. Both progress closures now check the captured action generation and
active admission flag before applying state. The expanded test passed (one
passed, 0.04 s), preserving replacement ID and progress as well as busy and
failure state. Production backup and restore streams both pass their captured
ActionsHandle to progress delivery. This remains controlled event-queue
coverage; real transport failure, cancel/retry, and Ubuntu verification remain
open. Full CI is required for the combined lifecycle changes.

A further same-generation case now delivers a stream disconnect after confirmed
completion but before a replacement action is admitted. Terminal handlers also
require active admission, preventing the completed result from being overwritten
while idle. The combined Xvfb regression passed (0.05 s). This addition postdates
the start of CI `002d698595fc41ef96f6f33e4dd2225b`, which exited 0 (123.118 s);
that run alone cannot certify the final source state. Source review also found early shared-busy release in
successful source inspection (`probe_source`) before its queued UI update;
non-job inspection/history/discovery completions need the same ordering audit.

That audit found the same worker-side release in successful disk discovery,
disk inspection, history loading, source probing, and restore preparation.
All five now release shared admission inside their UI update, after applying
results. Source-probe and restore-plan rejection branches also release it when
the inputs changed; disk inspection no longer returns before releasing it when
the selected source changed. Formatting and 25 GUI unit tests passed after
this edit. These tests cover input invalidation models but do not establish
all five RPC/UI completion paths; rebuilt daemon-backed GUI round-trip and
current full CI are still required. This edit also postdates CI 002d698595fc41ef96f6f33e4dd2225b.

After these ordering changes, local GUI/daemon bins and tests built successfully
in job `844a00425f074317bda2ba37cd980a63` (27.038 s). Explicit recompilation
identified `root_gui-6a602627df9ed1d8`; running its exact
`create_and_restore_through_the_gui_on_x11` case as WSL root with
`LR_ROOT_TESTS=1` passed (2.03 s, one passed, no ignored tests in the selected
case). This establishes the rebuilt scripted daemon-backed file round trip,
not physical mouse recovery. The updated GUI and notifier `src/lib.rs` files
were synchronized to Ubuntu staging; its rebuild and installed-GNOME check
remain pending. The staging tree has no `contrib/` directory, so it must not
be assumed to be a complete installer payload.

Ubuntu staging build `3d5bd4c1a4f2456f8df785111d3c9199` subsequently exited 0
(28.064 s), compiling the updated GUI and session notifier with daemon bins
and tests. This is build evidence only. The physical expanded-review check
`4e792cc4fea24df58512fa6ddc887d77` and local full CI
`1a74b3ec3f544642aa7dc8b4513eb208` were submitted separately; their terminal
results and the expanded screenshot still need inspection.

CI `1a74b3ec3f544642aa7dc8b4513eb208` exited 0 (107.101 s), covering the
combined lifecycle and non-job completion changes. Physical job
`4e792cc4fea24df58512fa6ddc887d77` exited 0 (37.057 s) on Ubuntu GUI SHA256
`fc1e8ca286db7f13be90813feba5acefc768821fb4c57cb0d330d33300bb7a1a`.
The source was unchanged, backup image created, and destination empty after
click 19. Inspected `/tmp/opencode/scale2-lifecycle-expanded-review.png`
shows Technical plan checked at 1024x768/200%, pinned unchecked consent and
disabled Restore. The details remain below the viewport: this establishes
the toggle only, not reading the expanded plan. The harness now supports
bounded `--scroll-after-final-clicks X,Y,TICKS`, sharing the existing total
ten-action limit, to inspect the expanded content. Its parser/help ran
successfully and the updated harness was copied to Ubuntu; physical execution
of the new sequence remains pending. No restoration was requested in this run.

The follow-up `9da8d5309ec448d3b321b5ea768ceb0e` captured the bottom of the
expanded technical plan after physical scrolling on the same GUI fingerprint.
Inspected `/tmp/opencode/scale2-expanded-review-bottom.png` shows the final
consistency warning completely, with pinned unchecked confirmation, Back, and
disabled Restore visible at 1024x768/200%. Backup/source assertions passed,
but the command exited 1 during TemporaryDirectory cleanup with ENOTCONN on
`gvfs`, after stopping the private bus. It is not an overall passing run.
The local-fixture portal environment now sets `GIO_USE_VFS=local` before bus
activation to avoid a GVfs FUSE side effect. This harness-only adjustment needs
physical revalidation and does not establish network-location chooser support.
A subsequent read-only findmnt query for the fixture's runtime/gvfs path
returned no mount entry; no unrelated session mounts were touched.

Revalidation with the local GIO backend, job
`9817bbb9766446baa6401a9ec38a16a7`, exited 0 (40.056 s), including cleanup.
The same binary fingerprints and backup/source checks were recorded.
Inspected `/tmp/opencode/scale2-expanded-local-vfs.png` confirms the bottom
of the expanded plan and visible unchecked consent/disabled Restore after
resize and physical scrolling. This verifies this local-folder review path
at 1024x768/200%; it does not cover network dialogs or an applied restore.

Source inspection of `Actions::check_job`, `ActionsHandle::finish`, and
`Actions::start` originally identified these verification points:

- A nonterminal status query updates only the shared status line; the
  operation-bound panel retains its disconnected message. The event stream
  is not reconnected by this query. Test that subsequent cancellation and
  terminal status queries remain usable and understandable.
- `finish` releases the atomic admission flag before its queued UI update
  clears the old job identity. Check interleavings with another admitted
  action and delayed status responses before claiming terminal-race coverage.
  This is a source-level concern, not a reproduced runtime race.

Native LSP navigation and current source inspection confirm the second point:
`Actions::start` admits work solely through `shared.busy.swap(true)`, while
`ActionsHandle::finish` clears this atomic before enqueuing the UI reset.
The regression should hold the UI event queue, deliver completion, attempt
admission, then drain the queue and verify that the completed job cannot clear
a newer operation's identity or busy state. A separate status-query regression
must delay a terminal GetJob response until after a new job starts and verify
that both receipt and eventual UI application reject stale identity. Testing
only the existing receipt-time guard is insufficient because terminal handling
enqueues another closure. These are test requirements, not executed evidence.
For the disconnected case, drive GetJob through running, cancel-request failure,
and a confirmed terminal response; assert operation-panel text, job identity,
busy/admission and retry availability at each step. Current root GUI happy-path
automation does not establish these recovery or interleaving properties.

Follow-up job `b9f9840f68504f99bce079df41c30c53` failed the restored-file-set
assertion (exit 1). The source remained unchanged and a backup image was
created. Its inspected `scale2-small-keyboard-roundtrip-before-keys.png`
shows that ten wheel ticks did not yet reach the confirmation control at
1024x768/200%. The final screenshot shows Disks rather than a restore result:
the unverified fixed Tab sequence navigated away. This is a failed physical
acceptance attempt, not evidence of an engine restore failure or successful
keyboard confirmation. The harness now allows bounded mouse clicks after the
final resize and scroll, preserving the pre-input screenshot and byte checks.

Ubuntu build job `2a119d1bbbfd47989ce9d0b707797bea` exited 0. Job
`b8acaacbeb80471d8acd9219332cf7c8` then exited 0 in 38.051 seconds: physical
backup at scale 2, unchanged source, empty restore destination at review, and
21 resized populated-step captures. GUI SHA256:
`a52608c404c64b1a58fc1a8ebee83788844e3771510d69141573ca3910a705cd`.
The inspected `/tmp/opencode/populated-scale2-review.png` shows the readable
review, exact destination, preserved warnings and unchecked consent at
1920x1080. Its `-click-19-1024x768.png` counterpart keeps the footer visible
but requires scrolling to reach consent; this run does not prove that scroll
interaction or perform a restore.

The X11 integration executable from the latest CI log,
`root_gui-85f4a90ef86159f6`, also passed its explicitly enabled create/restore
test as WSL root in 2.04 seconds, without skips. The new summary warning/token
regression is present and passes in the CI log.

The physical harness now supports a final required-size resize before scroll
and keyboard input, with a pre-keyboard capture. A short local scale-2 run
confirmed 1920x1080 to 1024x768 resizing and both captures. This enables a
separate bounded acceptance check of reaching consent in the smaller window.

## Initial confirmed findings

- `DiskListEntry.partition` serializes `None` as JSON `null`; the old GUI
  selected disks only when the key was absent.
- `ActionsHandle::fail` cleared the displayed busy flag but not the atomic
  busy flag used to admit subsequent actions.
- A cancellation RPC failure used the job-failure path and removed the live
  job identifier from the UI.
- Backup/restore clients accepted EOF without a `Finished` event as success.
- Restore callbacks used an existing token independently of current input
  fields, and the RPC client supplied `confirm: true` unconditionally.
- `token_secret_path` chmods its chosen runtime directory to `0700`, including
  the default directory shared with the group-accessible daemon socket.
- Disk/history hit areas were layout cells rather than full-row overlays.
- Existing root GUI tests invoke callbacks through scripts; those results do
  not validate pointer hit areas, file dialogs, resizing, or wizard usability.
- `LocalDestination::list` returns set-relative paths including the chain
  directory. Catalog scanning preserves these names and `ListChains` forwards
  them. The old GUI inserted `chain_id` again, duplicating the directory.

## Execution constraints

Update after restart: native Longrun health now includes the exact project
root. Job `b9d0deddc7d447cdbdedbe8fb3d0b6b5`, running `cargo test -p lr-gui
--lib`, completed with exit 0: 16 passed, 0 failed, 0 ignored. This compiled
the GUI library and its Slint integration. The job's wake receipt was revoked
after further session input; its terminal result was recovered by the existing
job ID without resubmission. GUI runtime and full-workspace gates remain open.

### Initial enrollment constraint (resolved)

Native OpenCode Longrun was available, with automatic continuation reported by
health. The user approved enrollment of `/home/w0w/linuxreflect`. The native
enrollment tool rejected this home-scoped session with `Open an exact Git
project first`. After verifying the exact Git root, that root alone was added
to `~/.config/opencode/longrun.json`; JSON validation passed. No Codex settings
were changed. The already-running backend retained the old allowed-root list
until OpenCode was restarted. The successful run above supersedes this blocker.

Next, build current GUI/daemon binaries and proceed with runtime UI checks and
the remaining acceptance items above. Library tests do not substitute for the
mouse-driven and privileged integration gates.

The standalone restore state module was compiled with `rustc --edition=2024
--test crates/lr-gui/src/review.rs` and its five tests passed: edit-and-revert
with a delayed response, confirmation and single consumption, changed target,
and a newer request superseding an older one, plus credential-path changes
requiring a new review. The approved operation carries both the token and the
reviewed passphrase-file path into the apply RPC. This verifies the pure state
machine only, not its Slint integration or the server-side token checks.

The standalone history path module has three passing tests covering
set-relative paths, SFTP/root destinations, and escaping/malformed member
names. `cargo fmt --all -- --check` passes after these changes.

The existing GUI build-script executable was run directly with output under
`/tmp/opencode` for a short Slint code-generation check. Both wizard layouts
compile at that boundary. This does not compile the Rust GUI client or verify
its runtime layout, scaling, dialog interaction, or mouse workflows.

The selected-device view now obtains `SourceLayout` through the daemon's
`DiskMap` RPC, including model, total size, partition starts, filesystem types,
mount points and discovery warnings. Relative coordinates are based on the
reported logical sector size. Three standalone geometry tests pass for 512/
4096-byte sectors, overflow/out-of-device extents and missing geometry. No
runtime device-map or click acceptance is claimed yet. Whole-device cards
remain outstanding; the current view still starts from a device list.

Device writes during testing must target only devices created for the tests.
Preserve read-only backup sources, server-side authorization, token validation,
and target revalidation. Repository documentation and code remain in English.
