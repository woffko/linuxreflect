# GUI redesign plan

The S15 GUI works end to end, but it reads like a form: four tab buttons, one
disk shown at a time, wizards that send the user back to the Disks tab to pick
a device, and a history page that needs a set name typed in before it shows
anything. This plan reorganises it around the way Macrium Reflect for Windows
is used, without adding operations the frozen specification does not have.

## Principles

- **Start from the thing you are protecting.** The main view lists every disk
  with its partition map; the backup and restore actions sit on the disk or
  partition they apply to.
- **Nothing is typed in ordinary use.** Sources, destinations, images and
  targets are chosen by clicking a map, a list or a native dialog. Text fields
  stay available under "Advanced" for paths a dialog cannot reach (SFTP).
- **A wizard is one place.** Its steps are listed on the left, the current
  step is on the right, Back/Next/Finish are at the bottom, and choosing a
  device happens inside the step instead of on another page.
- **Say what will happen before it happens.** Every wizard ends in a
  plain-language summary; the technical plan is one click away. A restore
  names the disk, its model and size, and the partitions that will be
  overwritten, and needs an explicit confirmation.
- **Errors are states, not strings.** Loading, empty, unavailable and failed
  states each have a message and, where it makes sense, a Retry button.
- **It fits the screen.** Everything is reachable at 1024x768 with 200%
  scaling: the navigation collapses to a top bar, long paths elide with the
  full path in a tooltip, and every page scrolls.

## Layout

```
┌──────────────┬───────────────────────────────────────────────────────┐
│ LinuxReflect │  Back up                                   [Refresh]  │
│              │ ┌───────────────────────────────────────────────────┐ │
│ ▸ Back up    │ │ Disk 1  Samsung SSD 980 · 500 GB · GPT            │ │
│   Restore    │ │ ┌──────┬──────────────────────────┬─────────────┐ │ │
│   Activity   │ │ │ EFI  │ root  ext4  420 GB       │ swap  8 GB  │ │ │
│              │ │ └──────┴──────────────────────────┴─────────────┘ │ │
│              │ │ Image this disk…   Image selected partition…      │ │
│              │ └───────────────────────────────────────────────────┘ │
│              │  Back up a folder…                                    │
├──────────────┴───────────────────────────────────────────────────────┤
│ Backup of /dev/sda  ███████████░░░░░ 64%  1.2 GB/s   [Cancel]         │
└──────────────────────────────────────────────────────────────────────┘
```

- **Back up** — every disk as a panel: header (model, size, partition-table
  type), a proportional partition bar coloured by filesystem, and actions.
  Clicking a tile selects the partition; the actions follow the selection.
  Service devices (loop, ram, zero-size) stay hidden behind a toggle.
- **Restore** — the backup library. The destination folder is remembered;
  every set in it is listed with its chains and members (full, incremental,
  differential, date, size, encrypted or not). Each member has Restore… and
  Verify. "Browse for an image file…" covers images outside the library.
- **Activity** — the current job with progress, throughput and elapsed time,
  and the jobs of this session with their results and technical reports.
- **Job strip** — while a job runs, a strip at the bottom shows it on every
  page with Cancel, so the user can look at other pages without losing it.

## Wizards

Backup (opened from a disk, a partition, or "Back up a folder…"):

1. **Source** — the chosen disk or partition shown on its map, or the folder.
   It can be changed here without leaving the wizard.
2. **Destination** — a folder picker with the recent destinations as one-click
   choices, and the backup name (defaulting to the source name).
3. **Options** — backup type (full, incremental, differential), compression,
   encryption with a passphrase file, consistency method and bad-sector
   policy. Defaults are safe and pre-selected; the page says what they are.
4. **Summary** — the `ProbeSource` plan in plain language (what, where, how
   consistent, estimated size), with the technical plan expandable.
5. **Progress and result.**

Restore (opened from a library member or an image file):

1. **Image** — what the image contains (source disk, date, kind, encrypted).
   An encrypted image asks for its passphrase file here.
2. **Destination** — for a disk image, the disk maps with the ineligible
   devices greyed out and the reason shown; for a file image, a folder.
3. **Summary** — the token plan in plain language: the exact target with model
   and size, what will be overwritten, and a confirmation checkbox. Changing
   anything on an earlier step invalidates the plan.
4. **Progress and result.**

## Code structure

- `ui/theme.slint` — palette (light and dark), spacing and type scale.
- `ui/widgets.slint` — navigation item, disk panel, partition bar, step list,
  wizard frame, message banner with Retry, empty state.
- `ui/pages/*.slint` — back up, library, activity, backup wizard, restore
  wizard.
- `ui/main.slint` — the window, navigation, job strip and attribution.
- Rust: the view models stay in `lr-gui` modules (`devices`, `history`,
  `review`, `job_view`, `result`); `lib.rs` keeps only wiring. The automation
  script keeps its property and callback names so existing scripted runs stay
  valid.

## Order of work

1. Split `main.slint`, add the theme and the navigation shell.
2. Disk panels for every disk with their maps and per-disk error states.
3. Backup wizard with the step list and in-wizard source selection.
4. Library listing every set at a destination (`ListSets` with no set name).
5. Restore wizard with in-wizard destination maps and the overwrite summary.
6. Activity page and job strip.
7. Resize, scaling and keyboard pass at 1024x768, 1280x720 and 1920x1080 at
   100/150/200%, on X11 and Wayland, with real round trips on owned devices.
