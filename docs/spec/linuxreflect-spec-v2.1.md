# LinuxReflect — Technical Specification v2.1

**Status:** implementer-ready draft. Supersedes v2.0. Incorporates external review R1 (developer, Sep 2026) and internal self-review R0. Every change is logged in Appendix A with the review item that triggered it.

**Audience:** an AI coding agent (Codex-style) implementing from this document, plus the human maintainer/reviewer loop. The document is written so that the agent does not have to make architectural decisions; where a decision is deliberately deferred, it is listed in §M.

**Conventions:** "MUST/MUST NOT" are hard requirements. "SHOULD" is the default unless a documented reason exists. Code identifiers are illustrative but binding for naming (crate names, trait names, CLI verbs, config keys).

---

## A. Overview, Goals, Non-Goals, Platforms

LinuxReflect is a GUI-driven, system-level backup and disaster-recovery tool for Linux, positioned as the Linux equivalent of Macrium Reflect. Core language: **Rust**.

### A.1 What "live backup" means on Linux (read this first)

Linux has no VSS. A live, point-in-time **block** snapshot of a mounted filesystem is only possible when the filesystem sits on a snapshot-capable layer that was in place **before** the filesystem was mounted (LVM, Btrfs/ZFS at the filesystem level, or an out-of-tree kernel driver). Stock device-mapper cannot be inserted underneath an already-mounted plain partition (`blk_interposer` was never merged; `dm-ioctl.h` has no interpose flag). LinuxReflect therefore:

- provides true point-in-time backups where the platform allows it (LVM, Btrfs, later ZFS);
- provides **quiesced** (frozen) or **offline** backups where it does not;
- always reports the **consistency level actually achieved** (§D.2) instead of silently degrading;
- never fakes a snapshot.

### A.2 MVP (first deliverable)

Slices 1–11 (§K): `lr-core`, `lr-format`, `lr-crypto`, `lr-fsmap`, `lr-snapshot`, `lr-engine`, `lr-store`, `lr-daemon`, `lr-cli`. Capabilities:

- Block-mode image of a partition or whole disk (used blocks only for ext4/xfs; raw with zero suppression otherwise).
- Stream-mode image of Btrfs (via `btrfs send`).
- Full / incremental (scan-and-diff) / differential chains, chain-based retention.
- Point-in-time consistency on LVM and Btrfs; frozen consistency on non-root plain partitions; offline consistency for unmounted devices.
- Encryption (Argon2id + AES-256-GCM / ChaCha20-Poly1305), compression (zstd), verification.
- Destinations: local path, mounted network path (SMB/NFS via mount), SFTP.
- Root daemon with gRPC-over-UDS IPC, polkit authorization, CLI client.
- Restore to an unmounted target of equal or larger size.

### A.3 Non-goals for the MVP (explicit)

- No GUI (Slice 15). No rescue media (Slice 16) — until then, offline backups of the root disk are performed by booting any live distro and running the statically linked `linuxreflect` CLI.
- No file-mode backup (Slice 12, first follow-on). No FUSE.
- No filesystem-aware resize on restore (`--resize` removed; see §H.4).
- No kernel CBT driver. Incrementals are scan-and-diff (§D.4); an optional `blksnap` provider is post-MVP.
- No ZFS. No NTFS/FAT used-block maps (raw + zero suppression only). NTFS partitions are restored sector-for-sector; there is no NTFS *file-level* restore.
- No LVM-aware or LUKS-aware whole-disk imaging: a PV or LUKS container inside a whole-disk image is captured as an opaque raw partition (offline consistency only). Individual LVs are backed up live via `--source /dev/vg/lv`.
- No cloud object storage, no email, no PXE, no consolidation/synthetic full, no passphrase change, no cross-set dedup.

### A.4 Supported platforms — capability matrix, not `uname`

| Platform | Notes |
|---|---|
| Debian 12+, Ubuntu 22.04+ | Default installs use plain ext4 → Frozen/Offline/None consistency unless LVM was chosen at install. |
| Fedora 40+ | Default Btrfs → Stream mode, point-in-time. |
| RHEL/Alma/Rocky 9 (kernel 5.14 + backports), RHEL 10 | LVM/XFS typical → point-in-time via LVM. No Btrfs. |
| Arch | Varies. |

There is **no** hard kernel-version check. `lr-core::caps::probe()` detects at runtime: `nbd` module loadable, `ublk` present (`/dev/ublk-control`), `fsfreeze` ioctls, `O_DIRECT` on target, `btrfs send` availability, `lvm2` tools, `polkit` version (pidfd subject support ≥ 121). Missing capabilities disable features with a clear error. The Freeze provider logs a warning on kernels < 5.17 (upstream fix "vfs: make freeze_super abort when sync_filesystem returns error"; backports unknown) — the deadman timer (§E.4) makes it safe regardless.

---

## B. Technology Stack

Every "X or Y" from the original plan is resolved. Versions are **tested versions to be recorded at bootstrap**, not selectors (§L.5).

| Concern | Decision | Version policy / constraint | Rationale |
|---|---|---|---|
| Language | Rust, edition 2024 | MSRV = Slint's MSRV at bootstrap | Single toolchain. |
| Async runtime | tokio 1 | latest stable | Required by tonic/russh. |
| CLI | clap 4 (derive) | latest stable | — |
| Errors | thiserror (libs), anyhow (bins) | — | Typed at crate boundaries. |
| Logging | tracing, tracing-subscriber, tracing-journald | — | journald in daemon. |
| Config | serde + toml | — | — |
| Compression | zstd 0.14 (libzstd) | verified current Sep 2026 | — |
| AEAD | aes-gcm (RustCrypto) + chacha20poly1305 | latest stable | ChaCha fallback without AES-NI. |
| KDF | argon2 (Argon2id) | latest stable | RFC 9106. |
| Hash / MAC | blake3 (keyed mode) | — | Keyed content hashes and MACs. |
| CDC (file/stream mode) | fastcdc (v2020) | — | Deterministic boundaries. |
| Partition tables | gpt, mbrman | — | Pure Rust R/W. |
| ioctls / syscalls | nix, libc (in `lr-unsafe`) | — | BLKGETSIZE64, BLKSSZGET, FIFREEZE/FITHAW, SEEK_HOLE, pidfd_open. |
| LVM | `lvcreate/lvremove/lvs` CLI | lvm2 ≥ 2.03 | No usable Rust API. |
| Btrfs | `btrfs` CLI (`subvolume snapshot -r`, `send`, `receive`, `subvolume list`) | btrfs-progs ≥ 6.x | Send stream format is versioned and stable; CLI avoids libbtrfsutil FFI. |
| Freeze | FIFREEZE/FITHAW ioctls | — | `fsfreeze(8)` semantics. |
| Block export | NBD (baseline): own newstyle NBD server + `nbd-client -u` ; ublk via libublk (optional) | ublk is `(Experimental)` in Kconfig | NBD is ubiquitous; ublk faster where present. |
| FUSE (file mode, follow-on) | fuser 0.18 | verified Jul 2026 | fuser provides FUSE plumbing only — no filesystem parsers. |
| IPC | tonic (gRPC) + prost over UDS | latest stable | Typed schema, streaming progress. |
| polkit / D-Bus | zbus 5, **zbus_polkit ≥ 5.1.0** | RUSTSEC-2026-0278 (CVSS 7.3 High), fixed in 5.1.0 | Subject uid type bug → PID-reuse bypass. |
| SFTP | russh + russh-sftp | latest stable | Pure Rust. |
| SMB/NFS | `mount.cifs` / `mount.nfs` via mount units | util-linux | Treated as mounted paths. |
| GUI (Slice 15) | Slint | latest stable | Rust-native; winit default on Linux (Qt preferred at runtime only if built with both). License: GPLv3 **or** Slint Royalty-Free (attribution) **or** commercial — choose in §M.1. |
| Rescue media (Slice 16) | mkosi: `BiosBootloader=grub` + signed shim/GRUB + distro kernel | mkosi ≥ 25 | Secure Boot via distro-signed chain; custom-signed UKI would need MOK enrolment. |
| Tests | losetup + sparse files, lvm2 on loop, qemu (OVMF + SeaBIOS) | — | — |

Rejected: C++20 (single toolchain), Qt/GTK for the GUI (Slint is Rust-native; cxx-qt reserved), qcow2/zchunk as image base (no per-chunk AEAD/dedup/chain semantics), raw dm-snapshot over mounted plain partitions (impossible — §A.1), dattobd/elastio-snap (archived Jan 2025), blksnap (unmerged; DKMS breaks on 6.14/6.17), FIEMAP as a used-block source (per-file only; physical addresses undefined on a mounted fs).

---

## C. Workspace Layout, Crates, Key Traits

```
linuxreflect/
├── Cargo.toml                # [workspace], [workspace.dependencies], resolver = "3"
├── Cargo.lock                # committed
├── deny.toml                 # cargo-deny: licenses + advisories
├── crates/
│   ├── lr-core/              # Error, ids, geometry, caps::probe, consistency enum, catalog types
│   ├── lr-unsafe/            # ALL unsafe: ioctls, pidfd, mmap; #![deny(unsafe_op_in_unsafe_fn)]
│   ├── lr-crypto/            # key hierarchy, AEAD, keyed BLAKE3, nonce counters, metadata-page codec
│   ├── lr-format/            # .lrimg: superblock, footer, chunk records, metadata pages, manifests
│   ├── lr-fsmap/             # UsedBlockProvider: ext4, xfs, raw-zero-skip (+ ntfs/fat later)
│   ├── lr-snapshot/          # BlockSnapshotProvider (lvm, freeze, offline, live-none), TreeSnapshotProvider (btrfs)
│   ├── lr-blocksource/       # BlockSource: O_DIRECT aligned reads over a block path + used map
│   ├── lr-store/             # Destination: local, mounted, sftp; set lock; atomic finalize
│   ├── lr-engine/            # backup/restore/verify; chains; scan-and-diff; whole-disk; stream mode
│   ├── lr-proto/             # prost/tonic generated (build.rs)
│   ├── lr-daemon/            # systemd service, gRPC server, AuthBackend (polkit), restore tokens
│   ├── lr-cli/               # `linuxreflect` binary; static musl build target for live-USB use
│   ├── lr-export/            # NBD server (+ ublk) exposing block images read-only   [Slice 13]
│   ├── lr-fuse/              # FUSE for file-mode images                             [Slice 12]
│   ├── lr-session/           # user-session helper: desktop notifications             [Slice 14]
│   ├── lr-gui/               # Slint GUI                                             [Slice 15]
│   └── lr-rescue/            # rescue-mode restore + boot repair; mkosi profile      [Slice 16]
└── xtask/                    # build automation, rescue image build, test fixtures
```

Rules: `lr-cli`, `lr-gui`, `lr-session` talk to `lr-daemon` only over gRPC and never open block devices. Every crate except `lr-unsafe` (and `-sys` crates) has `#![forbid(unsafe_code)]`.

### C.1 Key types and traits

```rust
// lr-core
pub enum Consistency { PointInTime, Frozen, Offline, PerFile, None }   // §D.2
pub enum ImageKind  { Block, Stream, File }                            // §D.1
pub struct SourceLayout { /* device path, fs type, mountpoints, holders, lvm/btrfs facts */ }

// lr-snapshot — two families, deliberately not one trait (R1-P0-2)
pub trait BlockSnapshotProvider: Send + Sync {
    fn id(&self) -> &'static str;                          // "lvm", "freeze", "offline", "live-none"
    fn supports(&self, src: &SourceLayout, opts: &SnapshotOpts) -> Support; // Yes | No(reason)
    fn create(&self, src: &SourceLayout, opts: &SnapshotOpts) -> Result<BlockSnapshot>;
}
pub struct BlockSnapshot {
    pub block_path: PathBuf,                               // readable device (or the origin for Frozen/Offline)
    pub consistency: Consistency,
    guard: Box<dyn Drop + Send>,                           // teardown: lvremove / thaw / cancel deadman
}
pub trait TreeSnapshotProvider: Send + Sync {
    fn id(&self) -> &'static str;                          // "btrfs" (later "zfs")
    fn supports(&self, src: &SourceLayout) -> Support;
    fn create(&self, src: &SourceLayout, opts: &SnapshotOpts) -> Result<TreeSnapshot>;
}
pub struct TreeSnapshot {
    pub roots: Vec<SubvolSnapshot>,                        // one per mounted subvolume
    pub consistency: Consistency,                          // PointInTime
    guard: Box<dyn Drop + Send>,
}
pub struct SubvolSnapshot { pub mount_target: PathBuf, pub subvol_path: PathBuf, pub snapshot_path: PathBuf, pub parent_snapshot: Option<PathBuf> }
impl SubvolSnapshot { pub fn send(&self, parent: Option<&Path>) -> Result<Box<dyn Read + Send>> /* btrfs send [-p] */ }

// lr-fsmap — each provider MUST include every block needed for a mountable filesystem (R1-P0-3)
pub trait UsedBlockProvider: Send + Sync {
    fn fs_type(&self) -> &'static str;                     // "ext4", "xfs", "raw"
    fn used_extents(&self, dev: &Path) -> Result<ExtentMap>; // byte extents, sorted, non-overlapping
}
pub struct ExtentMap { pub extents: Vec<(u64, u64)>, pub complete: bool } // complete=false => raw fallback

// lr-blocksource
pub trait BlockSource: Send {
    fn size_bytes(&self) -> u64;
    fn logical_block_size(&self) -> u32;
    fn read_at(&mut self, offset: u64, buf: &mut AlignedBuf) -> Result<usize>; // O_DIRECT, buf aligned to max(4096, lbs)
}

// lr-store
pub trait Destination: Send + Sync {
    fn open_set(&self, set: &SetId) -> Result<SetHandle>;
    fn lock_set(&self, set: &SetHandle, owner: &LockOwner, ttl: Duration) -> Result<SetLock>; // O_EXCL / SSH_FXF_EXCL
    fn create_tmp(&self, set: &SetHandle, name: &str) -> Result<Box<dyn WriteSeekSync + Send>>;
    fn finalize(&self, set: &SetHandle, tmp: &str, final_name: &str) -> Result<()>; // fsync + rename
    fn open_ro(&self, set: &SetHandle, name: &str) -> Result<Box<dyn ReadSeek + Send>>;
    fn list(&self, set: &SetHandle) -> Result<Vec<String>>;
    fn delete(&self, set: &SetHandle, name: &str) -> Result<()>;
}
```

---

## D. Concepts

### D.1 Image kinds

| Kind | Source | Unit | Consistency sources | Restore target |
|---|---|---|---|---|
| `Block` | partition, whole disk, LV | fixed chunks over used blocks | LVM (PointInTime), Freeze, Offline, live-none | unmounted block device ≥ source size |
| `Stream` | Btrfs subvolumes (ZFS later) | CDC chunks over `btrfs send` stream | Btrfs snapshot (PointInTime) | freshly formatted Btrfs (`mkfs.btrfs -U <uuid>`) + `btrfs receive` |
| `File` (Slice 12) | directory trees | CDC chunks per file | PerFile (or Btrfs snapshot → PointInTime) | existing filesystem |

Whole-disk images are `Block` with a multi-partition manifest (§G.7).

### D.2 Consistency levels (reported in manifest, CLI output, gRPC result)

| Level | Meaning | Produced by |
|---|---|---|
| `PointInTime` | All blocks/tree reflect one instant; filesystem quiesced at that instant | LVM snapshot (origin suspended with lockfs → fs frozen during snapshot creation), Btrfs read-only snapshot |
| `Frozen` | Filesystem frozen (`FIFREEZE`) for the **whole** read; point-in-time but writers blocked for the duration | Freeze provider (non-root volumes only) |
| `Offline` | Device not mounted and has no holders during the read | Offline provider, rescue environment |
| `PerFile` | Each file consistent as read; no cross-file point in time | File mode without tree snapshot |
| `None` | Live raw read of a mounted device; torn blocks possible | `--allow-inconsistent` only; image flagged |

Whole-disk images carry one level per partition; the image-level value is the minimum. The engine MUST refuse to produce `None` without `--allow-inconsistent`, and MUST print/return the achieved level.

### D.3 Backup sets, chains, catalog, locking

- **Backup set** = one destination directory for one job (`<dest>/<set-name>/`).
- **Chain** = one full plus its incrementals/differentials. Members: `<set>/<chain_id>/<seq>-<kind>-<image_uuid>.lrimg`.
- **Dependency rule:** an incremental N depends on **every** earlier member of its chain (chunks may be physically stored in any ancestor). Deletion is chain-granular: only whole chains are deleted (§J.3). Any future selective deletion requires consolidation (post-MVP).
- **Catalog** `<set>/catalog.json`: plaintext cache listing chains and members (uuid, kind, seq, parent uuid, created, source label, image kind, consistency, size). It is **not** authoritative: on any read the engine validates it against member superblocks (which are MAC'd, §G.3) and rebuilds it with `linuxreflect catalog rebuild`. This replaces v2.0's dual "chain.json sidecar + encrypted chunk".
- **Set lock** `<set>/set.lock` created with exclusive-create (`O_EXCL` locally, `SSH_FXF_EXCL` over SFTP) containing `{owner_host_id, daemon_pid, created, ttl}`; refreshed every ttl/3; stale locks (expired ttl) may be broken with `--break-stale-lock`. All of backup, retention, catalog rebuild, and `parent=latest` resolution run under the lock. The daemon additionally serializes jobs per set in-process.

### D.4 Incremental model: scan-and-diff (not CBT)

Without persistent dirty-block tracking, every incremental **reads and hashes all used blocks** of the source; it saves destination bandwidth/storage, not source I/O. Terminology throughout: *scan-and-diff incremental*. Block mode compares positionally (chunk *n* against chunk *n* of the parent state) using keyed BLAKE3; no global hash index is needed. A true CBT provider (`blksnap`, feature-gated) may later short-circuit the scan.

---

## E. Snapshot Strategy Decision Tree

Order of evaluation per source (first `Support::Yes` wins unless overridden by `--snapshot`):

1. **Btrfs** filesystem → `TreeSnapshotProvider::btrfs` → image kind `Stream`, `PointInTime`.
2. **LVM logical volume** (classic or thin) → `BlockSnapshotProvider::lvm` → `Block`, `PointInTime`.
3. **Device not mounted, no holders** → `offline` → `Block`, `Offline`.
4. **Mounted plain partition, not root, destination on another filesystem** → `freeze` (opt-in via `--snapshot freeze` or `auto` with `--allow-freeze`) → `Block`, `Frozen`.
5. **Mounted plain partition (root or otherwise) with `--allow-inconsistent`** → `live-none` → `Block`, `None`.
6. Otherwise → error `E_NO_CONSISTENT_METHOD` with the concrete options: boot rescue/live media (Offline), use file mode (Slice 12), or `--allow-inconsistent`.

Whole-disk sources evaluate each partition independently; the run proceeds only if every partition has a method, and reports per-partition levels. Snapshots of different partitions are **not** mutually atomic — documented in output.

### E.1 Btrfs provider (Stream)

- Determine the filesystem UUID of the source; enumerate mounted subvolumes: `findmnt -J -t btrfs` filtered by that UUID → `(target, subvol=, subvolid=)`. Mount the top-level subvolume (`-o subvolid=5,ro`) at a private mountpoint under `/run/linuxreflect/btrfs-<job>/`.
- For each mounted subvolume: `btrfs subvolume snapshot -r <top>/<subvol> <top>/.linuxreflect/<set>/<image_uuid>/<subvol-escaped>`.
- Emit `btrfs send [-p <previous snapshot of same subvol>] <snapshot>` per subvolume into the Stream chunker. For incrementals the previous snapshot MUST still exist locally; the engine keeps the last successful snapshot per set (`.linuxreflect/<set>/latest`) and deletes older ones after a new success. If the parent snapshot is missing → the incremental is refused and a new full is required (`E_STREAM_PARENT_MISSING`).
- Manifest records: fs UUID, label, per-subvolume path, `subvolid`, default subvolume id (`btrfs subvolume get-default`), mount options from `/etc/fstab` for that fs, `btrfs filesystem show` sizes.
- Teardown (`Drop`): nothing removed except on failure (the snapshot chain is needed for `-p`); private mount unmounted.

### E.2 LVM provider (Block)

- Classic: `lvcreate -s -n lr-<job> -L <cow_size> <vg>/<lv>`; thin: `lvcreate -s -n lr-<job> <vg>/<thinlv>` then `lvchange -K -ay <vg>/lr-<job>`.
- `cow_size` default = 10% of LV size, min 1 GiB, capped at VG free space; override `--lvm-cow-size`.
- Monitor every 5 s: `lvs --noheadings -o snap_percent <vg>/lr-<job>` (classic) / `data_percent` (thin pool). Abort the job at ≥ 90% (`E_SNAPSHOT_OVERFLOW`) — an overflowed classic snapshot becomes invalid.
- `block_path = /dev/<vg>/lr-<job>`; `lvremove -f` on `Drop`.
- LVM itself suspends the origin with lockfs, so the filesystem is frozen for the instant of creation → `PointInTime`.

### E.3 Offline provider

Preconditions: not in `/proc/self/mountinfo` (host namespace), not in `/proc/swaps`, `/sys/class/block/<dev>/holders/` empty for the device and every partition, not an active PV (`pvs`). Reads the device directly → `Offline`.

### E.4 Freeze provider (Block, non-root only)

Preconditions (all MUST hold, else `Support::No`): mountpoint is not `/`; the filesystem does not contain `/var/log`, `/var/lib/linuxreflect`, `/run`, `/tmp`, or the daemon's working directory; the destination path (for local/mounted destinations) has a different `st_dev`; `--freeze-timeout` given or defaulted (default 300 s).

Sequence:
1. Start the **external deadman**: `systemd-run --on-active=<timeout+30s> --unit=lr-thaw-<job> --quiet fsfreeze -u <mountpoint>`. This survives the daemon being SIGKILLed.
2. Switch job logging to an in-memory ring buffer (no journald writes while frozen).
3. `FIFREEZE` on an `O_RDONLY|O_DIRECTORY` fd of the mountpoint.
4. Read used blocks from the origin device.
5. `FITHAW`; `systemctl stop lr-thaw-<job>.timer` (ignore not-found); flush ring buffer to journald.
6. If the read exceeds `--freeze-timeout`, abort the job first, then thaw → `E_FREEZE_TIMEOUT`.

Consistency: `Frozen`. This is a quiesced backup mode, explicitly **not** equivalent to a snapshot: writers on that filesystem block for the entire duration.

### E.5 Live-none provider

Reads the mounted device as-is. Requires `--allow-inconsistent`. Manifest flag `inconsistent=true`; restore prints a warning and requires `--accept-inconsistent`.

### E.6 Post-MVP providers (interfaces reserved)

- `zfs` (TreeSnapshotProvider → Stream via `zfs send -i`).
- `blksnap` (BlockSnapshotProvider with real CBT), `--features blksnap`, runtime `modprobe` check; unsupported on kernels where the DKMS module fails to build.
- **Managed DM layer** (`lr-dmwrap`): opt-in installer/initramfs hook that places a `linear` DM device over selected partitions *before* mount, so that a `snapshot-origin` reload becomes possible later. Requires fstab/crypttab/bootloader changes; documented risks; never enabled implicitly.

---

## F. Used-Block Map Providers (`lr-fsmap`)

A provider MUST return every block required to reconstruct a mountable filesystem: superblocks and copies, group/AG descriptors, bitmaps/btrees, inode tables, journal/log, directory and data blocks. Acceptance for any provider (Slice 5): image a populated filesystem with used blocks only → restore → `fsck -n` clean → every file hash identical.

- **ext4 (also ext2/3):** run `dumpe2fs <dev>` on the snapshot/frozen/offline device. Parse `Block size:`, `Block count:`, `First block:`; then per `Group N: (Blocks a-b)` parse `Free blocks: r1-r2, r3, …` (inclusive ranges; may be empty; uninitialized groups are reported free). Used = `[first_block, block_count)` minus free ranges, converted to byte extents. Later: libext2fs bindings in `lr-unsafe` if `dumpe2fs` parsing proves fragile.
- **xfs:** `xfs_db -r -c "sb 0" -c "print blocksize" -c "print agblocks" -c "print agcount" <dev>` for geometry; `xfs_db -r -c "freesp -d" <dev>` for free extents (`agno agbno len` in fs blocks). Used = all AG blocks minus free; byte offset = `(agno*agblocks + agbno) * blocksize`. Internal log is not free → included. External log devices and realtime subvolumes: `complete=false` → raw fallback. (`xfs_metadump` is a metadata-only debugging tool and is **not** used.)
- **raw / unknown / ntfs / fat / swap header / LUKS / PV (MVP):** `complete=false`: read the whole partition, suppress all-zero chunks. NTFS (`$Bitmap`) and FAT (allocation table) providers are post-MVP.
- **FIEMAP** is used only in file mode for sparse detection — and even there `SEEK_HOLE/SEEK_DATA` is preferred (simpler, no physical addresses). FIEMAP physical addresses are never read from the device.

---

## G. Image Format `.lrimg` v1

Design goals: single write-once file; scalable metadata for multi-TB disks; per-chunk AEAD; authenticated headers; delta manifests for incrementals. Integers little-endian.

### G.1 Physical layout

```
[ Superblock            4096 B fixed ]
[ Chunk records         variable, appended sequentially ]
[ Metadata pages        variable: manifest pages, index pages, page table ]
[ Footer                4096 B fixed, at EOF ]
```

Metadata pages are **not** chunk records and are **not** in any index; they are addressed only from the footer's page table (resolves the v2.0 "index is itself a chunk" circularity).

### G.2 Sizes and scaling (R1-P0-5)

- Block mode chunk: **1 MiB default**, allowed 256 KiB–4 MiB, power of two, fixed per chain, aligned to chunk-size boundaries of the device. Used extents are rounded outward to chunk boundaries.
- Block manifest entry: 46 B (`state u8 | hash 32 | member u16 | offset u64 | stored_len u32` — with `state` packed) → 4 TB @ 1 MiB = 4 M entries ≈ **184 MB**; 16 TB ≈ 736 MB. Stored in 1 MiB pages, streamed, never fully materialized in RAM for restore (sequential) and only the parent's manifest pages are streamed for scan-and-diff.
- Incrementals store **delta manifests** (entries only for chunks that changed or became zero/hole); unchanged chunk numbers inherit from the parent state. Full and differential images store full manifests.
- Hash index (hash → location) exists only for `Stream`/`File` kinds (content dedup). For 1 TB @ 64 KiB avg CDC ≈ 16 M entries ≈ 700 MB in pages; dedup lookups use an in-RAM Bloom filter (configurable, default 64 MiB) over the chain plus page binary search on probable hits. Sub-chunk change detection inside 1 MiB block chunks is post-MVP.

### G.3 Superblock (offset 0, 4096 B)

| Field | Bytes | Notes |
|---|---|---|
| magic | 8 | `LRIMG\x01\0\0` |
| format_major / min_reader | 4 + 4 | reader rejects major > known |
| flags | 8 | bit0 encrypted, bit1 compressed, bit2 delta_manifest, bit3 whole_disk, bit4 inconsistent |
| image_kind | 1 | 1 Block, 2 Stream, 3 File |
| consistency | 1 | §D.2 enum |
| image_uuid, chain_id, set_id, parent_uuid | 16 × 4 | parent zero for full |
| seq_in_chain | 4 | 0 = full |
| created_unix | 8 | |
| source_size_bytes, logical_block_size, chunk_size | 8 + 4 + 4 | |
| kdf_id, aead_id | 4 + 4 | 1 Argon2id; 1 AES-256-GCM, 2 ChaCha20-Poly1305 |
| kdf_salt (chain-level) | 16 | identical in every member of the chain |
| argon2 m_cost/t_cost/p_cost | 4 × 3 | defaults 256 MiB / 3 / 4 |
| wrap_nonce | 12 | |
| wrapped_chain_key | 48 | AES-256-GCM(KEK) of 32 B chain key, AD = `"lrimg-v1/wrap"‖chain_id` |
| sb_hash | 32 | unkeyed BLAKE3 of all preceding bytes (corruption check before passphrase) |
| sb_mac | 32 | keyed BLAKE3(meta_key) of all preceding bytes incl. sb_hash (tamper check after key derivation) |
| reserved | pad | zero |

Unencrypted images (`--no-encrypt`): `sb_mac` = keyed BLAKE3 with a fixed public key; such images are **not tamper-evident** and the CLI says so.

### G.4 Key hierarchy and nonces

- `KEK = Argon2id(passphrase, kdf_salt, m, t, p)` → 32 B. Computed **once per restore/backup of a chain**.
- `chain_key`: random 32 B, generated with the chain's full; wrapped into every member's superblock (§G.3).
- Per file: `file_keys = HKDF-SHA256(ikm = chain_key, salt = image_uuid, info = "lrimg-v1/file")` → `data_key` (32 B) ‖ `meta_key` (32 B).
- `dedup_key = HKDF-SHA256(ikm = chain_key, salt = chain_id, info = "lrimg-v1/dedup")` → keyed BLAKE3 for all content hashes (same across the chain so positional/content comparison works).
- Nonce: 96-bit big-endian counter, starting at 0, separate counters for `data_key` and `meta_key`. **Files are write-once:** a `.tmp` is never resumed; any retry creates a new `image_uuid` → new keys, so counter reuse is impossible by construction. Nonce counters MUST live in one `NonceSeq` type that cannot be cloned or reset.

### G.5 Chunk record

```
[ magic u16 = 0xC4C7 ][ stored_len u32 ][ flags u8: bit0 zstd, bit1 encrypted ][ nonce 12 B ]
[ payload stored_len B ][ tag 16 B ]
payload = AEAD_data_key( zstd(plaintext) ), AD = keyed_hash(plaintext) 32 B ‖ kind u8
```

The keyed hash is not stored in the record; it lives in the manifest/index. `magic` + `stored_len` allow sequential scanning for a future `lrimg repair` (index rebuild).

### G.6 Metadata pages and footer

- Page: `[ page_magic u16 = 0x9A6E ][ len u32 ][ nonce 12 ][ ciphertext ][ tag 16 ]`, AEAD with `meta_key`, AD = `stream_id u8 ‖ page_no u64`. Streams: 1 = manifest, 2 = hash index, 3 = extras (partition table dumps, fstab, btrfs layout), 4 = page table (when it does not fit in the footer).
- Footer (last 4096 B): `LRFOOT\x01`, `total_chunks u64`, `data_end_offset u64`, inline page table (up to 120 entries of `stream_id u8 ‖ offset u64 ‖ len u32`) or pointer to a stream-4 page table, `superblock_copy` (the first 1024 B of the superblock, verbatim), `footer_hash` (unkeyed), `footer_mac` (keyed, meta_key). Reading starts at EOF−4096; a missing/invalid footer means the file is incomplete and never restorable. Restore code MUST verify `sb_mac` and `footer_mac` before trusting any offset, length, or flag.

### G.7 Manifests

- **Block (partition):** header `{chunk_size, chunk_count, used_extents_summary, fs_type, fs_uuid, label}` + entries per chunk number: `state` (0 unused/hole, 1 zero, 2 stored, 3 bad-sector), `hash`, `member` (index into the chain member list stored in stream 3), `offset`, `stored_len`. Delta manifests add `chunk_no u64` per entry and carry only changed entries.
- **Block (whole disk):** disk header `{disk_size, lbs, pt_type, pt_raw_bytes (MBR + primary GPT), serial/wwid}`; regions: `leading` (LBA 0 up to the first partition start, capped at 16 MiB, imaged raw with zero suppression — this carries BIOS GRUB `core.img`), one sub-manifest per partition (with its consistency), non-filesystem partitions (bios_grub, LVM PV, LUKS, mdadm member, unknown) imaged raw with zero suppression, `swap` partitions store only the first 4 KiB (header with UUID/label) and are recreated by `mkswap -U` on restore. The backup GPT is regenerated on restore. Gaps between partitions are not imaged.
- **Stream:** per subvolume `{subvol_path, subvolid, parent_snapshot_uuid?, send_stream_bytes, chunk list (hash, member, offset, stored_len)}` + fs layout extras.
- **File** (Slice 12): tree of `{path, mode, uid, gid, mtime, size, xattrs, acl, hardlink_group, chunks[]}`.

### G.8 Verification and compatibility

- `verify`: checks `sb_hash/sb_mac`, `footer_hash/footer_mac`, every page tag, every chunk tag, and recomputes every keyed content hash against the manifest. `verify --chain` walks the whole chain.
- Readers reject `format_major` > 1; new optional streams get new `stream_id`s and are ignored by older readers; field semantics are never repurposed; `min_reader` gates incompatible changes.

---

## H. Restore Semantics

### H.1 Targets (MVP)

- Target is an unmounted block device with **size ≥ source size**. Partitions are written at original offsets and sizes; extra space stays unallocated; the secondary GPT header/table is written at the end of the *target* with regenerated CRCs.
- Single-partition restore: target partition size ≥ source partition size; filesystem is not grown.
- Stream images: target is formatted `mkfs.btrfs -U <uuid> -L <label>`; subvolumes received in dependency order; default subvolume set; the user is reminded to check `subvol=` entries in `/etc/fstab` (they are stored in extras).
- Images flagged `inconsistent` require `--accept-inconsistent`.

### H.2 Restore token (R1-P1)

`PrepareRestore(image, target)` returns a human-readable plan and a token:
`{ image_uuid, target: { dev_t, wwid_or_serial, size_bytes, pt_hash (BLAKE3 of first 1 MiB + primary GPT) }, expires_at (≤ 10 min), nonce }`, MAC'd with a per-daemon-boot secret. `RestoreImage(token, confirm=true)` re-reads all target facts immediately before opening the device for write and aborts on any mismatch (`E_TARGET_CHANGED`). polkit action `org.linuxreflect.restore.apply` is `auth_admin` (no keep).

### H.3 Holder and mount checks

Before opening for write, for the target **and every partition/descendant** (`lsblk -J -o NAME,MOUNTPOINTS,TYPE` plus `/sys/class/block/*/holders`): not mounted in the daemon's mount namespace (a note is printed that other namespaces cannot be fully inspected), not in `/proc/swaps`, no dm/md holders, not an active LVM PV, not the device backing the running root (`/proc/self/mountinfo` for `/` and `/boot`, `/boot/efi`). In the rescue environment the same checks apply.

### H.4 Resize policy

`--resize` is **removed from the MVP CLI**. Post-MVP `restore --grow-last` grows the last filesystem into free space (ext4 `resize2fs`, xfs `xfs_growfs` after mount, btrfs `btrfs filesystem resize max`); shrinking is supported only for ext4/ntfs/btrfs and never for xfs; GPT relocation, LUKS/LVM layers and bootloader structures are handled explicitly per case.

### H.5 Boot repair (rescue, Slice 16)

After a whole-disk restore: UEFI — locate the ESP, ensure `\EFI\BOOT\BOOTX64.EFI` exists (copy shim if missing), create an NVRAM entry with `efibootmgr -c -d <disk> -p <n> -L <label> -l <loader>` when absent; BIOS — `core.img` arrives with the leading region; if the layout changed, offer `grub-install` from a chroot. Cross-hardware fixes (initramfs regeneration, driver changes) are out of scope for v1.

---

## I. Daemon and IPC

- Transport: tonic gRPC over UDS `/run/linuxreflect/daemon.sock` (root:linuxreflect, 0660). Socket activation via systemd (`linuxreflect.socket`), `Type=notify`, `sd_notify` READY/STATUS/WATCHDOG.
- Peer identity: `SO_PEERCRED` (pid, uid, gid) → immediately `pidfd_open(pid)`; re-read `/proc/<pid>/status` `Uid:` and compare; carry `{uid, pidfd, pid, start_time}` in the connection context.
- Authorization: `AuthBackend` trait with `PolkitBackend` (zbus_polkit ≥ 5.1.0; subject `unix-process` with `pidfd` when polkit ≥ 121, else `pid + start-time + uid`; `AllowUserInteraction`) and `StaticBackend` for tests/CI (`--auth static:<uid-list>` accepted only when the daemon is started with `LR_DEV_MODE=1`).
- Actions: `org.linuxreflect.disk.read` (allow_active yes), `.backup.create` (auth_admin_keep), `.restore.prepare` (auth_admin_keep), `.restore.apply` (auth_admin), `.snapshot.manage`, `.schedule.manage`, `.destination.configure`, `.export.manage`.
- Methods: `ListDisks`, `ProbeSource(SourceRef) -> Plan {provider, image_kind, consistency, estimated_bytes, warnings}`, `CreateBackup(BackupSpec) -> stream Progress`, `ListSets/ListChains`, `VerifyImage -> stream Progress`, `PrepareRestore -> RestorePlan+Token`, `RestoreImage(Token) -> stream Progress`, `ExportImage/UnexportImage` (Slice 13), `GetSchedule/SetSchedule`, `ApplyRetention -> stream Progress`, `RebuildCatalog`, `GetJob/CancelJob`, `WatchEvents -> stream Event` (used by `lr-session` and the GUI).
- Jobs are idempotent by client-supplied `job_id`; one running job per set; cancellation is cooperative with snapshot teardown guaranteed.

---

## J. CLI and Configuration

### J.1 Command tree

```
linuxreflect
  disk list [--json]
  disk map <device> [--json]
  probe --source <dev|path> [--snapshot auto|btrfs|lvm|freeze|offline|none] [--mode auto|block|stream]
  backup create --source <dev|path>... --dest <uri> --set <name>
                --type full|incremental|differential [--parent latest|<uuid>]
                [--mode auto|block|stream] [--snapshot auto|btrfs|lvm|freeze|offline|none]
                [--allow-freeze] [--freeze-timeout 300s] [--allow-inconsistent]
                [--chunk-size 1MiB] [--compress zstd:9] [--no-encrypt|--passphrase-file <p>]
                [--lvm-cow-size <size>] [--on-bad-sector abort|record] [--dry-run] [--json]
  backup list --dest <uri> [--set <name>] [--json]
  verify --image <uri> [--chain] [--json]
  restore prepare --image <uri> --target <dev> [--partition <n>] [--json]   -> prints plan + token
  restore apply   --token <t> --confirm [--accept-inconsistent] [--json]
  catalog rebuild --dest <uri> --set <name>
  retention apply --dest <uri> --set <name> [--dry-run]
  schedule set --config <path> | schedule list | schedule remove <job>
  export mount   --image <uri> [--nbd|--ublk] --at <mountpoint>   (Slice 13)
  export umount  --at <mountpoint>
  daemon run|status
```

Global: `--socket`, `-v/-q`, `--json`. Passphrase sources, in order: `--passphrase-file`, `LINUXREFLECT_PASSPHRASE_FILE`, interactive TTY prompt; never a command-line argument.

### J.2 Config `/etc/linuxreflect/config.toml`

```toml
[daemon]
socket = "/run/linuxreflect/daemon.sock"
log_level = "info"
lvm_cow_size = "10%"

[[job]]
name = "root-nightly"
source = ["/dev/vg0/root"]                # LV → LVM snapshot, PointInTime
dest = "sftp://backup@nas.local/backups/laptop"
set = "laptop-root"
type = "incremental"
parent = "latest"
mode = "auto"
snapshot = "auto"
compress = "zstd:9"
encrypt = true
passphrase_file = "/etc/linuxreflect/laptop-root.key"   # 0600 root
on_calendar = "*-*-* 02:00:00"            # systemd calendar syntax, copied verbatim
randomized_delay = "15m"
persistent = true
[job.retention]
keep_chains = 2                           # whole chains only (§D.3)
max_incrementals_per_chain = 14           # then the next run starts a new chain (new full)
new_chain_on_calendar = "Sun *-*-* 02:00:00"   # optional; also forces a new chain

[destinations.nas]
kind = "sftp"
host = "nas.local"
user = "backup"
known_hosts = "/etc/linuxreflect/known_hosts"
identity = "/etc/linuxreflect/id_ed25519"
```

### J.3 Retention algorithm

Under the set lock: list chains from validated catalog; a chain is *complete* if its full is present and every member verifies its superblock; never delete the newest complete chain; delete whole chains oldest-first until `keep_chains` remain; a run that would exceed `max_incrementals_per_chain` starts a new chain. No member of a chain is ever deleted individually (dependency graph: every incremental depends on all ancestors).

### J.4 Scheduling

The daemon materializes `linuxreflect-job@<name>.timer/.service` under `/etc/systemd/system/` from config (`OnCalendar` verbatim, `Persistent=`, `RandomizedDelaySec=`, `Wants=network-online.target` for network destinations) and runs `daemon-reload`.

---

## K. Slices with Acceptance Criteria and Tests

MVP = Slices 1–11. Each slice is a separate PR; CI must stay green (`cargo test`, integration tests need root and run in a privileged container or VM).

**S1 — Workspace, core, capability probe.** `lr-core`, `lr-unsafe` (BLKGETSIZE64, BLKSSZGET, FIFREEZE/FITHAW, pidfd_open), `caps::probe()`.
AC: `disk list` reports size/sector size for a loop device; `caps` prints nbd/ublk/lvm/btrfs availability.
Test: `truncate -s 1G d.img; losetup -f --show d.img`; assert 1 GiB.

**S2 — Partition discovery.** GPT/MBR parsing, `/sys/block`, `blkid -p -o export`, holders, mountpoints, LVM/Btrfs facts → `SourceLayout`; `disk map --json`.
AC: JSON matches a fixture disk built with `sgdisk` (ESP + bios_grub + ext4 + swap).

**S3 — Crypto.** Key hierarchy (§G.4), AEAD both ciphers, keyed BLAKE3, `NonceSeq`, metadata page codec, superblock/footer MAC helpers.
AC: known-answer vectors; wrong passphrase fails at unwrap; two files from one chain never share a key; compile-time impossibility of `NonceSeq` clone.

**S4 — Format codec.** Superblock, footer, chunk records, pages, page table, block/stream/file manifests, delta manifests; `proptest` round-trips; truncated/tampered files rejected (`sb_mac`/`footer_mac`).
AC: write 100 GiB sparse block manifest in < 2 GB RSS (streamed pages); tampered flag byte detected.

**S5 — Used-block maps.** ext4 (`dumpe2fs`), xfs (`xfs_db`), raw-zero-skip.
AC (completeness proof): populate ext4 and xfs loop filesystems (files, directories, xattrs, sparse, a deleted-then-recreated set), image used blocks only, restore to a fresh loop device, `fsck -n`/`xfs_repair -n` clean, all file hashes equal; a 1 GiB fs with 50 MiB data yields an image < 100 MiB.

**S6 — Block backup/restore (Offline provider).** `lr-blocksource` with O_DIRECT aligned buffers, zero-chunk detection, bad-sector recording via `dm-flakey`/`dm-error` fixture; `restore prepare/apply` with token and holder checks.
AC: byte-identical restore; `E_TARGET_CHANGED` when the target is repartitioned between prepare and apply; restore refused if a partition is mounted or in `/proc/swaps`.

**S7 — Whole-disk images.** Leading region, GPT/MBR capture, per-partition sub-manifests, raw non-FS partitions, swap header, GPT regeneration on restore to a larger disk.
AC: qemu (SeaBIOS and OVMF) VM with BIOS-GRUB and UEFI layouts imaged offline, restored to a larger virtual disk, boots.

**S8 — Snapshot providers.** LVM (classic + thin, overflow monitor), Btrfs tree snapshot + Stream mode (`send`/`receive`), Freeze (with deadman), live-none; `ProbeSource` plan; consistency reporting.
AC: LVM: snapshot content stable while a writer loop runs on the origin; no leaked LVs/loops after `Drop` and after `kill -9` of the job. Btrfs: two subvolumes, full then incremental (`-p`), receive into a fresh fs, `diff -r` clean, default subvolume preserved. Freeze: `fsfreeze --unfreeze` succeeds via the deadman after `kill -9`; provider refuses `/` and same-`st_dev` destinations.

**S9 — Chains.** Full/incremental/differential, delta manifests, positional scan-and-diff, catalog, set lock, `parent=latest`.
AC: modify 10 MiB → incremental stores ≈ 10 MiB + metadata; restore of the latest state byte-identical; two concurrent `backup create` on one set → second waits/fails with `E_SET_LOCKED`; catalog rebuild from superblocks equals the live catalog.

**S10 — Destinations.** Local, mounted path, SFTP (russh) with exclusive-create lock and rename-finalize; retry with backoff.
AC: killing the SFTP server mid-transfer leaves no finalized image and no dangling lock after ttl; resumed job creates a new `image_uuid`.

**S11 — Daemon, IPC, polkit, CLI complete, verify.** Socket activation, `AuthBackend`, restore tokens, `WatchEvents`, static musl CLI build.
AC: unauthorized uid denied by polkit (real polkit in VM test) and by `StaticBackend` in CI; `verify` names the offending chunk after a flipped byte; full CLI round trip on loop devices.
**← MVP boundary.**

**S12 — File mode + FUSE (first follow-on).** Tree walk with `O_NOFOLLOW`, `SEEK_HOLE`, xattrs/ACLs, hardlinks, `--one-file-system`, default excludes (`/proc /sys /dev /run /tmp`), Btrfs tree snapshot as source; restore into an existing filesystem; `lr-fuse` read-only mount.
AC: `rsync -nac` between source and restored tree reports nothing; FUSE `sha256sum` matches.

**S13 — Block export.** NBD server (newstyle, read-only) + `nbd-client -u`; ublk optional; kernel read-only mounts: ext4 `-o ro,noload`, xfs `-o ro,nouuid,norecovery`.
AC: mount an exported ext4 and xfs image alongside the running system; browse in a file manager; unmount/unexport clean.

**S14 — Scheduling, retention, session notifications.** Timer generation, retention (§J.3), `lr-session` (`systemd --user`) forwarding `WatchEvents` to `org.freedesktop.Notifications`.
AC: timer fires; retention keeps exactly `keep_chains` complete chains and never touches a chain member individually; desktop notification appears in a Wayland session.

**S15 — GUI (Slint).** Disk map, backup wizard (shows the `ProbeSource` plan and consistency level before starting), restore wizard (shows the token plan), progress, job history.
AC: create/restore via GUI; Wayland and X11.

**S16 — Rescue media + boot repair + file-mode bare-metal.** mkosi profile (`BiosBootloader=grub`, signed shim/GRUB, distro kernel, custom initramfs, `cage` + GUI, TUI fallback), USB disk image (ISO via xorriso optional); boot repair (§H.5); layout recreation for file-mode restores (`sfdisk` dump, `mkfs -U`, bootloader reinstall).
AC: boots on OVMF with Secure Boot enabled and on SeaBIOS; bare-metal restore then boot of the restored system.

**S17 — Hardening matrix.** ext4/xfs/btrfs/fat32/ntfs(raw) × BIOS/UEFI; `dm-flakey` bad sectors; SMB/NFS/SFTP interruption; multi-TB sparse-disk metadata scaling test (16 TB virtual, RSS bound).

**Post-MVP backlog:** ZFS, blksnap provider, managed DM layer, consolidation/synthetic full, `--grow-last`/shrink, LVM/LUKS-aware whole-disk, NTFS/FAT used maps, sub-chunk change detection, `lrimg repair`, passphrase change, PXE, cloud destinations, email.

---

## L. Safety, Errors, Logging, Style, Dependency Policy

### L.1 Safety invariants
- Sources are opened `O_RDONLY`; snapshots are read-only; nothing in a backup path may write to a source device.
- Writes to a device happen only in `restore apply` with a valid token, `--confirm`, `auth_admin`, and re-validated target facts.
- Images are write-once; finalize = fsync + rename; a file without a valid footer is never restorable and never resumed.
- Snapshot/freeze teardown is guaranteed by `Drop`; the Freeze provider additionally has the out-of-process deadman.
- The daemon never logs secrets; passphrase files are read with `O_NOFOLLOW`, mode checked (0600), contents zeroized (`zeroize`).

### L.2 Error contract
`lr_core::Error` variants: `Io`, `BadSector{offset,len}`, `NoSpace`, `NetworkTimeout`, `SnapshotOverflow`, `FreezeTimeout`, `NoConsistentMethod{options}`, `SetLocked{owner}`, `TargetChanged`, `TargetBusy{holder}`, `Aead`, `Corrupt{what}`, `Unsupported{cap}`. Bad sectors: recorded as state 3 in the manifest (never silently zero-filled) or abort per `--on-bad-sector`. ENOSPC/overflow: abort, delete `.tmp`, release lock, leave prior images intact. Network: bounded retries with backoff, then atomic abort.

### L.3 Logging
`tracing` spans per job/phase; journald in the daemon; ring buffer while frozen; one structured completion record per job with achieved consistency and byte counts.

### L.4 Code style
`rustfmt`, `cargo clippy --all-targets -- -D warnings`, `#![forbid(unsafe_code)]` outside `lr-unsafe`, `cargo deny check`, `cargo audit`, docs on all public items, `proptest` for codecs, integration tests behind `#[ignore]` + `LR_ROOT_TESTS=1`.

### L.5 Dependency policy
All versions in `[workspace.dependencies]` as exact tested versions (`=x.y.z` or `x.y.z` with committed `Cargo.lock`); the bootstrap PR records the resolved versions in `docs/versions.md`; Dependabot/Renovate bumps are reviewed weekly; `zbus_polkit < 5.1.0` is denied in `deny.toml`.

---

## M. Open Questions

1. **Slint license:** GPLv3 vs Royalty-Free (attribution) vs commercial — a product decision; affects only `lr-gui`.
2. **Bloom filter size vs RAM on rescue media** for Stream/File dedup (default 64 MiB; rescue images may have 2 GiB RAM).
3. **Managed DM layer**: whether to ship the opt-in installer hook at all, given fstab/bootloader coupling.

## N. Assumptions (override if wrong)

- GUI = Slint; CLI-first MVP; custom `.lrimg` format; NBD as baseline export.
- Btrfs is handled in Stream mode rather than block mode; ZFS follows the same model later.
- Raw root partitions have no live block path in v1 (Frozen for non-root, Offline via live/rescue media, `None` opt-in).
- Retention is chain-granular until consolidation exists.

---

## Appendix A — Review log (v2.0 → v2.1)

| # | Finding | Source | Resolution |
|---|---|---|---|
| 1 | dm-snapshot over a mounted plain partition impossible (no interposer in stock DM) | R1-P0-1, R0 | E.4 rewritten; §A.1; providers = LVM/Btrfs/Offline/Freeze/live-none; managed DM layer post-MVP |
| 2 | Snapshot trait conflated block and tree snapshots | R1-P0-2 | Split `BlockSnapshotProvider` / `TreeSnapshotProvider`; Btrfs → Stream kind |
| 3 | FIEMAP misused as used-block map; `xfs_metadump` is metadata-only | R1-P0-3, R0 | §F providers (dumpe2fs, xfs_db freesp); completeness AC; FIEMAP only in file mode |
| 4 | fsfreeze fallback semantics unclear; "BLAKE3 CBT" is not CBT | R1-P0-4, R0 | §E.4 Frozen mode with deadman and non-root rule; §D.4 scan-and-diff |
| 5 | Index does not scale (64 KiB chunks → GBs of metadata); index-as-chunk circular; footer superblock copy undefined | R1-P0-5 | §G.2: 1 MiB chunks, metadata pages, delta manifests, positional diff; §G.6 footer defined |
| 6 | Retention needs full ancestor dependency; set locking; catalog duality | R1-P0-6, R0 | §D.3 chain-granular deletion, set lock, single catalog |
| 7 | `--resize` not viable for MVP; NTFS wording | R1-P0-7, R0 | §H.4; NTFS sector restore clarified |
| 8 | polkit subject needs pidfd/start-time; CVSS 7.3 | R1-P1 | §I; RUSTSEC-2026-0278 pinned in deny.toml |
| 9 | Hard `kernel ≥ 5.17` contradicts RHEL 9 | R1-P1 | §A.4 capability probe; freeze warning only |
| 10 | Restore confirmation must bind target identity; holders/descendants | R1-P1 | §H.2–H.3 |
| 11 | Header/footer unauthenticated; nonce/resume contract | R1-P1 | §G.3 `sb_mac`/`footer_mac`; §G.4 write-once + per-file keys |
| 12 | FUSE cannot parse ext4/xfs; ublk experimental | R1, R0 | §B, S12/S13: FUSE for file mode, NBD baseline export |
| 13 | systemd-boot has no BIOS; Secure Boot chain | R1, R0 | §B, S16: mkosi `BiosBootloader=grub`, signed shim/GRUB, distro kernel |
| 14 | Slint license/backend wording; stale fuser; version selectors vs pins | R1 | §B, §L.5 |
| 15 | MVP text vs slices inconsistent (FUSE, SFTP, whole-disk, file mode) | R1, R0 | §A.2–A.3 and §K aligned |
| 16 | Whole-disk misses MBR gap/core.img, backup GPT, swap, non-FS partitions; boot repair | R0 | §G.7, §H.5 |
| 17 | Per-file Argon2 salt → one KDF per chain member on restore | R0 | §G.4 chain key wrapping |
| 18 | Unkeyed dedup hash allows fingerprinting | R0 | keyed BLAKE3 with `dedup_key` |
| 19 | Root-daemon cannot post session notifications | R0 | `lr-session` user service |
| 20 | Schedule grammar undefined; O_DIRECT alignment; FIFREEZE constants; polkit in CI | R0 | §J.4 OnCalendar verbatim; `AlignedBuf`; `lr-unsafe`; `StaticBackend` |

## Appendix B — Prior art

Clonezilla/Rescuezilla/partclone (used-block imaging, rescue media), Veeam Agent for Linux (closest commercial equivalent; relies on an out-of-tree module), restic/Borg/kopia (CDC, dedup, encrypted repositories), ReaR (bare-metal layout capture and recreation), Timeshift/Snapper (Btrfs/LVM snapshot orchestration), FSArchiver (filesystem-level images with resize on restore).
