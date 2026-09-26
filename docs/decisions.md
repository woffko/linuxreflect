# Decisions log

Small decisions the specification leaves open. Keep entries short: context,
decision, reason, and what would make us revisit it.

## D-001 — Discovery lives in `lr-core`

The specification's crate list (§C) has no discovery crate, but `SourceLayout`
and device geometry are `lr-core` types, and S2 discovery is pure read-only
probing. Discovery therefore lives in `lr-core::discovery` + `lr-core::sysfs`.

Revisit if discovery grows into snapshot planning; the providers in
`lr-snapshot` (S8) will own that, and discovery can be split out then.

## D-002 — Own identifier type instead of a UUID crate

The spec does not list a UUID dependency, but the superblock stores raw 16-byte
identifiers (§G.3). `lr_core::Id` wraps `[u8; 16]`, renders canonical UUID
strings, and generates values by reading `/dev/urandom` (version-4 bits set).

This also removes any RNG-version dependency from on-disk identity. `uuid`
still appears transitively through `gpt`; it is not part of our public API.

## D-003 — Workspace lint profile

Workspace lints enable `clippy::all` at `deny` plus `missing_docs` and
`unreachable_pub`. The full `clippy::pedantic` group is not enabled because the
spec's gate is `cargo clippy --all-targets -- -D warnings`; selected pedantic
lints can be turned on individually when they catch real bugs.

`unsafe_code` is enforced per crate with `#![forbid(unsafe_code)]` rather than a
workspace lint, because Cargo cannot combine `lints.workspace = true` with a
per-crate override.

## D-004 — Test fixtures over root

Prefer unprivileged fixtures (sparse image files, `sgdisk` layouts, sysfs
fixture trees, `LR_MOUNTINFO` files) and keep only genuinely privileged checks
behind `#[ignore] + LR_ROOT_TESTS=1`. This keeps `cargo test` meaningful on a
workstation and keeps CI honest.

## D-005 — Capability probing is non-destructive

`caps::probe()` never freezes a real filesystem to test `FIFREEZE`. It calls
`FITHAW` on an unfrozen directory: `EINVAL` proves the ioctl exists, `ENOTTY`
proves the kernel lacks it. `O_DIRECT` is probed on a throwaway temp file.

## D-006 — `SourceLayout::is_whole_disk` follows the layout, not the device class

A source is a whole-disk source when discovery found a partition table with
partitions. Kernel class is not used: a loop device attached with `--partscan`
and a disk image file are whole-disk sources too, and both must take the §G.7
path in S7. `is_offline` (no mount points, no holders) stays independent.

## D-007 — Partition filesystems are probed at an offset for image files

A whole-disk *image file* has no partition device nodes, so `disk map` would
otherwise report no filesystems for its partitions. Discovery therefore probes
the parent file with `blkid -O <offset> --size <partition size>`. The `--size`
bound is required for signatures stored at the end of a region, such as swap.
Real devices keep using the partition node directly.

## D-008 — Manifest entries are 46 bytes with the state packed into `member`

Spec §G.2 gives the entry as `state u8 | hash 32 | member u16 | offset u64 |
stored_len u32` (47 bytes) but calls it 46 bytes and sizes 4 M entries at
184 MB, which is 46 bytes per entry. The on-disk entry is therefore
`hash 32 ‖ member:u14/state:u2 (u16) ‖ offset u64 ‖ stored_len u32`. A member
index never exceeds 16383, and the two-bit state has exactly the four values
§G.7 lists. `docs/format-lrimg-v1.md` §5.2 is normative.

## D-009 — Superblock and footer byte offsets

Spec §G.3/§G.6 list the fields but not their packing. The superblock places
`sb_hash` at 1024 — the same 1024 bytes the footer copies verbatim — and
`sb_mac` at 1056, so both hashes cover a contiguous prefix. The footer keeps
its page table at 1056 with 120 packed 13-byte slots, then `footer_hash` at
2624 and `footer_mac` at 2656. `docs/format-lrimg-v1.md` §1 and §4 are
normative, and the tests decode real files at these offsets.

## D-010 — Compression is applied only when it shrinks the chunk

`--compress zstd:<level>` enables compression, but a chunk whose zstd frame is
not strictly smaller than the plaintext is stored raw with `flags.bit0` clear.
This avoids paying decompression cost for incompressible data and keeps the
stored length meaningful.

## D-011 — File manifests use continuation records

A file entry has a fixed-size header plus the first batch of 32-byte chunk
hashes; further hashes follow in continuation sections (kind 5) that belong to
the preceding entry. This keeps a 1 TB file from producing a single
multi-hundred-megabyte record and needs no extra stream id, so §G.8
compatibility stays intact.

## D-012 — Page streams hide page boundaries

Manifests are byte streams assembled from pages, so structures may straddle a
page boundary and parsers work by structure, not position. This is what lets
the writer stream a 736 MiB manifest in constant memory (verified by the
16 TiB release-mode test in `crates/lr-format/tests/streaming.rs`).

## D-013 — Dedup Bloom filter size

The Stream/File dedup Bloom filter is a runtime setting with a 64 MiB default
(spec §M.2). Slice S4 fixes the value in configuration and this log; the filter
itself is built by Slice S8 when stream dedup lands.

## D-014 — Unencrypted images, keys and pages

`--no-encrypt` images have no passphrase, so they have no KEK: `kdf_id` is 0,
the wrapping fields are zero, chunks carry no tag, and the header MACs use the
fixed public key from `lr_crypto::mac::fixed_public_mac_key`. Metadata pages are
still AEAD-sealed with a `meta_key` derived from that public chain key, which
protects against accidental corruption but not against tampering — the CLI must
say so when it reports such an image.

## D-015 — Where the chunk-record codec lives, and the extra HKDF entry point

Slice S4 puts the whole chunk record codec (`seal_chunk`/`open_chunk`, compression
included) in `lr-format`, not in `lr-crypto`: spec §C gives `lr-crypto` the AEAD
and the metadata-page codec, while compression is a format concern. `lr-crypto`
keeps the primitives the record needs (`seal_in_place`, `open_in_place`,
`content_hash`, `NonceSeq`).

`lr-crypto::keys::hkdf_sha256` is public rather than private because both
`file_keys` and `dedup_key` are instantiations of it and the KAT suite checks it
against RFC 5869 directly; a private helper would not be testable from an
integration test.


## D-016 — `AlignedBuf` lives in `lr-unsafe`

`O_DIRECT` requires the buffer, offset and length to share the device alignment
(spec §B, `max(4096, lbs)`), and Rust's allocator guarantees only word
alignment. `lr-unsafe::AlignedBuf` therefore allocates through `std::alloc`
with an explicit alignment and is the only place that touches raw pointers;
every other crate stays under `#![forbid(unsafe_code)]`.

## D-017 — The offline provider is the S6 subset of spec §E

Slice S6 reads a device that is mounted nowhere, has no holders, is not swap
and is not an active LVM physical volume, which makes it consistent by
construction (spec §E.3). `lr-snapshot` exposes the full
`BlockSnapshotProvider` shape so `lvm`, `btrfs`, `freeze` and `live-none` (S8)
plug in without changing the engine; `TreeSnapshotProvider` follows in S8.

## D-018 — Before the daemon exists the CLI runs the engine in-process

Spec §C says the CLI talks to the daemon only over gRPC, but Slice S11 is where
the daemon lands, and §K S6 requires `restore prepare`/`apply`. Until then the
CLI calls the same `lr-engine` entry points the daemon will wrap, and two
consequences are recorded here:

* The restore token carries the image and target *paths*, because no daemon is
  around to remember a job by id.
* The per-boot token secret is persisted in a 0600 file under
  `$XDG_RUNTIME_DIR/linuxreflect`, `/run/linuxreflect` or `/tmp/linuxreflect-<uid>`
  (first writable wins). `/run` is a tmpfs, so the secret disappears at reboot
  exactly as a daemon restart would; S11 hands the daemon the same file.

## D-019 — Holes are not written on restore

A chunk the source never had data in (`state = 0`) is left untouched, so a
restore does not overwrite unrelated data that happens to live in the target's
free space. Chunks that are explicitly all zero (`state = 1`) *are* written as
zeros, because the source really does contain zeros there. The acceptance test
compares the used regions of source and target, which is the strongest claim
that can be made under this rule.

## D-020 — Bad sectors are tested with a deterministic EIO, not `dm-error`

This kernel has `dm-flakey` but no `dm-error` target, and `dm-flakey` errors
every read during its "down" interval, which would also break the
used-block-map step. `lr-blocksource` unit tests inject a failing read through
the `BlockSource` trait, and the root test truncates a loop device's backing
file: reads past the truncation fail with `EIO` while the filesystem metadata
stays readable, so `--on-bad-sector abort` and `record` are both exercised
deterministically.

## D-021 — Passphrase files are `O_NOFOLLOW`, 0600, and zeroized

`--passphrase-file` and `LINUXREFLECT_PASSPHRASE_FILE` are the only sources in
S6. The file is opened `O_NOFOLLOW`, must be a regular file with mode exactly
0600, is capped at 4 KiB, has one trailing newline stripped, and is held in
`Zeroizing` memory. A passphrase is never a command-line argument (spec §J.1);
the TTY prompt moves to Slice S11.

## D-022 — `lr-store` starts with the local destination

`Destination` matches spec §C.1, but only the local backend exists in S6:
`create_tmp` writes `<name>.tmp` next to the image, `finalize` fsyncs the file
and the directory and then renames, and names are rejected if they contain
`..` or an absolute path. `lock_set` returns `Unsupported` until Slice S10 adds
`set.lock`, and SFTP arrives with it.

## D-023 — The manifest is spooled while chunks are written

The format puts chunk records before metadata pages (spec §G.1) while a
manifest entry needs the chunk's offset and stored length, so entries are
spooled to `<chain>/.<image>.manifest.spool` in the set directory and streamed
through the page writer afterwards. Memory stays at one page, and the spool is
removed on success or by the failure guard; it is never mistaken for an image
because only `.lrimg` files are images.

## D-024 — `used_bytes` and `imaged_bytes` are different numbers

The manifest records the map's own totals (`used_extent_count`, `used_bytes`),
while the engine reads chunk-aligned regions, which can be larger (spec §G.2
rounds extents outward). `BackupReport` reports both so a restore's
`bytes_written` can be checked against `imaged_bytes`, not against `used_bytes`.

## D-025 — Whole-disk manifest: region records plus reused block manifests

Spec §G.7 describes the whole-disk manifest as a disk header plus one
sub-manifest per partition. `docs/format-lrimg-v1.md` §8 fixes the encoding: a
`section_kind = 6` header carrying `{disk_size, lbs, pt_type, serial/wwid,
pt_raw (first 1 MiB), region_count}`, then one region record per imaged region
(`leading`, `partition-fs`, `partition-raw`, `swap`), then one ordinary block
manifest (S4's `section_kind` 1) per manifest-bearing region, in region order.
Entries are positional *within the region*, so a region's chunk `i` is at
`start_lba * lbs + i * chunk_size`. Reusing the S4 codec kept S7 small and
means a region manifest is streamed exactly like a block manifest.

The leading region is capped at 16 MiB (§G.7) and carries the BIOS `core.img`;
gaps and the backup GPT are not imaged; swap regions store only their first
4 KiB and are recreated with `mkswap -U` when the target has partition nodes,
otherwise from the stored header with a warning.

Whole-disk sources that are *image files* have no partition device nodes, so
their filesystem partitions are imaged raw (`map_backed = false` in the report);
use a loop device to get used-block maps. The loop-device acceptance test
covers the map-backed path.

## D-026 — Restore regenerates the GPT for the target size

After writing the regions, a GPT image is reopened through the `gpt` crate with
`only_valid_headers(false)` and rebuilt with `update_partitions` followed by
`write_inplace`. `update_partitions` recomputes both headers for the *current*
device size (fresh backup LBA, `last_usable`, CRCs); `write_inplace` alone
would keep the restored header's old backup LBA and produce the exact error
`sgdisk --verify` reports: "the secondary header's self-pointer indicates that
it doesn't reside at the end of the disk".

One consequence is documented in the tests: the leading region can no longer be
byte-identical after a restore to a larger disk, because sectors 0..34 hold the
primary GPT header, entries and their CRCs. The tests compare everything from
sector 34 onward (the boot-loader area) and the protective MBR, which is what
matters for booting.

## D-030 — The boot test asserts a serial marker, not an exit code

Spec §K S7 requires the restored disk to *boot*. The fixture is a GPT disk with
`bios_grub`, an ESP holding GRUB, the host kernel and a busybox initramfs; the
init mounts devtmpfs, prints `LRBOOT-OK` to `/dev/console` and powers off. The
test polls the serial log for the marker and then stops qemu.

The originally planned `isa-debug-exit` port write would have needed `unsafe`
port I/O in the guest init; a static busybox plus a serial marker is equally
deterministic and keeps the harness free of `unsafe`. A standalone
`grub-mkstandalone` image with the config embedded is used for UEFI, because
`grub-install` on Ubuntu installs the *signed* binary whose embedded config
searches Ubuntu's own paths (`/boot/grub`, `/.disk/info`) and ignores the test
configuration. `search --file --set=root /vmlinuz` is what makes a memdisk-based
GRUB find the ESP.

## D-032 — MBR partitions are numbered from 1, and sysfs start LBAs are used

`mbrman`'s `MBRHeader::iter()` yields `(i + 1, entry)` for primary partitions
(and `i + 5` for logical ones), which is also how the kernel numbers them. The
discovery code added another `+1`, so a single MBR partition appeared twice
(once from the sysfs index and once as index 2), and the resulting whole-disk
layout had overlapping regions. Partition indices now use `mbrman`'s numbering
directly, and the sysfs-only fallback reads the `start` attribute instead of
recording LBA 0. `crates/lr-core/tests/discovery_gpt.rs` has a regression test
built with `sfdisk`.

## D-027 — An orphaned LV is found by tag, not by name

When a job dies with `SIGKILL` the provider's `Drop` never runs, so its
snapshot LV stays in the volume group forever. Startup therefore sweeps LVs
whose tag is `linuxreflect:<owner>`, where `owner` is `<pid>:<starttime>` from
the creating process. A tag whose process is still alive (start time read back
from `/proc/<pid>/stat` field 22) is left alone; everything else is removed with
`lvremove -f`. Names alone would be wrong: two concurrent jobs can pick the same
derived name, and a name is no proof that the owner is gone.

The sweep runs from the provider's `probe`/`create` path, so a later job cleans
up after an earlier crash without a separate daemon.

## D-033 — The freeze deadman is two-layered

Spec §E.3 requires a deadman that thaws a filesystem if the process dies. In
WSL2 the obvious mechanism — `systemd-run --on-active=<n>` plus a stop on
successful thaw — proved unreliable: the transient timer sometimes fired many
tens of seconds late, and `--quiet` correlated with it not firing at all.

The provider now arms two independent timers. The first is the systemd one; the
second is a detached `sh -c 'sleep N; [ -f <marker> ] && fsfreeze -u <mp>; rm -f
<marker>'`. Both are disarmed by removing the marker file (the systemd unit is
also stopped). The marker is created before the first timer is armed, so a
timer that fires late still sees it and thaws. A `kill -9` of the process leaves
the marker behind, so the detached timer thaws the filesystem — that path is
covered by `kill_9_is_recovered_by_the_deadman`.

## D-037 — Discovery resolves device symlinks before probing sysfs

`/dev/<vg>/<lv>` is a symlink to `/dev/dm-N`, and mountinfo reports the LV by
either name. Discovery used the file name of the path it was given, so an LV
passed as `/dev/vg/lv` was looked up as `class/block/lv`, which does not exist;
the source degraded to "regular file" and the LVM provider then refused it with
"not a device-mapper LVM volume". Discovery now `canonicalize`s the path for
every sysfs and ioctl probe (mountinfo matching included) while keeping the
caller's path in `SourceLayout::device`, which is the name a human recognises
and the one a restore should target.

## D-028 — The Btrfs top-level subvolume is mounted read-write

Spec §E.1 says to mount the top-level subvolume (`subvolid=5,ro`) at a private
mount point under `/run/linuxreflect/btrfs-<job>/` and create the read-only
snapshots there. A read-only mount cannot create a subvolume: `btrfs subvolume
snapshot` is a write on the filesystem and fails with `EROFS`. The mount is
therefore done read-write, and the sources themselves are still never written:
the only writes are the snapshots under `.linuxreflect/` and they are read-only
snapshots. Nothing in the backup path opens a source block device for writing.

Revisit if the kernel grows a way to create a snapshot through a read-only
mount, or if a distribution requires the top level to stay read-only.

## D-029 — Stream dedup is per image; the parent chain is the btrfs stream

The format already has a hash index (stream 2) and a Bloom-filter design for
cross-image dedup (spec §G.5). Slice S8b writes that index sorted, and dedups
chunks *inside* one image only. A cross-image lookup would be redundant here:
incrementals are produced with `btrfs send -p`, so the sender has already
removed unchanged data before the chunker sees it, and the S8 acceptance test
shows an incremental sending far fewer bytes than the full image.

The in-RAM dedup table is bounded by the image, and the index entries are 46 B
per distinct chunk. A lookup across a chain needs the Bloom filter, the
page-binary search and an external sort; that work belongs with chains in
Slice S9, where several images of one chain are read together. Revisit then,
and revisit earlier if a single stream image is expected to exceed the RAM
budget for its index.

## D-034 — CDC parameters are recorded in extras, not inferred

The format's `chunk_size` field is a single power of two, which cannot express
`min 16 KiB / avg 64 KiB / max 256 KiB`. A stream image therefore records a
`CDC_PARAMS` extras record (kind 6) with all three sizes and the normalization
level, and the superblock's `chunk_size` carries the maximum (262144) so the
existing superblock validation stays meaningful. A reader that wants to explain
or reproduce the boundaries uses the extras record; a reader that only needs
the bytes never looks at it.

## D-035 — Btrfs snapshot layout, unique names, and restore renaming

Snapshots live at
`<top>/.linuxreflect/<set>/<image_uuid>/<escaped subvol path>.<image uuid8>`,
and `.linuxreflect/<set>/latest` maps each escaped subvolume path to the
snapshot that a later incremental must name as its parent. `latest` records the
snapshot's *own* UUID (not the UUID of its parent), because that is what
`btrfs send -p` expects the next time. Older snapshots are deleted only after
the new image is fsynced and renamed into place, so a failed job can never
destroy the parent a previous successful image still needs.

The name suffix exists because `btrfs send` names the stream after the
snapshot's last path component: with a stable name, an incremental received
beside its parent fails with `btrfs receive: creating snapshot X -> X failed:
File exists`. Received subvolumes get *new* ids and new names, so a restore
keeps only the final subvolume of each source path, renames it to the original
path, and recreates the default subvolume by *path* — `set-default` cannot use
the source's id because the receiver assigns its own.

## D-038 — The receive progress line may be on stdout or stderr

`btrfs receive` prints `At subvol <name>` (full) or `At snapshot <name>`
(incremental) so the caller can learn the name it chose, but which stream
carries it changed between btrfs-progs versions (observed on 6.6.3 the line for
an incremental went to stdout while the full-stream line was found on stderr).
Both pipes are captured and searched, and a successful receive that reports no
name is treated as corrupt rather than silently ignored, with the input byte
count included in the error.

## D-039 — The set identifier is adopted from the catalog

The superblock carries a `set_id`, but a backup set is named by the user, and a
second run against the same directory must belong to the same set. Each run
opens the set, loads (and validates) `catalog.json`, and takes the `set_id` the
members already recorded; the freshly generated one is used only when the set
is empty. Without this, every member of a chain would claim a different set and
the catalog would disagree with the superblocks forever.

## D-040 — Catalog validation without a passphrase uses the unkeyed hash

Spec §D.3 says a catalog is validated against member superblocks, "which are
MAC'd". The member MAC needs the chain key, and `catalog rebuild` per §J.1 takes
no passphrase, so the scan checks what is available without one: the superblock
structure and its unkeyed `sb_hash`. Encrypted members are therefore checked for
integrity, not for tampering; the MAC is verified opportunistically when a
passphrase is supplied. `source_label` is likewise cache-only: it is not part of
a superblock, so a rebuild leaves it empty and `same_records` ignores it. A
rebuild that ignores labels and `updated_unix` still equals the live catalog,
which is what the S9 acceptance test asserts.

## D-041 — `--parent` must be the chain's newest member

An incremental or differential is a comparison against its parent, and the
parent is what the new member links to. If `--parent <uuid>` named an older
member of a chain that already has newer ones, the new member would fork the
chain and its delta would silently describe the wrong base. The engine refuses
that (`--parent latest` is the way to express "the newest"), and it also refuses
when the source size differs from the parent's: the positional comparison of
spec §D.4 is only meaningful for the same geometry, so a resized source needs a
new full chain.

## D-042 — Stream chains are incremental only; whole-disk chains are deferred

A Btrfs member is a `btrfs send` stream, not a block manifest, so a differential
in the block sense (a full manifest that references ancestor chunks) has no
meaning. `--type differential` is refused for Stream sources, and every member
after the full is an incremental whose send parent is the snapshot recorded in
`.linuxreflect/<set>/latest`. Whole-disk images have a region layout that a
delta would have to match per region; `--type` other than `full` is refused
there until that design exists (per-region delta with region identity matching),
which is recorded here rather than silently approximated.

## D-043 — The set lock is local, leased and refreshed

Spec §D.3 wants `set.lock` created with `O_EXCL`, refreshed every `ttl/3`, and
breakable when expired. `LocalDestination` implements exactly that: a JSON
record `{host_id, pid, created, ttl_secs}`, a background thread that rewrites it
every `ttl/3` (default lease 300 s), and removal on drop only when the lock is
still ours. A lock whose lease expired is broken only when the caller asked
(`--break-stale-lock`); otherwise the job fails with `E_SET_LOCKED` and names
the owner. SFTP's exclusive-create variant arrives with Slice S10; the default
trait method refuses to break a remote lock rather than guessing.

## D-044 — Scan-and-diff compares states, not bytes read

The incremental scan reads and hashes every *used* block (spec §D.4: it saves
destination bandwidth, not source I/O) but stores only chunks whose state
differs from the parent's: a stored chunk is unchanged when its keyed hash
matches, `Zero` and `Unused` are different states, and a recorded bad sector is
always retried because the read may succeed now. A chunk whose data is unchanged
is not appended at all — the hash is computed before sealing, so an unchanged
incremental image is metadata only (the S9 test asserts a no-op incremental is
under 64 KiB).

## D-045 — SFTP runs behind a blocking bridge

The engine and the codec are synchronous while russh is async, so
`SftpDestination` owns a private tokio runtime and `block_on`s one operation at
a time; files handed to the codec are `Read`/`Write`/`Seek` wrappers that do the
same. The bridge never nests: no `block_on` is called from inside a future, and
the runtime is only ever driven from ordinary threads. Making the whole engine
async was rejected as a rewrite of every slice for one destination type.

## D-046 — A destination is a URI; credentials never are

`--dest` accepts a path, `file://…` or `sftp://[user@]host[:port]/path`, and
`user:password@host` is refused outright (spec §L.1: no secret may reach argv,
a log or the process list). Authentication is `ssh-agent` when `SSH_AUTH_SOCK`
is usable, otherwise the `--identity` file, which must be mode 0600. The server
key is checked against `known_hosts` (plain, `[host]:port` and hashed `|1|`
entries) before authentication; an unknown host is refused, and
`--insecure-ignore-host-key` exists only for tests and logs a warning.

## D-047 — A chain is read through the destination, not copied locally

`ChainMemberFile` names a member instead of holding a path, and
`open_ro` is called twice per member: one handle feeds the manifest page
streams, the other the chunk records. This is what makes an incremental to an
SFTP destination possible at all (the parent's manifests must be read remotely)
and keeps restore working from any destination. The codec's `ChunkReader` was
generalised from `std::fs::File` to `Box<dyn ReadSeek + Send>` so the local
`dup` and the remote ranged reader are the same thing to it.

## D-048 — Mounted paths are local paths, with a warning

SMB/NFS destinations are reached through a mount (spec §B), so they are ordinary
local paths; the CLI warns when the named directory is not a mount point, which
usually means the user forgot to mount it, and refuses to proceed only when the
path is not writable. The manifest spool is written next to the image for a
local destination (same filesystem, atomic finalize) and to a temporary
directory for a remote one.

## D-049 — Only transient failures are retried, and never a partial image

Operations retry up to five times with a 250 ms → 8 s backoff, and only for
connection-level failures (reset, broken pipe, timeout, connection lost). An
aborted job deletes its `.tmp` and leaves the set lock to expire; a resumed job
is a new invocation with a new `image_uuid`, because a `.tmp` is never resumed
(spec §G.4) — that is also what keeps the nonce counter safe.

## D-050 — OpenSSH's rename does not overwrite, so the catalog is replaced

`SSH_FXP_RENAME` in OpenSSH's sftp-server fails when the target exists; only the
`posix-rename@openssh.com` extension overwrites. Image names carry a fresh UUID
and never collide, but `catalog.json` is rewritten after every job, so
`finalize` removes an existing target first. The window between the two calls is
harmless: a missing catalog is simply rebuilt from the superblocks (spec §D.3).

## D-051 — The token carries how to reach the images

`restore prepare` puts the destination URI, the set name, the member names and
the identity/known_hosts paths into the MAC'd token, so `restore apply` needs no
repeated flags (spec §J.1). Paths are not secrets; keys and passphrases never
enter the token.

## D-052 — `verify` checks structure and content separately, and names the offender

Structural verification (magic, `sb_hash`/`sb_mac`, `footer_hash`/`footer_mac`,
chunk framing, every metadata page tag) already existed as
`lr_format::verify_structure`. Slice S11 adds the half that notices a chunk
whose ciphertext was swapped for valid-but-different data: every stored chunk's
plaintext is recomputed with the chain's keyed BLAKE3 and compared with the
manifest. Block and stream images are walked through the same readers restore
uses, so a verified image is exactly the image a restore would read, and
`--chain` verifies every ancestor and reports the member that failed.

Failures carry the file name, the chunk number, the chain member index and the
record offset, because "corrupt image" alone is not actionable. whole-disk
images are verified region by region from their disk header.

## D-053 — The rescue CLI is built for static musl

`ring` (the russh crypto backend) compiles C, so the static build needs a musl
toolchain: `apt-get install musl-tools` and
`CC_x86_64_unknown_linux_musl=musl-gcc cargo build -p lr-cli --target
x86_64-unknown-linux-musl`. The result is a `static-pie` binary, which is what
Slice S16's rescue media ships; `lr-unsafe`'s `ioctl` calls are cast with
`as _` so the request constants adapt to musl's `int`-typed signature.

## D-054 — A peer is identified by pidfd, not by pid alone

`SO_PEERCRED` gives the daemon the peer's pid, uid and gid, but a pid can be
reused between the connection and the authorization check. `PeerIdentity::capture`
therefore opens a pidfd for that pid (`pidfd_open`) and re-reads `/proc/<pid>/status`
and `/proc/<pid>/stat` through it, recording the uid and start time. The uid used
for authorization is the one read after the pidfd was taken, so a recycled pid
cannot inherit another process's identity (spec §B, §I).

## D-055 — The polkit subject is `unix-process`, with a pidfd detail when polkit can use it

polkit's `unix-process` subject names a pid and a start time, which is exactly the
pair D-054 verifies. When polkit ≥ 121 supports the `pidfd` detail, the daemon
sends the pidfd number as well, which closes the remaining race inside polkit;
older polkit falls back to pid + start time. The `*_keep` flag is passed for
actions whose policy says `auth_admin_keep`, so a burst of calls does not prompt
repeatedly.

## D-056 — `StaticBackend` exists only behind `--auth static:...` / dev mode

The daemon's real authorization path is polkit. `StaticBackend` is a test and
development backend and is only reachable through an explicit `--auth static:<uid>`
or `--dev-mode`, so a default installation can never be talked into trusting a
caller without polkit.

## D-057 — The socket's directory grants exactly the access the socket grants

The socket is `0660` owned by `root:<group>` (the group is created with
`groupadd -r linuxreflect` when missing) and `0600` with a warning otherwise. A
`0660` socket inside a `0700` directory is unreachable for the very group it
names, so `lr-daemon` now sets the parent directory to match: `0750
root:<group>` for a group socket, `0700` for a root-only socket, and `0755`
when `--socket-mode` explicitly grants other-user access. The directory is never
more permissive than the socket.

## D-058 — Jobs live in memory, one per set, cancellable, with an idempotent id

The registry keeps running jobs in memory only: a restart of the daemon loses
history, which is acceptable because an image is either finalized on disk or
absent. A caller-supplied job id is idempotent — repeating it returns the same
job instead of starting a second one — and a set can have at most one active
job. Cancellation is cooperative (an `AtomicBool` the engine polls at every
progress step) and the handler always tears down the job, so a cancelled or
failed run leaves no partial image and releases the set lock. `WatchEvents`
streams job state to any number of subscribers over a broadcast channel.

## D-059 — The daemon owns the restore token secret

`restore prepare` signs the token with a secret the daemon owns; the CLI does not
create or keep one. The secret is read from a shared file (created `0600` on
first use) whose path can be overridden with `LR_TOKEN_SECRET_FILE`, which is how
tests and a systemd unit point it at a per-installation location. The secret is
never printed and never travels in argv.

## D-060 — The CLI prefers the daemon and falls back to the library

Every command first tries the daemon socket (an `unix://` tonic channel with its
own runtime, because a channel that outlives its runtime is unusable). If no
socket is reachable the command runs in-process, which keeps single-machine use
and the existing acceptance tests working without a daemon. `daemon run` execs
the daemon binary from the same installation and `daemon status` reports whether
a daemon answers.

## D-061 — `DiskMap` is an extra RPC

Spec §I lists the methods by capability, not exhaustively. `disk map` needs the
partition map per disk, so a `DiskMap(SourceRef) -> DiskList` method was added
next to `ListDisks`; it returns the same data the local `disk map --json` prints.

## D-062 — Methods from later slices answer `UNIMPLEMENTED`

`Export*`, `GetSchedule`, `SetSchedule`, `ApplyRetention` and `UnexportImage`
are declared in the service so the contract is stable, and answer
`UNIMPLEMENTED` with "Slice S13/S14" until those slices land. A client can
therefore tell "not built yet" from "failed".

## D-063 — The real polkit check needs the bus, polkitd and the installed policy

The root acceptance test starts the daemon without `--auth` (polkit path), makes
the socket reachable for the unprivileged user, and checks that
`org.linuxreflect.backup.create` is denied for `nobody` and allowed for root. It
installs `contrib/polkit/org.linuxreflect.policy` into
`/usr/share/polkit-1/actions` when the file is not already there and removes it
again afterwards, so the check is reproducible on a machine that never deployed
the daemon. When the system bus or polkitd is missing the test prints the reason
and skips instead of pretending to have verified authorization. `setpriv` runs
the CLI as `nobody`, because `runuser` failed for unrelated PAM reasons in this
environment and reported them as a misleading exec error.

## D-064 — `--socket-mode` is an explicit, logged override

`--socket-mode OCTAL` replaces the usual `0600`/`0660` socket mode. It exists for
test setups that must let a specific peer connect (for example the polkit test)
and every use is logged as a warning, so an accidental override in production is
visible.

## D-065 — A file entry stores chunk *hashes*; the hash index resolves them

The file manifest (§G.7) records, per entry, the ordered keyed hashes of its
chunks rather than (member, offset, length) triples, because the same content
appears in many files and because an unchanged file must be able to point at
chunks an *ancestor* stored. The image's hash index (stream 2) maps every hash
the member stores to its location, and a restore builds the union of the
chain's indexes, so a reference resolves no matter which member holds it. The
format's `BlockEntry.member` field is what makes that union meaningful.
Per-file dedup is content-addressed; the cross-image Bloom filter of §G.2 is
still deferred (it is a scale optimisation for S17, not a correctness need).

## D-066 — File incrementals compare manifests; differentials compare the full

An incremental member walks the tree as usual and then, for every regular file
whose kind, mode, ownership, timestamps, size, link target, xattrs and ACL are
identical to the parent member's entry, copies that entry instead of chunking
the file again; its chunk references keep pointing at whatever member stored
them. A differential must be restorable on top of the full alone (spec §D.3),
so it compares against the chain's **full** member, not the newest one, and
therefore also carries changes that intermediate incrementals recorded.

## D-067 — A file restore targets an existing directory and writes in place

Spec §D.1 gives file mode "existing filesystem" as its restore target. The
target directory must exist when `prepare` runs; it may be empty, otherwise
`--merge` is required, in which case extra files are left alone. `prepare`
captures the directory's identity (device and inode) and the free space and
refuses when the free space is smaller than the tree; `apply` re-reads the
identity immediately before the first write and refuses with
`E_TARGET_CHANGED` if it moved (spec §H.2).

## D-068 — Hard links are grouped, stored once, and restored as links

A regular file with `st_nlink > 1` and no earlier `(st_dev, st_ino)` occurrence
opens a hard-link group; later occurrences are `FILE_KIND_HARDLINK` entries
with no chunks, and the group's first path carries the content. A restore
creates the content file first and then `link(2)`s the other names to it. If
the final state of a chain no longer contains the group's content-bearing
path, the hard link is restored by copying the group's last content instead of
failing.

## D-069 — Sparse regions are recorded, and zero chunks are ordinary chunks

`SEEK_DATA`/`SEEK_HOLE` produce the hole list of every regular file, written as
a `SECTION_FILE_HOLES` (kind 6) record after its entry. A restore seeks over
those regions (and punches holes) instead of writing the zeros the chunker read
through them, so a sparse source stays sparse; a filesystem without hole
support simply allocates the zeros. Zero *chunks* are not special-cased: a
compressed zero chunk is tiny and repeats dedupe, which avoids inventing a
"how long is a zero chunk" field the format does not have.

## D-070 — The FUSE view is read-only, shares hard-link inodes and lives in the CLI

`lr-fuse` builds the tree from the chain's manifests and serves `lookup`,
`getattr`, `read`, `readdir`, `readlink`, `open` and the xattr calls; every
mutating operation is refused and the mount carries `MountOption::RO`. A
hard-link entry is attached to the regular file's inode (with the link count
raised), so both names report the same inode. Chunk content is decoded from the
chain on first read and cached per inode in memory, which is what makes
`sha256sum` cheap; a view for multi-gigabyte files is a later refinement. The
mount is performed by `lr-cli restore mount`, not through the daemon, because a
FUSE mount belongs to the caller's mount namespace.

## D-071 — `--snapshot btrfs` snapshots the subvolume holding the source

A directory source on Btrfs is snapshotted (`btrfs subvolume snapshot -r`) and
the snapshot is walked, which turns `PerFile` into `PointInTime` (spec §D.2).
The provider enumerates *mounted subvolumes*, as in Stream mode, so the source
must be a mounted subvolume rather than a directory on the top level; any other
snapshot provider for a directory is refused with a clear message, and no
snapshot means `PerFile`, which every report states.

## D-072 — Default excludes are absolute paths, and `--one-file-system` uses `st_dev`

The walk skips `/proc`, `/sys`, `/dev`, `/run` and `/tmp` by canonical absolute
path, so a directory such as `/mnt/tmp` is unaffected. `--one-file-system`
compares `st_dev` with the source root: the mount point's directory entry is
recorded but not descended, exactly like `rsync -x`. A bind mount inside the
same filesystem is not a boundary for either tool, which the root test records
by using a tmpfs instead.

## D-073 — The `rsync` acceptance check uses `-i`

`rsync -n` prints nothing for a file it would transfer; only `-i` (itemize) or
`-v` reports it. The spec's acceptance criterion "`rsync -nac` reports nothing"
is therefore run as `rsync -naxci --delete`, which fails loudly when a single
byte, timestamp, permission, owner, device number or xattr differs and passes
only when the trees are identical.

## D-074 — `verify` covers file images by resolving every reference

Verifying a file chain re-hashes every stored chunk (naming the file path, the
member and the offset on failure) and additionally checks that every chunk
reference in every manifest resolves in the chain's index, which is the failure
a restore would otherwise hit later.

## D-075 — The export runs our own newstyle NBD server

`lr-export::nbd` implements the fixed-newstyle handshake, `NBD_OPT_LIST`,
`NBD_OPT_INFO`, `NBD_OPT_GO` and `NBD_OPT_EXPORT_NAME`, and the transmission
commands `READ`, `DISC`, `FLUSH` and `TRIM`; `WRITE`/`WRITE_ZEROES` are answered
with `EPERM` and the export advertises `NBD_FLAG_READ_ONLY`. Two protocol
details cost real debugging and are worth recording: every `NBD_REP_INFO`
payload starts with the two-byte info type, and `NBD_OPT_GO` **must** answer
with `NBD_INFO_EXPORT` whether or not the client asked for it (a zero-length
info list means "the default set", which includes it). Both were caught by
`qemu-img`, an independent client, after `nbd-client` had attached a device
with a nonsensical size.

## D-076 — Export serves single-filesystem `Block` images

The export backend indexes the chunks a block chain actually stores (holes and
unused chunks read as zeroes without touching the image), so an export costs
one manifest walk and a binary search per chunk. Whole-disk images are refused
for now: mounting one would need the region manifest, and Slice S13's
acceptance criterion is about filesystem images. `Stream` and `File` images are
not block devices and are refused with a clear message.

## D-077 — `export mount` spawns a detached server; the daemon serves in-process

A FUSE-style mount must outlive the command that created it, so the CLI starts
`linuxreflect export serve` as a child with its stdout/stderr redirected to a
log file (an inherited pipe would keep a capturing caller waiting forever) and
records `{image, mountpoint, socket, device, fs_type, options, server_pid}` in
`/run/linuxreflect/exports/`. `export umount` unmounts, detaches, stops the
server and removes the state. When the daemon performs the export it serves on
a thread of its own and marks the state `in_process`, so `export umount` goes
through `UnexportImage` instead of signalling a process.

## D-078 — ublk is optional and not implemented here

Spec §K S13 marks ublk as optional and experimental (`libublk`), and this
kernel has no `/dev/ublk-control`. `caps` still reports the capability, and
`export mount --kind ublk` fails with a message naming the missing device rather
than silently falling back to NBD. NBD is the baseline the acceptance criterion
names, and it is fully implemented.

## D-079 — Read-only mounts use the spec's options, and the filesystem type comes from the image

ext4 mounts `ro,noload`; xfs mounts `ro,nouuid,norecovery`; anything else
mounts `ro`. The type is read from the block manifest header rather than from
`blkid` on the attached device, so the options do not depend on a probe of a
device that is still being set up. The spec's "browse in a file manager" is
verified through the same VFS calls a file manager makes (`readdir`, `read`),
plus a kernel-level write refusal and a full byte comparison of the exported
device against the original image.

## D-080 — `ExportImage`/`UnexportImage` take real messages

Spec §I lists the methods but not their shape, so `ExportSpec {image, at, kind,
passphrase_file, identity, known_hosts, insecure_ignore_host_key}` and
`UnexportSpec {at}` were added, and both are unary calls returning `Progress`
with the state as JSON. They are authorized by `org.linuxreflect.export.manage`
(already in the polkit policy).

## D-081 — A source with no readable size is refused

Probing a source that has vanished (a detached loop device, a removed disk)
used to succeed with a size of zero and produce a valid-looking image with no
content. `backup_image` now refuses a `Block`/whole-disk source whose size is
0, so an empty image can never be mistaken for a successful backup.

## D-082 — An NBD connection has no read timeout

The first implementation set a one-second read timeout so the stop flag could
be polled; a mounted filesystem that went quiet for a second then lost its
device ("can't read superblock" during mount). The connection now has no
timeout: the accept loop polls the stop flag between connections, and a client
ends the connection with `nbd-client -d`, which is what `export umount` does.

## D-083 — Retention is whole-chain, keeps the newest complete chain, and also removes incomplete chains

`lr-engine::retention::apply` runs under the set lock and loads the *validated*
catalog (rebuilt from the members' superblocks, spec §D.3). A chain is complete
when its sequence starts at 0 and has no gaps; complete chains are sorted
newest-first, the newest `keep_chains` are kept (with `keep_chains = 0` still
keeping the newest one, as §J.3 demands), and every other complete chain is
deleted oldest-first. Chains that are *not* complete cannot be restored, so they
are deleted too — except a chain newer than the newest complete one, which could
be the next chain in progress and is left alone with a warning. Deletion is
per-chain: every member file goes, then the chain disappears from the catalog,
and the catalog is written only after all deletions succeeded so an interrupted
run never describes files that are gone.

## D-084 — `max_incrementals_per_chain` starts a new chain

`resolve_parent_chain` counts the incrementals of the chain the parent belongs
to; when the count has reached the limit the run behaves as if it had no parent,
so the member becomes a fresh full with a new chain id (spec §J.3). The limit
arrives from `--max-incrementals` on `backup create` (0 = no limit) or from
`[job.retention] max_incrementals_per_chain` in the config, and the generated
service passes it explicitly.

## D-085 — The config file is strict and validated

`lr-engine::schedule` parses §J.2 with `serde` + `toml` and `deny_unknown_fields`,
so a typo fails loudly instead of being ignored. Validation rejects duplicate
job names, a job without a source or destination, an unknown `--type`, an empty
`on_calendar`, and `encrypt = true` without a `passphrase_file`. A `dest` is
either a named `[destinations.<name>]` entry or a path/URI written in place; a
named destination without a path is an error.

## D-086 — Units are concrete `linuxreflect-job@<name>` instances

`materialize` renders `linuxreflect-job@<name>.service` and `.timer` as
concrete instance files (systemd accepts those without a template),
`OnCalendar`, `Persistent` and `RandomizedDelaySec` verbatim, and adds
`Wants=network-online.target`/`After=network-online.target` when the
destination is a network one. `keep_chains` becomes a second `ExecStart=` line
running `retention apply`, so retention happens right after the backup without
a second timer. `schedule set` writes the files, runs `systemctl
daemon-reload` and enables and starts the timers; a `--systemd-dir` other than
`/etc/systemd/system` cannot be seen by systemd, so the report says so instead
of pretending a reload happened.

## D-087 — `lr-session` is a user service, and only job-level events notify

A root daemon cannot post into a user's session (spec risk R0-19), so
`linuxreflect-session` runs in the session, subscribes to the daemon's
`WatchEvents` and calls `org.freedesktop.Notifications.Notify` on the *session*
bus. Progress chatter (`phase`, `bytes`) is deliberately silent — a nightly job
would otherwise post hundreds of notifications; `started` is low urgency,
`finished` normal, `failed` critical and keeps the `E_*` code in the body. The
notification payload is built by a pure function, and the acceptance test runs a
mock `org.freedesktop.Notifications` service on a private session bus because
this environment has no desktop session; a Wayland session receives exactly the
same `Notify` call (spec §K S14's "desktop notification appears in a Wayland
session" is therefore verified at the D-Bus contract, not visually).

## D-088 — The engine renders, the daemon and the CLI materialize

Rendering config → units lives in `lr-engine::schedule` so the daemon's
`SetSchedule`/`GetSchedule` and the CLI's in-process fallback share one
implementation. The daemon owns *writing* when it is running (spec §J.4 says the
daemon materializes the units); the CLI uses the daemon when a socket answers
and otherwise does the same work locally as root.

## D-089 — `E_UNSUPPORTED` maps to `FailedPrecondition`, not `Unimplemented`

Nothing in the service is unimplemented any more (S13 and S14 landed), so
`Code::Unimplemented` was the wrong answer for `E_UNSUPPORTED`: a request that
cannot be served with the given inputs now maps to `FailedPrecondition`, and an
unknown job or a missing config file reports exactly that instead of claiming to
be a future slice.

## D-090 — The GUI uses Slint under the Royalty-Free 2.0 option, with attribution

Spec §M.1 leaves Slint's licence to the product owner; the chosen option is
`LicenseRef-Slint-Royalty-free-2.0` (the project itself keeps no licence yet).
`deny.toml` allows exactly that reference with a clarifying block that records
the expression and the licence text, and only that one of Slint's three options
is allowed. The attribution the licence asks for is displayed in the window
(`ui/main.slint` footer) and repeated in `README.md`. Slint 1.18.0 is pinned
exactly, built with the winit backend for both X11 and Wayland and the software
renderer (no GPU needed), and the GUI is a pure daemon client: it never opens a
device (spec §B).

## D-091 — The GUI is driven through its own callbacks when a display cannot be clicked

The acceptance criterion wants create and restore *through the GUI* on Wayland
and X11. A windowed process cannot be clicked reliably from a test on every
display server (Wayland has no pointer-injection protocol; only X11 has
`xdotool`), so `linuxreflect-gui --script <file>` sets the same fields a user
types and invokes the same callbacks a click invokes, while the window is really
mapped on the display server under test. The X11 test additionally asserts with
`xdotool search --name LinuxReflect` that the window exists, and both tests
check the restored files on disk, so the round trip is verified end to end. The
tests print why they skip when `Xvfb`/`weston` are missing, and the acceptance
run in this environment used both.

## D-092 — Empty optional RPC fields mean the documented default

`CreateBackup` with an empty `member_type`, `compress` or `on_bad_sector` now
uses the documented default instead of failing with a parse error. The CLI
always sends explicit values, but the GUI (and any future client) should not
have to repeat them; the strictness that matters — rejecting an unknown
*non-empty* value — is unchanged.

## D-093 — The rescue medium is assembled from distribution components; mkosi describes the graphical variant

Spec §K S16 asks for a rescue medium built with mkosi (`BiosBootloader=grub`,
signed shim/GRUB, distro kernel, custom initramfs, `cage` + GUI, TUI fallback).
This repository builds and *boots* a medium assembled from the distribution's
own components: the signed shim and GRUB (`shim-signed`,
`grub-efi-amd64-signed`) for UEFI Secure Boot, `grub-install --target=i386-pc`
for BIOS, the distribution kernel, and a busybox initramfs carrying the static
`linuxreflect` CLI and the TUI. That image is what the acceptance test boots
under SeaBIOS and under OVMF with Secure Boot, and an *unsigned* loader is
rejected by the same firmware as a control. `contrib/rescue/mkosi.conf`
describes the full distribution image (systemd, `cage`, the graphical client,
the TUI as console fallback) and `contrib/rescue/build-rescue.sh` builds the
assembled one; the mkosi build itself was not run here because it needs a full
distribution bootstrap (network, gigabytes, and a graphical stack inside the
image), and the acceptance criterion — that the medium boots — is verified with
the assembled image instead. This is a recorded gap, not a silent substitution.

## D-094 — The BIOS loader cannot take a very large initramfs

A first attempt shipped the *debug* static CLI (171 MiB) in the initramfs:
the kernel booted under UEFI but the BIOS path stopped right after `linux`
loaded the kernel, with `initrd` never completing (no error on any console).
The fix is to ship the release, stripped binary (8.9 MiB → a 5 MiB initramfs)
and to refuse a rescue CLI larger than 24 MiB with a message that says why, so
the failure cannot come back silently.

## D-095 — The rescue init announces on the serial port, and a missing NVRAM entry is a warning

Two details make the medium usable rather than merely present: the init script
echoes its readiness marker to `/dev/ttyS0` as well as to stdout, because with
`console=tty0` on the command line the init's stdout is the VGA console and a
rescue machine is usually driven over a serial line; and `boot-repair` treats a
failing `efibootmgr` as a warning, because the fallback loader it just installed
is what makes the disk boot and a rescue environment often has no EFI variables
at all. `BootRepairOptions::esp_device` exists because a disk *image* has no
`<file>N` partition node, so a caller that repairs an image names the ESP's loop
device explicitly.

## D-096 — Metadata pages are always keyed; the footer MAC is not

The writer's `finish` used one optional key for both the metadata pages and the
footer MAC. Unencrypted images pass `None` (the footer MAC falls back to a fixed
public key, spec §G.3), so an image whose page table overflowed the footer's
inline table could not be written at all: "overflow page table needs a metadata
key". The 16 TB scaling test hit it immediately (its manifest needs 3.8 M chunk
entries). `ImageWriter::finish` now takes the page key (always present, derived
from the chain key even for unencrypted images) and the MAC key separately, and
`crates/lr-format/tests/writer_overflow.rs` pins the path with 64-byte pages so
it stays fast.

## D-097 — The final, region-clipped chunk is read with its own length

`BlockSource::read_at` used to infer the length from the buffer, so the
whole-disk path — which reuses one chunk-sized buffer for every chunk — asked
for a full chunk even when the region ended 1007 KiB into it. The source
returned more bytes than the plan expected and `read_chunk` reported a bad
sector, which made every whole-disk backup of a btrfs-rooted disk fail at the
last chunk (ext4 and xfs hide it because their last chunk happens to be full or
unused). `read_at` now takes an explicit `len`. The same investigation showed
that `O_DIRECT` rejects a *length* that is not a multiple of the device
alignment, which is exactly what a partition ending mid-block produces, so an
unaligned read or write of that tail falls back to buffered I/O for that one
transfer (an unaligned write cannot be padded without clobbering the bytes after
it). The filesystem × firmware boot matrix is the regression test.

## D-098 — The hardening matrix's scope, and the SMB gap

Spec §K S17 names five filesystems, two firmwares, `dm-flakey` bad sectors,
network interruptions and a 16 TB metadata scale test. `root_hardening.rs`
covers: a backup/restore round trip of ext4, xfs, btrfs, fat32 and ntfs with the
filesystem's own checker and a file-hash comparison; ext4, xfs and btrfs *roots*
booted under SeaBIOS and OVMF after a whole-disk restore (fat32 and ntfs cannot
boot Linux, so they appear in the round-trip matrix); `dm-flakey` with
`error_reads` (a linear head so stored chunks exist next to the recorded bad
ones) where `abort` fails, `record` completes, `verify` accepts the image and
`restore` refuses to invent the data; an NFS destination that disappears
mid-backup (force unmounted and unexported) leaving no image and a breakable
lock; and the 16 TB virtual disk. The SMB destination is now verified for real
as well: the test's own `smbd` binds a private per-process port, the mount is
accepted only once a marker written into the share is visible through it, and
the interruption leaves no image behind and breaks the lock. It runs green both
on this WSL host and on a clean Ubuntu test host (D-100). The SMB and NFS
destinations share the same "mounted path" path (spec §B); both are exercised.

## D-099 — The metadata RSS bound is 1 GiB for a 16 TB virtual disk

The scale test formats a 16 TB sparse ext4, backs it up with a 4 MiB chunk size
(3 814 698 chunks ≈ 175 MB of manifest entries, streamed in 1 MiB pages) and
samples the CLI's `VmHWM`. The measured peak is **29 MiB**, and the test fails
above 1 GiB — a bound that a fully materialized manifest (736 MB for 16 TB at
1 MiB chunks, per §G.2) would also break, so it is a real test of the streaming
design rather than a rubber stamp.
## D-100 — The SMB test runs its own server on a private port

The first SMB hardening test mounted `//127.0.0.1/matrix` on port 445 while the
distribution `smbd` was already listening there, so the client negotiated with
the wrong server and failed with `ENOENT` (which earlier read as a "WSL
limitation"). Two further defects surfaced while fixing it: `vers=3.0` is
rejected by the Samba 4.15/kernel-6.8 pair (`EOPNOTSUPP`) where `vers=3.1.1`
works, and `mount.cifs` can block in an uninterruptible state against a
half-open server, where `timeout -k` still waits for it.

The test now: creates smbd's `pids`/`locks`/`private`/`state`/`cache`
directories, binds `24000 + pid % 10000`, writes `lr-ready` into the share and
accepts the mount only when that marker is visible, mounts with `vers=3.1.1`,
and runs every client command through `run_bounded`, which abandons the process
after a deadline instead of joining it. The server is spawned with
`stdin(Stdio::null())`; without that, WSL interop sends the test `SIGTERM` when
the long-lived child keeps the interop handle open, which had made the suite
hang. The interruption itself stops the server as well as unmounting: a lazy
unmount leaves the detached filesystem connected, so an in-flight write can
still succeed (which is what made the test fail on the Ubuntu host). The mount
is `soft`, so once the server is gone the pending write returns an error instead
of retrying forever, and the backup fails after about 50 s. The SMB round trip
now passes on WSL and on the real Ubuntu host.

## D-101 — The mkosi rescue medium builds and boots; LinuxReflect content is still to embed

Spec §K S16 asks for the graphical rescue medium to be built with mkosi ≥ 25.
The profile in `contrib/rescue/mkosi.conf` had never been run and was not valid
for that mkosi: `Architecture=x86_64` is rejected, and `Bootable`,
`BiosBootloader` and `UnifiedKernelImages` belonged in `[Content]` while
`SecureBoot`/`SecureBootKeySource` belonged in `[Validation]`, where
`SecureBootKeySource=distro` is not an accepted value (only `file`, `engine`,
`provider`). The image also needs the `universe` component for `cage`, `seatd`
and `nbd-client`, and the host running mkosi needs `mkimage`,
`grub-mkimage`/`grub-bios-setup` and Python `pefile`.

The profile now builds a real image under mkosi 28~devel, and the build is
reproducible: it runs inside a privileged `ubuntu:24.04` container on the
`10.0.77.17` test host (mkosi's own build sandbox cannot resolve DNS in WSL,
so WSL is not usable for this step). The result is a 3.1 GB GPT image with a
FAT ESP, signed `shimx64.efi` + `grubx64.efi` from the distribution,
`Bootloader=grub-signed`, `ShimBootloader=signed`, `BiosBootloader=grub`, the
distro kernel and a custom initramfs. It boots on both firmwares:
SeaBIOS loads GRUB and Linux 6.8.0-139 with systemd 255, and OVMF with
`OVMF_CODE_4M.secboot.fd` against `OVMF_VARS_4M.ms.fd` gets through the signed
shim/GRUB chain to the same kernel — an unsigned loader would have been
rejected.

The graphical session is now part of the image. The Slint GUI cannot be a
static musl binary, so `build-mkosi.sh` builds `linuxreflect-gui` for noble and
stages it beside the CLI; `mkosi.extra/` also ships the `linuxreflect-rescue`
launcher, which starts `cage` with the Wayland software renderer
(`WLR_LIBINPUT_NO_DEVICES=1`, `WLR_RENDERER=pixman`) and falls back to the
console TUI when the compositor or GUI is unavailable. The launcher announces
`LINUXREFLECT-RESCUE-READY graphical|tui` on the serial console. Both firmwares
were proven to reach the graphical session and run the GUI (live
`sctk-adwaita` Wayland integration in the log, no `gui-exited`): SeaBIOS with
virtio-gpu on the test host (TCG) and OVMF Secure Boot with KVM locally. Note
that this host's KVM aborts inside SMM (`KVM: entry failed, hardware error`)
with `-vga none -monitor none` and the remote host has no KVM, so the Secure
Boot boot used the rescue tests' qemu configuration (`-machine q35`, `-m 1024`,
IDE disk).

What remains for the full S16 deliverable is the end-to-end file-mode
bare-metal restore followed by boot from the rescue medium; the mkosi profile,
the signed chain, the CLI/TUI and the cage+GUI session are all built and
verified.


The mkosi image now carries LinuxReflect: `mkosi.extra/` installs the static
`linuxreflect` CLI, a `linuxreflect-rescue.service` that owns tty1 and runs
`/usr/local/bin/linuxreflect-rescue`, and the console TUI. The launcher
announces the chosen session on the serial console. Both firmwares were proven
to reach it: under SeaBIOS on the test host (TCG) and under OVMF Secure Boot
with KVM locally, the serial log ends with
`LINUXREFLECT-RESCUE-READY tui`. Note that this host's KVM aborts inside SMM
(`KVM: entry failed, hardware error`) with `-vga none -monitor none` and the
remote host has no KVM, so the Secure Boot boot was run with the same qemu
configuration the rescue tests use (`-machine q35`, `-m 1024`, IDE disk).



## D-102 — The rescue medium restores a bare disk unattended, and the disk boots

Spec §K S16's "bare-metal restore → boot" is now an end-to-end root test, not a
manual procedure. The assembled medium's init gained an autorun mode: when the
kernel command line carries `linuxreflect.autorun=1`, `linuxreflect.image=`,
`linuxreflect.target=` and optionally `linuxreflect.backup=`, it mounts the
backup device, runs `restore prepare` then `restore apply --confirm` (sharing
the restore-token secret through `LR_TOKEN_SECRET_FILE`), announces
`LINUXREFLECT-AUTORUN-RESTORED` on the serial console and powers off.
`MediaRequest` gained `cmdline_extra` so a build can bake those arguments into
GRUB's `linux` line, and the autorun block is checked before the
`rescue.auto=1` self test because the default command line always contains the
latter.

The test `a_bare_metal_restore_from_the_medium_boots` builds a bootable source
disk, takes a whole-disk backup, copies the image (with its
`<dest>/<set>/<chain>/` directories — `restore prepare --image` requires the
full path) onto a small ext4 disk, builds a second medium whose command line
carries the autorun parameters, boots it with the rescue medium, the backup disk
and a bare target disk as virtio disks, asserts
`LINUXREFLECT-AUTORUN-RESTORED`, and finally boots the restored disk and asserts
`LINUXREFLECT-RESCUE-SELFTEST-OK`. It runs in about 30 s.

## D-103 — The session notification is verified against a real Wayland daemon

D-087 verified `linuxreflect-session` against a mock
`org.freedesktop.Notifications` service on a private bus. That is weaker than
spec §K S14's "desktop notification appears in a Wayland session", so the
acceptance now runs a real Wayland session: `sway` with the wlroots headless
backend, plus `mako` as the notification daemon on the same session bus. The
root test `the_session_helper_posts_a_notification_on_wayland` starts a private
`dbus-daemon`, sway and mako, runs the daemon and `linuxreflect-session`, drives
a file-mode backup through the daemon, and then asserts that `makoctl list`
reports a notification whose summary is `LinuxReflect`. It passes in a couple of
seconds. (dunst was tried first but this WSL environment's weston does not
advertise `zwlr_layer_shell_v1`, so dunst could not open a Wayland output;
sway does.)

## D-104 — Token keys preserve the socket directory's permissions

The token loader used to chmod its parent directory to 0700, contradicting
D-057 when the key and daemon socket shared `/run/linuxreflect`. The loader
now leaves existing directory permissions unchanged. Socket provisioning owns
the directory's group access; the key remains an effective-user-owned regular
file with mode 0600 and exactly 32 bytes. No key bytes or names are migrated.

Directory traversal uses pinned descriptors and rejects symlinks, foreign
owners and writable ancestors without trusted sticky-directory protection.
Root and the effective user are trusted ancestor owners; the final directory
must belong to the effective user and must not be writable by other users.
Only missing directories are created (0700). Key reads validate the opened
descriptor and are bounded; nonblocking open also rejects FIFOs without
waiting for a writer. Initial creation publishes a complete temporary file
without replacing an existing key, so concurrent processes use one winner.

Root CLI and daemon use `/run/linuxreflect/token.key` by default. Non-root
callers use `$XDG_RUNTIME_DIR/linuxreflect/token.key`, or the UID-specific
temporary location when XDG_RUNTIME_DIR is unset. The explicit key-file
override still applies. Invalid configured locations, permissions and key
contents fail closed, without silent fallback or regeneration. This deliberately
rejects previously tolerated symlink/parent-traversal paths and insecure keys.

The focused regressions verify concurrent creation, key reuse, permissions,
symlinks, file sizes/types and ancestor policy. A privileged temporary-socket
test verifies that a group peer connects but cannot read the key, while the
directory remains 0750. These are filesystem guarantees; activation, polkit,
desktop installation and full restore acceptance remain separate gates tracked
in `gui-revision-audit.md`.

## D-105 — Rescue writes need `--confirm`, a reviewed target and a known formatter

Spec §H.2's token belongs to `RestoreImage`; the rescue tool is a separate,
local, root-only command, so it does not issue tokens. It keeps the parts of
the restore boundary that still apply: `boot-repair` and `recreate-layout`
write only with `--confirm` (without it they print the plan and exit
non-zero), and a layout recreation re-reads the disk's `TargetFacts` captured
with the reviewed plan and runs the §H.3 busy checks immediately before the
first write. Boot repair is not busy-checked because it works on an ESP the
operator may have mounted on purpose.

Layout recreation accepts only `ext2`, `ext3`, `ext4`, `xfs`, `btrfs`, `vfat`
and `swap`, each with the flags its own formatter documents; the previous
universal `mkfs.<fs> -F -U -L` form broke `mkfs.fat` and `mkfs.xfs` and let
an arbitrary string choose the program. Other filesystems are refused rather
than guessed.

## D-106 — `ListSets` without a set name lists the sets

The GUI library used to need the set name typed in before it showed anything,
and asking for a set that did not exist created an empty set directory,
because `open_set` creates it. `ListSets` (spec §I) with an empty `set` now
returns `SetInfo.sets`: the names of the directories under the destination
root that hold at least one `.lrimg`, sorted. It never opens or creates a set.
`Destination::list_set_names` implements it for local (and mounted) and SFTP
destinations; symlinks are not followed locally. A named `ListSets` is
unchanged. The field is additive, so older clients are unaffected.

## D-107 — Stopping the daemon drains its jobs

The daemon used to have no signal handling: SIGTERM from `systemctl stop`,
an update or a shutdown ended the process at once, cutting a restore in half
and leaving the target unusable. Now the first SIGTERM or SIGINT stops
admission (a new job gets `E_TARGET_BUSY`, "the daemon is stopping"), waits
for the running jobs, reports `STOPPING=1` with the number still running, and
exits 0. A second signal cancels the running jobs through the same flag
`CancelJob` sets. Streams that never end on their own (`WatchEvents`) get five
seconds once no job runs.

The unit sets `TimeoutStopSec=infinity`, so systemd does not SIGKILL the daemon
mid-restore; an operator who wants it gone sooner cancels the job. Because
stopping is now safe, the installer requests it with `systemctl --no-block
stop` when the daemon is active: the old process finishes its jobs and exits,
the socket unit keeps the listening socket, and the next request starts the
new binary. This replaces "activation is pending until a maintenance window".

## D-108 — A file-mode restore uses the newest member's tree

Every file-mode member's manifest lists the whole tree at its backup time;
unchanged files only point at chunks an ancestor stored. The restore and the
FUSE view used to merge the manifests of every chain member ("a later member
replaces an earlier entry per path"), so a file deleted before an incremental
or differential came back when that member was restored or mounted. Both now
take the tree from the member with the highest `seq_in_chain` and use the
older members only for their hash indices. Found by a GUI chain test (full,
incremental, differential with a deletion); the engine and FUSE regressions
fail without the change. The existing tests missed it because none deleted a
file between members.

## D-109 — LinuxReflect is licensed MIT OR Apache-2.0

The project had no licence (D-090 left it open), which would have made a public
release "all rights reserved". The product owner chose the Rust ecosystem's
usual dual licence, MIT OR Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE`, and
`license` in every crate). Third-party licences are unchanged: the GUI binary
links Slint under its Royalty-Free 2.0 licence, whose attribution the window
and the README carry (D-090).

## D-110 — One metadata nonce counter per image; older encrypted images are flagged

Every metadata stream of an image (manifest, hash index, extras and the
overflow page table) is sealed under the same per-image `meta_key`. §G.4
asks for "separate counters for `data_key` and `meta_key`", that is one
counter per key, but each `PageStream` started its own counter at zero.
Page 0 of the manifest and page 0 of the extras stream therefore shared a
`(key, nonce)` pair (R01). Under AES-256-GCM or ChaCha20-Poly1305 that
reveals the XOR of the two plaintexts and, for GCM, the authentication
subkey, so the metadata of an encrypted image lost confidentiality and
integrity. Chunk data is sealed under the separate `data_key` with one
counter per image and was not affected.

- **Fix without a format change.** `ImageWriter` owns the image's single
  metadata `NonceSeq`, and every page stream draws from it through the
  `PageSink` it writes to. Each page record already stores its nonce, so
  readers are unchanged and the format version stays at v1.
- **One writer per stream.** `ImageWriter` requires every stream's pages in
  order from page 0 and refuses a stream that is written a second time;
  a reader could not tell such pages from the first writer's.
- **Existing images.** A pre-fix image always repeats a nonce across its
  streams (every image has a manifest and an extras stream), and a current
  image never does. `verify` and `restore prepare` read the page nonces and
  add a warning for an *encrypted* image that repeats one. The image still
  restores and verifies, because its tags are valid, but the warning
  recommends a new full backup to replace the chain. Unencrypted images make
  no confidentiality claim and get no extra warning. `prepare` checks the
  image it was given; `verify --chain` checks every member.
- **Argon2 budget (R11).** The KDF parameters are read from the superblock
  before anything can be authenticated. `derive_kek` now refuses
  `m > 1 GiB`, `t > 16`, `p > 16` or `m × t > 4 GiB passes` before Argon2
  allocates anything. The spec default (256 MiB, 3, 4) is well inside that
  budget. Derivations in one process are serialised, so a daemon running
  several jobs never holds more than one KDF's memory at a time.

Regression tests: `crates/lr-format/tests/nonces.rs` checks three things.
Nonces are unique across all four streams under both AEADs. A reopened
stream is refused. An image sealed the old way is recognised. The `kdf`
unit tests check that an over-budget header fails immediately. The first two
nonce tests and the budget test fail without the fix.

## D-115 — Set and job names follow one grammar; Btrfs cleanup is confined to its own snapshots

A set name is a directory at the destination and below a Btrfs source's
`.linuxreflect/`. A job name is part of a systemd unit name. The spec does
not constrain either. Set names were passed through unchecked, and the Btrfs
provider only replaced unusual characters, so `..` survived and the set's
state directory became the filesystem's top level. On commit the provider
then deleted every entry of that directory except `latest` and the current
image, recursively, which reached the source subvolumes themselves (R02).

- **Grammar.** Set and job names match `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`.
  The first character is a letter or digit, which excludes `.`, `..`, hidden
  names and names that look like options. `lr_core::names` holds the one
  validator. Chain names are image UUIDs generated by the engine and are
  not user input.
- **Where it is checked.** `lr_store::open` checks every non-empty set name.
  An empty name only lists sets (D-106), and a local destination refuses to
  open a set without a name. `BackupRequest::new` and `open_destination`
  check the name before any destination or snapshot work. The Btrfs
  provider checks it again before it mounts anything, the scheduler config
  checks job and set names, and the GUI's backup review explains the rule.
  The CLI and the daemon reach all of these through the engine.
- **Cleanup.** Retention in the Btrfs provider now touches only its own
  layout. It considers a directory directly in the set's state directory
  only when its name is an image UUID in canonical form, and within it
  deletes only the subvolumes directly inside, with `btrfs subvolume
  delete`. It never recurses, never follows a symlink, never calls
  `remove_dir_all`, and removes an image directory only once it is empty.
  Foreign subvolumes, directories and files stay where they are.

Regression tests: `crates/lr-core/src/names.rs`,
`crates/lr-engine/tests/names.rs` (refusal before anything is written, and a
sentinel beside the destination), the provider's unit tests (refusal before
mounting, and pruning that ignores foreign names and plain files) and the
root test `btrfs_cleanup_stays_inside_its_own_snapshots` on a loop-backed
Btrfs. The root test fails without the change.
