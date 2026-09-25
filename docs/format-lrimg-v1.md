# `.lrimg` format v1 — normative layout

This document fixes the byte layout that spec §G leaves to the implementation.
It is normative for `lr-format`: a reader and writer are only correct together
if they agree with the tables below, and the S4 tests decode real files with the
offsets stated here.

All integers are little-endian. `u32`/`u64` are unsigned, `i64` is signed
two's complement. "Reserved" bytes are written as zero and must be ignored on
read (a future reader rejects nonzero reserved bytes only if a future
`min_reader` says so).

An image file is written once and never resumed. Byte order in the file:

```
[ Superblock   4096 B at offset 0        ]
[ Chunk records 4096 .. data_end_offset  ]
[ Metadata pages  data_end_offset .. EOF-4096 ]
[ Footer       4096 B at EOF-4096        ]
```

## 1. Superblock (4096 bytes at offset 0)

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | `magic` = `4C 52 49 4D 47 01 00 00` (`"LRIMG\x01\0\0"`) |
| 8 | 4 | `format_major` = 1 |
| 12 | 4 | `min_reader` = 1 |
| 16 | 8 | `flags` (bit0 encrypted, bit1 compressed, bit2 delta manifest, bit3 whole disk, bit4 inconsistent) |
| 24 | 1 | `image_kind` (1 block, 2 stream, 3 file) |
| 25 | 1 | `consistency` (0 point-in-time, 1 frozen, 2 offline, 3 per-file, 4 none) |
| 26 | 16 | `image_uuid` |
| 42 | 16 | `chain_id` |
| 58 | 16 | `set_id` |
| 74 | 16 | `parent_uuid` (all zero for a full) |
| 90 | 4 | `seq_in_chain` (0 = full) |
| 94 | 8 | `created_unix` |
| 102 | 8 | `source_size_bytes` |
| 110 | 4 | `logical_block_size` |
| 114 | 4 | `chunk_size` |
| 118 | 4 | `kdf_id` (1 = Argon2id) |
| 122 | 4 | `aead_id` (1 = AES-256-GCM, 2 = ChaCha20-Poly1305) |
| 126 | 16 | `kdf_salt` (identical in every member of a chain) |
| 142 | 4 | `argon2_m_cost_kib` |
| 146 | 4 | `argon2_t_cost` |
| 150 | 4 | `argon2_p_cost` |
| 154 | 12 | `wrap_nonce` |
| 166 | 48 | `wrapped_chain_key` = AES-256-GCM(KEK, AD = `"lrimg-v1/wrap" ‖ chain_id`) |
| 214 | 810 | reserved, zero |
| 1024 | 32 | `sb_hash` = unkeyed BLAKE3 over bytes `0..1024` |
| 1056 | 32 | `sb_mac` = keyed BLAKE3(`meta_key`) over bytes `0..1056` |
| 1088 | 3008 | reserved, zero |

`sb_hash` is the corruption check that works before any key exists; `sb_mac` is
the tamper check and therefore requires the passphrase. Unencrypted images use
the fixed public key from `lr_crypto::mac::fixed_public_mac_key()` and are not
tamper-evident.

Validation on read: magic, `format_major <= 1`, `min_reader <= 1`,
`image_kind` and `consistency` in range, `kdf_id`/`aead_id` known,
`chunk_size` a power of two in `262144..=4194304`, `logical_block_size` a power
of two in `512..=4096`, `sb_hash` matches.

## 2. Chunk records (from offset 4096 up to `data_end_offset`)

```
[ magic u16 = 0xC4C7 ][ stored_len u32 ][ flags u8 ][ nonce 12 ]
[ payload stored_len B ][ tag 16 B (only when flags.bit1 is set) ]
```

* `flags` bit0 `zstd`: payload is a zstd frame; bit1 `encrypted`: payload is
  AEAD ciphertext and the 16-byte tag follows.
* Overhead is 35 B when encrypted (2+4+1+12+16) and 19 B when not.
* When encrypted, the associated data is
  `keyed_BLAKE3(dedup_key, plaintext) ‖ image_kind u8` (33 B) and the nonce
  comes from the image's data-key counter. The plaintext hash is not stored in
  the record: it lives in the manifest.
* `stored_len` is the length of what is actually stored: the zstd frame length
  when compressed, otherwise the plaintext length. On read it must be
  `<= 4 MiB + 65536` so a corrupt record cannot request a huge allocation.
* Compression is applied only when the zstd frame is strictly smaller than the
  plaintext; otherwise the chunk is stored raw with bit0 clear.

## 3. Metadata pages (from `data_end_offset` to `EOF-4096`)

```
[ page_magic u16 = 0x9A6E ][ len u32 ][ nonce 12 ][ ciphertext len B ][ tag 16 ]
```

* Always encrypted with `meta_key`; associated data is
  `stream_id u8 ‖ page_no u64` (9 B).
* `len` is the ciphertext length and must be `<= 4 MiB`.
* Streams: 1 manifest, 2 hash index, 3 extras, 4 overflow page table.
* A page stream is a byte stream: consecutive page payloads are concatenated.
  Page boundaries carry no meaning for the structures in §4 and §5.

## 4. Footer (4096 bytes at `EOF-4096`)

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | `magic` = `4C 52 46 4F 4F 54 01 00` (`"LRFOOT\x01"` + zero) |
| 8 | 8 | `total_chunks` |
| 16 | 8 | `data_end_offset` |
| 24 | 2 | `page_table_count` |
| 26 | 2 | `page_table_slots` = 120 |
| 28 | 4 | `flags` (bit0: page table stored in stream 4, see below) |
| 32 | 1024 | `superblock_copy` = superblock bytes `0..1024`, verbatim |
| 1056 | 1560 | inline page table, 120 slots × 13 B |
| 2616 | 8 | reserved, zero |
| 2624 | 32 | `footer_hash` = unkeyed BLAKE3 over bytes `0..2624` |
| 2656 | 32 | `footer_mac` = keyed BLAKE3(`meta_key`) over bytes `0..2656` |
| 2688 | 1408 | reserved, zero |

Page table slot (13 B): `stream_id u8 ‖ offset u64 ‖ len u32`, where `offset`
points at the page record and `len` is the value of the record's `len` field
(ciphertext length).

A page table with more than `page_table_slots` entries sets footer `flags`
bit0. In that case the real table is serialized (13 bytes per entry, no
padding) and written as stream-4 pages, and the inline table lists exactly
those stream-4 pages, starting from page 0: `page_table_count` is the number of
stream-4 pages, and the real entry count is the stream-4 plaintext length
divided by 13. A stream-4 table that does not itself fit in the inline slots is
an error, not a deeper recursion.

Reading starts at `EOF-4096`. A missing or invalid footer means the file is
incomplete and is never restorable. Both `sb_mac` and `footer_mac` must be
verified before any offset, length or flag is trusted.

## 5. Manifest stream (stream 1)

The manifest stream is a byte stream assembled from pages. Its first bytes are
a section header that identifies what follows.

### 5.1 Common header

| Offset | Size | Field |
|---|---|---|
| 0 | 2 | `ver` = 1 |
| 2 | 1 | `section_kind` |
| 3 | 1 | reserved |
| 4 | ... | kind-specific, see below |

`section_kind`: 1 block full, 2 block delta, 3 stream subvolume, 4 file entry,
5 file entry continuation.

### 5.2 Block manifest (kinds 1 and 2)

| Offset (relative) | Size | Field |
|---|---|---|
| 4 | 4 | `chunk_size` |
| 8 | 8 | `chunk_count` (total chunks of the image) |
| 16 | 8 | `entry_count` (entries in this manifest) |
| 24 | 8 | `used_extent_count` |
| 32 | 8 | `used_bytes` |
| 40 | 2 | `fs_type_len` |
| 42 | 2 | `fs_uuid_len` |
| 44 | 2 | `label_len` |
| 46 | 2 | reserved |
| 48 | var | `fs_type`, `fs_uuid`, `label` (UTF-8, no NUL) |
| ... | entry_count × entry | entries |

Entry (46 B) for kind 1:

| Offset | Size | Field |
|---|---|---|
| 0 | 32 | `hash` = keyed BLAKE3(`dedup_key`, chunk plaintext) |
| 32 | 2 | `member_state`: low 14 bits `member` index, high 2 bits `state` |
| 34 | 8 | `offset` (absolute file offset of the chunk record) |
| 42 | 4 | `stored_len` |

`state`: 0 unused/hole, 1 zero, 2 stored, 3 bad sector. Chunk number is
positional: entry `i` describes chunk `i`.

Entry (54 B) for kind 2 (delta) prepends `chunk_no u64`, so only changed chunks
appear; everything else is inherited from the parent state.

A chain is a sequence of members that share `chain_id`, `chunk_size`,
`source_size_bytes`, `set_id` and one wrapped chain key. The state of chunk `n`
is the entry from the **newest** member that mentions it:

* a **full** (sequence 0) or **differential** member carries a full manifest,
  so it mentions every chunk; a differential's unchanged entries keep the
  `member`, `offset`, `stored_len` and `hash` of the ancestor that stored the
  data (spec §D.3's dependency rule: a member may reference any ancestor);
* an **incremental** member carries a delta manifest and mentions only chunks
  that changed, whose data it stores itself.

`member` indexes the chain member list in the extras stream (kind 1), which
every member writes as the ordered prefix ending with itself, so an index means
the same image in every member of the chain. Readers apply a chain by walking
chunk numbers in order with one cursor per member; nothing larger than a bounded
buffer is held in RAM (spec §G.2).

The entry `state` value describes the chunk *after* applying this member: a
delta entry with `state` 0 records that a chunk became a hole or moved out of
the used set.

### 5.3 Stream manifest (kind 3, repeated per subvolume)

| Offset (relative) | Size | Field |
|---|---|---|
| 4 | 8 | `subvolid` |
| 12 | 8 | `send_stream_bytes` |
| 20 | 8 | `entry_count` |
| 28 | 1 | `has_parent` (0/1) |
| 29 | 16 | `parent_snapshot_uuid` (zero when `has_parent` = 0) |
| 45 | 2 | `subvol_path_len` |
| 47 | var | `subvol_path` |
| ... | entry_count × 46 B | chunk entries (same shape as kind 1) |

Sections repeat until the manifest stream ends.

For stream sections every 46-byte entry has `state` = 2 (stored), `member` = 0
and `chunk_no` implicit (entries follow the `btrfs send` stream in order). A
zero-filled region is stored like any other chunk: the receiver needs the exact
bytes of the send stream, so the block-mode `state` = 1 shortcut does not apply.

For a Btrfs stream image the superblock's `chunk_size` is the *maximum* CDC
chunk size (262144, §1). The exact `min`/`avg`/`max` and normalization level are
recorded in the `CDC_PARAMS` extras record. `subvol_path` is informational; the
name `btrfs send` gives the stream — and therefore the name the receiver uses —
is `<escaped subvol path>.<first 8 hex digits of the image UUID>`, because an
incremental received next to its parent must not reuse the parent's name.

### 5.4 File manifest (kinds 4 and 5)

| Offset (relative) | Size | Field |
|---|---|---|
| 4 | 8 | `chunk_refs_total` (all refs of this file) |
| 12 | 1 | `file_kind` (1 regular, 2 directory, 3 symlink, 4 hardlink, 5 special) |
| 13 | 4 | `mode` |
| 17 | 4 | `uid` |
| 21 | 4 | `gid` |
| 25 | 8 | `mtime_sec` |
| 33 | 4 | `mtime_nsec` |
| 37 | 8 | `size` |
| 45 | 8 | `rdev` (`st_rdev` for device nodes, 0 otherwise) |
| 53 | 4 | `hardlink_group` (0 = none) |
| 57 | 4 | `link_target_len`, then that many bytes |
| ... | 2 | `path_len`, then that many bytes |
| ... | 4 | `xattr_count` |
| ... | 4 | `acl_len`, then that many bytes |
| ... | 8 | `chunk_refs_here` |
| ... | var | xattrs (`u16 klen, key, u16 vlen, value`) × `xattr_count` |
| ... | `chunk_refs_here` × 32 B | chunk hashes |

`rdev` carries the device number of a `FILE_KIND_SPECIAL` entry (character or
block device); character devices, FIFOs and sockets have `rdev == 0`.


If `chunk_refs_here < chunk_refs_total`, the next section is kind 5:

| Offset (relative) | Size | Field |
|---|---|---|
| 4 | 8 | `chunk_refs_here` |
| 12 | var | that many 32-byte hashes |

If a regular file has sparse regions, the next section is kind 6:

| Offset (relative) | Size | Field |
|---|---|---|
| 4 | 8 | `hole_count` |
| 12 | `hole_count` × 16 B | `(offset u64, length u64)` pairs, ascending |

Both section kinds belong to the immediately preceding file entry, and a file
entry is followed by its continuations first and then, if present, its holes.

Continuations belong to the immediately preceding file section.

## 6. Hash index stream (stream 2)

Only used by stream and file images. A byte stream of 46-byte entries with the
same shape as a block entry (`hash`, `member_state`, `offset`, `stored_len`);
deduplicated by `hash`. Dedup lookup uses an in-RAM Bloom filter plus a binary
search over the sorted entry list; the filter size is a runtime setting
(default 64 MiB, applied by S8).

## 7. Extras stream (stream 3)

A sequence of records:

| Offset | Size | Field |
|---|---|---|
| 0 | 2 | `ver` = 1 |
| 2 | 1 | `kind` |
| 3 | 1 | reserved |
| 4 | 4 | `len` |
| 8 | len | payload |

Kinds: 1 chain member list, 2 partition table dump, 3 `fstab`, 4 Btrfs layout,
5 image metadata, 6 CDC parameters.

Kind 4 (Btrfs layout) is line-oriented so a reader can ignore unknown fields:

| Line | Meaning |
|---|---|
| `fs_uuid=<uuid>` | filesystem UUID to recreate on restore (required) |
| `label=<text>` | filesystem label |
| `default_subvolid=<n>` | default subvolume id on the source |
| `default_subvol_path=<path>` | path of the default subvolume, `-` for the top level |
| `mount_options=<opts>` | mount options of the source filesystem |
| `subvol=<path>TAB<subvolid>` | one line per snapshotted subvolume |

Kind 6 (CDC parameters) is 13 bytes: `min u32`, `avg u32`, `max u32`,
`normalization u8`. The chain member list is a sequence of
`u8 index ‖ u16 reserved ‖ 16 B image_uuid` entries (19 B each); `member`
indices in manifests refer to this list.

Unknown kinds are skipped using `len`, which is what keeps §G.8 forward
compatibility cheap.

## 8. Whole-disk manifest (stream 1, `section_kind` 6)

A whole-disk image sets superblock `flags` bit3 (`whole_disk`), keeps
`image_kind` = 1 (block) and records the disk size in `source_size_bytes`. Its
manifest stream starts with a disk header followed by one region record per
imaged region; after all the records, the block manifests follow in region
order, one for every region that carries data. Each is an ordinary block
manifest (§5.2, `section_kind` 1) whose entries are positional **within the
region**: entry `i` describes the chunk at
`region.start_lba * logical_block_size + i * chunk_size`. Gaps between
partitions and the backup GPT are not imaged (spec §G.7).

### 8.1 Disk header

| Offset (relative) | Size | Field |
|---|---|---|
| 0 | 2 | `ver` = 1 |
| 2 | 1 | `section_kind` = 6 |
| 3 | 1 | reserved |
| 4 | 8 | `disk_size` |
| 12 | 4 | `logical_block_size` |
| 16 | 1 | `pt_type` (0 none, 1 GPT, 2 MBR) |
| 17 | 3 | reserved |
| 20 | 2 | `serial_wwid_len` |
| 22 | var | `serial_wwid` (UTF-8, may be empty) |
| ... | 4 | `pt_raw_len` |
| ... | var | `pt_raw_bytes` (the first 1 MiB verbatim: protective MBR + primary GPT; empty when `pt_type` = 0) |
| ... | 8 | `region_count` |
| ... | var | `region_count` region records (§8.2) |

### 8.2 Region record

| Offset (relative) | Size | Field |
|---|---|---|
| 0 | 2 | `ver` = 1 |
| 2 | 1 | `kind` (1 leading, 2 partition-fs, 3 partition-raw, 4 swap) |
| 3 | 1 | `consistency` (as §1) |
| 4 | 4 | `flags` (bit0: a block manifest follows; bit1: bootable) |
| 8 | 4 | `index` (partition index; 0 for the leading region) |
| 12 | 8 | `start_lba` |
| 20 | 8 | `size_bytes` |
| 28 | 2 | `type_guid_len` |
| 30 | var | `type_guid` (GPT type GUID string; empty for MBR) |
| ... | 2 | `partuuid_len` |
| ... | var | `partuuid` |
| ... | 2 | `fs_type_len` |
| ... | var | `fs_type` |
| ... | 2 | `fs_uuid_len` |
| ... | var | `fs_uuid` |
| ... | 2 | `fs_label_len` |
| ... | var | `fs_label` |
| ... | 4 | `swap_header_len` (only meaningful for kind 4) |
| ... | var | `swap_header` (the partition's first 4 KiB) |

`leading` covers LBA 0 up to the first partition's start, capped at 16 MiB
(spec §G.7); it is read raw with zero suppression and carries the BIOS
`core.img` when GRUB is installed in the MBR gap.

`partition-fs` regions take their `chunk_count` from
`ceil(size_bytes / chunk_size)` and their entries from the filesystem's
used-block map; `partition-raw` regions (bios_grub, LVM PV, LUKS, mdadm member,
unknown) are read whole with zero suppression; `swap` regions store only
`swap_header` and are recreated with `mkswap -U <uuid> -L <label>` on restore.

Restoring a GPT image to a larger disk rewrites the primary and backup GPT for
the new device size (regenerated CRCs, `last_usable`, backup at the new end);
the extra space stays unallocated (spec §H.1). MBR images have no backup table.
