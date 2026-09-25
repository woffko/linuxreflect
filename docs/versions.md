# Dependency versions (bootstrap record)

Spec §L.5 requires every dependency to be pinned as an exact tested version in
`[workspace.dependencies]` and the resolved set to be recorded here at
bootstrap. The pin is authoritative; `Cargo.lock` is committed.

Toolchain: Rust 1.95.0 (`rust-toolchain.toml`), edition 2024, resolver 3.

"Locked" means the version is present in the committed `Cargo.lock` because a
workspace crate already depends on it and the workspace builds with it.
"Declared" means the version is pinned for a later slice and will enter the lock
the first time a crate uses it (unused workspace dependencies are not resolved
by Cargo).

## Runtime dependencies

| Crate | Pinned | Status | Used by |
|---|---|---|---|
| clap | 4.6.7 | Locked | lr-cli |
| thiserror | 2.0.20 | Locked | lr-core, lr-crypto, lr-format, lr-fsmap, lr-snapshot, lr-blocksource, lr-store, lr-engine, lr-daemon |
| anyhow | 1.0.104 | Locked | lr-cli, xtask |
| tracing | 0.1.44 | Locked | lr-core, lr-fsmap, lr-snapshot, lr-blocksource, lr-store, lr-engine, lr-daemon, lr-cli |
| tracing-subscriber | 0.3.23 | Locked | lr-cli |
| tracing-journald | 0.3.2 | Locked | lr-daemon |
| serde | 1.0.229 | Locked | lr-core, lr-format, lr-store, lr-proto, lr-cli |
| serde_json | 1.0.151 | Locked | lr-core, lr-store, lr-cli |
| toml | 1.1.6 | Locked | lr-engine config and job files (S14) |
| tokio | 1.53.1 | Locked | lr-store, lr-daemon |
| zstd | 0.14.0 | Locked | lr-format (S4) |
| aes-gcm | 0.11.1 | Locked, KAT-verified | lr-crypto (S3) |
| chacha20poly1305 | 0.11.0 | Locked, KAT-verified | lr-crypto (S3) |
| argon2 | 0.6.0 | Locked, KAT-verified | lr-crypto (S3) |
| hkdf | 0.13.0 | Locked, KAT-verified | lr-crypto (S3) |
| sha2 | 0.11.0 | Locked, KAT-verified | lr-crypto (S3) |
| blake3 | 1.8.7 | Locked, official test vectors | lr-crypto (S3) |
| zeroize | 1.9.0 | Locked | lr-crypto (S3) |
| fastcdc | 5.0.0 | Declared | lr-format stream/file chunking (S4, S12) |
| rand | 0.10.2 | Declared | tests only; identifiers use `/dev/urandom` |
| gpt | 4.1.0 | Locked | lr-core discovery |
| mbrman | 0.6.1 | Locked | lr-core discovery |
| nix | 0.31.3 | Declared | reserved for `lr-unsafe` helpers |
| libc | 0.2.189 | Locked | lr-unsafe |
| tonic | 0.14.6 | Locked | lr-proto, lr-daemon |
| prost | 0.14.4 | Locked | lr-proto |
| zbus | 5.19.0 | Locked | lr-daemon |
| zbus_polkit | 5.1.0 | Locked | lr-daemon (RUSTSEC-2026-0278 fix floor) |
| enumflags2 | 0.7.12 | Locked | lr-daemon (`CheckAuthorizationFlags` interaction) |
| fuser | 0.18.0 | Locked | lr-fuse (file-mode FUSE view, Slice S12) |
| slint | 1.18.0 | Locked | lr-gui (GUI, Slice S15), Royalty-Free 2.0 with attribution (D-090) |
| slint-build | 1.18.0 | Locked | lr-gui build script |
| hmac | 0.13.0 | Locked | lr-store hashed `known_hosts` (S10) |
| sha1 | 0.11.0 | Locked | lr-store hashed `known_hosts` (S10) |
| russh | 0.63.3 | Declared | lr-store SFTP (S10) |
| russh-sftp | 3.0.0 | Declared | lr-store SFTP (S10) |
| proptest | 1.11.0 | Locked | lr-crypto and lr-format dev-dependency |
| tempfile | 3.27.0 | Locked | tests |
| hex | 0.4.3 | Locked | lr-crypto and lr-format dev-dependency |
| uuid | 1.26.1 | Locked (transitive) | pulled in by `gpt` |

## Notes

* `zbus_polkit < 5.1.0` is denied in `deny.toml` because RUSTSEC-2026-0278
  (CVSS 7.3) allows a PID-reuse authorization bypass (spec §B, §I).
* `rand` is intentionally not used for identifiers: `lr_core::Id::generate()`
  reads `/dev/urandom` directly, so no RNG version can affect on-disk identity.
* `nix` is pinned but not yet used; block ioctls are implemented directly on
  `libc` in `lr-unsafe` so that every request number is visible in one place.
* Versions must be re-verified when their slice lands, and any change recorded
  here in the same pull request.

## Test oracles (system packages, not crates)

`tools/kats/generate.py` produces `crates/lr-crypto/tests/vectors/mod.rs` from
independent implementations. Regenerate with:

```sh
python3 tools/kats/generate.py
```

| Oracle | Used for | Installed with |
|---|---|---|
| `argon2` (reference CLI, P-H-C) | Argon2id known-answer values | `apt-get install argon2` |
| `python3-argon2` (argon2-cffi) | cross-check of the same values | `apt-get install python3-argon2` |
| `python3-cryptography` | AES-256-GCM, ChaCha20-Poly1305, HKDF-SHA256 | `python3-cryptography` |
| official BLAKE3 vectors | keyed and unkeyed BLAKE3 | downloaded from the BLAKE3 repository |

The generated file is committed, so a test run does not need any of them; only
regenerating the vectors does.

## File mode (Slice S12)

| Crate / tool | Version | Notes |
|---|---|---|
| `fuser` | 0.18.0 | FUSE plumbing only (spec §B); `default-features = false`, no libfuse development headers needed |
| `fusermount3`, `/dev/fuse` | fuse3 / kernel | required at runtime by `restore mount`; the acceptance test skips with a printed note when they are absent |
| `rsync` | distribution package | the acceptance oracle: `rsync -naxci --delete` must report nothing (D-073) |
| `btrfs` (`subvolume snapshot -r`) | btrfs-progs | `--snapshot btrfs` on a directory source (D-071) |

## Hardening matrix (Slice S17)

| Tool | Package | Used for |
|---|---|---|
| `mkfs.ntfs`, `ntfs-3g`, `ntfsfix` | ntfs-3g | the ntfs row of the filesystem matrix |
| `mkfs.vfat`, `fsck.vfat` | dosfstools | the fat32 row |
| `dmsetup` with `dm-flakey` (`error_reads`) | device-mapper | bad-sector injection with a linear head |
| `smbd`, `mount.cifs` | samba, cifs-utils | SMB destination test, run on a private port against the test's own server (verified, D-100) |
| `rpcbind`, `rpc.nfsd`, `exportfs`, `mount.nfs` | nfs-kernel-server, nfs-common | NFS destination test |
| `/dev/kvm` | kernel module | the boot matrix runs with hardware virtualisation |

## Rescue media and boot repair (Slice S16)

| Tool | Package | Used for |
|---|---|---|
| `shim-signed`, `grub-efi-amd64-signed` | distribution packages | the signed UEFI chain the medium boots with Secure Boot |
| `grub-pc-bin`, `grub-install` | grub-pc-bin | the BIOS bootloader in the leading region / BIOS boot partition |
| `busybox-static` | busybox-static | the statically linked initramfs userland |
| `OVMF_CODE_4M.secboot.fd`, `OVMF_VARS_4M.ms.fd` | ovmf | booting the medium with Secure Boot and the Microsoft keys enrolled |
| `qemu-system-x86_64` with `/dev/kvm` | qemu-system-x86 | the boot tests (KVM where the kernel exposes it) |
| `sgdisk`, `mkfs.vfat`, `sfdisk`, `blkid` | gdisk, dosfstools, util-linux | building the medium and recreating a layout |
| `mkosi` (28~devel), `docker.io` | mkosi, docker | the graphical rescue medium from `contrib/rescue/mkosi.conf`, built in a privileged `ubuntu:24.04` container; it boots on SeaBIOS and OVMF Secure Boot (D-101) |

## GUI (Slice S15)

| Tool | Package | Used for |
|---|---|---|
| `Xvfb` | xvfb | the X11 acceptance run (a private headless X server) |
| `xdotool` | xdotool | proving the GUI window is mapped on X11 |
| `weston` | weston | the Wayland acceptance run (headless backend) |
| `libxkbcommon-x11-0`, `libgl1-mesa-dri` | distribution packages | winit's X11 keyboard support and the software GL path |
| `arrayref` (BSD-2-Clause) | locked via Slint | added to `deny.toml`'s allow list for the GUI graph |

## Scheduling and session (Slice S14)

| Tool | Package | Used for |
|---|---|---|
| `systemctl`, `systemd-analyze` | systemd (255) | unit materialization, `daemon-reload`, and validating and running the generated timer |
| `dbus-daemon` | dbus | a private session bus for the notification test |
| `python3-dbus` (dbus-python) | distribution package | the mock `org.freedesktop.Notifications` service |
| `sway`, `mako`, `makoctl` | sway, mako-notifier | a real headless Wayland session and notification daemon (D-103) |
| `zbus` | 5.19.0 | `lr-session` calls `Notify` on the session bus (already a daemon dependency) |

## Block export (Slice S13)

| Tool | Package | Used for |
|---|---|---|
| `nbd-client` | nbd-client (3.24) | attaches the kernel NBD device; requires the `nbd` module |
| `qemu-nbd` | qemu-utils | independent client used to cross-check the handshake and the advertised size |
| `ublk` (`/dev/ublk-control`) | kernel | optional export path; absent on this kernel (D-078) |

## Test-only system dependencies

Slice S5/S6 tests drive real tools; none of them is a Rust dependency, and the
tests skip with a printed note when one is missing.

| Tool | Package | Used for |
|---|---|---|
| `dumpe2fs`, `mkfs.ext4`, `fsck.ext4`, `debugfs` | e2fsprogs | ext4 used-block map and the completeness acceptance test |
| `xfs_db`, `mkfs.xfs`, `xfs_repair` | xfsprogs | xfs used-block map and `xfs_repair -n` |
| `losetup`, `blockdev`, `blkid`, `mkswap`, `swapon` | util-linux | loop devices, swap-refusal check |
| `mkfs.vfat` | dosfstools | FAT signature for the S2 ESP fixture |
| `argon2` | argon2 | Argon2id KAT oracle (Slice S3) |
| `python3-argon2`, `python3-cryptography` | system Python packages | KAT cross-checks |
| `dm-flakey` | kernel module | recorded in D-020 as available but not used for deterministic tests |

## Slice S8 test dependencies

| Tool | Package | Used for |
|---|---|---|
| `pvcreate`, `vgcreate`, `lvcreate`, `lvs`, `lvremove`, `vgs` | lvm2 | LVM classic and thin snapshot providers |
| `thin_check`, `thin_dump` | thin-provisioning-tools | presence check for the thin-pool test (the package installs no binary named `thin-provisioning-tools`) |
| `btrfs` | btrfs-progs | subvolume detection and `send`/`receive` stream mode (Slice S8b) |
| `mkfs.btrfs` | btrfs-progs | btrfs fixtures |

## Remote destinations and the static musl CLI

| Crate / tool | Version | Notes |
|---|---|---|
| `russh` | 0.63.3 | `default-features = false, features = ["ring"]`; the default `aws-lc-rs` backend needs cmake/bindgen and does not build for musl |
| `russh-sftp` | 3.0.0 | client and server (the server is a dev-dependency for the hermetic test server) |
| `musl-tools` (musl-gcc) | distribution package | `ring` compiles C; build the rescue CLI with `CC_x86_64_unknown_linux_musl=musl-gcc cargo build --target x86_64-unknown-linux-musl` |

`deny.toml` allows `ISC` for this graph only: `ring` is `Apache-2.0 AND ISC` and
its `untrusted` helper is `ISC`. Both are permissive and OSI-approved.

| `openssh-server` (`sshd`, `/usr/lib/openssh/sftp-server`) | distribution package | the S10 acceptance test starts a throwaway sshd on the loopback and kills it mid-transfer |

## Slice S11 daemon, polkit and CLI test dependencies

| Tool | Package | Used for |
|---|---|---|
| `dbus-daemon`, `/run/dbus/system_bus_socket` | dbus | the system bus polkitd serves |
| `polkitd`, `pkaction` | polkitd (124) | the real authorization decision; `pkaction --version` records the version |
| `systemd-socket-activate` | systemd | the `LISTEN_FDS` socket-activation acceptance test |
| `setpriv` (`--reuid`/`--regid`/`--clear-groups`) | util-linux | running the CLI as `nobody` without PAM |
| `groupadd` | passwd | the daemon creates `linuxreflect` on first start |
| `contrib/polkit/org.linuxreflect.policy` | this repository | installed into `/usr/share/polkit-1/actions` (see D-063) |

## IPC code generation (Slice S11)

| Crate / tool | Version | Notes |
|---|---|---|
| `tonic-prost` | 0.14.6 | tonic 0.14 split the prost codec out of `tonic`; the generated code needs this runtime half |
| `tonic-prost-build` | 0.14.6 | code generator for the same split |
| `tokio-stream` | 0.1.19 | `UnixListenerStream` for serving gRPC over a Unix socket |
| `protoc` (`protobuf-compiler`) | distribution package | required at build time by the generator; `apt-get install protobuf-compiler` |
