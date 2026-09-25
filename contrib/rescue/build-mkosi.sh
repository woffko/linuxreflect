#!/bin/sh
# Build the graphical rescue medium with mkosi (spec §K S16).
#
# The output is a GPT disk image with a FAT ESP, the distribution-signed
# shim + GRUB chain, the distro kernel and a custom initramfs carrying the
# static `linuxreflect` rescue CLI. It boots on SeaBIOS and on OVMF with
# Secure Boot. See docs/decisions.md D-101.
#
# mkosi >= 25 needs Python >= 3.11 and systemd >= 254. WSL cannot run it
# because mkosi's build sandbox cannot resolve DNS there, so this script runs
# mkosi inside a privileged Ubuntu 24.04 container when Docker is available
# and otherwise runs it on the current host.
#
# The static CLI is taken from LINUXREFLECT_CLI (defaults to the stripped musl
# release build) and staged into `mkosi.extra/`.
#
# Usage: LINUXREFLECT_CLI=/path/to/linuxreflect contrib/rescue/build-mkosi.sh [out]
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT=${1:-"$HERE/rescue-out"}
CONF="$HERE/mkosi.conf"
EXTRA="$HERE/mkosi.extra"
REPO=$(CDPATH= cd -- "$HERE/../.." && pwd)
CLI=${LINUXREFLECT_CLI:-"$REPO/target/x86_64-unknown-linux-musl/release/linuxreflect.stripped"}

if [ ! -f "$CONF" ]; then
    echo "mkosi.conf not found next to this script" >&2
    exit 1
fi
if [ ! -x "$CLI" ]; then
    echo "static CLI not found at $CLI (set LINUXREFLECT_CLI)" >&2
    exit 1
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cp "$CONF" "$WORK/mkosi.conf"
cp -a "$EXTRA" "$WORK/mkosi.extra"
install -D -m 0755 "$CLI" "$WORK/mkosi.extra/usr/local/bin/linuxreflect"
chmod 0755 "$WORK/mkosi.extra/usr/local/bin/linuxreflect-rescue" \
           "$WORK/mkosi.extra/usr/local/bin/linuxreflect-rescue-tui"
mkdir -p "$WORK/mkosi.extra/etc/systemd/system/multi-user.target.wants"
ln -sf ../linuxreflect-rescue.service \
    "$WORK/mkosi.extra/etc/systemd/system/multi-user.target.wants/linuxreflect-rescue.service"
# Our session owns tty1.
ln -sf /dev/null "$WORK/mkosi.extra/etc/systemd/system/getty@tty1.service"
mkdir -p "$OUT" "$WORK/cache"

container='export DEBIAN_FRONTEND=noninteractive
sed -i "s/^Components: .*/Components: main restricted universe multiverse/" /etc/apt/sources.list.d/ubuntu.sources 2>/dev/null || true
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
  python3 python3-pefile git ca-certificates systemd systemd-container \
  debian-archive-keyring gnupg zstd mtools dosfstools e2fsprogs xfsprogs \
  btrfs-progs qemu-utils bubblewrap cpio gzip xz-utils squashfs-tools \
  u-boot-tools grub-common grub-pc-bin grub-efi-amd64-bin
if [ ! -d /opt/mkosi ]; then
  git clone --depth 1 https://github.com/systemd/mkosi /opt/mkosi
fi
/opt/mkosi/bin/mkosi build
ls -l rescue-out/'

if command -v docker >/dev/null 2>&1; then
    docker run --rm --privileged \
        -v "$WORK":/work -v "$WORK/cache":/var/cache/mkosi -w /work \
        ubuntu:24.04 bash -lc "$container"
    cp -a "$WORK/rescue-out/." "$OUT/"
else
    ( cd "$WORK" && ./bin/mkosi build )
    cp -a "$WORK/rescue-out/." "$OUT/"
fi

echo "rescue medium written to $OUT"
