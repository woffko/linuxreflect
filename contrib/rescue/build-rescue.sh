#!/bin/sh
# Build the assembled rescue image this repository verifies (spec §K S16).
#
# The image boots under SeaBIOS and under UEFI with Secure Boot: it carries the
# distribution's signed shim and GRUB, the distribution kernel, and a busybox
# initramfs with the static `linuxreflect` rescue CLI and the TUI. The graphical
# variant (cage + GUI) comes from `mkosi.conf` instead.
#
# Usage: contrib/rescue/build-rescue.sh <output.img> [kernel]
set -eu

REPO=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
OUT=${1:-"$REPO/target/rescue.img"}
KERNEL=${2:-"$(ls /boot/vmlinuz-* 2>/dev/null | tail -1)"}
CLI="$REPO/target/x86_64-unknown-linux-musl/release/linuxreflect.stripped"

if [ ! -x "$CLI" ]; then
    echo "building the static rescue CLI (release, stripped)…"
    ( cd "$REPO" && CC_x86_64_unknown_linux_musl=musl-gcc \
        cargo build -p lr-cli --release --target x86_64-unknown-linux-musl )
    cp "$REPO/target/x86_64-unknown-linux-musl/release/linuxreflect" "$CLI"
    strip "$CLI"
fi

exec "$REPO/target/debug/linuxreflect-rescue" build-media \
    --output "$OUT" --kernel "$KERNEL" --cli "$CLI" --size-mib 512
