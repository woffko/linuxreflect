#!/bin/sh
# Source this helper; staging and publication run in a cleanup-scoped subshell.
# Each executable is published atomically on the destination filesystem. This
# is not a transaction spanning the entire release and never restarts services.
install_binaries() (
    set -eu
    source_dir=$1
    destination_dir=$2
    names='linuxreflect linuxreflect-daemon linuxreflect-gui linuxreflect-session linuxreflect-rescue'
    for name in $names; do
        test -f "$source_dir/$name" && test -x "$source_dir/$name" || {
            echo "missing or non-executable binary: $source_dir/$name" >&2
            exit 1
        }
    done
    stage=$(mktemp -d "$destination_dir/.linuxreflect-install.XXXXXX")
    trap 'rm -rf -- "$stage"' 0
    trap 'exit 1' HUP INT TERM
    for name in $names; do
        install -m 0755 "$source_dir/$name" "$stage/$name"
    done
    # All copies succeeded before replacing any installed executable. -T avoids
    # following a destination symlink to a directory as a directory operand.
    for name in $names; do
        mv -fT -- "$stage/$name" "$destination_dir/$name"
    done
)
