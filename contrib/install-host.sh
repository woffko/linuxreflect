#!/bin/sh
# Install LinuxReflect system-wide on a Linux host (spec §I daemon, §K S15 GUI).
#
# Installs the release binaries to /usr/local/bin, the polkit policy, the
# systemd socket-activated daemon, the per-user session notifier and a desktop
# entry. Run it from a checkout whose `target/release` binaries are built:
#
#   cargo build --release -p lr-cli -p lr-daemon -p lr-gui -p lr-session -p lr-rescue
#   sudo ./contrib/install-host.sh
#
# After it finishes, members of the `linuxreflect` group talk to the daemon;
# put the desktop users into that group (`usermod -aG linuxreflect <user>`) and
# have them log in again, then start the GUI from the menu or `linuxreflect-gui`.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BIN=${BIN:-"$HERE/../target/release"}

for file in \
    "$BIN/linuxreflect" \
    "$BIN/linuxreflect-daemon" \
    "$BIN/linuxreflect-gui" \
    "$BIN/linuxreflect-session" \
    "$BIN/linuxreflect-rescue" \
    "$HERE/polkit/org.linuxreflect.policy" \
    "$HERE/applications/linuxreflect.desktop" \
    "$HERE/systemd/linuxreflect-daemon.socket" \
    "$HERE/systemd/linuxreflect-daemon.service" \
    "$HERE/systemd/linuxreflect-session.service" \
    "$HERE/install-binaries.sh"
do
    if [ ! -f "$file" ]; then
        echo "missing $file (build the release binaries first)" >&2
        exit 1
    fi
done

for name in linuxreflect linuxreflect-daemon linuxreflect-gui linuxreflect-session linuxreflect-rescue
do
    if [ ! -x "$BIN/$name" ]; then
        echo "not executable: $BIN/$name (build the release binaries first)" >&2
        exit 1
    fi
done

install -d -m 0755 /usr/local/bin /usr/share/polkit-1/actions \
    /usr/share/applications /etc/systemd/system /usr/lib/systemd/user /usr/lib/tmpfiles.d

. "$HERE/install-binaries.sh"
install_binaries "$BIN" /usr/local/bin

groupadd -f linuxreflect

install -m 0644 "$HERE/polkit/org.linuxreflect.policy" \
    /usr/share/polkit-1/actions/org.linuxreflect.policy

install -m 0644 "$HERE/applications/linuxreflect.desktop" \
    /usr/share/applications/linuxreflect.desktop

install -m 0644 "$HERE/systemd/linuxreflect-daemon.socket" \
    /etc/systemd/system/linuxreflect-daemon.socket
install -m 0644 "$HERE/systemd/linuxreflect-daemon.service" \
    /etc/systemd/system/linuxreflect-daemon.service
install -m 0644 "$HERE/systemd/linuxreflect-session.service" \
    /usr/lib/systemd/user/linuxreflect-session.service

# The runtime directory must let the group reach the socket before the daemon
# first runs; the daemon also enforces this on every start.
echo 'd /run/linuxreflect 0750 root linuxreflect -' \
    > /usr/lib/tmpfiles.d/linuxreflect.conf
systemd-tmpfiles --create linuxreflect.conf

systemctl daemon-reload
systemctl enable --now linuxreflect-daemon.socket

echo "LinuxReflect installed."
if systemctl is-active --quiet linuxreflect-daemon.service; then
    echo "  The running daemon was preserved to avoid interrupting jobs."
    echo "  New binaries are installed; daemon activation is pending."
    echo "  Activate during a maintenance window after all jobs finish and clients/schedules are quiesced."
fi
echo "  CLI:        linuxreflect --help"
echo "  GUI:        linuxreflect-gui (or the menu entry)"
echo "  Daemon:     systemctl status linuxreflect-daemon.socket"
echo "  Notifications (per user): systemctl --user enable --now linuxreflect-session"
