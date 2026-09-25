#!/usr/bin/env python3
"""Capture the real GUI in a private X11 display; never perform device writes.

Captures alone are not backup/restore acceptance. Optional fixture assertions
check files created by physical input; they never invoke GUI callbacks or RPCs.
Run against freshly built binaries and inspect the resulting screenshot.
Only processes owned by this invocation are terminated during cleanup.
"""

import argparse
import hashlib
import os
from pathlib import Path
import re
import select
import shutil
import signal
import subprocess
import tempfile
import time


def run(argv, env):
    return subprocess.run(argv, env=env, check=True, capture_output=True, text=True, timeout=3)


def fingerprint(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def same_bytes(left, right):
    with left.open("rb") as a, right.open("rb") as b:
        while True:
            block = a.read(65536)
            if block != b.read(65536):
                return False
            if not block:
                return True


def capture(window, output, capture_format, env):
    if output.exists():
        raise RuntimeError(f"Refusing to overwrite an existing screenshot: {output}")
    geometry = run(["xdotool", "getwindowgeometry", "--shell", window], env).stdout
    print(geometry)
    fields = dict(line.split("=", 1) for line in geometry.splitlines() if "=" in line)
    rectangle = ",".join(str(int(fields[key])) for key in ["X", "Y", "WIDTH", "HEIGHT"])
    if capture_format == "png":
        run(["scrot", "-a", rectangle, str(output)], env)
    else:
        run(["xwd", "-root", "-silent", "-out", str(output)], env)
    print(f"Screenshot: {output}", flush=True)


def resize(window, width, height, env):
    geometry = run(["xdotool", "getwindowgeometry", "--shell", window], env).stdout
    fields = dict(line.split("=", 1) for line in geometry.splitlines() if "=" in line)
    if (int(fields["WIDTH"]), int(fields["HEIGHT"])) == (width, height):
        print(f"Geometry confirmed without resize: {width}x{height}", flush=True)
        return
    run(["xdotool", "windowsize", window, str(width), str(height)], env)
    time.sleep(0.2)
    geometry = run(["xdotool", "getwindowgeometry", "--shell", window], env).stdout
    fields = dict(line.split("=", 1) for line in geometry.splitlines() if "=" in line)
    actual = int(fields["WIDTH"]), int(fields["HEIGHT"])
    if actual != (width, height):
        raise RuntimeError(f"Requested {width}x{height}; window reports {actual}")
    print(f"Resize confirmed: {width}x{height}", flush=True)


def focus_input(window, env, wayland):
    target = window
    if not wayland:
        # This display is private to the test. Portal chooser titles are set
        # by the app; never focus an unrelated desktop window by title.
        dialogs = subprocess.run(
            ["xdotool", "search", "--onlyvisible", "--name", "^Choose "],
            env=env, capture_output=True, text=True, timeout=2,
        )
        if dialogs.returncode not in (0, 1):
            raise RuntimeError("Could not discover the native input dialog")
        candidates = set(dialogs.stdout.split()) - {window}
        if len(candidates) > 1:
            raise RuntimeError("More than one visible chooser; keyboard target is ambiguous")
        if candidates:
            target = candidates.pop()
    run(["xdotool", "windowfocus", target], env)
    print("Keyboard target: " + ("native chooser" if target != window else "app/compositor"), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--width", type=int, default=1024)
    parser.add_argument("--height", type=int, default=768)
    parser.add_argument("--scale", choices=["1", "1.5", "2"], default="1")
    parser.add_argument("--final-size", choices=["1024x768", "1280x720", "1920x1080"],
                        help="Resize after all clicks, before scrolling and keyboard input")
    parser.add_argument("--capture-before-keys", action="store_true",
                         help="Capture the scrolled page before final clicks and keyboard input")
    parser.add_argument("--click-after-scroll", action="append", default=[],
                         help="Window-relative X,Y after final resize/scroll; at most four clicks")
    parser.add_argument("--scroll-after-final-clicks", action="append", default=[],
                         help="Window-relative X,Y,TICKS after final clicks, before keyboard input")
    parser.add_argument("--resize-cycle", action="store_true",
                         help="Enlarge and shrink the same window twice before capturing")
    parser.add_argument("--portal", action="store_true",
                         help="Use an isolated session bus and fixture home for native dialogs")
    parser.add_argument("--wayland", action="store_true",
                         help="Run native Wayland clients in private nested Weston; input enters its X11 output")
    parser.add_argument("--wayland-shell", choices=["desktop", "kiosk"], default="desktop",
                         help="Nested Weston shell; kiosk makes clients fullscreen")
    parser.add_argument("--wayland-debugger", action="store_true",
                         help="Run the owned compositor under batch GDB for a crash backtrace")
    parser.add_argument("--key-after-click", action="append", default=[],
                         help="N,KEY: physical Return, Escape, Tab, Down or Up after a click")
    parser.add_argument("--passphrase-fixture", action="store_true",
                         help="Create a private random passphrase file for physical picker tests")
    parser.add_argument("--bulk-fixture-mib", type=int, choices=[0, 512, 1024], default=0,
                         help="Add allocated test-only source data for physical cancellation")
    parser.add_argument("--fast-after-click", type=int, action="append", default=[],
                         help="Wait only 50 ms after this click, for cancelling a live job")
    parser.add_argument("--click", action="append", default=[], help="Window-relative X,Y; may be repeated")
    parser.add_argument("--double-click", type=int, action="append", default=[],
                        help="Send a physical double click at this existing click number")
    parser.add_argument("--scroll", action="append", default=[],
                        help="Window-relative X,Y,TICKS; positive scrolls down, after clicks")
    parser.add_argument("--key", action="append", default=[],
                        choices=["Tab", "shift+Tab", "Return", "space", "Escape", "Down", "Up"],
                        help="Physical key input after clicks and scrolling")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--binaries", type=Path,
                        help="Directory containing the reviewed GUI and daemon binaries")
    parser.add_argument("--capture-format", choices=["png", "xwd"], default="png",
                        help="PNG window area via scrot, or the whole private screen via xwd")
    parser.add_argument("--expect-fixture-backup", action="store_true",
                         help="Assert physical clicks created an image in the private Backups fixture")
    parser.add_argument("--expect-encrypted-backup", action="store_true",
                         help="Also require the produced images' format-v1 encrypted header flag")
    parser.add_argument("--expect-fixture-restore", action="store_true",
                        help="Assert restored fixture files match the original bytes and file set")
    parser.add_argument("--assert-fixture-empty-after-click", type=int,
                        help="Assert no destination writes after the numbered physical click (1-based)")
    parser.add_argument("--capture-after-click", type=int, action="append", default=[],
                         help="Also capture after this click, with a -click-N suffix; repeatable")
    parser.add_argument("--settle-after-click", action="append", default=[],
                         help="N,SECONDS: bounded extra settling time after a physical click")
    parser.add_argument("--layout-after-click", type=int, action="append", default=[],
                        help="Capture all three required sizes at this populated step, then restore the original size")
    args = parser.parse_args()
    if not 640 <= args.width <= 3840 or not 480 <= args.height <= 2160:
        parser.error("Screenshot dimensions are outside the bounded test range")
    clicks = []
    for value in args.click:
        x, y = map(int, value.split(","))
        if not 0 <= x < args.width or not 0 <= y < args.height:
            parser.error("Click must be inside the requested window")
        clicks.append((x, y))
    if len(clicks) > 32:
        parser.error("At most thirty-two clicks per inspection")
    if any(not 1 <= number <= len(clicks) for number in args.double_click):
        parser.error("Double click requires an existing click number")
    if any(not 1 <= number <= len(clicks) for number in args.fast_after_click):
        parser.error("Fast input requires an existing click number")
    settle_after_click = {}
    for value in args.settle_after_click:
        number, seconds = map(int, value.split(","))
        if not 1 <= number <= len(clicks) or not 1 <= seconds <= 10 or number in settle_after_click:
            parser.error("Settling requires a unique existing click and one to ten seconds")
        settle_after_click[number] = seconds
    if sum(settle_after_click.values()) > 30:
        parser.error("At most thirty seconds of extra settling per inspection")
    keys_after_click = {}
    for value in args.key_after_click:
        number_text, key = value.split(",")
        number = int(number_text)
        if not 1 <= number <= len(clicks) or key not in ["Return", "Escape", "Tab", "Down", "Up"]:
            parser.error("Intermediate key requires an existing click and an allowed key")
        keys_after_click.setdefault(number, []).append(key)
    if len(args.key_after_click) + len(args.key) > 20:
        parser.error("At most twenty key presses per inspection")
    if any(not 1 <= number <= len(clicks) for number in args.capture_after_click):
        parser.error("Intermediate capture requires an existing click number")
    if len(args.layout_after_click) > 8 or any(
        not 1 <= number <= len(clicks) for number in args.layout_after_click
    ):
        parser.error("Layout inspection requires up to eight existing click numbers")
    if (args.expect_fixture_backup or args.expect_fixture_restore) and not args.portal:
        parser.error("Fixture backup assertions require --portal")
    if args.passphrase_fixture and not args.portal:
        parser.error("The passphrase fixture requires --portal")
    if args.bulk_fixture_mib and not args.portal:
        parser.error("Bulk test data requires --portal")
    if args.wayland and not args.portal:
        parser.error("Nested Wayland requires --portal for a private runtime and session bus")
    if args.wayland_debugger and (not args.wayland or shutil.which("gdb") is None):
        parser.error("Compositor debugging requires --wayland and GDB")
    if args.expect_encrypted_backup and not (args.expect_fixture_backup or args.expect_fixture_restore):
        parser.error("Encrypted header assertions require a fixture backup or restore assertion")
    if args.assert_fixture_empty_after_click is not None and (
        not args.portal or not 1 <= args.assert_fixture_empty_after_click <= len(clicks)
    ):
        parser.error("Destination assertion requires --portal and an existing click number")
    scrolls = []
    scroll_width, scroll_height = (map(int, args.final_size.split("x"))
                                   if args.final_size else (args.width, args.height))
    final_clicks = []
    for value in args.click_after_scroll:
        x, y = map(int, value.split(","))
        if not 0 <= x < scroll_width or not 0 <= y < scroll_height:
            parser.error("Final click must be inside the final window")
        final_clicks.append((x, y))
    if len(final_clicks) > 4:
        parser.error("At most four final clicks per inspection")
    final_scrolls = []
    for values, destination in [(args.scroll, scrolls),
                                (args.scroll_after_final_clicks, final_scrolls)]:
        for value in values:
            x, y, ticks = map(int, value.split(","))
            if not 0 <= x < scroll_width or not 0 <= y < scroll_height or not 1 <= abs(ticks) <= 10:
                parser.error("Scroll must be inside the window with one to ten ticks")
            destination.append((x, y, ticks))
    if len(scrolls) + len(final_scrolls) > 10 or len(args.key) > 20:
        parser.error("At most ten scroll actions and twenty key presses per inspection")
    for name in ["Xvfb", "xdotool", "scrot" if args.capture_format == "png" else "xwd"]:
        if shutil.which(name) is None:
            parser.error(f"Required tool is missing: {name}")
    if args.portal and shutil.which("dbus-daemon") is None:
        parser.error("Native dialog inspection requires dbus-daemon and installed desktop portals")
    if args.wayland and shutil.which("weston") is None:
        parser.error("Nested Wayland inspection requires Weston with its X11 backend and desktop shell")
    project = Path(__file__).resolve().parents[1]
    binaries = args.binaries.resolve() if args.binaries else project / "target/debug"
    for name in ["linuxreflect-gui", "linuxreflect-daemon"]:
        if not (binaries / name).is_file():
            parser.error(f"Build {name} first")
    identities = {name: fingerprint(binaries / name)
                  for name in ["linuxreflect-gui", "linuxreflect-daemon"]}
    for name, digest in identities.items():
        print(f"SHA256 {name}: {digest}", flush=True)
    output = args.output.resolve()
    if not output.parent.is_dir():
        parser.error("The screenshot parent directory must already exist")
    if output.exists():
        parser.error("Refusing to overwrite an existing screenshot")
    before_keys_output = output.with_name(f"{output.stem}-before-keys{output.suffix}")
    if args.capture_before_keys and before_keys_output.exists():
        parser.error("Refusing to overwrite an existing pre-keyboard screenshot")
    intermediate_outputs = {
        number: output.with_name(f"{output.stem}-click-{number}{output.suffix}")
        for number in args.capture_after_click
    }
    if any(path.exists() for path in intermediate_outputs.values()):
        parser.error("Refusing to overwrite an existing intermediate screenshot")
    layout_outputs = {
        number: [(width, height, output.with_name(
            f"{output.stem}-click-{number}-{width}x{height}{output.suffix}"))
            for width, height in [(1024, 768), (1280, 720), (1920, 1080)]]
        for number in args.layout_after_click
    }
    if any(path.exists() for cases in layout_outputs.values() for _, _, path in cases):
        parser.error("Refusing to overwrite an existing layout screenshot")

    children = []
    compositor_group = None
    with tempfile.TemporaryDirectory(prefix="linuxreflect-visual-") as directory, tempfile.TemporaryFile(mode="w+") as display_log:
        temporary = Path(directory)
        try:
            # Xvfb allocates a free display and reports it through this pipe.
            read_fd, write_fd = os.pipe()
            try:
                xvfb = subprocess.Popen(
                    ["Xvfb", "-displayfd", str(write_fd), "-screen", "0",
                     f"{max(args.width, 1920)}x{max(args.height, 1080)}x24", "-nolisten", "tcp", "-nolisten", "unix",
                     "-noreset"],
                    pass_fds=(write_fd,), stdout=subprocess.DEVNULL, stderr=display_log,
                )
                children.append(xvfb)
                os.close(write_fd)
                write_fd = None
                if not select.select([read_fd], [], [], 5)[0]:
                    raise RuntimeError("Xvfb did not announce a display")
                display = os.read(read_fd, 32).decode("ascii").strip()
                if not display.isdigit():
                    display_log.seek(0)
                    raise RuntimeError(f"Invalid Xvfb display number {display!r}: {display_log.read(8192)}")
                print(f"Private Xvfb display: :{display}", flush=True)
            finally:
                os.close(read_fd)
                if write_fd is not None:
                    os.close(write_fd)

            env = dict(os.environ, DISPLAY=f":{display}", SLINT_BACKEND="winit-software",
                       SLINT_SCALE_FACTOR=args.scale)
            env.pop("WAYLAND_DISPLAY", None)
            if args.portal:
                home = temporary / "home"
                home.mkdir(mode=0o700)
                for name in ["01 Source", "02 Backups", "03 Restore"]:
                    (home / name).mkdir(mode=0o700)
                if args.passphrase_fixture:
                    # Keep secret bytes out of argv, automation text and output.
                    # The private fixture is removed after the owned GUI/daemon exit.
                    descriptor = os.open(home / "04 Passphrase", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(descriptor, "wb") as passphrase:
                        passphrase.write(os.urandom(32).hex().encode("ascii"))
                        passphrase.flush()
                        os.fsync(passphrase.fileno())
                (home / "01 Source" / "hello.txt").write_text("LinuxReflect mouse test fixture\n")
                (home / "01 Source" / "nested").mkdir(mode=0o700)
                (home / "01 Source" / "nested" / "data.bin").write_bytes(bytes(range(256)) * 1200)
                bulk_hash = None
                if args.bulk_fixture_mib:
                    digest = hashlib.sha256()
                    block = os.urandom(1024 * 1024)
                    with (home / "01 Source" / "bulk.bin").open("xb") as bulk:
                        for _ in range(args.bulk_fixture_mib):
                            bulk.write(block)
                            digest.update(block)
                    bulk_hash = digest.hexdigest()
                runtime = temporary / "runtime"
                runtime.mkdir(mode=0o700)
                env.update(HOME=str(home), XDG_RUNTIME_DIR=str(runtime), XDG_CURRENT_DESKTOP="XFCE",
                           XDG_CONFIG_HOME=str(home / ".config"), XDG_DATA_HOME=str(home / ".local/share"),
                           XDG_CACHE_HOME=str(home / ".cache"), GIO_USE_VFS="local")
                if args.wayland:
                    wayland_socket = "linuxreflect-visual-wayland"
                    compositor_command = ["weston", "--backend=x11-backend.so", f"--shell={args.wayland_shell}-shell.so",
                         "--no-config", "--use-pixman", "--idle-time=0",
                         f"--socket={wayland_socket}", f"--width={args.width}",
                         f"--height={args.height}"]
                    if args.wayland_debugger:
                        compositor_command = ["gdb", "--batch", "--return-child-result",
                                              "-ex", "run", "-ex", "thread apply all bt", "--args"] + compositor_command
                    weston = subprocess.Popen(
                        compositor_command,
                        env=env,
                        stdout=display_log, stderr=subprocess.STDOUT,
                        start_new_session=args.wayland_debugger,
                    )
                    children.append(weston)
                    if args.wayland_debugger:
                        compositor_group = weston.pid
                    deadline = time.monotonic() + 5
                    while not (runtime / wayland_socket).exists():
                        if weston.poll() is not None or time.monotonic() > deadline:
                            raise RuntimeError("Private nested Weston failed to become ready")
                        time.sleep(0.05)
                    env.update(WAYLAND_DISPLAY=wayland_socket, GDK_BACKEND="wayland",
                               WINIT_UNIX_BACKEND="wayland")
                # This scenario uses local fixtures only. Prevent GTK's GIO
                # backend from activating a GVfs FUSE mount in the temporary
                # runtime directory that outlives the private session bus.
                env.pop("DBUS_SESSION_BUS_ADDRESS", None)
                bus_env = dict(env)
                if args.wayland:
                    bus_env.pop("DISPLAY", None)
                bus = subprocess.Popen(
                    ["dbus-daemon", "--session", "--nofork", "--print-address=1"],
                    env=bus_env, stdout=subprocess.PIPE, stderr=display_log,
                )
                children.append(bus)
                if not select.select([bus.stdout], [], [], 5)[0]:
                    raise RuntimeError("Private session bus did not announce an address")
                address = bus.stdout.readline(4096).decode("utf-8").strip()
                if not address.startswith("unix:"):
                    raise RuntimeError("Private session bus returned an invalid address")
                env["DBUS_SESSION_BUS_ADDRESS"] = address
                print("Native dialogs use a private session bus and fixture home", flush=True)
            socket = temporary / "daemon.sock"
            with (temporary / "daemon.log").open("w") as daemon_log, (temporary / "gui.log").open("w") as gui_log:
                daemon = subprocess.Popen(
                    [str(binaries / "linuxreflect-daemon"), "--socket", str(socket),
                     "--socket-group", "lr-gui-test", "--no-create-group", "--dev-mode",
                     "--auth", "static:all", "--sd-notify=no", "--token-secret-file",
                     str(temporary / "token.key")],
                    env=env, stdout=daemon_log, stderr=subprocess.STDOUT,
                )
                children.append(daemon)
                deadline = time.monotonic() + 5
                while not socket.exists():
                    if daemon.poll() is not None or time.monotonic() > deadline:
                        diagnostic = (temporary / "daemon.log").read_text(errors="replace")[-8192:]
                        raise RuntimeError(f"Private test daemon failed to become ready: {diagnostic}")
                    time.sleep(0.05)
                gui_env = dict(env)
                if args.wayland:
                    gui_env.pop("DISPLAY", None)
                    print("GUI and portal activation use native Wayland without DISPLAY; input targets nested Weston", flush=True)
                gui = subprocess.Popen(
                    [str(binaries / "linuxreflect-gui"), "--socket", str(socket)],
                    env=gui_env, cwd=home if args.portal else project,
                    stdout=gui_log, stderr=subprocess.STDOUT,
                )
                children.append(gui)
                deadline = time.monotonic() + 5
                while True:
                    if args.wayland:
                        # Weston 9 does not publish _NET_WM_PID on its output.
                        # Read only this invocation's compositor announcement.
                        display_log.seek(0)
                        announcement = re.search(r"x11 output \d+x\d+, window id (\d+)", display_log.read())
                        if announcement:
                            window = announcement.group(1)
                            break
                    found = subprocess.run(
                        ["xdotool", "search", "--onlyvisible", "--pid", str(weston.pid if args.wayland else gui.pid)],
                        env=env, capture_output=True, text=True, timeout=2,
                    )
                    windows = found.stdout.split()
                    if found.returncode == 0 and windows:
                        window = windows[0]
                        break
                    if gui.poll() is not None or time.monotonic() > deadline:
                        diagnostic = (temporary / "gui.log").read_text(errors="replace")[-8192:]
                        display_log.seek(0)
                        server_diagnostic = display_log.read(8192)
                        raise RuntimeError(f"GUI did not map a visible window (exit={gui.poll()}): {diagnostic}\nXvfb: {server_diagnostic}")
                    time.sleep(0.05)
                if args.wayland:
                    # The compositor output can map before its Wayland client.
                    # Screenshots and fixture assertions establish client readiness.
                    time.sleep(1)
                    if gui.poll() is not None:
                        diagnostic = (temporary / "gui.log").read_text(errors="replace")[-8192:]
                        raise RuntimeError(f"Native Wayland GUI exited before input: {diagnostic}")
                sizes = [(args.width, args.height)]
                if args.resize_cycle:
                    sizes.extend([(1920, 1080), (args.width, args.height)] * 2)
                for width, height in sizes:
                    resize(window, width, height, env)
                for click_number, (x, y) in enumerate(clicks, 1):
                    click_args = ["--repeat", "2", "--delay", "100"] if click_number in args.double_click else []
                    run(["xdotool", "mousemove", "--window", window, str(x), str(y), "click", *click_args, "1"], env)
                    time.sleep(0.05 if click_number in args.fast_after_click else (1.5 if args.portal else 0.3))
                    if click_number in settle_after_click:
                        time.sleep(settle_after_click[click_number])
                    if click_number in keys_after_click:
                        for key in keys_after_click[click_number]:
                            focus_input(window, env, args.wayland)
                            run(["xdotool", "key", key], env)
                            time.sleep(0.2)
                        time.sleep(1.5 if args.portal else 0.3)
                    if args.portal and not args.wayland:
                        # Xvfb has no window manager to place a transient dialog.
                        # Keep the real portal window on-screen for inspection.
                        dialogs = subprocess.run(
                            ["xdotool", "search", "--onlyvisible", "--name", "^Choose "],
                            env=env, capture_output=True, text=True, timeout=2,
                        )
                        for dialog in dialogs.stdout.split():
                            if dialog != window:
                                run(["xdotool", "windowmove", dialog, "0", "0"], env)
                    if click_number == args.assert_fixture_empty_after_click:
                        if any((home / "03 Restore").iterdir()):
                            raise RuntimeError("Destination was written before confirmation")
                        print(f"Destination unchanged after physical click {click_number}", flush=True)
                    if click_number in intermediate_outputs:
                        capture(window, intermediate_outputs[click_number], args.capture_format, env)
                    if click_number in layout_outputs:
                        for width, height, path in layout_outputs[click_number]:
                            resize(window, width, height, env)
                            capture(window, path, args.capture_format, env)
                        resize(window, args.width, args.height, env)
                if args.final_size:
                    resize(window, scroll_width, scroll_height, env)
                for x, y, ticks in scrolls:
                    run(["xdotool", "mousemove", "--window", window, str(x), str(y),
                         "click", "--repeat", str(abs(ticks)), "5" if ticks > 0 else "4"], env)
                    time.sleep(0.2)
                if args.capture_before_keys:
                    capture(window, before_keys_output, args.capture_format, env)
                for x, y in final_clicks:
                    run(["xdotool", "mousemove", "--window", window, str(x), str(y), "click", "1"], env)
                    time.sleep(1.5 if args.portal else 0.3)
                for x, y, ticks in final_scrolls:
                    run(["xdotool", "mousemove", "--window", window, str(x), str(y),
                         "click", "--repeat", str(abs(ticks)), "5" if ticks > 0 else "4"], env)
                    time.sleep(0.2)
                if args.key:
                    for key in args.key:
                        focus_input(window, env, args.wayland)
                        run(["xdotool", "key", key], env)
                        time.sleep(0.2)
                    time.sleep(1.5 if args.portal else 0.2)
                capture(window, output, args.capture_format, env)
                for name, digest in identities.items():
                    if fingerprint(binaries / name) != digest:
                        raise RuntimeError(f"{name} changed during the visual test")
                if args.bulk_fixture_mib:
                    bulk = home / "01 Source" / "bulk.bin"
                    if bulk.stat().st_size != args.bulk_fixture_mib * 1024 * 1024 or fingerprint(bulk) != bulk_hash:
                        raise RuntimeError("Bulk source fixture was modified")
                    print(f"Bulk source unchanged: {args.bulk_fixture_mib} MiB", flush=True)
                if args.expect_fixture_backup or args.expect_fixture_restore:
                    images = list((home / "02 Backups").rglob("*.lrimg"))
                    if not images or any(path.stat().st_size == 0 for path in images):
                        raise RuntimeError("No completed backup image in the private fixture")
                    if args.expect_encrypted_backup:
                        for image in images:
                            with image.open("rb") as stream:
                                header = stream.read(24)
                            # Format v1 superblock: magic [0:8], flags u64 LE [16:24],
                            # ENCRYPTED bit 0 (lr-format/src/sb.rs; spec section G.3).
                            if (len(header) != 24 or header[:8] != b"LRIMG\x01\x00\x00"
                                    or int.from_bytes(header[8:12], "little") != 1
                                    or not int.from_bytes(header[16:24], "little") & 1):
                                raise RuntimeError("Expected a format-v1 encrypted backup image")
                        print("Produced image headers have the encrypted flag", flush=True)
                    if (home / "01 Source" / "hello.txt").read_text() != "LinuxReflect mouse test fixture\n":
                        raise RuntimeError("Source fixture was modified")
                    if (home / "01 Source" / "nested/data.bin").read_bytes() != bytes(range(256)) * 1200:
                        raise RuntimeError("Binary source fixture was modified")
                    print(f"Physical backup created {len(images)} nonempty image(s); source unchanged")
                if args.expect_fixture_restore:
                    source_files = {path.relative_to(home / "01 Source")
                                    for path in (home / "01 Source").rglob("*") if path.is_file()}
                    restored_files = {path.relative_to(home / "03 Restore")
                                      for path in (home / "03 Restore").rglob("*") if path.is_file()}
                    if source_files != restored_files:
                        raise RuntimeError("Restored file set differs from the source fixture")
                    for relative in source_files:
                        if not same_bytes(home / "01 Source" / relative, home / "03 Restore" / relative):
                            raise RuntimeError(f"Restored bytes differ for {relative}")
                    print(f"Physical restore matched all {len(source_files)} fixture files byte for byte")
        except Exception:
            if args.wayland:
                print(f"Nested Weston exit status: {weston.poll() if 'weston' in locals() else 'not started'}", flush=True)
                display_log.seek(0)
                print("Nested compositor/session diagnostics:\n" + display_log.read()[-8192:], flush=True)
            raise
        finally:
            if compositor_group is not None:
                # Only the fresh session created above, including GDB's inferior.
                try:
                    os.killpg(compositor_group, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            for child in reversed(children):
                if child.poll() is None:
                    child.terminate()
                try:
                    child.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=2)


if __name__ == "__main__":
    main()
