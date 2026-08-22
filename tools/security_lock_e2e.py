#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Core Devices LLC
# SPDX-License-Identifier: Apache-2.0

"""End-to-end tests for the security lock, driven against a running QEMU.

Drives the real UI -- buttons over the QEMU monitor, taps through the touch
device -- and asserts on the watch's own state via the `security status`
console command rather than on what a screenshot looks like. Screenshots are
still captured for every step so a human can see what happened, but no test
passes or fails on a pixel.

Standing in for Gadgetbridge where the phone is involved: the QEMU comm channel
carries real Pebble Protocol frames to the security endpoint, so the firmware
cannot tell the difference.

    ./pbl qemu &
    python3 tools/security_lock_e2e.py
    python3 tools/security_lock_e2e.py --only lock_and_unlock -v

Adjusting when the UI moves: menu positions live in ROWS and the keypad
geometry in PadGeometry.for_screen(). Those are the only places that need
touching if screen ordering or layout changes.
"""

import argparse
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MON_SOCK = os.path.join(REPO, "build", "qemu-mon.sock")
CONSOLE_PORT = 12345
PEBBLE_PORT = 12344

# --- Things to adjust when the UI changes -----------------------------------

#: Row index of each Security menu entry. Rows that only exist once a PIN is
#: set are marked; see SECURITY_ROWS_WITH_PIN.
SECURITY_ROWS_NO_PIN = ["Set PIN", "PIN Length"]
SECURITY_ROWS_WITH_PIN = ["Change PIN", "PIN Length", "Duress PIN", "Clear PIN", "Lock Now"]

#: Downs needed from the top of the Settings menu to reach Security.
SETTINGS_TO_SECURITY = 10


class PadGeometry:
    """Where the 3x3 keypad's keys are, mirroring prv_geometry() in
    src/fw/popups/security/pin_entry_window.c."""

    GAP = 3

    def __init__(self, w, h, round_display=False):
        margin_x = w // 6 if round_display else 6
        top = h // 6 if round_display else 6
        bottom = h - (h // 6 if round_display else 4)
        bar_h, text_h = 10, 34  # BAR_H, TEXT_H

        self.x = margin_x
        self.w = w - 2 * margin_x
        grid_top = top + bar_h + 2 + text_h
        grid_h = bottom - grid_top
        self.key_w = (self.w - 2 * self.GAP) // 3
        self.key_h = (grid_h - 2 * self.GAP) // 3
        self.grid_top = grid_top

    def centre(self, digit):
        """Screen coordinates of the centre of key `digit` (1-9)."""
        idx = digit - 1
        col, row = idx % 3, idx // 3
        x = self.x + col * (self.key_w + self.GAP) + self.key_w // 2
        y = self.grid_top + row * (self.key_h + self.GAP) + self.key_h // 2
        return x, y


# --- Driving the watch ------------------------------------------------------

VERBOSE = False


def log(msg):
    if VERBOSE:
        print(f"      {msg}")


def monitor(cmd):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(MON_SOCK)
        s.settimeout(3.0)
        time.sleep(0.15)
        s.sendall((cmd + "\n").encode())
        time.sleep(0.25)
        try:
            return s.recv(65536).decode(errors="replace")
        except socket.timeout:
            return ""


def press(*buttons, settle=0.12):
    """back|select|up|down, using the QEMU key names."""
    names = {"back": "left", "select": "right", "up": "up", "down": "down"}
    for b in buttons:
        monitor("sendkey " + names.get(b, b))
        time.sleep(settle)


def tap(x, y, settle=0.2):
    subprocess.run([sys.executable, "./pbl", "touch", str(x), str(y)],
                   cwd=REPO, capture_output=True)
    time.sleep(settle)


def type_pin(pad, digits, settle=0.2):
    for ch in digits:
        x, y = pad.centre(int(ch))
        log(f"tap {ch} at ({x},{y})")
        tap(x, y, settle)


def screenshot(name):
    path = f"/tmp/seclock-e2e-{name}.png"
    subprocess.run([sys.executable, "./pbl", "screenshot", "--screenshot-output", path],
                   cwd=REPO, capture_output=True)
    return path if os.path.exists(path) else None


class Console:
    """The firmware prompt and log stream, over PULSE on the QEMU serial port.

    One interface for both: PULSE allows a single connection, so a separate
    log-capture process would fight this one for it. Tests assert on the
    watch's own log lines as well as on `security status`, which is the only
    way to see inside things that leave no state behind -- a shred that ran,
    a message that was rejected.

    Raises the log level on connect, because the security lock logs its
    lifecycle at DEBUG and the default level swallows all of it.
    """

    def __init__(self):
        sys.path.insert(0, os.path.join(REPO, "tools"))
        sys.path.insert(0, os.path.join(REPO, "tools", "libs"))
        from pebble import pulse2, commander  # noqa: E402
        from log_hashing.logdehash import LogDehash  # noqa: E402

        self._commander = commander
        self.iface = pulse2.Interface.open_dbgserial(f"socket://localhost:{CONSOLE_PORT}")
        self._dehasher = LogDehash(os.path.join(REPO, "build", "src", "fw", "loghash_dict.json"))
        self.lines = []
        self._lock = threading.Lock()
        self._pump = threading.Thread(target=self._pump_logs, daemon=True)
        self._pump.start()
        self._await_link()
        self.command("log level set 200")   # DEBUG

    def _await_link(self, timeout=60.0):
        """PULSE takes a moment to negotiate, and longer if the watch is busy
        wiping. Without this the first command dies on a None link."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.iface.get_link() is not None:
                return True
            time.sleep(1.0)
        return False

    def _pump_logs(self):
        logs = self._commander.apps.StreamingLogs(self.iface)
        while True:
            try:
                msg = logs.receive(block=True)
            except Exception:
                return
            try:
                text = self._dehasher.commander_format_line(self._dehasher.dehash(msg))
            except Exception:
                text = repr(msg)
            with self._lock:
                self.lines.append(text)

    def command(self, cmd):
        link = self.iface.get_link()
        if link is None:
            self._await_link(timeout=10.0)
            link = self.iface.get_link()
            if link is None:
                return []
        prompt = self._commander.apps.Prompt(link)
        try:
            return list(prompt.command_and_response(cmd))
        except Exception:
            return []
        finally:
            try:
                prompt.close()
            except Exception:
                pass

    def status(self):
        """Parse `security status` into a dict, retrying while the watch is busy."""
        for _ in range(6):
            for line in self.command("security status"):
                fields = dict(re.findall(r"(\w+)=(-?\d+)", line))
                if "state" in fields:
                    return {k: int(v) for k, v in fields.items()}
            time.sleep(2.0)
        raise RuntimeError("watch did not answer `security status`")

    def mark(self):
        """Remember where the log is now, so a test can look only at what follows."""
        with self._lock:
            return len(self.lines)

    def since(self, marker):
        with self._lock:
            return list(self.lines[marker:])

    def saw(self, marker, needle):
        return any(needle in line for line in self.since(marker))

    def close(self):
        try:
            self.iface.close()
        except Exception:
            pass


class Phone:
    """Stands in for Gadgetbridge on the QEMU comm channel."""

    HDR, FTR = 0xFEED, 0xBEEF
    SPP, BT_CONN = 1, 3
    ENDPOINT = 11300

    def __init__(self):
        self.sock = socket.create_connection(("localhost", PEBBLE_PORT), timeout=5.0)
        self.sock.settimeout(20.0)

    def _qemu(self, protocol, data):
        self.sock.sendall(struct.pack(">HHH", self.HDR, protocol, len(data)) + data +
                          struct.pack(">H", self.FTR))

    def set_connected(self, connected):
        self._qemu(self.BT_CONN, struct.pack(">B", 1 if connected else 0))
        time.sleep(1.0)

    def send(self, payload):
        self._qemu(self.SPP, struct.pack(">HH", len(payload), self.ENDPOINT) + payload)

    def configure(self, enabled=True, lock_delay=300, shred_delay=1800):
        self.send(struct.pack(">BBHH", 0x01, 1 if enabled else 0, lock_delay, shred_delay))
        time.sleep(0.8)

    def lock(self, reason=0x01):
        self.send(struct.pack(">BB", 0x02, reason))

    def close(self):
        self.sock.close()


# --- Navigation -------------------------------------------------------------

def to_watchface(console):
    """Get back to a known place regardless of where we are."""
    press(*(["back"] * 6), settle=0.12)


def open_security(console):
    """watchface -> launcher -> Settings -> Security."""
    to_watchface(console)
    press("select")                       # launcher
    press(*(["up"] * 14), settle=0.08)    # top of launcher == Settings
    press("select")                       # Settings
    press(*(["up"] * 14), settle=0.08)    # top of Settings
    press(*(["down"] * SETTINGS_TO_SECURITY), settle=0.1)
    press("select")


def security_row(name, pin_set):
    rows = SECURITY_ROWS_WITH_PIN if pin_set else SECURITY_ROWS_NO_PIN
    return rows.index(name)


def select_security_row(name, pin_set):
    press(*(["up"] * 8), settle=0.08)
    press(*(["down"] * security_row(name, pin_set)), settle=0.1)
    press("select")


def set_or_change_pin(console, pad, new_pin, old_pin=None):
    """Set the PIN, taking whichever flow applies.

    The menu differs depending on whether a PIN already exists -- row 0 is
    "Set PIN" on a fresh watch and "Change PIN" once one is stored, and the
    latter asks for the current PIN first. Getting this wrong leaves the pad
    sitting on a stage the test never satisfies, so the state is queried
    rather than assumed. That matters because the emulator keeps its
    filesystem across a run, so the second test to touch the PIN is never
    looking at a fresh watch.
    """
    pin_set = console.status()["pin_len"] > 0
    open_security(console)
    select_security_row("Change PIN" if pin_set else "Set PIN", pin_set)
    if pin_set:
        type_pin(pad, old_pin or new_pin)   # authorise
    type_pin(pad, new_pin)                  # new
    type_pin(pad, new_pin)                  # repeat
    time.sleep(1.5)


def ensure_no_pin(console, pad, current="1234"):
    """Leave the watch with no PIN, whatever state it is in now."""
    if console.status()["pin_len"] == 0:
        return
    open_security(console)
    select_security_row("Clear PIN", pin_set=True)
    type_pin(pad, current)
    time.sleep(1.5)


# --- Tests ------------------------------------------------------------------

RESULTS = []


def wait_until_responsive(console, timeout=90.0):
    """Block until the watch answers again, e.g. after a wipe."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            console.status()
            time.sleep(1.0)   # let the UI catch up with the task
            return True
        except Exception:
            time.sleep(2.0)
    return False


def check(name, ok, detail=""):
    RESULTS.append((name, ok, detail))
    print(f"    [{'PASS' if ok else 'FAIL'}] {name}" + (f" - {detail}" if detail else ""))
    return ok


def test_starts_clean(console, pad):
    # The emulator keeps its filesystem for the whole run, so a re-run starts
    # wherever the last one stopped. Get to a known footing rather than
    # asserting a fresh watch and failing on the second run.
    ensure_no_pin(console, pad)
    st = console.status()
    check("starts disabled", st["state"] == 0, f"state={st['state']}")
    check("no PIN configured", st["pin_len"] == 0, f"pin_len={st['pin_len']}")
    check("no countdown armed", st["shred_in"] == -1 and st["lock_in"] == -1)
    check("defaults are 5 and 30 minutes",
          st["lock_delay"] == 300 and st["shred_delay"] == 1800,
          f"lock={st['lock_delay']} shred={st['shred_delay']}")


def test_set_pin(console, pad):
    screenshot("01-security-menu")
    set_or_change_pin(console, pad, "1234")
    screenshot("04-after-set")

    st = console.status()
    check("PIN is stored", st["pin_len"] == 4, f"pin_len={st['pin_len']}")
    check("moves to armed", st["state"] == 1, f"state={st['state']}")


def test_mismatched_pin_is_rejected(console, pad):
    pin_set = console.status()["pin_len"] > 0
    open_security(console)
    select_security_row("Change PIN" if pin_set else "Set PIN", pin_set)
    if pin_set:
        type_pin(pad, "1234")    # authorise
    type_pin(pad, "5678")        # new
    type_pin(pad, "8765")        # mismatched repeat
    time.sleep(1.0)
    screenshot("05-mismatch")
    press("back", "back")

    # The old PIN must still be the one that works.
    st = console.status()
    check("still armed after a mismatch", st["state"] == 1)
    check("PIN length unchanged", st["pin_len"] == 4)


def test_lock_and_unlock(console, pad):
    if console.status()["pin_len"] == 0:
        set_or_change_pin(console, pad, "1234")
    phone = Phone()
    phone.set_connected(True)
    phone.configure(lock_delay=300, shred_delay=1800)
    marker = console.mark()
    phone.lock()
    time.sleep(8.0)

    # These two survive the default log level on purpose; the rest of the
    # lock's chatter is DEBUG and compiled out, so tests must not depend on it.
    check("LOCK reaches the endpoint", console.saw(marker, "LOCK from phone"),
          " | ".join(console.since(marker))[:160])
    check("the shred runs", console.saw(marker, "Shredding:"))

    # The wipe runs on KernelMain and freezes the UI while it does, exactly as
    # a factory reset does. Input sent during that window is simply lost, so
    # wait for the watch to start answering again before touching it.
    wait_until_responsive(console)
    screenshot("06-locked-clock")

    st = console.status()
    if not check("phone LOCK locks the watch", st["state"] == 2, f"state={st['state']}"):
        phone.close()
        return

    # Any button raises the lock screen; the clock is what shows until then.
    press("select")
    time.sleep(1.0)
    screenshot("07-lock-screen")

    type_pin(pad, "1234")
    time.sleep(2.0)
    screenshot("08-after-unlock")

    st = console.status()
    check("correct PIN unlocks", st["state"] == 1, f"state={st['state']}")
    check("unlock clears the countdown", st["shred_in"] == -1 and st["lock_in"] == -1,
          f"lock_in={st['lock_in']} shred_in={st['shred_in']}")
    phone.close()


def test_wrong_pin_counts_up(console, pad):
    if console.status()["pin_len"] == 0:
        set_or_change_pin(console, pad, "1234")
    phone = Phone()
    phone.set_connected(True)
    phone.lock()
    time.sleep(8.0)
    wait_until_responsive(console)
    press("select")
    time.sleep(1.0)

    type_pin(pad, "9999")
    time.sleep(1.5)
    screenshot("09-wrong-pin")
    st = console.status()
    check("a wrong PIN is counted", st["attempts"] >= 1, f"attempts={st['attempts']}")
    check("stays locked after a wrong PIN", st["state"] == 2)

    type_pin(pad, "1234")
    time.sleep(2.0)
    st = console.status()
    check("a correct PIN still unlocks", st["state"] == 1)
    check("counter resets on success", st["attempts"] == 0, f"attempts={st['attempts']}")
    phone.close()


def test_disconnect_arms_countdown(console, pad):
    phone = Phone()
    phone.set_connected(True)
    phone.configure(lock_delay=300, shred_delay=1800)
    time.sleep(1.0)
    phone.set_connected(False)
    time.sleep(3.0)

    st = console.status()
    check("disconnect arms the lock countdown", 0 < st["lock_in"] <= 300,
          f"lock_in={st['lock_in']}")
    check("disconnect arms the shred countdown", 0 < st["shred_in"] <= 1800,
          f"shred_in={st['shred_in']}")

    phone.set_connected(True)
    time.sleep(3.0)
    st = console.status()
    check("reconnect cancels both countdowns",
          st["lock_in"] == -1 and st["shred_in"] == -1,
          f"lock_in={st['lock_in']} shred_in={st['shred_in']}")
    phone.close()


def test_configure_changes_delays(console, pad):
    phone = Phone()
    phone.set_connected(True)
    marker = console.mark()
    phone.configure(lock_delay=60, shred_delay=600)
    time.sleep(1.5)

    # The log says whether the message arrived at all, which state alone
    # cannot: an ignored message and a rejected one look identical from
    # outside.
    st = console.status()
    check("phone can set the lock delay", st["lock_delay"] == 60, f"={st['lock_delay']}")
    check("phone can set the shred delay", st["shred_delay"] == 600, f"={st['shred_delay']}")

    phone.configure(lock_delay=300, shred_delay=1800)
    time.sleep(1.0)
    phone.close()


def test_clear_pin(console, pad):
    if console.status()["pin_len"] == 0:
        check("nothing to clear", False, "no PIN was set")
        return
    open_security(console)
    select_security_row("Clear PIN", pin_set=True)
    type_pin(pad, "1234")
    time.sleep(1.5)
    screenshot("10-after-clear")
    st = console.status()
    check("clearing removes the PIN", st["pin_len"] == 0, f"pin_len={st['pin_len']}")
    check("clearing disables the lock", st["state"] == 0, f"state={st['state']}")


TESTS = [
    ("starts_clean", test_starts_clean),
    ("set_pin", test_set_pin),
    ("mismatched_pin_is_rejected", test_mismatched_pin_is_rejected),
    ("configure_changes_delays", test_configure_changes_delays),
    ("disconnect_arms_countdown", test_disconnect_arms_countdown),
    ("lock_and_unlock", test_lock_and_unlock),
    ("wrong_pin_counts_up", test_wrong_pin_counts_up),
    ("clear_pin", test_clear_pin),
]


def main():
    global VERBOSE
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", action="append", help="run only these tests")
    ap.add_argument("--width", type=int, default=200)
    ap.add_argument("--height", type=int, default=228)
    ap.add_argument("--round", action="store_true", help="round display (gabbro)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    VERBOSE = args.verbose

    if not os.path.exists(MON_SOCK):
        print(f"No QEMU monitor at {MON_SOCK}. Start one with ./pbl qemu")
        return 2

    pad = PadGeometry(args.width, args.height, args.round)
    console = Console()

    for name, fn in TESTS:
        if args.only and name not in args.only:
            continue
        print(f"\n=== {name} ===")
        try:
            # Back to a known screen; a test that left a half-finished PIN
            # entry up would otherwise poison every test after it.
            press(*(["back"] * 8), settle=0.1)
            fn(console, pad)
        except Exception as exc:  # keep going; one broken test should not hide the rest
            check(name + " (crashed)", False, repr(exc))

    console.close()

    passed = sum(1 for _, ok, _ in RESULTS if ok)
    failed = [n for n, ok, _ in RESULTS if not ok]
    print(f"\n{'=' * 60}\npassed {passed}/{len(RESULTS)}")
    for n in failed:
        print(f"  FAILED: {n}")
    print("screenshots: /tmp/seclock-e2e-*.png")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
