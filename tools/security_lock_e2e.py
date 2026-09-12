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

    pbl qemu &
    python3 tools/security_lock_e2e.py
    python3 tools/security_lock_e2e.py --only lock_and_unlock -v

The build directory, and everything in it, is the one `pbl` would use: the
workspace's `pbl.yml`, `PBL_BUILD_DIR`, or `--build-dir`.

Adjusting when the UI moves: menu positions live in ROWS and the keypad
geometry in PadGeometry. Those are the only places that need touching if
screen ordering or layout changes; the screen's size and shape are read off
the running machine and the board, never hardcoded.
"""

import argparse
import hashlib
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import deque

from pbl import emulator
from pbl.build import BuildDir
from pbl.workspace import Workspace

#: The checkout this script lives in, found the way `pbl` finds it.
WORKSPACE = Workspace.find(os.path.dirname(os.path.abspath(__file__)))
WORKSPACE.activate()
REPO = WORKSPACE.topdir

PEBBLE_PORT = emulator.PEBBLE_TOOL_PORT
CONSOLE_PORT = emulator.CONSOLE_PORT

#: How many log lines to keep. Long runs shred and reboot the watch repeatedly,
#: so the stream is unbounded; only the recent past is ever asserted on.
LOG_RING_SIZE = 20000

# --- Things to adjust when the UI changes -----------------------------------

#: Row index of each Security menu entry, mirroring the SettingsSecurityRow
#: order in src/fw/apps/system/settings/security.c. Two shapes only: the
#: master switch alone when off, everything when on. Off and "no PIN" are the
#: same state, because turning the feature off is what clears the PIN.
#:
#: This list has gone stale three times. If a menu assertion fails on a row
#: that obviously exists, check it against the SettingsSecurityRow enum first
#: -- a shifted index shows up as the wrong row silently doing nothing, and
#: the assertion that notices is rarely the one that broke.
SECURITY_ROWS_NO_PIN = ["Security Lock"]
SECURITY_ROWS_WITH_PIN = [
    "Security Lock",
    "Change PIN",
    "Lock After",
    "Erase After",
    "Erase Health Data",
    "Duress PIN",
    "Block Notifications",
    "Alarms When Locked",
    "Lock",
    "Lockdown + Erase",
    "Show in Launcher",
]

#: Enough DOWNs to reach the bottom of the Settings menu from anywhere in it.
#: Security is found from there rather than by counting down from the top --
#: see open_security() -- because everything above it is Kconfig-conditional.
SETTINGS_OVERSHOOT = 20

#: Nothing the wipe does may take longer than this. The blocking work is seven
#: small file zeroes, the data logging queue (however many session files exist),
#: plus about ten sector erases for the coredump and debug regions -- roughly
#: two seconds. Anything approaching this ceiling is a deadlock, not slow flash,
#: and every hang so far has been one.
SHRED_BUDGET_S = 15.0

#: A watch that has not drawn anything new in this long, and is not answering,
#: is hung rather than busy.
FREEZE_AFTER_S = 20.0


class PadGeometry:
    """Where the 3x3 keypad's keys are, mirroring prv_geometry() in
    src/fw/popups/security/pin_entry_window.c."""

    GAP = 3

    @classmethod
    def for_screen(cls, build):
        """Read the screen off the running machine and the configured board.

        The size comes from QEMU's own touch device, so it is whatever the
        emulator is actually drawing; the shape comes from the board's display
        header, which is where PBL_IF_ROUND_ELSE gets its answer too. Neither
        is a constant here, because a wrong one silently taps empty space.
        """
        with emulator.Qmp(build.join(emulator.QMP_SOCKET)) as qmp:
            width, height = qmp.touch_display()
        return cls(width, height, round_display=board_is_round(build))

    def __init__(self, w, h, round_display=False):
        self.screen = (w, h, round_display)
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

#: The build being driven, and where screenshots go. Both are set by main()
#: once the command line has been read.
BUILD = None
SHOT_DIR = None

#: PBL_ROUND in the board's display header is what decides the keypad layout;
#: `#define PBL_ROUND 1` is a round screen.
ROUND_RE = re.compile(r"^\s*#define\s+PBL_ROUND\s+(\d+)", re.MULTILINE)


def log(msg):
    if VERBOSE:
        print(f"      {msg}")


def board_is_round(build):
    board = build.board.split("@")[0]
    header = os.path.join(REPO, "src", "fw", "board", "displays", f"display_{board}.h")
    with open(header) as f:
        match = ROUND_RE.search(f.read())
    if match is None:
        raise RuntimeError(f"{header} does not define PBL_ROUND")
    return match.group(1) != "0"


def press(*buttons, settle=0.12):
    """back|select|up|down, using the QEMU key names."""
    names = {"back": "left", "select": "right", "up": "up", "down": "down"}
    with emulator.Monitor(BUILD.join(emulator.MONITOR_SOCKET)) as mon:
        for b in buttons:
            mon.command("sendkey " + names.get(b, b))
            time.sleep(settle)


def pbl(*args):
    """One `pbl` command against this build.

    `check=True` is the whole point: a tap that does not happen is a test that
    silently passes for the wrong reason, which is exactly how this harness
    spent its first life.
    """
    return subprocess.run(
        [sys.executable, "-m", "pbl", "--build-dir", str(BUILD), *args],
        cwd=REPO, capture_output=True, check=True, text=True,
    )


def tap(x, y, settle=0.2):
    pbl("touch", str(x), str(y))
    time.sleep(settle)


def type_pin(console, pad, digits, settle=0.2):
    """Tap `digits` on the keypad, once it is actually up.

    Waiting rather than sleeping: the pad is pushed from a menu selection, and
    tapping the screen underneath it lands on whatever is still there. That
    failure is silent -- the digits simply never arrive -- and surfaces several
    assertions later as a PIN that was never set.
    """
    if not wait_for_window(console, PIN_WINDOW):
        raise RuntimeError(f"the PIN pad never came up (top: {top_window(console)})")
    for ch in digits:
        x, y = pad.centre(int(ch))
        log(f"tap {ch} at ({x},{y})")
        tap(x, y, settle)


def screenshot(name):
    os.makedirs(SHOT_DIR, exist_ok=True)
    path = os.path.join(SHOT_DIR, f"{name}.png")
    try:
        pbl("screenshot", "-o", path)
    except subprocess.CalledProcessError as exc:
        log(f"screenshot {name} failed: {exc.stderr.strip()}")
        return None
    return path


class Console:
    """The firmware prompt and log stream, over PULSE on the QEMU serial port.

    One interface for both: PULSE allows a single connection, so a separate
    log-capture process would fight this one for it. Tests assert on the
    watch's own log lines as well as on `security status`, which is the only
    way to see inside things that leave no state behind -- a shred that ran,
    a message that was rejected.

    Note the log level cannot be raised from here. PBL_SHOULD_LOG gates on the
    module's compile-time level, so a DBG line the build dropped does not
    exist to be re-enabled; `log level set` only moves g_pbl_log_level, a
    later filter that already sits wide open. Seeing a module's DBG output
    means configuring with -DCONFIG_<MODULE>_LOG_LEVEL_DEBUG=y and rebuilding.
    """

    def __init__(self):
        from pebble import commander, pulse2

        from tools.log_hashing.logdehash import LogDehash

        self._commander = commander
        self._pulse2 = pulse2
        self.iface = pulse2.Interface.open_dbgserial(
            f"socket://localhost:{CONSOLE_PORT}"
        )
        # Only when the build actually hashes its log strings. Without a
        # dictionary every line raises inside the dehasher, and `str(msg)` --
        # `W - 12:00:00.000 file.c:12> message` -- is already what the tests
        # assert on.
        dict_path = BUILD.join("src", "fw", "loghash_dict.json")
        self._dehasher = (
            LogDehash(dict_path, monitor_dict_file=False)
            if os.path.exists(dict_path)
            else None
        )
        self.lines = deque(maxlen=LOG_RING_SIZE)
        #: Where `lines` starts, so a mark taken before the ring wrapped still
        #: names the right place in it.
        self._dropped = 0
        self.log_fault = None
        self._lock = threading.Lock()
        self._pump = threading.Thread(target=self._pump_logs, daemon=True)
        self._pump.start()
        self._await_link()
        # Kept for boards whose g_pbl_log_level default is lower than DEBUG.
        # A no-op on qemu_emery; see the class docstring.
        self.command("log level set 200")

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
        """The log stream, for the whole life of the run.

        When it stops, it says so: a silent log thread turns every later
        `saw()` into a false negative, and the assertion that notices is never
        the one that broke.
        """
        exceptions = self._pulse2.exceptions
        logs = self._commander.apps.StreamingLogs(self.iface)
        while True:
            try:
                msg = logs.receive(block=True)
            except (exceptions.PulseException, OSError, AttributeError) as exc:
                self.log_fault = f"{type(exc).__name__}: {exc}"
                return
            text = str(msg)
            if self._dehasher is not None:
                try:
                    text = self._dehasher.commander_format_line(
                        self._dehasher.dehash(msg)
                    )
                except (AttributeError, IndexError, KeyError, TypeError, ValueError):
                    # A line the dictionary cannot explain is still a line.
                    text = str(msg)
            with self._lock:
                if len(self.lines) == self.lines.maxlen:
                    self._dropped += 1
                self.lines.append(text)

    def command(self, cmd):
        exceptions = self._pulse2.exceptions
        link = self.iface.get_link()
        if link is None:
            self._await_link(timeout=10.0)
            link = self.iface.get_link()
            if link is None:
                return []
        prompt = self._commander.apps.Prompt(link)
        try:
            return list(prompt.command_and_response(cmd))
        except (
            self._commander.exceptions.PebbleCommanderError,
            exceptions.PulseException,
            OSError,
            AttributeError,
        ):
            # The watch is busy, wedged or rebooting. Callers retry or fail on
            # the emptiness; a traceback here would bury the real failure.
            return []
        finally:
            try:
                prompt.close()
            except (exceptions.PulseException, OSError, AttributeError) as exc:
                log(f"closing the prompt after {cmd!r}: {exc}")

    def status(self):
        """Parse `security status` into a dict, retrying while the watch is busy."""
        for _ in range(6):
            for line in self.command("security status"):
                fields = dict(re.findall(r"(\w+)=(-?\d+)", line))
                if "state" in fields:
                    return {k: int(v) for k, v in fields.items()}
            time.sleep(2.0)
        raise RuntimeError("watch did not answer `security status`")

    def ui(self):
        """Parse `security ui` into a dict of strings.

        Left as strings because half the fields are quoted text; the numeric
        ones anybody asks about are flags, which read fine as "0" and "1".

        Each value runs to the next `key=`, not to the next space: the modal
        debug names have spaces in them and are not quoted, so splitting on
        whitespace silently truncates "Alarm Popup" to "Alarm".
        """
        for line in self.command("security ui"):
            if "top_modal=" in line:
                return {k: v.strip().strip('"') for k, v in
                        re.findall(r'(\w+)=(.*?)(?=\s+\w+=|$)', line.strip())}
        raise RuntimeError("watch did not answer `security ui`")

    def mark(self):
        """Remember where the log is now, so a test can look only at what follows."""
        with self._lock:
            return self._dropped + len(self.lines)

    def since(self, marker):
        with self._lock:
            return list(self.lines)[max(0, marker - self._dropped):]

    def saw(self, marker, needle):
        return any(needle in line for line in self.since(marker))

    def close(self):
        try:
            self.iface.close()
        except (self._pulse2.exceptions.PulseException, OSError, AttributeError) as exc:
            log(f"closing the console: {exc}")


class Phone:
    """Stands in for Gadgetbridge on the QEMU comm channel."""

    HDR, FTR = 0xFEED, 0xBEEF
    SPP, BT_CONN = 1, 3
    ENDPOINT = 11300

    #: Commands, from the watch's side of the endpoint.
    STATUS_REQUEST, STATUS_RESPONSE = 0x03, 0x83

    def __init__(self):
        self.sock = socket.create_connection(("localhost", PEBBLE_PORT), timeout=5.0)
        self.sock.settimeout(20.0)
        self.buf = b""

    def _qemu(self, protocol, data):
        self.sock.sendall(struct.pack(">HHH", self.HDR, protocol, len(data)) + data +
                          struct.pack(">H", self.FTR))

    def _read_qemu_packet(self, deadline):
        """Pull one framed QEMU packet, resyncing on the header signature.

        Resyncing matters: the firmware puts log traffic on this channel too,
        so the stream is not a clean run of frames.
        """
        while True:
            idx = self.buf.find(struct.pack(">H", self.HDR))
            if idx >= 0 and len(self.buf) >= idx + 6:
                _, protocol, length = struct.unpack(">HHH", self.buf[idx:idx + 6])
                total = idx + 6 + length + 2
                if len(self.buf) >= total:
                    data = self.buf[idx + 6:idx + 6 + length]
                    self.buf = self.buf[total:]
                    return protocol, data

            if time.time() > deadline:
                return None, None
            try:
                chunk = self.sock.recv(4096)
            except TimeoutError:
                return None, None
            if not chunk:
                return None, None
            self.buf += chunk

    def expect(self, command, timeout=15.0):
        """Wait for one security-endpoint message with the given command."""
        deadline = time.time() + timeout
        while True:
            protocol, data = self._read_qemu_packet(deadline)
            if protocol is None:
                return None
            if protocol != self.SPP or len(data) < 5:
                continue
            length, endpoint = struct.unpack(">HH", data[:4])
            if endpoint != self.ENDPOINT:
                continue
            payload = data[4:4 + length]
            if payload and payload[0] == command:
                return payload

    def status_request(self):
        """STATUS_REQUEST (0x03): ask for the state over the wire."""
        self.send(struct.pack(">B", self.STATUS_REQUEST))

    def set_connected(self, connected):
        self._qemu(self.BT_CONN, struct.pack(">B", 1 if connected else 0))
        time.sleep(1.0)

    def send(self, payload):
        self._qemu(self.SPP, struct.pack(">HH", len(payload), self.ENDPOINT) + payload)

    def retired_configure(self, enabled=True, lock_delay=300, shred_delay=1800):
        """Send the retired CONFIGURE (0x01), which the watch must now ignore.

        Kept so a test can prove the phone cannot reach the watch's settings.
        The command was removed because the phone re-sent it on every
        connection, overriding what the user had chosen on the watch.
        """
        self.send(struct.pack(">BBHH", 0x01, 1 if enabled else 0, lock_delay, shred_delay))
        time.sleep(0.8)

    def lock(self, reason=0x01):
        """LOCK (0x02): lock now, leave the erase to the watch's Erase After."""
        self.send(struct.pack(">BB", 0x02, reason))

    def lock_erase(self, reason=0x01):
        """LOCK_ERASE (0x04): lock now and erase now, whatever Erase After says.

        Same length as LOCK -- only the command byte differs -- so a watch that
        drops one on a length check drops both, rather than silently taking the
        less destructive path.
        """
        self.send(struct.pack(">BB", 0x04, reason))

    def close(self):
        self.sock.close()


# --- Navigation -------------------------------------------------------------

WINDOW_RE = re.compile(r"window\s+0x[0-9a-fA-F]+\s+<([^>]*)>")
PRIORITY_RE = re.compile(r"Priority:\s*(\d+)")

#: Debug names from `window stack`. Which of these is home depends on the
#: build: a firmware with no watchface installed comes up in the launcher and
#: BACK never leaves it, which is what qemu_emery does.
LAUNCHER_WINDOW = "Launcher Menu"
#: The keypad, and the two-item length picker that precedes it. The same pad
#: is used twice over: pushed onto the Settings app's own stack when a PIN is
#: being set, and as a modal by the lock screen (lock_screen.h) when one is
#: being demanded. Only the stack it lives on differs.
PIN_WINDOW = "Security PIN"
OPTION_MENU_WINDOW = "OptionMenu"

#: ModalPriorityDiscreet in kernel/ui/modals/modal_manager.h: overlays such as
#: Timeline Peek, which sit on top of the watchface without obstructing it. A
#: discreet modal is not what the user is looking at.
DISCREET_MODAL_PRIORITY = 0


def window_stack(console):
    """`window stack`, top first, as a list of window debug names."""
    names = []
    for line in console.command("window stack"):
        match = WINDOW_RE.search(line)
        if match:
            names.append(match.group(1))
    return names


def modal_stack(console):
    """`modal stack` -> {priority: [names]}, top first within a priority."""
    stacks = {}
    priority = None
    for line in console.command("modal stack"):
        prio = PRIORITY_RE.search(line)
        if prio:
            priority = int(prio.group(1))
            stacks.setdefault(priority, [])
            continue
        window = WINDOW_RE.search(line)
        if window and priority is not None:
            stacks[priority].append(window.group(1))
    return stacks


def top_window(console):
    """What the user is actually looking at.

    The obstructing modal if there is one, otherwise the top of the app window
    stack. Both stacks matter: the lock screen is a modal while the Settings
    PIN pad is an app window, so a check that read only `window stack` sees
    "TicToc" on a locked watch and taps the watchface.
    """
    modals = modal_stack(console)
    for priority in sorted(modals, reverse=True):
        if priority <= DISCREET_MODAL_PRIORITY:
            break
        if modals[priority]:
            return modals[priority][0]
    stack = window_stack(console)
    return stack[0] if stack else None


def wait_for_window(console, name, timeout=8.0):
    """Block until `name` is the top window."""
    deadline = time.time() + timeout
    while True:
        if top_window(console) == name:
            return True
        if time.time() >= deadline:
            return False
        time.sleep(0.25)


def go_home(console, tries=10):
    """Back out until BACK stops changing anything, and say where that is.

    Counting BACK presses assumes a depth; asking the watch does not. It also
    settles which screen home *is*: a build with a watchface comes back to it,
    one without -- qemu_emery, out of the box -- comes back to the launcher and
    stays there however many times BACK is pressed.
    """
    previous = None
    for _ in range(tries):
        name = top_window(console)
        if name is not None and name == previous:
            return name
        previous = name
        press("back", settle=0.25)
    return top_window(console)


def open_security(console):
    """home -> launcher -> Settings -> Security.

    Security is reached from the *bottom* of the Settings menu rather than by
    counting down from the top: `SettingsMenuItemSecurity` sits immediately
    before `SettingsMenuItemSystem`, which is the last entry (menu.h), and
    everything above Security is conditional on Kconfig. Menus clamp rather
    than wrap, so overshooting downwards lands on System whatever the build
    compiled in, and one UP is then Security.
    """
    if go_home(console) != LAUNCHER_WINDOW:
        press("select", settle=0.4)          # a watchface: SELECT opens the launcher
    press(*(["up"] * 14), settle=0.1)        # top of the launcher == Settings
    press("select", settle=0.6)              # Settings
    press(*(["down"] * SETTINGS_OVERSHOOT), settle=0.1)   # clamps on System
    press("up", settle=0.25)                 # Security is the row above it
    press("select", settle=0.6)


def security_row(name, pin_set):
    rows = SECURITY_ROWS_WITH_PIN if pin_set else SECURITY_ROWS_NO_PIN
    return rows.index(name)


def select_security_row(name, pin_set):
    # Enough UPs to reach the top from anywhere in the menu, whichever row set
    # is showing. Derived rather than a literal: a row added below is a row the
    # old count could no longer climb past.
    press(*(["up"] * len(SECURITY_ROWS_WITH_PIN)), settle=0.1)
    press(*(["down"] * security_row(name, pin_set)), settle=0.12)
    press("select", settle=0.4)


#: The lengths the picker offers, in order. Mirrors
#: security_lock_pin_len_is_valid() -- every even width from 4 to 10.
PIN_LENGTHS = (4, 6, 8, 10)


def choose_pin_length(console, digits, current=4):
    """Pick a length on the length step of the set-PIN flow.

    The picker opens on the current length, so this walks the distance between
    the two rows rather than pressing once: 4 to 10 is three presses, and a
    single one would silently pick 6. It has no row constant because it is its
    own option menu rather than the Security menu.

    Waited for, not slept through: a SELECT sent before the picker is up goes
    to the Security menu instead, which opens the flow a second time and
    leaves every later step one screen out of phase.
    """
    if digits not in PIN_LENGTHS:
        raise ValueError(f"{digits} is not a length the picker offers")
    if not wait_for_window(console, OPTION_MENU_WINDOW):
        raise RuntimeError(
            f"the PIN length picker never came up (top: {top_window(console)})"
        )
    # An unknown current length leaves the picker on its first row.
    opens_on = current if current in PIN_LENGTHS else PIN_LENGTHS[0]
    steps = PIN_LENGTHS.index(digits) - PIN_LENGTHS.index(opens_on)
    if steps:
        press(*(["down" if steps > 0 else "up"] * abs(steps)), settle=0.2)
    press("select", settle=0.3)
    time.sleep(0.8)


def set_or_change_pin(console, pad, new_pin, old_pin=None):
    """Set the PIN, taking whichever flow applies.

    Setting a PIN is what turns the feature on, so a fresh watch has one row
    and reaching the pad goes through it; once a PIN exists the flow is
    "Change PIN" and asks for the current one first. Both then step through
    the length picker before the pad. Getting this wrong leaves the pad on a
    stage the test never satisfies, so the state is queried rather than
    assumed -- the emulator keeps its filesystem across a run, so the second
    test to touch the PIN is never looking at a fresh watch.
    """
    st = console.status()
    pin_set = st["pin_len"] > 0
    open_security(console)
    select_security_row("Change PIN" if pin_set else "Security Lock", pin_set)
    if pin_set:
        type_pin(console, pad, old_pin or new_pin)   # authorise
    choose_pin_length(console, len(new_pin), current=st["pin_len"] or 4)
    type_pin(console, pad, new_pin)                  # new
    type_pin(console, pad, new_pin)                  # repeat
    time.sleep(1.5)


def ensure_no_pin(console, pad, current="1234"):
    """Leave the watch with no PIN, whatever state it is in now.

    Turning the feature off is what clears the PIN -- there is no separate
    Clear PIN row, because it would be the same button under a second name --
    and it asks for the PIN first, so an unlocked watch cannot be disarmed by
    whoever happens to be holding it.
    """
    if console.status()["pin_len"] == 0:
        return
    open_security(console)
    select_security_row("Security Lock", pin_set=True)
    type_pin(console, pad, current)
    time.sleep(1.5)


# --- Tests ------------------------------------------------------------------

RESULTS = []

#: What a test crashing is allowed to look like. Broad on purpose -- one broken
#: test must not hide the rest -- but enumerated rather than bare, so a genuine
#: defect in this harness still stops the run instead of being logged as a
#: watch failure.
TEST_FAILURES = (
    ArithmeticError,
    AssertionError,
    AttributeError,
    LookupError,
    OSError,
    RuntimeError,
    TypeError,
    ValueError,
    struct.error,
    subprocess.SubprocessError,
)


def wait_until_responsive(console, timeout=SHRED_BUDGET_S):
    """Block until the watch answers again, e.g. after a wipe.

    Bounded by SHRED_BUDGET_S rather than something generous: a wipe that has
    not finished by then is wedged, and waiting longer only turns a clear
    failure into a slow one.
    """
    started = time.time()
    deadline = started + timeout
    while time.time() < deadline:
        try:
            console.status()
            time.sleep(1.0)   # let the UI catch up with the task
            return True
        except RuntimeError:
            time.sleep(1.0)
    check("watch recovers within the wipe budget", False,
          f"still not answering after {timeout:.0f}s -- treat as a hang")
    return False


def _screen_fingerprint():
    """Hash of the current display, or None if the screenshot failed."""
    path = screenshot("freeze-probe")
    if path is None:
        return None
    with open(path, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()


def diagnose_hang():
    """Say plainly what a hung watch looks like, rather than dying on a
    PULSE error twenty lines later."""
    first = _screen_fingerprint()
    time.sleep(6.0)
    second = _screen_fingerprint()
    if first is None or second is None:
        return "the emulator is not answering screenshot requests at all"
    if first == second:
        return (f"the display has not changed in 6s (fingerprint {first[:8]}) and the "
                "console is silent -- the watch is hung, most likely mid-wipe. "
                "Relaunching `pbl qemu` rebuilds the flash image and clears it.")
    return "the display is still updating, so the UI task is alive but the console is not"


#: `security status`'s state field: 0 disabled, 1 armed, 2 locked.
STATE_LOCKED = 2


def reset_to_known_state(console):
    """A run must not start on a watch that a previous one left locked.

    Every screen the tests navigate sits behind the lock screen, so a locked
    start turns the whole suite into one repeated "the PIN pad never came up".
    `security clear pin` is a test hook rather than the UI, deliberately: this
    is setup, and the first test asserts exactly the clean slate it leaves.
    """
    if console.status()["state"] != STATE_LOCKED:
        return
    print("!! the watch was locked; clearing the PIN to start from a known state")
    console.command("security clear pin")
    time.sleep(1.0)


def assert_booted(console):
    """Fail fast and clearly if the watch never finished booting.

    A frozen boot used to surface as an obscure PULSE 'NoneType has no
    open_socket' several tests later; a wipe that hangs during boot blocks the
    task that brings the UI up, so this is the failure to expect.
    """
    deadline = time.time() + FREEZE_AFTER_S
    while time.time() < deadline:
        try:
            console.status()
            return True
        except RuntimeError:
            time.sleep(1.5)
    print(f"\n!! watch did not finish booting within {FREEZE_AFTER_S:.0f}s")
    print(f"!! {diagnose_hang()}")
    return False


def check(name, ok, detail=""):
    RESULTS.append((name, ok, detail))
    # Flushed: a run takes minutes, and a redirected stdout otherwise says
    # nothing at all until it is over -- including when it hangs.
    print(f"    [{'PASS' if ok else 'FAIL'}] {name}" + (f" - {detail}" if detail else ""),
          flush=True)
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
    # Erase After ships as Never, so out of the box the watch locks and never
    # erases. Turning erasing on is the user's decision, not the default.
    check("defaults are 5 minutes and never erase",
          st["lock_delay"] == 300 and st["shred_delay"] == 0,
          f"lock={st['lock_delay']} shred={st['shred_delay']}")


def test_set_pin(console, pad):
    screenshot("01-security-menu")
    set_or_change_pin(console, pad, "1234")
    screenshot("04-after-set")

    st = console.status()
    check("PIN is stored", st["pin_len"] == 4, f"pin_len={st['pin_len']}")
    check("moves to armed", st["state"] == 1, f"state={st['state']}")


def test_mismatched_pin_is_rejected(console, pad):
    st = console.status()
    pin_set = st["pin_len"] > 0
    open_security(console)
    select_security_row("Change PIN" if pin_set else "Security Lock", pin_set)
    if pin_set:
        type_pin(console, pad, "1234")    # authorise
    choose_pin_length(console, 4, current=st["pin_len"] or 4)
    type_pin(console, pad, "5678")        # new
    type_pin(console, pad, "8765")        # mismatched repeat
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
    # The watch owns its delays now; nothing to configure from here.
    marker = console.mark()
    phone.lock()
    time.sleep(8.0)

    # These two survive the default log level on purpose; the rest of the
    # lock's chatter is DEBUG and compiled out, so tests must not depend on it.
    check("LOCK reaches the endpoint", console.saw(marker, "LOCK from phone"),
          " | ".join(console.since(marker))[:160])
    # LOCK arms the erase rather than performing it, and the shipped Erase
    # After is Never -- so nothing is erased here at all. Asserting on
    # "Shredding:" would be asserting the old behaviour. LOCK_ERASE is the
    # command that does erase, and test_phone_lock_erase covers it.
    check("plain LOCK does not erase", not console.saw(marker, "Shredding:"),
          " | ".join(console.since(marker))[:160])

    # The wipe runs on the launcher task and freezes the UI while it does,
    # exactly as a factory reset does. Input sent during that window is lost,
    # so wait for the watch to answer again -- and hold it to a budget, because
    # every hang in this feature so far has looked like "just slow".
    started = time.time()
    recovered = wait_until_responsive(console)
    elapsed = time.time() - started
    check(f"the wipe finishes inside {SHRED_BUDGET_S:.0f}s", recovered,
          f"took {elapsed:.1f}s")
    if not recovered:
        print(f"    !! {diagnose_hang()}")
        return
    screenshot("06-locked-clock")

    st = console.status()
    if not check("phone LOCK locks the watch", st["state"] == 2, f"state={st['state']}"):
        phone.close()
        return

    # Any button raises the lock screen; the clock is what shows until then.
    press("select")
    time.sleep(1.0)
    screenshot("07-lock-screen")

    type_pin(console, pad, "1234")
    time.sleep(2.0)
    screenshot("08-after-unlock")

    st = console.status()
    check("correct PIN unlocks", st["state"] == 1, f"state={st['state']}")
    check("unlock clears the countdown", st["shred_in"] == -1 and st["lock_in"] == -1,
          f"lock_in={st['lock_in']} shred_in={st['shred_in']}")
    phone.close()


def test_status_over_the_wire(console, pad):
    """STATUS_REQUEST comes back as a STATUS_RESPONSE that agrees with the watch.

    The only test that reads a reply off the endpoint rather than asserting on
    a console line, so it is what covers the response actually being serialised
    the way the phone expects. Cross-checked against `security status`, which
    is the watch's own answer: a wire format that has drifted shows up as the
    two disagreeing rather than as a frame nobody reads.
    """
    phone = Phone()
    phone.set_connected(True)
    phone.status_request()
    reply = phone.expect(Phone.STATUS_RESPONSE)

    if not check("STATUS_REQUEST is answered", reply is not None):
        phone.close()
        return

    _, state, pin_configured, remaining = struct.unpack(">BBBI", reply[:7])
    st = console.status()
    check("the reported state is the watch's own", state == st["state"],
          f"wire={state} console={st['state']}")
    check("the PIN flag matches", pin_configured == (1 if st["pin_len"] else 0),
          f"wire={pin_configured} pin_len={st['pin_len']}")
    # -1 is the console's "no deadline"; the wire carries 0 for the same thing.
    expected = max(st["lock_in"], 0)
    check("the deadline matches", abs(int(remaining) - expected) <= 2,
          f"wire={remaining}s console={st['lock_in']}s")
    phone.close()


def test_phone_lock_erase(console, pad):
    """LOCK_ERASE locks and erases on the spot, with Erase After left at Never.

    The counterpart to "plain LOCK does not erase". Erase After governs the
    countdown, not this: a phone that asked for the content to go now is not
    asking for a timer, so Never must not veto it.
    """
    if console.status()["pin_len"] == 0:
        set_or_change_pin(console, pad, "1234")
    phone = Phone()
    phone.set_connected(True)
    marker = console.mark()
    phone.lock_erase()
    time.sleep(8.0)

    check("LOCK_ERASE reaches the endpoint", console.saw(marker, "LOCK_ERASE from phone"),
          " | ".join(console.since(marker))[:160])
    check("LOCK_ERASE erases despite Erase After being Never",
          console.saw(marker, "Shredding:"),
          " | ".join(console.since(marker))[:160])

    started = time.time()
    recovered = wait_until_responsive(console)
    elapsed = time.time() - started
    check(f"the wipe finishes inside {SHRED_BUDGET_S:.0f}s", recovered,
          f"took {elapsed:.1f}s")
    if not recovered:
        print(f"    !! {diagnose_hang()}")
        phone.close()
        return

    st = console.status()
    check("LOCK_ERASE locks the watch too", st["state"] == 2, f"state={st['state']}")
    # It erased already, so there is nothing left for a countdown to count.
    check("LOCK_ERASE leaves no countdown", st["shred_in"] == -1,
          f"shred_in={st['shred_in']}")

    press("select")
    time.sleep(1.0)
    type_pin(console, pad, "1234")
    time.sleep(2.0)
    st = console.status()
    check("the PIN still opens an erased watch", st["state"] == 1, f"state={st['state']}")
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

    type_pin(console, pad, "9999")
    time.sleep(1.5)
    screenshot("09-wrong-pin")
    st = console.status()
    check("a wrong PIN is counted", st["attempts"] >= 1, f"attempts={st['attempts']}")
    check("stays locked after a wrong PIN", st["state"] == 2)

    type_pin(console, pad, "1234")
    time.sleep(2.0)
    st = console.status()
    check("a correct PIN still unlocks", st["state"] == 1)
    check("counter resets on success", st["attempts"] == 0, f"attempts={st['attempts']}")
    phone.close()


def test_disconnect_arms_countdown(console, pad):
    phone = Phone()
    phone.set_connected(True)
    # The watch owns its delays now; nothing to configure from here.
    time.sleep(1.0)
    phone.set_connected(False)
    time.sleep(3.0)

    st = console.status()
    check("disconnect arms the lock countdown", 0 < st["lock_in"] <= 300,
          f"lock_in={st['lock_in']}")
    check("no erase countdown, since Erase After is Never", st["shred_in"] == -1,
          f"shred_in={st['shred_in']}")

    phone.set_connected(True)
    time.sleep(3.0)
    st = console.status()
    check("reconnect cancels both countdowns",
          st["lock_in"] == -1 and st["shred_in"] == -1,
          f"lock_in={st['lock_in']} shred_in={st['shred_in']}")
    phone.close()


def test_phone_cannot_change_the_delays(console, pad):
    """The delays belong to the watch, so a phone asking must change nothing.

    CONFIGURE used to carry them and was retired: the phone re-sent it on
    every connection, overriding whatever the user had chosen in Settings. A
    phone that can disarm the watch is a phone that can be compelled to.
    """
    before = console.status()
    phone = Phone()
    phone.set_connected(True)
    phone.retired_configure(lock_delay=60, shred_delay=600)
    time.sleep(1.5)

    st = console.status()
    check("the retired message leaves the lock delay alone",
          st["lock_delay"] == before["lock_delay"],
          f"{before['lock_delay']} -> {st['lock_delay']}")
    check("the retired message leaves the erase delay alone",
          st["shred_delay"] == before["shred_delay"],
          f"{before['shred_delay']} -> {st['shred_delay']}")
    phone.close()


def test_turning_it_off_clears_the_pin(console, pad):
    """Off is a clean slate, and getting there costs the PIN.

    There is no Clear PIN row: clearing the PIN is what turning the switch
    off does. It asks for the PIN first, so an unlocked watch cannot be
    disarmed by whoever is holding it -- which the switch used to allow in
    two presses, protecting less than the lock screen it controlled.
    """
    if console.status()["pin_len"] == 0:
        check("nothing to turn off", False, "no PIN was set")
        return
    open_security(console)
    select_security_row("Security Lock", pin_set=True)

    type_pin(console, pad, "9999")
    time.sleep(1.0)
    st = console.status()
    check("a wrong PIN will not turn it off", st["state"] != 0, f"state={st['state']}")
    check("a wrong PIN leaves the PIN in place", st["pin_len"] == 4,
          f"pin_len={st['pin_len']}")

    type_pin(console, pad, "1234")
    time.sleep(1.5)
    screenshot("10-after-turning-off")
    st = console.status()
    check("turning it off clears the PIN", st["pin_len"] == 0, f"pin_len={st['pin_len']}")
    check("turning it off disables the lock", st["state"] == 0, f"state={st['state']}")


def test_alarm_rings_while_locked(console, pad):
    """A locked watch still wakes the user; a shredded one does not.

    Locking because the phone walked out of range does not stop the watch
    being a watch. Once the content has actually been erased it does: nothing
    is left to be useful for, and the radio is down.
    """
    if console.status()["pin_len"] == 0:
        set_or_change_pin(console, pad, "1234")

    # Lock, which is what a disconnect produces too: locked, with whatever
    # Erase After says still running. Asserted on the log rather than on the
    # dirty flag, which stays clear after an earlier test's wipe until the phone
    # writes something and so cannot tell a re-run anything.
    marker = console.mark()
    console.command("security lock")
    time.sleep(3.0)
    st = console.status()
    if not check("Lock locks without erasing",
                 st["state"] == 2 and not console.saw(marker, "Shredding:"),
                 f"state={st['state']}"):
        return

    console.command("alarm")
    time.sleep(2.5)
    ui = console.ui()
    screenshot("12-alarm-while-locked")
    check("the alarm rings while locked", ui["top_modal"] == "Alarm Popup",
          f"top_modal={ui['top_modal']}")

    # UP is snooze. It has to reach the popup rather than raise the lock
    # screen, or a locked watch is one the user cannot silence.
    press("up")
    time.sleep(2.5)
    ui = console.ui()
    check("snooze reaches the alarm, not the lock screen", ui["visible"] == "0",
          f"visible={ui['visible']} top_modal={ui['top_modal']}")

    # And the next press still raises the lock screen, as it always did.
    press("select")
    time.sleep(1.5)
    check("a press after that still raises the lock screen",
          console.ui()["visible"] == "1")

    # The alarm outranks the PIN pad, and is the only thing that does. With the
    # pad up it still comes to the front, because an alarm that cannot be
    # snoozed is worse than one that never rang.
    console.command("alarm")
    time.sleep(2.5)
    check("a ringing alarm comes up over the PIN pad",
          console.ui()["top_modal"] == "Alarm Popup",
          f"top_modal={console.ui()['top_modal']}")

    # And answering it gets nobody further in: what it uncovers is the pad it
    # was covering, still locked.
    press("down")
    time.sleep(3.0)
    ui = console.ui()
    check("dismissing it uncovers the pad, still locked",
          ui["visible"] == "1" and console.status()["state"] == 2,
          f"visible={ui['visible']} top_modal={ui['top_modal']}")

    console.command("alarm")
    time.sleep(2.5)

    marker = console.mark()
    console.command("security shred")
    if not check("the wipe finishes", wait_until_responsive(console)):
        return
    check("the radio goes down", console.saw(marker, "taking the radio down"),
          " | ".join(console.since(marker))[:160])
    check("the wipe silences the alarm with everything else",
          console.ui()["top_modal"] != "Alarm Popup",
          f"top_modal={console.ui()['top_modal']}")

    console.command("alarm")
    time.sleep(2.5)
    ui = console.ui()
    check("a shredded watch stays silent", ui["top_modal"] != "Alarm Popup",
          f"top_modal={ui['top_modal']}")

    type_pin(console, pad, "1234")
    time.sleep(2.0)
    if not check("it unlocks afterwards", console.status()["state"] == 1):
        return

    # And the switch that turns the whole exemption off.
    console.command("security alarms 0")
    check("the setting is recorded", console.status()["alarms"] == 0)
    console.command("security lock")
    time.sleep(3.0)
    console.command("alarm")
    time.sleep(2.5)
    ui = console.ui()
    check("Alarms When Locked off keeps a locked watch silent",
          ui["top_modal"] != "Alarm Popup", f"top_modal={ui['top_modal']}")

    press("select")
    time.sleep(1.5)
    type_pin(console, pad, "1234")
    time.sleep(2.0)
    console.command("security alarms 1")
    check("it unlocks and the setting goes back", console.status()["state"] == 1)


def test_notification_hidden_while_locked(console, pad):
    """A notification arriving behind the lock is kept, and never drawn.

    The two are separate promises and the second one used to have a hole in it.
    Blocking pop-ups is reference counted, and the count is taken by
    security_lock_ui_lockout() -- which a watch that rebooted straight into the
    locked state has never run, because nothing raises the pad until the first
    button press. So this test reboots into the lock rather than locking from a
    running watch: the interesting window is the one before that first press,
    and locking normally never enters it.

    The unread count is what tells "kept, unshown" apart from "discarded". Both
    look like an empty screen, which is exactly why the hole survived review.
    """
    if console.status()["pin_len"] == 0:
        set_or_change_pin(console, pad, "1234")

    console.command("security notifs 0")
    if not check("notifications are set to be kept",
                 console.status()["block_notifs"] == 0):
        return

    console.command("security lock")
    time.sleep(3.0)
    if not check("the watch is locked", console.status()["state"] == 2):
        return

    # Rebooting while locked comes back locked, and re-runs the wipe on the way
    # -- so this waits out a shred, not just a boot.
    console.command("reset")
    time.sleep(2.0)
    if not check("it reboots", assert_booted(console)):
        return
    if not check("it comes back locked", console.status()["state"] == 2,
                 f"state={console.status()['state']}"):
        return

    # The window this test exists for: locked, but nothing has raised the pad,
    # so no pop-up block has been taken.
    ui = console.ui()
    if not check("the pad is down after the reboot", ui["visible"] == "0",
                 f"visible={ui['visible']} top_modal={ui['top_modal']}"):
        return

    before = console.status()["unread"]
    console.command("notif test")
    time.sleep(2.5)

    ui = console.ui()
    screenshot("13-notification-while-locked")
    check("nothing is drawn for it", ui["top_modal"] != "Notification Window",
          f"top_modal={ui['top_modal']}")
    check("the pad is still down", ui["visible"] == "0",
          f"visible={ui['visible']}")
    check("but it was kept", console.status()["unread"] == before + 1,
          f"unread {before} -> {console.status()['unread']}")

    # And it is still there once the watch is open, which is the whole point of
    # keeping it.
    press("select")
    time.sleep(1.5)
    type_pin(console, pad, "1234")
    time.sleep(2.0)
    if not check("it unlocks", console.status()["state"] == 1):
        return
    check("the notification survived the unlock",
          console.status()["unread"] == before + 1,
          f"unread={console.status()['unread']}")

    # The other branch: on, and the notification is discarded rather than kept.
    console.command("security notifs 1")
    console.command("security lock")
    time.sleep(3.0)
    before = console.status()["unread"]
    console.command("notif test")
    time.sleep(2.5)
    ui = console.ui()
    check("with blocking on it is not drawn either",
          ui["top_modal"] != "Notification Window", f"top_modal={ui['top_modal']}")
    check("and it is discarded rather than kept",
          console.status()["unread"] == before,
          f"unread {before} -> {console.status()['unread']}")

    press("select")
    time.sleep(1.5)
    type_pin(console, pad, "1234")
    time.sleep(2.0)
    console.command("security notifs 0")
    check("it unlocks and the setting goes back", console.status()["state"] == 1)


TESTS = [
    ("starts_clean", test_starts_clean),
    ("status_over_the_wire", test_status_over_the_wire),
    ("set_pin", test_set_pin),
    ("mismatched_pin_is_rejected", test_mismatched_pin_is_rejected),
    ("phone_cannot_change_the_delays", test_phone_cannot_change_the_delays),
    ("disconnect_arms_countdown", test_disconnect_arms_countdown),
    ("lock_and_unlock", test_lock_and_unlock),
    ("phone_lock_erase", test_phone_lock_erase),
    ("wrong_pin_counts_up", test_wrong_pin_counts_up),
    ("alarm_rings_while_locked", test_alarm_rings_while_locked),
    ("turning_it_off_clears_the_pin", test_turning_it_off_clears_the_pin),
    # Last, because it reboots the watch: the console socket goes with it and
    # the log stream does not reconnect, so anything after it loses console.saw().
    ("notification_hidden_while_locked", test_notification_hidden_while_locked),
]


def main():
    global VERBOSE, BUILD, SHOT_DIR
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--only", action="append", help="run only these tests")
    ap.add_argument(
        "-b", "--build-dir", metavar="DIR",
        help="the build QEMU is running (default: the one `pbl` would use)",
    )
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    VERBOSE = args.verbose

    BUILD = BuildDir(args.build_dir or WORKSPACE.build_dir, REPO)
    BUILD.ensure_configured()
    SHOT_DIR = BUILD.join("security-lock-e2e")

    monitor_socket = BUILD.join(emulator.MONITOR_SOCKET)
    if not os.path.exists(monitor_socket):
        print(f"No QEMU monitor at {monitor_socket}. Start one with `pbl qemu`")
        return 2

    pad = PadGeometry.for_screen(BUILD)
    width, height, is_round = pad.screen
    print(f"{BUILD.board}: {width}x{height} {'round' if is_round else 'rectangular'}, "
          f"keypad keys {pad.key_w}x{pad.key_h}")
    console = Console()

    if not assert_booted(console):
        print("\nAborting: the watch is not up, so every result below would be noise.")
        return 2

    reset_to_known_state(console)

    for name, fn in TESTS:
        if args.only and name not in args.only:
            continue
        print(f"\n=== {name} ===", flush=True)
        try:
            # Back to a known screen; a test that left a half-finished PIN
            # entry up would otherwise poison every test after it.
            go_home(console)
            fn(console, pad)
        except TEST_FAILURES as exc:
            check(name + " (crashed)", False, repr(exc))

    console.close()

    passed = sum(1 for _, ok, _ in RESULTS if ok)
    failed = [n for n, ok, _ in RESULTS if not ok]
    print(f"\n{'=' * 60}\npassed {passed}/{len(RESULTS)}")
    for n in failed:
        print(f"  FAILED: {n}")
    if console.log_fault:
        print(f"  !! the log stream stopped mid-run: {console.log_fault}")
    print(f"screenshots: {SHOT_DIR}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
