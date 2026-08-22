#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Core Devices LLC
# SPDX-License-Identifier: Apache-2.0

"""A long-running daemon that owns the connection to a watch running in QEMU.

Why this exists
---------------
PULSE allows exactly one connection to the console port, so every tool that
wants to talk to the watch has to tear its connection down before the next one
can start. The result is that log lines are dropped between commands -- which
is precisely where an intermittent boot hang lives -- and that a dead link
surfaces as a PULSE traceback (`AttributeError: 'NoneType' object has no
attribute 'recv'`) several steps after the thing that actually broke.

This harness keeps one connection open for its whole lifetime. A supervisor
thread reconnects when the link dies and bumps `link_generation` so callers can
tell. Log capture runs in its own thread and never stops, not even while a
prompt command is in flight. Clients ask one-shot questions over a UNIX socket
and get structured JSON back; failures come back as `{"ok": false, "reason":
...}`, never as a traceback.

Starting it
-----------
QEMU first (this is not started for you)::

    export PEBBLE_QEMU_BIN=~/.pebble-sdk/SDKs/4.33.1/toolchain/bin/qemu-pebble
    ./pbl qemu &

Then the daemon, in the background, using the repo venv's python::

    ~/pblvenv/bin/python tools/pebble_harness.py serve &

Worked example
--------------
::

    $ python tools/pebble_harness.py ping --text
    link_up=True gen=1 qemu=True logs=412 last_log_age=0.4s

    $ python tools/pebble_harness.py health --text
    ok: prompt answered in 63 ms

    $ python tools/pebble_harness.py screen --text
    top_window   TicToc
    security     state=0 pin_len=0 attempts=0 shred_pending=0 lock_in=-1 ...
    windows      TicToc @0x2005041c
    screenshot   build/harness/screen-1787339000.png

    $ M=$(python tools/pebble_harness.py mark | python -c 'import json,sys;
                                  print(json.load(sys.stdin)["seq"])')
    $ python tools/pebble_harness.py press select
    $ python tools/pebble_harness.py wait 'launcher' --since $M --timeout 10
    $ python tools/pebble_harness.py logs --since $M --text

Every client subcommand prints JSON to stdout and exits nonzero when `ok` is
false. `--text` renders the same answer compactly for a human.

Sharing QEMU with other tools
-----------------------------
The PULSE console port allows one connection, so nothing else may talk to it
while the daemon runs -- that includes `./pbl console` and anything that builds
its own `pulse2.Interface`. Ask this daemon instead.

QEMU's QMP socket also serves one client at a time, so the daemon releases it
after `QMP_IDLE_RELEASE_S` of inactivity; `./pbl touch` and `./pbl swipe` work
normally between bursts, but will block if they land mid-burst.

The HMP monitor socket (screenshots, buttons) is opened per call and is not
held, so it never conflicts.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from collections import deque

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD_DIR = os.path.join(REPO, "build")
MON_SOCK = os.path.join(BUILD_DIR, "qemu-mon.sock")
QMP_SOCK = os.path.join(BUILD_DIR, "qmp.sock")
SHOT_DIR = os.path.join(BUILD_DIR, "harness")
DEFAULT_HARNESS_SOCK = os.path.join(BUILD_DIR, "harness.sock")
DEFAULT_TTY = "socket://localhost:12345"
CONSOLE_PORT = 12345
LOGHASH_DICT = os.path.join(BUILD_DIR, "src", "fw", "loghash_dict.json")

#: How the harness decides the firmware is up. There is no generic
#: boot-complete signal from the firmware, so we poll a console command that
#: only answers once the system is running. Point this at another command (and
#: its expected reply shape) if the security feature ever goes away.
READINESS_COMMAND = "security status"
READINESS_PATTERN = re.compile(r"\bstate=")

#: Raised to DEBUG after every (re)connect; the interesting lifecycle logging
#: is below the default level.
LOG_LEVEL_COMMAND = "log level set 200"

LOG_RING_SIZE = 20000
PROMPT_TIMEOUT_S = 20.0
LINK_WAIT_S = 45.0
QMP_ABS_MAX = 32767  # QEMU absolute-axis range for input-send-event
BUTTON_KEYS = {"back": "left", "select": "right", "up": "up", "down": "down"}
INVALID_COMMAND_RE = re.compile(r"^Invalid command .*Try 'help'")

#: LogDehash.commander_format_line() appends a colour reset even when built
#: with color=False, so the formatted line always carries an escape sequence.
#: These go into JSON and into regexes, so strip them.
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

sys.path.insert(0, os.path.join(REPO, "tools"))
sys.path.insert(0, os.path.join(REPO, "tools", "libs"))


# --- parsing the firmware's replies -----------------------------------------


KEY_RE = re.compile(r"(\w+)=")


def _coerce(value):
    try:
        return int(value)
    except ValueError:
        return value


def scan_kv(line):
    """Split one `key=value` line, tolerating values that contain spaces.

    `security status` is all bare integers, but `security ui` mixes three
    shapes on one line::

        visible=1 top_modal=PIN Entry pin_len=4 title="Enter PIN" message=""

    `title`/`message` are quoted and may contain anything; `top_modal` is a
    window debug name that is *not* quoted and still contains spaces. So a
    quoted value runs to its closing quote, and a bare one runs to the last
    space before the next `key=`.
    """
    out = {}
    pos = 0
    while True:
        match = KEY_RE.search(line, pos)
        if not match:
            return out
        key, start = match.group(1), match.end()
        if start < len(line) and line[start] == '"':
            end = line.find('"', start + 1)
            if end == -1:  # unterminated: take the rest
                out[key] = line[start + 1 :]
                return out
            out[key] = line[start + 1 : end]
            pos = end + 1
            continue
        following = KEY_RE.search(line, start)
        if following:
            end = line.rfind(" ", start, following.start())
            if end == -1:
                end = following.start()
        else:
            end = len(line)
        out[key] = _coerce(line[start:end].strip())
        pos = end


def parse_kv(lines):
    """Pull `key=value` pairs out of the first line that has any. Values that
    look like integers come back as integers so callers can compare directly."""
    for line in lines:
        pairs = scan_kv(line)
        if pairs:
            return pairs
    return None


WINDOW_RE = re.compile(r"window\s+(0x[0-9a-fA-F]+)\s+<([^>]*)>")
PRIORITY_RE = re.compile(r"Priority:\s*(\d+)")


def parse_window_stack(lines):
    """`window stack` -> [{addr, name}], top first."""
    return [
        {"addr": addr, "name": name}
        for addr, name in (m.groups() for m in map(WINDOW_RE.search, lines) if m)
    ]


def parse_modal_stack(lines):
    """`modal stack` -> {priority: [{addr, name}]}, top first within a priority."""
    stacks = {}
    priority = None
    for line in lines:
        prio_match = PRIORITY_RE.search(line)
        if prio_match:
            priority = prio_match.group(1)
            stacks.setdefault(priority, [])
            continue
        win_match = WINDOW_RE.search(line)
        if win_match and priority is not None:
            stacks[priority].append(
                {"addr": win_match.group(1), "name": win_match.group(2)}
            )
    return stacks


#: ModalPriorityDiscreet in src/fw/kernel/ui/modals/modal_manager.h: watchface
#: overlays such as Timeline Peek, which deliberately do not obstruct the app
#: below. A discreet modal is on top but is not what the user is looking at.
DISCREET_MODAL_PRIORITY = 0


def top_modal(modal_stack):
    """The topmost modal window of any priority, discreet included."""
    for priority in sorted(modal_stack, key=int, reverse=True):
        if modal_stack[priority]:
            return modal_stack[priority][0]
    return None


def top_window_name(window_stack, modal_stack):
    """What the user is actually looking at: the highest obstructing modal, or
    the top of the app window stack if only discreet overlays are up."""
    for priority in sorted(modal_stack, key=int, reverse=True):
        if int(priority) <= DISCREET_MODAL_PRIORITY:
            break
        if modal_stack[priority]:
            return modal_stack[priority][0]["name"]
    if window_stack:
        return window_stack[0]["name"]
    modal = top_modal(modal_stack)
    return modal["name"] if modal else None


def is_invalid_command(lines):
    """A command the firmware does not know about. Soft failure, not an error."""
    return any(INVALID_COMMAND_RE.match(line.strip()) for line in lines)


# --- QEMU: process, monitor, QMP --------------------------------------------


def find_qemu_pids():
    """PIDs of qemu-pebble instances launched from this repo checkout."""
    pids = []
    try:
        entries = os.listdir("/proc")
    except OSError:
        return pids
    for entry in entries:
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/cmdline", "rb") as handle:
                argv = handle.read().decode("utf8", "replace").split("\0")
        except OSError:
            continue
        if not argv or os.path.basename(argv[0]) != "qemu-pebble":
            continue  # argv[0], not a substring: shells that spawned it do not count
        # Only ours: another worktree's QEMU must not be touched.
        if any(REPO in arg for arg in argv[1:]):
            pids.append(int(entry))
    return pids


def qemu_running():
    return bool(find_qemu_pids()) and os.path.exists(MON_SOCK)


def monitor_command(command, timeout=8.0):
    """Run one HMP command on build/qemu-mon.sock.

    A fresh connection per call, deliberately: the HMP prompt framing makes a
    shared persistent connection fiddly, and these calls are rare compared to
    prompt commands and log traffic.
    """
    if not os.path.exists(MON_SOCK):
        raise HarnessError("qemu_monitor_missing", f"no monitor socket at {MON_SOCK}")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect(MON_SOCK)
        except OSError as exc:
            raise HarnessError("qemu_monitor_unreachable", str(exc))

        def drain():
            buf = b""
            deadline = time.time() + timeout
            while b"(qemu) " not in buf and time.time() < deadline:
                try:
                    chunk = sock.recv(4096)
                except TimeoutError:
                    break
                except OSError as exc:
                    raise HarnessError("qemu_monitor_io", str(exc))
                if not chunk:
                    break
                buf += chunk
            return buf.decode("utf8", "replace")

        drain()
        try:
            sock.sendall((command + "\n").encode())
        except OSError as exc:
            raise HarnessError("qemu_monitor_io", str(exc))
        return drain()


#: QEMU's QMP UNIX socket serves one client at a time, so holding it open
#: forever would make `./pbl touch` hang for as long as the daemon runs. Keep
#: it for the length of a burst (typing a PIN is four taps) and drop it when
#: idle. The expensive part -- the QOM tree walk for the touch geometry -- is
#: cached for the daemon's whole life either way.
QMP_IDLE_RELEASE_S = 5.0


class QmpClient:
    """Cached QMP connection plus the resolved touch-device geometry.

    `./pbl touch` reconnects and re-walks the QOM tree on every tap; both are
    cached here, which is nearly all of the per-tap cost.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._stream = None
        self._sock = None
        self._last_use = 0.0
        self.size = None
        self._reaper = threading.Thread(
            target=self._reap_idle, name="harness-qmp-reaper", daemon=True
        )
        self._reaper.start()

    def _reap_idle(self):
        while True:
            time.sleep(1.0)
            with self._lock:
                idle = time.time() - self._last_use
                if self._stream is not None and idle > QMP_IDLE_RELEASE_S:
                    self._disconnect()

    def _cmd(self, obj):
        self._stream.write(json.dumps(obj) + "\n")
        self._stream.flush()
        return json.loads(self._stream.readline())

    def _connect(self):
        if not os.path.exists(QMP_SOCK):
            raise HarnessError("qmp_missing", f"no QMP socket at {QMP_SOCK}")
        sock = socket.socket(socket.AF_UNIX)
        sock.settimeout(5)
        try:
            sock.connect(QMP_SOCK)
        except OSError as exc:
            raise HarnessError("qmp_unreachable", str(exc))
        stream = sock.makefile("rw")
        stream.readline()  # greeting
        self._sock, self._stream = sock, stream
        self._cmd({"execute": "qmp_capabilities"})
        if self.size is None:  # the QOM walk survives reconnects
            self.size = self._find_touch_display()

    def _find_touch_display(self):
        stack = ["/machine"]
        while stack:
            path = stack.pop()
            listing = self._cmd(
                {"execute": "qom-list", "arguments": {"path": path}}
            ).get("return", [])
            for entry in listing:
                if not entry.get("type", "").startswith("child<"):
                    continue
                child = path + "/" + entry["name"]
                name = entry["name"].lower()
                kind = entry.get("type", "").lower()
                if "touch" in name or "touch" in kind:
                    width = self._cmd(
                        {
                            "execute": "qom-get",
                            "arguments": {"path": child, "property": "display-width"},
                        }
                    )["return"]
                    height = self._cmd(
                        {
                            "execute": "qom-get",
                            "arguments": {"path": child, "property": "display-height"},
                        }
                    )["return"]
                    return (width, height)
                stack.append(child)
        raise HarnessError("qmp_no_touch_device", "pebble-touch not found in QOM tree")

    def _disconnect(self):
        """Drop the socket, keep the geometry."""
        for obj in (self._stream, self._sock):
            try:
                if obj is not None:
                    obj.close()
            except OSError:
                pass
        self._stream = self._sock = None

    def close(self):
        """Drop everything, including the geometry (QEMU is going away)."""
        self._disconnect()
        self.size = None

    def _ensure(self):
        if self._stream is None:
            self._connect()
        self._last_use = time.time()

    def _abs_events(self, px, py):
        width, height = self.size
        return [
            {
                "type": "abs",
                "data": {"axis": "x", "value": int(px / width * QMP_ABS_MAX)},
            },
            {
                "type": "abs",
                "data": {"axis": "y", "value": int(py / height * QMP_ABS_MAX)},
            },
        ]

    def _send(self, events):
        self._cmd({"execute": "input-send-event", "arguments": {"events": events}})

    def _with_retry(self, action):
        """QEMU restarts underneath us; one silent reconnect, then give up."""
        with self._lock:
            for attempt in (0, 1):
                try:
                    self._ensure()
                    result = action()
                    self._last_use = time.time()
                    return result
                except HarnessError:
                    self.close()
                    if attempt:
                        raise
                except (OSError, ValueError) as exc:
                    self.close()
                    if attempt:
                        raise HarnessError("qmp_io", str(exc))
        return None

    def tap(self, x, y):
        def action():
            down = [{"type": "btn", "data": {"button": "left", "down": True}}]
            self._send(self._abs_events(x, y) + down)
            time.sleep(0.05)
            self._send([{"type": "btn", "data": {"button": "left", "down": False}}])
            return {"size": list(self.size)}

        return self._with_retry(action)

    def swipe(self, x1, y1, x2, y2, steps=12, duration=0.25):
        def action():
            down = [{"type": "btn", "data": {"button": "left", "down": True}}]
            self._send(self._abs_events(x1, y1) + down)
            dt = duration / max(1, steps)
            for i in range(1, max(1, steps) + 1):
                px = x1 + (x2 - x1) * i // steps
                py = y1 + (y2 - y1) * i // steps
                self._send(self._abs_events(px, py))
                time.sleep(dt)
            self._send([{"type": "btn", "data": {"button": "left", "down": False}}])
            return {"size": list(self.size)}

        return self._with_retry(action)


def take_screenshot(path=None):
    """Ask QEMU to write a PNG. QEMU does the writing, so the path is absolute."""
    if path is None:
        os.makedirs(SHOT_DIR, exist_ok=True)
        path = os.path.join(SHOT_DIR, f"screen-{int(time.time() * 1000)}.png")
    path = os.path.abspath(path)
    if os.path.exists(path):
        try:
            os.unlink(path)
        except OSError:
            pass
    response = monitor_command(f"screendump {path} -f png")
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        raise HarnessError(
            "screendump_failed",
            f"QEMU wrote nothing to {path}: {response[-200:]}",
        )
    return path


def screenshot_fingerprint(path):
    with open(path, "rb") as handle:
        return hashlib.md5(handle.read()).hexdigest()


# --- errors -----------------------------------------------------------------


class HarnessError(Exception):
    """Anything the daemon knows how to explain. Never escapes as a traceback."""

    def __init__(self, reason, detail=""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail

    def as_response(self):
        return {"ok": False, "reason": self.reason, "detail": self.detail}


# --- the watch connection ---------------------------------------------------


class WatchLink:
    """Sole owner of the PULSE console connection.

    One `pulse2.Interface`, one log-pump thread, one supervisor that notices a
    dead link and rebuilds both. `link_generation` increments on every
    successful (re)connect so callers can tell "still the same session" from
    "it rebooted while you were not looking".
    """

    def __init__(self, tty=DEFAULT_TTY, on_event=None):
        self.tty = tty
        self.link_generation = 0
        self.link_up = False
        self.last_fault = None

        self._on_event = on_event or (lambda msg: None)
        self._iface = None
        self._logs_app = None
        self._prompt_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._log_cond = threading.Condition()
        self._ring = deque(maxlen=LOG_RING_SIZE)
        self._seq = 0
        self._last_log_ts = None
        self._pump = None
        self._running = True
        self._paused = False
        self._dehasher = self._make_dehasher()

        threading.excepthook = self._thread_excepthook
        self._supervisor = threading.Thread(
            target=self._supervise, name="harness-supervisor", daemon=True
        )
        self._supervisor.start()

    # -- log formatting ------------------------------------------------------

    @staticmethod
    def _make_dehasher():
        """LogDehash even on boards that do not hash: it is a passthrough when
        the dictionary is missing, and boards that do hash need it."""
        try:
            from log_hashing.logdehash import LogDehash

            return LogDehash(
                dict_path=LOGHASH_DICT,
                justify="small",
                color=False,
                bold=-1,
                print_core=False,
                monitor_dict_file=False,
            )
        except Exception:
            return None

    def _format(self, msg):
        text = None
        if self._dehasher is not None:
            try:
                text = self._dehasher.commander_format_line(self._dehasher.dehash(msg))
            except Exception:
                text = None
        if text is None:
            text = str(msg)
        return ANSI_RE.sub("", text).rstrip()

    # -- fault plumbing ------------------------------------------------------

    def _thread_excepthook(self, args):
        """pulse2's receive loop can die on `AttributeError: 'NoneType' object
        has no attribute 'recv'` when the socket goes away underneath pyserial.
        Record it and let the supervisor rebuild rather than printing a
        traceback that reaches a client."""
        self.last_fault = f"{args.exc_type.__name__}: {args.exc_value}"
        self._on_event(f"thread fault in {args.thread}: {self.last_fault}")
        with self._state_lock:
            self.link_up = False

    # -- connection lifecycle ------------------------------------------------

    def _console_accepting(self):
        try:
            with socket.create_connection(("localhost", CONSOLE_PORT), timeout=1.0):
                return True
        except OSError:
            return False

    def _teardown(self):
        with self._state_lock:
            self.link_up = False
        iface, self._iface = self._iface, None
        self._logs_app = None
        if iface is not None:
            try:
                iface.close()
            except Exception:
                pass

    def _connect_once(self):
        from pebble import commander, pulse2

        iface = pulse2.Interface.open_dbgserial(url=self.tty)
        deadline = time.time() + LINK_WAIT_S
        link = None
        while time.time() < deadline:
            if iface.closed or not iface.receive_thread.is_alive():
                break
            link = iface.get_link(timeout=1.0)
            if link is not None:
                break
        if link is None:
            try:
                iface.close()
            except Exception:
                pass
            raise HarnessError("link_negotiation_failed", "LCP did not come up")

        self._iface = iface
        self._logs_app = commander.apps.StreamingLogs(iface)
        with self._state_lock:
            self.link_generation += 1
            self.link_up = True
            self.last_fault = None
        generation = self.link_generation
        self._pump = threading.Thread(
            target=self._pump_logs,
            args=(generation,),
            name=f"harness-logs-{generation}",
            daemon=True,
        )
        self._pump.start()
        self._on_event(f"link up (generation {generation})")
        try:
            self.prompt(LOG_LEVEL_COMMAND, timeout=5.0)
        except HarnessError as exc:
            self._on_event(f"log level set failed: {exc.reason}")

    def _link_healthy(self):
        iface = self._iface
        if iface is None or iface.closed:
            return False
        if not iface.receive_thread.is_alive():
            return False
        if self._pump is not None and not self._pump.is_alive():
            return False
        return self.link_up

    def _supervise(self):
        while self._running:
            try:
                if self._paused:
                    if self._iface is not None:
                        self._teardown()
                    time.sleep(0.3)
                    continue
                if self._link_healthy():
                    time.sleep(0.5)
                    continue
                if self._iface is not None:
                    self._on_event(f"link down ({self.last_fault}); reconnecting")
                    self._teardown()
                # Reconnect the instant the port accepts, so the boot-time log
                # burst -- the whole point of this harness -- is not missed.
                if not self._console_accepting():
                    time.sleep(0.3)
                    continue
                self._connect_once()
            except HarnessError as exc:
                self.last_fault = exc.reason
                self._teardown()
                time.sleep(1.0)
            except Exception as exc:  # never let the supervisor die
                self.last_fault = f"{type(exc).__name__}: {exc}"
                self._teardown()
                time.sleep(1.0)

    def pause(self):
        """Release the console port (QEMU is about to be restarted)."""
        self._paused = True
        deadline = time.time() + 5.0
        while self._iface is not None and time.time() < deadline:
            time.sleep(0.1)
        self._teardown()

    def resume(self):
        self._paused = False

    def stop(self):
        self._running = False
        self._teardown()

    # -- logs ----------------------------------------------------------------

    def _pump_logs(self, generation):
        """Never stops while a prompt command runs. That is the whole point."""
        from pebble import pulse2

        app = self._logs_app
        while self._running and generation == self.link_generation:
            try:
                msg = app.receive(block=True, timeout=1.0)
            except pulse2.exceptions.ReceiveQueueEmpty:
                continue
            except pulse2.exceptions.SocketClosed:
                self.last_fault = "log socket closed"
                with self._state_lock:
                    self.link_up = False
                return
            except Exception as exc:
                self.last_fault = f"{type(exc).__name__}: {exc}"
                with self._state_lock:
                    self.link_up = False
                return
            self._append_log(self._format(msg))

    def _append_log(self, text):
        with self._log_cond:
            self._seq += 1
            self._last_log_ts = time.time()
            self._ring.append({"seq": self._seq, "ts": self._last_log_ts, "text": text})
            self._log_cond.notify_all()

    def mark(self):
        with self._log_cond:
            return self._seq

    def log_count(self):
        with self._log_cond:
            return self._seq

    def last_log_age(self):
        with self._log_cond:
            if self._last_log_ts is None:
                return None
            return round(time.time() - self._last_log_ts, 3)

    def logs(self, since=None, pattern=None, tail=None):
        with self._log_cond:
            entries = list(self._ring)
        if since is not None:
            entries = [e for e in entries if e["seq"] > since]
        if pattern is not None:
            entries = [e for e in entries if pattern.search(e["text"])]
        if tail:
            entries = entries[-tail:]
        return entries

    def wait_for(self, pattern, timeout=30.0, since=None):
        """Block until a log line after `since` matches.

        Without `since` only lines that arrive from now on count, so a stale
        match from an earlier step cannot satisfy the wait by accident. Pass a
        cursor from `mark` to include lines already buffered since then.
        """
        started = time.time()
        deadline = started + timeout
        with self._log_cond:
            cursor = self._seq if since is None else int(since)
            while True:
                for entry in self._ring:
                    if entry["seq"] <= cursor:
                        continue
                    if pattern.search(entry["text"]):
                        return entry, round(time.time() - started, 3)
                    cursor = entry["seq"]
                remaining = deadline - time.time()
                if remaining <= 0:
                    return None, round(time.time() - started, 3)
                self._log_cond.wait(min(remaining, 0.5))

    # -- prompt --------------------------------------------------------------

    def prompt(self, command, timeout=PROMPT_TIMEOUT_S):
        """One console command. Serialized: two prompts on one link corrupt
        each other. A fresh Prompt per command, as tools/pulse_console.py does.
        """
        from pebble import commander

        with self._prompt_lock:
            iface = self._iface
            if iface is None or iface.closed:
                raise HarnessError("link_down", "no PULSE link to the watch")
            link = iface.get_link(timeout=2.0)
            if link is None:
                raise HarnessError("link_down", "PULSE link not negotiated")
            try:
                prompt = commander.apps.Prompt(link)
            except Exception as exc:
                raise HarnessError("prompt_open_failed", str(exc))
            try:
                return list(prompt.command_and_response(command, timeout=timeout))
            except commander.exceptions.CommandTimedOut:
                raise HarnessError(
                    "prompt_timeout",
                    f"{command!r} got no reply in {timeout:g}s",
                )
            except Exception as exc:
                with self._state_lock:
                    self.link_up = False
                raise HarnessError("prompt_failed", f"{type(exc).__name__}: {exc}")
            finally:
                try:
                    prompt.close()
                except Exception:
                    pass

    def try_prompt(self, command, timeout=PROMPT_TIMEOUT_S):
        """Prompt that never raises: (lines, error_reason_or_None)."""
        try:
            return self.prompt(command, timeout=timeout), None
        except HarnessError as exc:
            return [], exc.reason


# --- the daemon -------------------------------------------------------------


class Harness:
    def __init__(self, sock_path, tty):
        self.sock_path = sock_path
        self.tty = tty
        self.started_at = time.time()
        self.qmp = QmpClient()
        self.watch = WatchLink(tty=tty, on_event=self._event)
        self._stop = threading.Event()
        self._kill_qemu_on_exit = False
        self._boot_lock = threading.Lock()

    def _event(self, message):
        print(f"[harness] {message}", flush=True)

    # -- request handlers ----------------------------------------------------

    def handle(self, request):
        command = request.get("cmd")
        args = request.get("args") or {}
        handler = getattr(self, "do_" + str(command).replace("-", "_"), None)
        if handler is None:
            return {
                "ok": False,
                "reason": "unknown_command",
                "detail": str(command),
                "known": sorted(
                    name[3:] for name in dir(self) if name.startswith("do_")
                ),
            }
        try:
            return handler(args)
        except HarnessError as exc:
            return exc.as_response()
        except Exception as exc:  # structured, never a traceback
            return {
                "ok": False,
                "reason": "internal_error",
                "detail": f"{type(exc).__name__}: {exc}",
            }

    def do_ping(self, args):
        return {
            "ok": True,
            "link_up": self.watch.link_up,
            "link_generation": self.watch.link_generation,
            "qemu_running": qemu_running(),
            "log_count": self.watch.log_count(),
            "last_log_age_s": self.watch.last_log_age(),
            "last_fault": self.watch.last_fault,
            "uptime_s": round(time.time() - self.started_at, 1),
        }

    def do_prompt(self, args):
        command = args.get("command")
        if not command:
            raise HarnessError("bad_request", "prompt needs a command string")
        timeout = float(args.get("timeout") or PROMPT_TIMEOUT_S)
        started = time.time()
        lines = self.watch.prompt(command, timeout=timeout)
        return {
            "ok": True,
            "lines": lines,
            "elapsed_ms": int((time.time() - started) * 1000),
            "invalid_command": is_invalid_command(lines),
        }

    def do_mark(self, args):
        return {"ok": True, "seq": self.watch.mark()}

    def do_logs(self, args):
        pattern = None
        if args.get("grep"):
            try:
                pattern = re.compile(args["grep"])
            except re.error as exc:
                raise HarnessError("bad_regex", str(exc))
        since = args.get("since")
        tail = args.get("tail")
        entries = self.watch.logs(
            since=int(since) if since is not None else None,
            pattern=pattern,
            tail=int(tail) if tail else None,
        )
        return {"ok": True, "lines": entries, "count": len(entries)}

    def do_wait(self, args):
        expr = args.get("pattern")
        if not expr:
            raise HarnessError("bad_request", "wait needs a regex")
        try:
            pattern = re.compile(expr)
        except re.error as exc:
            raise HarnessError("bad_regex", str(exc))
        since = args.get("since")
        entry, waited = self.watch.wait_for(
            pattern,
            timeout=float(args.get("timeout") or 30.0),
            since=int(since) if since is not None else None,
        )
        if entry is None:
            return {
                "ok": False,
                "reason": "timeout",
                "matched": False,
                "pattern": expr,
                "waited_s": waited,
            }
        return {
            "ok": True,
            "matched": True,
            "line": entry["text"],
            "seq": entry["seq"],
            "waited_s": waited,
        }

    def do_screen(self, args):
        """One composite snapshot of what the watch is showing right now."""
        status_lines, status_err = self.watch.try_prompt("security status")
        ui_lines, _ui_err = self.watch.try_prompt("security ui")
        win_lines, win_err = self.watch.try_prompt("window stack")
        modal_lines, _modal_err = self.watch.try_prompt("modal stack")

        if status_err and win_err:
            raise HarnessError(status_err, "watch is not answering the console")

        window_stack = parse_window_stack(win_lines)
        modal_stack = parse_modal_stack(modal_lines)
        # `security ui` is added by a parallel workstream; absent is fine.
        security_ui = None
        if ui_lines and not is_invalid_command(ui_lines):
            security_ui = parse_kv(ui_lines)

        shot = None
        shot_error = None
        if not args.get("no_shot"):
            try:
                shot = take_screenshot(args.get("out"))
            except HarnessError as exc:
                shot_error = exc.reason

        return {
            "ok": True,
            "security_status": parse_kv(status_lines),
            "security_ui": security_ui,
            "window_stack": window_stack,
            "modal_stack": {p: w for p, w in modal_stack.items() if w},
            "modal_stack_empty_priorities": sorted(
                (p for p, w in modal_stack.items() if not w), key=int, reverse=True
            ),
            "top_window": top_window_name(window_stack, modal_stack),
            "top_modal": top_modal(modal_stack),
            "screenshot": shot,
            "screenshot_error": shot_error,
            "link_generation": self.watch.link_generation,
            "prompt_errors": {
                k: v
                for k, v in {
                    "security status": status_err,
                    "window stack": win_err,
                }.items()
                if v
            },
        }

    def do_screenshot(self, args):
        return {"ok": True, "path": take_screenshot(args.get("out"))}

    def do_touch(self, args):
        result = self.qmp.tap(int(args["x"]), int(args["y"]))
        return {"ok": True, "x": int(args["x"]), "y": int(args["y"]), **(result or {})}

    def do_swipe(self, args):
        result = self.qmp.swipe(
            int(args["x1"]),
            int(args["y1"]),
            int(args["x2"]),
            int(args["y2"]),
            steps=int(args.get("steps") or 12),
            duration=float(args.get("duration") or 0.25),
        )
        return {"ok": True, **(result or {})}

    def do_press(self, args):
        button = args.get("button")
        if button not in BUTTON_KEYS:
            raise HarnessError(
                "bad_request", f"button must be one of {sorted(BUTTON_KEYS)}"
            )
        monitor_command(f"sendkey {BUTTON_KEYS[button]}")
        return {"ok": True, "button": button, "key": BUTTON_KEYS[button]}

    def do_health(self, args):
        """Exactly one of: ok / watch_hung / link_down / qemu_dead.

        When it is not ok, two screenshots four seconds apart say whether the
        display is still moving. Frozen display + silent console is the boot
        hang; moving display + silent console means the UI task is alive and
        only the console is wedged.
        """
        pids = find_qemu_pids()
        if not pids or not os.path.exists(MON_SOCK):
            return {
                "ok": False,
                "status": "qemu_dead",
                "reason": "qemu_dead",
                "detail": "no qemu-pebble process for this checkout"
                if not pids
                else f"monitor socket {MON_SOCK} is gone",
                "qemu_pids": pids,
                "link_up": self.watch.link_up,
                "display": None,
                "verdict": "QEMU is not running; nothing to diagnose on the watch.",
            }

        if not self.watch.link_up:
            status, detail = "link_down", self.watch.last_fault or "LCP never came up"
        else:
            started = time.time()
            lines, err = self.watch.try_prompt(
                READINESS_COMMAND, timeout=float(args.get("timeout") or 8.0)
            )
            elapsed_ms = int((time.time() - started) * 1000)
            if err == "prompt_timeout":
                status, detail = (
                    "watch_hung",
                    f"{READINESS_COMMAND!r} timed out",
                )
            elif err:
                status, detail = "link_down", err
            elif any(READINESS_PATTERN.search(line) for line in lines):
                return {
                    "ok": True,
                    "status": "ok",
                    "qemu_pids": pids,
                    "link_up": True,
                    "link_generation": self.watch.link_generation,
                    "prompt_ms": elapsed_ms,
                    "readiness_command": READINESS_COMMAND,
                    "lines": lines,
                    "display": None,
                    "verdict": f"ok: prompt answered in {elapsed_ms} ms",
                }
            else:
                status, detail = (
                    "watch_hung",
                    f"{READINESS_COMMAND!r} answered but not with {READINESS_PATTERN.pattern}",
                )

        display = self._display_fingerprint(gap=float(args.get("gap") or 4.0))
        return {
            "ok": False,
            "status": status,
            "reason": status,
            "detail": detail,
            "qemu_pids": pids,
            "link_up": self.watch.link_up,
            "link_generation": self.watch.link_generation,
            "last_fault": self.watch.last_fault,
            "last_log_age_s": self.watch.last_log_age(),
            "display": display,
            "verdict": self._verdict(status, display),
        }

    def _display_fingerprint(self, gap=4.0):
        """Two screendumps `gap` apart, MD5'd. Is the display moving at all?"""
        try:
            os.makedirs(SHOT_DIR, exist_ok=True)
            first = take_screenshot(os.path.join(SHOT_DIR, "health-a.png"))
            digest_a = screenshot_fingerprint(first)
            time.sleep(gap)
            second = take_screenshot(os.path.join(SHOT_DIR, "health-b.png"))
            digest_b = screenshot_fingerprint(second)
        except HarnessError as exc:
            return {"error": exc.reason, "detail": exc.detail}
        return {
            "gap_s": gap,
            "md5_a": digest_a,
            "md5_b": digest_b,
            "changing": digest_a != digest_b,
            "paths": [first, second],
        }

    @staticmethod
    def _verdict(status, display):
        if status == "link_down":
            return "link_down: PULSE will not negotiate on the console port."
        changing = (display or {}).get("changing")
        gap = (display or {}).get("gap_s")
        if status == "watch_hung" and changing is False:
            return (
                "watch_hung: console silent and the display did not change over "
                f"{gap}s -- the boot-hang signature. Caveat: a watchface that only "
                "redraws once a minute also reads FROZEN, so raise --gap above "
                "60 before concluding from an idle watchface."
            )
        if status == "watch_hung" and changing is True:
            return (
                "watch_hung: console silent but the display IS still updating -- "
                "the UI task is alive, only the console is wedged."
            )
        return status

    def do_boot(self, args):
        """Relaunch QEMU and capture the boot logs. Cold rebuilds the SPI flash
        image, warm keeps it."""
        if not self._boot_lock.acquire(blocking=False):
            raise HarnessError("boot_in_progress", "another boot is already running")
        try:
            return self._boot(args)
        finally:
            self._boot_lock.release()

    def _boot(self, args):
        warm = bool(args.get("warm"))
        timeout = float(args.get("timeout") or 180.0)
        mark = self.watch.mark()

        # Let go of the console port before QEMU dies under us.
        self.watch.pause()
        self.qmp.close()
        killed = self._kill_qemu()

        for path in (MON_SOCK, QMP_SOCK):
            try:
                os.unlink(path)
            except OSError:
                pass

        env = dict(os.environ)
        env.setdefault(
            "PEBBLE_QEMU_BIN",
            os.path.expanduser(
                "~/.pebble-sdk/SDKs/4.33.1/toolchain/bin/qemu-pebble",
            ),
        )
        env["PATH"] = os.path.dirname(sys.executable) + os.pathsep + env.get("PATH", "")
        os.makedirs(SHOT_DIR, exist_ok=True)
        log_path = os.path.join(SHOT_DIR, "qemu-boot.log")
        cmd = [sys.executable, "./pbl", "qemu"]
        if warm:
            cmd.append("--keep-flash-image")
        started = time.time()
        with open(log_path, "wb") as log_file:
            proc = subprocess.Popen(
                cmd,
                cwd=REPO,
                env=env,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
            )

        # The supervisor reconnects as soon as the port accepts, which is what
        # gets the boot-time log burst into the ring.
        self.watch.resume()

        deadline = started + timeout
        ready_at = None
        while time.time() < deadline:
            if proc.poll() is not None and not find_qemu_pids():
                break
            if self.watch.link_up:
                lines, err = self.watch.try_prompt(READINESS_COMMAND, timeout=5.0)
                if not err and any(READINESS_PATTERN.search(ln) for ln in lines):
                    ready_at = time.time()
                    break
            time.sleep(1.0)

        boot_logs = self.watch.logs(since=mark)
        hung = ready_at is None
        return {
            "ok": not hung,
            "reason": None if not hung else "boot_timeout",
            "mode": "warm" if warm else "cold",
            "killed_pids": killed,
            "launcher_pid": proc.pid,
            "qemu_pids": find_qemu_pids(),
            "boot_time_s": round((ready_at or time.time()) - started, 2),
            "hung": hung,
            "link_generation": self.watch.link_generation,
            "launcher_log": log_path,
            "log_count": len(boot_logs),
            "logs": [entry["text"] for entry in boot_logs],
        }

    @staticmethod
    def _kill_qemu(timeout=10.0):
        pids = find_qemu_pids()
        for pid in pids:
            try:
                os.kill(pid, 15)
            except OSError:
                pass
        deadline = time.time() + timeout
        while time.time() < deadline and find_qemu_pids():
            time.sleep(0.2)
        for pid in find_qemu_pids():
            try:
                os.kill(pid, 9)
            except OSError:
                pass
        return pids

    def do_shutdown(self, args):
        self._kill_qemu_on_exit = bool(args.get("kill_qemu"))
        self._stop.set()
        return {"ok": True, "stopping": True, "kill_qemu": self._kill_qemu_on_exit}

    # -- socket server -------------------------------------------------------

    def serve(self):
        if os.path.exists(self.sock_path):
            if _daemon_alive(self.sock_path):
                raise HarnessError(
                    "daemon_already_running",
                    f"another harness owns {self.sock_path}",
                )
            os.unlink(self.sock_path)
        os.makedirs(os.path.dirname(self.sock_path) or ".", exist_ok=True)

        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind(self.sock_path)
        except OSError as exc:
            server.close()
            # AF_UNIX paths are capped at ~108 bytes, which a deep scratch
            # directory blows through easily.
            raise HarnessError("bind_failed", f"{self.sock_path}: {exc}")
        server.listen(16)
        server.settimeout(0.5)
        self._event(f"listening on {self.sock_path} (tty {self.tty})")

        try:
            while not self._stop.is_set():
                try:
                    conn, _ = server.accept()
                except TimeoutError:
                    continue
                except OSError as exc:
                    if exc.errno == errno.EINTR:
                        continue
                    raise
                threading.Thread(
                    target=self._serve_conn, args=(conn,), daemon=True
                ).start()
        except KeyboardInterrupt:
            pass
        finally:
            server.close()
            try:
                os.unlink(self.sock_path)
            except OSError:
                pass
            self.watch.stop()
            self.qmp.close()
            if self._kill_qemu_on_exit:
                self._event(f"killing QEMU: {self._kill_qemu()}")
            self._event("stopped")
        return 0

    def _serve_conn(self, conn):
        """One JSON request, one JSON response, then close."""
        with conn:
            conn.settimeout(600)
            try:
                buf = b""
                while b"\n" not in buf:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                if not buf.strip():
                    return
                request = json.loads(buf.decode("utf8"))
                response = self.handle(request)
            except TimeoutError:
                response = {"ok": False, "reason": "request_timeout"}
            except json.JSONDecodeError as exc:
                response = {"ok": False, "reason": "bad_json", "detail": str(exc)}
            except OSError as exc:
                return self._event(f"client I/O error: {exc}")
            try:
                conn.sendall((json.dumps(response) + "\n").encode())
            except OSError:
                pass


# --- client -----------------------------------------------------------------


def _daemon_alive(sock_path):
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(1.0)
            sock.connect(sock_path)
        return True
    except OSError:
        return False


def call(sock_path, cmd, args=None, timeout=600.0):
    """Send one request to the daemon. Returns a response dict, always."""
    payload = json.dumps({"cmd": cmd, "args": args or {}}) + "\n"
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(sock_path)
    except OSError as exc:
        start = f"{sys.executable} {os.path.relpath(os.path.abspath(__file__), os.getcwd())} serve --socket {sock_path} &"
        return {
            "ok": False,
            "reason": "daemon_not_running",
            "detail": f"{sock_path} ({exc.strerror or exc})",
            "hint": "start it with:  " + start,
        }
    with sock:
        try:
            sock.sendall(payload.encode())
            buf = b""
            while b"\n" not in buf:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buf += chunk
        except TimeoutError:
            return {"ok": False, "reason": "daemon_timeout", "detail": cmd}
        except OSError as exc:
            return {"ok": False, "reason": "daemon_io_error", "detail": str(exc)}
    if not buf.strip():
        return {"ok": False, "reason": "daemon_closed", "detail": "empty response"}
    try:
        return json.loads(buf.decode("utf8"))
    except json.JSONDecodeError as exc:
        return {"ok": False, "reason": "bad_response", "detail": str(exc)}


def _fmt_windows(windows):
    return ", ".join(f"{w['name']} @{w['addr']}" for w in windows)


def _fmt_kv(mapping):
    return " ".join(f"{k}={v}" for k, v in mapping.items())


def render_text(cmd, response):
    """Compact human rendering; the JSON stays the source of truth."""
    if not response.get("ok"):
        parts = [f"FAIL {cmd}: {response.get('reason', 'unknown')}"]
        for key in ("detail", "verdict", "hint"):
            if response.get(key):
                parts.append(f"  {response[key]}")
        if cmd == "health" and response.get("display"):
            parts.append(f"  display: {_fmt_display(response['display'])}")
        return "\n".join(parts)

    if cmd == "ping":
        return (
            f"link_up={response['link_up']} gen={response['link_generation']} "
            f"qemu={response['qemu_running']} logs={response['log_count']} "
            f"last_log_age={response['last_log_age_s']}s"
        )
    if cmd == "health":
        line = response.get("verdict", response.get("status", ""))
        if response.get("display"):
            line += f"\n  display: {_fmt_display(response['display'])}"
        return line
    if cmd == "prompt":
        return "\n".join([*response["lines"], f"({response['elapsed_ms']} ms)"])
    if cmd == "screen":
        rows = [f"top_window   {response.get('top_window')}"]
        status = response.get("security_status")
        if status:
            rows.append(f"security     {_fmt_kv(status)}")
        if response.get("security_ui"):
            rows.append(f"security_ui  {_fmt_kv(response['security_ui'])}")
        else:
            rows.append("security_ui  (not available)")
        rows.append(
            f"windows      {_fmt_windows(response['window_stack']) or '(none)'}"
        )
        for priority in sorted(response["modal_stack"], key=int, reverse=True):
            windows = _fmt_windows(response["modal_stack"][priority])
            rows.append(f"modal p{priority:<3}   {windows}")
        if not response["modal_stack"]:
            rows.append("modal        (none)")
        rows.append(f"screenshot   {response.get('screenshot')}")
        return "\n".join(rows)
    if cmd == "logs":
        return "\n".join(f"{e['seq']:6d} {e['text']}" for e in response["lines"])
    if cmd == "wait":
        return f"matched after {response['waited_s']}s: {response['line']}"
    if cmd == "mark":
        return str(response["seq"])
    if cmd == "boot":
        return (
            f"booted {response['mode']} in {response['boot_time_s']}s "
            f"(gen {response['link_generation']}, {response['log_count']} log lines)"
        )
    return " ".join(
        f"{k}={v}" for k, v in response.items() if k != "ok" and v is not None
    )


def _fmt_display(display):
    if display.get("error"):
        return f"unavailable ({display['error']})"
    state = "CHANGING" if display["changing"] else "FROZEN"
    return (
        f"{state} over {display['gap_s']}s "
        f"({display['md5_a'][:8]} -> {display['md5_b'][:8]})"
    )


# --- CLI --------------------------------------------------------------------


def build_parser():
    parser = argparse.ArgumentParser(
        prog="pebble_harness.py",
        description=__doc__.split("\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--socket",
        default=DEFAULT_HARNESS_SOCK,
        help="daemon control socket (default: %(default)s)",
    )
    sub = parser.add_subparsers(dest="subcommand", required=True)

    def client(name, help_text):
        p = sub.add_parser(name, help=help_text)
        p.add_argument(
            "--text", action="store_true", help="compact human-readable output"
        )
        return p

    p = sub.add_parser("serve", help="Run the daemon (owns the watch connection)")
    p.add_argument(
        "--tty", default=DEFAULT_TTY, help="PULSE console (default: %(default)s)"
    )

    client("ping", "Liveness and link state")

    p = client("prompt", "Run one firmware console command")
    p.add_argument("command", nargs="+", help="console command, e.g. 'security status'")
    p.add_argument("--timeout", type=float, default=PROMPT_TIMEOUT_S)

    p = client("screen", "Composite snapshot of what the watch is showing")
    p.add_argument("--no-shot", action="store_true", help="skip the screenshot")
    p.add_argument("--out", help="screenshot path (default: build/harness/)")

    client("mark", "Current log cursor")

    p = client("logs", "Captured log lines")
    p.add_argument("--since", type=int, help="only lines after this seq")
    p.add_argument("--grep", help="regex filter")
    p.add_argument("--tail", type=int, help="last N lines")

    p = client("wait", "Block until a log line matches a regex")
    p.add_argument("pattern")
    p.add_argument("--timeout", type=float, default=30.0)
    p.add_argument("--since", type=int)

    p = client("touch", "Inject a tap (screen pixels)")
    p.add_argument("x", type=int)
    p.add_argument("y", type=int)

    p = client("swipe", "Inject a swipe (screen pixels)")
    p.add_argument("x1", type=int)
    p.add_argument("y1", type=int)
    p.add_argument("x2", type=int)
    p.add_argument("y2", type=int)
    p.add_argument("--steps", type=int, default=12)
    p.add_argument("--duration", type=float, default=0.25)

    p = client("press", "Press a watch button")
    p.add_argument("button", choices=sorted(BUTTON_KEYS))

    p = client("screenshot", "Write a PNG of the display")
    p.add_argument("--out", help="output path (default: build/harness/)")

    p = client("health", "ok / watch_hung / link_down / qemu_dead, with evidence")
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument(
        "--gap",
        type=float,
        default=4.0,
        help="seconds between the two screenshots used as freeze evidence",
    )

    p = client("boot", "Relaunch QEMU and capture the boot logs")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--cold", action="store_true", help="rebuild the SPI flash image")
    mode.add_argument("--warm", action="store_true", help="keep the flash image")
    p.add_argument("--timeout", type=float, default=180.0)

    p = client("shutdown", "Stop the daemon")
    p.add_argument("--kill-qemu", action="store_true")

    return parser


def args_for(options):
    """Turn parsed CLI options into the daemon's `args` dict."""
    cmd = options.subcommand
    if cmd == "prompt":
        return {"command": " ".join(options.command), "timeout": options.timeout}
    if cmd == "screen":
        return {"no_shot": options.no_shot, "out": options.out}
    if cmd == "logs":
        return {"since": options.since, "grep": options.grep, "tail": options.tail}
    if cmd == "wait":
        return {
            "pattern": options.pattern,
            "timeout": options.timeout,
            "since": options.since,
        }
    if cmd == "touch":
        return {"x": options.x, "y": options.y}
    if cmd == "swipe":
        return {
            "x1": options.x1,
            "y1": options.y1,
            "x2": options.x2,
            "y2": options.y2,
            "steps": options.steps,
            "duration": options.duration,
        }
    if cmd == "press":
        return {"button": options.button}
    if cmd == "screenshot":
        return {"out": options.out}
    if cmd == "health":
        return {"timeout": options.timeout, "gap": options.gap}
    if cmd == "boot":
        return {"warm": bool(options.warm), "timeout": options.timeout}
    if cmd == "shutdown":
        return {"kill_qemu": options.kill_qemu}
    return {}


#: Client-side socket timeouts. `None` means "derive it from the options", so
#: the client always outlasts the work the daemon was asked to do.
CLIENT_TIMEOUTS = {"boot": None, "wait": None, "health": None}


def client_timeout(options):
    fixed = CLIENT_TIMEOUTS.get(options.subcommand, 120.0)
    if fixed is not None:
        return fixed
    slack = 30.0
    if options.subcommand == "health":
        return options.timeout + 2 * options.gap + slack
    return float(getattr(options, "timeout", 120.0)) + slack


def main(argv=None):
    options = build_parser().parse_args(argv)

    if options.subcommand == "serve":
        try:
            return Harness(options.socket, options.tty).serve()
        except HarnessError as exc:
            print(json.dumps(exc.as_response()))
            return 1
        except Exception as exc:  # a daemon must not die with a traceback
            print(
                json.dumps(
                    {
                        "ok": False,
                        "reason": "serve_failed",
                        "detail": f"{type(exc).__name__}: {exc}",
                    }
                )
            )
            return 1

    response = call(
        options.socket, options.subcommand, args_for(options), client_timeout(options)
    )

    if options.text:
        print(render_text(options.subcommand, response))
    else:
        print(json.dumps(response, indent=2))
    return 0 if response.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
