#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Core Devices LLC
# SPDX-License-Identifier: Apache-2.0

"""Hunt for a use-after-open race between the security shred and its targets.

The race
--------
`security_lock_shred()` wipes each file in `s_shred_targets` with
`pfs_shred()` (`src/fw/services/filesystem/pfs.c`), which zeroes the payload
and then calls `pfs_remove()`. `pfs_remove()` does not report "file is busy"
as an error -- it calls::

    PBL_CROAK("Cannot delete %s, it is currently in use", ...)

which is a fatal assert that resets the watch (`pfs.c`, the `FDBusy` branch of
`pfs_remove`). So *any* other task holding an open descriptor on a shred
target at that instant turns a privacy wipe into a reboot.

`prv_shred()` (`src/fw/services/security_lock/shred.c`) closes and reopens
`pin_db`, `reminder_db` and `timeline_event` around the wipe precisely to
avoid this. The other five targets get no such treatment: `notifstr`,
`contactsdb`, `weatherdb`, `iosnotifprefdb`, `appglancedb`. For `notifstr` in
particular, `notification_storage_reset_and_init()` runs *after* the wipe, not
before.

Why it is not obviously impossible
----------------------------------
`pfs_shred()` holds `s_pfs_mutex` from its first `pfs_open()` to its final
`pfs_remove()`, so a writer that stayed inside PFS for its whole operation
could never collide. But `notification_storage_store()` does not: it takes its
own `s_notif_storage_mutex`, calls `pfs_open()` (which takes and *releases*
`s_pfs_mutex`), then seeks and writes, then closes. Between that open and
close the descriptor is `FD_STATUS_IN_USE` while `s_pfs_mutex` is free. That
gap is the window. The `prv_compress()` path -- taken when the 30 KB file
fills -- rewrites the whole file inside that same gap, and is far wider.

The two sides also genuinely run on different tasks, which is what makes the
window reachable at all:

* console commands execute on **KernelBG** (`prompt.c` dispatches every
  command through `system_task_add_callback`), and `notif test` calls
  `notifications_add_notification()` -> `notification_storage_store()` inline;
* `security shred` marshals to the **launcher task**
  (`command_security_shred` -> `launcher_task_add_callback`).

Crucially the *real* trigger does the same thing: the disconnect-timeout path
ends at `launcher_task_add_callback(prv_deadline_shred_callback, ...)` in
`src/fw/services/security_lock/endpoint.c`. Both triggers therefore run the
identical `prv_shred()` on the identical task, so the console trigger used
here is a faithful proxy for the deadline trigger, not a weaker cousin.

How this tool tries to land in the window
-----------------------------------------
Observed live, the file-wipe loop is narrow: `Shredding:` to `Erasing coredump
region` is about 30 ms, and `notifstr` is the *first* target, so the vulnerable
instant is a few milliseconds starting roughly 5-40 ms after the trigger. Log
delivery lags ~70 ms, so reacting to the `Shredding:` log line is far too late
to aim with. Instead each iteration runs continuous notification traffic
across the trigger and randomises the *phase* between the two:

* ``offset > 0`` -- traffic starts first, trigger fires ``offset`` ms later;
* ``offset < 0`` -- trigger fires first, traffic starts ``|offset|`` ms later.

Traffic keeps running for ``--traffic-ms`` so it spans the whole wipe. The RNG
is seeded and the seed is printed, so a hit is replayable.

``--prefill N`` stores N notifications before the timed section to push
`notifstr` toward the compaction threshold, so the store that collides is more
likely to be the slow `prv_compress()` rewrite rather than a quick append.
This trades wall-clock time for a much wider window and is the highest-value
knob here.

Detection
---------
A crash is not instantly visible: the watch needs a couple of seconds to
reboot and the daemon a moment more to reconnect. Judging on the first missed
console reply reports every crash as a bare ``link_down`` and misses the
reboot logs that say what actually happened, so each iteration first waits up
to ``--recover-s`` for the console to return, *then* looks. An iteration fails
if any of these hold:

* ``security status`` never comes back within ``--recover-s``;
* it does come back but was unreachable for a while -- it went away, so
  something restarted it;
* the PULSE link generation changed (the daemon rebuilt the link);
* the log since the iteration's mark matches a reset/assert signature
  (``Cannot delete``, ``CROAK``, ``ASSERTION``, ``Resetting!``, ``Dangerously
  rebooted``, a ``*Fault`` handler, or the boot-only ``SECBOOT handle_boot
  enter``);
* the launcher task is wedged -- a launcher-marshalled probe (``window
  stack``) times out while ``security status``, which stays on KernelBG, still
  answers instantly;
* the harness ``health`` status is not ``ok``.

Only ``Cannot delete`` means *the hunted race*; it is tracked separately and
reported separately, because the shred can and does kill the watch by other
means and conflating them would overstate the result. One such other mode was
observed immediately: with a notification on screen, wiping ``notifstr`` makes
``notification_storage_get()`` fail (``Failed to read notification``,
`notification_window.c`) and KernelMain then takes a UsageFault on a wild PC.
That is a real bug, but it is not this one.

On failure the run stops, dumps the surrounding logs plus ``log dump current``,
and exits non-zero. Note that the shred erases the debug-log flash region, so
``log dump current`` is often empty right after one; the live ring is the
reliable record, which is why the daemon keeps it.

Running it
----------
QEMU and the harness daemon must already be up; this tool never opens its own
console connection, because the daemon owns port 12345 exclusively::

    export PEBBLE_QEMU_BIN=~/.pebble-sdk/SDKs/4.33.1/toolchain/bin/qemu-pebble
    ./pbl qemu &
    ~/pblvenv/bin/python tools/pebble_harness.py serve &

    ~/pblvenv/bin/python tools/security_lock_stress.py --iterations 100
    ~/pblvenv/bin/python tools/security_lock_stress.py --iterations 20 --prefill 80
    ~/pblvenv/bin/python tools/security_lock_stress.py --self-test

Reading the output
------------------
Each iteration prints one line: the index, the trigger used, the requested and
*achieved* offset (they differ because the daemon serialises prompts, so a
trigger can queue behind an in-flight ``notif test``), how many notifications
were delivered, and the verdict. The closing summary reports iterations
completed, failures, and a histogram of achieved offsets -- so a "no repro"
result is legible about which part of the window was actually covered rather
than just asserting a count.

A clean no-repro is a real result. This tool does not manufacture failures.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import socket
import sys
import threading
import time
from collections import Counter

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "tools"))

DEFAULT_SOCK = os.path.join(REPO, "build", "harness.sock")

#: Log signatures that mean the watch died or restarted. `PBL_CROAK` renders as
#: `*** CROAK: ...`; `Cannot delete` is the exact message from the `pfs_remove`
#: busy branch and is the smoking gun for *this* race specifically.
#: `SECBOOT handle_boot enter` is emitted once per boot and nowhere else, so it
#: is unambiguous evidence of a restart mid-run.
FAILURE_PATTERNS = [
    ("cannot_delete", re.compile(r"Cannot delete")),
    ("croak", re.compile(r"CROAK")),
    ("assertion", re.compile(r"ASSERTION|PBL_ASSERT")),
    ("resetting", re.compile(r"Resetting!")),
    ("dangerous_reboot", re.compile(r"Dangerously rebooted")),
    ("fault", re.compile(r"UsageFault|HardFault|MemManage|BusFault")),
    ("rebooted", re.compile(r"SECBOOT handle_boot enter")),
    # Privacy-relevant, not merely a stability signal. `prv_shred()` erases the
    # coredump region on purpose, because "a coredump is a snapshot of RAM and
    # can contain notification text or contact details". A crash *after* that
    # erase writes a fresh ~280 KB RAM snapshot straight back into the region
    # the wipe just cleared, re-creating the artefact the shred destroyed.
    ("coredump_rewritten", re.compile(r"Starting core dump|CD: Saving to")),
]

#: The one signature that means *the hunted race* specifically -- another task
#: held a descriptor open on a shred target when `pfs_remove()` ran. Every other
#: tag above means the watch died of something else, which is still a bug but
#: is a different bug, and the report must not conflate them.
HUNTED_TAG = "cannot_delete"

#: Not a failure on its own: `notification_storage_get()` returning false is the
#: *expected* outcome of reading a notification whose backing file was just
#: wiped. It is recorded because it marks the moment the UI noticed, which is
#: what the observed KernelMain fault follows.
PRECURSOR_RE = re.compile(r"Failed to read notification")

#: Marshalled to the launcher task, which is where the shred runs. If this
#: times out while `security status` (KernelBG) still answers, the launcher
#: task is wedged rather than the whole watch being dead.
LAUNCHER_PROBE = "window stack"
KERNELBG_PROBE = "security status"


# --- talking to the harness daemon ------------------------------------------


def _call(sock_path, cmd, args=None, timeout=120.0):
    """One request to the harness daemon. Returns a dict, never raises.

    Deliberately a local reimplementation of `pebble_harness.call` rather than
    an import: this file must keep working if the harness module is mid-edit by
    another workstream, and the wire format is two lines of JSON.
    """
    payload = json.dumps({"cmd": cmd, "args": args or {}}) + "\n"
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(sock_path)
    except OSError as exc:
        return {
            "ok": False,
            "reason": "daemon_not_running",
            "detail": f"{sock_path} ({exc.strerror or exc})",
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


class Watch:
    """Thin, never-throwing facade over the harness daemon."""

    def __init__(self, sock_path, verbose=False):
        self.sock = sock_path
        self.verbose = verbose

    def prompt(self, command, timeout=20.0):
        response = _call(
            self.sock,
            "prompt",
            {"command": command, "timeout": timeout},
            timeout=timeout + 30.0,
        )
        if self.verbose:
            state = "ok" if response.get("ok") else response.get("reason")
            print(f"      . {command!r} -> {state}", flush=True)
        return response

    def lines(self, command, timeout=20.0):
        return self.prompt(command, timeout=timeout).get("lines") or []

    def mark(self):
        return _call(self.sock, "mark").get("seq")

    def logs(self, since=None, grep=None, tail=None):
        response = _call(
            self.sock, "logs", {"since": since, "grep": grep, "tail": tail}
        )
        return [entry["text"] for entry in (response.get("lines") or [])]

    def health(self, timeout=8.0, gap=0.5):
        return _call(
            self.sock,
            "health",
            {"timeout": timeout, "gap": gap},
            timeout=timeout + 2 * gap + 30.0,
        )

    def link_generation(self):
        return _call(self.sock, "ping").get("link_generation")

    def boot(self, warm=False, timeout=180.0):
        return _call(
            self.sock,
            "boot",
            {"warm": warm, "timeout": timeout},
            timeout=timeout + 60.0,
        )

    def security_status(self):
        """`security status` as a dict of ints, or None if it did not answer."""
        for line in self.lines(KERNELBG_PROBE, timeout=8.0):
            if "state=" in line:
                out = {}
                for token in line.split():
                    if "=" in token:
                        key, _, value = token.partition("=")
                        try:
                            out[key] = int(value)
                        except ValueError:
                            out[key] = value
                return out
        return None


# --- pure helpers (covered by --self-test) ----------------------------------


def schedule(offset_ms):
    """Split a signed phase offset into (traffic_delay_s, trigger_delay_s).

    Positive means traffic leads and the trigger follows; negative means the
    trigger fires first and traffic follows. Both are delays from a common t0,
    so exactly one of them is always zero.
    """
    offset_s = offset_ms / 1000.0
    return max(0.0, -offset_s), max(0.0, offset_s)


def classify_logs(lines):
    """Failure tags present in these log lines, in the order listed."""
    hits = []
    for tag, pattern in FAILURE_PATTERNS:
        if any(pattern.search(line) for line in lines):
            hits.append(tag)
    return hits


def histogram(values, bin_ms=50, width=48):
    """Text histogram of achieved offsets, so 'no repro' says what was covered."""
    if not values:
        return ["(no samples)"]
    counts = Counter(int(v // bin_ms) * bin_ms for v in values)
    peak = max(counts.values())
    rows = []
    for lo in sorted(counts):
        n = counts[lo]
        bar = "#" * max(1, int(n * width / peak))
        rows.append(f"  [{lo:+5d},{lo + bin_ms:+5d}) ms {n:4d} {bar}")
    return rows


# --- notification traffic ---------------------------------------------------


class Traffic:
    """Background `notif test` storm spanning the trigger.

    Each `notif test` runs `notification_storage_store()` inline on KernelBG,
    so while one is in flight the `notifstr` descriptor is open. Runs in its
    own thread; the daemon serialises the actual prompts, and the small
    randomised gap between them leaves room for the trigger prompt to slip in
    rather than starving it behind a back-to-back stream.
    """

    def __init__(self, watch, rng, gap_ms=(0, 25)):
        self.watch = watch
        self.rng = rng
        self.gap_ms = gap_ms
        self.sent = 0
        self.errors = 0
        self._stop = threading.Event()
        self._thread = None

    def _run(self, start_at, until):
        delay = start_at - time.monotonic()
        if delay > 0:
            self._stop.wait(delay)
        while not self._stop.is_set() and time.monotonic() < until:
            response = self.watch.prompt("notif test", timeout=10.0)
            if response.get("ok"):
                self.sent += 1
            else:
                self.errors += 1
                # A dead link will not recover inside this iteration; stop
                # hammering it and let the detector do its job.
                if response.get("reason") in ("link_down", "daemon_not_running"):
                    return
            lo, hi = self.gap_ms
            self._stop.wait(self.rng.uniform(lo, hi) / 1000.0)

    def start(self, start_at, duration_s):
        self._thread = threading.Thread(
            target=self._run,
            args=(start_at, start_at + duration_s),
            name="stress-traffic",
            daemon=True,
        )
        self._thread.start()

    def join(self, timeout=30.0):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout)


# --- the experiment ---------------------------------------------------------


class Stress:
    def __init__(self, watch, options):
        self.watch = watch
        self.options = options
        self.rng = random.Random(options.seed)
        self.offsets = []
        self.failures = []
        self.completed = 0

    # -- state management ----------------------------------------------------

    def reset_state(self):
        """Get back to unlocked with no PIN.

        This matters more than it looks: `notifications_add_notification()`
        drops the notification outright when the watch is locked, so a locked
        watch generates no `notifstr` traffic at all and the window cannot be
        hit. Every iteration must start unlocked or it tests nothing.
        """
        status = self.watch.security_status()
        if status is None:
            return False
        if status.get("state"):
            # The PIN may be unknown (set by an earlier run), so clear rather
            # than guess: `security clear pin` disables the feature outright.
            self.watch.prompt("security clear pin", timeout=10.0)
            status = self.watch.security_status()
        elif status.get("pin_len"):
            self.watch.prompt("security clear pin", timeout=10.0)
            status = self.watch.security_status()
        self.watch.prompt("security deadlines 0 0", timeout=10.0)
        return bool(status) and not status.get("state")

    def arm_trigger(self, trigger):
        """Prepare whatever the trigger needs, and return the console command.

        `lock` needs a PIN before `security lock` will do anything. It is kept
        in the mix because it is a different entry point, but note that it
        locks the watch *first*, which closes the notification window -- so it
        is a control, not the main event. That asymmetry is reported.
        """
        if trigger == "lock":
            self.watch.prompt("security set pin 1234", timeout=10.0)
            return "security lock"
        return "security shred"

    def prefill(self, count):
        """Push `notifstr` toward full so the colliding store is a compaction.

        `notification_storage_store()` only takes the slow `prv_compress()`
        path -- a full 30 KB file rewrite with the descriptor held open -- once
        the file cannot fit another record. Every shred resets the file, so
        this has to be redone each iteration.
        """
        for _ in range(count):
            if not self.watch.prompt("notif test", timeout=10.0).get("ok"):
                return False
        return True

    # -- detection -----------------------------------------------------------

    def await_console(self, timeout_s):
        """Poll `security status` until it answers again.

        A reset is not instantly visible: the watch takes a couple of seconds
        to reboot and the daemon a moment more to reconnect, during which the
        console is simply absent. Judging on the first missed reply reports
        every crash as `link_down` and never sees the reboot logs that say what
        actually happened -- so wait, then look.
        """
        deadline = time.monotonic() + timeout_s
        while True:
            status = self.watch.security_status()
            if status is not None:
                return status, round(timeout_s - (deadline - time.monotonic()), 1)
            if time.monotonic() >= deadline:
                return None, round(timeout_s, 1)
            time.sleep(1.0)

    def detect(self, since_seq, generation_before):
        """Everything that says this iteration broke the watch."""
        reasons = []

        status, waited_s = self.await_console(self.options.recover_s)
        if status is None:
            reasons.append(f"{KERNELBG_PROBE!r} still not answering after {waited_s}s")
        elif waited_s > 1.5:
            # It came back, which means it went away: worth recording even when
            # the log scan below is what names the cause.
            reasons.append(f"console was unreachable for ~{waited_s}s")

        generation_after = self.watch.link_generation()
        if (
            generation_before is not None
            and generation_after is not None
            and generation_after != generation_before
        ):
            reasons.append(
                f"link_generation {generation_before} -> {generation_after} "
                "(the PULSE link was rebuilt)"
            )

        log_lines = self.watch.logs(since=since_seq)
        tags = classify_logs(log_lines)
        for tag in tags:
            reasons.append(f"log signature: {tag}")

        if status is not None:
            # Only worth probing the launcher task while KernelBG is healthy;
            # that asymmetry is what distinguishes wedged from dead.
            probe = self.watch.prompt(LAUNCHER_PROBE, timeout=10.0)
            if not probe.get("ok"):
                reasons.append(
                    f"launcher task wedged: {LAUNCHER_PROBE!r} failed "
                    f"({probe.get('reason')}) while {KERNELBG_PROBE!r} still answers"
                )

        if reasons:
            # health() is slow (two screendumps), so only pay for it once we
            # already believe something is wrong.
            health = self.watch.health(gap=self.options.health_gap)
            reasons.append(f"health: {health.get('status')} -- {health.get('detail')}")
        return reasons, log_lines, tags

    # -- one iteration -------------------------------------------------------

    def iteration(self, index):
        options = self.options
        trigger = self.rng.choice(options.triggers)

        if not self.reset_state():
            return {
                "index": index,
                "trigger": trigger,
                "failed": True,
                "reasons": ["could not reach a known unlocked state before the run"],
                "logs": [],
            }

        if options.prefill and not self.prefill(options.prefill):
            return {
                "index": index,
                "trigger": trigger,
                "failed": True,
                "reasons": [
                    "prefill failed: the watch stopped accepting notifications"
                ],
                "logs": [],
            }

        command = self.arm_trigger(trigger)
        offset_ms = self.rng.uniform(options.offset_min, options.offset_max)
        traffic_delay, trigger_delay = schedule(offset_ms)

        since_seq = self.watch.mark()
        generation_before = self.watch.link_generation()

        traffic = Traffic(self.watch, self.rng, gap_ms=(0.0, options.traffic_gap_ms))
        t0 = time.monotonic() + 0.05  # small lead so both sides can arm
        traffic.start(t0 + traffic_delay, options.traffic_ms / 1000.0)

        sleep_for = (t0 + trigger_delay) - time.monotonic()
        if sleep_for > 0:
            time.sleep(sleep_for)
        fired_at = time.monotonic()
        trigger_response = self.watch.prompt(command, timeout=20.0)
        # The daemon serialises prompts, so the trigger can queue behind an
        # in-flight `notif test`. Report what actually happened, not what was
        # asked for -- the histogram is only honest if it uses this.
        achieved_ms = (fired_at - (t0 + traffic_delay)) * 1000.0

        traffic.join(timeout=options.traffic_ms / 1000.0 + 30.0)
        # Let the launcher task finish the wipe and the sweep settle.
        time.sleep(options.settle_ms / 1000.0)

        reasons, log_lines, tags = self.detect(since_seq, generation_before)
        if traffic.sent > 0 and trigger_response.get("ok"):
            self.offsets.append(achieved_ms)

        return {
            "index": index,
            "trigger": trigger,
            "command": command,
            "requested_offset_ms": round(offset_ms, 1),
            "achieved_offset_ms": round(achieved_ms, 1),
            "notifs_sent": traffic.sent,
            "notif_errors": traffic.errors,
            "trigger_ok": bool(trigger_response.get("ok")),
            # An iteration that delivered no notifications collided the shred
            # with nothing at all. It is not evidence either way, so it is
            # excluded from the coverage histogram rather than padding it.
            "valid": traffic.sent > 0 and bool(trigger_response.get("ok")),
            "failed": bool(reasons),
            "reasons": reasons,
            "tags": tags,
            "hunted": HUNTED_TAG in tags,
            "precursor": any(PRECURSOR_RE.search(line) for line in log_lines),
            "logs": log_lines,
        }

    # -- recovery ------------------------------------------------------------

    def recover(self):
        """Best-effort return to a usable watch after a suspected failure."""
        if self.watch.security_status() is not None:
            return True
        print("  recovering: watch is not answering; warm boot", flush=True)
        response = self.watch.boot(warm=True)
        return bool(response.get("ok"))

    # -- the run -------------------------------------------------------------

    def run(self):
        options = self.options
        print(f"seed={options.seed} iterations={options.iterations}")
        print(
            f"triggers={','.join(options.triggers)} "
            f"offset=[{options.offset_min:+.0f},{options.offset_max:+.0f}]ms "
            f"traffic={options.traffic_ms}ms gap<={options.traffic_gap_ms}ms "
            f"prefill={options.prefill}"
        )

        if options.cold_boot:
            print("cold booting for a clean flash ...", flush=True)
            response = self.watch.boot(warm=False)
            if not response.get("ok"):
                print(f"FATAL: cold boot failed: {response.get('reason')}")
                return 2
            print(f"  booted in {response.get('boot_time_s')}s", flush=True)

        if self.watch.security_status() is None:
            print("FATAL: the watch is not answering the console; is QEMU up?")
            return 2

        for index in range(1, options.iterations + 1):
            try:
                result = self.iteration(index)
            except Exception as exc:  # a stress tool must not die on a traceback
                result = {
                    "index": index,
                    "trigger": "?",
                    "failed": True,
                    "reasons": [f"driver error: {type(exc).__name__}: {exc}"],
                    "logs": [],
                }

            self.completed += 1
            self.report_iteration(result)

            if result["failed"]:
                self.failures.append(result)
                self.report_failure(result)
                if not options.keep_going:
                    self.summary()
                    return 1
                if not self.recover():
                    print("could not recover the watch; stopping")
                    self.summary()
                    return 1

        self.summary()
        return 0

    def report_iteration(self, result):
        if not result["failed"]:
            verdict = "ok"
        elif result.get("hunted"):
            verdict = "FAIL <-- CANNOT-DELETE (the hunted race)"
        else:
            verdict = "FAIL " + ",".join(result.get("tags") or ["no-signature"])
        print(
            f"[{result['index']:4d}] {result.get('trigger', '?'):6s} "
            f"req={result.get('requested_offset_ms', 0):+7.1f}ms "
            f"got={result.get('achieved_offset_ms', 0):+7.1f}ms "
            f"notifs={result.get('notifs_sent', 0):3d} "
            f"{verdict}",
            flush=True,
        )

    def report_failure(self, result):
        print("\n" + "=" * 72)
        if result.get("hunted"):
            print("REPRODUCED THE HUNTED RACE: pfs_remove() found the file in use")
        else:
            print("Watch failed, but NOT via the hunted 'Cannot delete' path")
        print("=" * 72)
        print(f"seed              {self.options.seed}")
        print(f"iteration         {result['index']}")
        print(f"trigger           {result.get('command')}")
        print(f"requested offset  {result.get('requested_offset_ms')} ms")
        print(f"achieved offset   {result.get('achieved_offset_ms')} ms")
        print(f"notifications     {result.get('notifs_sent')}")
        print(f"prefill           {self.options.prefill}")
        print("reasons:")
        for reason in result["reasons"]:
            print(f"  - {reason}")
        print("\n--- logs since the iteration mark ---")
        for line in result["logs"][-200:]:
            print(f"  {line}")
        # The flash replay is slow and the shred erases the debug-log region
        # anyway, so it rarely adds anything. Pay for it when it matters: the
        # hunted race, or the first failure of a run.
        if result.get("hunted") or len(self.failures) <= 1:
            print("\n--- log dump current (on-flash boot log) ---")
            dump = self.watch.lines("log dump current", timeout=60.0)
            for line in dump[-400:]:
                print(f"  {line}")
        else:
            print("\n(skipping 'log dump current': see the first failure above)")
        print("=" * 72 + "\n", flush=True)

    def summary(self):
        print("\n" + "-" * 72)
        print("SUMMARY")
        print("-" * 72)
        hunted = [f for f in self.failures if f.get("hunted")]
        print(f"seed                  {self.options.seed}")
        print(f"iterations completed  {self.completed} of {self.options.iterations}")
        print(
            f"valid trials          {len(self.offsets)}  "
            "(notifications actually delivered across the trigger)"
        )
        print(f"prefill per iteration {self.options.prefill}")
        print(f"failures (any kind)   {len(self.failures)}")
        print(f"hunted race hits      {len(hunted)}  ('Cannot delete' from pfs_remove)")

        kinds = Counter()
        for failure in self.failures:
            kinds[",".join(failure.get("tags") or ["no-signature"])] += 1
        if kinds:
            print("failure kinds:")
            for kind, count in kinds.most_common():
                print(f"  {count:4d}  {kind}")

        if self.offsets:
            print(
                f"achieved offsets      min={min(self.offsets):+.1f}ms "
                f"max={max(self.offsets):+.1f}ms n={len(self.offsets)}"
            )
        print("offset coverage (achieved, ms between traffic start and trigger):")
        for row in histogram(self.offsets, bin_ms=self.options.bin_ms):
            print(row)

        if not hunted:
            print(
                "\nThe hunted 'Cannot delete' race was NOT reproduced. That is a "
                "negative result, not proof of absence: the vulnerable instant is "
                "only a few ms wide and sits inside a ~30ms wipe loop. --prefill "
                "is the strongest knob for widening it, because it forces the "
                "slow prv_compress() rewrite to be the colliding operation."
            )
        if self.failures and not hunted:
            print(
                "Other crashes WERE seen. They are real bugs in the same feature "
                "but a different mechanism; see the per-failure dumps above."
            )
        print("-" * 72, flush=True)


# --- self-test for the pure helpers -----------------------------------------


def self_test():
    """Check the parts that do not need a watch. Cheap guard against the
    scheduling maths silently inverting, which would make every iteration test
    the wrong phase and quietly produce a meaningless 'no repro'."""
    failures = []

    def check(name, got, want):
        if got != want:
            failures.append(f"{name}: got {got!r}, want {want!r}")

    check("schedule(+100)", schedule(100), (0.0, 0.1))
    check("schedule(-100)", schedule(-100), (0.1, 0.0))
    check("schedule(0)", schedule(0), (0.0, 0.0))
    # Exactly one side is always delayed.
    for offset in (-500, -1, 0, 1, 500):
        traffic, trigger = schedule(offset)
        if traffic and trigger:
            failures.append(f"schedule({offset}) delays both sides")

    check("classify_logs(clean)", classify_logs(["all is well"]), [])
    check(
        "classify_logs(croak)",
        classify_logs(["*** CROAK: Cannot delete notifstr, it is currently in use"]),
        ["cannot_delete", "croak"],
    )
    check(
        "classify_logs(reboot)",
        classify_logs(["SECBOOT handle_boot enter"]),
        ["rebooted"],
    )
    # The KernelMain fault seen in practice must classify, and must NOT be
    # mistaken for the hunted race.
    fault_tags = classify_logs(
        [
            "fault_handling.c:439> [UsageFault_Handler!]",
            "die.c:41> Resetting!",
            "reboot_reason.c:135> Dangerously rebooted due to HardFault",
        ]
    )
    check(
        "classify_logs(fault)",
        fault_tags,
        ["resetting", "dangerous_reboot", "fault"],
    )
    check(
        "classify_logs(coredump)",
        classify_logs(["core_dump.c:0> Starting core dump"]),
        ["coredump_rewritten"],
    )
    if HUNTED_TAG in fault_tags:
        failures.append("a plain fault was misclassified as the hunted race")
    if HUNTED_TAG not in classify_logs(["*** CROAK: Cannot delete notifstr"]):
        failures.append("the hunted race signature is not detected")
    check(
        "precursor",
        bool(PRECURSOR_RE.search("cation_window.c:521> Failed to read notification")),
        True,
    )
    check("histogram(empty)", histogram([]), ["(no samples)"])
    if len(histogram([0.0, 10.0, 120.0], bin_ms=50)) != 2:
        failures.append("histogram binning is wrong")

    for line in failures:
        print(f"FAIL {line}")
    print("self-test: " + ("FAILED" if failures else "passed"))
    return 1 if failures else 0


# --- CLI --------------------------------------------------------------------


def build_parser():
    parser = argparse.ArgumentParser(
        prog="security_lock_stress.py",
        description=__doc__.split("\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="See the module docstring for the race being hunted.",
    )
    parser.add_argument("--socket", default=DEFAULT_SOCK, help="harness control socket")
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="RNG seed; a random one is chosen and printed if omitted",
    )
    parser.add_argument(
        "--triggers",
        default="shred",
        help="comma-separated: shred,lock (default: %(default)s). "
        "'lock' locks the watch first, which drops notifications and so "
        "closes the window; it is a control, not the main event.",
    )
    parser.add_argument("--offset-min", type=float, default=-300.0)
    parser.add_argument("--offset-max", type=float, default=300.0)
    parser.add_argument(
        "--traffic-ms",
        type=float,
        default=1500.0,
        help="how long notification traffic runs, spanning the trigger",
    )
    parser.add_argument(
        "--traffic-gap-ms",
        type=float,
        default=25.0,
        help="upper bound on the randomised gap between notif tests",
    )
    parser.add_argument(
        "--prefill",
        type=int,
        default=0,
        help="notifications stored before the timed section, to force the slow "
        "compaction path (widest window). ~100 fills the 30 KB file.",
    )
    parser.add_argument(
        "--settle-ms",
        type=float,
        default=800.0,
        help="pause after the trigger so the launcher task finishes the wipe",
    )
    parser.add_argument(
        "--recover-s",
        type=float,
        default=45.0,
        help="how long to wait for the console to come back before calling the "
        "watch dead; a reset needs a few seconds to reboot and reconnect",
    )
    parser.add_argument("--health-gap", type=float, default=0.5)
    parser.add_argument("--bin-ms", type=int, default=50)
    parser.add_argument(
        "--cold-boot",
        action="store_true",
        help="cold boot first for a clean flash (recommended for a real run)",
    )
    parser.add_argument(
        "--keep-going",
        action="store_true",
        help="carry on after a failure instead of stopping with a reproducer",
    )
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument(
        "--self-test", action="store_true", help="check the pure helpers and exit"
    )
    return parser


def main(argv=None):
    options = build_parser().parse_args(argv)
    if options.self_test:
        return self_test()

    if options.seed is None:
        options.seed = random.randrange(1 << 30)
    options.triggers = [t.strip() for t in options.triggers.split(",") if t.strip()]
    unknown = set(options.triggers) - {"shred", "lock"}
    if unknown:
        print(f"unknown trigger(s): {sorted(unknown)}")
        return 2
    if options.offset_min > options.offset_max:
        print("--offset-min must not exceed --offset-max")
        return 2

    watch = Watch(options.socket, verbose=options.verbose)
    return Stress(watch, options).run()


if __name__ == "__main__":
    sys.exit(main())
