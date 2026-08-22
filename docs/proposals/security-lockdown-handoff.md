# Security Lockdown — Handoff

Companion to `security-lockdown.md`, which holds the design. This is the state
of the work and what to pick up next.

- **PebbleOS**: `security-lockdown` branch, 35 commits off `origin/main`,
  worktree `~/development/worktrees/PebbleOS-security-lockdown`
- **Gadgetbridge**: `ben.temple/security-lockdown`, 6 commits off
  `origin/master`, worktree `~/development/worktrees/Gadgetbridge-security-lockdown`

## Where it stands

| | State |
|---|---|
| Firmware build (`qemu_emery`) | Clean, no warnings, KERNEL_RAM ~33% |
| Unit tests | **6/6 suites pass** |
| End-to-end in QEMU | **19/24** |
| Gadgetbridge | Complete — APK builds, 1216 tests pass |

Everything is implemented: lock state, wipe engine, lock screen, touch PIN pad,
Settings menu, protocol endpoint, configurable delays, duress PIN, system shred
event, and the Gadgetbridge half.

**What works on the watch, verified in the emulator:** boot, Settings →
Security, setting a PIN through the pad, the phone's `LOCK` reaching the
endpoint, the watch locking, the lock screen rendering, disconnect arming both
countdowns, and reconnect cancelling them.

## The one blocker

`shred_pending` is set when a wipe starts and cleared when it finishes. **It is
never cleared**, so every boot sees a wipe owed, runs another, and the watch
sits permanently mid-wipe behind a lock screen that will not accept a PIN.

```
state=2  pin_len=4  shred_pending=1   <- never returns to 0
```

All five remaining end-to-end failures are downstream of this one flag.

**Where to look.** `prv_shred()` in `src/fw/services/security_lock/shred.c`:

- `:201` sets the flag
- `:267` starts the asynchronous sector sweep
- `:270-276` closes and reopens `pin_db`, `reminder_db`, `timeline_event` and
  notification storage
- `:292` clears the flag

The console keeps answering (it is serviced by KernelBG) while the launcher task
is blocked, which is exactly the symptom: lock screen drawn, taps ignored. That
points at `:270-276` rather than at the sweep.

Worth ruling out first: the blocking work should only take about **two seconds**
— seven small file zeroes plus roughly ten sector erases for the 640 KB coredump
and debug regions. Anything longer is a deadlock, not slowness. The sweep is the
only long-running part and it is budgeted and already deferred.

Suggested first move: log after each of the four re-inits and immediately before
`:292`. If a re-init blocks, either defer it or clear the flag before starting
the sweep.

## Bugs found by running it, and their lessons

Four bugs got through every unit test and were only caught by driving the real
UI. They are worth knowing because each represents a class.

1. **PIN could never be saved.** `CONFIG_RNG_STUB` boards — `qemu_emery`
   included — have an `rng_rand()` that always fails, and the salt helper
   treated that as fatal. Real hardware still refuses; only stub boards fall
   back to clock entropy.
2. **Unbootable watch.** The wipe ran inside `services_normal_early_init()` and
   blocked boot for as long as it took. *Nothing may touch flash before boot
   completes.* The boot path now only records that a wipe is owed.
3. **Permanent hang on lock.** The wipe ran on KernelBG, where the database
   deinit calls deadlock. `factory_reset_fast()` runs the same work from the
   launcher task for exactly this reason. Every wipe path now routes through
   `launcher_task_add_callback`.
4. **Watchdog reset mid-wipe.** Masking only the current task still let a task
   blocked behind it miss its own check-in. Long loops must call
   `task_watchdog_bit_set_all()`.

A trap that cost real time: **the security lock's own logs are compiled out.**
`PBL_SHOULD_LOG` gates on the compile-time module level and
`CONFIG_SERVICE_SECURITY_LOCK_LOG_LEVEL` is 0, so `PBL_LOG_DBG` never emits.
Several cycles went into chasing a protocol endpoint that was never broken,
because the assertion was checking for a log line that could not exist.
`Shredding:` and `LOCK from phone` are INFO on purpose; the rest is DBG.

## Decisions that should not be quietly reversed

- **The wipe only destroys what the phone can restore.** Health and step
  history, third-party app storage and BT pairing are never touched. That is
  what makes it safe to trigger aggressively, and it is why locking almost
  always ends in a wipe. A seized watch still yields step and sleep history —
  a deliberate trade.
- **Any reboot while armed wipes.** SELECT+BACK held for five seconds hard
  resets from the button ISR, below anything software can intercept, so
  restarting must never be cheaper than waiting.
- **A duress unlock does not tell the phone.** `SHRED_COMPLETE` and the
  unfaithful flag are suppressed, or the phone restores everything within
  seconds and the duress PIN achieves nothing.
- **SHA-256 is vendored, not from mbedtls.** `third_party/wscript_build` only
  recurses mbedtls under `CONFIG_BT_FW_NIMBLE`, so boards on the QEMU stack
  never build it.
- **Emery/gabbro only**, gated on `SERVICE_TOUCH`. Verified on and off.

## Open questions

- Should reconnecting the phone **auto-unlock**, or only cancel the countdown?
  It currently only cancels. Auto-unlock is convenient and consistent with
  "a connected phone means the phone is unlocked", but a thief who stays in
  Bluetooth range of your phone would get an unlocked watch.
- Should `PEBBLE_SECURITY_SHRED_EVENT` be **exported to third-party apps**?
  The firmware half is done; the SDK half is the separate export sequence in
  `docs/development/sdk_export.md`.
- **Round display (gabbro) has never been rendered.** The pad geometry is
  computed for it but only the rectangular layout has been seen.

## Working on this

Build environment is not checked in. Setup and the traps are recorded in
`security-lockdown.md` and in the notes below.

```bash
V=/path/to/venv                     # uv venv + requirements.txt + pip
PATH="$V/bin:$PATH" ./waf configure --board qemu_emery --relax_toolchain_restrictions
PATH="$V/bin:$PATH" ./waf build
PATH="$V/bin:$PATH" ./waf test -M '.*(security_lock|settings_security|pin_entry|sha256|test_pfs).*'

export PEBBLE_QEMU_BIN=~/.pebble-sdk/SDKs/4.33.1/toolchain/bin/qemu-pebble
PATH="$V/bin:$PATH" ./pbl qemu &
PATH="$V/bin:$PATH" python3 tools/security_lock_e2e.py
```

- `./waf test -M` matches a **path**, so wrap patterns in `.*...*`; a bare name
  silently runs nothing.
- **One QEMU per worktree.** The monitor socket, QMP socket and ports
  12344/12345 are fixed paths; a second instance kills the first's socket.
- `tests/fw/comm/test_gatt_service_changed_server.c` fails to compile on
  `origin/main` and aborts an unfiltered `./waf test`. Not ours.
- `tools/security_lock_e2e.py` asserts on the `security status` console command
  and on log lines, never on pixels. Menu positions and pad geometry are
  isolated at the top of the file for when the UI moves.
