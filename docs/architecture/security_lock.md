# Security lock

A PIN lock for the watch, and a shred that destroys the watch's copy of the
phone's data. It exists for one situation: the phone is taken, and the watch on
the wrist is a second screen showing the same notifications, calendar and
contacts — behind no authentication at all.

This page describes what the feature *does*, end to end, where each part of it
lives, and the reasoning behind the decisions that are not obvious from the
code alone.

The whole thing is normal-firmware only *at runtime*: `security_lock_init()`
and `security_lock_handle_boot()` are called from
`services_normal_early_init()`, which PRF never runs. Nothing else reaches the
service, so a locked or shredding watch is a normal-firmware watch.

`CONFIG_SERVICE_SECURITY_LOCK` itself carries no `!RECOVERY_FW` guard, so a PRF
configure still selects it and the service's sources still compile — they are
simply never called, and `--gc-sections` drops them from the linked image. Only
the applib event-service state accessors survive into a PRF build. Adding the
guard would make the Kconfig say what the runtime already does; it has not been
added, so this is written down instead.

## Vocabulary

Settled after an audit of every user-facing string, and written down because
the question has come up twice.

| Word | Means | Where |
|---|---|---|
| **Security Lock** | the feature, and its master switch | Settings row |
| **Locked** | the state: the PIN gates input | lock screen, `Alarms When Locked` |
| **Lock** | the action: lock now. Whatever `Erase After` says goes on counting, exactly as it does under any other lock | Quick Launch, the app, the Settings row |
| **Lockdown** | locking *and* erasing. Only ever appears as `Lockdown + Erase` | Quick Launch, the Settings row, the phone's `LOCK_ERASE` |
| **Erase** | destroying the watch's copy of the phone's content | `Erase After`, every subtitle |

The rule that holds it together: **a lock is a lock however it was reached.** A
disconnect lock and the manual action produce the same watch — locked, with the
configured erase counting down — so they share a word. The only thing that
earns the word *Lockdown* is erasing, which is the one outcome the PIN cannot
call back.

That is why the manual action is `Lock` and not `Lockdown`. It was originally
the latter, on the reasoning that starting the erase clock was something extra
it did. It is not extra: a disconnect lock leaves the same clock running, from
the same setting. What the manual action adds is only that the lock happens now
instead of at `Lock After`, and `Lock` says that.

The phone's two commands line up with the same pair: `LOCK` is a Lock, and
`LOCK_ERASE` is a Lockdown + Erase. A disconnect must never be described as the
latter.

Known rough edge: the Quick Launch picker shows the name alone, so `Lock` reads
identically whether `Erase After` is `Never` (it only locks) or set (it locks,
and the erase is running). The Settings row carries a subtitle that says which;
the picker has nowhere to put one.

## Threat model

1. **Border / device seizure.** Adversary holds both phone and watch and may
   compel unlock.
2. **Protest / activist context.** Phone taken while the watch is worn; the
   watch must act autonomously when it loses the phone.
3. **Opportunistic theft / snooping.** Someone picks the watch up and reads it.

### What this cannot defend against

- **No encryption at rest on the watch.** There is no AES/KDF-at-rest code in
  `src/fw`; `MBEDTLS_AES_C` is compiled only for the NimBLE link layer. Erasure,
  not access control, is the only real control available.
- **The 5-second SELECT+BACK+UP hard reset cannot be blocked.** Handled in the
  button ISR below the OS, commented *"This back door absolutely must work."*
  Holding UP as well sets `BOOT_BIT_FORCE_PRF` and boots recovery firmware,
  which never starts this feature. This is deliberate, not a hole to be
  closed: reboot-while-locked re-runs the shred at early boot, so the back door
  escapes the lock screen but not the wipe. What it gives an attacker is a
  *wiped* watch, which is the outcome the feature is trying to produce anyway.
- **A 4- or 6-digit PIN is not a cryptographic secret.** With flash in hand an
  attacker enumerates candidates offline regardless of hashing. The PIN
  defends the screen; the shred defends the data.
- **Residual copies below PFS.** `pfs_shred()` zeroes the live payload, and
  `pfs_gc_deleted_sectors()` sweeps stale copies left by earlier deletes and
  compaction, but the flash translation layer can remap and retain physical
  pages beneath both. Against a determined chip-off adversary this is
  best-effort.
- Health/step data, installed apps, and Bluetooth bonding all survive by
  design — see "What the erase destroys" below.

## One switch, and it ships off

There is exactly one notion of "on": `SecurityLockStateDisabled`. Off means no
trigger fires — not a lock that never engages, not a shred that quietly runs
anyway. It is enforced at the two funnels every path goes through,
`security_lock_engage()` in `lock.c` and `security_lock_shred()` in `shred.c`,
rather than at each caller, so a trigger that forgets to ask is covered anyway.

"Has a PIN" and "is on" are the same fact. Setting a PIN turns the feature on.
Turning it off requires the PIN and clears it.

The PIN is exactly 4 or 6 digits — nothing in between — of 1-9, since the pad
has no 0 key. It is hashed locally with 10,000 rounds of SHA-256
(`pin_hash.c`, `sha256.c` — local to the service, because mbedtls is only built
under `CONFIG_BT_FW_NIMBLE` and a lock that works on only some boards is not a
lock). **The PIN never goes over the air**, in either direction.

## Settings > Security

With no PIN set the menu is one row. Once a PIN exists it is ten:

| Row | What it does |
|---|---|
| Security Lock | Off/on. Turning it off asks for the PIN and clears it. |
| Change PIN | Asks for the current PIN, then sets a new one. |
| Lock After | Grace period from an unexpected disconnect to the lock. |
| Erase After | Countdown from a lockdown to the erase. **Ships as `Never`.** |
| Duress PIN | A second PIN that unlocks and wipes. |
| Block Notifications | Whether a notification arriving while locked is discarded or kept. **Ships off.** |
| Alarms When Locked | Whether an alarm still goes off while locked. **Ships on.** |
| Lock | Lock now; erase at `Erase After`, which the PIN cancels. |
| Lockdown + Erase | Lock now and erase now. No countdown. |
| Show in Launcher | Whether the Lock app is listed. |

`Lock After` offers 1 minute to 1 hour. `Erase After` offers 30 minutes to 24
hours plus `Never`, and `Never` is listed last because it is the weakest choice
on the list, not the one to land on by accident. An `Erase After` shorter than
`Lock After` is filtered out of the menu — it would erase a watch that had not
locked yet.

The `Lock` row states its own consequence in its subtitle, recomputed from
`Erase After` as the menu is drawn: *"Locks now, erases in 4 hr"*, or *"Locks
now, no timed erase"* when `Erase After` is `Never`.

The `Security Lock` row deliberately carries **no** subtitle. Any state shown
there is the state that has to stay hidden — whether the watch is protected is
the whole secret.

Source: `src/fw/apps/system/settings/security.c`.

## What triggers what

| Trigger | Result |
|---|---|
| Lock app, or its Quick Launch chord | Lock now, erase at `Erase After` |
| Settings > Lock | Lock now, erase at `Erase After` |
| Phone sends `LOCK` | Lock now, erase at `Erase After` |
| Settings > Lockdown + Erase | Lock **and erase**, immediately |
| Lockdown + Erase Quick Launch chord | Lock **and erase**, immediately |
| Phone sends `LOCK_ERASE` | Lock **and erase**, immediately |
| Unexpected disconnect while armed | Lock at `Lock After`, erase at `Erase After` |
| Erase countdown elapses | Erase, stay locked |
| Boot with state `Locked` | Re-erase, stay locked |
| 3 consecutive wrong PINs | Re-erase, stay locked |
| Clock wound back past the high-water mark | Erase, stay locked |
| Duress PIN | Unlock, erase silently, turn the feature off |

Everything in the first group is a countdown the PIN cancels, and arms nothing
at all when `Erase After` is `Never`. Everything below it is not a countdown,
and `Never` does not reach it.

The split matters because the triggers a user can hit *by accident* — the wrong
launcher row, a `LOCK` the phone derived from a platform callback — are all in
the first group. A mistaken tap costs a PIN entry, not data.

## The two Quick Launch apps

`Lock` and `Lockdown + Erase` are separate system apps with separate UUIDs,
so Quick Launch — which binds an install id resolved from the UUID — can bind
them to different buttons.

They differ in reach as well as in effect:

| | Launcher | Quick Launch | Available when |
|---|---|---|---|
| `Lock` | `Show in Launcher` | always | the lock is usable |
| `Lockdown + Erase` | **never** | when erasing is on | `Erase After` is not `Never` |

`Lockdown + Erase` is deliberately never listed in the launcher. The launcher is
somewhere a user lands by accident, and this is the one manual trigger the PIN
cannot call back — reaching it should take a binding made on purpose, or the
Settings row, which asks first. That also keeps `Show in Launcher` meaning what
it says instead of one switch governing two apps with very different
consequences.

`Erase After` gates it because that setting is where opting into erasing is
expressed: a user who has said "never erase on a timer" is not offered a chord
that erases with no timer at all.

A binding outlives the setting — nothing about moving `Erase After` to `Never`
clears the install id Quick Launch stored — so the app stays reachable through a
stale binding. In that case it **degrades to a plain `Lock`** rather than
refusing: locking is never the wrong half to do, and a panic chord that did
nothing would be the worst reading of it.

Neither app asks for confirmation. A panic button that asks is a worse panic
button, and reaching either takes a deliberate binding or a chosen launcher row.

Source: `src/fw/apps/system/lockdown.c`, registered in
`src/fw/shell/normal/system_app_registry_list.json`.

## The erase countdown

Deadlines are absolute wall-clock timestamps in the lock record, re-checked on a
periodic timer rather than armed as one long timeout — a one-shot timer survives
neither the watch sleeping nor a reboot, and the record survives both.

A countdown records **why** it was armed (`SecurityCountdownSource`), because
what may retire it depends entirely on that:

- **`SecurityCountdownDisconnect`** — the phone went away. Its coming back makes
  the countdown moot, so a session opening retires it.
- **`SecurityCountdownManual`** — the user (or their phone) asked for it. Only
  the PIN retires this one. A Bluetooth blip must not cancel a lockdown someone
  triggered on purpose, and a later disconnect may not restart, shorten or
  extend it either.

The source is written only through `security_lock_set_deadlines()`, alongside
the deadlines it describes, so it cannot be flushed separately from them or
outlive them.

Arming a manual countdown takes the **earlier** of the configured delay and any
countdown already pending, so pressing `Lock` can bring an erase forward but
never postpone one.

Rebooting does not cancel anything — restarting must never be cheaper than
waiting — and the `Lock` confirmation says so in as many words.

## What the erase destroys

The invariant the rest of the design rests on: **everything the shred destroys
comes back from the phone.** That is what makes triggering it aggressively
reasonable.

Destroyed (`shred_targets.c`): notification store, pins, reminders, contacts,
weather, iOS notification preferences, app glances.

Not destroyed: step and sleep history, installed apps and the app database,
Bluetooth bonding, and the datalogging queue — `dls` files are the outbound
watch-to-phone queue, so wiping them would destroy data the phone does *not*
have.

Nothing on the watch is encrypted. This protects the screen, not the flash.

A shred that runs while the watch is locked also takes the radio down
(`security_lock_radio_blackout_engage()`), restoring the user's prior airplane
setting on unlock. The blackout follows the *wipe*, not the lock: locking alone
leaves the radio up.

The wipe runs on KernelMain and holds it for seconds, the same freeze a factory
reset causes. That is deliberate — it closes and reopens databases whose re-init
is asynchronous, and driven from KernelBG they deadlock.

## While locked

The lock screen (`src/fw/popups/security/`) is a modal at
`ModalPriorityAlarm` — *not* `ModalPriorityMax`, which would stop it rendering
and receiving buttons at all. It shows `Locked` and a PIN pad, and forces touch
on for its lifetime so that someone who disabled touch before locking is not
shut out of their own watch.

Three consecutive wrong PINs re-shred and leave the watch locked. A correct PIN
resets the counter.

There is deliberately no `UNLOCK` command and no countdown display: the screen
says `Locked` and nothing else.

### Alarms still ring

The lockout's pop-up block is `launcher_block_popups_for_lock()`, a reference
count of its own rather than the shared `launcher_block_popups()`, and it lets
`PEBBLE_ALARM_CLOCK_EVENT` through. A watch that locked because the phone
walked out of range is still the user's watch, and an alarm that does not go
off is a missed flight. The exemption is not the general blocker's to grant — a
firmware update or a factory reset must still swallow an alarm — which is why
the count is separate.

Binding the modal stack at `ModalPriorityAlarm` is necessary but not
sufficient, and for a while only the first half was done: the event is dropped
in `prv_handle_event()` before a pop-up is ever built, so the priority bound
had nothing to let through.

Nothing leaks. The pop-up shows the current time and nothing else, and alarms
are not a shred target because the phone cannot restore them.

The alarm gets its own buttons, ahead of the raise-the-lock-screen rule, so
snooze and dismiss work without the PIN — otherwise a locked watch is one the
user cannot silence, and raising the lock screen would pop the pop-up and
silence the alarm by destroying it. The check compares the actual top window
rather than trusting the alarm's own "am I up" flag: this hands button events
to a modal on a locked watch, so *something is showing* is not good enough.

That does open one hole, and it is a deliberate trade: whoever holds a locked
watch can silence tomorrow's alarm. Nothing is read and nothing unlocks.

It stops once the content has actually been erased — past that the watch holds
nothing and talks to nobody — and `Settings > Security > Alarms When Locked`,
which ships on, turns the exemption off outright.

Both are asked of the lock itself, per event, rather than of the pop-up block.
The watch locks first and erases later, so the answer changes mid-lock; and the
block is taken by `security_lock_ui_lockout()`, which a watch that rebooted
straight into the locked state has not run — nothing does until the first
button press raises the lock screen. Keyed on the block, an erased watch would
ring through that whole window, and so would one whose owner had turned alarms
off.

A ringing alarm outranks the PIN pad, and is **the only thing that does**.
`ModalPriorityAlarm` sits one level above `ModalPrioritySecurityLock`, which is
itself above every other modal — so the pad covers everything except an alarm,
and an alarm covers the pad.

That way round because an alarm nobody can snooze or dismiss is worse than one
that never rang, and because it costs nothing: what answering it uncovers is
the pad it was covering, or the clock, both still locked. The app task never
sees the buttons either (`task_mask`), and the lockout bounds every stack at
the pad's level, so the alarm's is the only one that can be above it.

`security_lock_ui_lockout()` therefore bounds at `ModalPrioritySecurityLock`
rather than at the alarm's level: the bound has to admit the pad, and admitting
the pad admits the one level above it. The same applies to low power, which
clamps the same bound — a locked watch entering low power keeps its pad and its
alarms, and leaving low power cannot lower the clamp, because the lock holds it
as a *floor* and the effective bound is the higher of the two.

One consequence: the wipe cannot reach a ringing alarm by priority, since it
spares the pad and the alarm is above the pad. `security_lock_ui_quiesce()`
closes it by name instead.

### Two display shapes

The feature needs a digitizer, so it is on exactly where `CONFIG_TOUCH` is:
the obelix board (emery platform, rect 200x228) and the getafix board (gabbro
platform, **round** 260x260), plus their `qemu_emery` and `qemu_gabbro`
emulators. Half the supported hardware is round, so the pad has to be laid out
for a circle, not a bounding box.

`prv_geometry()` in `pin_entry_window.c` picks the margins with the
`PBL_IF_ROUND_ELSE()` macro, so the round arm is not compiled at all on a rect
build and vice versa. On a round display the whole layout pulls in by a sixth
of the display on each side, top and bottom, which is what keeps the four
corner keys inside the circle.

On gabbro that works out at nine 56x38 keys, columns at x = 43 / 102 / 161 and
rows at y = 95 / 136 / 177, inside a visible circle of radius 130 centred on
(130, 130). The tightest clearance is not a key: it is the **progress bar** at
the top, which sits 9px inside the circle at its narrowest row. The worst key
is the bottom row, at 11px. Anything that moves the bar or the two lines of
message text further up the screen eats that 9px first.

`tests/fw/popups/security/test_pin_entry_window.c` builds for both shapes
(`PLATFORMS obelix gabbro` in the test's `CMakeLists.txt`) and asserts every
key, the bar and the text against `g_perimeter_for_display` — the same
callback the firmware uses to say which columns a round display actually
shows for a given band of rows. On a rect build the visible span is the full
width and those assertions are trivially satisfied; running them there is what
stops the round arm of the layout being code nobody ever compiles.

## The duress PIN

A second PIN that *unlocks* the watch and wipes it in the background, leaving no
airplane-mode tell and looking like an ordinary unlock. It also turns the
feature off on the way through. At the disable prompt the ordering is explicit —
wipe, then disable — in one callback on one task, because the losing
interleaving of the race it replaced disarmed the lock with nothing erased.

That ordering used to be two tasks racing on priority — the wipe queued onto
the launcher task, the disable running straight through on the app task — which
usually resolved correctly and occasionally did not. "Usually" is the problem
on a compelled entry, so the two halves are now one callback with the order
written down instead of inferred:

```c
static void prv_duress_disable_cb(void *unused) {
  security_lock_shred(SecurityShredReasonDuressPin);
  security_lock_disable();
}
```

`security_lock_verify_pin_verdict()` is what makes this safe to build:
it reports `Wrong`, `Real` or `Duress` and schedules nothing, leaving the
ordering to the one caller in a position to get it right. It deliberately does
not become a UI branch — both accepted verdicts dismiss the prompt identically,
and the only difference is whether a wipe runs behind the dismissal. A future
caller that showed different UI for the two verdicts would be the bug this
type exists to prevent.

The residual tell: the wipe's first step tears down the running app, so
Settings closes to the watchface instead of returning to a Security menu now
reading "Off". That gap is not closeable without skipping the teardown, which
exists because a consumer left reading shredded storage mid-wipe is a crash,
not a cosmetic problem — so it is left open and written down here instead.

## The phone side

Private endpoint **11300 / 0x2C24**. Every message is `uint8 command` plus a
payload, big-endian, with responses carrying the high bit.

| Cmd | Msg | Direction | Payload |
|---|---|---|---|
| `0x02` | `LOCK` | phone → watch | `uint8 reason` |
| `0x03` | `STATUS_REQUEST` | phone → watch | — |
| `0x04` | `LOCK_ERASE` | phone → watch | `uint8 reason` |
| `0x82` | `LOCK_ACK` | watch → phone | `uint8 reason` |
| `0x83` | `STATUS_RESPONSE` | watch → phone | `uint8 state`, `uint8 pin_configured`, `uint32 deadline_remaining_s` |
| `0x84` | `SHRED_COMPLETE` | watch → phone | `uint8 reason`, `uint32 wiped_db_bitmap` |
| `0x85` | `STATE_CHANGED` | watch → phone | `uint8 state` |

`0x01` was `CONFIGURE`, which let the phone set the master switch and both
delays. It is retired: the watch owns its own security configuration, and a
phone that can disarm the watch is a phone that can be compelled to. An older
phone still sending it falls through the unknown-command path.

**`LOCK_ACK` means locked, not erased**, on both commands. `SHRED_COMPLETE` is
what says the content is gone — immediately on `LOCK_ERASE`, and when and if the
countdown expires on `LOCK`. It carries the database bitmap the phone must
resend, and is queued until there is a session to say it on, because the two
cases that need it are precisely the ones with no phone attached.

`LOCK_ERASE` acks *before* it erases, and the order is load-bearing: the erase
takes the radio down, so an ack sent afterwards could never arrive.

A refused `LOCK` answers with `STATE_CHANGED` rather than `LOCK_ACK` — silence
would be indistinguishable from a watch that had gone away, and an ack would
make the phone believe a watch that did nothing is now locked and wiped.

Source: `src/fw/services/security_lock/endpoint.c`.

### Gadgetbridge

Two screens, because the settings answer to different owners:

- **App-wide** (Settings > Security lockdown) — whether to respond to Android
  entering lockdown at all, and a "Lock watches now" action for the case where
  Android reports lockdown only if notifications were showing at the time.
- **Per watch** (device settings > General > Security) — `Erase this watch on
  lockdown`, on by default. Per watch because only a PebbleOS build carrying
  this endpoint can act on it, and because one paired watch may hold real
  content while another is a test unit.

Gadgetbridge cannot switch the Bluetooth adapter off; it disconnects and stops
using the radio. It also cannot make Android itself enter real Lockdown —
`DevicePolicyManager.lockNow()` is an ordinary lock that leaves biometrics
enabled, and the only route to true Lockdown is an accessibility service driving
the power menu, gated behind a permission an app cannot grant itself.

## Recovering a watch whose PIN is lost

Hold SELECT+BACK+UP. The button ISR sets `BOOT_BIT_FORCE_PRF` below anything
software can intercept, and the watch boots recovery firmware, which never
starts this feature — no lock screen, no PIN prompt. A factory reset from there
returns an empty watch, ready to re-pair and resync.

**This is deliberate, not a hole to be closed.** What it gives an attacker is a
*wiped* watch, which is the outcome the feature is trying to produce anyway; it
cannot be used to read anything. Closing it would trade nothing for a user
permanently locked out by a forgotten four-digit PIN.

## Not built, deliberately

- **A menu to choose what gets erased**, including health data and apps. Asked
  for and then withdrawn: it would break the invariant the rest of this design
  rests on — that everything the shred destroys comes back from the phone —
  which is what makes triggering it aggressively reasonable. Revisiting it
  means revisiting "locking almost always ends in a shred" at the same time,
  and an unrestorable target needs a warning the user cannot miss.
- **Shredding health/step data**, for the same reason. A watch-initiated phone
  lockdown was considered too, for the symmetric case — see the Gadgetbridge
  section above for why Android does not permit it.

## Where the code lives

| Path | Role |
|---|---|
| `src/fw/services/security_lock/service.c` | State, records, persistence |
| `src/fw/services/security_lock/lock.c` | The lock funnel and its three entry points |
| `src/fw/services/security_lock/shred.c` | The wipe, the boot hook, the blackout |
| `src/fw/services/security_lock/shred_targets.c` | What gets erased |
| `src/fw/services/security_lock/endpoint.c` | Protocol, deadlines, the periodic check |
| `src/fw/services/security_lock/pin_hash.c`, `sha256.c` | PIN hashing |
| `src/fw/popups/security/` | Lock screen and PIN pad |
| `src/fw/apps/system/settings/security.c` | Settings > Security |
| `src/fw/apps/system/lockdown.c` | The Lock and Lockdown + Erase apps |
| `include/pbl/services/security_lock*.h` | Public interfaces |

## Testing

Unit suites live under `tests/fw/services/security_lock/`, plus
`tests/fw/apps/system_apps/settings/test_settings_security.c`,
`tests/fw/apps/system_apps/lockdown/`, `tests/fw/popups/security/` and
`tests/fw/applib/test_security_shred_service.c`. `pbl test` builds a CMake/
ctest project for the host, so `-R` filters by the test's declared name (each
`pbl_clar_test(name ...)`) rather than a file path — no single pattern
matches every test this feature added, since not all of them are named
`test_security_lock*`:

```
pbl test -- -R 'test_security_lock|test_settings_security|test_lockdown|test_pin_entry_window|test_security_shred_service'
```

Two harnesses drive a running QEMU instance: `tools/security_lock_e2e.py`
(the real touch UI and the protocol endpoint) and `tools/security_lock_stress.py`
(a wipe colliding with notification traffic). Both assume **one** QEMU instance —
a second collides on the fixed monitor, QMP and console sockets and produces
convincing failures that are pure artefact.

`security_lock_e2e.py` drives the real UI, so it has to know where things are
on the screen. Everything that depends on the UI's shape — the Settings menu
order and the keypad geometry — is collected at the top of the file, under a
heading that says so, rather than spread through the individual tests: moving a
menu row or retuning the pad is one edit in one place. Everything else it needs
(display size, display shape) is read off the running machine and the board.
The unit suite above is the one that says the pad is laid out correctly; the
harness only assumes it is.
