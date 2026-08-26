# Security lock

A PIN lock for the watch, and a shred that destroys the watch's copy of the
phone's data. It exists for one situation: the phone is taken, and the watch on
the wrist is a second screen showing the same notifications, calendar and
contacts — behind no authentication at all.

The design rationale, threat model and the arguments behind each decision live
in `docs/proposals/security-lockdown.md`. This page describes what the feature
*does*, end to end, and where each part of it lives.

The whole thing is normal-firmware only: `security_lock_init()` and
`security_lock_handle_boot()` are called from `services_normal_early_init()`,
which sits behind `#ifndef CONFIG_RECOVERY_FW`. PRF does not build it.

## One switch, and it ships off

There is exactly one notion of "on": `SecurityLockStateDisabled`. Off means no
trigger fires — not a lock that never engages, not a shred that quietly runs
anyway. It is enforced at the two funnels every path goes through,
`security_lock_engage()` in `lock.c` and `security_lock_shred()` in `shred.c`,
rather than at each caller, so a trigger that forgets to ask is covered anyway.

"Has a PIN" and "is on" are the same fact. Setting a PIN turns the feature on.
Turning it off requires the PIN and clears it.

The PIN is 4–6 digits, hashed locally with 10,000 rounds of SHA-256
(`pin_hash.c`, `sha256.c` — local to the service, because mbedtls is only built
under `CONFIG_BT_FW_NIMBLE` and a lock that works on only some boards is not a
lock). **The PIN never goes over the air**, in either direction.

## Settings > Security

With no PIN set the menu is one row. Once a PIN exists it is eight:

| Row | What it does |
|---|---|
| Security Lock | Off/on. Turning it off asks for the PIN and clears it. |
| Change PIN | Asks for the current PIN, then sets a new one. |
| Lock After | Grace period from an unexpected disconnect to the lock. |
| Erase After | Countdown from a lockdown to the erase. **Ships as `Never`.** |
| Duress PIN | A second PIN that unlocks and wipes. |
| Lockdown | Lock now; erase at `Erase After`, which the PIN cancels. |
| Lockdown + Erase | Lock now and erase now. No countdown. |
| Show in Launcher | Whether the Lockdown app is listed. |

`Lock After` offers 1 minute to 1 hour. `Erase After` offers 30 minutes to 24
hours plus `Never`, and `Never` is listed last because it is the weakest choice
on the list, not the one to land on by accident. An `Erase After` shorter than
`Lock After` is filtered out of the menu — it would erase a watch that had not
locked yet.

The `Lockdown` row states its own consequence in its subtitle, recomputed from
`Erase After` as the menu is drawn: *"Locks, erases in 4 hr"*, or *"Locks, no
timed erase"* when `Erase After` is `Never`.

The `Security Lock` row deliberately carries **no** subtitle. Any state shown
there is the state that has to stay hidden — whether the watch is protected is
the whole secret.

Source: `src/fw/apps/system/settings/security.c`.

## What triggers what

| Trigger | Result |
|---|---|
| Lockdown app, or its Quick Launch chord | Lock now, erase at `Erase After` |
| Settings > Lockdown | Lock now, erase at `Erase After` |
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

`Lockdown` and `Lockdown + Erase` are separate system apps with separate UUIDs,
so Quick Launch — which binds an install id resolved from the UUID — can bind
them to different buttons.

They differ in reach as well as in effect:

| | Launcher | Quick Launch | Available when |
|---|---|---|---|
| `Lockdown` | `Show in Launcher` | always | the lock is usable |
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
stale binding. In that case it **degrades to a plain `Lockdown`** rather than
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
countdown already pending, so pressing `Lockdown` can bring an erase forward but
never postpone one.

Rebooting does not cancel anything — restarting must never be cheaper than
waiting — and the `Lockdown` confirmation says so in as many words.

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

## The duress PIN

A second PIN that *unlocks* the watch and wipes it in the background, leaving no
airplane-mode tell and looking like an ordinary unlock. It also turns the
feature off on the way through. At the disable prompt the ordering is explicit —
wipe, then disable — in one callback on one task, because the losing
interleaving of the race it replaced disarmed the lock with nothing erased.

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
software can intercept, and the watch boots recovery firmware, which does not
build this feature. A factory reset from there returns an empty watch, ready to
re-pair and resync.

**This is deliberate, not a hole to be closed.** What it gives an attacker is a
*wiped* watch, which is the outcome the feature is trying to produce anyway; it
cannot be used to read anything. Closing it would trade nothing for a user
permanently locked out by a forgotten four-digit PIN.

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
| `src/fw/apps/system/lockdown.c` | The Lockdown app |
| `include/pbl/services/security_lock*.h` | Public interfaces |

## Testing

Unit suites live under `tests/fw/services/security_lock/`, plus
`tests/fw/apps/system_apps/settings/test_settings_security.c` and
`tests/fw/apps/system_apps/lockdown/`. Note that `./waf test -M` matches the
**absolute path** with `re.match`, so an unanchored alternative like
`security_lock` can match every test in the tree and silently disable the
filter — anchor under `/tests/`:

```
./waf test -M '.*/tests/.*security_lock.*'
```

Two harnesses drive a running QEMU instance: `tools/security_lock_e2e.py`
(the real touch UI and the protocol endpoint) and `tools/security_lock_stress.py`
(a wipe colliding with notification traffic). Both assume **one** QEMU instance —
a second collides on the fixed monitor, QMP and console sockets and produces
convincing failures that are pure artefact.

`security_lock_e2e.py` encodes the Settings menu row order as a list. That list
has gone stale repeatedly, and a shifted index shows up as the wrong row quietly
doing nothing rather than as an obvious failure.
