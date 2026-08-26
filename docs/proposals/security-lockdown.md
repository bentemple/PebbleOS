# Proposal: Security Lockdown & Data Shred

## Summary

A coordinated PebbleOS + Gadgetbridge feature. When the phone enters Android
lockdown mode (or a tamper condition is detected on the watch), the watch locks
behind a PIN and destroys the sensitive data it holds.

**The shred is watch-only, and deliberately limited to data the phone can
restore.** The rationale is asymmetry: Android gives the phone real
file-based encryption at rest, so a locked phone's data is already
cryptographically protected. The watch has *no encryption of any kind*
(verified — there is no at-rest crypto anywhere in `src/fw`), so everything on
it is cleartext to anyone with a flash reader. The watch is the weak link, and
that is where the effort goes.

Because everything shredded is restorable from the phone on reconnect, the
shred is cheap to trigger and safe to trigger often. That in turn means we can
be aggressive about triggering it.

### Explicitly out of scope

Health and step history (`activity` settings file, `healthdb`), third-party app
persistent storage, the app DB, BT pairing keys, and **datalogging buffers**
(`dls*`) are **not** shredded. Health data is sensitive and this is an accepted
cost — it is not restorable from the phone, and wiping it would make the feature
destructive enough that nobody would turn it on. Preserving pairing also means
the watch silently reconnects and resyncs, which is what makes
reboot-while-locked a non-event.

Datalogging deserves its own note, because an earlier draft did shred it. Those
files are the outbound watch→phone queue: by definition they hold data the phone
does *not* have yet, so wiping them is unrecoverable loss rather than a resync.
They also carry activity samples, which means shredding them quietly destroyed
part of the one category this document promises never to touch. The rule that
resolves it: **the shred only ever destroys data the phone can give back.**
Anything that fails that test does not belong in the target list.

Shredding health data was considered as an opt-in setting and deliberately not
built. It would be the only control capable of destroying something the user
cannot get back, and no threat in the model above justifies offering it.

A menu for *which* data gets erased, health and apps included, was proposed and
then withdrawn — see "Not built, deliberately" under Status. Two notes for
anyone who revisits it. Nothing in the countdown machinery names a target list:
every trigger calls `security_lock_shred(reason)` and the scope is decided
inside, so a list would be read when the wipe runs rather than when the
countdown is armed — which is the easier of the two to build, but means
changing the list mid-countdown changes what that countdown destroys. And more
importantly, adding anything unrestorable invalidates the reasoning in "Locking
almost always ends in a shred", which has to be revisited at the same time.

This has a consequence that must not be glossed over: **a seized watch still
yields step, sleep, and heart-rate history.** That is a deliberate trade, not
an oversight.

## Threat model

1. **Border / device seizure.** Adversary holds both phone and watch and may
   compel unlock.
2. **Protest / activist context.** Phone taken while the watch is worn; the
   watch must act autonomously when it loses the phone.
3. **Opportunistic theft / snooping.** Someone picks the watch up and reads it.

### What this cannot defend against

- **No encryption at rest on the watch.** Verified: no AES/KDF-at-rest code in
  `src/fw`; `MBEDTLS_AES_C` is compiled only for the NimBLE link layer. Erasure,
  not access control, is the only real control available.
- **The 5-second SELECT+BACK hard reset cannot be blocked.** Handled in the TIM4
  debounce ISR below the OS (`src/fw/drivers/nrf5/debounced_button.c:160-186`,
  mirrored in `sf32lb52/`), commented *"This back door absolutely must work."*
  Holding UP as well sets `BOOT_BIT_FORCE_PRF` and boots recovery firmware.
  **Mitigation: reboot-while-locked re-runs the shred at early boot, so the back
  door escapes the lock screen but not the wipe.**
- **A 4-digit PIN is not a cryptographic secret.** With flash in hand an attacker
  enumerates 10,000 candidates offline regardless of hashing. The PIN defends the
  screen; the shred defends the data.
- **Residual copies below PFS.** See "Zeroing actually works" below — we can do a
  great deal better than `pfs_remove()`, but the FTL/wear-levelling layer
  (`flash_translation.c`) can remap and retain physical pages, and we do not
  control it. Against a determined chip-off adversary this is best-effort.
- Health/step data survives, per "out of scope" above.

## Architecture

### State machine

```
              set PIN
Disabled ──────────────> Armed ──────────────────> Locked
   ^                       ^   Lockdown              │ (erase countdown armed)
   │                       │   phone LOCK cmd        │
   │                       │   disconnect grace      │  correct PIN
   │  turn off (PIN goes)  │   Lockdown + Erase ─────┤  cancels the countdown
   └───────────────────────┴─────────────────────────┘
                                   ^                 │  Erase After elapses
                                   │                 v  / reboot / 3 bad PINs
                                   └───────────── Shredding
                          (re-shred + stay locked)
```

**Locking and erasing are two things, and the destructive one has to be asked
for by name.** Everything reachable without choosing it specifically — the
Lockdown app and its chord, the Settings `Lockdown` row, the phone's `LOCK`, the
disconnect grace — locks *now* and arms the erase for `Erase After` later. The
PIN cancels it. Erasing on the spot has its own controls: the
`Lockdown + Erase` row in Settings, which asks first; the phone's `LOCK_ERASE`;
and a `Lockdown + Erase` Quick Launch app, which is bindable only while
`Erase After` is set and is deliberately never listed in the launcher.

That is a change from an earlier revision, where every manual trigger erased
immediately and only the disconnect path deferred. The reasoning:

- The triggers a user can hit by accident are the ones reached without aiming —
  the wrong launcher row, a `LOCK` Gadgetbridge derived from a platform
  callback. An immediate erase made all of them unrecoverable in the only sense
  that matters to the user: the watch goes blank and stays blank until the phone
  resyncs.
- A Quick Launch binding is not one of those. It is a button the user chose to
  bind to a named app, so it is the one place an erase-now chord is defensible —
  and it stays gated on `Erase After`, so it cannot be bound at all by someone
  who has not opted into erasing. Held in a pocket it still erases, which is the
  residual cost of having the chord exist.
- Locking without *some* timed erase is not offered, because it would be a
  second way to spell `Erase After: Never` and the two would drift. A user who
  wants lock-only sets Never, which every countdown path already honours.
- `LOCK` arrives over the air and is derived from a platform callback rather
  than a button, so it defers to `Erase After` like every other unaimed trigger.
  A phone that means "now" says so with `LOCK_ERASE`, which is a separate
  command precisely so the unaimed one is not the destructive one. See §8.

`Disabled` is the master switch for the whole feature, and it is where the watch
ships. It is not a second notion of "on" beside the PIN: there is exactly one,
so nothing can consult the wrong one. Off means no trigger fires — not the
phone's `LOCK`, not Lockdown, not Lockdown + Erase, not the console, not a
disconnect deadline (none is armed in the first place), not a clock rollback. It
is enforced at the two funnels every trigger goes through, `prv_engage()` in
`lock.c` — which `security_lock_engage()`, `security_lock_engage_lock_only()`
and `security_lock_engage_with_countdown()` all reach — and
`security_lock_shred()`, rather than at each caller, so a trigger added later is
gated without knowing about it. A refused lock arms no countdown either: the
arming happens after the state change, not before the attempt.

**Off is a clean slate, and getting there costs the PIN.** Setting a PIN is the
only way in; `security_lock_disable()` is the only way out, and it clears the
PIN, the duress PIN and every setting the feature keeps. So "has a PIN" and "is
on" are one fact rather than two that have to be kept in step, and there is no
`set_enabled(true)` for them to disagree through.

That is a security property, not tidiness. A switch that merely paused the
feature protected less than the lock screen did: anyone holding an *unlocked*
watch could walk into Settings and disarm the whole thing in two presses.
Turning it off now goes through the same PIN prompt as changing the PIN does.

One refusal remains: it cannot be turned off while `Locked`, which would be an
unlock without the PIN. Settings is unreachable from a locked watch so nothing
reaches it today, but the rule lives in the store rather than in the caller.
Only the PIN clears a lock.

`security_lock_clear_pin()` is the same operation reached from the recovery
side — the console hook and internal cleanup — and deliberately does *not*
carry the `Locked` refusal.

Settings > Security has exactly two shapes, and the switch is row 0 in both:

| Off | On |
|---|---|
| Security Lock — *Off* | Security Lock — *On* |
| | Change PIN — *Set, N digits* |
| | Lock After — *N min after disconnect* |
| | Erase After — *N min after disconnect* / *Never, locks only* |
| | Duress PIN — *(no subtitle, ever)* |
| | Lockdown — *Locks, erases in N min* / *Locks, erases in N hr* / *Locks, no timed erase* |
| | Lockdown + Erase — *Locks and erases now* |
| | Show in Launcher — *On* / *Off, Quick Launch only* |

There is no Clear PIN row: clearing the PIN is what turning the switch off does,
so a row for it would be the same button under a second name. There is no PIN
Length row either — see below. And there is no lock-only row: that is `Erase
After: Never` plus *Lockdown*, and a row for it would be a second spelling of a
setting the disconnect path already obeys.

`Lock Now` is gone rather than reused. Once there were two actions its name and
its subtitle (*Lock and erase*) described neither accurately, and the one it
described worst was the destructive one.

**The Lockdown row's subtitle is the only place the concrete delay appears
beside the action it applies to.** `Erase After` says what the number is and
what it is counted from; the row below says what pressing it will cost. Without
that, learning that *Lockdown* starts an erase at all means reading a setting
three rows up and joining them yourself. It follows the setting live, so
changing `Erase After` and glancing down is the ordinary way to use the pair.

**PIN length is a step in the set-PIN flow**, not a row. With the menu down to
one row while the feature is off there is nowhere for a standalone row to live,
and a user turning the feature on from scratch would otherwise get whatever
length happened to be stored rather than one they chose. So:

- Turning it on: *Security Lock* → length picker → New PIN → Repeat PIN.
- Changing it: *Change PIN* → Current PIN → length picker → New PIN → Repeat.
- Turning it off: *Security Lock* → Current PIN ("Turning off clears your PIN").
- Duress PIN: *Duress PIN* → Current PIN → New duress PIN → Repeat. **No
  picker** — a duress PIN is pinned to the real PIN's length, because
  `security_lock_verify_pin()` only tries the duress hash when the entered
  length matches and the lock screen only ever prompts for the real PIN's.

The picker opens on the current PIN's length (or four when there is none), so
the extra step costs one press when the length is not the point. This also
retires the old two-step dance — set the length in one row, then go and change
the PIN in another — which was listed as a known wart.

The two records can still lose step: the config record holds the PIN and the
runtime record holds the state, and they version independently, so a firmware
upgrade that bumps only the runtime version discards the state while the PIN
survives. `security_lock_init()` repairs that by coming back `Armed` when it
falls back to defaults with a PIN still stored. This is *not* made redundant by
off clearing the PIN — a watch that was turned off has no config record to be
rearmed from, so the fallback now only ever fires for someone who genuinely had
the feature on, and the old caveat that it might re-enable something the user
had switched off no longer applies.

The one thing the switch does not gate is finishing a wipe that was interrupted
by power loss (`shred_pending`). The content is already half destroyed by then,
and a half-wiped filesystem passes for an untouched one, so that runs at the
next boot whatever the switch says — but it locks nothing.

There is **one shred scope**. Every trigger runs the same wipe; escalation
triggers differ only in that they re-run it and keep the watch locked. This is
a simplification over an earlier two-tier draft, and it follows directly from
the shred being non-destructive.

### Locking ends in a shred if the user has asked for one

Worth stating plainly, because it is the practical behaviour rather than an
edge case. With an `Erase After` set, avoiding the shred once the watch locks
requires entering the correct PIN before that delay elapses *and* not rebooting
in the meantime. A flat battery, a crash, a five-second SELECT+BACK, or simply
not noticing all end in a wipe.

That is intended, and it is only reasonable because of the scope decision
above: everything the shred destroys comes back from the phone on reconnect.
Nothing unrecoverable is at stake -- health and step history, the one category
the phone cannot restore, is deliberately never touched. So the cost of an
unnecessary shred is a resync, not a loss.

The lock phase is therefore best understood as a grace period, not as a durable
state the watch is expected to sit in. If that ever stops being true -- if
something unrestorable gets added to the shred list -- this trade has to be
revisited at the same time.

**`Erase After` ships as `Never`, so out of the box none of that happens.** The
watch locks, the countdown is armed at nothing, and the content survives until
the user opts into a delay. The erase is the destructive half and the half the
watch cannot undo, so it is the half that is opt-in.

The reboot rule is the one exception `Never` does not cover, and it is
deliberate: a reboot while locked still shreds. Rebooting is the one reliable
way past the lock screen -- SELECT+BACK held for five seconds hard resets from
the button ISR, below anything software can intercept -- so restarting must
never be cheaper than waiting. `Never` disarms the *timed* erase, not every
erase.

### Trigger matrix

| Trigger | Detected where | Result |
|---|---|---|
| Lockdown app / Quick Launch chord | `security_lock_engage_with_countdown()` | Lock now, erase at `Erase After` |
| Settings > Lockdown | Same, after a confirmation | Lock now, erase at `Erase After` |
| Phone sends `LOCK` | Protocol endpoint | Lock now, erase at `Erase After` |
| Settings > Lockdown + Erase | `security_lock_engage()` | Lock + shred, immediately |
| Lockdown + Erase Quick Launch chord | Same, gated on `Erase After` | Lock + shred, immediately |
| Unexpected disconnect while Armed | `PebbleCommSessionEvent` close + grace | Lock at `Lock After`, erase at `Erase After` |
| Boot with state == `Locked` | Early-boot hook | Re-shred, stay locked |
| Erase countdown elapses | Absolute-deadline check | Shred, stay locked |
| 3 consecutive wrong PINs | Lock screen | Re-shred, stay locked |
| Duress PIN | PIN verification | Unlock, shred silently |
| `rtc_get_time()` < persisted high-water mark | Deadline check | Shred, stay locked |

Every "erase at `Erase After`" row above is a countdown the PIN cancels, and
every one of them arms nothing at all when `Erase After` is `Never`. The rows
below the divider are not countdowns and `Never` does not reach them.

### Which countdown, and what may cancel it

Two things arm the erase countdown, and what may retire it depends entirely on
which. That is stored, not inferred:

```c
typedef enum {
  SecurityCountdownNone = 0,
  SecurityCountdownDisconnect = 1,
  SecurityCountdownManual = 2,
} SecurityCountdownSource;
```

It lives in the runtime record beside the deadlines, written by the same
`security_lock_set_deadlines()` call, so no reader can catch a countdown whose
source has not caught up and no caller can arm one without saying why. Both
deadlines at zero forces the source back to `None`, so "armed" has one spelling
and a stale source cannot outlive the countdown it described.

It is persisted rather than kept in RAM because a reboot while locked is a
designed-for case, and a manual countdown that came back as a disconnect one
would hand the very next Bluetooth reconnect the power to cancel it.

**A session opening retires a disconnect countdown and never a manual one.**
The phone coming back makes the first moot; it says nothing whatever about the
second. Without the distinction, a Bluetooth blip silently cancels a lockdown
someone triggered on purpose — and Gadgetbridge reconnects on its own, so that
is the shape an attacker holding the phone actually produces. Only the PIN
retires a manual countdown, for the same reason only the PIN clears a lock.

**A session closing leaves a manual countdown exactly as it found it.** The
reverse direction, and just as easy to get wrong: arming afresh would restart
the erase clock, so with a longer `Erase After` — or `Never` — walking out of
Bluetooth range would postpone or cancel the erase the user asked for. Nothing
is lost by skipping the arming, because a manual countdown implies the watch is
already locked and there is no lock deadline left to arm.

**A manual lockdown may only ever bring an erase forward.** If a disconnect
countdown was already closer than the configured delay, that deadline is kept
rather than replaced — and promoted to manual either way, which is what takes it
out of reach of the reconnect that would otherwise have cancelled it. So
pressing *Lockdown* on a watch that has already lost its phone cannot buy time.

## Firmware design

### 1. Lock state store — `src/fw/services/security/lock_state.{c,h}`

A dedicated `settings_file` named `seclock`, opened directly rather than through
blob\_db, because it must be readable before `blob_db_init_dbs()` runs.

```c
typedef struct PACKED {
  uint16_t version;
  SecurityLockState state;      // Disabled / Armed / Locked
  uint8_t  pin_len;             // 4..8
  uint8_t  salt[16];            // from rng_rand()
  uint8_t  pin_hash[32];
  uint8_t  failed_attempts;
  bool     shred_pending;       // set before shredding, cleared after
  time_t   lock_deadline;       // 0 = not armed
  time_t   shred_deadline;      // 0 = not armed
  uint8_t  countdown_source;    // why: none / disconnect / manual
  time_t   time_high_water;     // monotonic guard against RTC rollback
} SecurityLockRecord;
```

Two write-ordering rules that carry the whole design:

- **Increment `failed_attempts` and flush *before* checking the PIN**, so pulling
  power mid-verification counts as a failure rather than resetting the counter.
- **Set `shred_pending` before starting a shred**, so an interrupted shred
  resumes at next boot.

Mirror "locked" into a spare RTC-backup boot bit (`1 << 20` is free,
`src/fw/system/bootbits.h`). The settings file is authoritative; the boot bit is
a redundant signal that survives a corrupted filesystem. It does not survive a
long battery pull, so it can never be the only copy.

### 2. Making the zeroing actually work

This is the part that is easy to get wrong, and the requirement is explicit:
clear the data *and zero the memory it was stored in*.

Three layers each retain data after an ordinary delete, all verified:

1. `pfs_remove()` clears a single page-header flag and leaves the payload bytes
   untouched (`pfs.c:825` `unlink_flash_file`, called from `pfs.c:1494`).
2. `settings_file` deletes are tombstones — a new zero-length record is appended
   and the old record's header bits flipped; key and value bytes remain
   (`settings_file.c:507-585`).
3. Even after compaction (`settings_file_rewrite_filtered`, `settings_file.c:219`)
   the *old* PFS file is only unlinked, so its bytes persist until PFS garbage
   collection happens to reclaim that sector.

Since we are not doing a full `pfs_format()` (that would take health data with
it), the shred needs two new primitives:

```c
//! Overwrite a file's payload with zeroes, then unlink it.
//! NOR flash writes only clear bits, so writing 0x00 over live data always
//! succeeds without an erase.
status_t pfs_shred(const char *filename);

//! Force garbage collection of every erase-sector that contains deleted pages.
//! Live pages are copied out and the sector is physically erased, destroying
//! stale copies left behind by earlier deletes, compactions and overwrites.
//! Preserves all live data, so health/activity storage is unaffected.
status_t pfs_gc_deleted_sectors(void);
```

`pfs_gc_deleted_sectors()` reuses the existing `garbage_collect_sector()`
machinery (`pfs.c:2059`), which already does exactly the right thing — copy live
pages to the GC sector, erase the original — but is normally driven only by
allocation pressure. Exposing it as a deliberate sweep is the key change.

Shred sequence per target: `pfs_shred()` each file, then one
`pfs_gc_deleted_sectors()` sweep at the end. Cost is bounded by how many sectors
actually hold deleted pages (~150 ms per 64 KB sector erase).

Shredding a whole settings-file-backed DB via `pfs_shred()` on the file handles
live records and tombstones together — no need to walk records individually.

### 3. Shred targets

| Data | Backing store |
|---|---|
| Notifications | PFS `notifstr` (`notification_storage.c:29`) |
| Calendar pins | PFS `pindb` (`pin_db.c:27`) |
| Reminders | `reminderdb` |
| Contacts | `contactsdb` |
| Weather | `weatherdb` |
| iOS notif prefs | `iosnotifprefdb` |
| App glances | `appglancedb` |

Plus non-PFS flash regions that can hold leaked content — a coredump is a RAM
snapshot and can contain notification text: raw erase of `FLASH_REGION_CD_*` and
`FLASH_REGION_DEBUG_DB_*`.

Plus RAM-resident state: music metadata (`music/service.c:41-43`), phone-call /
caller-ID event state, and — easy to forget — **the compositor framebuffer**,
which may be displaying a notification at the instant of lock. Force a repaint.

While `Locked`, incoming notifications must be **dropped, not stored**. Add the
check in `notifications.c` rather than relying on wiping them later.

### 4. Lock screen — `src/fw/popups/security/lock_screen.{c,h}`

Implement as a **modal, not an app.** Verified reason: the BACK-held-1.5s
force-quit path (`event_loop.c:182-198`) kills any app at
`ProcessAppRunLevelNormal`, which would pop a lock screen implemented as an app.
Modals are not subject to it.

Follow the kernel-panic / critical-battery precedent (`kernel/panic.c:15-29`,
`shell/normal/battery_ui_fsm.c:166-181`):

```c
modal_manager_pop_all();
modal_manager_set_min_priority(ModalPriorityMax);   // blocks everything below
window_set_overrides_back_button(window, true);     // factory_reset.c:41-44
```

Quick Launch needs no special handling: its bindings live on the watchface's
click-config provider, and `launcher_handle_button_event` routes to
`modal_manager_handle_button_event` whenever a modal has focus
(`event_loop.c:240-246`), so they are suppressed naturally.

Behaviour — clock stays visible, any button raises the lock screen:

- On entering `Locked`: `app_manager_close_current_app(true)`, then
  `watchface_launch_default()`, then `launcher_block_popups(true)`.
- Do not push the modal yet; the clock remains on screen.
- In `launcher_handle_button_event`, if `Locked` and the modal is not up: push it
  and swallow the event. Also swallow the 10×BACK coredump path
  (`event_loop.c:200-213`) while locked.

### 5. PIN entry

`selection_layer` caps at `MAX_SELECTION_LAYER_CELLS = 3`, too few for a 4-digit
PIN without raising a constant that costs memory for every other user. Write a
small dedicated `security_pin_window`: UP/DOWN change the digit, SELECT advances.

Hashing: `MBEDTLS_SHA256_C` / `MBEDTLS_PKCS5_C` are **not** currently enabled in
`third_party/mbedtls/.../pebble_mbedtls_config.h` (only `MBEDTLS_AES_C`).
Enabling them costs a few KB of flash. Salt from `rng_rand()`
(`include/pbl/drivers/rng.h:11`).

Be clear-eyed: PBKDF2 over a 4-digit PIN is trivially brute-forced offline. It
prevents casual recovery of the PIN string itself (which the user may have
reused). The attempt counter, not the hash, protects the data.

### 6. Early-boot shred hook

`services_normal_early_init()` is exactly `pfs_init(true)`
(`services_normal/service.c:81-83`), called from `main.c:317` — after PFS mounts,
but before `display_init()` (`main.c:344`), `bt_driver_init()` (`main.c:352`) and
`services_init()` (`main.c:354`).

Read `seclock` there; if `state == Locked` or `shred_pending`, run the shred
before any pixel is drawn or the radio comes up.

### 7. Erase countdown and clock trust

Timers survive neither sleep nor reboot. Use the pattern established by
`cron/service.c`: persist an **absolute deadline**, re-arm a short capped timer
on each wake.

- On session close while Armed or Locked, and no manual countdown running:
  `lock_deadline = now + Lock After`, `shred_deadline = now + Erase After`,
  `countdown_source = Disconnect`.
- On a manual lockdown: `shred_deadline = now + Erase After`,
  `countdown_source = Manual`, never later than a deadline already pending.
- On session open: clear, **unless the source is Manual**.
- On unlock: clear, whatever the source. This is the only thing that retires a
  manual countdown, and it goes through `security_lock_set_state()` so no caller
  has to remember.
- Check on every wake, timer tick, and at the boot hook. The tick also stops the
  timer once nothing is armed, which is how an unlock retires it: the record
  store cannot reach into the endpoint to stop a timer.

`Erase After: Never` leaves the shred deadline at zero, which is already how
"nothing pending" is spelled everywhere else, so it needs no special case
beyond the ordering check in `security_lock_set_delays()`. **`Never` is the
shipped default**, which makes that path the ordinary one rather than an
option.

`rtc_get_time()` is settable by the user and the phone; there is no
reboot-persistent monotonic clock (`rtc_get_ticks()` resets on boot). Keep
`time_high_water` in the lock record, bump it as time advances, and treat a
backwards jump beyond a small slack as tamper. Refuse phone-initiated time
changes while `Locked`.

### 8. Protocol endpoint

New private endpoint in `normal_fw_only` of
`src/fw/services/comm_session/protocol_endpoints_table.json`. Proposed ID
**11300 / 0x2C24** (unused; neighbours are 11000 voice, 11440 timeline actions).
Self-assigned — flag if upstream compatibility matters.

Every message is `uint8 command` followed by a command-specific payload,
big-endian, following the `RESPONSE_MASK = 1 << 7` convention the BlobDB
endpoint already uses.

**The PIN is set on the watch and never sent over the air.** The phone can lock
the watch but cannot set, read or clear the PIN. Otherwise compromising the
phone would hand over the watch's unlock secret, which defeats the point of the
watch locking when the phone is seized.

| Cmd | Msg | Direction | Payload |
|---|---|---|---|
| `0x02` | `LOCK` | phone → watch | `uint8 reason` |
| `0x03` | `STATUS_REQUEST` | phone → watch | — |
| `0x04` | `LOCK_ERASE` | phone → watch | `uint8 reason` |
| `0x82` | `LOCK_ACK` | watch → phone | `uint8 reason` |
| `0x83` | `STATUS_RESPONSE` | watch → phone | `uint8 state`, `uint8 pin_configured`, `uint32 deadline_remaining_s` |
| `0x84` | `SHRED_COMPLETE` | watch → phone | `uint8 reason`, `uint32 wiped_db_bitmap` |
| `0x85` | `STATE_CHANGED` | watch → phone | `uint8 state` |

Reason codes: `0x00` unknown, `0x01` phone lockdown, `0x02` manual panic,
`0x03` disconnect timeout, `0x04` reboot while locked, `0x05` PIN attempts
exhausted, `0x06` clock rollback.

**The watch owns its own security configuration.** There is no command that sets
the master switch or either delay: those live in Settings > Security and nowhere
else. The phone can *act* on the watch — `LOCK`, `LOCK_ERASE` — and *ask* about
it — `STATUS_REQUEST` — but it cannot change the watch's security posture.

That split is deliberate rather than an omission. A phone that can disarm the
watch is a phone that can be compelled to disarm the watch, and the phone being
taken is the situation this whole feature exists for. It also settles a smaller
argument: a companion app that re-sent its own idea of the settings on every
connection would silently overwrite whatever the user had chosen on the wrist,
every time the two reconnected.

`0x01` was `CONFIGURE`, which carried `enabled` and both delays. It is retired.
A phone built against the older protocol still sending it is ignored on the
unknown-command path — logged and dropped, with no reply and no side effect.

**`LOCK` locks and starts the erase countdown. `LOCK_ERASE` locks and erases on
the spot.** Both lock; they differ only in what is left on the watch afterwards.

`LOCK` is the trigger least likely to have been aimed — Gadgetbridge derives it
from `REASON_LOCKDOWN`, a platform callback, not a button — so it defers to the
watch's own `Erase After`, which the PIN cancels. `LOCK_ERASE` is the one a
phone sends when waiting is the thing that costs, and it is what Gadgetbridge
sends by default, because lockdown is the case this feature exists for and a
watch that only locks still holds every notification, calendar entry and contact
it was sent, behind four digits, on flash that is not encrypted.

The obvious objection is that `LOCK_ERASE` is an unconditional remote-wipe
primitive available to anything that can speak the protocol. It is, and the
mitigations are the ones that already exist rather than new ones: the master
switch refuses both commands when the feature is off, the funnel refuses both
when there is no usable PIN, and everything the erase destroys is a *copy* the
phone puts back on the next unlock and reconnect. So the worst an attacker with
protocol access can do is force a resync — and to do the same to a watch already
on `Erase After`, they need only wait. What they cannot do with either command
is read anything, weaken the watch, or stop the user getting back in with the
PIN.

This shifts what `LOCK_ACK` means, without changing the wire format:
`LOCK_ACK` says the watch is locked. `SHRED_COMPLETE` says the content is gone —
immediately on `LOCK_ERASE`, and when and if the countdown runs out on `LOCK`.
The phone can watch the gap via `STATUS_RESPONSE.deadline_remaining_s`, which
reports a manual countdown as readily as a disconnect one. A phone that reads
`LOCK_ACK` as "locked and erased" is optimistic on `LOCK`; a phone that reads it
as "locked" is right in both cases, and that was always the accurate reading —
the ack is keyed on `security_lock_is_locked()`, not on anything having been
destroyed.

**`LOCK_ERASE` acks before it erases, and the order is load-bearing.**
`security_lock_shred()` engages the radio blackout whenever the watch is locked,
so by the time an erase returns there is no session left to answer on. An ack
sent afterwards would never arrive, and the phone would spend its retry window
re-asking a watch that had already done the work. So the handler locks through
the lock-only funnel, acks over a radio that is still up, and only then erases —
two calls rather than `security_lock_engage()`, which does both with nothing in
between. The cost is that the UI quiesces twice, closing and relaunching the
watchface once, which is invisible next to a wipe that holds KernelMain for
seconds. The lock is *checked* before the erase rather than assumed: a refusal
must not be followed by wiping a watch that was never locked.

An unfortunate consequence worth naming: the same phone reconnecting cannot
call off the countdown it started. That is not an oversight — a `LOCK` a
reconnect undoes would be undone by the phone's own reconnect logic within
seconds — but it does mean a `LOCK` sent in error costs the user a PIN entry,
and there is no `UNLOCK`. There is deliberately no `UNLOCK`: it would be a way
past the lock screen that does not require the PIN.

`LOCK` is refused outright while the feature is off, and the watch replies with
`STATE_CHANGED(Disabled)` rather than `LOCK_ACK`. `LOCK_ACK` carries only a
reason echo and has no failure encoding; `STATE_CHANGED` is a message the phone
already parses, and `Disabled` is the whole reason for the refusal, so this says
no without needing a phone that understands a new code. What must not happen is
an ack: the phone reads that as "locked and erased" and stops asking. The same
rule covers every other way a lock can fail to take — the ack is keyed on the
watch actually being locked afterwards, not on having asked.

`STATUS_RESPONSE`'s `pin_configured` is answered from the stored PIN rather than
from the state. The two agree by construction now, but reading the thing being
reported keeps them honest: a record where they disagree reports what is
actually stored rather than what the state implies.

`Lock After` is counted **from the disconnect**. `Erase After` is counted from
whatever started the lockdown — that same disconnect, or the press — and never
from the lock. So on the disconnect path a `Lock After` of five minutes and an
`Erase After` of thirty give twenty-five minutes of lock, not thirty, which is
why the subtitles say what they are counted from. On a manual lockdown the same
thirty is thirty from the press, because that is when the lockdown began.

`SECURITY_LOCK_SHRED_DELAY_NEVER` is zero and simply leaves the shred deadline
unarmed, which is how "nothing pending" is already spelled everywhere else;
`STATUS_RESPONSE.deadline_remaining_s` reports zero for it, which is accurate,
because there is no countdown to report. Note that the *setting* being zero and
the *deadline* being zero are different fields answering different questions —
"is a timed erase configured" and "is one running" — and `countdown_source`
answers the second unambiguously.

State values match `SecurityLockState`: `0` disabled, `1` armed, `2` locked.

`wiped_db_bitmap` uses `1 << BlobDBId`, so bit 1 = Pins, bit 3 = Reminders,
bit 4 = Notifs, bit 5 = Weather, bit 8 = Contacts. Gadgetbridge uses it to
decide which sync state to drop. Bit 31 means "content not covered by a
BlobDB was also wiped" and is informational.

## Gadgetbridge design

Repo: `../Gadgetbridge`. All work in a **git worktree** — another session is
editing that checkout.

### 1. Detecting lockdown

Android has a real, public signal, and Gadgetbridge is already positioned to
receive it. `NotificationListenerService.REASON_LOCKDOWN` (value **23**, public
since API 34) is delivered to `onNotificationRemoved(sbn, rankingMap, reason)`
for every active notification when lockdown is entered. The platform does this
deliberately — `NotificationManagerService` registers a `StrongAuthTracker` and
on `STRONG_AUTH_REQUIRED_AFTER_USER_LOCKDOWN` calls
`cancelNotificationsWhenEnterLockDownMode()`, whose javadoc tells listeners to
*"ensure the canceled notifications are indeed removed on their end to prevent
data leaking."*

`NotificationListener.java` currently overrides only the 2-arg
`onNotificationRemoved(sbn)` (**line 1057**); the 3-arg variant carrying `reason`
is free to add.

```java
// REASON_LOCKDOWN is public only at API 34, but the value has flowed
// through the 3-arg callback for longer.
private static final int REASON_LOCKDOWN_COMPAT = 23;

@Override
public void onNotificationRemoved(StatusBarNotification sbn,
                                  RankingMap rankingMap, int reason) {
    if (reason == REASON_LOCKDOWN_COMPAT) {
        LockdownController.onLockdownEntered(getApplicationContext());
    }
    super.onNotificationRemoved(sbn, rankingMap, reason);
}
```

**Gap: if no notifications are active when lockdown is entered, nothing fires** —
the platform iterates an empty list. Close it with a composite check
(`isDeviceLocked()` && active notifications just went non-empty → empty) and ship
a manual Lockdown action regardless.

What does not work, so nobody re-litigates it: `KeyguardManager.isDeviceLocked()`
/ `isKeyguardLocked()` / `isDeviceSecure()` cannot distinguish lockdown from an
ordinary lock; `UserManager.isUserUnlocked()` tracks CE storage (BFU→AFU) and
stays `true` through lockdown; `LockPatternUtils.StrongAuthTracker` is hidden-API
blocked and signature-permission gated; `DevicePolicyManager.getStrongAuthRequired`
does not exist; `Settings.Secure` has no runtime lockdown-state key
(`lockdown_in_power_menu` only controls whether the button is shown).

Exit has no reason code — detect via `ACTION_USER_PRESENT` following a
`REASON_LOCKDOWN`. The platform re-posts every notification 20 ms apart on exit;
suppress forwarding for ~2 s or the watch gets flooded.

### 2. Response sequence

```
REASON_LOCKDOWN
   │
   ├─ t=0    send LOCK_ERASE (or LOCK) to watch
   ├─ t=0    stop forwarding notifications; apply privacy mode
   ├─ 0<t<10 retry on LOCK_ACK timeout; re-send on reconnect
   └─ t=10s  disconnect device, then tear down Bluetooth
```

The 10-second delay leaves room for the `LOCK_ACK` round trip and a retry, while
bounding the exposure window. Watch-side disconnect detection remains the
backstop for a watch that never got the message.

**Which of the two goes out is `Erase this watch on lockdown`, and it is on by
default.** Lockdown is the case the feature exists for: a watch that only locks
still holds every notification, calendar entry and contact it was sent, behind
four digits, on flash that is not encrypted. Everything the erase destroys is a
copy this phone puts back on the next unlock and reconnect, so the default costs
a resync and the alternative costs the data.

**It is a per-watch setting**, under the Pebble's own device settings rather
than on the app-wide lockdown screen. Two reasons. Only a PebbleOS build
carrying this endpoint can act on it at all, so it does not belong on a screen
shared with every other device Gadgetbridge supports; and one paired watch may
hold real content while another is a test unit that should merely lock.
`LockdownController` therefore stays device-agnostic — it says only "lock down",
and `PebbleIoThread` resolves the watch's own preference when it encodes the
command. The panic dialog on the shared screen names no single outcome for the
same reason: it fans out to every watch, and each answers for itself.

**`LOCK_ACK` means locked, not erased — on both commands.** On `LOCK` the watch
arms its countdown and `SHRED_COMPLETE` arrives when, and only if, `Erase After`
expires. On `LOCK_ERASE` the ack is sent *before* the wipe starts, deliberately:
the erase takes the radio down, so an ack after it would never arrive. Either
way GB must not read the ack as confirmation that content is gone, nor read a
missing `SHRED_COMPLETE` as a failed lock.

A second command sent to "make sure" is safe. A repeated `LOCK` can never
postpone the erase — the watch keeps whichever deadline is nearer — and a
repeated `LOCK_ERASE` reaches a watch whose radio is already down, or, if it
does land, is absorbed by the re-entry guard in `security_lock_shred()` and the
dirty flag that makes a second wipe a no-op.

The teardown at t=10s closes the session, which the watch sees as an ordinary
disconnect. That is safe by construction — the watch leaves a manual countdown
alone on a session close — and so is the reconnect that follows when GB comes
back, which cannot cancel it either.

- **GB never calls `BluetoothAdapter.enable()`/`disable()` anywhere** (verified by
  grep across the app), so the API-33 deprecation is a non-issue. Existing
  teardown primitives: `GBApplication.deviceService().disconnect()` (fan-out via
  `ACTION_DISCONNECT`, `model/DeviceService.java:58`, handled at
  `DeviceCommunicationService.java:669`) and `GBApplication.quit()`
  (`GBApplication.java:133`).
- Turning the adapter genuinely off is not available silently on modern Android.
  **Scope: disconnect the device and stop GB using the radio.** The UI must not
  claim more.
- Schedule the 10 s action with `Handler.postDelayed` on a foreground-service
  context, not `WorkManager` — the latency requirement is tighter than
  WorkManager's guarantees.

### 3. Supporting `is_unfaithful` — the "resend everything" flag

PebbleOS already has a resync signal and Gadgetbridge ignores it. Adding support
is worth doing in its own right: it makes GB behave correctly against *stock*
Pebble firmware after any factory reset or re-pair, not just for this feature.

`bt_persistent_storage_is_unfaithful()` is reported in the version handshake
(`system_versions.c:51,149`), set on first boot (`shell_event_loop.c:79`) and on
re-pairing, cleared only after the phone issues a BlobDB `CLEAR`
(`blob_db/endpoint.c:296-299`).

GB's `case ENDPOINT_FIRMWAREVERSION:` (`PebbleProtocol.java:2447`) parses only
the running-firmware metadata and stops after `hwRev` — 47 of 155 payload bytes.
`is_unfaithful` is never reached. Verified layout of `struct VersionsMessage`
(`system_versions.c:36-54`), all sizes confirmed from the headers:

| Field | Size | Offset |
|---|---|---|
| `command` | 1 | 0 |
| `running_fw_metadata` | 47 | 1 |
| `recovery_fw_metadata` | 47 | 48 |
| `boot_version` | 4 | 95 |
| `hw_version[9]` | 9 | 99 |
| `serial_number[12]` | 12 | 108 |
| `device_address` | 6 | 120 |
| `system_resources_version` | 8 | 126 |
| `iso_locale[6]` | 6 | 134 |
| `lang_version` | 2 | 140 |
| `capabilities` | 8 | 142 |
| **`is_unfaithful`** | **1** | **150** |
| `activity_insights_version` | 2 | 151 |
| `javascript_bytecode_version` | 2 | 153 |

(`FirmwareMetadata` = 47 B: `firmware_metadata.h:68-86`. `capabilities` is a
union over `uint64_t` = 8 B: `session_remote_version.h:15-43`. `BTDeviceAddress`
= 6 B: `bluetooth_types.h:171-173`. `ResourceVersion` = two `uint32_t` = 8 B:
`resource.h:25-30`.)

GB stops at offset 47 (it never consumes `metadata_version`). Continue parsing
sequentially with explicit skips rather than an absolute seek — self-documenting
and it matches the struct:

```java
// ...existing parse ends after hwRev, at offset 47
// Skip metadata_version, recovery_fw_metadata, boot_version, hw_version,
// serial_number, device_address, system_resources_version, iso_locale,
// lang_version and capabilities. Sizes mirror struct VersionsMessage.
if (length >= bytesParsed + VERSIONS_IS_UNFAITHFUL_SKIP + 1) {
    buf.position(buf.position() + VERSIONS_IS_UNFAITHFUL_SKIP);  // == 103
    boolean isUnfaithful = buf.get() != 0;
    if (isUnfaithful) {
        // watch lost its data - clear all sync state and re-push everything
    }
}
```

**Bound the read with the message's own `length` header, not
`buf.remaining()`.** An earlier draft of this document said to use
`buf.remaining()`; that is wrong and unsafe. `PebbleIoThread` hands
`decodeResponse()` a *reused, fixed 8192-byte* array and the decoder does
`ByteBuffer.wrap()` over the whole thing, so `remaining()` reports
`8192 - position` rather than how much of *this* message is left. Against a
truncated message from older firmware it would happily read leftover bytes from
the previous message and could report a fabricated `is_unfaithful`, triggering a
spurious full resync. Keep `buf.remaining()` only as a secondary bounds check.

### 4. Forcing a full resync

Triggered by either `is_unfaithful` or our `SHRED_COMPLETE`. A calendar resync
requires clearing **two** layers — this is the part that is easy to get wrong:

1. **The greenDAO table.** `CalendarSyncState` (generated at
   `GBDaoGenerator.java:1377`; unique index on `deviceId`+`calendarEntryId`)
   stores a per-event `hash`. `CalendarReceiver.syncCalendar()` treats an event as
   already-on-watch when `calendarSyncState.getHash() == e.hashCode()`
   (`CalendarReceiver.java:175`). Delete all rows for the device.
2. **The in-memory cache.** `CalendarReceiver.eventState` is a per-instance
   `Hashtable` with **no public invalidation method**. Clearing only the DB still
   short-circuits here. Add a `clearSyncState()` method, or force receiver
   recreation via `DeviceCommunicationService.setReceiversEnableState()`
   (`DeviceCommunicationService.java:1392`).

Only then broadcast `FORCE_CALENDAR_SYNC`. On its own that intent **does not
force anything** — it calls `scheduleSync()`, which runs the same hash diff and
concludes everything is synced. This is precisely the failure mode a watch-side
shred would otherwise hit.

Notifications need no state clearing (GB tracks none). Weather can reuse
`encodeBlobDBClear(BLOBDB_WEATHER)` (`PebbleProtocol.java:795`).

Incidental bug worth fixing while here: `PebbleProtocol.decodeBlobDb()`
(line 2219) reads the response token and status, logs them, and **returns
`null`** — GB never correlates BlobDB acks to requests and assumes every write
succeeds.

### 5. Adding the endpoint

`PebbleProtocol.decodeResponse()` (`PebbleProtocol.java:2399`) is a plain switch
on endpoint id; there is no registry. `ENDPOINT_HEALTH_SYNC = 911`
(`PebbleProtocol.java:115`, encoder at 770, decoder case at 2788) is an existing
custom endpoint in this tree — copy that pattern exactly.

### 6. Settings

Two screens, because the settings answer to different owners.

- **App-wide**, in new `res/xml/lockdown_settings.xml`, registered in
  `activities/SettingsActivity.java` (search index and click routing around lines 110-120 and 150-160, following
  `MapsSettingsActivity`). Holds `lockdown_enabled` and the `lockdown_panic`
  action — both about how *the phone* responds to lockdown, so both apply to
  every device. Keys in `util/GBPrefs.java`.
- **Per watch**, in new `res/xml/devicesettings_pebble_security.xml`, added to
  the `GENERIC` root screen in `PebbleCoordinator.getDeviceSpecificSettings()`.
  Holds `pebble_lockdown_erase`, read through `GBApplication.getDevicePrefs()`
  in `PebbleIoThread.sendSecurityLock()`. It lives here because only a PebbleOS
  watch running this endpoint can act on it, and because two paired watches can
  reasonably want different answers.
- Add a `PreferenceMigratorNN` if any key moves between the two.
- Reuse the Pebble privacy-mode plumbing (`PebbleSupport.java:192-206`, pref
  `pebble_pref_privacy_mode`) for the notification-suppression half.

## Status

Feature-complete on the watch and driven end to end under QEMU. **Nothing has
run on real hardware**, and that gap matters more here than it usually would —
see the caveat at the end of this section.

### Verified under QEMU

| | |
|---|---|
| `tools/security_lock_e2e.py` — real touch UI and protocol endpoint | 33/33 |
| `tools/security_lock_stress.py` — a wipe colliding with notification traffic | 0 failures, 20 valid trials |
| Unit suites for the feature and its neighbours | 33/35 |
| Gadgetbridge Mainline unit suite | 1216 tests, 0 failures |

The two failing unit suites are `test_health_db` and `test_weather_db`,
pre-existing DUMA stack smashes that link nothing this work touches.

Behaviours confirmed on the watch rather than inferred: the PIN pad unlocks;
repeated wipes cost one real erase and then nothing; `shred_pending` never
sticks, so there are no half-wipes; a reboot while locked comes back locked
with the wipe finished; the radio blackout engages on a wipe and restores the
user's prior airplane setting on unlock; a reconnect does not cancel a lock;
a duress PIN at the disable prompt wipes before it disables; a phone `LOCK`
locks without erasing while `LOCK_ERASE` erases on the spot even with
`Erase After` at `Never`, and the PIN still opens the watch afterwards.

The `Lockdown + Erase` Quick Launch entry was checked by eye rather than by the
suite, in both directions: it appears in the picker with `Erase After` set to 30
minutes and is absent with it at `Never`. Worth knowing where to look — it sorts
into the Quick-Launch-only group at the *top* of the picker
(`prv_app_node_comparator()`, "Quick Launch only apps are first"), not
alphabetically among the rest.

### Not built, deliberately

- **A menu to choose what gets erased**, including health data and apps. Asked
  for and then withdrawn. It would break the invariant the rest of this design
  rests on — that everything the shred destroys comes back from the phone —
  which is what makes triggering it aggressively reasonable. If it is ever
  revisited, "Locking almost always ends in a shred" has to be revisited at the
  same time, and enabling an unrestorable target needs a warning the user
  cannot miss.
- **Shredding health data**, for the same reason, per "Explicitly out of scope".
- **A watch-initiated phone lockdown.** Android does not permit it:
  `DevicePolicyManager.lockNow()` is an ordinary lock that leaves biometrics
  enabled, and the only route to real Lockdown is an accessibility service
  driving the power menu, gated behind a setting an app cannot grant itself.

### The hardware caveat

The bug that dominated this work — a leaked flash erase semaphore presenting as
an intermittent boot hang — existed *only* because the QEMU HAL reports a 1 ms
erase duration, which truncates to zero in `expected_duration * 7 / 8`. Real
backends return 150/50 ms and never truncate.

So the emulator both created that bug and was the only place it could have been
found. The symmetric case — something that misbehaves only on hardware — is
exactly what none of the testing above can catch.

### Corrections found while building

Two things in the design above were wrong and are worth recording so they are
not reintroduced:

- **`modal_manager_set_min_priority(ModalPriorityMax)` is wrong for a modal.**
  `modal_manager_get_enabled()` is `s_modal_min_priority < ModalPriorityMax`, so
  setting `Max` stops the modal rendering, stops it receiving buttons, and locks
  the stack it would be pushed to. `panic.c` and `battery_ui_fsm.c` get away
  with it because their UI is an *app*, not a modal. The lock screen uses
  `ModalPriorityAlarm`; an alarm popup cannot collide because
  `launcher_block_popups(true)` drops the event before a popup is created.
- **Quick Launch chords complete from an `app_timer`, not an event.** No button
  handler can intercept that, so a chord half-held at the moment of locking
  would launch an app under the lock screen a few hundred ms later.
  `security_lock_engage()` therefore calls `watchface_reset_click_manager()` and
  `launcher_cancel_force_quit()`.

**SHA-256 is local to the service, not from mbedtls.**
`third_party/wscript_build` only recurses mbedtls under `CONFIG_BT_FW_NIMBLE`,
so boards on the QEMU Bluetooth stack never build it and both the include path
and the link fail there. A lock that only works on some boards is not a lock.

### Recovering a watch whose PIN is lost

Hold SELECT+BACK+UP. The button ISR sets `BOOT_BIT_FORCE_PRF`
(`debounced_button.c`), below anything software can intercept, and the watch
boots recovery firmware. PRF does not build this feature at all —
`services_normal_early_init()`, which is what calls `security_lock_init()` and
`security_lock_handle_boot()`, sits behind `#ifndef CONFIG_RECOVERY_FW` — so
there is no lock screen there. A factory reset from PRF erases the filesystem
and the watch comes back empty, ready to re-pair and resync.

**This is deliberate, not a hole to be closed.** It reads like one, because the
escape exists as a consequence of PRF not building the feature rather than as
anything anyone wrote — so it is recorded here to stop a later change "fixing"
it.

The reasoning: what the escape gives an attacker is a *wiped watch*, which is
the outcome this feature is trying to produce anyway. It cannot be used to read
anything. The only way it could leak data is if PRF's console exposed
filesystem reads, and reaching that console means physical access to the debug
port — which means opening the watch, at which point the flash can be read
directly and the threat model has already conceded (see "What this cannot
defend against").

Closing it would trade nothing for a user permanently locked out of their own
watch by a forgotten four-digit PIN with three attempts.

## Risks and open questions

- **Health data survives a seizure.** Accepted trade; stated here so it stays a
  conscious one.
- **FTL retains stale physical pages.** `pfs_gc_deleted_sectors()` erases at the
  PFS sector level, but the translation layer below it may have remapped pages we
  cannot reach. Best-effort against chip-off.
- **Lock-on-disconnect UX.** Locking every time the watch leaves BT range would be
  miserable. Gated on the master switch, which is off out of the box, and on a
  `Lock After` grace period when it is on. The *erase* half of it is separately
  off by default, so the worst an unconfigured disconnect can cost is a PIN
  entry.
- **Flash wear.** The GC sweep erases sectors on every shred. Frequent triggering
  costs NOR endurance — bounded, but worth measuring.
- **GB cannot switch the Bluetooth adapter off** without privileged access.
- **Zero-notification blind spot** in `REASON_LOCKDOWN` detection; the Lockdown
  app and its Quick Launch chord are the fallback, not a nicety.
- **The forced repaint does not blank the screen.** `security_lock_engage()`
  uses `compositor_render_app()`, which repaints from the app framebuffer. It
  reliably removes a notification modal, which is the stated requirement, but
  during the seconds the shred holds KernelMain the display keeps showing the
  outgoing app. A sensitive app's own content stays visible for that window.
- **`security_lock_verify_pin()` blocks KernelMain for roughly 350ms** (10,000
  SHA-256 rounds) with no progress indication and no watchdog kick. Fine today;
  worth revisiting if the KernelMain watchdog is ever tightened.
- **Turning the feature off costs the PIN, and there is no confirmation
  dialog.** The PIN prompt is the confirmation: it says "Turning off clears your
  PIN" and cannot be got past without knowing it. A user who genuinely wanted a
  pause has to set the PIN again afterwards, which is the price of the switch
  being as protected as the lock screen.
- **A duress PIN at the disable prompt wipes and then disables, and the watch
  ends up on the watchface rather than back on the Security menu.** The wipe
  closes the running app, which a real disable does not. See "Duress at the
  disable prompt" below for why that is left as-is.
- **Nothing has run on hardware yet.** It has now been driven extensively under
  QEMU (`tools/pebble_harness.py`, `tools/security_lock_stress.py`), which is
  where most of the bugs below were found — but no claim here has been checked
  on a real watch, and the emulator's flash timings differ enough from real
  hardware to have hidden a deadlock for an entire session. Hardware validation
  is planned. See "What running it actually found".
- **Endpoint ID 0x2C24 is self-assigned.**
- Unverified: whether ANCS caches caller ID to flash (`ancs/ancs_phone_call.c`),
  and whether the voice/audio endpoints buffer audio to flash. Both need a read
  before finalising the shred target list.

### Duress at the disable prompt

Turning the feature off asks for the PIN, which raises a question the duress PIN
did not have to answer before: what happens if the *duress* PIN is typed there?

**It acts like the real PIN, but wipes first.** The wipe runs with
`SecurityShredReasonDuressPin`, and then the feature is turned off exactly as the
real PIN turns it off — PIN cleared, duress PIN cleared, delays and deadlines
back at their defaults. Being made to switch the protection off is close to the
case the duress PIN exists for, and refusing it there would cost the user the
behaviour they were relying on at precisely the wrong moment.

#### The order is the whole of it

`security_lock_shred()` refuses once the feature is off. So a switch-off that
landed first would leave the lock disarmed with nothing erased — the worst
available outcome, on a compelled entry.

That ordering cannot be left to task priorities, which is what the first attempt
did:

- `security_lock_verify_pin()` reports a duress match as an ordinary success and
  queues the wipe onto the launcher task (`tskIDLE_PRIORITY + 3`).
- Settings runs on the app task (`tskIDLE_PRIORITY + 2`) and carries straight on
  to turn the feature off.
- The higher-priority wipe usually preempts and wins — but "usually" is the
  problem, and the wipe also quiesces the UI, which kills the app mid-flow.

So the two halves are not split across two tasks at all. The prompt queues **one
callback on the launcher task**, which shreds and then disables, in that order,
in one function body. Nothing can interleave between them, and the order is
written down rather than inferred:

```c
static void prv_duress_disable_cb(void *unused) {
  security_lock_shred(SecurityShredReasonDuressPin);
  security_lock_disable();
}
```

#### Telling the caller which PIN it was

`security_lock_verify_pin()` deliberately hides duress from everything above it,
so that no UI can branch on it and leak it. That has to be relaxed for exactly
this call site, because ordering the wipe against its own next step is something
only the caller can do.

`security_lock_verify_pin_verdict()` reports `Wrong`, `Real` or `Duress` and
**schedules nothing** — the wipe is the caller's to run. `verify_pin()` keeps its
bool contract and keeps queueing the wipe for everyone else. The verdict variant
replaces `security_lock_verify_real_pin()`, which existed only to refuse duress
here and now has no caller.

What keeps the verdict safe is what the one caller does with it: both accepted
verdicts dismiss the prompt identically, and the difference between them is a
wipe rather than anything drawn. A future caller that branched into the *UI* on
the verdict would be the bug. It is also not an oracle — only an entry that
actually matches a configured duress PIN is ever reported as duress, so the only
person it tells is the one who just typed it.

The attempt counter treats it as what it is: a match resets the counter,
whichever PIN it was.

#### What the user actually sees

Not quite a real disable, and it cannot be made to be. The wipe's first step is
`security_lock_ui_quiesce()`, which closes the running app — so Settings is torn
down and the watch lands on the watchface, where a real disable would return to
the Security menu now reading "Off".

The quiesce is not negotiable: it exists to stop consumers reading shredded
storage, and a notification window left on screen during a wipe was a
reproducible HardFault. Suppressing it to make the two endings match would trade
a cosmetic tell for a crash.

The residual tell is therefore *the app closing instead of returning to the
menu*. It only appears after a PIN that matched, it is indistinguishable from the
app simply exiting, and re-opening Settings shows Security Lock **Off** — which
is what was demanded. There is no clean way to close that gap without touching
the quiesce, so it is left open and written down.

#### Three things the path must not depend on

- **The wipe may erase nothing.** The dirty-since-shred early-out skips the file
  zeroing when nothing has been written since the last wipe. That is correct —
  there is nothing left to destroy — and the switch-off is deliberately not
  conditional on what the wipe reported destroying.
- **Turning it off is not a write.** The switch-off resets the runtime record,
  and the defaults it resets to read *dirty* — the right answer for a record
  nothing is known about, and the wrong one for this one. Left that way it undid
  the early-out for the wipe that came next: the wipe cleared the flag and the
  disable a few instructions later set it again, so the second duress wipe in a
  row always did the full job over an empty filesystem.
  `security_lock_clear_pin()` therefore carries `dirty_since_shred` and
  `shred_pending` across the reset. Those two are observations about the
  filesystem; the rest of that record is policy, and only the policy is being
  turned off.
- **The phone must not be told.** `prv_shred()` already suppresses both the
  unfaithful flag and `SHRED_COMPLETE` for `SecurityShredReasonDuressPin`, and it
  drains the refused-writes accumulator unconditionally — so the
  `prv_report_refused_writes()` inside the `security_lock_disable()` that follows
  finds nothing to report and stays silent. A phone that resynced would undo the
  whole thing.

The other Settings prompts are unaffected and unchanged: a duress PIN authorises
Change PIN and Duress PIN and takes its wipe with it through `verify_pin()`,
because nothing in those flows turns the feature off underneath the queued shred.
That is still pinned by a test.

## What running it actually found

Everything above was written from code reading and unit tests. Driving the real
firmware under QEMU contradicted several of its conclusions. Recorded here
because the wrong explanations were confidently held for a long time.

### The "boot hang" was never in this feature

A locked watch would freeze on the boot splash, intermittently, with no log
output. It was blamed in turn on the watchdog, on the sector sweep being slow,
on the wipe running at early boot, and on a KernelBG deadlock. Each theory got a
fix; none of them was the cause.

The actual cause was a pre-existing bug in the generic flash driver.
`prv_flash_erase_start()` documents "returns 0 if the erase has completed" and
returned `expected_duration * 7 / 8`. The QEMU flash HAL reports a 1 ms typical
erase duration, and `1 * 7 / 8 == 0` — so a live erase reported itself finished,
the caller skipped polling, and `prv_flash_erase_poll()` (the only thing on the
normal path that releases `s_erase_semphr`) never ran. The next erase blocked
forever on a `portMAX_DELAY` take. Fixed by clamping both truncating returns.

The shred was simply the first code path to erase a non-blank, non-sector-aligned
region: `CD` is 64K-aligned and never written, so its erases all took the
blank-check early exit, which does release the semaphore. `DEBUG_DB` starts at
`0x11FCF000` and holds the live log page, so it took a real erase — and wedged.

Three lessons worth keeping:

- **The watch appearing dead is not evidence about the subsystem you are
  working on.** Four fixes were made to `security_lock` for a fault in
  `drivers/flash`.
- **Instrument before patching.** Every fix that missed was a guess; the one
  that worked came from a recovered FreeRTOS backtrace.
- **An emulator-only constant hid it.** Real backends return 150/50 ms, which
  never truncates. Whether hardware can reach the same wedged state by another
  route is untested.

### Bugs the design intended to prevent, but did not

- **The disconnect path erased at the *lock* delay.** `security_lock_engage()`
  ended with an unconditional `security_lock_shred()`, and the lock deadline
  called it, so the shred delay was dead code on the only trigger that used it.
  With the defaults, a disconnect erased at 5 minutes rather than 30. Split into
  `security_lock_engage()` and `security_lock_engage_lock_only()`.
- **The clock-rollback trigger never fired at boot.** A refactor moved
  `security_lock_note_time()` and discarded its return value, dropping
  `rolled_back` from the decision entirely.
- **A locked watch still stored notifications.** The requirement to drop rather
  than store them was specified above and never implemented, and there are
  *three* ingresses to `notification_storage_store()`, not one — including the
  blob\_db path, which is how Gadgetbridge delivers them.
- **The dirty-since-shred early-out almost never fired.** It was blamed on the
  wipe marking itself, since `prv_shred()` ends by re-initialising four
  databases. It does not: `security_lock_is_shredding()` holds across that tail
  and every ingress to both marking sites refuses while it does. The real
  culprit was `security_lock_clear_pin()`, which resets the runtime record to
  defaults — and the defaults read dirty. Any switch-off, including the duress
  one, therefore armed a full wipe for whenever the feature was next turned on.
  Found by adding `dirty=` to `security status` and watching it go 0 → 1 across
  `security enable 0` with nothing else running.

### What `PEBBLE_SECURITY_SHRED_EVENT` is and is not

The shred broadcasts this before wiping so that anything holding data of its own
gets the chance to destroy it. Nothing in the firmware subscribes, and that is
deliberate: it exists for **third-party apps**, which is why it is on the list
to be SDK-exported. `event_put()` delivery is asynchronous, which is fine for an
app — apps run on their own task.

It is specifically *not* a general-purpose "everything gets to clean up first"
hook. A subscriber living on KernelMain would not be woken until the shred had
already finished, because the shred occupies that task for its whole duration.
Anything KernelMain-resident that holds references into shredded storage — the
notification window, for one — has to be torn down synchronously, in-line,
before the first file is zeroed.

### Reconnecting must never unlock

An earlier revision unlocked the watch when the phone reconnected, reasoning
that Gadgetbridge could not reach the watch unless the phone had been unlocked.
That is false: Android keeps Bluetooth up while the screen is locked and
Gadgetbridge reconnects on its own. A reconnect is something an attacker can
arrange — a shielded bag, or simply carrying the phone out of range and back —
so it proves nothing. Only the PIN clears a lock, whatever caused it.

### Reconnecting must not cancel a manual countdown either

The same argument, one level down, and it only became reachable when manual
triggers started arming countdowns instead of erasing on the spot.
`security_lock_handle_comm_session_event()` cleared *both* deadlines on every
session open. That is right for a countdown the phone's absence armed — the
phone is back, the countdown is moot — and wrong for one the user asked for.
Left alone it would have meant a Bluetooth blip silently cancelling a lockdown
someone triggered on purpose, with nothing on screen to say so, and the shape
that produces it is not exotic: Gadgetbridge reconnects by itself, so an
attacker holding the phone gets it for free.

The fix is `countdown_source`, persisted beside the deadlines. Both directions
have to hold, and the reverse is the easier one to miss — a manual countdown
must not be shortened, restarted or extended by the disconnect arming logic when
the phone later goes away, or walking out of range would postpone the erase the
user asked for. Both are covered by explicit tests, because a reconnect
cancelling a manual lockdown is exactly the bug that only surfaces the day
someone actually needs the feature.

### The timed erase is opt-in

`SECURITY_LOCK_DEFAULT_SHRED_DELAY_S` was thirty minutes. It is `Never` now, so
the feature ships lock-only.

One consequence is worth stating rather than discovering: `prv_runtime_defaults()`
feeds both the fresh-record path and the unreadable-record path, and there is
still only one default. A firmware upgrade that discards the runtime record —
which is what the separate `CFG_RECORD_VERSION` and `RT_RECORD_VERSION` exist to
survive — therefore returns a user who had configured an erase delay to `Never`.

That is the deliberate direction. Reinstating a real delay would arm a
destructive countdown the user never asked for as a side effect of an upgrade,
and the erase is opt-in precisely so that cannot happen. Everything that
protects them is untouched: the watch still locks, still needs the PIN, and
still erases on a reboot while locked, on three wrong PINs and on a duress PIN.
Only the timed erase is lost, and it is the one thing the user explicitly chose
and can choose again.

The other place `Never` interacts with the record is the clock-rollback trigger,
which is gated on a shred deadline being armed. With `Never` as the default,
nothing is armed by default, so a rollback shreds nothing until the user opts
in. That is the same rule as before — "with the timed erase turned off there is
nothing to outrun" — but it is now the default rather than a choice.
