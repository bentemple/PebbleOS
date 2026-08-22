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
built. It would be the only control here capable of destroying something the
user cannot get back, and no threat in the model above justifies offering it.

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
        configure PIN
Disabled ──────────────> Armed ──────────────────> Locked
   ^                       ^   phone LOCK cmd        │
   │                       │   manual panic          │  correct PIN
   │  disable + PIN        │   disconnect grace      │
   └───────────────────────┴─────────────────────────┘
                                   ^                 │
                                   │                 v
                                   └───────────── Shredding
                          (re-shred + stay locked on
                           reboot / 30min / 3 bad PINs)
```

There is **one shred scope**. Every trigger runs the same wipe; escalation
triggers differ only in that they re-run it and keep the watch locked. This is
a simplification over an earlier two-tier draft, and it follows directly from
the shred being non-destructive.

### Locking almost always ends in a shred

Worth stating plainly, because it is the practical behaviour rather than an
edge case. Once the watch locks, avoiding the shred requires the user to enter
the correct PIN before the shred delay elapses *and* not reboot in the
meantime. A flat battery, a crash, a five-second SELECT+BACK, or simply not
noticing for half an hour all end in a wipe.

That is intended, and it is only reasonable because of the scope decision
above: everything the shred destroys comes back from the phone on reconnect.
Nothing unrecoverable is at stake -- health and step history, the one category
the phone cannot restore, is deliberately never touched. So the cost of an
unnecessary shred is a resync, not a loss.

The lock phase is therefore best understood as a short grace period, not as a
durable state the watch is expected to sit in. If that ever stops being true --
if something unrestorable gets added to the shred list -- this trade has to be
revisited at the same time.

### Trigger matrix

| Trigger | Detected where | Result |
|---|---|---|
| Phone sends `LOCK` | New protocol endpoint | Lock + shred |
| Manual panic action | Watch menu / GB action | Lock + shred |
| Unexpected disconnect while Armed | `PebbleCommSessionEvent` close + grace | Lock + shred (configurable) |
| Boot with state == `Locked` | Early-boot hook | Re-shred, stay locked |
| Disconnected > 30 min while Locked | Absolute-deadline check | Re-shred, stay locked |
| 3 consecutive wrong PINs | Lock screen | Re-shred, stay locked |
| `rtc_get_time()` < persisted high-water mark | Deadline check | Re-shred, stay locked |

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
  time_t   disconnect_deadline; // 0 = not armed
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

### 7. Disconnect deadline and clock trust

Timers survive neither sleep nor reboot. Use the pattern established by
`cron/service.c`: persist an **absolute deadline**, re-arm a short capped timer
on each wake.

- On session close while `Locked`: `disconnect_deadline = rtc_get_time() + 1800`.
- On session open: clear it.
- Check on every wake, timer tick, and at the boot hook.

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
| `0x01` | `CONFIGURE` | phone → watch | `uint8 enabled`, `uint16 lock_delay_s`, `uint16 shred_delay_s` |
| `0x02` | `LOCK` | phone → watch | `uint8 reason` |
| `0x03` | `STATUS_REQUEST` | phone → watch | — |
| `0x82` | `LOCK_ACK` | watch → phone | `uint8 reason` |
| `0x83` | `STATUS_RESPONSE` | watch → phone | `uint8 state`, `uint8 pin_configured`, `uint32 deadline_remaining_s` |
| `0x84` | `SHRED_COMPLETE` | watch → phone | `uint8 reason`, `uint32 wiped_db_bitmap` |
| `0x85` | `STATE_CHANGED` | watch → phone | `uint8 state` |

Reason codes: `0x00` unknown, `0x01` phone lockdown, `0x02` manual panic,
`0x03` disconnect timeout, `0x04` reboot while locked, `0x05` PIN attempts
exhausted, `0x06` clock rollback.

Both delays in `CONFIGURE` are counted **from the disconnect**, not from each
other, so the defaults lock at five minutes and erase at thirty — twenty-five
minutes after locking, not thirty. A zero in either field means "leave that
delay alone" rather than "set it to zero", so a phone that does not care about
the timings can send zeroes and change nothing.

That encoding has a consequence worth stating: `SECURITY_LOCK_SHRED_DELAY_NEVER`
is also zero, so **"never erase" cannot currently be expressed over the wire** —
it is reachable only from the watch's own Settings menu. Fixing that means
either swapping the sentinels (`0xffff` for "leave alone", freeing zero for its
natural meaning) or appending a flags byte, which would also require relaxing
the handler's length check so existing six-byte messages keep working.
`STATUS_RESPONSE.deadline_remaining_s` has the same ambiguity: zero means both
"never" and "no countdown running".

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
a manual panic action regardless.

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
   ├─ t=0    send LOCK to watch
   ├─ t=0    stop forwarding notifications; apply privacy mode
   ├─ 0<t<10 retry LOCK on LOCK_ACK timeout; re-send on reconnect
   └─ t=10s  disconnect device, then tear down Bluetooth
```

The 10-second delay leaves room for the `LOCK_ACK` round trip and a retry, while
bounding the exposure window. Watch-side disconnect detection remains the
backstop for a watch that never got the message.

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

- New `res/xml/lockdown_settings.xml`, registered in
  `activities/SettingsActivity.java` (search index and click routing around lines 110-120 and 150-160, following
  `MapsSettingsActivity`).
- Keys in `util/GBPrefs.java`; add a `PreferenceMigratorNN` if any key moves.
- Reuse the Pebble privacy-mode plumbing (`PebbleSupport.java:192-206`, pref
  `pebble_pref_privacy_mode`) for the notification-suppression half.

## Phasing

All twelve phases are implemented. Firmware builds clean for `qemu_emery`;
Gadgetbridge builds a full APK and its suite passes.

1. ✅ `lock_state` settings-file store + unit tests.
2. ✅ `pfs_shred()` + `pfs_gc_deleted_sectors()` + tests against the flash emulator.
3. ✅ Shred engine, driven from a console prompt command only.
4. ✅ Early-boot hook + resume-after-interruption.
5. ✅ Lock screen modal + button lockout.
6. ✅ PIN entry window + attempt counter + escalation.
7. ✅ Protocol endpoint + `SHRED_COMPLETE`.
8. ✅ Disconnect deadline + RTC rollback guard.
9. ✅ **GB: `is_unfaithful` parsing + full-resync path.**
10. ✅ GB: lockdown detection, LOCK send, 10 s BT teardown.
11. ✅ GB: `SHRED_COMPLETE` handling.
12. ✅ Settings UI on watch; settings UI in Gadgetbridge.

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

## Risks and open questions

- **PRF gap.** SELECT+BACK+UP boots recovery firmware, which does not run
  `services_normal_early_init()`. PRF is built from this tree
  (`bluetooth_persistent_storage_prf.c` exists), so an equivalent hook can be
  added — but a device carrying an older PRF image is unprotected. Needs a
  decision.
- **Health data survives a seizure.** Accepted trade; stated here so it stays a
  conscious one.
- **FTL retains stale physical pages.** `pfs_gc_deleted_sectors()` erases at the
  PFS sector level, but the translation layer below it may have remapped pages we
  cannot reach. Best-effort against chip-off.
- **Lock-on-disconnect UX.** Locking every time the watch leaves BT range would be
  miserable. Default off; when on, use a grace period.
- **Flash wear.** The GC sweep erases sectors on every shred. Frequent triggering
  costs NOR endurance — bounded, but worth measuring.
- **GB cannot switch the Bluetooth adapter off** without privileged access.
- **Zero-notification blind spot** in `REASON_LOCKDOWN` detection; the manual
  panic action is the fallback, not a nicety.
- **The forced repaint does not blank the screen.** `security_lock_engage()`
  uses `compositor_render_app()`, which repaints from the app framebuffer. It
  reliably removes a notification modal, which is the stated requirement, but
  during the seconds the shred holds KernelMain the display keeps showing the
  outgoing app. A sensitive app's own content stays visible for that window.
- **`security_lock_verify_pin()` blocks KernelMain for roughly 350ms** (10,000
  SHA-256 rounds) with no progress indication and no watchdog kick. Fine today;
  worth revisiting if the KernelMain watchdog is ever tightened.
- **Changing PIN length is a two-step flow** (PIN Length, then Change PIN)
  rather than a picker inside the change flow. Contained, but slightly awkward.
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
