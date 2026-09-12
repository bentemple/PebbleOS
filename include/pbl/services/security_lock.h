/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "system/status_codes.h"
#include "pbl/util/attributes.h"

//! Persistent state for the security lockdown feature.
//!
//! Backed by a dedicated settings file rather than a blob db, because it must
//! be readable from services_normal_early_init(), before blob_db_init_dbs()
//! has run. See docs/architecture/security_lock.md.

//! A PIN is an even number of digits, 4 to 10 -- nothing odd and nothing
//! outside that. The pad has no 0 key, so digits are 1-9.
//!
//! The Settings picker offers exactly this set and security_lock_set_pin()
//! accepts exactly this set, which is why the rule lives here rather than in
//! either of them: a length one side allowed and the other refused would be a
//! row that cannot be used, or a PIN that cannot be typed.
#define SECURITY_LOCK_PIN_MIN_LEN 4
#define SECURITY_LOCK_PIN_MAX_LEN 10
#define SECURITY_LOCK_PIN_LEN_STEP 2
#define SECURITY_LOCK_NUM_PIN_LENGTHS \
  (((SECURITY_LOCK_PIN_MAX_LEN - SECURITY_LOCK_PIN_MIN_LEN) / SECURITY_LOCK_PIN_LEN_STEP) + 1)
#define SECURITY_LOCK_SALT_LEN 16
#define SECURITY_LOCK_HASH_LEN 32

//! Whether @p len is a length the lock will ever store or ask for.
//!
//! Everything that reads a stored length checks it through here, because a
//! record carrying anything else is inconsistent rather than merely unusual:
//! the pad would collect digits no verifier could ever match.
static inline bool security_lock_pin_len_is_valid(uint8_t len) {
  return (len >= SECURITY_LOCK_PIN_MIN_LEN) && (len <= SECURITY_LOCK_PIN_MAX_LEN) &&
         (((len - SECURITY_LOCK_PIN_MIN_LEN) % SECURITY_LOCK_PIN_LEN_STEP) == 0);
}

//! Wrong PINs tolerated before the watch re-shreds and stays locked.
#define SECURITY_LOCK_MAX_PIN_ATTEMPTS 3

//! Once the attempts are spent, every further entry is refused without being
//! compared until this much time has passed since the last counted attempt.
//! The delay doubles with each further failure and stops at the cap, so an
//! exhaustive search of the 9^4 space takes months rather than an hour.
//!
//! A refused entry is not counted, so hammering the pad cannot push the delay
//! up without bound and lock the owner out for good.
#define SECURITY_LOCK_LOCKOUT_BASE_S 60
#define SECURITY_LOCK_LOCKOUT_MAX_S (60 * 60)

//! Shred delay meaning "no timed erase". The watch still locks -- when the
//! phone goes away, and when the user asks for a Lock -- and the triggers
//! that erase outright still do: Lockdown + Erase, a duress PIN, exhausted
//! attempts, a reboot while locked. Only the timed erase is disarmed.
//!
//! Zero rather than a large sentinel because an unarmed deadline is already 0
//! everywhere, so this needs no special case beyond the ordering check in
//! security_lock_set_delays().
#define SECURITY_LOCK_SHRED_DELAY_NEVER 0

//! Defaults only. Both are configurable in watch Settings. The lock delay is
//! measured from the moment the phone went away; the erase delay from whatever
//! started the lockdown, which is that same disconnect or the user's press.
//!
//! The watch locks first and erases later, so a brief separation costs the
//! user a PIN entry while a real one still destroys the data.
//!
//! The erase ships off. It is the destructive half and the half the watch
//! cannot undo on its own, so it is opt-in: a user who wants it picks a delay
//! under Settings > Security > Erase After. Until they do, every countdown in
//! the feature ends in a lock and nothing else.
#define SECURITY_LOCK_DEFAULT_LOCK_DELAY_S (5 * 60)
#define SECURITY_LOCK_DEFAULT_SHRED_DELAY_S SECURITY_LOCK_SHRED_DELAY_NEVER

//! Slack allowed when comparing against the persisted time high-water mark.
//! The RTC can legitimately drift or be nudged by a resync; anything beyond
//! this reads as a deliberate rollback.
#define SECURITY_LOCK_TIME_ROLLBACK_SLACK_S (5 * 60)

typedef enum {
  //! Feature off, and a clean slate: no PIN, no duress PIN, no deadline armed,
  //! every delay back at its default. Nothing locks and nothing erases.
  SecurityLockStateDisabled = 0,
  //! Configured and watching, but the watch is usable.
  SecurityLockStateArmed = 1,
  //! Locked: PIN gates all input, content has been shredded.
  SecurityLockStateLocked = 2,
} SecurityLockState;

void security_lock_init(void);
void security_lock_deinit(void);

SecurityLockState security_lock_get_state(void);
bool security_lock_is_locked(void);
status_t security_lock_set_state(SecurityLockState state);

//! The master switch for the whole feature, persisted, off out of the box.
//!
//! Derived from the state rather than stored beside it, so there is exactly one
//! notion of "on" and a future trigger cannot consult the wrong one. Having a
//! PIN and being on are the same fact: setting a PIN arms, and turning it off
//! discards the PIN, so the two cannot diverge and there is no third answer to
//! keep in step.
//!
//! Enforced at the two funnels, security_lock_engage() and
//! security_lock_shred(), so nothing that trips a lock or an erase has to
//! remember to ask.
static inline bool security_lock_is_enabled(void) {
  return security_lock_get_state() != SecurityLockStateDisabled;
}

//! Configure the PIN and move to Armed. Digits are ASCII '0'-'9'.
//!
//! Setting a PIN is what turns the feature on; there is nothing else to opt in
//! with, and a PIN that armed nothing would be a control that did nothing.
//! There is deliberately no counterpart that turns it on without one.
status_t security_lock_set_pin(const char *digits, uint8_t len);

//! Clear the PIN and move to Disabled. Also clears any duress PIN.
//!
//! The recovery path as well as the user-facing one, so it takes the watch out
//! of Locked too. security_lock_disable() is the control a user reaches.
status_t security_lock_clear_pin(void);

//! Turn the whole feature off: back to how the watch behaves with the feature
//! never having been used.
//!
//! Clears the PIN and the duress PIN with it. Keeping a PIN across a switch-off
//! meant the switch protected less than the lock screen did -- anyone holding an
//! unlocked watch could walk into Settings and disarm it -- so off is a clean
//! slate and turning it back on is setting a PIN again.
//!
//! Refuses while Locked, which would be an unlock without the PIN. Settings is
//! unreachable from a locked watch, so nothing reaches this today; the rule
//! lives here so that stays true of every future caller.
//!
//! @return S_NO_ACTION_REQUIRED if it was already off.
status_t security_lock_disable(void);

//! Configure a second PIN that unlocks the watch and silently destroys its
//! content at the same time.
//!
//! For being made to unlock under observation or coercion: the watch behaves
//! exactly as it does for the real PIN -- same animation, no message, no
//! difference an onlooker could spot -- while the shred runs in the
//! background. The phone is deliberately not told, because it would restore
//! everything within seconds and the duress PIN would achieve nothing.
//!
//! Must differ from the real PIN, and follows the same 4-or-6-digit rule.
status_t security_lock_set_duress_pin(const char *digits, uint8_t len);
status_t security_lock_clear_duress_pin(void);
bool security_lock_has_duress_pin(void);

//! Number of digits the configured PIN has, so the lock screen knows how many
//! cells to prompt for. 0 if no PIN is configured.
uint8_t security_lock_get_pin_len(void);

//! Verify a PIN attempt.
//!
//! The failed-attempt counter is incremented and flushed to flash BEFORE the
//! comparison is performed, so yanking power mid-verification counts as a
//! failure rather than resetting the count. On success the counter is reset.
//!
//! Once the attempts are spent the entry is refused before it is hashed and
//! reported as wrong, until the escalating lockout above has elapsed. Enforced
//! here rather than in the lock screen, because the console and the phone
//! endpoint reach this same function.
//!
//! A duress PIN is reported as an ordinary success and the wipe it carries is
//! queued onto the launcher task from in here, so no caller has to know about
//! it -- and nothing above this layer can leak it into the UI.
//!
//! @param[out] attempts_remaining_out may be NULL. Set to the number of
//!             attempts left before escalation.
//! @return true if the PIN matched.
bool security_lock_verify_pin(const char *digits, uint8_t len, uint8_t *attempts_remaining_out);

//! Which PIN an attempt matched. See security_lock_verify_pin_verdict().
typedef enum {
  //! No match. A duress PIN that is not configured, or one of the wrong
  //! length, lands here exactly as any other wrong entry does.
  SecurityPinVerdictWrong = 0,
  SecurityPinVerdictReal,
  SecurityPinVerdictDuress,
} SecurityPinVerdict;

//! Verify a PIN and report which one it was, scheduling nothing.
//!
//! For the caller that has to order the duress wipe against work of its own:
//! Settings' turn-it-off prompt, which must wipe and then disable. Those cannot
//! be a queued wipe plus a caller that carries on, because the wipe would land
//! on the launcher task while the caller runs on the app task -- so which went
//! first would be the scheduler's decision, and one of the two answers is a
//! lock disarmed with nothing erased. Handed the verdict, the caller can put
//! both halves in one callback in a fixed order.
//!
//! The only place duress is visible above this file, and it stays safe because
//! of what that one caller does with it: the two verdicts are indistinguishable
//! on screen, and what differs is the wipe rather than anything shown. A new
//! caller that branches into the UI on this would be the bug.
//!
//! Not a way to ask whether a duress PIN exists -- only an entry that actually
//! matches one is ever reported as duress, which means whoever typed it already
//! knew. Burns an attempt in the same before-the-comparison order as above, and
//! a duress match resets the counter exactly as a real one does.
SecurityPinVerdict security_lock_verify_pin_verdict(const char *digits, uint8_t len);

uint8_t security_lock_get_failed_attempts(void);
status_t security_lock_reset_failed_attempts(void);

//! True once failed attempts have reached SECURITY_LOCK_MAX_PIN_ATTEMPTS.
bool security_lock_attempts_exhausted(void);

//! Seconds until the next PIN attempt will be looked at, 0 if one is allowed
//! now.
//!
//! Measured from the last counted attempt rather than stored as a deadline, so
//! a clock wound backwards adds to the wait rather than retiring it.
uint32_t security_lock_get_lockout_remaining_s(void);

//! Set before a shred begins and cleared once it finishes, so an interrupted
//! shred is resumed at next boot.
bool security_lock_is_shred_pending(void);
status_t security_lock_set_shred_pending(bool pending);

//! True only while security_lock_shred() is actually running.
//!
//! RAM only, and deliberately not the persisted flag above: that one stays set
//! across a reboot until the wipe finishes, so gating incoming content on it
//! would drop everything for as long as an interrupted shred went unresumed.
//!
//! Needed on top of security_lock_is_locked() because two triggers shred while
//! the watch is unlocked -- the duress PIN, where unlocking normally is the
//! entire point, and a detected clock rollback.
bool security_lock_is_shredding(void);

//! True when an inbound notification must not reach flash.
//!
//! Always while a wipe is running: a store landing then would put cleartext
//! straight back behind the erase. While merely locked it follows the
//! block-notifications-when-locked setting, which is on by default. Off stores
//! them for whoever unlocks; it never means shown, since the lock screen
//! outranks the notification modal either way.
bool security_lock_should_drop_notifications(void);

//! True when something has been written to the storage a shred destroys since
//! the last shred ran.
//!
//! Almost everything a shred erases is content the phone sent, so a shred that
//! runs before the phone has resynced has nothing new to destroy and can skip
//! the filesystem half of the wipe.
//!
//! Reads true whenever the answer is not positively known -- no record yet, an
//! unrecognised record version, the service not yet initialised. The flag may
//! only ever err towards shredding: a redundant wipe is waste, a skipped one
//! is a data leak.
bool security_lock_is_dirty_since_shred(void);

//! Record that content a shred would destroy has just been written.
//!
//! Called from the storage entry points themselves rather than attributed to a
//! source, so nothing can be misclassified. Cheap once already dirty: only the
//! clean-to-dirty transition writes flash, so this costs one write per shred
//! cycle rather than one per notification.
//!
//! A no-op with the feature off, so the storage entry points can call it
//! unguarded.
#ifdef CONFIG_SERVICE_SECURITY_LOCK
void security_lock_mark_dirty_since_shred(void);
#else
static inline void security_lock_mark_dirty_since_shred(void) {}
#endif

//! Clear the flag. For a shred to call as it begins destroying content, so
//! anything written from that point on re-marks and the next shred runs whole.
status_t security_lock_clear_dirty_since_shred(void);

//! Hold the radio down because the watch is locked and has been shredded.
//!
//! A locked, shredded watch has nothing left to receive, and every message it
//! drops instead is an ack the phone reads as a successful sync. With the radio
//! down the phone sees an ordinary disconnect, so the usual reconnect-and-resync
//! semantics apply once the watch is unlocked.
//!
//! Real airplane mode rather than the bt_ctl override: it is persisted, so a
//! locked watch stays dark across a reboot with nothing to re-apply, and it is
//! visible, so the user can see why the watch is not talking to their phone
//! rather than it merely appearing broken.
//!
//! Idempotent. The airplane-mode setting is saved on the way in and only on the
//! first call, so a repeat shred -- or the re-assert at boot -- cannot record
//! the blackout as its own "previous state" and strand airplane mode on.
void security_lock_radio_blackout_engage(void);

//! Put airplane mode back the way the user had it.
//!
//! No-op unless we took it, so a watch that was already in airplane mode before
//! the shred stays in it.
void security_lock_radio_blackout_release(void);

//! True while the radio is being held down.
//!
//! Also means the watch has reached a terminal state: nothing can arrive, so
//! nothing is left to run a countdown for and only the PIN gets out.
bool security_lock_is_radio_blackout(void);

//! How long after a disconnect the watch locks, and how long after a lockdown
//! begins it erases. Persisted, so a reboot keeps the user's choice.
uint32_t security_lock_get_lock_delay_s(void);
uint32_t security_lock_get_shred_delay_s(void);

//! @return E_INVALID_ARGUMENT if the erase would land before the lock.
//!         SECURITY_LOCK_SHRED_DELAY_NEVER is exempt: it schedules no erase.
status_t security_lock_set_delays(uint32_t lock_delay_s, uint32_t shred_delay_s);

//! Whether an alarm may still ring while the watch is locked. Persisted, on out
//! of the box, configurable under Settings > Security.
//!
//! On: the alarm rings, and goes on ringing for as long as the watch has
//! anything left to protect. A watch that locked because the phone walked out
//! of range is still the user's watch, and an alarm that does not go off is a
//! missed flight. What it shows is the current time and nothing else, and the
//! alarms themselves are not a shred target -- the phone cannot restore them --
//! so nothing the lock is protecting reaches the screen either way.
//!
//! Off: silent from the moment the watch locks, for the user who would rather
//! a locked watch drew no attention at all.
//!
//! Either way an erased watch stays silent: past that it holds nothing and
//! talks to nobody, so there is nothing left to be useful for. That half is not
//! configurable, which is why this is a plain switch rather than a choice of
//! three.
bool security_lock_get_alarms_when_locked(void);
status_t security_lock_set_alarms_when_locked(bool allowed);

//! Why the armed countdown is armed.
//!
//! Persisted beside the deadlines, because what may retire a countdown depends
//! entirely on what started it and a reboot while locked is a designed-for
//! case. Without this the two are indistinguishable in the record, and the
//! reconnect handler -- which is right to retire one and must never touch the
//! other -- has nothing to tell them apart by.
typedef enum {
  //! Nothing is counting down. Holds exactly when both deadlines are 0, which
  //! security_lock_set_deadlines() enforces rather than trusts.
  SecurityCountdownNone = 0,
  //! The phone went away. Its coming back makes the countdown moot, so a
  //! session opening retires this one.
  SecurityCountdownDisconnect = 1,
  //! The user asked for it: the Lock app, the Quick Launch chord, the
  //! Settings row or the phone's LOCK. Only the PIN retires this one. A
  //! Bluetooth blip must not cancel a lockdown someone triggered on purpose,
  //! and the disconnect delays must not shorten, restart or extend it either.
  SecurityCountdownManual = 2,
} SecurityCountdownSource;

//! Absolute wall-clock deadlines. 0 means not armed.
//!
//! A disconnect countdown is cleared on unlock and on reconnect, and does not
//! re-arm until the next unexpected disconnect -- so an unlocked, reconnected
//! watch is not sitting on a countdown the user cannot see. A manual one
//! outlives every reconnect and only the PIN clears it.
time_t security_lock_get_lock_deadline(void);
time_t security_lock_get_shred_deadline(void);
SecurityCountdownSource security_lock_get_countdown_source(void);

//! Arm, re-arm or retire the countdown, recording what armed it.
//!
//! One write rather than a deadline setter and a separate flag: the two are
//! flushed together, so no reader can catch a countdown whose source has not
//! caught up, and no caller can arm one without saying why.
//!
//! Both deadlines at 0 forces the source to SecurityCountdownNone whatever was
//! passed, so "armed" has one spelling and a stale source cannot outlive the
//! countdown it described.
status_t security_lock_set_deadlines(time_t lock_deadline, time_t shred_deadline,
                                     SecurityCountdownSource source);
status_t security_lock_clear_deadlines(void);

//! True if the corresponding deadline is armed and `now` is at or past it.
bool security_lock_lock_deadline_expired(time_t now);
bool security_lock_shred_deadline_expired(time_t now);

//! Record the current time, maintaining a monotonic high-water mark.
//!
//! There is no reboot-persistent monotonic clock on this hardware, so a
//! deliberate backwards jump is the only rollback signal available.
//!
//! @return true if `now` is further back than the allowed slack, i.e. the
//!         clock appears to have been wound back.
bool security_lock_note_time(time_t now);

time_t security_lock_get_time_high_water(void);
