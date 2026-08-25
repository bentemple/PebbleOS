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
//! has run. See docs/proposals/security-lockdown.md.

//! A PIN is exactly 4 or 6 digits -- nothing in between. The pad has no 0 key,
//! so digits are 1-9.
#define SECURITY_LOCK_PIN_MIN_LEN 4
#define SECURITY_LOCK_PIN_MAX_LEN 6
#define SECURITY_LOCK_SALT_LEN 16
#define SECURITY_LOCK_HASH_LEN 32

//! Wrong PINs tolerated before the watch re-shreds and stays locked.
#define SECURITY_LOCK_MAX_PIN_ATTEMPTS 3

//! Defaults only. Both are configurable by the phone and in watch Settings,
//! and both are measured from the moment the phone went away.
//!
//! The watch locks first and shreds later, so a brief separation costs the
//! user a PIN entry while a real one still destroys the data.
#define SECURITY_LOCK_DEFAULT_LOCK_DELAY_S (5 * 60)
#define SECURITY_LOCK_DEFAULT_SHRED_DELAY_S (30 * 60)

//! Shred delay meaning "no timed erase". The watch still locks when the phone
//! goes away, and every explicit trigger -- the phone's LOCK command, Lock Now,
//! a duress PIN, exhausted attempts -- still erases. Only the disconnect
//! countdown is disarmed.
//!
//! Zero rather than a large sentinel because an unarmed deadline is already 0
//! everywhere, so this needs no special case beyond the ordering check in
//! security_lock_set_delays(). Note the phone cannot select it: CONFIGURE reads
//! a zero delay field as "leave this one alone".
#define SECURITY_LOCK_SHRED_DELAY_NEVER 0

//! Slack allowed when comparing against the persisted time high-water mark.
//! The RTC can legitimately drift or be nudged by a resync; anything beyond
//! this reads as a deliberate rollback.
#define SECURITY_LOCK_TIME_ROLLBACK_SLACK_S (5 * 60)

typedef enum {
  //! Feature off. Nothing locks, nothing erases, no deadline is armed. A PIN
  //! may still be stored: turning the feature back on must not cost the user
  //! another one.
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
//! notion of "on" and a future trigger cannot consult the wrong one. Disabled
//! already meant "nothing fires", already defaulted off, and setting a PIN
//! already left it -- the only thing it gains here is that a PIN may outlive it.
//!
//! Enforced at the two funnels, security_lock_engage() and
//! security_lock_shred(), so nothing that trips a lock or an erase has to
//! remember to ask.
static inline bool security_lock_is_enabled(void) {
  return security_lock_get_state() != SecurityLockStateDisabled;
}

//! Turn the whole feature on or off, keeping any stored PIN either way.
//!
//! Refuses to turn on without a PIN: there would be no way back out of the lock
//! screen. Refuses to turn off while Locked, which would be an unlock without
//! the PIN -- and the phone can ask for this.
//!
//! @return S_NO_ACTION_REQUIRED if it was already that way.
status_t security_lock_set_enabled(bool enabled);

//! Configure the PIN and move to Armed. Digits are ASCII '0'-'9'.
//!
//! Setting a PIN is what turns the feature on; there is nothing else to opt in
//! with, and a PIN that armed nothing would be a control that did nothing.
status_t security_lock_set_pin(const char *digits, uint8_t len);

//! Clear the PIN and move to Disabled. Also clears any duress PIN.
status_t security_lock_clear_pin(void);

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
//! @param[out] attempts_remaining_out may be NULL. Set to the number of
//!             attempts left before escalation.
//! @return true if the PIN matched.
bool security_lock_verify_pin(const char *digits, uint8_t len, uint8_t *attempts_remaining_out);

uint8_t security_lock_get_failed_attempts(void);
status_t security_lock_reset_failed_attempts(void);

//! True once failed attempts have reached SECURITY_LOCK_MAX_PIN_ATTEMPTS.
bool security_lock_attempts_exhausted(void);

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
void security_lock_mark_dirty_since_shred(void);

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

//! Absolute wall-clock deadlines armed when the phone disconnects. 0 means
//! not armed.
//!
//! Both are cleared on unlock and on reconnect, and neither re-arms until the
//! next unexpected disconnect -- so an unlocked, reconnected watch is not
//! sitting on a countdown the user cannot see.
//! How long after a disconnect the watch locks, and how long after a
//! disconnect it shreds. Persisted, so a reboot keeps the user's choice.
uint32_t security_lock_get_lock_delay_s(void);
uint32_t security_lock_get_shred_delay_s(void);

//! @return E_INVALID_ARGUMENT if the erase would land before the lock.
//!         SECURITY_LOCK_SHRED_DELAY_NEVER is exempt: it schedules no erase.
status_t security_lock_set_delays(uint32_t lock_delay_s, uint32_t shred_delay_s);

time_t security_lock_get_lock_deadline(void);
time_t security_lock_get_shred_deadline(void);
status_t security_lock_set_deadlines(time_t lock_deadline, time_t shred_deadline);
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
