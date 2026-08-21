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

#define SECURITY_LOCK_PIN_MIN_LEN 4
#define SECURITY_LOCK_PIN_MAX_LEN 8
#define SECURITY_LOCK_SALT_LEN 16
#define SECURITY_LOCK_HASH_LEN 32

//! Wrong PINs tolerated before the watch re-shreds and stays locked.
#define SECURITY_LOCK_MAX_PIN_ATTEMPTS 3

//! Seconds the watch may stay disconnected while locked before re-shredding.
#define SECURITY_LOCK_DISCONNECT_TIMEOUT_S (30 * 60)

//! Slack allowed when comparing against the persisted time high-water mark.
//! The RTC can legitimately drift or be nudged by a resync; anything beyond
//! this reads as a deliberate rollback.
#define SECURITY_LOCK_TIME_ROLLBACK_SLACK_S (5 * 60)

typedef enum {
  //! Feature off; no PIN configured.
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

//! Configure the PIN and move to Armed. Digits are ASCII '0'-'9'.
status_t security_lock_set_pin(const char *digits, uint8_t len);

//! Clear the PIN and move to Disabled.
status_t security_lock_clear_pin(void);

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

//! Absolute deadline (wall clock) after which a disconnected, locked watch
//! must re-shred. 0 means no deadline is armed.
time_t security_lock_get_disconnect_deadline(void);
status_t security_lock_set_disconnect_deadline(time_t deadline);
status_t security_lock_clear_disconnect_deadline(void);

//! True if the deadline is armed and `now` is at or past it.
bool security_lock_disconnect_deadline_expired(time_t now);

//! Record the current time, maintaining a monotonic high-water mark.
//!
//! There is no reboot-persistent monotonic clock on this hardware, so a
//! deliberate backwards jump is the only rollback signal available.
//!
//! @return true if `now` is further back than the allowed slack, i.e. the
//!         clock appears to have been wound back.
bool security_lock_note_time(time_t now);

time_t security_lock_get_time_high_water(void);
