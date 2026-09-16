/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

//! Tests for the lock funnel: what engaging does, and what it refuses to do.
//!
//! This is one of the two places the master switch is enforced -- the other is
//! security_lock_shred() -- so it is where "off means nothing locks and nothing
//! erases" is stated for every trigger that goes through a lock rather than
//! straight to a wipe.
//!
//! Everything it drives is faked. The subject is which of set_state, the UI
//! lockout and the wipe run, not what any of them go on to do.

#include "clar.h"

#include <string.h>

#include "pbl/services/security_lock.h"
#include "pbl/services/security_lock_shred.h"
#include "pbl/services/security_lock_ui.h"

// Stubs
////////////////////////////////////
#include "stubs_logging.h"
#include "stubs_passert.h"
#include "stubs_pebble_tasks.h"
#include "stubs_print.h"
#include "stubs_serial.h"

// Fakes
////////////////////////////////////

//! Standing in for the settings-backed service. The real record store is
//! covered by test_security_lock.
static SecurityLockState s_state;
static uint8_t s_pin_len;

static int s_shreds;
static int s_lockouts;
static int s_quiesces;
static int s_state_changed_msgs;
static int s_lock_screen_pops;

SecurityLockState security_lock_get_state(void) {
  return s_state;
}

bool security_lock_is_locked(void) {
  return s_state == SecurityLockStateLocked;
}

status_t security_lock_set_state(SecurityLockState state) {
  s_state = state;
  return S_SUCCESS;
}

uint8_t security_lock_get_pin_len(void) {
  return s_pin_len;
}

uint32_t security_lock_shred(SecurityShredReason reason) {
  s_shreds++;
  return 0;
}

const char *security_lock_shred_reason_str(SecurityShredReason reason) {
  return "test";
}

void security_lock_endpoint_send_state_changed(SecurityLockState state) {
  s_state_changed_msgs++;
}

//! The arming half lives in endpoint.c, with the timer that reads what it
//! writes. Counted rather than performed: what matters here is that the funnel
//! reaches it only on the paths that should, and only once the lock has taken.
static int s_countdowns_armed;

void security_lock_endpoint_arm_manual_countdown(void) {
  s_countdowns_armed++;
}

// The UI lockout and the quiesce live in the same file as the funnel, so they
// are exercised rather than faked; everything they in turn call is not.

static bool s_lock_screen_visible;
static bool s_watchface_running = true;

bool security_lock_screen_is_visible(void) {
  return s_lock_screen_visible;
}

void security_lock_screen_pop(void) {
  s_lock_screen_pops++;
}

//! Pulled in by security_lock_ui_quiesce(): an alarm already on screen is torn
//! down with everything else when the watch locks.
void alarm_popup_close(void) {}

void launcher_block_popups_for_lock(bool block) {
  s_lockouts += block ? 1 : -1;
}

void launcher_cancel_force_quit(void) {}

typedef int ModalPriority;
void modal_manager_set_min_priority(ModalPriority priority) {}
void modal_manager_set_min_priority_floor(ModalPriority priority) {}
void modal_manager_pop_all(void) {
  s_quiesces++;
}
void modal_manager_pop_all_below_priority(ModalPriority priority) {
  s_quiesces++;
}

void watchface_reset_click_manager(void) {}
void watchface_launch_default(const void *animation) {}

bool app_manager_is_watchface_running(void) {
  return s_watchface_running;
}

bool app_manager_close_current_app(bool gracefully) {
  return true;
}

void compositor_render_app(void) {}

bool compositor_display_update_in_progress(void) {
  return false;
}

void compositor_display_update(void (*handle_update_complete)(void)) {}

// Helpers
////////////////////////////////////

void test_security_lock_engage__initialize(void) {
  s_state = SecurityLockStateArmed;
  s_pin_len = 4;
  s_shreds = 0;
  s_lockouts = 0;
  s_quiesces = 0;
  s_state_changed_msgs = 0;
  s_lock_screen_pops = 0;
  s_countdowns_armed = 0;
  s_lock_screen_visible = false;
  s_watchface_running = true;

  // The UI lockout is reference counted in a static, and clar runs every test
  // in one process. Disengaging is how it is released, which makes this its own
  // reset path rather than a back door.
  security_lock_disengage();
  s_state = SecurityLockStateArmed;
  s_lockouts = 0;
  s_quiesces = 0;
  s_state_changed_msgs = 0;
  s_lock_screen_pops = 0;
  s_countdowns_armed = 0;
}

void test_security_lock_engage__cleanup(void) {}

// The ordinary path
////////////////////////////////////

void test_security_lock_engage__locks_and_wipes(void) {
  security_lock_engage(SecurityShredReasonPhoneLockdown);

  cl_assert_equal_i(SecurityLockStateLocked, s_state);
  cl_assert_equal_i(1, s_shreds);
  cl_assert_equal_i(1, s_lockouts);
}

//! The lock deadline locks without erasing: the separate erase deadline decides
//! when -- or whether -- the content goes.
void test_security_lock_engage__lock_only_does_not_wipe(void) {
  security_lock_engage_lock_only(SecurityShredReasonDisconnectTimeout);

  cl_assert_equal_i(SecurityLockStateLocked, s_state);
  cl_assert_equal_i(0, s_shreds);
  // Nothing wiped it for us, so the funnel takes the screen down itself.
  cl_assert_equal_i(1, s_quiesces);
}

//! And it arms nothing: the disconnect that caused it armed the erase deadline
//! already, and a second countdown on top would restart the clock at the lock.
void test_security_lock_engage__lock_only_arms_no_countdown(void) {
  security_lock_engage_lock_only(SecurityShredReasonDisconnectTimeout);

  cl_assert_equal_i(0, s_countdowns_armed);
}

//! The wipe takes a ringing alarm down with everything else, including when
//! the lock screen is up and the bound spares it.
//!
//! The lock screen has a priority of its own, one above the alarm's, so
//! "everything below the lock screen" is everything -- the alarm included.
//! That is what stops an erased watch, which holds nothing and talks to
//! nobody, from carrying on buzzing about it.
void test_security_lock_engage__quiescing_reaches_the_alarm_under_the_lock_screen(void) {
  s_lock_screen_visible = true;

  security_lock_engage_lock_only(SecurityShredReasonDisconnectTimeout);

  cl_assert_equal_i(1, s_quiesces);
}

// The countdown path
////////////////////////////////////
//
// What every manual trigger does: lock at once, erase at the configured delay,
// PIN cancels. The third mode exists because the other two are the extremes --
// erase now, or arm nothing at all -- and neither is what a user pressing
// Lockdown wants.

void test_security_lock_engage__with_countdown_locks_without_wiping(void) {
  security_lock_engage_with_countdown(SecurityShredReasonManualPanic);

  cl_assert_equal_i(SecurityLockStateLocked, s_state);
  cl_assert_equal_i(0, s_shreds);
  cl_assert_equal_i(1, s_lockouts);
  cl_assert_equal_i(1, s_countdowns_armed);
  // Nothing wiped it for us, so the funnel takes the screen down itself.
  cl_assert_equal_i(1, s_quiesces);
}

//! Arming happens after the lock takes, not before it is attempted. A countdown
//! left running for a lock that was refused would erase an unlocked watch.
void test_security_lock_engage__the_feature_being_off_arms_no_countdown(void) {
  s_state = SecurityLockStateDisabled;

  security_lock_engage_with_countdown(SecurityShredReasonManualPanic);

  cl_assert_equal_i(SecurityLockStateDisabled, s_state);
  cl_assert_equal_i(0, s_countdowns_armed);
  cl_assert_equal_i(0, s_shreds);
  cl_assert_equal_i(0, s_lockouts);
}

void test_security_lock_engage__an_unusable_pin_length_arms_no_countdown(void) {
  s_pin_len = SECURITY_LOCK_PIN_MAX_LEN + 1;

  security_lock_engage_with_countdown(SecurityShredReasonManualPanic);

  cl_assert_equal_i(SecurityLockStateArmed, s_state);
  cl_assert_equal_i(0, s_countdowns_armed);
}

//! The erase-now path stays what it was. Whether it also arms a countdown is
//! not a detail: the wipe has already happened, so a countdown behind it would
//! be a second erase scheduled over an empty filesystem.
void test_security_lock_engage__erasing_now_arms_no_countdown(void) {
  security_lock_engage(SecurityShredReasonManualPanic);

  cl_assert_equal_i(1, s_shreds);
  cl_assert_equal_i(0, s_countdowns_armed);
}

// The master switch
////////////////////////////////////

//! The defect the switch exists to dissolve, stated at the funnel: with the
//! feature off, nothing locks and -- crucially -- nothing erases. Erasing a
//! watch that was never protected destroys the user's content and leaves the
//! watch wide open afterwards, which is neither half of what this is for.
void test_security_lock_engage__the_feature_being_off_does_nothing(void) {
  s_state = SecurityLockStateDisabled;

  security_lock_engage(SecurityShredReasonPhoneLockdown);

  cl_assert_equal_i(SecurityLockStateDisabled, s_state);
  cl_assert_equal_i(0, s_shreds);
  cl_assert_equal_i(0, s_lockouts);
  cl_assert_equal_i(0, s_quiesces);
}

void test_security_lock_engage__the_feature_being_off_blocks_lock_only_too(void) {
  s_state = SecurityLockStateDisabled;

  security_lock_engage_lock_only(SecurityShredReasonDisconnectTimeout);

  cl_assert_equal_i(SecurityLockStateDisabled, s_state);
  cl_assert_equal_i(0, s_lockouts);
}

//! The switch is checked before the PIN, so a stored PIN left behind by a
//! switch-off cannot talk the funnel into running.
void test_security_lock_engage__a_kept_pin_does_not_reenable_the_funnel(void) {
  s_state = SecurityLockStateDisabled;
  s_pin_len = 6;

  security_lock_engage(SecurityShredReasonManualPanic);

  cl_assert_equal_i(0, s_shreds);
}

//! Enabled with a PIN the lock screen could not prompt for is an inconsistent
//! record, not a state any control produces. It used to erase without locking,
//! which is the worst of both: the content is gone and the watch is open.
void test_security_lock_engage__an_unusable_pin_length_wipes_nothing(void) {
  s_state = SecurityLockStateArmed;
  s_pin_len = SECURITY_LOCK_PIN_MAX_LEN + 1;

  security_lock_engage(SecurityShredReasonPhoneLockdown);

  cl_assert_equal_i(SecurityLockStateArmed, s_state);
  cl_assert_equal_i(0, s_shreds);
}

void test_security_lock_engage__no_pin_at_all_wipes_nothing(void) {
  s_state = SecurityLockStateArmed;
  s_pin_len = 0;

  security_lock_engage(SecurityShredReasonPhoneLockdown);

  cl_assert_equal_i(0, s_shreds);
}

// Leaving the locked state
////////////////////////////////////

void test_security_lock_engage__disengage_arms_and_tells_the_phone(void) {
  security_lock_engage(SecurityShredReasonPhoneLockdown);

  security_lock_disengage();

  cl_assert_equal_i(SecurityLockStateArmed, s_state);
  cl_assert_equal_i(1, s_lock_screen_pops);
  cl_assert_equal_i(1, s_state_changed_msgs);
  // The lockout is released, not merely decremented past zero: the reference
  // count asserts on underflow.
  cl_assert_equal_i(0, s_lockouts);
}
