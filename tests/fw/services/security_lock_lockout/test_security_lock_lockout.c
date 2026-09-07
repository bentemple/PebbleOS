/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include "clar.h"

#include <string.h>

#include "kernel/events.h"
#include "pbl/services/security_lock.h"
#include "pbl/services/security_lock_pin_hash.h"
#include "pbl/services/security_lock_shred.h"
#include "pbl/services/filesystem/pfs.h"
#include "pbl/services/settings/settings_file.h"
#include "util/units.h"

// Stubs
////////////////////////////////////
#include "stubs_analytics.h"
#include "stubs_logging.h"
#include "stubs_mutex.h"
#include "stubs_passert.h"
#include "stubs_pbl_malloc.h"
#include "stubs_pebble_tasks.h"
#include "stubs_print.h"
#include "stubs_prompt.h"
#include "stubs_rand_ptr.h"
#include "stubs_serial.h"
#include "stubs_sleep.h"
#include "stubs_system_reset.h"
#include "stubs_task_watchdog.h"
#include "fake_bluetooth_ctl.h"
#include "fake_rng.h"
#include "fake_rtc.h"
#include "fake_spi_flash.h"

// Fakes
////////////////////////////////////

typedef struct CommSession CommSession;
CommSession *comm_session_get_system_session(void) { return (CommSession *)1; }

static void (*s_pending_cb)(void *);
void launcher_task_add_callback(void (*cb)(void *), void *data) { s_pending_cb = cb; }

uint32_t security_lock_shred(SecurityShredReason reason) { return 0; }

static int s_resync_reports;
void security_lock_endpoint_report_resync_needed(SecurityShredReason reason, uint32_t dbs) {
  s_resync_reports++;
}

void bt_persistent_storage_set_unfaithful(bool unfaithful) {}

//! Pulled in by security_lock_should_drop_notifications(). The real ones live
//! in shred.c and the shell prefs; neither is the subject of this suite.
bool security_lock_is_shredding(void) { return false; }
bool shell_prefs_get_block_notifications_when_locked(void) { return true; }

void event_put(PebbleEvent *event) {}

//! Counts every derivation, which is what tells a refused entry from a compared
//! one: a refusal must never reach the hash.
static int s_hash_call_count;

status_t security_lock_pin_hash(const char *digits, uint8_t len,
                                const uint8_t salt[SECURITY_LOCK_SALT_LEN],
                                uint8_t hash_out[SECURITY_LOCK_HASH_LEN]) {
  if (len < SECURITY_LOCK_PIN_MIN_LEN || len > SECURITY_LOCK_PIN_MAX_LEN) {
    return E_INVALID_ARGUMENT;
  }
  s_hash_call_count++;
  for (int i = 0; i < SECURITY_LOCK_HASH_LEN; ++i) {
    hash_out[i] = (uint8_t)(salt[i % SECURITY_LOCK_SALT_LEN] ^ digits[i % len] ^ (uint8_t)i ^ len);
  }
  return S_SUCCESS;
}

bool security_lock_hash_equal(const uint8_t a[SECURITY_LOCK_HASH_LEN],
                              const uint8_t b[SECURITY_LOCK_HASH_LEN]) {
  return memcmp(a, b, SECURITY_LOCK_HASH_LEN) == 0;
}

// Helpers
////////////////////////////////////

static const char *PIN = "1234";
static const char *WRONG_PIN = "9999";

//! Tear the service down and bring it back up without touching the flash, so
//! state has to survive via the settings file rather than the RAM cache.
static void prv_simulate_reboot(void) {
  security_lock_deinit();
  security_lock_init();
}

//! Spend the budget, leaving the watch in the first backoff window.
static void prv_exhaust(void) {
  for (int i = 0; i < SECURITY_LOCK_MAX_PIN_ATTEMPTS; ++i) {
    cl_assert(!security_lock_verify_pin(WRONG_PIN, strlen(WRONG_PIN), NULL));
  }
  cl_assert(security_lock_attempts_exhausted());
}

void test_security_lock_lockout__initialize(void) {
  s_pending_cb = NULL;
  s_hash_call_count = 0;
  s_resync_reports = 0;
  fake_bt_ctl_reset();
  fake_rtc_init(0, 1000);
  fake_spi_flash_init(0, 0x1000000);
  pfs_init(false);
  security_lock_init();
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
}

void test_security_lock_lockout__cleanup(void) {
  security_lock_deinit();
  fake_spi_flash_cleanup();
}

// The refusal
////////////////////////////////////
//
// Without it, 9^4 guesses at ~350ms each is a forty minute exhaustive search
// that ends in a genuine unlock. The gate is here rather than in the lock
// screen because the console and the phone endpoint reach this same function.

void test_security_lock_lockout__nothing_waits_before_the_budget_is_spent(void) {
  cl_assert_equal_i(0, security_lock_get_lockout_remaining_s());
  for (int i = 0; i < SECURITY_LOCK_MAX_PIN_ATTEMPTS - 1; ++i) {
    cl_assert(!security_lock_verify_pin(WRONG_PIN, strlen(WRONG_PIN), NULL));
    cl_assert_equal_i(0, security_lock_get_lockout_remaining_s());
  }
}

void test_security_lock_lockout__a_spent_budget_starts_the_backoff(void) {
  prv_exhaust();
  cl_assert_equal_i(SECURITY_LOCK_LOCKOUT_BASE_S, security_lock_get_lockout_remaining_s());
}

//! The whole point: the right PIN does not get in either, so there is nothing
//! to be found by carrying on.
void test_security_lock_lockout__the_right_pin_is_refused_during_the_backoff(void) {
  prv_exhaust();
  cl_assert(!security_lock_verify_pin(PIN, strlen(PIN), NULL));
  cl_assert(!security_lock_is_locked());
}

//! Refused before hashing, not after: an attempt that reached the comparison
//! would still leak timing and would still cost the flash a write.
void test_security_lock_lockout__a_refused_attempt_is_never_compared(void) {
  prv_exhaust();
  s_hash_call_count = 0;

  cl_assert(!security_lock_verify_pin(PIN, strlen(PIN), NULL));
  cl_assert(!security_lock_verify_pin(WRONG_PIN, strlen(WRONG_PIN), NULL));

  cl_assert_equal_i(0, s_hash_call_count);
}

//! Refusals are not counted. Counting them would let someone hammering the pad
//! push the delay to the cap and hold it there, locking the owner out for good.
void test_security_lock_lockout__a_refused_attempt_is_not_counted(void) {
  prv_exhaust();
  for (int i = 0; i < 20; ++i) {
    cl_assert(!security_lock_verify_pin(WRONG_PIN, strlen(WRONG_PIN), NULL));
  }
  cl_assert_equal_i(SECURITY_LOCK_MAX_PIN_ATTEMPTS, security_lock_get_failed_attempts());
  cl_assert_equal_i(SECURITY_LOCK_LOCKOUT_BASE_S, security_lock_get_lockout_remaining_s());
}

// The escalation
////////////////////////////////////

void test_security_lock_lockout__one_guess_per_window_and_the_window_doubles(void) {
  prv_exhaust();

  // A second short of the window is still short.
  fake_rtc_increment_time(SECURITY_LOCK_LOCKOUT_BASE_S - 1);
  cl_assert_equal_i(1, security_lock_get_lockout_remaining_s());
  cl_assert(!security_lock_verify_pin(WRONG_PIN, strlen(WRONG_PIN), NULL));
  cl_assert_equal_i(SECURITY_LOCK_MAX_PIN_ATTEMPTS, security_lock_get_failed_attempts());

  // On the second, one guess is looked at -- and spending it doubles the wait.
  fake_rtc_increment_time(1);
  cl_assert_equal_i(0, security_lock_get_lockout_remaining_s());
  cl_assert(!security_lock_verify_pin(WRONG_PIN, strlen(WRONG_PIN), NULL));
  cl_assert_equal_i(SECURITY_LOCK_MAX_PIN_ATTEMPTS + 1, security_lock_get_failed_attempts());
  cl_assert_equal_i(2 * SECURITY_LOCK_LOCKOUT_BASE_S, security_lock_get_lockout_remaining_s());

  fake_rtc_increment_time(2 * SECURITY_LOCK_LOCKOUT_BASE_S);
  cl_assert(!security_lock_verify_pin(WRONG_PIN, strlen(WRONG_PIN), NULL));
  cl_assert_equal_i(4 * SECURITY_LOCK_LOCKOUT_BASE_S, security_lock_get_lockout_remaining_s());
}

//! Capped, so the wait cannot run away to something the owner can never sit
//! out. An hour a guess is still months for the 9^4 space.
void test_security_lock_lockout__the_backoff_stops_at_the_cap(void) {
  prv_exhaust();

  for (int i = 0; i < 20; ++i) {
    fake_rtc_increment_time(SECURITY_LOCK_LOCKOUT_MAX_S);
    cl_assert_equal_i(0, security_lock_get_lockout_remaining_s());
    cl_assert(!security_lock_verify_pin(WRONG_PIN, strlen(WRONG_PIN), NULL));
    cl_assert(security_lock_get_lockout_remaining_s() <= SECURITY_LOCK_LOCKOUT_MAX_S);
  }
  cl_assert_equal_i(SECURITY_LOCK_LOCKOUT_MAX_S, security_lock_get_lockout_remaining_s());
}

//! Delayed, not shut out: once the wait is over the owner's PIN works and
//! everything the lockout was tracking goes back to zero.
void test_security_lock_lockout__the_right_pin_gets_in_once_the_wait_is_over(void) {
  prv_exhaust();

  fake_rtc_increment_time(SECURITY_LOCK_LOCKOUT_BASE_S);
  cl_assert(security_lock_verify_pin(PIN, strlen(PIN), NULL));
  cl_assert_equal_i(0, security_lock_get_failed_attempts());
  cl_assert_equal_i(0, security_lock_get_lockout_remaining_s());
}

// The clock
////////////////////////////////////

//! Measured from the last attempt rather than stored as a deadline, so winding
//! the clock back adds to the wait instead of retiring it.
void test_security_lock_lockout__winding_the_clock_back_does_not_shorten_it(void) {
  prv_exhaust();

  fake_rtc_init(0, 1);
  cl_assert_equal_i(SECURITY_LOCK_LOCKOUT_BASE_S, security_lock_get_lockout_remaining_s());
  cl_assert(!security_lock_verify_pin(PIN, strlen(PIN), NULL));
}

// Across a reboot
////////////////////////////////////
//
// Power cycling is the obvious way to try to shake the wait off, so the
// counter and the time it is measured from are both on flash.

void test_security_lock_lockout__the_backoff_survives_a_reboot(void) {
  prv_exhaust();

  prv_simulate_reboot();

  cl_assert(security_lock_attempts_exhausted());
  cl_assert_equal_i(SECURITY_LOCK_LOCKOUT_BASE_S, security_lock_get_lockout_remaining_s());
  s_hash_call_count = 0;
  cl_assert(!security_lock_verify_pin(PIN, strlen(PIN), NULL));
  cl_assert_equal_i(0, s_hash_call_count);

  fake_rtc_increment_time(SECURITY_LOCK_LOCKOUT_BASE_S);
  cl_assert(security_lock_verify_pin(PIN, strlen(PIN), NULL));
}

//! An escalated wait survives too, so cycling power part way up the ladder does
//! not drop back to the first rung.
void test_security_lock_lockout__the_escalated_backoff_survives_a_reboot(void) {
  prv_exhaust();
  fake_rtc_increment_time(SECURITY_LOCK_LOCKOUT_BASE_S);
  cl_assert(!security_lock_verify_pin(WRONG_PIN, strlen(WRONG_PIN), NULL));

  prv_simulate_reboot();

  cl_assert_equal_i(2 * SECURITY_LOCK_LOCKOUT_BASE_S, security_lock_get_lockout_remaining_s());
  cl_assert_equal_i(SECURITY_LOCK_MAX_PIN_ATTEMPTS + 1, security_lock_get_failed_attempts());
}

//! Unlocking clears it, so the next lock starts the owner on a clean budget.
void test_security_lock_lockout__unlocking_clears_it_for_good(void) {
  prv_exhaust();
  fake_rtc_increment_time(SECURITY_LOCK_LOCKOUT_BASE_S);
  cl_assert(security_lock_verify_pin(PIN, strlen(PIN), NULL));

  prv_simulate_reboot();

  cl_assert_equal_i(0, security_lock_get_failed_attempts());
  cl_assert_equal_i(0, security_lock_get_lockout_remaining_s());
}

// Leaving Locked by setting a PIN
////////////////////////////////////
//
// The third path out of the locked state, and deliberately the quiet one. It
// writes the state itself rather than going through set_state, so it does not
// retire a countdown the watch is legitimately running: a lock armed by a
// bluetooth disconnect takes a much less aggressive stance than one the user is
// standing in front of, and setting a PIN is not an answer to it. Covered here
// because this suite already stands up the whole service against real flash.

void test_security_lock_lockout__setting_a_pin_out_of_locked_leaves_the_countdown_alone(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_state(SecurityLockStateLocked));
  cl_assert_equal_i(S_SUCCESS,
                    security_lock_set_deadlines(4000, 5000, SecurityCountdownDisconnect));

  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin("5678", 4));

  // Out of Locked, but nothing else unwound.
  cl_assert_equal_i(SecurityLockStateArmed, security_lock_get_state());
  cl_assert_equal_i(4000, security_lock_get_lock_deadline());
  cl_assert_equal_i(5000, security_lock_get_shred_deadline());
  cl_assert_equal_i(SecurityCountdownDisconnect, security_lock_get_countdown_source());
}

//! The attempt budget still resets, so a new PIN is not born already locked out.
void test_security_lock_lockout__setting_a_pin_clears_the_lockout(void) {
  prv_exhaust();
  cl_assert(security_lock_get_lockout_remaining_s() > 0);

  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin("5678", 4));

  cl_assert_equal_i(0, security_lock_get_failed_attempts());
  cl_assert_equal_i(0, security_lock_get_lockout_remaining_s());
}
