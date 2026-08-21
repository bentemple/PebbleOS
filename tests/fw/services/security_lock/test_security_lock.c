/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include "clar.h"

#include <string.h>

#include "pbl/services/security_lock.h"
#include "pbl/services/security_lock_pin_hash.h"
#include "pbl/services/filesystem/pfs.h"

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
#include "fake_rng.h"
#include "fake_rtc.h"
#include "fake_spi_flash.h"

// Fake PIN hash
////////////////////////////////////
// Substituted for the mbedtls-backed implementation so the test does not link
// a crypto library to exercise the record store. Must still be salt- and
// PIN-sensitive, or the tests below would pass vacuously.

//! Attempts already recorded at the moment hashing was invoked. Used to prove
//! the counter is bumped before any comparison happens.
static int s_attempts_at_hash_time;
static int s_hash_call_count;

status_t security_lock_pin_hash(const char *digits, uint8_t len,
                                const uint8_t salt[SECURITY_LOCK_SALT_LEN],
                                uint8_t hash_out[SECURITY_LOCK_HASH_LEN]) {
  if (len < SECURITY_LOCK_PIN_MIN_LEN || len > SECURITY_LOCK_PIN_MAX_LEN) {
    return E_INVALID_ARGUMENT;
  }
  s_hash_call_count++;
  s_attempts_at_hash_time = security_lock_get_failed_attempts();

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

//! Tear the service down and bring it back up without touching the flash, so
//! state has to survive via the settings file rather than the RAM cache.
static void prv_simulate_reboot(void) {
  security_lock_deinit();
  security_lock_init();
}

static const char *PIN = "1234";
static const char *WRONG_PIN = "9999";

void test_security_lock__initialize(void) {
  s_attempts_at_hash_time = -1;
  s_hash_call_count = 0;
  fake_spi_flash_init(0, 0x1000000);
  pfs_init(false);
  security_lock_init();
}

void test_security_lock__cleanup(void) {
  security_lock_deinit();
  fake_spi_flash_cleanup();
}

// Defaults
////////////////////////////////////

void test_security_lock__defaults_are_disabled(void) {
  cl_assert_equal_i(SecurityLockStateDisabled, security_lock_get_state());
  cl_assert(!security_lock_is_locked());
  cl_assert_equal_i(0, security_lock_get_failed_attempts());
  cl_assert(!security_lock_attempts_exhausted());
  cl_assert(!security_lock_is_shred_pending());
  cl_assert_equal_i(0, security_lock_get_disconnect_deadline());
  cl_assert_equal_i(0, security_lock_get_time_high_water());
}

void test_security_lock__verify_without_pin_fails(void) {
  cl_assert(!security_lock_verify_pin(PIN, strlen(PIN), NULL));
}

// PIN configuration
////////////////////////////////////

void test_security_lock__set_pin_arms(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert_equal_i(SecurityLockStateArmed, security_lock_get_state());
}

void test_security_lock__rejects_bad_pin_lengths(void) {
  cl_assert(security_lock_set_pin("123", 3) != S_SUCCESS);
  cl_assert(security_lock_set_pin("123456789", 9) != S_SUCCESS);
  cl_assert_equal_i(SecurityLockStateDisabled, security_lock_get_state());
}

void test_security_lock__rejects_non_digits(void) {
  cl_assert(security_lock_set_pin("12a4", 4) != S_SUCCESS);
  cl_assert_equal_i(SecurityLockStateDisabled, security_lock_get_state());
}

void test_security_lock__correct_pin_verifies(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  uint8_t remaining = 0;
  cl_assert(security_lock_verify_pin(PIN, strlen(PIN), &remaining));
  cl_assert_equal_i(0, security_lock_get_failed_attempts());
  cl_assert_equal_i(SECURITY_LOCK_MAX_PIN_ATTEMPTS, remaining);
}

void test_security_lock__wrong_pin_fails(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert(!security_lock_verify_pin(WRONG_PIN, strlen(WRONG_PIN), NULL));
  cl_assert_equal_i(1, security_lock_get_failed_attempts());
}

void test_security_lock__wrong_length_pin_fails(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert(!security_lock_verify_pin("123456", 6, NULL));
  cl_assert_equal_i(1, security_lock_get_failed_attempts());
}

void test_security_lock__clear_pin_disables_and_forgets(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert_equal_i(S_SUCCESS, security_lock_clear_pin());
  cl_assert_equal_i(SecurityLockStateDisabled, security_lock_get_state());
  cl_assert(!security_lock_verify_pin(PIN, strlen(PIN), NULL));
}

// The lock screen sizes itself from this, so a wrong answer either prompts for
// digits that cannot be entered or submits short and always fails.
void test_security_lock__pin_len_reports_configured_length(void) {
  cl_assert_equal_i(0, security_lock_get_pin_len());
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin("12345678", 8));
  cl_assert_equal_i(8, security_lock_get_pin_len());
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert_equal_i(4, security_lock_get_pin_len());
}

void test_security_lock__pin_len_is_zero_without_a_pin(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert_equal_i(S_SUCCESS, security_lock_clear_pin());
  cl_assert_equal_i(0, security_lock_get_pin_len());
}

void test_security_lock__pin_len_survives_reboot(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin("123456", 6));
  prv_simulate_reboot();
  cl_assert_equal_i(6, security_lock_get_pin_len());
}

void test_security_lock__pin_survives_reboot(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  prv_simulate_reboot();
  cl_assert_equal_i(SecurityLockStateArmed, security_lock_get_state());
  cl_assert(security_lock_verify_pin(PIN, strlen(PIN), NULL));
}

void test_security_lock__changing_pin_invalidates_old(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin("5678", 4));
  cl_assert(!security_lock_verify_pin(PIN, strlen(PIN), NULL));
  cl_assert(security_lock_verify_pin("5678", 4, NULL));
}

// Attempt counting -- the security-critical part
////////////////////////////////////

void test_security_lock__attempts_accumulate_to_exhaustion(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));

  uint8_t remaining = 0xff;
  for (int i = 1; i <= SECURITY_LOCK_MAX_PIN_ATTEMPTS; ++i) {
    cl_assert(!security_lock_verify_pin(WRONG_PIN, strlen(WRONG_PIN), &remaining));
    cl_assert_equal_i(i, security_lock_get_failed_attempts());
    cl_assert_equal_i(SECURITY_LOCK_MAX_PIN_ATTEMPTS - i, remaining);
  }
  cl_assert(security_lock_attempts_exhausted());
}

//! The counter must reach flash before the PIN is compared, otherwise an
//! attacker could guess repeatedly and cut power on each wrong answer.
void test_security_lock__attempt_is_counted_before_comparison(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  s_hash_call_count = 0;

  cl_assert(!security_lock_verify_pin(WRONG_PIN, strlen(WRONG_PIN), NULL));

  // The hash ran (so a comparison was actually attempted) and by that point
  // the attempt had already been recorded.
  cl_assert(s_hash_call_count > 0);
  cl_assert_equal_i(1, s_attempts_at_hash_time);
}

//! Complements the above: the recorded attempt is durable, not just cached.
void test_security_lock__attempts_survive_reboot(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert(!security_lock_verify_pin(WRONG_PIN, strlen(WRONG_PIN), NULL));
  cl_assert(!security_lock_verify_pin(WRONG_PIN, strlen(WRONG_PIN), NULL));

  prv_simulate_reboot();

  cl_assert_equal_i(2, security_lock_get_failed_attempts());
  cl_assert(!security_lock_attempts_exhausted());

  cl_assert(!security_lock_verify_pin(WRONG_PIN, strlen(WRONG_PIN), NULL));
  cl_assert(security_lock_attempts_exhausted());
}

void test_security_lock__correct_pin_resets_attempts(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert(!security_lock_verify_pin(WRONG_PIN, strlen(WRONG_PIN), NULL));
  cl_assert(!security_lock_verify_pin(WRONG_PIN, strlen(WRONG_PIN), NULL));
  cl_assert_equal_i(2, security_lock_get_failed_attempts());

  cl_assert(security_lock_verify_pin(PIN, strlen(PIN), NULL));
  cl_assert_equal_i(0, security_lock_get_failed_attempts());

  prv_simulate_reboot();
  cl_assert_equal_i(0, security_lock_get_failed_attempts());
}

void test_security_lock__reset_attempts_explicitly(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert(!security_lock_verify_pin(WRONG_PIN, strlen(WRONG_PIN), NULL));
  cl_assert_equal_i(S_SUCCESS, security_lock_reset_failed_attempts());
  cl_assert_equal_i(0, security_lock_get_failed_attempts());
}

// State transitions
////////////////////////////////////

void test_security_lock__state_survives_reboot(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert_equal_i(S_SUCCESS, security_lock_set_state(SecurityLockStateLocked));
  cl_assert(security_lock_is_locked());

  prv_simulate_reboot();
  cl_assert(security_lock_is_locked());
}

void test_security_lock__unlocking_clears_attempts_and_deadline(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert_equal_i(S_SUCCESS, security_lock_set_state(SecurityLockStateLocked));
  cl_assert(!security_lock_verify_pin(WRONG_PIN, strlen(WRONG_PIN), NULL));
  cl_assert_equal_i(S_SUCCESS, security_lock_set_disconnect_deadline(5000));

  cl_assert_equal_i(S_SUCCESS, security_lock_set_state(SecurityLockStateArmed));
  cl_assert_equal_i(0, security_lock_get_failed_attempts());
  cl_assert_equal_i(0, security_lock_get_disconnect_deadline());
}

// Shred-pending flag
////////////////////////////////////

void test_security_lock__shred_pending_survives_reboot(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_shred_pending(true));
  prv_simulate_reboot();
  cl_assert(security_lock_is_shred_pending());

  cl_assert_equal_i(S_SUCCESS, security_lock_set_shred_pending(false));
  prv_simulate_reboot();
  cl_assert(!security_lock_is_shred_pending());
}

// Disconnect deadline
////////////////////////////////////

void test_security_lock__deadline_expiry(void) {
  cl_assert(!security_lock_disconnect_deadline_expired(100000));

  cl_assert_equal_i(S_SUCCESS, security_lock_set_disconnect_deadline(1000));
  cl_assert(!security_lock_disconnect_deadline_expired(999));
  cl_assert(security_lock_disconnect_deadline_expired(1000));
  cl_assert(security_lock_disconnect_deadline_expired(1001));
}

void test_security_lock__deadline_survives_reboot(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_disconnect_deadline(4242));
  prv_simulate_reboot();
  cl_assert_equal_i(4242, security_lock_get_disconnect_deadline());
  cl_assert(security_lock_disconnect_deadline_expired(4242));
}

void test_security_lock__cleared_deadline_never_expires(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_disconnect_deadline(1000));
  cl_assert_equal_i(S_SUCCESS, security_lock_clear_disconnect_deadline());
  cl_assert(!security_lock_disconnect_deadline_expired(999999));
}

// Clock rollback
////////////////////////////////////

void test_security_lock__time_high_water_advances(void) {
  cl_assert(!security_lock_note_time(1000));
  cl_assert_equal_i(1000, security_lock_get_time_high_water());

  cl_assert(!security_lock_note_time(2000));
  cl_assert_equal_i(2000, security_lock_get_time_high_water());

  // Going backwards must not lower the mark.
  cl_assert(!security_lock_note_time(1999));
  cl_assert_equal_i(2000, security_lock_get_time_high_water());
}

void test_security_lock__small_backwards_step_is_tolerated(void) {
  cl_assert(!security_lock_note_time(100000));
  // Inside the slack window: ordinary drift or a time resync, not tampering.
  cl_assert(!security_lock_note_time(100000 - SECURITY_LOCK_TIME_ROLLBACK_SLACK_S + 1));
}

void test_security_lock__large_rollback_is_flagged(void) {
  cl_assert(!security_lock_note_time(100000));
  cl_assert(security_lock_note_time(100000 - SECURITY_LOCK_TIME_ROLLBACK_SLACK_S - 1));
}

void test_security_lock__high_water_survives_reboot(void) {
  cl_assert(!security_lock_note_time(500000));
  prv_simulate_reboot();
  cl_assert_equal_i(500000, security_lock_get_time_high_water());
  cl_assert(security_lock_note_time(500000 - SECURITY_LOCK_TIME_ROLLBACK_SLACK_S - 1));
}

void test_security_lock__first_note_is_never_a_rollback(void) {
  // No mark recorded yet, so any time is acceptable.
  cl_assert(!security_lock_note_time(1));
}
