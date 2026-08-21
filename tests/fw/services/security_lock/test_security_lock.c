/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include "clar.h"

#include <string.h>

#include "pbl/services/security_lock.h"
#include "pbl/services/security_lock_pin_hash.h"
#include "pbl/services/security_lock_shred.h"
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

// Fakes for the service's new dependencies
////////////////////////////////////

//! Changing a PIN requires a connected phone; tests drive this directly.
static bool s_phone_connected = true;
typedef struct CommSession CommSession;
CommSession *comm_session_get_system_session(void) {
  return s_phone_connected ? (CommSession *)1 : NULL;
}

//! A duress unlock schedules the wipe on KernelBG rather than running it
//! inline, so the test captures the callback instead of shredding.
static int s_duress_shreds;
static void (*s_pending_cb)(void *);
bool system_task_add_callback(void (*cb)(void *), void *data) {
  s_pending_cb = cb;
  return true;
}
static void prv_run_pending_callback(void) {
  if (s_pending_cb) {
    void (*cb)(void *) = s_pending_cb;
    s_pending_cb = NULL;
    cb(NULL);
  }
}
uint32_t security_lock_shred(SecurityShredReason reason) {
  if (reason == SecurityShredReasonDuressPin) {
    s_duress_shreds++;
  }
  return 0;
}

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
  s_phone_connected = true;
  s_duress_shreds = 0;
  s_pending_cb = NULL;
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
  cl_assert_equal_i(0, security_lock_get_shred_deadline());
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
  cl_assert(security_lock_set_pin("1234567", 7) != S_SUCCESS);
  // 5 is between the two allowed lengths, so it must be rejected too.
  cl_assert(security_lock_set_pin("12345", 5) != S_SUCCESS);
  cl_assert_equal_i(SecurityLockStateDisabled, security_lock_get_state());
}

void test_security_lock__rejects_non_digits(void) {
  cl_assert(security_lock_set_pin("12a4", 4) != S_SUCCESS);
  // The pad has no 0 key, so a PIN with one could never be typed.
  cl_assert(security_lock_set_pin("1204", 4) != S_SUCCESS);
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
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin("123456", 6));
  cl_assert_equal_i(6, security_lock_get_pin_len());
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
  cl_assert_equal_i(S_SUCCESS, security_lock_set_deadlines(0, 5000));

  cl_assert_equal_i(S_SUCCESS, security_lock_set_state(SecurityLockStateArmed));
  cl_assert_equal_i(0, security_lock_get_failed_attempts());
  cl_assert_equal_i(0, security_lock_get_shred_deadline());
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
  cl_assert(!security_lock_shred_deadline_expired(100000));

  cl_assert_equal_i(S_SUCCESS, security_lock_set_deadlines(0, 1000));
  cl_assert(!security_lock_shred_deadline_expired(999));
  cl_assert(security_lock_shred_deadline_expired(1000));
  cl_assert(security_lock_shred_deadline_expired(1001));
}

void test_security_lock__deadline_survives_reboot(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_deadlines(0, 4242));
  prv_simulate_reboot();
  cl_assert_equal_i(4242, security_lock_get_shred_deadline());
  cl_assert(security_lock_shred_deadline_expired(4242));
}

void test_security_lock__cleared_deadline_never_expires(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_deadlines(0, 1000));
  cl_assert_equal_i(S_SUCCESS, security_lock_clear_deadlines());
  cl_assert(!security_lock_shred_deadline_expired(999999));
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

// Configurable delays
////////////////////////////////////

void test_security_lock__delays_default_to_five_and_thirty_minutes(void) {
  cl_assert_equal_i(5 * 60, security_lock_get_lock_delay_s());
  cl_assert_equal_i(30 * 60, security_lock_get_shred_delay_s());
}

void test_security_lock__delays_are_configurable(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_delays(60, 120));
  cl_assert_equal_i(60, security_lock_get_lock_delay_s());
  cl_assert_equal_i(120, security_lock_get_shred_delay_s());
}

void test_security_lock__delays_survive_reboot(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_delays(90, 900));
  prv_simulate_reboot();
  cl_assert_equal_i(90, security_lock_get_lock_delay_s());
  cl_assert_equal_i(900, security_lock_get_shred_delay_s());
}

//! Shredding before locking would destroy the data without the user ever
//! getting a chance to stop it.
void test_security_lock__shred_delay_cannot_precede_lock_delay(void) {
  cl_assert(security_lock_set_delays(600, 300) != S_SUCCESS);
  cl_assert_equal_i(5 * 60, security_lock_get_lock_delay_s());
}

void test_security_lock__equal_delays_are_allowed(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_delays(300, 300));
}

// Deadline arming and re-arming
////////////////////////////////////

void test_security_lock__both_deadlines_arm_and_expire_independently(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_deadlines(1000, 2000));

  cl_assert(!security_lock_lock_deadline_expired(999));
  cl_assert(security_lock_lock_deadline_expired(1000));
  cl_assert(!security_lock_shred_deadline_expired(1999));
  cl_assert(security_lock_shred_deadline_expired(2000));
}

//! A correct PIN retires the countdown entirely.
void test_security_lock__unlocking_clears_both_deadlines(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert_equal_i(S_SUCCESS, security_lock_set_state(SecurityLockStateLocked));
  cl_assert_equal_i(S_SUCCESS, security_lock_set_deadlines(1000, 2000));

  cl_assert_equal_i(S_SUCCESS, security_lock_set_state(SecurityLockStateArmed));

  cl_assert_equal_i(0, security_lock_get_lock_deadline());
  cl_assert_equal_i(0, security_lock_get_shred_deadline());
  cl_assert(!security_lock_shred_deadline_expired(999999));
}

//! Cleared deadlines stay cleared across a reboot -- an unlocked watch must not
//! come back still counting down.
void test_security_lock__cleared_deadlines_stay_cleared_over_reboot(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_deadlines(1000, 2000));
  cl_assert_equal_i(S_SUCCESS, security_lock_clear_deadlines());
  prv_simulate_reboot();
  cl_assert_equal_i(0, security_lock_get_shred_deadline());
  cl_assert(!security_lock_shred_deadline_expired(999999));
}

//! Re-arming after a reconnect/disconnect cycle must produce a fresh countdown,
//! not resume the old one.
void test_security_lock__deadlines_rearm_from_scratch(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_delays(60, 600));

  // First disconnect at t=1000.
  cl_assert_equal_i(S_SUCCESS, security_lock_set_deadlines(1060, 1600));
  // Reconnect clears.
  cl_assert_equal_i(S_SUCCESS, security_lock_clear_deadlines());
  // Second disconnect much later at t=5000.
  cl_assert_equal_i(S_SUCCESS, security_lock_set_deadlines(5060, 5600));

  // The old deadline must not still be pending.
  cl_assert(!security_lock_shred_deadline_expired(5599));
  cl_assert(security_lock_shred_deadline_expired(5600));
}

//! An already-locked watch arms only the shred countdown; there is nothing left
//! to lock.
void test_security_lock__locked_watch_arms_only_the_shred_deadline(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_deadlines(0, 2000));
  cl_assert_equal_i(0, security_lock_get_lock_deadline());
  cl_assert(!security_lock_lock_deadline_expired(999999));
  cl_assert(security_lock_shred_deadline_expired(2000));
}

// Changing a PIN requires the phone
////////////////////////////////////

//! A watch on its own must not be re-PINnable by whoever is holding it.
void test_security_lock__cannot_set_pin_without_the_phone(void) {
  s_phone_connected = false;
  cl_assert(security_lock_set_pin(PIN, strlen(PIN)) != S_SUCCESS);
  cl_assert_equal_i(SecurityLockStateDisabled, security_lock_get_state());
}

void test_security_lock__cannot_change_pin_without_the_phone(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  s_phone_connected = false;
  cl_assert(security_lock_set_pin("5678", 4) != S_SUCCESS);
  // The original PIN must still be the one that works.
  s_phone_connected = true;
  cl_assert(security_lock_verify_pin(PIN, strlen(PIN), NULL));
}

void test_security_lock__cannot_clear_pin_without_the_phone(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  s_phone_connected = false;
  cl_assert(security_lock_clear_pin() != S_SUCCESS);
  s_phone_connected = true;
  cl_assert(security_lock_verify_pin(PIN, strlen(PIN), NULL));
}

//! Verifying must still work with no phone -- otherwise a watch that lost its
//! phone could never be unlocked again.
void test_security_lock__can_still_unlock_without_the_phone(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  s_phone_connected = false;
  cl_assert(security_lock_verify_pin(PIN, strlen(PIN), NULL));
}

// Duress PIN
////////////////////////////////////

static const char *DURESS = "4321";

void test_security_lock__duress_pin_unlocks_and_shreds(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert_equal_i(S_SUCCESS, security_lock_set_duress_pin(DURESS, strlen(DURESS)));

  // Indistinguishable from a real unlock as far as the caller can tell.
  uint8_t remaining = 0;
  cl_assert(security_lock_verify_pin(DURESS, strlen(DURESS), &remaining));
  cl_assert_equal_i(SECURITY_LOCK_MAX_PIN_ATTEMPTS, remaining);
  cl_assert_equal_i(0, security_lock_get_failed_attempts());

  // ...but a wipe was scheduled.
  cl_assert_equal_i(0, s_duress_shreds);
  prv_run_pending_callback();
  cl_assert_equal_i(1, s_duress_shreds);
}

void test_security_lock__real_pin_does_not_shred(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert_equal_i(S_SUCCESS, security_lock_set_duress_pin(DURESS, strlen(DURESS)));

  cl_assert(security_lock_verify_pin(PIN, strlen(PIN), NULL));
  prv_run_pending_callback();
  cl_assert_equal_i(0, s_duress_shreds);
}

void test_security_lock__wrong_pin_does_not_shred(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert_equal_i(S_SUCCESS, security_lock_set_duress_pin(DURESS, strlen(DURESS)));

  cl_assert(!security_lock_verify_pin("9999", 4, NULL));
  prv_run_pending_callback();
  cl_assert_equal_i(0, s_duress_shreds);
}

void test_security_lock__duress_pin_survives_reboot(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert_equal_i(S_SUCCESS, security_lock_set_duress_pin(DURESS, strlen(DURESS)));
  prv_simulate_reboot();

  cl_assert(security_lock_verify_pin(DURESS, strlen(DURESS), NULL));
  prv_run_pending_callback();
  cl_assert_equal_i(1, s_duress_shreds);
}

//! Identical PINs would make the duress one unreachable: the real check runs
//! first and would always win.
void test_security_lock__duress_pin_cannot_equal_the_real_pin(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert(security_lock_set_duress_pin(PIN, strlen(PIN)) != S_SUCCESS);
  cl_assert(!security_lock_has_duress_pin());
}

void test_security_lock__duress_pin_needs_a_real_pin_first(void) {
  cl_assert(security_lock_set_duress_pin(DURESS, strlen(DURESS)) != S_SUCCESS);
}

//! Changing the real PIN must not silently disarm the duress PIN.
void test_security_lock__duress_pin_survives_a_pin_change(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert_equal_i(S_SUCCESS, security_lock_set_duress_pin(DURESS, strlen(DURESS)));
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin("5678", 4));

  cl_assert(security_lock_has_duress_pin());
  cl_assert(security_lock_verify_pin(DURESS, strlen(DURESS), NULL));
  prv_run_pending_callback();
  cl_assert_equal_i(1, s_duress_shreds);
}

void test_security_lock__clearing_the_pin_clears_the_duress_pin(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert_equal_i(S_SUCCESS, security_lock_set_duress_pin(DURESS, strlen(DURESS)));
  cl_assert_equal_i(S_SUCCESS, security_lock_clear_pin());
  cl_assert(!security_lock_has_duress_pin());
}

void test_security_lock__duress_pin_can_be_cleared(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert_equal_i(S_SUCCESS, security_lock_set_duress_pin(DURESS, strlen(DURESS)));
  cl_assert_equal_i(S_SUCCESS, security_lock_clear_duress_pin());

  cl_assert(!security_lock_has_duress_pin());
  // The old duress PIN is now simply a wrong PIN.
  cl_assert(!security_lock_verify_pin(DURESS, strlen(DURESS), NULL));
  prv_run_pending_callback();
  cl_assert_equal_i(0, s_duress_shreds);
}

void test_security_lock__duress_pin_can_be_six_digits(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert_equal_i(S_SUCCESS, security_lock_set_duress_pin("654321", 6));
  cl_assert(security_lock_verify_pin("654321", 6, NULL));
  prv_run_pending_callback();
  cl_assert_equal_i(1, s_duress_shreds);
}
