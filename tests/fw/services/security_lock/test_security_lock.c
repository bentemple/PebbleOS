/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include "clar.h"

#include <string.h>

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

// Fakes for the service's new dependencies
////////////////////////////////////

//! Changing a PIN requires a connected phone; tests drive this directly.
static bool s_phone_connected = true;
typedef struct CommSession CommSession;
CommSession *comm_session_get_system_session(void) {
  return s_phone_connected ? (CommSession *)1 : NULL;
}

//! A duress unlock defers the wipe to the launcher task rather than running it
//! inline, so the test captures the callback instead of shredding.
static int s_duress_shreds;
static void (*s_pending_cb)(void *);
void launcher_task_add_callback(void (*cb)(void *), void *data) {
  s_pending_cb = cb;
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

//! What the service asked the phone to resend and, because the fake bt_ctl
//! applies airplane mode synchronously, whether the radio was already back at
//! the moment it asked.
static int s_resync_reports;
static SecurityShredReason s_resync_reason;
static uint32_t s_resync_dbs;
static bool s_airplane_at_report;
void security_lock_endpoint_report_resync_needed(SecurityShredReason reason, uint32_t dbs) {
  s_resync_reports++;
  s_resync_reason = reason;
  s_resync_dbs |= dbs;
  s_airplane_at_report = bt_ctl_is_airplane_mode_on();
}

static int s_unfaithful_marks;
void bt_persistent_storage_set_unfaithful(bool unfaithful) {
  s_unfaithful_marks++;
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

//! Rewrite a stored record with a version the service does not know, which is
//! what a downgrade or a record from a future build looks like. Length is
//! preserved so only the version field is in question.
static void prv_corrupt_record_version(const char *key) {
  SettingsFile file;
  cl_assert_equal_i(S_SUCCESS, settings_file_open(&file, "seclock", KiBYTES(2)));
  const int len = settings_file_get_len(&file, key, strlen(key));
  cl_assert(len > (int)sizeof(uint16_t));

  uint8_t *record = malloc(len);
  cl_assert_equal_i(S_SUCCESS, settings_file_get(&file, key, strlen(key), record, len));
  // The version is the first field of both records.
  record[0] = 0xff;
  record[1] = 0xff;
  cl_assert_equal_i(S_SUCCESS, settings_file_set(&file, key, strlen(key), record, len));

  settings_file_close(&file);
  free(record);
}

static void prv_corrupt_runtime_version(void) {
  prv_corrupt_record_version("rt");
}

//! Replace the runtime record with a shorter one, which is what a record
//! written by a build with fewer fields actually looks like -- the real upgrade
//! path, where the length rather than the version is what rejects it.
static void prv_shorten_runtime_record(void) {
  SettingsFile file;
  cl_assert_equal_i(S_SUCCESS, settings_file_open(&file, "seclock", KiBYTES(2)));
  const int len = settings_file_get_len(&file, "rt", 2);
  cl_assert(len > (int)sizeof(uint16_t));

  uint8_t *record = malloc(len);
  cl_assert_equal_i(S_SUCCESS, settings_file_get(&file, "rt", 2, record, len));
  cl_assert_equal_i(S_SUCCESS, settings_file_set(&file, "rt", 2, record, len - 2));

  settings_file_close(&file);
  free(record);
}

static const char *PIN = "1234";
static const char *WRONG_PIN = "9999";
static const char *DURESS = "4321";

void test_security_lock__initialize(void) {
  s_attempts_at_hash_time = -1;
  s_hash_call_count = 0;
  s_phone_connected = true;
  s_duress_shreds = 0;
  s_pending_cb = NULL;
  s_resync_reports = 0;
  s_resync_reason = SecurityShredReasonUnknown;
  s_resync_dbs = 0;
  s_airplane_at_report = false;
  s_unfaithful_marks = 0;
  fake_bt_ctl_reset();
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

// The master switch
////////////////////////////////////
//
// Not a field of its own: Disabled already meant "nothing fires", already
// defaulted off, and setting a PIN already left it. Turning it off discards the
// PIN, so "has a PIN" and "is on" are one fact and cannot disagree.

void test_security_lock__the_feature_is_off_out_of_the_box(void) {
  cl_assert(!security_lock_is_enabled());
}

//! Setting a PIN is the only way to opt in; there is nothing else to opt in
//! with, and a PIN that armed nothing would be a control that did nothing.
void test_security_lock__setting_a_pin_turns_the_feature_on(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert(security_lock_is_enabled());
}

//! The point of the switch: off is off, not paused. A PIN that outlived it
//! would leave the switch protecting less than the lock screen does.
void test_security_lock__turning_the_feature_off_clears_the_pin(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));

  cl_assert_equal_i(S_SUCCESS, security_lock_disable());

  cl_assert(!security_lock_is_enabled());
  cl_assert_equal_i(SecurityLockStateDisabled, security_lock_get_state());
  cl_assert_equal_i(0, security_lock_get_pin_len());
  cl_assert(!security_lock_verify_pin(PIN, strlen(PIN), NULL));
}

//! And the duress PIN with it. A forgotten one surviving into the next PIN
//! would be a wipe nobody remembers arming.
void test_security_lock__turning_the_feature_off_clears_the_duress_pin(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert_equal_i(S_SUCCESS, security_lock_set_duress_pin(DURESS, strlen(DURESS)));

  cl_assert_equal_i(S_SUCCESS, security_lock_disable());

  cl_assert(!security_lock_has_duress_pin());
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert(!security_lock_has_duress_pin());
}

//! "Everything behaves like before this feature existed": the delays go back to
//! their defaults rather than being kept for a lock that no longer exists.
void test_security_lock__turning_the_feature_off_restores_the_defaults(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert_equal_i(S_SUCCESS, security_lock_set_delays(90, 900));

  cl_assert_equal_i(S_SUCCESS, security_lock_disable());

  cl_assert_equal_i(SECURITY_LOCK_DEFAULT_LOCK_DELAY_S, security_lock_get_lock_delay_s());
  cl_assert_equal_i(SECURITY_LOCK_DEFAULT_SHRED_DELAY_S, security_lock_get_shred_delay_s());
}

//! Off is persisted, and nothing is left to come back: the config record went
//! with the PIN, so there is no stored credential for a reboot to rearm from.
void test_security_lock__off_survives_a_reboot(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert_equal_i(S_SUCCESS, security_lock_disable());

  prv_simulate_reboot();

  cl_assert(!security_lock_is_enabled());
  cl_assert_equal_i(0, security_lock_get_pin_len());
}

//! The same, through the path that discards the runtime record. This is the one
//! that used to disarm the lock silently: the config record versions separately
//! and survives, so a watch that was on comes back on -- and a watch that was
//! turned off has no PIN to be rearmed from.
void test_security_lock__off_survives_an_unreadable_runtime_record(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert_equal_i(S_SUCCESS, security_lock_disable());

  prv_corrupt_runtime_version();
  prv_simulate_reboot();

  cl_assert(!security_lock_is_enabled());
  cl_assert_equal_i(0, security_lock_get_pin_len());
}

//! Turning the feature off is not a way past the lock screen: it would be an
//! unlock without the PIN. Only the PIN clears a lock.
void test_security_lock__the_feature_cannot_be_turned_off_while_locked(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert_equal_i(S_SUCCESS, security_lock_set_state(SecurityLockStateLocked));

  cl_assert_equal_i(E_INVALID_OPERATION, security_lock_disable());

  cl_assert(security_lock_is_locked());
  cl_assert_equal_i(strlen(PIN), security_lock_get_pin_len());
}

//! Off means no countdown is left running, rather than one running that every
//! check declines to act on.
void test_security_lock__turning_the_feature_off_retires_the_deadlines(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert_equal_i(S_SUCCESS, security_lock_set_deadlines(5000, 6000));

  cl_assert_equal_i(S_SUCCESS, security_lock_disable());

  cl_assert_equal_i(0, security_lock_get_lock_deadline());
  cl_assert_equal_i(0, security_lock_get_shred_deadline());
}

void test_security_lock__turning_off_an_already_off_feature_is_a_no_op(void) {
  cl_assert_equal_i(S_NO_ACTION_REQUIRED, security_lock_disable());
}

//! Clearing the PIN is what turning the feature off does, so it is the same
//! outcome reached from the recovery side.
void test_security_lock__clearing_the_pin_turns_the_feature_off(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert_equal_i(S_SUCCESS, security_lock_clear_pin());

  cl_assert(!security_lock_is_enabled());
  cl_assert_equal_i(0, security_lock_get_pin_len());
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

// Dirty-since-shred flag
////////////////////////////////////

//! A watch that has never recorded the flag knows nothing about what is on it,
//! and a shred that believes an unknown watch is clean is a data leak. Reading
//! dirty is the only safe answer.
void test_security_lock__unrecorded_state_reads_dirty(void) {
  cl_assert(security_lock_is_dirty_since_shred());
}

//! Before the record has been read at all -- which is where the boot shred
//! decision would sit if the ordering ever changed.
void test_security_lock__uninitialised_reads_dirty(void) {
  security_lock_deinit();
  cl_assert(security_lock_is_dirty_since_shred());
  security_lock_init();
}

void test_security_lock__clearing_and_marking_survive_reboot(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_clear_dirty_since_shred());
  cl_assert(!security_lock_is_dirty_since_shred());
  prv_simulate_reboot();
  cl_assert(!security_lock_is_dirty_since_shred());

  security_lock_mark_dirty_since_shred();
  cl_assert(security_lock_is_dirty_since_shred());
  prv_simulate_reboot();
  cl_assert(security_lock_is_dirty_since_shred());
}

//! Marking runs on every stored notification and every inbound blob db write.
//! Persisting each one would be a flash write per notification, so only the
//! clean-to-dirty transition may touch flash.
void test_security_lock__marking_only_writes_flash_on_the_transition(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_clear_dirty_since_shred());

  const uint32_t before_first = fake_flash_write_count();
  security_lock_mark_dirty_since_shred();
  const uint32_t after_first = fake_flash_write_count();
  cl_assert(after_first > before_first);

  for (int i = 0; i < 20; ++i) {
    security_lock_mark_dirty_since_shred();
  }
  cl_assert_equal_i(after_first, fake_flash_write_count());
  cl_assert(security_lock_is_dirty_since_shred());
}

//! A record written by a build that did not have the flag cannot be trusted to
//! say anything about it, so the whole record is discarded -- and the defaults
//! it falls back to have to read dirty, or the upgrade would talk the first
//! shred out of running.
void test_security_lock__record_from_an_unknown_version_reads_dirty(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_clear_dirty_since_shred());
  cl_assert(!security_lock_is_dirty_since_shred());

  prv_corrupt_runtime_version();
  prv_simulate_reboot();

  cl_assert(security_lock_is_dirty_since_shred());
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

//! Never is not an erase scheduled before the lock, it is no timed erase at
//! all, so the ordering rule must not reject it.
void test_security_lock__shred_delay_can_be_never(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_delays(600, SECURITY_LOCK_SHRED_DELAY_NEVER));
  cl_assert_equal_i(600, security_lock_get_lock_delay_s());
  cl_assert_equal_i(SECURITY_LOCK_SHRED_DELAY_NEVER, security_lock_get_shred_delay_s());
}

void test_security_lock__never_survives_reboot(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_delays(600, SECURITY_LOCK_SHRED_DELAY_NEVER));
  prv_simulate_reboot();
  cl_assert_equal_i(SECURITY_LOCK_SHRED_DELAY_NEVER, security_lock_get_shred_delay_s());
}

//! Never disarms the countdown, not the deadline machinery: an unarmed shred
//! deadline is already how "nothing pending" is represented.
void test_security_lock__a_never_shred_deadline_never_expires(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_deadlines(1000, 0));
  cl_assert(security_lock_lock_deadline_expired(1000));
  cl_assert(!security_lock_shred_deadline_expired(999999));
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

// Duress PIN
////////////////////////////////////

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

//! For the caller that cannot honour duress semantics: a duress PIN is simply
//! a wrong PIN, and nothing is scheduled by it. Turning the feature off is what
//! stops a queued wipe from running, so accepting one there would sometimes
//! disarm the lock and erase nothing.
void test_security_lock__real_pin_verify_refuses_a_duress_pin(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert_equal_i(S_SUCCESS, security_lock_set_duress_pin(DURESS, strlen(DURESS)));

  cl_assert(!security_lock_verify_real_pin(DURESS, strlen(DURESS)));
  prv_run_pending_callback();
  cl_assert_equal_i(0, s_duress_shreds);
}

void test_security_lock__real_pin_verify_accepts_the_real_pin(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert_equal_i(S_SUCCESS, security_lock_set_duress_pin(DURESS, strlen(DURESS)));

  cl_assert(security_lock_verify_real_pin(PIN, strlen(PIN)));
  cl_assert_equal_i(0, security_lock_get_failed_attempts());
  prv_run_pending_callback();
  cl_assert_equal_i(0, s_duress_shreds);
}

//! It counts against the same budget as any other guess, so it cannot be used
//! as a free oracle for whether an entry is the duress PIN.
void test_security_lock__real_pin_verify_burns_an_attempt(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert_equal_i(S_SUCCESS, security_lock_set_duress_pin(DURESS, strlen(DURESS)));

  cl_assert(!security_lock_verify_real_pin(DURESS, strlen(DURESS)));
  cl_assert_equal_i(1, security_lock_get_failed_attempts());
  cl_assert(!security_lock_verify_real_pin("9999", 4));
  cl_assert_equal_i(2, security_lock_get_failed_attempts());
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

// Radio blackout
////////////////////////////////////

void test_security_lock__blackout_turns_airplane_mode_on(void) {
  cl_assert(!security_lock_is_radio_blackout());

  security_lock_radio_blackout_engage();

  cl_assert(security_lock_is_radio_blackout());
  cl_assert(bt_ctl_is_airplane_mode_on());
}

void test_security_lock__release_puts_airplane_mode_back(void) {
  security_lock_radio_blackout_engage();
  security_lock_radio_blackout_release();

  cl_assert(!security_lock_is_radio_blackout());
  cl_assert(!bt_ctl_is_airplane_mode_on());
}

//! The user's own setting is what gets restored, not "off". Someone who was
//! already in airplane mode before the wipe must not be dropped out of it.
void test_security_lock__release_keeps_airplane_mode_the_user_already_had(void) {
  fake_bt_ctl_set_airplane_mode(true);

  security_lock_radio_blackout_engage();
  cl_assert(bt_ctl_is_airplane_mode_on());

  security_lock_radio_blackout_release();
  cl_assert(bt_ctl_is_airplane_mode_on());
}

//! The saved value is taken once, on the way in. A second engage -- a repeat
//! wipe, or the re-assert after a reboot -- would otherwise record the blackout
//! as its own "previous state" and strand airplane mode on forever.
void test_security_lock__engaging_twice_does_not_save_its_own_state(void) {
  security_lock_radio_blackout_engage();
  security_lock_radio_blackout_engage();

  security_lock_radio_blackout_release();
  cl_assert(!bt_ctl_is_airplane_mode_on());
}

//! A watch that has never been blacked out must not have its airplane mode
//! touched by a stray release.
void test_security_lock__release_without_a_blackout_changes_nothing(void) {
  fake_bt_ctl_set_airplane_mode(true);
  const int writes_before = fake_bt_ctl_get_airplane_writes();

  security_lock_radio_blackout_release();

  cl_assert(bt_ctl_is_airplane_mode_on());
  cl_assert_equal_i(writes_before, fake_bt_ctl_get_airplane_writes());
}

//! A reboot while locked is a designed-for case, so the saved value cannot live
//! in RAM: unlocking after one would otherwise restore the wrong state.
void test_security_lock__blackout_and_saved_state_survive_reboot(void) {
  fake_bt_ctl_set_airplane_mode(true);
  security_lock_radio_blackout_engage();

  prv_simulate_reboot();
  cl_assert(security_lock_is_radio_blackout());

  security_lock_radio_blackout_release();
  cl_assert(bt_ctl_is_airplane_mode_on());
}

void test_security_lock__blackout_off_survives_reboot(void) {
  security_lock_radio_blackout_engage();
  prv_simulate_reboot();

  security_lock_radio_blackout_release();
  prv_simulate_reboot();

  cl_assert(!security_lock_is_radio_blackout());
  cl_assert(!bt_ctl_is_airplane_mode_on());
}

//! The blackout belongs to the locked state, so leaving that state is what
//! gives the radio back -- whatever the reason for leaving it.
void test_security_lock__leaving_the_locked_state_releases_the_radio(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert_equal_i(S_SUCCESS, security_lock_set_state(SecurityLockStateLocked));
  security_lock_radio_blackout_engage();

  cl_assert_equal_i(S_SUCCESS, security_lock_set_state(SecurityLockStateArmed));

  cl_assert(!security_lock_is_radio_blackout());
  cl_assert(!bt_ctl_is_airplane_mode_on());
}

//! Re-entering the locked state must not release it.
void test_security_lock__locking_again_keeps_the_radio_down(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert_equal_i(S_SUCCESS, security_lock_set_state(SecurityLockStateLocked));
  security_lock_radio_blackout_engage();

  cl_assert_equal_i(S_SUCCESS, security_lock_set_state(SecurityLockStateLocked));

  cl_assert(security_lock_is_radio_blackout());
  cl_assert(bt_ctl_is_airplane_mode_on());
}

//! Turning the feature off wipes the runtime record, which is where the blackout
//! is recorded. The radio has to come back before that record goes, or nothing
//! is left that knows to restore it.
void test_security_lock__clearing_the_pin_releases_the_radio(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  security_lock_radio_blackout_engage();

  cl_assert_equal_i(S_SUCCESS, security_lock_clear_pin());

  cl_assert(!security_lock_is_radio_blackout());
  cl_assert(!bt_ctl_is_airplane_mode_on());
}

// Record versioning
////////////////////////////////////

//! The config record holds the PIN and the runtime record holds everything
//! else, and they version independently. A runtime-only change must not be able
//! to discard the PIN and disarm the lock, which is what a single shared
//! version number did on every bump.
void test_security_lock__an_unreadable_runtime_record_keeps_the_pin(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin("123456", 6));

  prv_corrupt_runtime_version();
  prv_simulate_reboot();

  cl_assert_equal_i(6, security_lock_get_pin_len());
  cl_assert(security_lock_verify_pin("123456", 6, NULL));
}

//! ...and the surviving PIN has to be reflected in the state, or the watch comes
//! back configured but not watching: every trigger is gated on the state, so
//! Disabled would be a silently disarmed lock.
void test_security_lock__an_unreadable_runtime_record_stays_armed(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));

  prv_corrupt_runtime_version();
  prv_simulate_reboot();

  cl_assert_equal_i(SecurityLockStateArmed, security_lock_get_state());
}

//! With no PIN to fall back on there is nothing to be armed about.
void test_security_lock__an_unreadable_runtime_record_without_a_pin_is_disabled(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_shred_pending(true));

  prv_corrupt_runtime_version();
  prv_simulate_reboot();

  cl_assert_equal_i(SecurityLockStateDisabled, security_lock_get_state());
  cl_assert_equal_i(0, security_lock_get_pin_len());
}

//! The shape an actual upgrade takes: the old runtime record is too short for
//! the new one, so it is rejected on length before the version is even looked
//! at. The config record is unchanged in both length and version, so the PIN is
//! read back exactly as it was written.
void test_security_lock__a_shorter_runtime_record_keeps_the_pin_and_arms(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert_equal_i(S_SUCCESS, security_lock_set_delays(90, 900));

  prv_shorten_runtime_record();
  prv_simulate_reboot();

  cl_assert_equal_i(SecurityLockStateArmed, security_lock_get_state());
  cl_assert_equal_i(4, security_lock_get_pin_len());
  cl_assert(security_lock_verify_pin(PIN, strlen(PIN), NULL));

  // The runtime half is genuinely gone: the delays are back to their defaults
  // and the dirty flag reads the safe answer.
  cl_assert_equal_i(SECURITY_LOCK_DEFAULT_LOCK_DELAY_S, security_lock_get_lock_delay_s());
  cl_assert(security_lock_is_dirty_since_shred());
}

//! The reverse direction: an unreadable config record leaves no PIN, and a
//! watch with no PIN must not claim to be locked -- there would be no way past
//! the lock screen.
void test_security_lock__an_unreadable_config_record_leaves_no_pin(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));

  prv_corrupt_record_version("cfg");
  prv_simulate_reboot();

  cl_assert_equal_i(0, security_lock_get_pin_len());
  cl_assert(!security_lock_verify_pin(PIN, strlen(PIN), NULL));
}

// Writes refused while locked
////////////////////////////////////

//! The bug this exists for. A locked watch drops inbound writes and acks them
//! as successes, and Gadgetbridge records a calendar event as synced the moment
//! it fires the write -- so a pin pushed to a locked watch is discarded, acked,
//! and never offered again. Leaving the locked state is the one chance to undo
//! that.
void test_security_lock__unlocking_asks_the_phone_to_resend_what_was_refused(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert_equal_i(S_SUCCESS, security_lock_set_state(SecurityLockStateLocked));
  security_lock_note_write_refused(BlobDBIdPins);
  security_lock_note_write_refused(BlobDBIdWeather);

  cl_assert_equal_i(S_SUCCESS, security_lock_set_state(SecurityLockStateArmed));

  cl_assert_equal_i(1, s_resync_reports);
  cl_assert_equal_i(SECURITY_SHRED_DB_BIT(BlobDBIdPins) | SECURITY_SHRED_DB_BIT(BlobDBIdWeather),
                    s_resync_dbs);
  // Nothing was wiped, and the reason field is what says so.
  cl_assert_equal_i(SecurityShredReasonWritesRefused, s_resync_reason);
}

//! A spurious resync is not free: it costs the phone a full calendar re-push
//! every time the watch is unlocked.
void test_security_lock__unlocking_with_nothing_refused_asks_for_nothing(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert_equal_i(S_SUCCESS, security_lock_set_state(SecurityLockStateLocked));

  cl_assert_equal_i(S_SUCCESS, security_lock_set_state(SecurityLockStateArmed));

  cl_assert_equal_i(0, s_resync_reports);
  cl_assert_equal_i(0, s_unfaithful_marks);
}

//! Reported once. The second unlock has nothing left to report, so it is
//! indistinguishable from a watch that never refused anything.
void test_security_lock__the_refusals_are_cleared_once_reported(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert_equal_i(S_SUCCESS, security_lock_set_state(SecurityLockStateLocked));
  security_lock_note_write_refused(BlobDBIdPins);
  cl_assert_equal_i(S_SUCCESS, security_lock_set_state(SecurityLockStateArmed));
  cl_assert_equal_i(1, s_resync_reports);

  cl_assert_equal_i(S_SUCCESS, security_lock_set_state(SecurityLockStateLocked));
  cl_assert_equal_i(S_SUCCESS, security_lock_set_state(SecurityLockStateArmed));

  cl_assert_equal_i(1, s_resync_reports);
}

//! Repeats collapse: the phone is asked for a database, not for a write count.
void test_security_lock__repeated_refusals_of_one_database_report_once(void) {
  security_lock_note_write_refused(BlobDBIdPins);
  security_lock_note_write_refused(BlobDBIdPins);
  security_lock_note_write_refused(BlobDBIdPins);

  cl_assert_equal_i(SECURITY_SHRED_DB_BIT(BlobDBIdPins), security_lock_take_refused_dbs());
  cl_assert_equal_i(0, security_lock_take_refused_dbs());
}

//! The phone-side flag for the same request. Gadgetbridge stops parsing the
//! version handshake long before it reaches this byte, so it cannot be the only
//! mechanism, but the official app reads it and it costs nothing to be right
//! for both.
void test_security_lock__unlocking_marks_the_watch_unfaithful(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert_equal_i(S_SUCCESS, security_lock_set_state(SecurityLockStateLocked));
  security_lock_note_write_refused(BlobDBIdPins);

  cl_assert_equal_i(S_SUCCESS, security_lock_set_state(SecurityLockStateArmed));

  cl_assert_equal_i(1, s_unfaithful_marks);
}

//! The ordering that matters. The same transition releases the radio, and a
//! request sent while it is still down would find no session and vanish. The
//! release runs first, so the message is offered to a radio that is back.
void test_security_lock__the_radio_is_back_before_the_phone_is_asked(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert_equal_i(S_SUCCESS, security_lock_set_state(SecurityLockStateLocked));
  security_lock_radio_blackout_engage();
  cl_assert(bt_ctl_is_airplane_mode_on());
  security_lock_note_write_refused(BlobDBIdPins);

  cl_assert_equal_i(S_SUCCESS, security_lock_set_state(SecurityLockStateArmed));

  cl_assert_equal_i(1, s_resync_reports);
  cl_assert(!s_airplane_at_report);
}

//! Turning the feature off is another way out of the locked state, and it does
//! not go through security_lock_set_state().
void test_security_lock__clearing_the_pin_asks_the_phone_to_resend(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  cl_assert_equal_i(S_SUCCESS, security_lock_set_state(SecurityLockStateLocked));
  security_lock_note_write_refused(BlobDBIdContacts);

  cl_assert_equal_i(S_SUCCESS, security_lock_clear_pin());

  cl_assert_equal_i(1, s_resync_reports);
  cl_assert_equal_i(SECURITY_SHRED_DB_BIT(BlobDBIdContacts), s_resync_dbs);
}

//! Deliberately not persisted. A reboot while locked wipes, and the wipe asks
//! for its own resend -- so nothing is lost by keeping this in RAM, and a
//! persisted bitmap would mean a flash write per refused write.
void test_security_lock__refusals_do_not_survive_a_reboot(void) {
  security_lock_note_write_refused(BlobDBIdPins);

  prv_simulate_reboot();

  cl_assert_equal_i(0, security_lock_take_refused_dbs());
}

//! Locking is not a transition out of the locked state, so it reports nothing.
void test_security_lock__locking_asks_for_nothing(void) {
  cl_assert_equal_i(S_SUCCESS, security_lock_set_pin(PIN, strlen(PIN)));
  security_lock_note_write_refused(BlobDBIdPins);

  cl_assert_equal_i(S_SUCCESS, security_lock_set_state(SecurityLockStateLocked));

  cl_assert_equal_i(0, s_resync_reports);
}
