/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

//! Tests for the disconnect countdown: when it arms, when it does not, and what
//! happens once the watch has taken its own radio down.
//!
//! Everything the endpoint drives is faked. The subject is which countdowns get
//! armed and which timers get run, not what any of them go on to do.

#include "clar.h"

#include <string.h>

#include "kernel/events.h"
#include "pbl/services/regular_timer.h"
#include "pbl/services/security_lock.h"
#include "pbl/services/security_lock_endpoint.h"
#include "pbl/services/security_lock_shred.h"

// Stubs
////////////////////////////////////
#include "stubs_logging.h"
#include "stubs_passert.h"
#include "stubs_pebble_tasks.h"
#include "stubs_print.h"
#include "stubs_serial.h"

// Fakes
////////////////////////////////////

//! Stands in for the settings-backed service, so the endpoint's decisions can
//! be driven directly. The real record store is covered by test_security_lock.
static SecurityLockState s_state;
static bool s_blackout;
static time_t s_lock_deadline;
static time_t s_shred_deadline;
static uint32_t s_lock_delay_s = 60;
static uint32_t s_shred_delay_s = 600;
static time_t s_now = 1000;
static bool s_rolled_back;

static int s_blackouts;
static int s_locks_engaged;
static int s_shreds;

//! The registered regular timer, or NULL when none is running.
static RegularTimerInfo *s_timer;

SecurityLockState security_lock_get_state(void) {
  return s_state;
}

bool security_lock_is_locked(void) {
  return s_state == SecurityLockStateLocked;
}

bool security_lock_is_radio_blackout(void) {
  return s_blackout;
}

void security_lock_radio_blackout_engage(void) {
  s_blackouts++;
  s_blackout = true;
}

uint32_t security_lock_get_lock_delay_s(void) {
  return s_lock_delay_s;
}

uint32_t security_lock_get_shred_delay_s(void) {
  return s_shred_delay_s;
}

time_t security_lock_get_lock_deadline(void) {
  return s_lock_deadline;
}

time_t security_lock_get_shred_deadline(void) {
  return s_shred_deadline;
}

status_t security_lock_set_deadlines(time_t lock_deadline, time_t shred_deadline) {
  s_lock_deadline = lock_deadline;
  s_shred_deadline = shred_deadline;
  return S_SUCCESS;
}

status_t security_lock_clear_deadlines(void) {
  return security_lock_set_deadlines(0, 0);
}

bool security_lock_lock_deadline_expired(time_t now) {
  return (s_lock_deadline != 0) && (now >= s_lock_deadline);
}

bool security_lock_shred_deadline_expired(time_t now) {
  return (s_shred_deadline != 0) && (now >= s_shred_deadline);
}

bool security_lock_note_time(time_t now) {
  return s_rolled_back;
}

status_t security_lock_set_delays(uint32_t lock_delay_s, uint32_t shred_delay_s) {
  s_lock_delay_s = lock_delay_s;
  s_shred_delay_s = shred_delay_s;
  return S_SUCCESS;
}

uint32_t security_lock_shred(SecurityShredReason reason) {
  s_shreds++;
  return 0;
}

void security_lock_engage(SecurityShredReason reason) {
  s_locks_engaged++;
  s_state = SecurityLockStateLocked;
}

void security_lock_engage_lock_only(SecurityShredReason reason) {
  s_locks_engaged++;
  s_state = SecurityLockStateLocked;
}

time_t rtc_get_time(void) {
  return s_now;
}

//! Run inline. Everything the endpoint defers is deferred only because of the
//! task it must land on, and the tests care that it happened at all.
typedef void (*CallbackEventCallback)(void *data);
void launcher_task_add_callback(CallbackEventCallback cb, void *data) {
  cb(data);
}

bool system_task_add_callback(CallbackEventCallback cb, void *data) {
  cb(data);
  return true;
}

void regular_timer_add_multiminute_callback(RegularTimerInfo *cb, uint16_t minutes) {
  s_timer = cb;
}

bool regular_timer_remove_callback(RegularTimerInfo *cb) {
  s_timer = NULL;
  return true;
}

//! Whether a phone is attached. The whole point of the deferred resync is what
//! happens when it is not, so this is driven directly.
static bool s_session_up;

typedef struct CommSession CommSession;
CommSession *comm_session_get_system_session(void) {
  return s_session_up ? (CommSession *)1 : NULL;
}

//! Every message the endpoint put on the wire. Only the last one is inspected;
//! the count is what proves a queued request is not sent twice.
static int s_msgs_sent;
static uint8_t s_last_msg[16];
static size_t s_last_msg_len;

void comm_session_send_data(CommSession *session, uint16_t endpoint_id, const uint8_t *data,
                            size_t length, uint32_t timeout_ms) {
  cl_assert(length <= sizeof(s_last_msg));
  memcpy(s_last_msg, data, length);
  s_last_msg_len = length;
  s_msgs_sent++;
}

// Helpers
////////////////////////////////////

static void prv_session_event(bool is_open) {
  const PebbleCommSessionEvent event = {.is_open = is_open, .is_system = true};
  security_lock_handle_comm_session_event(&event);
}

//! Drive one tick of the periodic deadline check.
static void prv_tick(void) {
  cl_assert(s_timer != NULL);
  s_timer->cb(s_timer->cb_data);
}

static bool prv_timer_running(void) {
  return s_timer != NULL;
}

//! SHRED_COMPLETE: command, reason, then the bitmap big-endian.
#define CMD_SHRED_COMPLETE 0x84

static uint32_t prv_last_resync_bitmap(void) {
  cl_assert_equal_i(6, (int)s_last_msg_len);
  cl_assert_equal_i(CMD_SHRED_COMPLETE, s_last_msg[0]);
  return ((uint32_t)s_last_msg[2] << 24) | ((uint32_t)s_last_msg[3] << 16) |
         ((uint32_t)s_last_msg[4] << 8) | (uint32_t)s_last_msg[5];
}

static uint8_t prv_last_resync_reason(void) {
  cl_assert_equal_i(6, (int)s_last_msg_len);
  cl_assert_equal_i(CMD_SHRED_COMPLETE, s_last_msg[0]);
  return s_last_msg[1];
}

void test_security_lock_endpoint__initialize(void) {
  s_state = SecurityLockStateArmed;
  s_blackout = false;
  s_lock_deadline = 0;
  s_shred_deadline = 0;
  s_lock_delay_s = 60;
  s_shred_delay_s = 600;
  s_now = 1000;
  s_rolled_back = false;
  s_blackouts = 0;
  s_locks_engaged = 0;
  s_shreds = 0;
  s_timer = NULL;

  // endpoint.c tracks its timer and any queued resync request in statics, and
  // clar runs every test in one process, so the module needs resetting too. A
  // reconnect is how it retires the timer and flushes the queue, which makes
  // this its own reset path rather than a back door.
  s_session_up = true;
  prv_session_event(true);
  s_timer = NULL;
  s_lock_deadline = 0;
  s_shred_deadline = 0;
  s_msgs_sent = 0;
  s_last_msg_len = 0;
}

void test_security_lock_endpoint__cleanup(void) {}

// The ordinary countdown
////////////////////////////////////

void test_security_lock_endpoint__losing_the_phone_arms_both_deadlines(void) {
  prv_session_event(false);

  cl_assert_equal_i(s_now + 60, s_lock_deadline);
  cl_assert_equal_i(s_now + 600, s_shred_deadline);
  cl_assert(prv_timer_running());
}

void test_security_lock_endpoint__reconnecting_retires_the_countdown(void) {
  prv_session_event(false);
  prv_session_event(true);

  cl_assert_equal_i(0, s_lock_deadline);
  cl_assert_equal_i(0, s_shred_deadline);
  cl_assert(!prv_timer_running());
}

void test_security_lock_endpoint__the_lock_deadline_locks(void) {
  prv_session_event(false);
  s_now += 60;
  prv_tick();

  cl_assert_equal_i(1, s_locks_engaged);
  cl_assert_equal_i(0, s_shreds);
}

void test_security_lock_endpoint__the_shred_deadline_shreds(void) {
  prv_session_event(false);
  s_now += 600;
  prv_tick();

  cl_assert_equal_i(1, s_shreds);
  cl_assert(!prv_timer_running());
}

// Hazard: the blackout closing the session
////////////////////////////////////

//! Taking the radio down tears the session down with it, which reaches the same
//! handler as the phone walking away. Arming a fresh countdown off that would
//! make the blackout schedule a wipe as a side effect of its own cleanup.
void test_security_lock_endpoint__our_own_disconnect_arms_nothing(void) {
  s_state = SecurityLockStateLocked;
  s_blackout = true;

  prv_session_event(false);

  cl_assert_equal_i(0, s_lock_deadline);
  cl_assert_equal_i(0, s_shred_deadline);
  cl_assert(!prv_timer_running());
}

//! Locked with the radio down is terminal: nothing can arrive, so a countdown
//! left over from before the wipe has nothing left to count down. It retires
//! itself rather than ticking for the duration of the lock.
void test_security_lock_endpoint__going_dark_retires_a_running_countdown(void) {
  prv_session_event(false);
  cl_assert(prv_timer_running());

  // The wipe that goes with, say, three wrong PINs, on a watch that was already
  // counting down.
  s_state = SecurityLockStateLocked;
  s_blackout = true;

  prv_tick();

  cl_assert_equal_i(0, s_shred_deadline);
  cl_assert(!prv_timer_running());
}

//! The deadline it retires must not fire on the way out.
void test_security_lock_endpoint__a_dark_watch_does_not_shred_on_a_stale_deadline(void) {
  prv_session_event(false);
  s_state = SecurityLockStateLocked;
  s_blackout = true;
  s_now += 600;

  prv_tick();

  cl_assert_equal_i(0, s_shreds);
}

//! A clock rollback is the one tamper that outruns a deadline. With the radio
//! down there is no deadline left to outrun.
void test_security_lock_endpoint__a_dark_watch_ignores_a_rollback(void) {
  prv_session_event(false);
  s_state = SecurityLockStateLocked;
  s_blackout = true;
  s_rolled_back = true;

  prv_tick();

  cl_assert_equal_i(0, s_shreds);
}

//! The guard is the blackout, not the locked state: a watch locked by the lock
//! deadline has not been wiped and still has its radio, and it needs the shred
//! countdown to keep running.
void test_security_lock_endpoint__a_locked_watch_with_a_radio_still_counts_down(void) {
  s_state = SecurityLockStateLocked;

  prv_session_event(false);

  cl_assert_equal_i(0, s_lock_deadline);
  cl_assert_equal_i(s_now + 600, s_shred_deadline);
  cl_assert(prv_timer_running());
}

// Boot
////////////////////////////////////

//! The boot wipe locks the watch before bt_ctl exists, so the blackout it owes
//! is taken here instead.
void test_security_lock_endpoint__init_takes_the_radio_down_when_locked(void) {
  s_state = SecurityLockStateLocked;

  security_lock_endpoint_init();

  cl_assert_equal_i(1, s_blackouts);
}

//! Re-asserted rather than re-decided: airplane mode is persisted, so a
//! blackout held across the reboot is normally already in force.
void test_security_lock_endpoint__init_re_asserts_a_held_blackout(void) {
  s_state = SecurityLockStateLocked;
  s_blackout = true;

  security_lock_endpoint_init();

  cl_assert_equal_i(1, s_blackouts);
  cl_assert(s_blackout);
}

void test_security_lock_endpoint__init_leaves_an_unlocked_watch_on_the_air(void) {
  s_state = SecurityLockStateArmed;

  security_lock_endpoint_init();

  cl_assert_equal_i(0, s_blackouts);
}

//! A watch that was locked and offline across a reboot needs the countdown
//! running again without waiting for another disconnect event.
void test_security_lock_endpoint__init_resumes_a_pending_countdown(void) {
  s_shred_deadline = 5000;

  security_lock_endpoint_init();

  cl_assert(prv_timer_running());
}

// Asking the phone to resend
////////////////////////////////////

void test_security_lock_endpoint__a_report_goes_out_on_a_live_session(void) {
  security_lock_endpoint_report_resync_needed(SecurityShredReasonWritesRefused,
                                              SECURITY_SHRED_DB_BIT(BlobDBIdPins));

  cl_assert_equal_i(1, s_msgs_sent);
  cl_assert_equal_i(SECURITY_SHRED_DB_BIT(BlobDBIdPins), prv_last_resync_bitmap());
  cl_assert_equal_i(SecurityShredReasonWritesRefused, prv_last_resync_reason());
}

//! The hazard the whole thing turns on. Both cases that need to ask the phone
//! for a resend are cases where the phone is not there: a wipe caused by it
//! walking away, and an unlock that has only just given the radio back. Sending
//! into a session that does not exist yet would drop the request silently.
void test_security_lock_endpoint__a_report_with_no_session_waits_for_one(void) {
  s_session_up = false;

  security_lock_endpoint_report_resync_needed(SecurityShredReasonWritesRefused,
                                              SECURITY_SHRED_DB_BIT(BlobDBIdPins));
  cl_assert_equal_i(0, s_msgs_sent);

  s_session_up = true;
  prv_session_event(true);

  cl_assert_equal_i(1, s_msgs_sent);
  cl_assert_equal_i(SECURITY_SHRED_DB_BIT(BlobDBIdPins), prv_last_resync_bitmap());
}

//! Once told, the phone is not told again on every reconnect for the rest of
//! time -- each repeat would be another full calendar re-push.
void test_security_lock_endpoint__a_queued_report_is_sent_once(void) {
  s_session_up = false;
  security_lock_endpoint_report_resync_needed(SecurityShredReasonWritesRefused,
                                              SECURITY_SHRED_DB_BIT(BlobDBIdPins));

  s_session_up = true;
  prv_session_event(true);
  prv_session_event(false);
  prv_session_event(true);

  cl_assert_equal_i(1, s_msgs_sent);
}

//! Reports made while the phone is away merge rather than queue up, so a watch
//! that was offline for a while still costs one message.
void test_security_lock_endpoint__reports_made_while_offline_merge(void) {
  s_session_up = false;
  security_lock_endpoint_report_resync_needed(SecurityShredReasonWritesRefused,
                                              SECURITY_SHRED_DB_BIT(BlobDBIdPins));
  security_lock_endpoint_report_resync_needed(SecurityShredReasonDisconnectTimeout,
                                              SECURITY_SHRED_DB_BIT(BlobDBIdWeather));

  s_session_up = true;
  prv_session_event(true);

  cl_assert_equal_i(1, s_msgs_sent);
  cl_assert_equal_i(SECURITY_SHRED_DB_BIT(BlobDBIdPins) | SECURITY_SHRED_DB_BIT(BlobDBIdWeather),
                    prv_last_resync_bitmap());
  // The most recent cause, which is the one that lost the most.
  cl_assert_equal_i(SecurityShredReasonDisconnectTimeout, prv_last_resync_reason());
}

//! Nothing lost, nothing asked for. Every unlock reaches this, so an empty
//! report must be silent rather than a resync of everything.
void test_security_lock_endpoint__an_empty_report_sends_nothing(void) {
  security_lock_endpoint_report_resync_needed(SecurityShredReasonWritesRefused, 0);

  cl_assert_equal_i(0, s_msgs_sent);

  // And nothing is left queued for the next reconnect either.
  prv_session_event(true);
  cl_assert_equal_i(0, s_msgs_sent);
}

void test_security_lock_endpoint__reconnecting_with_nothing_queued_sends_nothing(void) {
  prv_session_event(false);
  prv_session_event(true);

  cl_assert_equal_i(0, s_msgs_sent);
}
