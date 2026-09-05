/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

//! Tests for the endpoint: what the phone can ask for, and the disconnect
//! countdown -- when it arms, when it does not, and what happens once the watch
//! has taken its own radio down.
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
static SecurityCountdownSource s_countdown_source;
static uint8_t s_pin_len = 4;
static uint32_t s_lock_delay_s = 60;
static uint32_t s_shred_delay_s = 600;
static time_t s_now = 1000;
static bool s_rolled_back;

static int s_blackouts;
static int s_locks_engaged;
static int s_shreds;
static SecurityShredReason s_last_shred_reason;

//! The command byte of every message the endpoint put on the wire, in order. A
//! refusal is as much about what was not sent as about what was.
//!
//! Up here rather than beside the session fake because the shred fake below
//! samples the count: on the erase path the ack has to precede the wipe, and
//! "both happened" is not the same claim.
#define MAX_SENT 8
static uint8_t s_sent_cmds[MAX_SENT];
static int s_sent_count;

//! How many messages had gone out by the time the shred started.
static int s_sent_at_shred;

//! The registered regular timer, or NULL when none is running.
static RegularTimerInfo *s_timer;

SecurityLockState security_lock_get_state(void) {
  return s_state;
}

uint8_t security_lock_get_pin_len(void) {
  return s_pin_len;
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

//! Nothing in endpoint.c calls this today, which is the claim under test: the
//! delays are the watch's own and the retired CONFIGURE must not reach them.
//! Present as a fake rather than left undefined so that claim can be asserted
//! -- without it the delay statics are ones only this file ever writes, and no
//! amount of protocol traffic could disturb them however wrong the parser got.
static int s_set_delays_calls;

status_t security_lock_set_delays(uint32_t lock_delay_s, uint32_t shred_delay_s) {
  s_set_delays_calls++;
  s_lock_delay_s = lock_delay_s;
  s_shred_delay_s = shred_delay_s;
  return S_SUCCESS;
}

time_t security_lock_get_lock_deadline(void) {
  return s_lock_deadline;
}

time_t security_lock_get_shred_deadline(void) {
  return s_shred_deadline;
}

//! Mirrors the store's one invariant: a source cannot outlive the countdown it
//! describes. A fake that kept a stale Manual around would hide exactly the bug
//! the guards below are written against.
status_t security_lock_set_deadlines(time_t lock_deadline, time_t shred_deadline,
                                     SecurityCountdownSource source) {
  s_lock_deadline = lock_deadline;
  s_shred_deadline = shred_deadline;
  s_countdown_source =
      ((lock_deadline == 0) && (shred_deadline == 0)) ? SecurityCountdownNone : source;
  return S_SUCCESS;
}

status_t security_lock_clear_deadlines(void) {
  return security_lock_set_deadlines(0, 0, SecurityCountdownNone);
}

SecurityCountdownSource security_lock_get_countdown_source(void) {
  return s_countdown_source;
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

uint32_t security_lock_shred(SecurityShredReason reason) {
  s_shreds++;
  s_last_shred_reason = reason;
  s_sent_at_shred = s_sent_count;
  return 0;
}

//! Stands in for lock.c, including its refusals -- the endpoint decides what to
//! tell the phone from whether the watch actually ended up locked, so a fake
//! that always locked would hide the case this exists for.
static bool prv_engage_refused(void) {
  return (s_state == SecurityLockStateDisabled) || (s_pin_len < SECURITY_LOCK_PIN_MIN_LEN);
}

void security_lock_engage(SecurityShredReason reason) {
  if (prv_engage_refused()) {
    return;
  }
  s_locks_engaged++;
  s_state = SecurityLockStateLocked;
}

//! The same refusals. It shares one funnel with the other two, so a fake that
//! locked unconditionally would let a LOCK_ERASE that was refused go on to
//! erase -- the exact thing prv_lock_erase_callback checks for.
void security_lock_engage_lock_only(SecurityShredReason reason) {
  if (prv_engage_refused()) {
    return;
  }
  s_locks_engaged++;
  s_state = SecurityLockStateLocked;
}

//! Same refusals, then the arming half -- which is not faked, because it is the
//! thing under test. lock.c arms only once the lock has taken, so a refusal
//! here must leave no countdown behind either.
void security_lock_engage_with_countdown(SecurityShredReason reason) {
  if (prv_engage_refused()) {
    return;
  }
  s_locks_engaged++;
  s_state = SecurityLockStateLocked;
  security_lock_endpoint_arm_manual_countdown();
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
  if (s_sent_count < MAX_SENT) {
    s_sent_cmds[s_sent_count++] = data[0];
  }
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
#define CMD_LOCK_ACK 0x82
#define CMD_STATE_CHANGED 0x85
//! STATUS_RESPONSE: command, state, pin_configured, then the remaining erase
//! countdown big-endian.
#define CMD_STATUS_RESPONSE 0x83
#define STATUS_RESPONSE_LEN 7

//! Inbound commands, as the phone spells them.
#define CMD_LOCK 0x02
#define CMD_STATUS_REQUEST 0x03
#define CMD_LOCK_ERASE 0x04

//! The retired CONFIGURE, still spoken by a phone built against the old
//! protocol: command, enabled, then both delays big-endian.
#define CMD_RETIRED_CONFIGURE 0x01

static void prv_phone_lock(uint8_t reason) {
  const uint8_t msg[] = {CMD_LOCK, reason};
  security_lock_protocol_msg_callback(NULL, msg, sizeof(msg));
}

static void prv_phone_lock_erase(uint8_t reason) {
  const uint8_t msg[] = {CMD_LOCK_ERASE, reason};
  security_lock_protocol_msg_callback(NULL, msg, sizeof(msg));
}

static void prv_phone_retired_configure(bool enabled, uint16_t lock_delay_s,
                                        uint16_t shred_delay_s) {
  const uint8_t msg[] = {CMD_RETIRED_CONFIGURE,         (uint8_t)(enabled ? 1 : 0),
                         (uint8_t)(lock_delay_s >> 8),  (uint8_t)lock_delay_s,
                         (uint8_t)(shred_delay_s >> 8), (uint8_t)shred_delay_s};
  security_lock_protocol_msg_callback(NULL, msg, sizeof(msg));
}

static void prv_phone_status_request(void) {
  const uint8_t msg[] = {CMD_STATUS_REQUEST};
  security_lock_protocol_msg_callback(NULL, msg, sizeof(msg));
}

//! Every message the endpoint sent, so a test can say a LOCK_ACK never went out
//! rather than only that the last message was something else.
static int prv_count_sent(uint8_t cmd) {
  int count = 0;
  for (int i = 0; i < s_sent_count; ++i) {
    if (s_sent_cmds[i] == cmd) {
      count++;
    }
  }
  return count;
}

//! How many of `cmd` went out among the first `limit` messages. Ordering, not
//! just occurrence.
static int prv_count_sent_before(uint8_t cmd, int limit) {
  int count = 0;
  for (int i = 0; (i < s_sent_count) && (i < limit); ++i) {
    if (s_sent_cmds[i] == cmd) {
      count++;
    }
  }
  return count;
}

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

//! The tail of a STATUS_RESPONSE: everything past the state and the PIN flag.
static uint32_t prv_last_status_remaining(void) {
  cl_assert_equal_i(STATUS_RESPONSE_LEN, (int)s_last_msg_len);
  cl_assert_equal_i(CMD_STATUS_RESPONSE, s_last_msg[0]);
  return ((uint32_t)s_last_msg[3] << 24) | ((uint32_t)s_last_msg[4] << 16) |
         ((uint32_t)s_last_msg[5] << 8) | (uint32_t)s_last_msg[6];
}

void test_security_lock_endpoint__initialize(void) {
  s_state = SecurityLockStateArmed;
  s_blackout = false;
  s_lock_deadline = 0;
  s_shred_deadline = 0;
  s_countdown_source = SecurityCountdownNone;
  s_pin_len = 4;
  s_lock_delay_s = 60;
  s_shred_delay_s = 600;
  s_now = 1000;
  s_rolled_back = false;
  s_blackouts = 0;
  s_locks_engaged = 0;
  s_shreds = 0;
  s_last_shred_reason = SecurityShredReasonUnknown;
  s_sent_at_shred = 0;
  s_set_delays_calls = 0;
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
  s_countdown_source = SecurityCountdownNone;
  s_msgs_sent = 0;
  s_last_msg_len = 0;
  s_sent_count = 0;
}

void test_security_lock_endpoint__cleanup(void) {}

// What the phone can ask for
////////////////////////////////////

void test_security_lock_endpoint__a_phone_lock_locks_and_is_acked(void) {
  prv_phone_lock(SecurityShredReasonPhoneLockdown);

  cl_assert_equal_i(1, s_locks_engaged);
  cl_assert_equal_i(1, prv_count_sent(CMD_LOCK_ACK));
  cl_assert_equal_i(SecurityShredReasonPhoneLockdown, s_last_msg[1]);
}

//! LOCK arrives over the air, from a phone that may be the thing that was
//! taken. Erasing on it outright is an unconditional remote wipe available to
//! anything that can speak the protocol, so it gets the countdown the chord
//! gets: the watch is still on the user's wrist and the PIN can stop it.
void test_security_lock_endpoint__a_phone_lock_arms_the_countdown_rather_than_erasing(void) {
  prv_phone_lock(SecurityShredReasonPhoneLockdown);

  cl_assert_equal_i(SecurityLockStateLocked, s_state);
  cl_assert_equal_i(0, s_shreds);
  cl_assert_equal_i(s_now + 600, s_shred_deadline);
  cl_assert_equal_i(SecurityCountdownManual, s_countdown_source);
}

//! And the countdown it arms is the user's, not the phone's: the same phone
//! reconnecting cannot call it off. Otherwise LOCK would be undone by the very
//! next reconnect, which is a thing the phone does by itself.
void test_security_lock_endpoint__the_phone_cannot_undo_its_own_lock_by_reconnecting(void) {
  prv_phone_lock(SecurityShredReasonPhoneLockdown);
  const time_t armed_at = s_shred_deadline;

  prv_session_event(false);
  prv_session_event(true);

  cl_assert_equal_i(armed_at, s_shred_deadline);
  cl_assert_equal_i(SecurityLockStateLocked, s_state);
}

//! The ack still means the lock took. What it no longer means is that the
//! content is gone -- SHRED_COMPLETE says that, when and if the erase runs.
void test_security_lock_endpoint__a_phone_lock_is_acked_before_anything_is_erased(void) {
  prv_phone_lock(SecurityShredReasonPhoneLockdown);

  cl_assert_equal_i(1, prv_count_sent(CMD_LOCK_ACK));
  cl_assert_equal_i(0, s_shreds);
}

//! A phone LOCK on a watch with the timed erase off locks and erases nothing,
//! the same as every other manual trigger. Never means never, whoever asks.
void test_security_lock_endpoint__a_phone_lock_with_never_only_locks(void) {
  s_shred_delay_s = SECURITY_LOCK_SHRED_DELAY_NEVER;

  prv_phone_lock(SecurityShredReasonPhoneLockdown);

  cl_assert_equal_i(SecurityLockStateLocked, s_state);
  cl_assert_equal_i(0, s_shreds);
  cl_assert_equal_i(0, s_shred_deadline);
  cl_assert_equal_i(1, prv_count_sent(CMD_LOCK_ACK));
}

//! A refused lock leaves no countdown behind. Arming one for a lock that never
//! took would erase a watch that was never locked.
void test_security_lock_endpoint__a_refused_lock_arms_no_countdown(void) {
  s_state = SecurityLockStateArmed;
  s_pin_len = 0;

  prv_phone_lock(SecurityShredReasonPhoneLockdown);

  cl_assert_equal_i(0, s_shred_deadline);
  cl_assert_equal_i(SecurityCountdownNone, s_countdown_source);
  cl_assert(!prv_timer_running());
}

//! The defect this whole switch exists to dissolve. A watch with the feature
//! off has nothing to protect and no PIN to open it again, so a phone LOCK must
//! erase nothing -- and, just as importantly, must not come back saying it did.
//! An ack is what makes the phone stop asking and treat its own copy as the
//! only one left.
void test_security_lock_endpoint__a_phone_lock_with_the_feature_off_does_nothing(void) {
  s_state = SecurityLockStateDisabled;

  prv_phone_lock(SecurityShredReasonPhoneLockdown);

  cl_assert_equal_i(0, s_locks_engaged);
  cl_assert_equal_i(0, s_shreds);
  cl_assert_equal_i(SecurityLockStateDisabled, s_state);
  cl_assert_equal_i(0, prv_count_sent(CMD_LOCK_ACK));
}

//! Silence would be indistinguishable from a watch that had gone away, so the
//! refusal says which state refused it. STATE_CHANGED rather than a new failure
//! code: the phone already parses it, and Disabled is the whole reason.
void test_security_lock_endpoint__a_refused_lock_reports_the_state_instead(void) {
  s_state = SecurityLockStateDisabled;

  prv_phone_lock(SecurityShredReasonPhoneLockdown);

  cl_assert_equal_i(1, prv_count_sent(CMD_STATE_CHANGED));
  cl_assert_equal_i(2, (int)s_last_msg_len);
  cl_assert_equal_i(SecurityLockStateDisabled, s_last_msg[1]);
}

//! The ack is keyed on the watch actually being locked, not on having asked, so
//! every refusal inside engage() reaches the phone as one -- an unusable stored
//! PIN length among them, which no control produces but a corrupt record does.
void test_security_lock_endpoint__a_lock_that_does_not_take_is_not_acked(void) {
  // Past the early refusal -- the feature is on -- but engage() declines,
  // because there is no PIN the lock screen could prompt for.
  s_state = SecurityLockStateArmed;
  s_pin_len = 0;

  prv_phone_lock(SecurityShredReasonPhoneLockdown);

  cl_assert_equal_i(0, s_locks_engaged);
  cl_assert_equal_i(0, prv_count_sent(CMD_LOCK_ACK));
  cl_assert_equal_i(1, prv_count_sent(CMD_STATE_CHANGED));
}

// What the phone can ask for: LOCK_ERASE
////////////////////////////////////

//! The other half of the pair. LOCK defers to Erase After; this one is how a
//! phone says the content goes now, and it is what the lockdown response sends
//! by default -- the case it exists for is the one where waiting is the thing
//! that costs.
void test_security_lock_endpoint__a_phone_lock_erase_locks_and_erases(void) {
  prv_phone_lock_erase(SecurityShredReasonPhoneLockdown);

  cl_assert_equal_i(1, s_locks_engaged);
  cl_assert_equal_i(SecurityLockStateLocked, s_state);
  cl_assert_equal_i(1, s_shreds);
  cl_assert_equal_i(SecurityShredReasonPhoneLockdown, s_last_shred_reason);
}

//! The reason byte comes off the wire, and only PhoneLockdown may be asked for.
//! DuressPin is the one that matters: it suppresses the radio blackout and the
//! resend request, so a phone that could name it would erase the watch and go
//! on believing it was in sync -- content gone, and nobody aware of it.
void test_security_lock_endpoint__a_phone_cannot_name_an_internal_reason(void) {
  prv_phone_lock_erase(SecurityShredReasonDuressPin);

  cl_assert_equal_i(1, s_shreds);
  cl_assert_equal_i(SecurityShredReasonPhoneLockdown, s_last_shred_reason);
}

//! Every other internal reason, and a value the enum does not define at all.
void test_security_lock_endpoint__every_reason_off_the_wire_becomes_phone_lockdown(void) {
  const uint8_t reasons[] = {SecurityShredReasonUnknown,      SecurityShredReasonManualPanic,
                             SecurityShredReasonDisconnectTimeout,
                             SecurityShredReasonRebootWhileLocked,
                             SecurityShredReasonPinAttemptsExhausted,
                             SecurityShredReasonClockRollback, SecurityShredReasonDuressPin,
                             SecurityShredReasonWritesRefused, 0xFF};

  for (size_t i = 0; i < sizeof(reasons) / sizeof(reasons[0]); ++i) {
    // Back to a connected, armed watch; each pass must stand on its own.
    test_security_lock_endpoint__initialize();
    prv_phone_lock_erase(reasons[i]);
    cl_assert_equal_i(1, s_shreds);
    cl_assert_equal_i(SecurityShredReasonPhoneLockdown, s_last_shred_reason);
  }
}

//! The whole reason the two are separate calls rather than one engage(). The
//! erase blacks the radio out, so an ack sent after it would have no session to
//! go out on and the phone would burn its retry window re-asking a watch that
//! had already erased itself.
void test_security_lock_endpoint__a_phone_lock_erase_acks_before_it_erases(void) {
  prv_phone_lock_erase(SecurityShredReasonPhoneLockdown);

  cl_assert_equal_i(1, s_shreds);
  cl_assert_equal_i(1, prv_count_sent_before(CMD_LOCK_ACK, s_sent_at_shred));
}

//! Erase After governs the countdown, not this. A phone that asked for the
//! content to go now is not asking for a timer, so Never does not veto it --
//! the setting says when an unattended watch gives up, and this watch was not
//! unattended, it was told.
void test_security_lock_endpoint__a_phone_lock_erase_ignores_erase_after(void) {
  s_shred_delay_s = SECURITY_LOCK_SHRED_DELAY_NEVER;

  prv_phone_lock_erase(SecurityShredReasonPhoneLockdown);

  cl_assert_equal_i(SecurityLockStateLocked, s_state);
  cl_assert_equal_i(1, s_shreds);
  cl_assert_equal_i(0, s_shred_deadline);
}

//! It locks first, so there is no countdown left to run afterwards. Arming one
//! would leave a deadline pointing at content that no longer exists.
void test_security_lock_endpoint__a_phone_lock_erase_arms_no_countdown(void) {
  prv_phone_lock_erase(SecurityShredReasonPhoneLockdown);

  cl_assert_equal_i(0, s_shred_deadline);
  cl_assert_equal_i(0, s_lock_deadline);
  cl_assert_equal_i(SecurityCountdownNone, s_countdown_source);
}

//! The master switch refuses this exactly as it refuses LOCK. A watch with the
//! feature off has no PIN to reopen it, so erasing would destroy content and
//! leave the watch wide open -- the defect the switch exists to dissolve.
void test_security_lock_endpoint__a_phone_lock_erase_with_the_feature_off_does_nothing(void) {
  s_state = SecurityLockStateDisabled;

  prv_phone_lock_erase(SecurityShredReasonPhoneLockdown);

  cl_assert_equal_i(0, s_locks_engaged);
  cl_assert_equal_i(0, s_shreds);
  cl_assert_equal_i(SecurityLockStateDisabled, s_state);
  cl_assert_equal_i(0, prv_count_sent(CMD_LOCK_ACK));
  cl_assert_equal_i(1, prv_count_sent(CMD_STATE_CHANGED));
}

//! And a lock that fails inside the funnel stops the erase with it. Wiping a
//! watch that never locked is the one outcome worse than doing nothing: the
//! content goes and there is no lock screen in front of what is left.
void test_security_lock_endpoint__a_lock_erase_that_does_not_take_erases_nothing(void) {
  // Past the early refusal -- the feature is on -- but the funnel declines,
  // because there is no PIN the lock screen could prompt for.
  s_state = SecurityLockStateArmed;
  s_pin_len = 0;

  prv_phone_lock_erase(SecurityShredReasonPhoneLockdown);

  cl_assert_equal_i(0, s_locks_engaged);
  cl_assert_equal_i(0, s_shreds);
  cl_assert_equal_i(0, prv_count_sent(CMD_LOCK_ACK));
  cl_assert_equal_i(1, prv_count_sent(CMD_STATE_CHANGED));
}

//! A short LOCK_ERASE is dropped rather than read past its end, the same as a
//! short LOCK. The reason byte is what makes it two bytes.
void test_security_lock_endpoint__a_short_lock_erase_is_ignored(void) {
  const uint8_t msg[] = {CMD_LOCK_ERASE};
  security_lock_protocol_msg_callback(NULL, msg, sizeof(msg));

  cl_assert_equal_i(0, s_locks_engaged);
  cl_assert_equal_i(0, s_shreds);
  cl_assert_equal_i(0, s_msgs_sent);
}

// The retired CONFIGURE
////////////////////////////////////

//! The master switch and both delays are the watch's own, so the command that
//! set them is gone. A phone built against the old protocol still sends it on
//! every connection, and every one of those must change nothing -- otherwise
//! reconnecting quietly overwrites whatever the user chose on the wrist.
void test_security_lock_endpoint__the_retired_configure_cannot_turn_the_feature_off(void) {
  prv_phone_retired_configure(false, 0, 0);

  cl_assert_equal_i(SecurityLockStateArmed, s_state);
  cl_assert_equal_i(0, s_msgs_sent);
}

//! The direction that motivated the removal: a companion app that sends
//! enabled=1 unconditionally must not re-arm a watch the user turned off.
void test_security_lock_endpoint__the_retired_configure_cannot_turn_the_feature_on(void) {
  s_state = SecurityLockStateDisabled;

  prv_phone_retired_configure(true, 0, 0);

  cl_assert_equal_i(SecurityLockStateDisabled, s_state);
  cl_assert_equal_i(0, s_msgs_sent);
}

//! Nor can it reach the delays, which is what made "never erase" inexpressible
//! over the wire in the first place. The delays are only reachable through
//! security_lock_set_delays(), so the claim is that it is never called -- and
//! the fake above is what makes that a thing this test can observe.
void test_security_lock_endpoint__the_retired_configure_cannot_reach_the_delays(void) {
  prv_phone_retired_configure(true, 30, 90);

  cl_assert_equal_i(0, s_set_delays_calls);
  cl_assert_equal_i(60, (int)s_lock_delay_s);
  cl_assert_equal_i(600, (int)s_shred_delay_s);
}

//! Nothing else the phone can send reaches them either. CONFIGURE is the
//! command that used to, but a parser that mislaid a length could get there
//! from any of them.
void test_security_lock_endpoint__nothing_on_the_wire_reaches_the_delays(void) {
  prv_phone_lock(SecurityShredReasonPhoneLockdown);
  prv_phone_status_request();
  prv_phone_retired_configure(true, 30, 90);
  prv_session_event(false);
  prv_session_event(true);

  cl_assert_equal_i(0, s_set_delays_calls);
}

// Malformed traffic
////////////////////////////////////

//! A zero-length payload is dropped before the command byte is read. The
//! buffer still holds a command -- a length of zero on the wire does not empty
//! the receive buffer it points into -- so a parser that trusted the pointer
//! and not the length would act on a message the phone never sent.
void test_security_lock_endpoint__an_empty_message_is_dropped(void) {
  const uint8_t msg[] = {CMD_STATUS_REQUEST};
  security_lock_protocol_msg_callback(NULL, msg, 0);

  cl_assert_equal_i(0, s_msgs_sent);
  cl_assert_equal_i(0, s_locks_engaged);
  cl_assert_equal_i(0, s_shreds);
}

//! A short LOCK is dropped rather than read past its end, the same as a short
//! LOCK_ERASE. The reason byte is what makes it two bytes, and acting on one
//! that is not there would lock the watch for a reason read off the stack.
void test_security_lock_endpoint__a_short_lock_is_ignored(void) {
  const uint8_t msg[] = {CMD_LOCK};
  security_lock_protocol_msg_callback(NULL, msg, sizeof(msg));

  cl_assert_equal_i(0, s_locks_engaged);
  cl_assert_equal_i(0, s_shreds);
  cl_assert_equal_i(0, s_msgs_sent);
}

//! An unknown command is ignored rather than answered. Anything that can speak
//! the protocol can send one, so a reply would be a free liveness oracle.
void test_security_lock_endpoint__an_unknown_command_is_ignored(void) {
  const uint8_t msg[] = {0x7f, 0x01, 0x02};
  security_lock_protocol_msg_callback(NULL, msg, sizeof(msg));

  cl_assert_equal_i(0, s_locks_engaged);
  cl_assert_equal_i(0, s_shreds);
  cl_assert_equal_i(0, s_msgs_sent);
}

// STATUS, in full
////////////////////////////////////

//! The whole message, not just the two bytes the tests above read. A phone
//! parses this by offset, so a field that moved would be read as another one.
void test_security_lock_endpoint__status_reports_the_whole_message(void) {
  s_state = SecurityLockStateLocked;
  s_pin_len = 6;
  security_lock_set_deadlines(0, s_now + 300, SecurityCountdownManual);

  prv_phone_status_request();

  cl_assert_equal_i(1, s_msgs_sent);
  cl_assert_equal_i(STATUS_RESPONSE_LEN, (int)s_last_msg_len);
  cl_assert_equal_i(CMD_STATUS_RESPONSE, s_last_msg[0]);
  cl_assert_equal_i(SecurityLockStateLocked, s_last_msg[1]);
  cl_assert_equal_i(1, s_last_msg[2]);
  cl_assert_equal_i(300, (int)prv_last_status_remaining());
}

//! Nothing armed is nothing remaining, rather than the deadline itself -- 0 is
//! how "no countdown" is spelled everywhere else, and a phone told it had zero
//! seconds left would show a wipe that is not coming.
void test_security_lock_endpoint__status_reports_no_countdown_as_zero(void) {
  cl_assert_equal_i(0, (int)s_shred_deadline);

  prv_phone_status_request();

  cl_assert_equal_i(0, (int)prv_last_status_remaining());
}

//! The underflow guard. A deadline in the past is a countdown that has expired
//! but not yet been acted on -- the watch was asleep, or the tick has not come
//! round. The field is unsigned, so subtracting without the guard would send
//! the phone a countdown of some four billion seconds.
void test_security_lock_endpoint__status_does_not_underflow_a_passed_deadline(void) {
  security_lock_set_deadlines(0, s_now - 100, SecurityCountdownDisconnect);

  prv_phone_status_request();

  cl_assert_equal_i(0, (int)prv_last_status_remaining());
}

//! And the boundary between the two, where a deadline exactly now is already
//! passed rather than a countdown of zero that has yet to fire.
void test_security_lock_endpoint__status_reports_a_deadline_reached_now_as_zero(void) {
  security_lock_set_deadlines(0, s_now, SecurityCountdownDisconnect);

  prv_phone_status_request();

  cl_assert_equal_i(0, (int)prv_last_status_remaining());
}

//! It reports the erase countdown, not the lock one. They differ, and the erase
//! is the one with consequences the phone might want to surface.
void test_security_lock_endpoint__status_reports_the_erase_countdown(void) {
  prv_session_event(false);
  cl_assert_equal_i(s_now + 60, s_lock_deadline);

  prv_phone_status_request();

  cl_assert_equal_i(600, (int)prv_last_status_remaining());
}

//! A STATUS_REQUEST with bytes after it is still a STATUS_REQUEST: it carries
//! no payload, so trailing bytes are a longer phone's problem, not a reason to
//! stop answering.
void test_security_lock_endpoint__a_long_status_request_is_still_answered(void) {
  const uint8_t msg[] = {CMD_STATUS_REQUEST, 0xff, 0xff};
  security_lock_protocol_msg_callback(NULL, msg, sizeof(msg));

  cl_assert_equal_i(1, s_msgs_sent);
  cl_assert_equal_i(CMD_STATUS_RESPONSE, s_last_msg[0]);
}

//! Retiring it left no countdown behind either: an old phone's CONFIGURE is a
//! no-op in full, not one with a side effect on the disconnect deadlines.
void test_security_lock_endpoint__the_retired_configure_leaves_the_countdown_alone(void) {
  prv_session_event(false);
  const time_t lock_deadline = s_lock_deadline;
  const time_t shred_deadline = s_shred_deadline;
  cl_assert(shred_deadline != 0);

  prv_phone_retired_configure(false, 0, 0);

  cl_assert_equal_i((int)lock_deadline, (int)s_lock_deadline);
  cl_assert_equal_i((int)shred_deadline, (int)s_shred_deadline);
}

//! STATUS answers "is there a PIN" from the PIN, not from the state. A PIN
//! outlives the switch now, so the two are different questions.
void test_security_lock_endpoint__status_reports_a_pin_kept_across_the_switch(void) {
  s_state = SecurityLockStateDisabled;
  s_pin_len = 4;

  prv_phone_status_request();

  cl_assert_equal_i(SecurityLockStateDisabled, s_last_msg[1]);
  cl_assert_equal_i(1, s_last_msg[2]);
}

void test_security_lock_endpoint__status_reports_no_pin_when_there_is_none(void) {
  s_state = SecurityLockStateDisabled;
  s_pin_len = 0;

  prv_phone_status_request();

  cl_assert_equal_i(0, s_last_msg[2]);
}

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

//! Off means no countdown is ever armed, rather than one armed and then
//! declined at every tick. Nothing should be counting down on a watch that has
//! said it does not want this.
void test_security_lock_endpoint__losing_the_phone_arms_nothing_when_off(void) {
  s_state = SecurityLockStateDisabled;

  prv_session_event(false);

  cl_assert_equal_i(0, s_lock_deadline);
  cl_assert_equal_i(0, s_shred_deadline);
  cl_assert(!prv_timer_running());
}

//! And a deadline left in the record from before the switch was thrown does not
//! fire either: the tick refuses before it reads one.
void test_security_lock_endpoint__a_stale_deadline_does_not_fire_when_off(void) {
  prv_session_event(false);
  cl_assert(prv_timer_running());

  s_state = SecurityLockStateDisabled;
  s_now += 600;
  prv_tick();

  cl_assert_equal_i(0, s_shreds);
  cl_assert_equal_i(0, s_locks_engaged);
}

//! Nor does a rollback, which is the one tamper that outruns a deadline.
void test_security_lock_endpoint__a_rollback_is_ignored_when_off(void) {
  prv_session_event(false);

  s_state = SecurityLockStateDisabled;
  s_rolled_back = true;
  prv_tick();

  cl_assert_equal_i(0, s_shreds);
}

//! A stale deadline is retired at boot rather than resumed: nothing arms one
//! while off, so it is a record from before the switch was thrown.
void test_security_lock_endpoint__init_retires_a_stale_deadline_when_off(void) {
  s_state = SecurityLockStateDisabled;
  s_shred_deadline = 5000;

  security_lock_endpoint_init();

  cl_assert_equal_i(0, s_shred_deadline);
  cl_assert(!prv_timer_running());
}

// The manual countdown
////////////////////////////////////
//
// A lockdown the user asked for locks at once and erases at the configured
// Erase After, and only the PIN gets in between. Everything below is about what
// must not be allowed to interfere with that.

//! Locks now, erases later. The erase is the Erase After setting measured from
//! the press, not from a disconnect that never happened.
void test_security_lock_endpoint__a_manual_lockdown_locks_now_and_arms_the_erase(void) {
  security_lock_engage_with_countdown(SecurityShredReasonManualPanic);

  cl_assert_equal_i(SecurityLockStateLocked, s_state);
  cl_assert_equal_i(0, s_shreds);
  cl_assert_equal_i(s_now + 600, s_shred_deadline);
  cl_assert_equal_i(SecurityCountdownManual, s_countdown_source);
  cl_assert(prv_timer_running());
}

//! There is nothing left to lock, so no lock deadline is armed. One left over
//! from a disconnect goes with it: the lock it was counting towards has
//! happened.
void test_security_lock_endpoint__a_manual_lockdown_arms_no_lock_deadline(void) {
  prv_session_event(false);
  cl_assert(s_lock_deadline != 0);

  security_lock_engage_with_countdown(SecurityShredReasonManualPanic);

  cl_assert_equal_i(0, s_lock_deadline);
}

//! Erase After set to Never is how a user gets lock-without-erase, which is why
//! there is no separate lock-only action anywhere in the UI. It has to actually
//! arm nothing rather than arm a countdown nothing acts on.
void test_security_lock_endpoint__a_manual_lockdown_with_never_only_locks(void) {
  s_shred_delay_s = SECURITY_LOCK_SHRED_DELAY_NEVER;

  security_lock_engage_with_countdown(SecurityShredReasonManualPanic);

  cl_assert_equal_i(SecurityLockStateLocked, s_state);
  cl_assert_equal_i(0, s_shred_deadline);
  cl_assert_equal_i(SecurityCountdownNone, s_countdown_source);
  cl_assert_equal_i(0, s_shreds);
}

//! And it stays only a lock: nothing later turns the erase back on by itself.
void test_security_lock_endpoint__a_never_lockdown_does_not_erase_on_a_tick(void) {
  s_shred_delay_s = SECURITY_LOCK_SHRED_DELAY_NEVER;
  security_lock_engage_with_countdown(SecurityShredReasonManualPanic);

  s_now += 100000;
  if (prv_timer_running()) {
    prv_tick();
  }

  cl_assert_equal_i(0, s_shreds);
  cl_assert_equal_i(SecurityLockStateLocked, s_state);
}

void test_security_lock_endpoint__a_manual_countdown_erases_when_it_expires(void) {
  security_lock_engage_with_countdown(SecurityShredReasonManualPanic);

  s_now += 600;
  prv_tick();

  cl_assert_equal_i(1, s_shreds);
  // Reported as what it was. A manual lockdown told the phone "disconnect
  // timeout" would be a lie about a watch that never lost its phone.
  cl_assert_equal_i(SecurityShredReasonManualPanic, s_last_shred_reason);
  cl_assert_equal_i(SecurityCountdownNone, s_countdown_source);
}

//! THE hazard. A session opening is right to retire a countdown the phone's
//! absence armed -- the phone is back, so the countdown is moot -- and says
//! nothing whatever about one the user asked for. A Bluetooth blip cancelling a
//! deliberate lockdown is the bug that only surfaces the day someone needs it.
void test_security_lock_endpoint__a_reconnect_does_not_cancel_a_manual_lockdown(void) {
  security_lock_engage_with_countdown(SecurityShredReasonManualPanic);
  const time_t armed_at = s_shred_deadline;

  prv_session_event(false);
  prv_session_event(true);

  cl_assert_equal_i(armed_at, s_shred_deadline);
  cl_assert_equal_i(SecurityCountdownManual, s_countdown_source);
  cl_assert(prv_timer_running());
}

//! Not once, either. Gadgetbridge reconnects on its own, so this is the shape
//! an attacker with the phone actually produces.
void test_security_lock_endpoint__repeated_reconnects_do_not_cancel_it(void) {
  security_lock_engage_with_countdown(SecurityShredReasonManualPanic);
  const time_t armed_at = s_shred_deadline;

  for (int i = 0; i < 5; ++i) {
    prv_session_event(false);
    prv_session_event(true);
  }

  cl_assert_equal_i(armed_at, s_shred_deadline);
  cl_assert_equal_i(SecurityCountdownManual, s_countdown_source);
}

//! And the countdown still fires afterwards, rather than merely surviving as a
//! record nothing is watching.
void test_security_lock_endpoint__a_manual_countdown_still_fires_after_a_reconnect(void) {
  security_lock_engage_with_countdown(SecurityShredReasonManualPanic);

  prv_session_event(false);
  prv_session_event(true);
  s_now += 600;
  prv_tick();

  cl_assert_equal_i(1, s_shreds);
}

//! The reverse direction, and just as easy to get wrong: the phone going away
//! while a manual countdown runs must not reschedule it. Arming afresh would
//! restart the erase clock, and with a longer Erase After it would postpone the
//! erase the user asked for by walking out of Bluetooth range.
void test_security_lock_endpoint__losing_the_phone_does_not_restart_a_manual_countdown(void) {
  security_lock_engage_with_countdown(SecurityShredReasonManualPanic);
  const time_t armed_at = s_shred_deadline;

  s_now += 300;
  prv_session_event(false);

  cl_assert_equal_i(armed_at, s_shred_deadline);
  cl_assert_equal_i(SecurityCountdownManual, s_countdown_source);
  cl_assert(prv_timer_running());
}

//! Nor shorten it. The disconnect delays describe a countdown that has not
//! started; the one that is running belongs to the user.
void test_security_lock_endpoint__losing_the_phone_does_not_shorten_a_manual_countdown(void) {
  security_lock_engage_with_countdown(SecurityShredReasonManualPanic);
  const time_t armed_at = s_shred_deadline;

  s_shred_delay_s = 10;
  prv_session_event(false);

  cl_assert_equal_i(armed_at, s_shred_deadline);
}

//! Nor turn it off, which is what an Erase After of Never would otherwise do to
//! a countdown that was already running.
void test_security_lock_endpoint__losing_the_phone_with_never_does_not_disarm_it(void) {
  security_lock_engage_with_countdown(SecurityShredReasonManualPanic);
  const time_t armed_at = s_shred_deadline;

  s_shred_delay_s = SECURITY_LOCK_SHRED_DELAY_NEVER;
  prv_session_event(false);

  cl_assert_equal_i(armed_at, s_shred_deadline);
  cl_assert_equal_i(SecurityCountdownManual, s_countdown_source);
}

//! Pressing Lockdown must never buy time. A disconnect countdown already closer
//! than the configured delay is kept rather than replaced -- and promoted to
//! manual, so the reconnect that would have cancelled it no longer can.
void test_security_lock_endpoint__a_manual_lockdown_never_postpones_an_erase(void) {
  prv_session_event(false);
  const time_t disconnect_deadline = s_shred_deadline;

  // Long enough after the disconnect that a fresh countdown would land later.
  s_now += 300;
  security_lock_engage_with_countdown(SecurityShredReasonManualPanic);

  cl_assert_equal_i(disconnect_deadline, s_shred_deadline);
  cl_assert_equal_i(SecurityCountdownManual, s_countdown_source);
}

//! But it does bring one forward. A user who reaches for Lockdown wants it
//! sooner, not to wait out whatever the disconnect had scheduled.
void test_security_lock_endpoint__a_manual_lockdown_can_bring_an_erase_forward(void) {
  prv_session_event(false);

  s_shred_delay_s = 60;
  security_lock_engage_with_countdown(SecurityShredReasonManualPanic);

  cl_assert_equal_i(s_now + 60, s_shred_deadline);
  cl_assert_equal_i(SecurityCountdownManual, s_countdown_source);
}

//! Setting Erase After to Never after a disconnect countdown has already armed
//! one does not retroactively disarm it, so a Lockdown on top of that keeps the
//! erase that was already scheduled -- and takes it out of the reach of a
//! reconnect.
void test_security_lock_endpoint__a_never_lockdown_keeps_an_erase_already_scheduled(void) {
  prv_session_event(false);
  const time_t disconnect_deadline = s_shred_deadline;

  s_shred_delay_s = SECURITY_LOCK_SHRED_DELAY_NEVER;
  security_lock_engage_with_countdown(SecurityShredReasonManualPanic);

  cl_assert_equal_i(disconnect_deadline, s_shred_deadline);
  cl_assert_equal_i(SecurityCountdownManual, s_countdown_source);
}

//! A reconnect still retires an ordinary disconnect countdown. The guard above
//! must be about why the countdown was armed, not a blanket refusal to clear
//! anything -- otherwise an unlocked, reconnected watch sits on a countdown the
//! user cannot see.
void test_security_lock_endpoint__a_reconnect_still_retires_a_disconnect_countdown(void) {
  prv_session_event(false);
  cl_assert_equal_i(SecurityCountdownDisconnect, s_countdown_source);

  prv_session_event(true);

  cl_assert_equal_i(0, s_lock_deadline);
  cl_assert_equal_i(0, s_shred_deadline);
  cl_assert_equal_i(SecurityCountdownNone, s_countdown_source);
  cl_assert(!prv_timer_running());
}

//! A watch that rebooted mid-lockdown comes back still counting down, and still
//! knowing the countdown is the user's -- which is the whole reason the record
//! carries it rather than a RAM flag.
void test_security_lock_endpoint__init_resumes_a_manual_countdown(void) {
  s_state = SecurityLockStateLocked;
  s_shred_deadline = 5000;
  s_countdown_source = SecurityCountdownManual;

  security_lock_endpoint_init();

  cl_assert(prv_timer_running());
  cl_assert_equal_i(SecurityCountdownManual, s_countdown_source);

  // And the reconnect that follows the reboot does not cancel it either.
  prv_session_event(true);
  cl_assert_equal_i(5000, s_shred_deadline);
}

//! The PIN clears the deadlines through the record store, which cannot reach
//! into this file to stop the timer. The next tick has to notice and retire it,
//! or the watch ticks for the rest of the day over nothing.
void test_security_lock_endpoint__the_timer_stops_once_nothing_is_counting_down(void) {
  security_lock_engage_with_countdown(SecurityShredReasonManualPanic);
  cl_assert(prv_timer_running());

  // What unlocking does to the record.
  s_state = SecurityLockStateArmed;
  security_lock_clear_deadlines();

  prv_tick();

  cl_assert(!prv_timer_running());
  cl_assert_equal_i(0, s_shreds);
}

//! A clock wound back is the one tamper that outruns a deadline, and a manual
//! countdown is no more exempt from it than a disconnect one.
void test_security_lock_endpoint__a_rollback_still_erases_under_a_manual_countdown(void) {
  security_lock_engage_with_countdown(SecurityShredReasonManualPanic);

  s_rolled_back = true;
  prv_tick();

  cl_assert_equal_i(1, s_shreds);
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
