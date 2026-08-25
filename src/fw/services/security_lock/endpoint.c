/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include "pbl/services/security_lock_endpoint.h"

#include <inttypes.h>
#include <string.h>

#include <pbl/drivers/rtc.h>
#include <pbl/logging/logging.h>
#include "kernel/event_loop.h"
#include "kernel/events.h"
#include "pbl/services/comm_session/session.h"
#include "pbl/services/regular_timer.h"
#include "pbl/services/security_lock_ui.h"
#include "pbl/services/system_task.h"
#include "pbl/util/attributes.h"
#include "util/net.h"

PBL_LOG_MODULE_DECLARE(service_security_lock, CONFIG_SERVICE_SECURITY_LOCK_LOG_LEVEL);

#define SECURITY_LOCK_ENDPOINT_ID 11300

//! Response commands carry the high bit, matching the BlobDB endpoint.
#define RESPONSE_MASK (1 << 7)

//! 0x01 was CONFIGURE. The watch owns its own security configuration now, so
//! there is nothing for the phone to set; an old phone still sending it falls
//! through to the unknown-command path.
typedef enum PACKED {
  SecurityLockCmdLock = 0x02,
  SecurityLockCmdStatusRequest = 0x03,

  SecurityLockCmdLockAck = 0x02 | RESPONSE_MASK,
  SecurityLockCmdStatusResponse = 0x03 | RESPONSE_MASK,
  SecurityLockCmdShredComplete = 0x04 | RESPONSE_MASK,
  SecurityLockCmdStateChanged = 0x05 | RESPONSE_MASK,
} SecurityLockCmd;

typedef struct PACKED {
  uint8_t cmd;
  uint8_t reason;
} SecurityLockReasonMsg;

typedef struct PACKED {
  uint8_t cmd;
  uint8_t state;
  uint8_t pin_configured;
  net32 deadline_remaining_s;
} SecurityLockStatusMsg;

typedef struct PACKED {
  uint8_t cmd;
  uint8_t reason;
  net32 wiped_dbs;
} SecurityLockShredCompleteMsg;

typedef struct PACKED {
  uint8_t cmd;
  uint8_t state;
} SecurityLockStateMsg;

static RegularTimerInfo s_deadline_timer;
static bool s_deadline_timer_running;

//! Databases the phone must resend, and the most recent reason it must, held
//! until there is a session to say it on. 0 means nothing owed.
static uint32_t s_resync_dbs;
static SecurityShredReason s_resync_reason;

static void prv_stop_deadline_timer(void);

//! @return false if there was no session to send on, so nothing went out
static bool prv_send(const void *msg, size_t len) {
  CommSession *session = comm_session_get_system_session();
  if (session == NULL) {
    PBL_LOG_DBG("No session; phone will be told on reconnect");
    return false;
  }
  comm_session_send_data(session, SECURITY_LOCK_ENDPOINT_ID, msg, len,
                         COMM_SESSION_DEFAULT_TIMEOUT);
  return true;
}

//! Hand the outstanding resync request to the phone, if there is one to hand it
//! to. Cleared only once it has actually gone out.
static void prv_flush_resync(void) {
  if (s_resync_dbs == 0) {
    return;
  }

  const SecurityLockShredCompleteMsg msg = {
      .cmd = SecurityLockCmdShredComplete,
      .reason = (uint8_t)s_resync_reason,
      .wiped_dbs = hton32(s_resync_dbs),
  };
  if (!prv_send(&msg, sizeof(msg))) {
    return;
  }

  PBL_LOG_INFO("Told the phone to resend databases 0x%" PRIx32 ", reason %" PRIu8, s_resync_dbs,
               (uint8_t)s_resync_reason);
  s_resync_dbs = 0;
}

void security_lock_endpoint_report_resync_needed(SecurityShredReason reason, uint32_t dbs) {
  if (dbs == 0) {
    // Nothing was lost, so nothing is asked for. Every unlock reaches here and
    // a resync the phone did not need costs it a full calendar re-push.
    return;
  }

  // Recorded before the attempt rather than on its failure. Both callers run on
  // KernelMain, as does the session event that would flush this, so the two
  // cannot actually interleave today -- but a signal that survives only because
  // the send happened to fail in the right order is not one worth relying on.
  s_resync_dbs |= dbs;
  s_resync_reason = reason;
  prv_flush_resync();
}

void security_lock_endpoint_send_state_changed(SecurityLockState state) {
  const SecurityLockStateMsg msg = {
      .cmd = SecurityLockCmdStateChanged,
      .state = (uint8_t)state,
  };
  prv_send(&msg, sizeof(msg));
}

static void prv_send_lock_ack(SecurityShredReason reason) {
  const SecurityLockReasonMsg msg = {
      .cmd = SecurityLockCmdLockAck,
      .reason = (uint8_t)reason,
  };
  prv_send(&msg, sizeof(msg));
}

static void prv_send_status(void) {
  // Report the shred countdown: it is the one with consequences the phone
  // might want to surface.
  const time_t deadline = security_lock_get_shred_deadline();
  const time_t now = rtc_get_time();
  uint32_t remaining = 0;
  if ((deadline != 0) && (deadline > now)) {
    remaining = (uint32_t)(deadline - now);
  }

  const SecurityLockStatusMsg msg = {
      .cmd = SecurityLockCmdStatusResponse,
      .state = (uint8_t)security_lock_get_state(),
      // Answered from the PIN itself, not from the state. A PIN outlives the
      // master switch, so Disabled no longer implies there is none -- and a
      // phone told otherwise would offer to set one that already exists.
      .pin_configured = (security_lock_get_pin_len() != 0) ? 1 : 0,
      .deadline_remaining_s = hton32(remaining),
  };
  prv_send(&msg, sizeof(msg));
}

//! Say no to a LOCK by reporting the state that refused it.
//!
//! LOCK_ACK carries only a reason echo and has no failure encoding, and adding
//! one would need a phone that understands it. STATE_CHANGED is a message the
//! phone already parses, and Disabled is the entire reason for the refusal --
//! so this says no in a vocabulary that exists today.
//!
//! What must not happen is a LOCK_ACK: the phone reads that as "locked and
//! erased" and stops asking. Reporting success for a watch that did neither is
//! the worst of the three outcomes.
static void prv_refuse_lock(void) {
  security_lock_endpoint_send_state_changed(security_lock_get_state());
}

//! security_lock_engage() touches the app and modal stacks, so it is
//! KernelMain-only. It also blocks for the duration of the shred.
static void prv_lock_callback(void *data) {
  const SecurityShredReason reason = (SecurityShredReason)(uintptr_t)data;
  security_lock_engage(reason);

  // Keyed on what actually happened rather than on having asked. engage()
  // refuses on more than the master switch -- an unusable stored PIN length
  // among them -- and every one of those must reach the phone as a refusal.
  if (!security_lock_is_locked()) {
    PBL_LOG_WRN("LOCK did not take effect; reporting state instead of acking");
    prv_refuse_lock();
    return;
  }
  prv_send_lock_ack(reason);
}

static void prv_handle_lock(const uint8_t *msg, size_t len) {
  if (len < sizeof(SecurityLockReasonMsg)) {
    PBL_LOG_ERR("Short LOCK message: %u", (unsigned)len);
    return;
  }
  if (!security_lock_is_enabled()) {
    // Refused here as well as at the funnel, so the watch does not tear its own
    // UI down on the way to doing nothing.
    PBL_LOG_WRN("Ignoring LOCK: the security lock is off");
    prv_refuse_lock();
    return;
  }
  const SecurityLockReasonMsg *lock_msg = (const SecurityLockReasonMsg *)msg;
  PBL_LOG_INFO("LOCK from phone, reason %" PRIu8, lock_msg->reason);
  launcher_task_add_callback(prv_lock_callback, (void *)(uintptr_t)lock_msg->reason);
}

void security_lock_protocol_msg_callback(CommSession *session, const uint8_t *msg, size_t len) {
  if (len < 1) {
    PBL_LOG_ERR("Empty message");
    return;
  }

  switch (msg[0]) {
    case SecurityLockCmdLock:
      prv_handle_lock(msg, len);
      break;
    case SecurityLockCmdStatusRequest:
      prv_send_status();
      break;
    default:
      PBL_LOG_WRN("Unexpected command 0x%" PRIx8, msg[0]);
      break;
  }
}

// Disconnect deadline
////////////////////////////////////

static void prv_deadline_shred_callback(void *unused) {
  security_lock_shred(SecurityShredReasonDisconnectTimeout);
}

static void prv_rollback_shred_callback(void *unused) {
  security_lock_shred(SecurityShredReasonClockRollback);
}

//! Runs on KernelMain because locking touches the app and modal stacks.
static void prv_deadline_lock_callback(void *unused) {
  if (security_lock_is_locked()) {
    return;
  }
  PBL_LOG_DBG("Lock delay elapsed while disconnected");
  // Lock only. The shred deadline is what erases, and it may be disarmed
  // outright; shredding here would collapse the two delays into one.
  security_lock_engage_lock_only(SecurityShredReasonDisconnectTimeout);
}

//! Re-checked on a timer rather than armed as one long timeout, because a
//! one-shot timer survives neither the watch sleeping nor a reboot. The
//! deadlines are absolute timestamps in the lock record, so they survive both
//! and are re-checked at boot.
static void prv_deadline_check(void *unused) {
  if (!security_lock_is_enabled()) {
    return;
  }

  // Locked with the radio down is terminal: nothing can arrive, so a countdown
  // armed before the wipe has nothing left to count down and only the PIN gets
  // out. Retire it rather than tick uselessly for the duration of the lock.
  if (security_lock_is_radio_blackout()) {
    security_lock_clear_deadlines();
    prv_stop_deadline_timer();
    return;
  }

  const time_t now = rtc_get_time();
  // Only a shred deadline can be outrun by winding the clock back. With the
  // timed erase turned off there is nothing to outrun, and shredding anyway
  // would be the one outcome the user asked not to have.
  if (security_lock_note_time(now) && (security_lock_get_shred_deadline() != 0)) {
    launcher_task_add_callback(prv_rollback_shred_callback, NULL);
    return;
  }

  // Shred first: if the watch was powered off past both deadlines, the data
  // mattering more than the lock screen is the whole point.
  if (security_lock_shred_deadline_expired(now)) {
    PBL_LOG_DBG("Shred delay elapsed while disconnected");
    security_lock_clear_deadlines();
    prv_stop_deadline_timer();
    // KernelMain: the wipe closes and reopens databases, which deadlocks if
    // driven from here. See security_lock_engage().
    launcher_task_add_callback(prv_deadline_shred_callback, NULL);
    return;
  }

  if (security_lock_lock_deadline_expired(now) && !security_lock_is_locked()) {
    launcher_task_add_callback(prv_deadline_lock_callback, NULL);
  }
}

static void prv_deadline_timer_callback(void *unused) {
  system_task_add_callback(prv_deadline_check, NULL);
}

static void prv_start_deadline_timer(void) {
  if (s_deadline_timer_running) {
    return;
  }
  s_deadline_timer = (RegularTimerInfo){.cb = prv_deadline_timer_callback};
  regular_timer_add_multiminute_callback(&s_deadline_timer, 1);
  s_deadline_timer_running = true;
}

static void prv_stop_deadline_timer(void) {
  if (!s_deadline_timer_running) {
    return;
  }
  regular_timer_remove_callback(&s_deadline_timer);
  s_deadline_timer_running = false;
}

void security_lock_handle_comm_session_event(const PebbleCommSessionEvent *event) {
  if (!event->is_system) {
    return;
  }

  if (event->is_open) {
    // Reconnecting stops the countdown but never unlocks. A reconnect proves
    // nothing an attacker cannot arrange: Android keeps Bluetooth up while the
    // screen is locked and Gadgetbridge reconnects on its own, so a phone
    // carried out of range and back -- or shielded and unshielded -- would
    // otherwise clear the lock without anyone knowing the PIN. Only the PIN
    // clears a lock, whatever caused it.
    security_lock_clear_deadlines();
    prv_stop_deadline_timer();

    // The phone is back, so anything the watch could not tell it while it was
    // gone goes now. This is the half that matters: an unlock releases the
    // radio blackout, but the session is not rebuilt until after that has been
    // and gone, and a wipe caused by the phone walking away never had one at
    // all. comm_session_open() adds the session to its list before publishing
    // this event, so there is one to send on by the time we are called.
    prv_flush_resync();
    return;
  }

  // Off means no deadline is ever armed, rather than one armed and then
  // declined to act on: nothing should be counting down on a watch that has
  // said it does not want this.
  if (!security_lock_is_enabled()) {
    return;
  }

  // We took the radio down ourselves, so this close is our own doing and there
  // is no phone out there to come back. Arming off it would make the blackout
  // schedule a fresh countdown as a side effect of its own cleanup.
  if (security_lock_is_radio_blackout()) {
    PBL_LOG_DBG("Session closed by our own blackout; nothing to count down");
    return;
  }

  // Both are measured from the disconnect, so a watch that is already locked
  // still gets the full shred delay rather than an immediate wipe.
  const time_t now = rtc_get_time();
  const uint32_t shred_delay_s = security_lock_get_shred_delay_s();
  const time_t lock_deadline =
      security_lock_is_locked() ? 0 : now + (time_t)security_lock_get_lock_delay_s();
  // Never leaves the shred deadline unarmed, which is already how "nothing
  // pending" is spelled everywhere else.
  const time_t shred_deadline =
      (shred_delay_s == SECURITY_LOCK_SHRED_DELAY_NEVER) ? 0 : now + (time_t)shred_delay_s;
  security_lock_set_deadlines(lock_deadline, shred_deadline);

  if ((lock_deadline == 0) && (shred_deadline == 0)) {
    // Already locked with no timed erase: nothing left to count down.
    PBL_LOG_DBG("Phone gone: already locked, no timed erase");
    return;
  }
  prv_start_deadline_timer();

  PBL_LOG_DBG("Phone gone: lock in %" PRIu32 "s, shred in %" PRIu32 "s",
              security_lock_get_lock_delay_s(), shred_delay_s);
}

void security_lock_endpoint_init(void) {
  // The boot wipe runs from services_normal_early_init(), before bt_ctl exists,
  // so the blackout it owes is taken here instead -- this is the first point
  // after the radio is up. security_lock_handle_boot() wipes on every path that
  // leaves the watch locked, so the locked state is the whole condition.
  // Idempotent, so a blackout held across the reboot is merely re-asserted;
  // airplane mode is persisted, so it is normally already in force.
  if (security_lock_is_locked()) {
    security_lock_radio_blackout_engage();
  }

  // A watch that was locked and offline across a reboot needs the timer running
  // again without waiting for another disconnect event. Nothing arms a deadline
  // while the feature is off, so a leftover one is a record from before it was
  // turned off: retire it rather than resume counting down on it.
  const bool armed =
      (security_lock_get_lock_deadline() != 0) || (security_lock_get_shred_deadline() != 0);
  if (!armed) {
    return;
  }
  if (!security_lock_is_enabled()) {
    security_lock_clear_deadlines();
    return;
  }
  prv_start_deadline_timer();
}
