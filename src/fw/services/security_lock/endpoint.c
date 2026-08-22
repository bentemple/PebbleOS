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

typedef enum PACKED {
  SecurityLockCmdConfigure = 0x01,
  SecurityLockCmdLock = 0x02,
  SecurityLockCmdStatusRequest = 0x03,

  SecurityLockCmdLockAck = 0x02 | RESPONSE_MASK,
  SecurityLockCmdStatusResponse = 0x03 | RESPONSE_MASK,
  SecurityLockCmdShredComplete = 0x04 | RESPONSE_MASK,
  SecurityLockCmdStateChanged = 0x05 | RESPONSE_MASK,
} SecurityLockCmd;

typedef struct PACKED {
  uint8_t cmd;
  uint8_t enabled;
  net16 lock_delay_s;
  net16 shred_delay_s;
} SecurityLockConfigureMsg;

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

//! Whether the phone has asked for the feature at all. Not persisted: the
//! phone re-sends CONFIGURE on every connection. The delays themselves are
//! persisted by the service, because Settings can set them too and they have
//! to survive a reboot.
static bool s_enabled = true;

static RegularTimerInfo s_deadline_timer;
static bool s_deadline_timer_running;

static void prv_stop_deadline_timer(void);

static void prv_send(const void *msg, size_t len) {
  CommSession *session = comm_session_get_system_session();
  if (session == NULL) {
    // Expected whenever the shred was triggered by the phone going away.
    PBL_LOG_DBG("No session; phone will be told on reconnect");
    return;
  }
  comm_session_send_data(session, SECURITY_LOCK_ENDPOINT_ID, msg, len,
                         COMM_SESSION_DEFAULT_TIMEOUT);
}

void security_lock_endpoint_send_shred_complete(SecurityShredReason reason, uint32_t wiped_dbs) {
  const SecurityLockShredCompleteMsg msg = {
      .cmd = SecurityLockCmdShredComplete,
      .reason = (uint8_t)reason,
      .wiped_dbs = hton32(wiped_dbs),
  };
  prv_send(&msg, sizeof(msg));
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
      .pin_configured = (security_lock_get_state() != SecurityLockStateDisabled) ? 1 : 0,
      .deadline_remaining_s = hton32(remaining),
  };
  prv_send(&msg, sizeof(msg));
}

//! security_lock_engage() touches the app and modal stacks, so it is
//! KernelMain-only. It also blocks for the duration of the shred.
static void prv_lock_callback(void *data) {
  const SecurityShredReason reason = (SecurityShredReason)(uintptr_t)data;
  security_lock_engage(reason);
  prv_send_lock_ack(reason);
}

static void prv_handle_lock(const uint8_t *msg, size_t len) {
  if (len < sizeof(SecurityLockReasonMsg)) {
    PBL_LOG_ERR("Short LOCK message: %u", (unsigned)len);
    return;
  }
  if (!s_enabled) {
    PBL_LOG_WRN("Ignoring LOCK: feature disabled");
    return;
  }
  const SecurityLockReasonMsg *lock_msg = (const SecurityLockReasonMsg *)msg;
  PBL_LOG_INFO("LOCK from phone, reason %" PRIu8, lock_msg->reason);
  launcher_task_add_callback(prv_lock_callback, (void *)(uintptr_t)lock_msg->reason);
}

static void prv_handle_configure(const uint8_t *msg, size_t len) {
  if (len < sizeof(SecurityLockConfigureMsg)) {
    PBL_LOG_ERR("Short CONFIGURE message: %u", (unsigned)len);
    return;
  }
  const SecurityLockConfigureMsg *cfg = (const SecurityLockConfigureMsg *)msg;
  s_enabled = (cfg->enabled != 0);

  // Zero means "leave it alone" rather than "act immediately", so a phone that
  // does not care about the timings cannot accidentally set them to nothing.
  const uint16_t lock_delay = ntoh16(cfg->lock_delay_s);
  const uint16_t shred_delay = ntoh16(cfg->shred_delay_s);
  if ((lock_delay != 0) || (shred_delay != 0)) {
    const uint32_t new_lock =
        (lock_delay != 0) ? lock_delay : security_lock_get_lock_delay_s();
    const uint32_t new_shred =
        (shred_delay != 0) ? shred_delay : security_lock_get_shred_delay_s();
    if (security_lock_set_delays(new_lock, new_shred) != S_SUCCESS) {
      PBL_LOG_WRN("Rejected delays: lock=%" PRIu32 "s shred=%" PRIu32 "s", new_lock, new_shred);
    }
  }

  PBL_LOG_DBG("Configured: enabled=%d lock=%" PRIu32 "s shred=%" PRIu32 "s", (int)s_enabled,
              security_lock_get_lock_delay_s(), security_lock_get_shred_delay_s());
}

void security_lock_protocol_msg_callback(CommSession *session, const uint8_t *msg, size_t len) {
  if (len < 1) {
    PBL_LOG_ERR("Empty message");
    return;
  }

  switch (msg[0]) {
    case SecurityLockCmdConfigure:
      prv_handle_configure(msg, len);
      break;
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
  if (security_lock_get_state() == SecurityLockStateDisabled) {
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
    return;
  }

  if (!s_enabled || (security_lock_get_state() == SecurityLockStateDisabled)) {
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
  // again without waiting for another disconnect event.
  if ((security_lock_get_lock_deadline() != 0) || (security_lock_get_shred_deadline() != 0)) {
    prv_start_deadline_timer();
  }
}
