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
  net16 disconnect_timeout_s;
  uint8_t lock_on_disconnect;
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

//! Runtime config pushed by the phone. Not persisted: the phone re-sends it on
//! every connection, and a stale timeout is worse than the default.
static uint16_t s_disconnect_timeout_s = SECURITY_LOCK_DISCONNECT_TIMEOUT_S;
static bool s_lock_on_disconnect;
static bool s_enabled = true;

static RegularTimerInfo s_deadline_timer;
static bool s_deadline_timer_running;

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
  const time_t deadline = security_lock_get_disconnect_deadline();
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
  PBL_LOG_DBG("LOCK from phone, reason %" PRIu8, lock_msg->reason);
  launcher_task_add_callback(prv_lock_callback, (void *)(uintptr_t)lock_msg->reason);
}

static void prv_handle_configure(const uint8_t *msg, size_t len) {
  if (len < sizeof(SecurityLockConfigureMsg)) {
    PBL_LOG_ERR("Short CONFIGURE message: %u", (unsigned)len);
    return;
  }
  const SecurityLockConfigureMsg *cfg = (const SecurityLockConfigureMsg *)msg;
  s_enabled = (cfg->enabled != 0);
  s_lock_on_disconnect = (cfg->lock_on_disconnect != 0);

  const uint16_t timeout = ntoh16(cfg->disconnect_timeout_s);
  // Zero means "use the default" rather than "shred immediately".
  s_disconnect_timeout_s = (timeout != 0) ? timeout : SECURITY_LOCK_DISCONNECT_TIMEOUT_S;

  PBL_LOG_DBG("Configured: enabled=%d timeout=%" PRIu16 "s lock_on_disconnect=%d", (int)s_enabled,
              s_disconnect_timeout_s, (int)s_lock_on_disconnect);
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

static void prv_deadline_expired_callback(void *unused) {
  if (!security_lock_is_locked()) {
    return;
  }
  security_lock_shred(SecurityShredReasonDisconnectTimeout);
}

//! Re-checked on a timer rather than armed as a single long timeout, because a
//! one-shot timer does not survive the watch sleeping or rebooting. The
//! deadline itself is an absolute timestamp in the lock record, so it does.
static void prv_deadline_check(void *unused) {
  if (!security_lock_is_locked()) {
    return;
  }

  const time_t now = rtc_get_time();
  if (security_lock_note_time(now)) {
    // Clock wound back, most likely to dodge the deadline.
    security_lock_shred(SecurityShredReasonClockRollback);
    return;
  }

  if (security_lock_disconnect_deadline_expired(now)) {
    prv_deadline_expired_callback(NULL);
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
    security_lock_clear_disconnect_deadline();
    prv_stop_deadline_timer();
    return;
  }

  if (security_lock_get_state() == SecurityLockStateDisabled) {
    return;
  }

  if (security_lock_is_locked()) {
    const time_t deadline = rtc_get_time() + s_disconnect_timeout_s;
    security_lock_set_disconnect_deadline(deadline);
    prv_start_deadline_timer();
    PBL_LOG_DBG("Locked and disconnected; deadline in %" PRIu16 "s", s_disconnect_timeout_s);
  } else if (s_lock_on_disconnect && s_enabled) {
    // Off by default: locking every time the watch wanders out of Bluetooth
    // range would be unusable.
    PBL_LOG_DBG("Locking on unexpected disconnect");
    launcher_task_add_callback(prv_lock_callback,
                             (void *)(uintptr_t)SecurityShredReasonDisconnectTimeout);
  }
}

void security_lock_endpoint_init(void) {
  // A watch that was locked and offline across a reboot needs the timer running
  // again without waiting for another disconnect event.
  if (security_lock_is_locked() && (security_lock_get_disconnect_deadline() != 0)) {
    prv_start_deadline_timer();
  }
}
