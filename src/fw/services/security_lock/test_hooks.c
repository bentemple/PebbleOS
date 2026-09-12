/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

//! Console control surface for the security lock, so an automated test can put
//! the watch into any state without driving the touch UI. Driving the UI is
//! slow, flaky, and -- when the UI is not the thing under test -- in the way.
//!
//! Every one of these bypasses a user-facing control, so the whole file is
//! compiled only under CONFIG_SERVICE_SECURITY_LOCK_TEST_HOOKS. It is the one
//! thing to grep for, and it never reaches a shipping build. The only entries
//! it needs in production source are the console table rows and their forward
//! declarations in prompt_commands.h.

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pbl/kernel/sem.h"

#include <pbl/drivers/rtc.h>
#include <pbl/logging/logging.h>
#include "console/prompt.h"
#include "kernel/event_loop.h"
#include "kernel/events.h"
#include "kernel/ui/modals/modal_manager.h"
#include "pbl/services/security_lock.h"
#include "shell/prefs.h"
#include "pbl/services/security_lock_endpoint.h"
#include "pbl/services/security_lock_shred.h"
#include "pbl/services/security_lock_ui.h"
#include "popups/security/lock_screen.h"
#include "popups/security/pin_entry_window.h"
#include "system/bootbits.h"

//! Every command reports through here so the same text lands in the log and in
//! the console response: the log survives a command that never returns, and the
//! response is there when the harness has a prompt but no log capture.
static void prv_sectest_report(const char *line) {
  PBL_LOG_INFO("%s", line);
  prompt_send_response(line);
}

//! What the security UI is showing, as one key=value line.
//!
//! The pad draws its title and message inline rather than through a TextLayer,
//! so there is no layer tree to walk and this is the only way an automated test
//! can see the screen without reading the framebuffer.
typedef struct SecurityUiInfo {
  struct pbl_sem interlock;
  bool visible;
  uint8_t entered;
  uint8_t pin_len;
  int8_t pressed_key;
  char top_modal[24];
  char title[24];
  char message[SECURITY_PIN_MESSAGE_BUF_SIZE];
} SecurityUiInfo;

//! The modal stack and the pad both belong to the launcher task.
static void prv_security_ui_cb(void *ctx) {
  SecurityUiInfo *info = ctx;

  Window *top = modal_manager_get_top_window();
  strncpy(info->top_modal, (top != NULL) ? window_get_debug_name(top) : "-",
          sizeof(info->top_modal) - 1);

  info->visible = security_lock_screen_is_visible();
  const SecurityPinEntryWindow *pad = security_lock_screen_get_pin_window();
  if (pad != NULL) {
    info->entered = security_pin_entry_window_get_entered(pad);
    info->pin_len = security_pin_entry_window_get_pin_len(pad);
    info->pressed_key = security_pin_entry_window_get_pressed_key(pad);
    strncpy(info->title, security_pin_entry_window_get_title(pad), sizeof(info->title) - 1);
    strncpy(info->message, security_pin_entry_window_get_message(pad), sizeof(info->message) - 1);
  }

  pbl_sem_give(&info->interlock);
}

void command_security_ui(void) {
  SecurityUiInfo info = {
      .pressed_key = -1,
  };
  pbl_sem_init(&info.interlock, 0, 1);

  launcher_task_add_callback(prv_security_ui_cb, &info);
  pbl_sem_take(&info.interlock, PBL_FOREVER);
  pbl_sem_deinit(&info.interlock);

  char buf[192];
  snprintf(buf, sizeof(buf),
           "visible=%d top_modal=%s entered=%u pin_len=%u pressed_key=%d "
           "title=\"%s\" message=\"%s\"",
           (int)info.visible, info.top_modal, (unsigned)info.entered, (unsigned)info.pin_len,
           (int)info.pressed_key, info.title, info.message);
  prompt_send_response(buf);
}

void command_security_set_pin(const char *digits) {
  char buf[96];
  const size_t len = strlen(digits);
  const status_t rv = security_lock_set_pin(digits, (uint8_t)len);
  snprintf(buf, sizeof(buf), "SECTEST set_pin len=%u rv=%" PRId32 " state=%d", (unsigned)len,
           (int32_t)rv, (int)security_lock_get_state());
  prv_sectest_report(buf);
}

//! The master switch, so a test can reach the "feature off" cases without
//! walking the Settings menu.
//!
//! Only off is a thing that can be commanded. Turning it on is setting a PIN
//! and nothing else, so `security set pin` is the other half; `enable 1` is
//! kept and refused rather than removed, so a script asking for it gets an
//! answer that says why instead of an unknown command.
void command_security_enable(const char *on_str) {
  char buf[96];
  const bool enable = (on_str[0] != '0');
  const status_t rv = enable ? E_INVALID_OPERATION : security_lock_disable();
  snprintf(buf, sizeof(buf), "SECTEST enable on=%d rv=%" PRId32 " state=%d%s", (int)enable,
           (int32_t)rv, (int)security_lock_get_state(),
           enable ? " (use `security set pin` to turn it on)" : "");
  prv_sectest_report(buf);
}

void command_security_set_duress(const char *digits) {
  char buf[96];
  const size_t len = strlen(digits);
  const status_t rv = security_lock_set_duress_pin(digits, (uint8_t)len);
  snprintf(buf, sizeof(buf), "SECTEST set_duress len=%u rv=%" PRId32, (unsigned)len, (int32_t)rv);
  prv_sectest_report(buf);
}

void command_security_clear_pin(void) {
  char buf[96];
  const status_t rv = security_lock_clear_pin();
  snprintf(buf, sizeof(buf), "SECTEST clear_pin rv=%" PRId32 " state=%d", (int32_t)rv,
           (int)security_lock_get_state());
  prv_sectest_report(buf);
}

//! Deliberately not blocked on: engage() runs the shred inline and holds the
//! launcher task for seconds, which would leave the console's own task parked
//! long enough to look hung itself. The completion line is the signal.
static void prv_security_lockdown_cb(void *unused) {
  char buf[96];
  security_lock_engage(SecurityShredReasonPhoneLockdown);
  snprintf(buf, sizeof(buf), "SECTEST lockdown done state=%d", (int)security_lock_get_state());
  PBL_LOG_INFO("%s", buf);
}

//! Lock and erase on the spot: what the Settings Lockdown + Erase row, the
//! Quick Launch chord of the same name and the phone's LOCK_ERASE all do.
void command_security_lockdown(void) {
  prv_sectest_report("SECTEST lockdown queued");
  prompt_command_finish();
  launcher_task_add_callback(prv_security_lockdown_cb, NULL);
}

static void prv_security_lock_cb(void *unused) {
  char buf[96];
  security_lock_engage_with_countdown(SecurityShredReasonManualPanic);
  const time_t now = rtc_get_time();
  const time_t shred_deadline = security_lock_get_shred_deadline();
  snprintf(buf, sizeof(buf), "SECTEST lock done state=%d shred_in=%d countdown=%d",
           (int)security_lock_get_state(), (shred_deadline == 0) ? -1 : (int)(shred_deadline - now),
           (int)security_lock_get_countdown_source());
  PBL_LOG_INFO("%s", buf);
}

//! Lock and leave the erase running: what the Lock app, the Quick Launch chord,
//! the Settings Lock row and the phone's LOCK all do.
//!
//! The two commands used to mean the opposite of their names -- `lock` erased
//! and `lockdown` did not -- which was the console half of the vocabulary this
//! feature has since settled. See docs/proposals/security-lockdown.md.
void command_security_lock(void) {
  prv_sectest_report("SECTEST lock queued");
  prompt_command_finish();
  launcher_task_add_callback(prv_security_lock_cb, NULL);
}

typedef struct SecurityUnlockInfo {
  struct pbl_sem interlock;
  const char *digits;
  bool matched;
  uint8_t attempts_remaining;
} SecurityUnlockInfo;

//! The same verify-then-disengage the pad's submit handler runs, minus the
//! on-screen failure message -- which is the pad's own business and the point
//! of this command is to reach the unlock path without the pad.
//!
//! On the launcher task because disengage() touches the modal and app stacks.
static void prv_security_unlock_cb(void *ctx) {
  SecurityUnlockInfo *info = ctx;
  info->matched = security_lock_verify_pin(info->digits, (uint8_t)strlen(info->digits),
                                           &info->attempts_remaining);
  if (info->matched) {
    security_lock_disengage();
  }
  pbl_sem_give(&info->interlock);
}

void command_security_unlock(const char *digits) {
  SecurityUnlockInfo info = {
      .digits = digits,
  };
  pbl_sem_init(&info.interlock, 0, 1);

  launcher_task_add_callback(prv_security_unlock_cb, &info);
  pbl_sem_take(&info.interlock, PBL_FOREVER);
  pbl_sem_deinit(&info.interlock);

  char buf[96];
  snprintf(buf, sizeof(buf), "SECTEST unlock result=%d attempts_left=%u state=%d",
           (int)info.matched, (unsigned)info.attempts_remaining, (int)security_lock_get_state());
  prv_sectest_report(buf);
}

void command_security_alarms(const char *on_str) {
  char buf[96];
  const bool allowed = (on_str[0] != '0');
  const status_t rv = security_lock_set_alarms_when_locked(allowed);
  snprintf(buf, sizeof(buf), "SECTEST alarms on=%d rv=%" PRId32, (int)allowed, (int32_t)rv);
  prv_sectest_report(buf);
}

//! Whether a notification arriving behind the lock is discarded or kept.
//!
//! In shell prefs rather than the lock's own record, so this goes through the same setter the
//! Settings row uses. Reachable from the console because a test has to drive both branches and
//! the row is several presses deep.
void command_security_notifs(const char *on_str) {
  char buf[96];
  const bool block = (on_str[0] != '0');
  shell_prefs_set_block_notifications_when_locked(block);
  snprintf(buf, sizeof(buf), "SECTEST notifs block=%d", (int)block);
  prv_sectest_report(buf);
}

//! Whether the wipe also destroys step and sleep history. Reachable from the
//! console because the Settings row deliberately asks first, and a harness
//! cannot take a confirmation.
void command_security_health(const char *on_str) {
  char buf[96];
  const bool enabled = (on_str[0] != '0');
  const status_t rv = security_lock_set_shred_health(enabled);
  snprintf(buf, sizeof(buf), "SECTEST health on=%d rv=%" PRId32, (int)enabled, (int32_t)rv);
  prv_sectest_report(buf);
}

void command_security_delays(const char *lock_s, const char *shred_s) {
  char buf[96];
  const uint32_t lock_delay = (uint32_t)atoi(lock_s);
  const uint32_t shred_delay = (uint32_t)atoi(shred_s);
  const status_t rv = security_lock_set_delays(lock_delay, shred_delay);
  snprintf(buf, sizeof(buf), "SECTEST delays lock=%" PRIu32 " shred=%" PRIu32 " rv=%" PRId32,
           lock_delay, shred_delay, (int32_t)rv);
  prv_sectest_report(buf);
}

//! Seconds from now, so a test can arm a deadline that expires while it
//! watches. 0 disarms, matching the record's own convention.
//!
//! Always a disconnect countdown: this pokes the record the way a disconnect
//! would, so what it arms is retired by the next reconnect. `security lockdown`
//! is the way to reach a manual one, which goes through the real funnel.
void command_security_deadlines(const char *lock_in_s, const char *shred_in_s) {
  char buf[96];
  const time_t now = rtc_get_time();
  const int lock_in = atoi(lock_in_s);
  const int shred_in = atoi(shred_in_s);
  const status_t rv = security_lock_set_deadlines((lock_in == 0) ? 0 : now + lock_in,
                                                  (shred_in == 0) ? 0 : now + shred_in,
                                                  SecurityCountdownDisconnect);
  snprintf(buf, sizeof(buf), "SECTEST deadlines lock_in=%d shred_in=%d rv=%" PRId32, lock_in,
           shred_in, (int32_t)rv);
  prv_sectest_report(buf);
}

typedef struct SecuritySessionInfo {
  struct pbl_sem interlock;
  bool is_open;
} SecuritySessionInfo;

//! On the launcher task because that is where the real event is dispatched
//! from, and the handler queues further launcher work of its own.
static void prv_security_session_cb(void *ctx) {
  SecuritySessionInfo *info = ctx;
  const PebbleCommSessionEvent event = {
      .is_open = info->is_open,
      .is_system = true,
  };
  security_lock_handle_comm_session_event(&event);
  pbl_sem_give(&info->interlock);
}

//! Fake a phone connecting or disconnecting, so the disconnect deadlines can be
//! exercised with no phone anywhere near the watch.
void command_security_session(const char *is_open_str) {
  SecuritySessionInfo info = {
      .is_open = (is_open_str[0] != '0'),
  };
  pbl_sem_init(&info.interlock, 0, 1);

  launcher_task_add_callback(prv_security_session_cb, &info);
  pbl_sem_take(&info.interlock, PBL_FOREVER);
  pbl_sem_deinit(&info.interlock);

  char buf[96];
  const time_t now = rtc_get_time();
  const time_t lock_deadline = security_lock_get_lock_deadline();
  const time_t shred_deadline = security_lock_get_shred_deadline();
  // countdown= is what makes a reconnect that leaves a manual countdown alone
  // distinguishable from one that cleared it and rearmed something identical.
  snprintf(buf, sizeof(buf), "SECTEST session open=%d state=%d lock_in=%d shred_in=%d countdown=%d",
           (int)info.is_open, (int)security_lock_get_state(),
           (lock_deadline == 0) ? -1 : (int)(lock_deadline - now),
           (shred_deadline == 0) ? -1 : (int)(shred_deadline - now),
           (int)security_lock_get_countdown_source());
  prv_sectest_report(buf);
}

//! 1 sets the bit and therefore suppresses the boot wipe; 0 clears it and
//! restores normal behaviour.
void command_security_boot_wipe(const char *skip_str) {
  char buf[96];
  const bool skip = (skip_str[0] != '0');
  if (skip) {
    boot_bit_set(BOOT_BIT_SECURITY_SKIP_BOOT_WIPE);
  } else {
    boot_bit_clear(BOOT_BIT_SECURITY_SKIP_BOOT_WIPE);
  }
  snprintf(buf, sizeof(buf), "SECTEST boot_wipe skip=%d", (int)skip);
  prv_sectest_report(buf);
}
