/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include "popups/security/lock_screen.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <pbl/logging/logging.h>
#include "applib/ui/window_stack.h"
#include "kernel/event_loop.h"
#include "kernel/ui/modals/modal_manager.h"
#include "popups/security/pin_entry_window.h"
#include "pbl/services/i18n/i18n.h"
#include "pbl/services/security_lock.h"
#include "pbl/services/security_lock_shred.h"
#include "pbl/services/security_lock_ui.h"
#include "pbl/services/touch/touch.h"
#include "system/passert.h"

//! Statically allocated on purpose. There is only ever one lock screen, and
//! locking must not be able to fail for want of a few hundred bytes of heap at
//! exactly the moment the watch is being taken off someone.
static SecurityPinEntryWindow s_pin_window;
static bool s_visible;

//! The window keeps a pointer rather than a copy, so this has to outlive it.
static char s_title[24];

//! The global touch setting as we found it, so forcing it on for the pad does
//! not quietly turn it on for good.
static bool s_touch_was_enabled = true;

static void prv_shred_callback(void *unused) {
  security_lock_shred(SecurityShredReasonPinAttemptsExhausted);
}

static void prv_show_failure(uint8_t attempts_remaining) {
  char message[SECURITY_PIN_MESSAGE_BUF_SIZE];

  if (security_lock_attempts_exhausted()) {
    PBL_LOG_WRN("PIN attempts exhausted, re-shredding");
    i18n_get_with_buffer(i18n_noop("Wrong PIN. Data erased."), message, sizeof(message));
    // Deferred so the message reaches the screen first: the shred holds
    // KernelMain for seconds while sectors erase.
    launcher_task_add_callback(prv_shred_callback, NULL);
  } else {
    char format[SECURITY_PIN_MESSAGE_BUF_SIZE];
    i18n_get_with_buffer((attempts_remaining == 1) ? i18n_noop("Wrong PIN, 1 try left")
                                                   : i18n_noop("Wrong PIN, %u tries left"),
                         format, sizeof(format));
    sniprintf(message, sizeof(message), format, attempts_remaining);
  }

  security_pin_entry_window_set_message(&s_pin_window, message);
}

static void prv_submit(const char *digits, uint8_t len, void *context) {
  uint8_t attempts_remaining = 0;
  const bool matched = security_lock_verify_pin(digits, len, &attempts_remaining);

  if (matched) {
    PBL_LOG_DBG("PIN accepted");
    security_lock_disengage();
    return;
  }

  PBL_LOG_DBG("PIN rejected, %" PRIu8 " attempts left", attempts_remaining);
  prv_show_failure(attempts_remaining);
}

//! BACK hides the pad. It does not unlock anything: the state stays Locked, the
//! UI lockout stays held, and the next button press raises the pad again from
//! launcher_handle_button_event().
//!
//! Done here rather than by letting the window stack pop the window, because
//! s_visible and the forced touch setting are ours to unwind.
static void prv_dismiss(void *unused) {
  PBL_LOG_DBG("Lock screen dismissed; still locked");
  security_lock_screen_pop();
}

void security_lock_screen_push(void) {
  PBL_ASSERT_TASK(PebbleTask_KernelMain);

  if (s_visible) {
    return;
  }

  const uint8_t pin_len = security_lock_get_pin_len();
  if (pin_len < SECURITY_LOCK_PIN_MIN_LEN || pin_len > SECURITY_LOCK_PIN_MAX_LEN) {
    // A screen with no PIN to satisfy is a screen with no way past it. Leave
    // the clock alone rather than bricking the watch.
    PBL_LOG_ERR("Locked with no usable PIN (len %" PRIu8 "); not raising lock screen", pin_len);
    return;
  }

  i18n_get_with_buffer(i18n_noop("Locked"), s_title, sizeof(s_title));

  security_pin_entry_window_init(&s_pin_window, pin_len, prv_submit, NULL);
  security_pin_entry_window_set_dismiss_cb(&s_pin_window, prv_dismiss);
  security_pin_entry_window_set_title(&s_pin_window, s_title);

  // The pad is the only way in, so the global touch switch cannot be allowed to
  // stand between the user and their watch. Someone who turned touch off for a
  // swim and then locked would otherwise have no input at all, and a reboot
  // re-shreds and comes back locked -- an unrecoverable watch. Restored on the
  // way out so the user's setting survives the lock.
  s_touch_was_enabled = touch_service_is_globally_enabled();
  if (!s_touch_was_enabled) {
    PBL_LOG_DBG("Forcing touch on for the lock screen");
    touch_service_set_globally_enabled(true);
  }

  // engage() already did this when the watch locked, but a watch that rebooted
  // into the locked state never ran it. Idempotent.
  security_lock_ui_lockout();

  // Anything already on screen is by definition not the lock screen.
  modal_manager_pop_all();
  modal_window_push(&s_pin_window.window, SECURITY_LOCK_MODAL_PRIORITY, true /* animated */);
  s_visible = true;

  PBL_LOG_DBG("Lock screen up, prompting for %" PRIu8 " digits", pin_len);
}

void security_lock_screen_pop(void) {
  if (!s_visible) {
    return;
  }
  s_visible = false;
  security_pin_entry_window_reset(&s_pin_window);
  window_stack_remove(&s_pin_window.window, true /* animated */);

  if (!s_touch_was_enabled) {
    touch_service_set_globally_enabled(false);
  }
}

bool security_lock_screen_is_visible(void) {
  return s_visible;
}

const SecurityPinEntryWindow *security_lock_screen_get_pin_window(void) {
  return s_visible ? &s_pin_window : NULL;
}
