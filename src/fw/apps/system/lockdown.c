/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include "lockdown.h"

#ifdef CONFIG_SERVICE_SECURITY_LOCK

#include "applib/app.h"
#include "applib/ui/app_window_stack.h"
#include "applib/ui/dialogs/simple_dialog.h"
#include "applib/ui/window.h"
#include "applib/ui/window_private.h"
#include "kernel/event_loop.h"
#include "kernel/pbl_malloc.h"
#include "pbl/services/i18n/i18n.h"
#include "pbl/services/security_lock.h"
#include "pbl/services/security_lock_shred.h"
#include "pbl/services/security_lock_ui.h"
#include <pbl/logging/logging.h>
#include "process_state/app_state/app_state.h"
#include "resource/resource_ids.auto.h"
#include "shell/prefs.h"

//! Long enough to read a sentence. The app has nothing else to show and closes
//! when this pops.
#define UNAVAILABLE_MESSAGE_TIMEOUT_MS 3000

#define UNAVAILABLE_MESSAGE_BUF_SIZE 96

//! Whether engaging would actually lock anything.
//!
//! The master switch, and the same PIN bounds security_lock_engage() applies: a
//! stored length outside them is one the lock screen could never prompt for.
//! engage() refuses on both, so an app that ignored them would do nothing at
//! all and say nothing about it.
static bool prv_lock_is_available(void) {
  const uint8_t pin_len = security_lock_get_pin_len();
  return security_lock_is_enabled() && (pin_len >= SECURITY_LOCK_PIN_MIN_LEN) &&
         (pin_len <= SECURITY_LOCK_PIN_MAX_LEN);
}

//! Say why, and erase nothing.
//!
//! Reachable despite the app being hidden: a Quick Launch binding is an install
//! id in prefs, and neither clearing the PIN nor turning the feature off
//! touches it. Silence would leave the user with a chord that stopped working
//! and no reason given.
static void prv_show_lock_unavailable(void) {
  SimpleDialog *simple_dialog = simple_dialog_create(WINDOW_NAME("Lockdown"));
  if (!simple_dialog) {
    // The app exits on an empty window stack, which is still the right outcome.
    PBL_LOG_ERR("Could not create the Lockdown unavailable message");
    return;
  }

  char text[UNAVAILABLE_MESSAGE_BUF_SIZE];
  /// Shown when Lockdown is opened while the security lock is off or has no
  /// PIN. It erases the watch's copy of the phone's content and locks behind
  /// the PIN, so without either there is nothing to lock and it refuses to run.
  /// Covers both cases: turning the switch on with no PIN asks for one.
  i18n_get_with_buffer(i18n_noop("Turn on Security Lock in Settings to use Lockdown"), text,
                       sizeof(text));

  Dialog *dialog = simple_dialog_get_dialog(simple_dialog);
  dialog_set_text(dialog, text);
  dialog_set_icon(dialog, RESOURCE_ID_GENERIC_WARNING_LARGE);
  dialog_set_timeout(dialog, UNAVAILABLE_MESSAGE_TIMEOUT_MS);
  app_simple_dialog_push(simple_dialog);
}

//! Runs on KernelMain, which the lock funnel asserts on: it drives the app and
//! modal stacks.
//!
//! The countdown rather than an immediate erase. This app is the one trigger
//! that can be reached by accident -- a Quick Launch chord in a pocket, a
//! misremembered binding, the wrong launcher row -- and locking without a timed
//! erase is not an option either: a user who wants that sets Erase After to
//! Never, which this path honours by arming nothing. Erasing on the spot is a
//! separate action and lives in Settings, where it cannot be hit by mistake.
//!
//! Closing this app is part of what it does -- security_lock_ui_quiesce() calls
//! app_manager_close_current_app() and lands on the watchface -- so there is
//! nothing to do afterwards and nothing here that outlives the call.
static void prv_engage_callback(void *unused) {
  security_lock_engage_with_countdown(SecurityShredReasonManualPanic);
}

static void prv_main(void) {
  if (!prv_lock_is_available()) {
    prv_show_lock_unavailable();
    app_event_loop();
    return;
  }

  // A window with nothing in it, purely to keep the app alive for the handful
  // of milliseconds before the kernel closes it. app_event_loop()'s first act
  // is to kill any app whose window stack is empty, and that kill event would
  // race the hand-over below: the app would already be closing, or gone and
  // replaced, by the time engage() ran.
  Window *window = app_malloc_check(sizeof(*window));
  app_state_set_user_data(window);

  window_init(window, WINDOW_NAME("Lockdown"));
  window_set_background_color(window, GColorBlack);
  // Same reason: BACK popping the only window would take the stack to empty.
  // There is nothing to back out of anyway, which is the point of the app.
  window_set_overrides_back_button(window, true);
  app_window_stack_push(window, false /* animated */);

  // No confirmation, deliberately. A panic button that asks is a worse panic
  // button, and nothing is destroyed by the time it runs: the erase it starts
  // is one the PIN calls off, so a mistaken tap costs a PIN entry.
  launcher_task_add_callback(prv_engage_callback, NULL);

  app_event_loop();

  app_free(window);
}

//! Static records rather than one mutable one. The registry calls this on every
//! enumeration and from more than one task, so reading the PIN and the
//! preference here leaves nothing to invalidate and nothing to write.
//!
//! They differ only in visibility, and must keep differing only in that: Quick
//! Launch stores an install id resolved from the UUID, so a binding made while
//! the app was listed has to survive it being unlisted.
const PebbleProcessMd *lockdown_app_get_app_info(void) {
  static const PebbleProcessMdSystem s_listed = {
    .common = {
      .main_func = prv_main,
      .uuid = LOCKDOWN_UUID,
      .visibility = ProcessVisibilityShown,
    },
    .name = i18n_noop("Lockdown"),
    .icon_resource_id = RESOURCE_ID_GENERIC_WARNING_TINY,
  };

  // Hidden from the launcher, still selectable in Quick Launch.
  static const PebbleProcessMdSystem s_unlisted = {
    .common = {
      .main_func = prv_main,
      .uuid = LOCKDOWN_UUID,
      .visibility = ProcessVisibilityQuickLaunch,
    },
    .name = i18n_noop("Lockdown"),
    .icon_resource_id = RESOURCE_ID_GENERIC_WARNING_TINY,
  };

  // Nowhere at all while the feature is off or there is no PIN. Hidden rather
  // than the record above because Quick Launch's picker only filters out
  // entries that are hidden and not Quick-Launch-visible -- and an app that
  // cannot lock does not belong on that list either.
  static const PebbleProcessMdSystem s_unavailable = {
    .common = {
      .main_func = prv_main,
      .uuid = LOCKDOWN_UUID,
      .visibility = ProcessVisibilityHidden,
    },
    .name = i18n_noop("Lockdown"),
    .icon_resource_id = RESOURCE_ID_GENERIC_WARNING_TINY,
  };

  // Outranks the preference: engaging refuses outright in both cases, and a
  // panic button that does nothing is worse than no panic button.
  if (!prv_lock_is_available()) {
    return &s_unavailable.common;
  }

  return shell_prefs_get_lockdown_app_in_launcher() ? &s_listed.common : &s_unlisted.common;
}

#endif  // CONFIG_SERVICE_SECURITY_LOCK
