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

//! Whether the user has opted into erasing at all.
//!
//! Erase After is the one place that opt-in is expressed, so it gates the
//! erasing app as well as the countdown. A user who has said "never erase on a
//! timer" is not offered a chord that erases with no timer at all.
static bool prv_erase_is_enabled(void) {
  return security_lock_get_shred_delay_s() != SECURITY_LOCK_SHRED_DELAY_NEVER;
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

//! Erase on the spot, which is the whole difference from the app above.
//!
//! Degrades to that app rather than refusing when Erase After has been set to
//! Never since the binding was made. The record Quick Launch keeps is an
//! install id, which nothing about changing that setting touches, so this is
//! reachable with erasing switched off. A panic chord that did nothing would be
//! the worst reading of it: locking is never the wrong half to do, and the
//! countdown path honours Never by arming nothing.
static void prv_engage_erase_callback(void *unused) {
  if (!prv_erase_is_enabled()) {
    PBL_LOG_WRN("Lockdown + Erase with the erase turned off; locking only");
    security_lock_engage_with_countdown(SecurityShredReasonManualPanic);
    return;
  }
  security_lock_engage(SecurityShredReasonManualPanic);
}

//! @param window_name already through WINDOW_NAME(), which compiles out in a
//!                    release build
//! @param engage which funnel to hand over to, on the launcher task
static void prv_run(const char *window_name, void (*engage)(void *)) {
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

  window_init(window, window_name);
  window_set_background_color(window, GColorBlack);
  // Same reason: BACK popping the only window would take the stack to empty.
  // There is nothing to back out of anyway, which is the point of the app.
  window_set_overrides_back_button(window, true);
  app_window_stack_push(window, false /* animated */);

  // No confirmation, deliberately. A panic button that asks is a worse panic
  // button, and reaching either of these takes a Quick Launch binding the user
  // made on purpose or a launcher row they chose.
  launcher_task_add_callback(engage, NULL);

  app_event_loop();

  app_free(window);
}

static void prv_main(void) {
  prv_run(WINDOW_NAME("Lockdown"), prv_engage_callback);
}

static void prv_erase_main(void) {
  prv_run(WINDOW_NAME("Lockdown + Erase"), prv_engage_erase_callback);
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

//! Quick Launch or nowhere -- there is deliberately no listed record.
//!
//! The launcher is somewhere a user lands by accident, and this is the one
//! manual trigger the PIN cannot call back. Reaching it should take a binding
//! made on purpose, or the Settings row, which asks first. That also leaves
//! Show in Launcher meaning exactly what it says, rather than one switch
//! quietly governing two apps with very different consequences.
//!
//! Erase After gates it, so a user who has not opted into erasing is never
//! offered a chord that erases. A binding that outlives the setting is handled
//! at the other end, in prv_engage_erase_callback().
const PebbleProcessMd *lockdown_erase_app_get_app_info(void) {
  static const PebbleProcessMdSystem s_quick_launch = {
    .common = {
      .main_func = prv_erase_main,
      .uuid = LOCKDOWN_ERASE_UUID,
      .visibility = ProcessVisibilityQuickLaunch,
    },
    .name = i18n_noop("Lockdown + Erase"),
    .icon_resource_id = RESOURCE_ID_GENERIC_WARNING_TINY,
  };

  static const PebbleProcessMdSystem s_unavailable = {
    .common = {
      .main_func = prv_erase_main,
      .uuid = LOCKDOWN_ERASE_UUID,
      .visibility = ProcessVisibilityHidden,
    },
    .name = i18n_noop("Lockdown + Erase"),
    .icon_resource_id = RESOURCE_ID_GENERIC_WARNING_TINY,
  };

  if (!prv_lock_is_available() || !prv_erase_is_enabled()) {
    return &s_unavailable.common;
  }
  return &s_quick_launch.common;
}

#endif  // CONFIG_SERVICE_SECURITY_LOCK
