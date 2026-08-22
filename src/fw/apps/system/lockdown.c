/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include "lockdown.h"

#ifdef CONFIG_SERVICE_SECURITY_LOCK

#include "applib/app.h"
#include "applib/ui/app_window_stack.h"
#include "applib/ui/window.h"
#include "applib/ui/window_private.h"
#include "kernel/event_loop.h"
#include "kernel/pbl_malloc.h"
#include "pbl/services/i18n/i18n.h"
#include "pbl/services/security_lock_shred.h"
#include "pbl/services/security_lock_ui.h"
#include "process_state/app_state/app_state.h"
#include "resource/resource_ids.auto.h"
#include "shell/prefs.h"

//! Runs on KernelMain, which security_lock_engage() asserts on: it drives the
//! app and modal stacks and holds the task for the length of the erase.
//!
//! Closing this app is part of what it does -- security_lock_ui_quiesce() calls
//! app_manager_close_current_app() and lands on the watchface -- so there is
//! nothing to do afterwards and nothing here that outlives the call.
static void prv_engage_callback(void *unused) {
  security_lock_engage(SecurityShredReasonManualPanic);
}

static void prv_main(void) {
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
  // button, and everything the erase destroys comes back from the phone on
  // reconnect -- a mistaken tap costs a resync, not data.
  launcher_task_add_callback(prv_engage_callback, NULL);

  app_event_loop();

  app_free(window);
}

//! Two records rather than one mutable one. The registry calls this on every
//! enumeration and from more than one task, so reading the preference here
//! leaves nothing to invalidate and nothing to write.
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

  return shell_prefs_get_lockdown_app_in_launcher() ? &s_listed.common : &s_unlisted.common;
}

#endif  // CONFIG_SERVICE_SECURITY_LOCK
