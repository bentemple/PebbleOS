/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include "pbl/services/security_lock_endpoint.h"
#include "pbl/services/security_lock_ui.h"
#include "pbl/services/system_task.h"

#include <inttypes.h>

#include <pbl/logging/logging.h>
#include "kernel/event_loop.h"
#include "kernel/ui/modals/modal_manager.h"
#include "popups/security/lock_screen.h"
#include "process_management/app_manager.h"
#include "pbl/services/compositor/compositor.h"
#include "pbl/services/compositor/compositor_display.h"
#include "pbl/services/security_lock.h"
#include "shell/normal/watchface.h"
#include "system/passert.h"

PBL_LOG_MODULE_DECLARE(service_security_lock, CONFIG_SERVICE_SECURITY_LOCK_LOG_LEVEL);

//! Tracks the launcher_block_popups() reference we hold. That count asserts on
//! underflow and engage() is documented as safe to call twice, so the lockout
//! has to be idempotent in both directions.
static bool s_ui_lockout_held;

void security_lock_ui_lockout(void) {
  if (s_ui_lockout_held) {
    return;
  }
  s_ui_lockout_held = true;

  // Keep notification, alarm and battery popups off the clock.
  launcher_block_popups(true);

  // Lock every modal stack below the lock screen's own. Deliberately not
  // ModalPriorityMax, which the panic and critical-battery paths use: that
  // reports modals as disabled outright, which would stop the lock screen
  // itself from being pushed, rendered or given button events.
  modal_manager_set_min_priority(SECURITY_LOCK_MODAL_PRIORITY);
}

void security_lock_ui_quiesce(void) {
  PBL_ASSERT_TASK(PebbleTask_KernelMain);

  // Buttons may be held down right now. Left alone, the BACK 1.5s timer would
  // force quit whatever we launch below, and a half-completed quick launch
  // chord would launch an app straight over the clock -- neither of which the
  // button handler can intercept, because both fire from a timer rather than
  // from an event.
  launcher_cancel_force_quit();
  watchface_reset_click_manager();

  // Whatever is on screen may well be the notification that prompted this, or
  // a timeline peek showing a pin from a database that is about to be zeroed.
  // The lock screen is the one modal that has to survive: it shows only a
  // title and a message, and the duress and attempts-exhausted wipes are
  // triggered from it, so popping it would take away the only feedback there
  // is. It sits above every other stack, so leaving it is a priority bound
  // rather than a special case.
  if (security_lock_screen_is_visible()) {
    modal_manager_pop_all_below_priority(SECURITY_LOCK_MODAL_PRIORITY);
  } else {
    modal_manager_pop_all();
  }

  // A watchface reads none of the shredded databases -- the timeline peek is a
  // modal and has just gone -- so there is nothing to close. Skipping the
  // relaunch also keeps the duress wipe indistinguishable from an ordinary
  // unlock, which lands on exactly this screen.
  if (!app_manager_is_watchface_running()) {
    app_manager_close_current_app(true /* gracefully */);
    watchface_launch_default(NULL);
  }

  // Repaint before shredding rather than after. The shred holds KernelMain for
  // the duration, and nothing else would flush the framebuffer for that whole
  // time, so a notification drawn a moment ago would sit on the display
  // throughout.
  compositor_render_app();
  if (!compositor_display_update_in_progress()) {
    compositor_display_update(NULL);
  }
}

static void prv_release_ui_lockout(void) {
  if (!s_ui_lockout_held) {
    return;
  }
  s_ui_lockout_held = false;
  launcher_block_popups(false);
  modal_manager_set_min_priority(ModalPriorityMin);
}

static void prv_engage(SecurityShredReason reason, bool shred) {
  PBL_ASSERT_TASK(PebbleTask_KernelMain);

  const uint8_t pin_len = security_lock_get_pin_len();
  if (pin_len < SECURITY_LOCK_PIN_MIN_LEN || pin_len > SECURITY_LOCK_PIN_MAX_LEN) {
    if (!shred) {
      PBL_LOG_WRN("No PIN configured; nothing to lock");
      return;
    }
    PBL_LOG_WRN("No PIN configured; shredding without locking");
    security_lock_shred(reason);
    return;
  }

  PBL_LOG_INFO("Engaging lock: %s", security_lock_shred_reason_str(reason));

  security_lock_set_state(SecurityLockStateLocked);
  security_lock_ui_lockout();

  if (!shred) {
    security_lock_ui_quiesce();
    return;
  }

  // Deliberately on this task rather than KernelBG. The wipe closes and
  // reopens pin_db, reminder_db and timeline_event, and factory_reset_fast
  // does the same from the launcher task for a reason: driven from KernelBG
  // they deadlock, which the watchdog used to hide by resetting the watch and
  // now simply hangs it. The freeze while it runs is the same one a factory
  // reset causes, and the slow sector sweep is deferred anyway.
  //
  // Quiescing the UI is the shred's own first step, so this path no longer
  // does it here: doing it twice would close and relaunch an app for nothing.
  security_lock_shred(reason);
}

void security_lock_engage(SecurityShredReason reason) {
  prv_engage(reason, true /* shred */);
}

void security_lock_engage_lock_only(SecurityShredReason reason) {
  prv_engage(reason, false /* shred */);
}

void security_lock_disengage(void) {
  PBL_ASSERT_TASK(PebbleTask_KernelMain);

  security_lock_screen_pop();
  prv_release_ui_lockout();
  security_lock_set_state(SecurityLockStateArmed);
  security_lock_endpoint_send_state_changed(SecurityLockStateArmed);

  PBL_LOG_DBG("Unlocked");
}
