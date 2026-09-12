/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include "pbl/services/security_lock_endpoint.h"
#include "pbl/services/security_lock_ui.h"
#include "pbl/services/system_task.h"

#include <inttypes.h>

#include <pbl/logging/logging.h>
#include "kernel/event_loop.h"
#include "kernel/ui/modals/modal_manager.h"
#include "popups/alarm_popup.h"
#include "popups/security/lock_screen.h"
#include "process_management/app_manager.h"
#include "pbl/services/compositor/compositor.h"
#include "pbl/services/compositor/compositor_display.h"
#include "pbl/services/security_lock.h"
#include "pbl/services/security_lock_endpoint.h"
#include "shell/normal/watchface.h"
#include "system/passert.h"

PBL_LOG_MODULE_DECLARE(service_security_lock, CONFIG_SERVICE_SECURITY_LOCK_LOG_LEVEL);

//! Tracks the launcher_block_popups_for_lock() reference we hold. That count
//! asserts on underflow and engage() is documented as safe to call twice, so
//! the lockout has to be idempotent in both directions.
static bool s_ui_lockout_held;

void security_lock_ui_lockout(void) {
  if (s_ui_lockout_held) {
    return;
  }
  s_ui_lockout_held = true;

  // Keep notification and battery popups off the clock. Alarms are the one
  // exemption, and only until the content is actually erased -- see
  // launcher_block_popups_for_lock(). This is also what the phone UI reads.
  launcher_block_popups_for_lock(true);

  // Bound at the lock screen's own level, which lets exactly two things
  // through: the lock screen, and the alarm one level above it. Everything
  // below is shut out.
  //
  // Deliberately not ModalPriorityMax, which the panic and critical-battery
  // paths use: that reports modals as disabled outright, which would stop the
  // lock screen itself from being pushed, rendered or given button events.
  //
  // The floor rather than the plain setter: the battery FSM drops the same
  // bound to ModalPriorityMin on leaving low power, and nothing here would
  // re-assert it.
  modal_manager_set_min_priority_floor(SECURITY_LOCK_MODAL_PRIORITY);
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
    // The bound above spares the lock screen, and the alarm sits above the lock
    // screen -- so a ringing alarm would carry on buzzing straight through the
    // wipe and after it. Named rather than popped by priority, because there is
    // no range that takes the alarm and leaves the pad.
    alarm_popup_close();
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
  launcher_block_popups_for_lock(false);
  modal_manager_set_min_priority_floor(ModalPriorityMin);
}

//! What locking should leave behind it.
typedef enum {
  //! Erase now. The triggers that mean "the content goes, and it goes now":
  //! Lockdown + Erase, and the escalation paths.
  EngageEraseNow,
  //! Lock and arm nothing. For the disconnect lock deadline, where the same
  //! disconnect already armed the erase deadline.
  EngageArmNothing,
  //! Lock and start the erase countdown. Every manual trigger.
  EngageArmCountdown,
} EngageAction;

static void prv_engage(SecurityShredReason reason, EngageAction action) {
  PBL_ASSERT_TASK(PebbleTask_KernelMain);

  // One of the two funnels the master switch is enforced at, so a trigger that
  // forgets to ask is covered anyway. security_lock_shred() holds the other.
  if (!security_lock_is_enabled()) {
    PBL_LOG_WRN("Security lock is off; ignoring %s", security_lock_shred_reason_str(reason));
    return;
  }

  const uint8_t pin_len = security_lock_get_pin_len();
  if (!security_lock_pin_len_is_valid(pin_len)) {
    // Enabled with an unusable PIN is an inconsistent record, not a state any
    // control produces. Erasing anyway would destroy the content of a watch
    // that was never protected and leave it wide open afterwards.
    PBL_LOG_ERR("Enabled with an unusable PIN length %" PRIu8 "; refusing to lock", pin_len);
    return;
  }

  PBL_LOG_INFO("Engaging lock: %s", security_lock_shred_reason_str(reason));

  security_lock_set_state(SecurityLockStateLocked);
  security_lock_ui_lockout();

  if (action != EngageEraseNow) {
    // After the lock has taken, so a refusal above leaves no countdown behind
    // to erase a watch that was never locked. Before the quiesce, which
    // repaints the display: the record is what survives a power cut here.
    if (action == EngageArmCountdown) {
      security_lock_endpoint_arm_manual_countdown();
    }
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
  prv_engage(reason, EngageEraseNow);
}

void security_lock_engage_lock_only(SecurityShredReason reason) {
  prv_engage(reason, EngageArmNothing);
}

void security_lock_engage_with_countdown(SecurityShredReason reason) {
  prv_engage(reason, EngageArmCountdown);
}

void security_lock_disengage(void) {
  PBL_ASSERT_TASK(PebbleTask_KernelMain);

  security_lock_screen_pop();
  prv_release_ui_lockout();
  security_lock_set_state(SecurityLockStateArmed);
  security_lock_endpoint_send_state_changed(SecurityLockStateArmed);

  PBL_LOG_DBG("Unlocked");
}
