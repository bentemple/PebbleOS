/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include "pbl/services/security_lock_ui.h"

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

static void prv_release_ui_lockout(void) {
  if (!s_ui_lockout_held) {
    return;
  }
  s_ui_lockout_held = false;
  launcher_block_popups(false);
  modal_manager_set_min_priority(ModalPriorityMin);
}

void security_lock_engage(SecurityShredReason reason) {
  PBL_ASSERT_TASK(PebbleTask_KernelMain);

  const uint8_t pin_len = security_lock_get_pin_len();
  if (pin_len < SECURITY_LOCK_PIN_MIN_LEN || pin_len > SECURITY_LOCK_PIN_MAX_LEN) {
    PBL_LOG_WRN("No PIN configured; shredding without locking");
    security_lock_shred(reason);
    return;
  }

  PBL_LOG_DBG("Engaging lock: %s", security_lock_shred_reason_str(reason));

  security_lock_set_state(SecurityLockStateLocked);
  security_lock_ui_lockout();

  // BACK may be held down right now. Left alone, the 1.5s timer would fire
  // after the lockout is up and force quit whatever we just launched.
  launcher_cancel_force_quit();

  // Whatever is on screen may well be the notification that prompted this.
  modal_manager_pop_all();
  app_manager_close_current_app(true /* gracefully */);
  watchface_launch_default(NULL);

  // Repaint before shredding rather than after. The shred holds KernelMain for
  // seconds, and nothing else would flush the framebuffer for that whole time,
  // so a notification drawn a moment ago would sit on the display throughout.
  compositor_render_app();
  if (!compositor_display_update_in_progress()) {
    compositor_display_update(NULL);
  }

  security_lock_shred(reason);
}

void security_lock_disengage(void) {
  PBL_ASSERT_TASK(PebbleTask_KernelMain);

  security_lock_screen_pop();
  prv_release_ui_lockout();
  security_lock_set_state(SecurityLockStateArmed);

  PBL_LOG_DBG("Unlocked");
}
