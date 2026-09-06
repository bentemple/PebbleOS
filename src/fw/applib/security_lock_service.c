/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include "security_lock_service.h"
#include "security_lock_service_private.h"

#include "event_service_client.h"
#include "kernel/events.h"
#include "process_state/app_state/app_state.h"
#include "process_state/worker_state/worker_state.h"
#include "syscall/syscall.h"
#include "system/passert.h"

static SecurityLockServiceState *prv_get_state(void) {
  PebbleTask task = pebble_task_get_current();

  if (task == PebbleTask_App) {
    return app_state_get_security_lock_service_state();
  } else if (task == PebbleTask_Worker) {
    return worker_state_get_security_lock_service_state();
  }

  WTF;
}

//! Only the new state is forwarded. The lock service knows why the watch
//! locked and which PIN unlocked it, and neither may reach an app: one of the
//! PINs unlocks while silently wiping, and a difference here would give away
//! that it was used.
static void prv_do_handle(PebbleEvent *e, void *context) {
  SecurityLockServiceState *state = prv_get_state();
  if (state->handler != NULL) {
    state->handler(e->security_lock.is_locked);
  }
}

bool security_lock_service_peek_is_locked(void) {
  return sys_security_lock_is_locked();
}

void security_lock_service_subscribe(SecurityLockHandler handler) {
  SecurityLockServiceState *state = prv_get_state();
  state->handler = handler;
  event_service_client_subscribe(&state->sls_info);
}

void security_lock_service_unsubscribe(void) {
  SecurityLockServiceState *state = prv_get_state();
  event_service_client_unsubscribe(&state->sls_info);
  state->handler = NULL;
}

// Not gated on CONFIG_SERVICE_SECURITY_LOCK: the event type exists on every
// board, so on a board without the feature this subscribes to something that
// never fires and the SDK surface stays identical everywhere. The syscall
// answers false there for the same reason.
void security_lock_service_state_init(SecurityLockServiceState *state) {
  *state = (SecurityLockServiceState) {
    .sls_info = {
      .type = PEBBLE_SECURITY_LOCK_EVENT,
      .handler = prv_do_handle,
    },
  };
}
