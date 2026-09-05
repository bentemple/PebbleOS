/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include "security_shred_service.h"
#include "security_shred_service_private.h"

#include "event_service_client.h"
#include "kernel/events.h"
#include "process_state/app_state/app_state.h"
#include "process_state/worker_state/worker_state.h"
#include "system/passert.h"

static SecurityShredServiceState *prv_get_state(void) {
  PebbleTask task = pebble_task_get_current();

  if (task == PebbleTask_App) {
    return app_state_get_security_shred_service_state();
  } else if (task == PebbleTask_Worker) {
    return worker_state_get_security_shred_service_state();
  }

  WTF;
}

//! The event's reason code is deliberately not forwarded. The one wipe worth
//! telling apart -- the duress PIN -- is not published at all, because dropping
//! the reason here would still leave the event itself observable next to an
//! unlock; this is the second half of the same rule, so nothing downstream can
//! reintroduce it.
static void prv_do_handle(PebbleEvent *e, void *context) {
  SecurityShredServiceState *state = prv_get_state();
  if (state->handler != NULL) {
    state->handler();
  }
}

void security_shred_service_subscribe(SecurityShredHandler handler) {
  SecurityShredServiceState *state = prv_get_state();
  state->handler = handler;
  event_service_client_subscribe(&state->sss_info);
}

void security_shred_service_unsubscribe(void) {
  SecurityShredServiceState *state = prv_get_state();
  event_service_client_unsubscribe(&state->sss_info);
  state->handler = NULL;
}

// Not gated on CONFIG_SERVICE_SECURITY_LOCK: the event type exists on every
// board, so on a board without the feature this subscribes to something that
// never fires and the SDK surface stays identical everywhere.
void security_shred_service_state_init(SecurityShredServiceState *state) {
  *state = (SecurityShredServiceState) {
    .sss_info = {
      .type = PEBBLE_SECURITY_SHRED_EVENT,
      .handler = prv_do_handle,
    },
  };
}
