/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include "clar.h"

#include "applib/security_shred_service.h"
#include "applib/security_shred_service_private.h"
#include "kernel/events.h"
#include "kernel/pebble_tasks.h"
#include "pbl/services/security_lock_shred.h"

#include <stdbool.h>
#include <stdint.h>

// Stubs
#include "stubs_logging.h"
#include "stubs_passert.h"

// The API decision this service exists to enforce: the callback carries
// nothing, so no shred reason -- SecurityShredReasonDuressPin above all -- can
// reach a third-party app.
_Static_assert(__builtin_types_compatible_p(SecurityShredHandler, void (*)(void)),
               "SecurityShredHandler must take no arguments");

// Fake event service
//////////////////////////////////////////
static int s_subscribe_count;
static int s_unsubscribe_count;
static EventServiceInfo *s_subscribed_info;

void event_service_client_subscribe(EventServiceInfo *info) {
  s_subscribe_count++;
  s_subscribed_info = info;
}

void event_service_client_unsubscribe(EventServiceInfo *info) {
  s_unsubscribe_count++;
  cl_assert_equal_p(info, s_subscribed_info);
  s_subscribed_info = NULL;
}

// Task / state plumbing so prv_get_state() resolves to our test state
//////////////////////////////////////////
static SecurityShredServiceState s_app_state;
static SecurityShredServiceState s_worker_state;
static PebbleTask s_current_task;

PebbleTask pebble_task_get_current(void) {
  return s_current_task;
}

SecurityShredServiceState *app_state_get_security_shred_service_state(void) {
  return &s_app_state;
}

SecurityShredServiceState *worker_state_get_security_shred_service_state(void) {
  return &s_worker_state;
}

// Handler bookkeeping
//////////////////////////////////////////
static int s_handler_calls;

static void prv_handler(void) {
  s_handler_calls++;
}

static int s_other_handler_calls;

static void prv_other_handler(void) {
  s_other_handler_calls++;
}

//! Publish a shred event the way the event service would.
static void prv_deliver_shred(SecurityShredReason reason) {
  cl_assert(s_subscribed_info != NULL);
  PebbleEvent e = {
    .type = PEBBLE_SECURITY_SHRED_EVENT,
    .security_shred = {.reason = (uint8_t)reason},
  };
  s_subscribed_info->handler(&e, s_subscribed_info->context);
}

// setup
//////////////////////////////////////////
void test_security_shred_service__initialize(void) {
  s_subscribe_count = 0;
  s_unsubscribe_count = 0;
  s_subscribed_info = NULL;
  s_handler_calls = 0;
  s_other_handler_calls = 0;
  s_current_task = PebbleTask_App;
  security_shred_service_state_init(&s_app_state);
  security_shred_service_state_init(&s_worker_state);
}

void test_security_shred_service__cleanup(void) {
}

// tests
//////////////////////////////////////////

// The state is wired to the shred event and starts with no handler.
void test_security_shred_service__state_init(void) {
  cl_assert_equal_i(s_app_state.sss_info.type, PEBBLE_SECURITY_SHRED_EVENT);
  cl_assert(s_app_state.sss_info.handler != NULL);
  cl_assert(s_app_state.handler == NULL);
}

// Subscribing registers with the event service and records the handler.
void test_security_shred_service__subscribe_registers(void) {
  security_shred_service_subscribe(prv_handler);

  cl_assert_equal_i(s_subscribe_count, 1);
  cl_assert_equal_p(s_subscribed_info, &s_app_state.sss_info);
  cl_assert(s_app_state.handler == prv_handler);
}

// A delivered event reaches the subscriber.
void test_security_shred_service__event_reaches_handler(void) {
  security_shred_service_subscribe(prv_handler);

  prv_deliver_shred(SecurityShredReasonPhoneLockdown);

  cl_assert_equal_i(s_handler_calls, 1);
}

// Every reason produces exactly the same callback. A duress wipe must be
// indistinguishable from any other wipe to an app.
void test_security_shred_service__reason_is_not_observable(void) {
  security_shred_service_subscribe(prv_handler);

  const SecurityShredReason reasons[] = {
    SecurityShredReasonUnknown,
    SecurityShredReasonPhoneLockdown,
    SecurityShredReasonManualPanic,
    SecurityShredReasonDisconnectTimeout,
    SecurityShredReasonRebootWhileLocked,
    SecurityShredReasonPinAttemptsExhausted,
    SecurityShredReasonClockRollback,
    SecurityShredReasonDuressPin,
  };

  for (size_t i = 0; i < sizeof(reasons) / sizeof(reasons[0]); ++i) {
    prv_deliver_shred(reasons[i]);
  }

  cl_assert_equal_i(s_handler_calls, (int)(sizeof(reasons) / sizeof(reasons[0])));
}

// Unsubscribing drops the registration and the handler.
void test_security_shred_service__unsubscribe(void) {
  security_shred_service_subscribe(prv_handler);
  security_shred_service_unsubscribe();

  cl_assert_equal_i(s_unsubscribe_count, 1);
  cl_assert(s_app_state.handler == NULL);
}

// Re-subscribing replaces the handler rather than stacking a second one.
void test_security_shred_service__resubscribe_replaces_handler(void) {
  security_shred_service_subscribe(prv_handler);
  security_shred_service_subscribe(prv_other_handler);

  prv_deliver_shred(SecurityShredReasonManualPanic);

  cl_assert_equal_i(s_handler_calls, 0);
  cl_assert_equal_i(s_other_handler_calls, 1);
}

// A NULL handler is tolerated, including for an event that arrives after an
// unsubscribe has already been queued behind it.
void test_security_shred_service__null_handler_is_safe(void) {
  security_shred_service_subscribe(prv_handler);
  EventServiceInfo *info = s_subscribed_info;
  security_shred_service_unsubscribe();

  s_subscribed_info = info;
  prv_deliver_shred(SecurityShredReasonDuressPin);

  cl_assert_equal_i(s_handler_calls, 0);
}

// Workers get their own state, so a worker subscribing does not disturb the
// app's registration.
void test_security_shred_service__worker_has_its_own_state(void) {
  s_current_task = PebbleTask_Worker;
  security_shred_service_subscribe(prv_handler);

  cl_assert_equal_p(s_subscribed_info, &s_worker_state.sss_info);
  cl_assert(s_worker_state.handler == prv_handler);
  cl_assert(s_app_state.handler == NULL);

  prv_deliver_shred(SecurityShredReasonClockRollback);
  cl_assert_equal_i(s_handler_calls, 1);
}
