/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include "clar.h"

#include "applib/security_lock_service.h"
#include "applib/security_lock_service_private.h"
#include "kernel/events.h"
#include "kernel/pebble_tasks.h"

#include <setjmp.h>
#include <stdbool.h>
#include <stdint.h>

// Stubs
#include "stubs_logging.h"

// Deliberately not stubs_passert.h: the WTF branch below is worth covering, and
// that header's wtf() calls cl_fail() outright, which cl_assert_passert()
// cannot catch. This one routes through the same machinery a passert does.
void wtf(void) {
  if (clar_expecting_passert) {
    clar_passert_occurred = true;
    longjmp(clar_passert_jmp_buf, 1);
  }
  cl_fail("WTF");
  while (1) {
  }
}

// The API decision this service exists to enforce: the callback carries the new
// state and nothing else. No reason for the lock, no attempt count, and no way
// to tell a duress unlock from an ordinary one.
_Static_assert(__builtin_types_compatible_p(SecurityLockHandler, void (*)(bool)),
               "SecurityLockHandler must take nothing but the new locked state");

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

// Fake syscall, standing in for the kernel-side lock state
//////////////////////////////////////////
static bool s_sys_is_locked;
static int s_sys_peek_calls;

bool sys_security_lock_is_locked(void) {
  s_sys_peek_calls++;
  return s_sys_is_locked;
}

// Task / state plumbing so prv_get_state() resolves to our test state
//////////////////////////////////////////
static SecurityLockServiceState s_app_state;
static SecurityLockServiceState s_worker_state;
static PebbleTask s_current_task;

PebbleTask pebble_task_get_current(void) {
  return s_current_task;
}

SecurityLockServiceState *app_state_get_security_lock_service_state(void) {
  return &s_app_state;
}

SecurityLockServiceState *worker_state_get_security_lock_service_state(void) {
  return &s_worker_state;
}

// Handler bookkeeping
//////////////////////////////////////////
static int s_handler_calls;
static bool s_handler_last_locked;

static void prv_handler(bool is_locked) {
  s_handler_calls++;
  s_handler_last_locked = is_locked;
}

static int s_other_handler_calls;

static void prv_other_handler(bool is_locked) {
  s_other_handler_calls++;
}

//! Publish a lock event the way the event service would.
static void prv_deliver_lock(bool is_locked) {
  cl_assert(s_subscribed_info != NULL);
  PebbleEvent e = {
    .type = PEBBLE_SECURITY_LOCK_EVENT,
    .security_lock = {.is_locked = is_locked},
  };
  s_subscribed_info->handler(&e, s_subscribed_info->context);
}

// setup
//////////////////////////////////////////
void test_security_lock_service__initialize(void) {
  s_subscribe_count = 0;
  s_unsubscribe_count = 0;
  s_subscribed_info = NULL;
  s_sys_is_locked = false;
  s_sys_peek_calls = 0;
  s_handler_calls = 0;
  s_handler_last_locked = false;
  s_other_handler_calls = 0;
  s_current_task = PebbleTask_App;
  security_lock_service_state_init(&s_app_state);
  security_lock_service_state_init(&s_worker_state);
}

void test_security_lock_service__cleanup(void) {
}

// tests
//////////////////////////////////////////

// The state is wired to the lock event and starts with no handler.
void test_security_lock_service__state_init(void) {
  cl_assert_equal_i(s_app_state.sls_info.type, PEBBLE_SECURITY_LOCK_EVENT);
  cl_assert(s_app_state.sls_info.handler != NULL);
  cl_assert(s_app_state.handler == NULL);
}

// The peek asks the kernel every time. It is neither cached nor fed from the
// event stream, so a subscriber whose last event has since gone stale still
// gets the truth -- which is the case a watchface relies on when it renders
// after being launched into an already-locked watch.
void test_security_lock_service__peek_follows_the_kernel_not_the_last_event(void) {
  security_lock_service_subscribe(prv_handler);
  prv_deliver_lock(true);

  s_sys_is_locked = false;
  cl_assert_equal_b(security_lock_service_peek_is_locked(), false);

  s_sys_is_locked = true;
  cl_assert_equal_b(security_lock_service_peek_is_locked(), true);

  // Asked again for the second answer rather than reusing the first.
  cl_assert_equal_i(s_sys_peek_calls, 2);
}

// Peeking works without a subscription.
void test_security_lock_service__peek_without_subscribe(void) {
  s_sys_is_locked = true;

  cl_assert_equal_b(security_lock_service_peek_is_locked(), true);
  cl_assert_equal_i(s_subscribe_count, 0);
}

// Subscribing registers with the event service and records the handler.
void test_security_lock_service__subscribe_registers(void) {
  security_lock_service_subscribe(prv_handler);

  cl_assert_equal_i(s_subscribe_count, 1);
  cl_assert_equal_p(s_subscribed_info, &s_app_state.sls_info);
  cl_assert(s_app_state.handler == prv_handler);
}

// A delivered event reaches the subscriber, carrying the new state.
void test_security_lock_service__event_reaches_handler(void) {
  security_lock_service_subscribe(prv_handler);

  prv_deliver_lock(true);
  cl_assert_equal_i(s_handler_calls, 1);
  cl_assert_equal_b(s_handler_last_locked, true);

  prv_deliver_lock(false);
  cl_assert_equal_i(s_handler_calls, 2);
  cl_assert_equal_b(s_handler_last_locked, false);
}

// The handler is not fed from the peek: what it is told is what the event
// carried, so an event that crosses a later change is not rewritten.
void test_security_lock_service__handler_reports_the_event_not_the_peek(void) {
  security_lock_service_subscribe(prv_handler);
  s_sys_is_locked = true;

  prv_deliver_lock(false);

  cl_assert_equal_b(s_handler_last_locked, false);
  cl_assert_equal_i(s_sys_peek_calls, 0);
}

// Unsubscribing drops the registration and the handler.
void test_security_lock_service__unsubscribe(void) {
  security_lock_service_subscribe(prv_handler);
  security_lock_service_unsubscribe();

  cl_assert_equal_i(s_unsubscribe_count, 1);
  cl_assert(s_app_state.handler == NULL);
}

// Re-subscribing replaces the handler rather than stacking a second one.
void test_security_lock_service__resubscribe_replaces_handler(void) {
  security_lock_service_subscribe(prv_handler);
  security_lock_service_subscribe(prv_other_handler);

  prv_deliver_lock(true);

  cl_assert_equal_i(s_handler_calls, 0);
  cl_assert_equal_i(s_other_handler_calls, 1);
}

// A NULL handler is tolerated, including for an event that arrives after an
// unsubscribe has already been queued behind it.
void test_security_lock_service__null_handler_is_safe(void) {
  security_lock_service_subscribe(prv_handler);
  EventServiceInfo *info = s_subscribed_info;
  security_lock_service_unsubscribe();

  s_subscribed_info = info;
  prv_deliver_lock(true);

  cl_assert_equal_i(s_handler_calls, 0);
}

// Workers get their own state, so a worker subscribing does not disturb the
// app's registration.
void test_security_lock_service__worker_has_its_own_state(void) {
  s_current_task = PebbleTask_Worker;
  security_lock_service_subscribe(prv_handler);

  cl_assert_equal_p(s_subscribed_info, &s_worker_state.sls_info);
  cl_assert(s_worker_state.handler == prv_handler);
  cl_assert(s_app_state.handler == NULL);

  prv_deliver_lock(true);
  cl_assert_equal_i(s_handler_calls, 1);
}

// Only an app and a worker have state to hand back. There is no third process
// to subscribe on behalf of, so any other task is a caller bug rather than a
// case to fall through with a NULL state and fault on the first field.
void test_security_lock_service__any_other_task_is_a_bug(void) {
  s_current_task = PebbleTask_KernelMain;

  cl_assert_passert(security_lock_service_subscribe(prv_handler));
  cl_assert_passert(security_lock_service_unsubscribe());

  // Nothing was registered on the way out.
  cl_assert_equal_i(s_subscribe_count, 0);
  cl_assert_equal_i(s_unsubscribe_count, 0);
}
