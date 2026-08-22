/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include "clar.h"

#include <string.h>

#include "apps/system/lockdown.h"
#include "applib/ui/window.h"
#include "pbl/services/security_lock_shred.h"
#include "shell/prefs.h"

// Stubs
////////////////////////////////////
#include "stubs_logging.h"
#include "stubs_passert.h"
#include "stubs_pbl_malloc.h"
#include "stubs_pebble_tasks.h"
#include "stubs_print.h"
#include "stubs_serial.h"

// Fakes
////////////////////////////////////

static bool s_in_launcher;
static int s_engage_calls;
static SecurityShredReason s_engage_reason;
static void (*s_deferred_callback)(void *);
static Window *s_pushed_window;
//! Captured at push time: the app frees the window on the way out, so the test
//! must not read it back afterwards.
static bool s_pushed_overrides_back;
static int s_pushes;
static int s_event_loops;
static void *s_user_data;

bool shell_prefs_get_lockdown_app_in_launcher(void) {
  return s_in_launcher;
}

void shell_prefs_set_lockdown_app_in_launcher(bool enable) {
  s_in_launcher = enable;
}

void security_lock_engage(SecurityShredReason reason) {
  s_engage_calls++;
  s_engage_reason = reason;
}

void launcher_task_add_callback(void (*callback)(void *data), void *data) {
  s_deferred_callback = callback;
}

void window_init(Window *window, const char *debug_name) {
  memset(window, 0, sizeof(*window));
}

void window_set_background_color(Window *window, GColor background_color) {}

void window_set_overrides_back_button(Window *window, bool overrides_back_button) {
  window->overrides_back_button = overrides_back_button;
}

void app_window_stack_push(Window *window, bool animated) {
  s_pushed_window = window;
  s_pushed_overrides_back = window->overrides_back_button;
  s_pushes++;
}

//! Stands in for the app task blocking until the kernel deinits it. Nothing in
//! the app runs after this returns.
void app_event_loop(void) {
  s_event_loops++;
}

void app_state_set_user_data(void *data) {
  s_user_data = data;
}

void *app_state_get_user_data(void) {
  return s_user_data;
}

// Helpers
////////////////////////////////////

static const PebbleProcessMdSystem *prv_md(void) {
  return (const PebbleProcessMdSystem *)lockdown_app_get_app_info();
}

static void prv_run_app(void) {
  prv_md()->common.main_func();
}

void test_lockdown__initialize(void) {
  s_in_launcher = true;
  s_engage_calls = 0;
  s_engage_reason = SecurityShredReasonManualPanic;
  s_deferred_callback = NULL;
  s_pushed_window = NULL;
  s_pushed_overrides_back = false;
  s_pushes = 0;
  s_event_loops = 0;
  s_user_data = NULL;
}

// Visibility
////////////////////////////////////

void test_lockdown__is_listed_in_the_launcher_by_default(void) {
  cl_assert_equal_i(ProcessVisibilityShown, prv_md()->common.visibility);
}

// Off is Quick-Launch-only rather than hidden outright: the whole point of the
// toggle is that a button binding keeps working.
void test_lockdown__drops_off_the_launcher_list_when_turned_off(void) {
  shell_prefs_set_lockdown_app_in_launcher(false);
  cl_assert_equal_i(ProcessVisibilityQuickLaunch, prv_md()->common.visibility);
}

void test_lockdown__visibility_tracks_the_pref_both_ways(void) {
  shell_prefs_set_lockdown_app_in_launcher(false);
  cl_assert_equal_i(ProcessVisibilityQuickLaunch, prv_md()->common.visibility);
  shell_prefs_set_lockdown_app_in_launcher(true);
  cl_assert_equal_i(ProcessVisibilityShown, prv_md()->common.visibility);
}

// Quick Launch stores an install id, which is resolved from the UUID. If the
// identity moved with the toggle, hiding the app would silently break a binding
// the user had already made.
void test_lockdown__identity_survives_the_toggle(void) {
  const PebbleProcessMdSystem listed = *prv_md();
  shell_prefs_set_lockdown_app_in_launcher(false);
  const PebbleProcessMdSystem unlisted = *prv_md();

  cl_assert(uuid_equal(&listed.common.uuid, &unlisted.common.uuid));
  cl_assert(listed.common.main_func == unlisted.common.main_func);
  cl_assert_equal_s(listed.name, unlisted.name);
  cl_assert_equal_i(listed.icon_resource_id, unlisted.icon_resource_id);
}

// Launching
////////////////////////////////////

// security_lock_engage() asserts it is on KernelMain, drives the app and modal
// stacks and blocks for the length of the erase. This runs on the app task.
void test_lockdown__defers_engage_to_the_kernel(void) {
  prv_run_app();

  cl_assert_equal_i(0, s_engage_calls);
  cl_assert(s_deferred_callback != NULL);

  s_deferred_callback(NULL);
  cl_assert_equal_i(1, s_engage_calls);
  cl_assert_equal_i(SecurityShredReasonManualPanic, s_engage_reason);
}

// No prompt, no dialog, no second window: a panic button that asks is a worse
// panic button, and everything the erase destroys comes back from the phone.
void test_lockdown__asks_nothing_before_engaging(void) {
  prv_run_app();
  cl_assert_equal_i(1, s_pushes);
}

// app_event_loop()'s first act is to kill any app whose window stack is empty.
// That kill event would race the hand-over above, so the app has to be holding
// a window by the time it gets there.
void test_lockdown__holds_a_window_until_the_kernel_closes_it(void) {
  prv_run_app();

  cl_assert(s_pushed_window != NULL);
  cl_assert_equal_i(1, s_event_loops);
}

// Same reason: popping the only window takes the stack to empty. There is
// nothing to back out of here in any case.
void test_lockdown__back_does_not_pop_the_window(void) {
  prv_run_app();
  cl_assert(s_pushed_overrides_back);
}

// The window is pushed, and the hand-over queued, before the app ever blocks.
void test_lockdown__queues_the_handover_before_blocking(void) {
  prv_run_app();
  cl_assert(s_pushed_window != NULL);
  cl_assert(s_deferred_callback != NULL);
  cl_assert_equal_i(1, s_event_loops);
}
