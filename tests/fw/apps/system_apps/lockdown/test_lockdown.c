/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include "clar.h"

#include <string.h>

#include "apps/system/lockdown.h"
#include "applib/ui/dialogs/simple_dialog.h"
#include "applib/ui/window.h"
#include "pbl/services/security_lock.h"
#include "pbl/services/security_lock_shred.h"
#include "resource/resource_ids.auto.h"
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
static uint8_t s_pin_len;
static SecurityLockState s_state;
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

//! The no-PIN message. Captured rather than drawn.
static SimpleDialog s_simple_dialog;
static bool s_dialog_create_fails;
static int s_dialog_creates;
static int s_dialog_pushes;
static char s_dialog_text[128];
static uint32_t s_dialog_icon;
static uint32_t s_dialog_timeout;

bool shell_prefs_get_lockdown_app_in_launcher(void) {
  return s_in_launcher;
}

void shell_prefs_set_lockdown_app_in_launcher(bool enable) {
  s_in_launcher = enable;
}

uint8_t security_lock_get_pin_len(void) {
  return s_pin_len;
}

SecurityLockState security_lock_get_state(void) {
  return s_state;
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

SimpleDialog *simple_dialog_create(const char *dialog_name) {
  if (s_dialog_create_fails) {
    return NULL;
  }
  s_dialog_creates++;
  memset(&s_simple_dialog, 0, sizeof(s_simple_dialog));
  return &s_simple_dialog;
}

Dialog *simple_dialog_get_dialog(SimpleDialog *simple_dialog) {
  return &simple_dialog->dialog;
}

void dialog_set_text(Dialog *dialog, const char *text) {
  strncpy(s_dialog_text, text, sizeof(s_dialog_text) - 1);
  s_dialog_text[sizeof(s_dialog_text) - 1] = '\0';
}

void dialog_set_icon(Dialog *dialog, uint32_t icon_id) {
  s_dialog_icon = icon_id;
}

void dialog_set_timeout(Dialog *dialog, uint32_t timeout) {
  s_dialog_timeout = timeout;
}

void app_simple_dialog_push(SimpleDialog *simple_dialog) {
  s_dialog_pushes++;
}

void i18n_get_with_buffer(const char *string, char *buffer, size_t length) {
  strncpy(buffer, string, length);
  buffer[length - 1] = '\0';
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
  // A configured PIN with the feature on is the ordinary case; the app only
  // exists to lock behind one. The refusal tests take one or the other away.
  s_pin_len = 4;
  s_state = SecurityLockStateArmed;
  s_engage_calls = 0;
  s_engage_reason = SecurityShredReasonManualPanic;
  s_deferred_callback = NULL;
  s_pushed_window = NULL;
  s_pushed_overrides_back = false;
  s_pushes = 0;
  s_event_loops = 0;
  s_user_data = NULL;
  s_dialog_create_fails = false;
  s_dialog_creates = 0;
  s_dialog_pushes = 0;
  s_dialog_text[0] = '\0';
  s_dialog_icon = 0;
  s_dialog_timeout = 0;
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

// Without a PIN the app cannot do what its name says: engaging would erase the
// watch and leave it unlocked. Hidden rather than Quick-Launch-only, because
// Quick Launch keeps an app pickable while it is off the launcher list and this
// one belongs in neither place.
void test_lockdown__is_hidden_everywhere_without_a_pin(void) {
  s_pin_len = 0;
  cl_assert_equal_i(ProcessVisibilityHidden, prv_md()->common.visibility);
}

// The PIN outranks the preference: a user who asked for the launcher entry does
// not thereby get one for an app that would erase without locking.
void test_lockdown__no_pin_outranks_the_launcher_pref(void) {
  s_pin_len = 0;
  shell_prefs_set_lockdown_app_in_launcher(true);
  cl_assert_equal_i(ProcessVisibilityHidden, prv_md()->common.visibility);
  shell_prefs_set_lockdown_app_in_launcher(false);
  cl_assert_equal_i(ProcessVisibilityHidden, prv_md()->common.visibility);
}

// Same bounds security_lock_engage() applies. A length outside them is a record
// the lock screen could not prompt for, so it is no usable PIN.
void test_lockdown__a_pin_length_the_lock_cannot_use_counts_as_none(void) {
  s_pin_len = SECURITY_LOCK_PIN_MAX_LEN + 1;
  cl_assert_equal_i(ProcessVisibilityHidden, prv_md()->common.visibility);
  s_pin_len = SECURITY_LOCK_PIN_MIN_LEN - 1;
  cl_assert_equal_i(ProcessVisibilityHidden, prv_md()->common.visibility);
}

void test_lockdown__comes_back_when_a_pin_is_set(void) {
  s_pin_len = 0;
  cl_assert_equal_i(ProcessVisibilityHidden, prv_md()->common.visibility);
  s_pin_len = 4;
  cl_assert_equal_i(ProcessVisibilityShown, prv_md()->common.visibility);
}

// Same reason as the toggle: the install id a Quick Launch binding holds is
// resolved from the UUID, so the identity has to survive the PIN coming and
// going too.
void test_lockdown__identity_survives_the_pin_going_away(void) {
  const PebbleProcessMdSystem with_pin = *prv_md();
  s_pin_len = 0;
  const PebbleProcessMdSystem without_pin = *prv_md();

  cl_assert(uuid_equal(&with_pin.common.uuid, &without_pin.common.uuid));
  cl_assert(with_pin.common.main_func == without_pin.common.main_func);
  cl_assert_equal_s(with_pin.name, without_pin.name);
  cl_assert_equal_i(with_pin.icon_resource_id, without_pin.icon_resource_id);
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

// Launched without a PIN
////////////////////////////////////
//
// Hiding the app is not enough to stop this: a Quick Launch binding is an
// install id in prefs, and clearing the PIN does not touch it. The chord still
// launches the app afterwards, so the refusal has to be here.

void test_lockdown__does_not_shred_without_a_pin(void) {
  s_pin_len = 0;
  prv_run_app();

  cl_assert_equal_i(0, s_engage_calls);
  cl_assert(s_deferred_callback == NULL);
}

// Says why rather than doing nothing: the user pressed a chord that used to
// work and is owed the reason it stopped.
void test_lockdown__says_the_lock_must_be_turned_on(void) {
  s_pin_len = 0;
  prv_run_app();

  cl_assert_equal_i(1, s_dialog_pushes);
  cl_assert(strstr(s_dialog_text, "Settings") != NULL);
  cl_assert_equal_i(RESOURCE_ID_GENERIC_WARNING_LARGE, s_dialog_icon);
}

// The master switch
////////////////////////////////////
//
// engage() refuses while the feature is off, so an app that ignored the switch
// would be a panic button that silently did nothing.

void test_lockdown__is_hidden_everywhere_while_the_feature_is_off(void) {
  s_state = SecurityLockStateDisabled;
  cl_assert_equal_i(ProcessVisibilityHidden, prv_md()->common.visibility);
}

//! Hiding is not enough: a Quick Launch binding is an install id in prefs, and
//! the switch does not touch it.
void test_lockdown__does_not_shred_while_the_feature_is_off(void) {
  s_state = SecurityLockStateDisabled;
  prv_run_app();

  cl_assert_equal_i(0, s_engage_calls);
  cl_assert(s_deferred_callback == NULL);
  cl_assert_equal_i(1, s_dialog_pushes);
}

//! Off with a PIN still stored is not a state any control produces -- turning
//! the feature off discards the PIN -- but an inconsistent record must not be
//! enough to make the app usable. Only the switch decides.
void test_lockdown__a_stored_pin_does_not_make_the_app_usable(void) {
  s_state = SecurityLockStateDisabled;
  s_pin_len = 6;

  cl_assert_equal_i(ProcessVisibilityHidden, prv_md()->common.visibility);
  prv_run_app();
  cl_assert_equal_i(0, s_engage_calls);
}

void test_lockdown__comes_back_when_the_feature_is_turned_on(void) {
  s_state = SecurityLockStateDisabled;
  cl_assert_equal_i(ProcessVisibilityHidden, prv_md()->common.visibility);
  s_state = SecurityLockStateArmed;
  cl_assert_equal_i(ProcessVisibilityShown, prv_md()->common.visibility);
}

// The message times out on its own. Popping the last window is what ends the
// app, so a dialog without a timeout would strand the user in it.
void test_lockdown__the_message_dismisses_itself(void) {
  s_pin_len = 0;
  prv_run_app();
  cl_assert(s_dialog_timeout > 0);
}

// Not the black holding window: that one overrides BACK and has nothing to pop
// it, which is only safe because the kernel is about to close the app.
void test_lockdown__no_pin_leaves_no_window_to_be_stuck_in(void) {
  s_pin_len = 0;
  prv_run_app();

  cl_assert_equal_i(0, s_pushes);
  cl_assert_equal_i(1, s_event_loops);
}

// Out of memory is still not a reason to erase the watch.
void test_lockdown__does_not_shred_when_the_message_cannot_be_shown(void) {
  s_pin_len = 0;
  s_dialog_create_fails = true;
  prv_run_app();

  cl_assert_equal_i(0, s_engage_calls);
  cl_assert(s_deferred_callback == NULL);
  cl_assert_equal_i(0, s_dialog_pushes);
  cl_assert_equal_i(1, s_event_loops);
}

// And nothing about the refusal touches the ordinary path.
void test_lockdown__still_engages_once_a_pin_exists(void) {
  s_pin_len = 6;
  prv_run_app();

  cl_assert_equal_i(0, s_dialog_pushes);
  cl_assert(s_deferred_callback != NULL);
  s_deferred_callback(NULL);
  cl_assert_equal_i(1, s_engage_calls);
}
