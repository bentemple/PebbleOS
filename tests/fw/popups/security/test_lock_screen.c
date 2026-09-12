/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include "clar.h"

#include <string.h>

#include "applib/touch_service.h"
#include "applib/ui/vibes.h"
#include "applib/ui/window_stack.h"
#include "kernel/event_loop.h"
#include "popups/security/lock_screen.h"
#include "popups/security/pin_entry_window.h"
#include "pbl/services/security_lock.h"
#include "pbl/services/security_lock_shred.h"
#include "pbl/services/security_lock_ui.h"
#include "pbl/services/touch/touch.h"

// Stubs
////////////////////////////////////
#include "stubs_app_state.h"
#include "stubs_fonts.h"
#include "stubs_graphics.h"
#include "stubs_graphics_context.h"
#include "stubs_i18n.h"
#include "stubs_layer.h"
#include "stubs_logging.h"
#include "stubs_passert.h"
#include "stubs_pbl_malloc.h"
#include "stubs_pebble_tasks.h"
#include "stubs_print.h"
#include "stubs_process_manager.h"
#include "stubs_serial.h"

// Window fakes
////////////////////////////////////
// Same shape as the pad's own test: capturing the handlers is what lets this
// drive a finger and a button without a touch service or a ClickManager.

static ClickConfigProvider s_click_config_provider;
static void *s_click_config_context;
static ClickHandler s_handlers[NUM_BUTTONS];
static WindowHandlers s_window_handlers;

void window_init(Window *window, const char *debug_name) { memset(window, 0, sizeof(*window)); }

void window_set_overrides_back_button(Window *window, bool overrides_back_button) {}

void window_set_touch_bridge_disabled(Window *window, bool disabled) {}

void window_set_window_handlers(Window *window, const WindowHandlers *handlers) {
  s_window_handlers = *handlers;
}

void window_set_click_config_provider_with_context(Window *window,
                                                   ClickConfigProvider click_config_provider,
                                                   void *context) {
  s_click_config_provider = click_config_provider;
  s_click_config_context = context;
}

void window_single_click_subscribe(ButtonId button_id, ClickHandler handler) {
  s_handlers[button_id] = handler;
}

void window_single_repeating_click_subscribe(ButtonId button_id, uint16_t repeat_interval_ms,
                                             ClickHandler handler) {
  s_handlers[button_id] = handler;
}

// Not in stubs_graphics.h, which only carries the fill variants.
void graphics_draw_rect(GContext *ctx, const GRect *rect) {}
void graphics_draw_round_rect(GContext *ctx, const GRect *rect, uint16_t radius) {}

void vibes_enqueue_custom_pattern(VibePattern pattern) {}

// Window stack / modal fakes
////////////////////////////////////

static Window *s_pushed_window;
static int s_push_count;
static int s_pop_all_count;
static int s_remove_count;

static ModalPriority s_pushed_priority;

void modal_window_push(Window *window, ModalPriority priority, bool animated) {
  s_pushed_window = window;
  s_pushed_priority = priority;
  s_push_count++;
}

void modal_manager_pop_all(void) { s_pop_all_count++; }

bool window_stack_remove(Window *window, bool animated) {
  s_remove_count++;
  return true;
}

// Touch fakes
////////////////////////////////////

static TouchServiceHandler s_touch_handler;
static void *s_touch_context;

void touch_service_subscribe(TouchServiceHandler handler, void *context) {
  s_touch_handler = handler;
  s_touch_context = context;
}

void touch_service_unsubscribe(void) {
  s_touch_handler = NULL;
  s_touch_context = NULL;
}

static bool s_touch_globally_enabled;
static int s_touch_enable_calls;

bool touch_service_is_globally_enabled(void) { return s_touch_globally_enabled; }

void touch_service_set_globally_enabled(bool enabled) {
  s_touch_globally_enabled = enabled;
  s_touch_enable_calls++;
}

// Launcher queue fake
////////////////////////////////////
// Recorded rather than run, so a test can count what was queued before any of
// it executes. The real queue defers onto KernelMain for exactly that reason:
// the shred holds the task for seconds.

#define MAX_QUEUED 8
static CallbackEventCallback s_queued[MAX_QUEUED];
static void *s_queued_data[MAX_QUEUED];
static int s_queued_count;

void launcher_task_add_callback(CallbackEventCallback callback, void *data) {
  cl_assert(s_queued_count < MAX_QUEUED);
  s_queued[s_queued_count] = callback;
  s_queued_data[s_queued_count] = data;
  s_queued_count++;
}

static void prv_run_queued(void) {
  const int count = s_queued_count;
  for (int i = 0; i < count; ++i) {
    s_queued[i](s_queued_data[i]);
  }
}

// Security lock fake
////////////////////////////////////
// Models the parts of the service the lock screen leans on, including the
// order the real one does them in: the attempt is burned before the comparison,
// so power pulled mid-verify still costs a guess, and once the budget is spent
// an entry is refused without being compared until the backoff has run.
//
// The counter, the time of the last counted attempt and the fake clock are all
// "persisted": prv_simulate_reboot() below resets everything else.

#define FAKE_PIN "1234"

static uint8_t s_pin_len;
static uint8_t s_failed_attempts;
static time_t s_last_attempt;
static time_t s_now;
static int s_disengage_count;
static int s_lockout_count;
static int s_shred_count;
static int s_verify_calls;
static SecurityShredReason s_last_shred_reason;

uint8_t security_lock_get_pin_len(void) { return s_pin_len; }

//! 60s, doubling per further failure, capped at an hour.
static uint32_t prv_fake_lockout_delay(void) {
  if (s_failed_attempts < SECURITY_LOCK_MAX_PIN_ATTEMPTS) {
    return 0;
  }
  const uint8_t over = s_failed_attempts - SECURITY_LOCK_MAX_PIN_ATTEMPTS;
  uint32_t delay = SECURITY_LOCK_LOCKOUT_BASE_S;
  for (uint8_t i = 0; (i < over) && (delay < SECURITY_LOCK_LOCKOUT_MAX_S); ++i) {
    delay *= 2;
  }
  return (delay > SECURITY_LOCK_LOCKOUT_MAX_S) ? SECURITY_LOCK_LOCKOUT_MAX_S : delay;
}

uint32_t security_lock_get_lockout_remaining_s(void) {
  const uint32_t delay = prv_fake_lockout_delay();
  if (delay == 0) {
    return 0;
  }
  const time_t elapsed = s_now - s_last_attempt;
  if (elapsed < 0) {
    return delay;
  }
  return ((uint32_t)elapsed >= delay) ? 0 : (delay - (uint32_t)elapsed);
}

bool security_lock_verify_pin(const char *digits, uint8_t len, uint8_t *attempts_remaining_out) {
  s_verify_calls++;
  if (attempts_remaining_out) {
    *attempts_remaining_out = 0;
  }
  // Refused before the comparison, and not counted: hammering the pad must not
  // be able to push the backoff up without bound.
  if (security_lock_get_lockout_remaining_s() > 0) {
    return false;
  }

  if (s_failed_attempts < UINT8_MAX) {
    s_failed_attempts++;
  }
  s_last_attempt = s_now;
  const bool matched = (len == strlen(FAKE_PIN)) && (memcmp(digits, FAKE_PIN, len) == 0);
  if (matched) {
    s_failed_attempts = 0;
    s_last_attempt = 0;
  }
  if (attempts_remaining_out) {
    *attempts_remaining_out = (s_failed_attempts >= SECURITY_LOCK_MAX_PIN_ATTEMPTS)
                                  ? 0
                                  : SECURITY_LOCK_MAX_PIN_ATTEMPTS - s_failed_attempts;
  }
  return matched;
}

bool security_lock_attempts_exhausted(void) {
  return s_failed_attempts >= SECURITY_LOCK_MAX_PIN_ATTEMPTS;
}

void security_lock_disengage(void) { s_disengage_count++; }

void security_lock_ui_lockout(void) { s_lockout_count++; }

uint32_t security_lock_shred(SecurityShredReason reason) {
  s_shred_count++;
  s_last_shred_reason = reason;
  return 0;
}

// Helpers
////////////////////////////////////

//! The window stack is faked, so nothing else gives the pad a size or brings it
//! on screen. Without both, there is no layout to aim a finger at.
static void prv_bring_up_pad(void) {
  cl_assert(s_pushed_window != NULL);
  s_pushed_window->layer.bounds = GRect(0, 0, PBL_DISPLAY_WIDTH, PBL_DISPLAY_HEIGHT);
  cl_assert(s_click_config_provider != NULL);
  s_click_config_provider(s_click_config_context);
  cl_assert(s_window_handlers.appear != NULL);
  s_window_handlers.appear(s_pushed_window);
}

static void prv_push(void) {
  security_lock_screen_push();
  if (s_pushed_window) {
    prv_bring_up_pad();
  }
}

static const SecurityPinEntryWindow *prv_pad(void) {
  const SecurityPinEntryWindow *pad = security_lock_screen_get_pin_window();
  cl_assert(pad != NULL);
  return pad;
}

static void prv_tap(char digit) {
  const SecurityPinEntryWindow *pad = prv_pad();
  cl_assert(s_touch_handler != NULL);
  for (int16_t y = 0; y < PBL_DISPLAY_HEIGHT; ++y) {
    for (int16_t x = 0; x < PBL_DISPLAY_WIDTH; ++x) {
      const GPoint point = GPoint(x, y);
      if (security_pin_entry_window_digit_at(pad, point) != digit) {
        continue;
      }
      const TouchEvent down = {.type = TouchEvent_Touchdown, .x = x, .y = y};
      const TouchEvent up = {.type = TouchEvent_Liftoff, .x = x, .y = y};
      s_touch_handler(&down, s_touch_context);
      s_touch_handler(&up, s_touch_context);
      return;
    }
  }
  cl_fail("no key for that digit");
}

static void prv_enter(const char *pin) {
  for (const char *c = pin; *c != '\0'; ++c) {
    prv_tap(*c);
  }
}

static void prv_press_back(void) {
  cl_assert(s_handlers[BUTTON_ID_BACK] != NULL);
  s_handlers[BUTTON_ID_BACK](NULL, s_click_config_context);
}

//! Everything the lock screen keeps in RAM goes; the attempt counter, the time
//! of the last counted attempt and the clock are what a real reboot preserves.
static void prv_simulate_reboot(void) {
  security_lock_screen_pop();
  s_pushed_window = NULL;
  s_push_count = 0;
  s_pop_all_count = 0;
  s_remove_count = 0;
  s_lockout_count = 0;
  s_queued_count = 0;
  s_verify_calls = 0;
  memset(s_queued, 0, sizeof(s_queued));
  memset(s_queued_data, 0, sizeof(s_queued_data));
  prv_push();
}

void test_lock_screen__initialize(void) {
  memset(s_handlers, 0, sizeof(s_handlers));
  memset(&s_window_handlers, 0, sizeof(s_window_handlers));
  s_click_config_provider = NULL;
  s_click_config_context = NULL;
  s_pushed_window = NULL;
  s_pushed_priority = ModalPriorityInvalid;
  s_push_count = 0;
  s_pop_all_count = 0;
  s_remove_count = 0;
  s_touch_handler = NULL;
  s_touch_context = NULL;
  s_touch_globally_enabled = true;
  s_touch_enable_calls = 0;
  memset(s_queued, 0, sizeof(s_queued));
  memset(s_queued_data, 0, sizeof(s_queued_data));
  s_queued_count = 0;
  s_pin_len = 4;
  s_failed_attempts = 0;
  s_last_attempt = 0;
  s_now = 1000;
  s_verify_calls = 0;
  s_disengage_count = 0;
  s_lockout_count = 0;
  s_shred_count = 0;
  s_last_shred_reason = SecurityShredReasonUnknown;

  // The screen's own state is a file static that outlives a test, so every test
  // starts by putting it away.
  security_lock_screen_pop();
  s_remove_count = 0;
}

void test_lock_screen__cleanup(void) { security_lock_screen_pop(); }

// Raising and putting away
////////////////////////////////////

void test_lock_screen__push_raises_the_pad(void) {
  cl_assert(!security_lock_screen_is_visible());
  cl_assert(security_lock_screen_get_pin_window() == NULL);

  prv_push();

  cl_assert(security_lock_screen_is_visible());
  cl_assert_equal_i(1, s_push_count);
  cl_assert_equal_i(4, security_pin_entry_window_get_pin_len(prv_pad()));
}

// A stack of its own, above every other modal but the alarm. Sharing one with
// the alarm meant sharing a WindowStack, where push order alone decided which
// of the two the user could reach.
//
// The alarm is deliberately the exception and the only one: an alarm nobody can
// snooze is worse than one that never rang, and answering it uncovers the pad
// or the clock rather than anything further in. Below ModalPriorityMax, which
// is the "no modals at all" sentinel and would stop the pad being pushed at
// all.
void test_lock_screen__the_pad_outranks_every_modal_but_the_alarm(void) {
  prv_push();

  cl_assert(s_pushed_priority > ModalPriorityCritical);
  cl_assert(s_pushed_priority < ModalPriorityAlarm);
  cl_assert(s_pushed_priority < ModalPriorityMax);
}

//! And the alarm is the *only* thing above it, so "the alarm outranks the pad"
//! cannot quietly become "several things do".
void test_lock_screen__only_the_alarm_sits_above_the_pad(void) {
  prv_push();

  cl_assert_equal_i(ModalPriorityAlarm, s_pushed_priority + 1);
  cl_assert_equal_i(ModalPriorityMax, ModalPriorityAlarm + 1);
}

// Anything already on screen is by definition not the lock screen, and the
// lockout is what stops something being pushed back over it.
void test_lock_screen__push_clears_the_screen_and_takes_the_lockout(void) {
  prv_push();
  cl_assert_equal_i(1, s_pop_all_count);
  cl_assert_equal_i(1, s_lockout_count);
}

// A watch that rebooted into the locked state gets here twice: once from the
// boot path and once from the first button press.
void test_lock_screen__a_second_push_is_a_no_op(void) {
  prv_push();
  security_lock_screen_push();

  cl_assert_equal_i(1, s_push_count);
  cl_assert_equal_i(1, s_pop_all_count);
  cl_assert_equal_i(1, s_lockout_count);
  cl_assert(security_lock_screen_is_visible());
}

// Half typed entries must not survive the pad going away: the window is static
// and the next push reuses it.
void test_lock_screen__pop_takes_it_away_and_clears_the_entry(void) {
  prv_push();
  prv_enter("12");
  cl_assert_equal_i(2, security_pin_entry_window_get_entered(prv_pad()));

  security_lock_screen_pop();

  cl_assert(!security_lock_screen_is_visible());
  cl_assert(security_lock_screen_get_pin_window() == NULL);
  cl_assert_equal_i(1, s_remove_count);
}

void test_lock_screen__pop_without_a_push_is_a_no_op(void) {
  security_lock_screen_pop();
  cl_assert_equal_i(0, s_remove_count);
}

// BACK, once there is nothing left to take back, hides the pad without
// unlocking anything: still locked, still lockout held, one press from the pad.
void test_lock_screen__back_on_an_empty_entry_puts_the_pad_away(void) {
  prv_push();

  prv_press_back();

  cl_assert(!security_lock_screen_is_visible());
  cl_assert_equal_i(0, s_disengage_count);
  cl_assert_equal_i(0, s_shred_count);
}

// Brick avoidance
////////////////////////////////////
//
// A pad prompting for a length no PIN can satisfy is a screen with no way past
// it, and a locked watch reboots back into the locked state -- so raising one
// would be unrecoverable. Leaving the clock up is the lesser failure.

void test_lock_screen__no_pin_configured_raises_nothing(void) {
  s_pin_len = 0;
  security_lock_screen_push();

  cl_assert(!security_lock_screen_is_visible());
  cl_assert_equal_i(0, s_push_count);
  cl_assert_equal_i(0, s_pop_all_count);
  cl_assert_equal_i(0, s_lockout_count);
}

void test_lock_screen__a_pin_length_outside_the_range_raises_nothing(void) {
  const uint8_t bad[] = {1, 3, SECURITY_LOCK_PIN_MAX_LEN + 1, 9, 255};
  for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
    s_pin_len = bad[i];
    security_lock_screen_push();
    cl_assert(!security_lock_screen_is_visible());
    cl_assert_equal_i(0, s_push_count);
  }
}

void test_lock_screen__both_ends_of_the_allowed_range_do_raise(void) {
  s_pin_len = SECURITY_LOCK_PIN_MIN_LEN;
  prv_push();
  cl_assert(security_lock_screen_is_visible());
  cl_assert_equal_i(SECURITY_LOCK_PIN_MIN_LEN, security_pin_entry_window_get_pin_len(prv_pad()));
  security_lock_screen_pop();

  s_pin_len = SECURITY_LOCK_PIN_MAX_LEN;
  prv_push();
  cl_assert(security_lock_screen_is_visible());
  cl_assert_equal_i(SECURITY_LOCK_PIN_MAX_LEN, security_pin_entry_window_get_pin_len(prv_pad()));
}

// Touch
////////////////////////////////////
//
// The pad is the only way in, so the global touch switch cannot stand between
// the user and their watch: someone who turned touch off and then locked would
// otherwise have no input at all, and a reboot comes back locked.

void test_lock_screen__touch_is_forced_on_when_it_was_off(void) {
  s_touch_globally_enabled = false;

  prv_push();

  cl_assert(s_touch_globally_enabled);
  cl_assert_equal_i(1, s_touch_enable_calls);
}

// The user's setting has to survive the lock, or unlocking silently turns touch
// on for good.
void test_lock_screen__touch_is_restored_on_pop(void) {
  s_touch_globally_enabled = false;
  prv_push();

  security_lock_screen_pop();

  cl_assert(!s_touch_globally_enabled);
  cl_assert_equal_i(2, s_touch_enable_calls);
}

// Already on: nothing to force and nothing to restore, so the setting is not
// written at all.
void test_lock_screen__touch_already_on_is_left_alone(void) {
  s_touch_globally_enabled = true;

  prv_push();
  cl_assert_equal_i(0, s_touch_enable_calls);

  security_lock_screen_pop();
  cl_assert(s_touch_globally_enabled);
  cl_assert_equal_i(0, s_touch_enable_calls);
}

// Entry
////////////////////////////////////

void test_lock_screen__the_right_pin_unlocks(void) {
  prv_push();

  prv_enter(FAKE_PIN);

  cl_assert_equal_i(1, s_disengage_count);
  cl_assert_equal_i(0, s_shred_count);
  cl_assert_equal_i(0, s_queued_count);
}

void test_lock_screen__a_wrong_pin_says_how_many_tries_are_left(void) {
  prv_push();

  prv_enter("9999");

  cl_assert_equal_i(0, s_disengage_count);
  const char *message = security_pin_entry_window_get_message(prv_pad());
  cl_assert(strstr(message, "2") != NULL);
  // The entry restarts, so the next attempt is a whole PIN.
  cl_assert_equal_i(0, security_pin_entry_window_get_entered(prv_pad()));
}

void test_lock_screen__the_last_try_is_singular(void) {
  prv_push();

  prv_enter("9999");
  prv_enter("9999");

  cl_assert(strstr(security_pin_entry_window_get_message(prv_pad()), "1 try left") != NULL);
}

// Exhaustion
////////////////////////////////////

// The wipe is queued rather than run inline: the shred holds KernelMain for
// seconds while sectors erase, and the user should see why first.
void test_lock_screen__exhausting_the_attempts_queues_one_shred(void) {
  prv_push();

  for (int i = 0; i < SECURITY_LOCK_MAX_PIN_ATTEMPTS; ++i) {
    prv_enter("9999");
  }

  cl_assert(security_lock_attempts_exhausted());
  // One, from the attempt that spent the last of the budget. The earlier wrong
  // entries queue nothing, and the refused ones after it queue nothing either.
  cl_assert_equal_i(1, s_queued_count);
  // Nothing has erased yet -- only the message is on screen.
  cl_assert_equal_i(0, s_shred_count);
  cl_assert(strstr(security_pin_entry_window_get_message(prv_pad()), "erased") != NULL);

  prv_run_queued();

  cl_assert_equal_i(1, s_shred_count);
  cl_assert_equal_i(SecurityShredReasonPinAttemptsExhausted, s_last_shred_reason);
}

// Exhausting the attempts erases, but does not unlock: the watch stays locked
// and the pad stays up, so the content is gone rather than handed over.
void test_lock_screen__exhausting_the_attempts_does_not_unlock(void) {
  prv_push();

  for (int i = 0; i < SECURITY_LOCK_MAX_PIN_ATTEMPTS; ++i) {
    prv_enter("9999");
  }

  cl_assert_equal_i(0, s_disengage_count);
  cl_assert(security_lock_screen_is_visible());
}

// The right PIN entered before the last attempt is spent still unlocks, and
// nothing is queued.
void test_lock_screen__a_correct_pin_before_exhaustion_still_unlocks(void) {
  prv_push();

  for (int i = 0; i < SECURITY_LOCK_MAX_PIN_ATTEMPTS - 1; ++i) {
    prv_enter("9999");
  }
  prv_enter(FAKE_PIN);

  cl_assert_equal_i(1, s_disengage_count);
  cl_assert_equal_i(0, s_queued_count);
  cl_assert(!security_lock_attempts_exhausted());
}

// Backoff
////////////////////////////////////
//
// Past the threshold every further entry is refused without being compared,
// including a correct one, until the backoff has run. Nothing else bounds the
// search: 9^4 guesses at 350ms each is a forty minute exhaustive sweep that
// ends in a genuine unlock.

void test_lock_screen__guessing_stops_at_exhaustion(void) {
  prv_push();

  for (int i = 0; i < SECURITY_LOCK_MAX_PIN_ATTEMPTS; ++i) {
    prv_enter("9999");
  }
  cl_assert_equal_i(1, s_queued_count);
  cl_assert_equal_i(SECURITY_LOCK_MAX_PIN_ATTEMPTS, s_failed_attempts);

  // A further wrong entry costs nothing and queues nothing: it was turned away
  // before anything was compared.
  prv_enter("9999");
  cl_assert_equal_i(1, s_queued_count);
  cl_assert_equal_i(SECURITY_LOCK_MAX_PIN_ATTEMPTS, s_failed_attempts);
  cl_assert(strstr(security_pin_entry_window_get_message(prv_pad()), "min") != NULL);

  // And the right PIN does not get in either, which is what makes the search
  // hopeless rather than merely slow.
  prv_enter(FAKE_PIN);
  cl_assert_equal_i(0, s_disengage_count);
  cl_assert(security_lock_screen_is_visible());
}

// One guess per window, and the window doubles each time one is spent.
void test_lock_screen__the_backoff_lets_one_guess_through_then_doubles(void) {
  prv_push();

  for (int i = 0; i < SECURITY_LOCK_MAX_PIN_ATTEMPTS; ++i) {
    prv_enter("9999");
  }
  cl_assert_equal_i(SECURITY_LOCK_LOCKOUT_BASE_S, security_lock_get_lockout_remaining_s());

  // One second short is still short.
  s_now += SECURITY_LOCK_LOCKOUT_BASE_S - 1;
  prv_enter("9999");
  cl_assert_equal_i(SECURITY_LOCK_MAX_PIN_ATTEMPTS, s_failed_attempts);

  s_now += 1;
  cl_assert_equal_i(0, security_lock_get_lockout_remaining_s());
  prv_enter("9999");
  cl_assert_equal_i(SECURITY_LOCK_MAX_PIN_ATTEMPTS + 1, s_failed_attempts);
  cl_assert_equal_i(2 * SECURITY_LOCK_LOCKOUT_BASE_S, security_lock_get_lockout_remaining_s());
}

// Once the wait is over the pad works again -- the owner is delayed, not shut
// out for good.
void test_lock_screen__the_right_pin_gets_in_once_the_backoff_expires(void) {
  prv_push();

  for (int i = 0; i < SECURITY_LOCK_MAX_PIN_ATTEMPTS; ++i) {
    prv_enter("9999");
  }
  prv_enter(FAKE_PIN);
  cl_assert_equal_i(0, s_disengage_count);

  s_now += SECURITY_LOCK_LOCKOUT_BASE_S;
  prv_enter(FAKE_PIN);
  cl_assert_equal_i(1, s_disengage_count);
  cl_assert_equal_i(0, s_failed_attempts);
  cl_assert_equal_i(0, security_lock_get_lockout_remaining_s());
}

// A clock wound backwards must not retire the wait -- that would be the
// cheapest possible way round it.
void test_lock_screen__winding_the_clock_back_does_not_shorten_the_backoff(void) {
  prv_push();

  for (int i = 0; i < SECURITY_LOCK_MAX_PIN_ATTEMPTS; ++i) {
    prv_enter("9999");
  }

  s_now -= 999;
  cl_assert_equal_i(SECURITY_LOCK_LOCKOUT_BASE_S, security_lock_get_lockout_remaining_s());
  prv_enter(FAKE_PIN);
  cl_assert_equal_i(0, s_disengage_count);
}

// Reboot
////////////////////////////////////
//
// Power cycling is the obvious way to try to shake the backoff off, so the
// counter and the time it is measured from both have to survive one.

void test_lock_screen__the_backoff_survives_a_reboot(void) {
  prv_push();

  for (int i = 0; i < SECURITY_LOCK_MAX_PIN_ATTEMPTS; ++i) {
    prv_enter("9999");
  }

  prv_simulate_reboot();

  cl_assert(security_lock_attempts_exhausted());
  cl_assert_equal_i(SECURITY_LOCK_LOCKOUT_BASE_S, security_lock_get_lockout_remaining_s());

  // A fresh screen is not a fresh budget: still refused, still nothing queued.
  prv_enter(FAKE_PIN);
  cl_assert_equal_i(0, s_disengage_count);
  cl_assert_equal_i(0, s_queued_count);

  s_now += SECURITY_LOCK_LOCKOUT_BASE_S;
  prv_enter(FAKE_PIN);
  cl_assert_equal_i(1, s_disengage_count);
}

// Rebooting part way through the budget keeps what was spent, and the attempt
// that spends the last of it still queues its one wipe.
void test_lock_screen__attempts_spent_before_a_reboot_still_count(void) {
  prv_push();

  for (int i = 0; i < SECURITY_LOCK_MAX_PIN_ATTEMPTS - 1; ++i) {
    prv_enter("9999");
  }

  prv_simulate_reboot();

  cl_assert(!security_lock_attempts_exhausted());
  prv_enter("9999");
  cl_assert(security_lock_attempts_exhausted());
  cl_assert_equal_i(1, s_queued_count);
}
