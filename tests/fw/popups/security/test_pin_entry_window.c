/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include "clar.h"

#include <string.h>

#include "applib/touch_service.h"
#include "popups/security/pin_entry_window.h"

// Stubs
////////////////////////////////////
#include "stubs_app_state.h"
#include "stubs_fonts.h"
#include "stubs_graphics.h"
#include "stubs_graphics_context.h"
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
// The window under test only talks to the UI through these. Capturing the
// touch handler and the click handler is what lets the test drive a finger and
// a button without a touch service or a ClickManager.

static ClickConfigProvider s_click_config_provider;
static void *s_click_config_context;
static ClickHandler s_handlers[NUM_BUTTONS];
static bool s_overrides_back_button;
static bool s_touch_bridge_disabled;
static WindowHandlers s_window_handlers;

void window_init(Window *window, const char *debug_name) {
  memset(window, 0, sizeof(*window));
}

void window_set_overrides_back_button(Window *window, bool overrides_back_button) {
  s_overrides_back_button = overrides_back_button;
}

void window_set_touch_bridge_disabled(Window *window, bool disabled) {
  s_touch_bridge_disabled = disabled;
}

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

// Touch fakes
////////////////////////////////////

static TouchServiceHandler s_touch_handler;
static void *s_touch_context;
static int s_touch_subscribes;
static int s_touch_unsubscribes;

void touch_service_subscribe(TouchServiceHandler handler, void *context) {
  s_touch_handler = handler;
  s_touch_context = context;
  s_touch_subscribes++;
}

void touch_service_unsubscribe(void) {
  s_touch_handler = NULL;
  s_touch_context = NULL;
  s_touch_unsubscribes++;
}

// Helpers
////////////////////////////////////

//! Big enough to exercise a real layout; the assertions below never depend on
//! the number, only on the pad being self-consistent inside it.
#define TEST_W 200
#define TEST_H 228

static SecurityPinEntryWindow s_pin_window;

static int s_submit_count;
static char s_submitted[SECURITY_LOCK_PIN_MAX_LEN + 1];
static uint8_t s_submitted_len;
//! Proves the window has already cleared itself by the time the callback runs.
static char s_digits_at_submit_time[SECURITY_LOCK_PIN_MAX_LEN];
static uint8_t s_entered_at_submit_time;

static void prv_submit_cb(const char *digits, uint8_t len, void *context) {
  s_submit_count++;
  s_submitted_len = len;
  memcpy(s_submitted, digits, len);
  s_submitted[len] = '\0';
  memcpy(s_digits_at_submit_time, s_pin_window.digits, sizeof(s_digits_at_submit_time));
  s_entered_at_submit_time = s_pin_window.entered;
}

static void prv_open(uint8_t pin_len) {
  security_pin_entry_window_init(&s_pin_window, pin_len, prv_submit_cb, NULL);
  s_pin_window.window.layer.bounds = GRect(0, 0, TEST_W, TEST_H);
  cl_assert(s_click_config_provider != NULL);
  s_click_config_provider(s_click_config_context);
  cl_assert(s_window_handlers.appear != NULL);
  s_window_handlers.appear(&s_pin_window.window);
}

static void prv_touch(TouchEventType type, GPoint point) {
  cl_assert(s_touch_handler != NULL);
  const TouchEvent event = {.type = type, .x = point.x, .y = point.y};
  s_touch_handler(&event, s_touch_context);
}

//! Any point on the key for `digit`, found by asking the window rather than by
//! recomputing its layout here.
static GPoint prv_point_for(char digit) {
  for (int16_t y = 0; y < TEST_H; ++y) {
    for (int16_t x = 0; x < TEST_W; ++x) {
      const GPoint point = GPoint(x, y);
      if (security_pin_entry_window_digit_at(&s_pin_window, point) == digit) {
        return point;
      }
    }
  }
  cl_fail("no key for that digit");
  return GPointZero;
}

static void prv_tap(char digit) {
  const GPoint point = prv_point_for(digit);
  prv_touch(TouchEvent_Touchdown, point);
  prv_touch(TouchEvent_Liftoff, point);
}

static void prv_tap_pin(const char *pin) {
  for (const char *c = pin; *c != '\0'; ++c) {
    prv_tap(*c);
  }
}

void test_pin_entry_window__initialize(void) {
  memset(s_handlers, 0, sizeof(s_handlers));
  memset(&s_window_handlers, 0, sizeof(s_window_handlers));
  s_click_config_provider = NULL;
  s_click_config_context = NULL;
  s_overrides_back_button = false;
  s_touch_bridge_disabled = false;
  s_touch_handler = NULL;
  s_touch_context = NULL;
  s_touch_subscribes = 0;
  s_touch_unsubscribes = 0;
  s_submit_count = 0;
  s_submitted_len = 0;
  memset(s_submitted, 0, sizeof(s_submitted));
  memset(s_digits_at_submit_time, 0, sizeof(s_digits_at_submit_time));
  s_entered_at_submit_time = 0xff;

  prv_open(4);
}

void test_pin_entry_window__cleanup(void) {}

// Layout
////////////////////////////////////

// Asserted as properties rather than against copied-out coordinates, so the
// layout can be retuned without rewriting the test, but cannot silently lose a
// key or start overlapping them.
void test_pin_entry_window__all_nine_keys_are_reachable(void) {
  bool seen[SECURITY_PIN_PAD_KEYS] = {0};
  for (int16_t y = 0; y < TEST_H; ++y) {
    for (int16_t x = 0; x < TEST_W; ++x) {
      const char digit = security_pin_entry_window_digit_at(&s_pin_window, GPoint(x, y));
      if (digit != '\0') {
        cl_assert(digit >= '1' && digit <= '9');
        seen[digit - '1'] = true;
      }
    }
  }
  for (int i = 0; i < SECURITY_PIN_PAD_KEYS; ++i) {
    cl_assert(seen[i]);
  }
}

void test_pin_entry_window__keys_are_laid_out_left_to_right_top_to_bottom(void) {
  GPoint first[SECURITY_PIN_PAD_KEYS];
  for (int i = 0; i < SECURITY_PIN_PAD_KEYS; ++i) {
    first[i] = prv_point_for((char)('1' + i));
  }

  for (int row = 0; row < SECURITY_PIN_PAD_ROWS; ++row) {
    const int base = row * SECURITY_PIN_PAD_COLS;
    // Reading order across a row.
    cl_assert(first[base].x < first[base + 1].x);
    cl_assert(first[base + 1].x < first[base + 2].x);
    // And the same row, so 1 2 3 really is a row and not a diagonal.
    cl_assert_equal_i(first[base].y, first[base + 1].y);
    cl_assert_equal_i(first[base].y, first[base + 2].y);
  }
  // Rows descend.
  cl_assert(first[0].y < first[3].y);
  cl_assert(first[3].y < first[6].y);
  // Columns line up.
  cl_assert_equal_i(first[0].x, first[3].x);
  cl_assert_equal_i(first[0].x, first[6].x);
}

// The top strip carries the progress bar and the message, and a tap there must
// not enter a digit.
void test_pin_entry_window__the_top_of_the_screen_is_not_a_key(void) {
  cl_assert_equal_i('\0', security_pin_entry_window_digit_at(&s_pin_window, GPoint(0, 0)));
  cl_assert_equal_i('\0',
                    security_pin_entry_window_digit_at(&s_pin_window, GPoint(TEST_W / 2, 0)));
}

void test_pin_entry_window__points_off_the_pad_are_not_keys(void) {
  cl_assert_equal_i('\0', security_pin_entry_window_digit_at(&s_pin_window, GPoint(-5, -5)));
  cl_assert_equal_i(
      '\0', security_pin_entry_window_digit_at(&s_pin_window, GPoint(TEST_W + 5, TEST_H + 5)));
}

// Setup
////////////////////////////////////

void test_pin_entry_window__starts_empty(void) {
  cl_assert_equal_i(4, s_pin_window.pin_len);
  cl_assert_equal_i(0, s_pin_window.entered);
  cl_assert_equal_i(-1, s_pin_window.pressed_key);
}

// BACK must not dismiss the lock screen. The window overriding it is half of
// that; the other half is that it is bound to clearing instead.
void test_pin_entry_window__back_is_overridden_and_clears(void) {
  cl_assert(s_overrides_back_button);
  cl_assert(s_handlers[BUTTON_ID_BACK] != NULL);
}

// The shared navigation recognizers would read a tap on a key as a select and
// a swipe as a back, so the window has to opt out of them.
void test_pin_entry_window__opts_out_of_the_navigation_bridge(void) {
  cl_assert(s_touch_bridge_disabled);
}

void test_pin_entry_window__pin_len_is_clamped(void) {
  security_pin_entry_window_init(&s_pin_window, 0, prv_submit_cb, NULL);
  cl_assert_equal_i(SECURITY_LOCK_PIN_MIN_LEN, s_pin_window.pin_len);

  security_pin_entry_window_init(&s_pin_window, 200, prv_submit_cb, NULL);
  cl_assert_equal_i(SECURITY_LOCK_PIN_MAX_LEN, s_pin_window.pin_len);
}

// A window pushed over this one must not have its taps stolen.
void test_pin_entry_window__touch_follows_the_window_on_and_off_screen(void) {
  cl_assert_equal_i(1, s_touch_subscribes);
  cl_assert(s_touch_handler != NULL);

  s_window_handlers.disappear(&s_pin_window.window);
  cl_assert_equal_i(1, s_touch_unsubscribes);
  cl_assert(s_pin_window.touch_subscribed == false);

  s_window_handlers.appear(&s_pin_window.window);
  cl_assert_equal_i(2, s_touch_subscribes);
}

// Entry
////////////////////////////////////

void test_pin_entry_window__tapping_a_key_enters_its_digit(void) {
  prv_tap('7');
  cl_assert_equal_i(1, s_pin_window.entered);
  cl_assert_equal_i('7', s_pin_window.digits[0]);
}

void test_pin_entry_window__submits_on_the_last_digit(void) {
  prv_tap_pin("123");
  cl_assert_equal_i(0, s_submit_count);

  prv_tap('4');
  cl_assert_equal_i(1, s_submit_count);
  cl_assert_equal_i(4, s_submitted_len);
  cl_assert_equal_s("1234", s_submitted);
}

void test_pin_entry_window__submits_a_six_digit_pin(void) {
  prv_open(6);
  prv_tap_pin("135792");
  cl_assert_equal_i(1, s_submit_count);
  cl_assert_equal_i(6, s_submitted_len);
  cl_assert_equal_s("135792", s_submitted);
}

// The callback may pop and forget the window, so the buffer has to be clear
// before it runs rather than after.
void test_pin_entry_window__digits_are_gone_before_the_callback_runs(void) {
  prv_tap_pin("1234");
  cl_assert_equal_i(1, s_submit_count);
  cl_assert_equal_i(0, s_entered_at_submit_time);
  for (int i = 0; i < SECURITY_LOCK_PIN_MAX_LEN; ++i) {
    cl_assert_equal_i('\0', s_digits_at_submit_time[i]);
  }
}

void test_pin_entry_window__entry_restarts_after_a_rejected_pin(void) {
  prv_tap_pin("1234");
  prv_tap_pin("5678");
  cl_assert_equal_i(2, s_submit_count);
  cl_assert_equal_s("5678", s_submitted);
}

// Touch behaviour
////////////////////////////////////

void test_pin_entry_window__a_tap_in_a_gap_enters_nothing(void) {
  // Between two keys on the top row: right of 1's first column, left of 2.
  const GPoint one = prv_point_for('1');
  const GPoint two = prv_point_for('2');
  bool found_gap = false;
  for (int16_t x = one.x; x < two.x; ++x) {
    if (security_pin_entry_window_digit_at(&s_pin_window, GPoint(x, one.y)) == '\0') {
      prv_touch(TouchEvent_Touchdown, GPoint(x, one.y));
      prv_touch(TouchEvent_Liftoff, GPoint(x, one.y));
      found_gap = true;
      break;
    }
  }
  cl_assert(found_gap);
  cl_assert_equal_i(0, s_pin_window.entered);
}

// Sliding off a key abandons it, the way a physical button does, so a mis-aimed
// touch can be corrected without lifting into the wrong digit.
void test_pin_entry_window__sliding_off_a_key_abandons_it(void) {
  const GPoint one = prv_point_for('1');
  const GPoint five = prv_point_for('5');

  prv_touch(TouchEvent_Touchdown, one);
  cl_assert_equal_i(0, s_pin_window.pressed_key);
  prv_touch(TouchEvent_PositionUpdate, five);
  cl_assert_equal_i(-1, s_pin_window.pressed_key);
  prv_touch(TouchEvent_Liftoff, five);

  cl_assert_equal_i(0, s_pin_window.entered);
}

void test_pin_entry_window__lifting_off_a_different_key_enters_nothing(void) {
  prv_touch(TouchEvent_Touchdown, prv_point_for('1'));
  prv_touch(TouchEvent_Liftoff, prv_point_for('9'));
  cl_assert_equal_i(0, s_pin_window.entered);
}

// Clearing
////////////////////////////////////

void test_pin_entry_window__back_clears_the_whole_entry(void) {
  prv_tap_pin("123");
  cl_assert_equal_i(3, s_pin_window.entered);

  s_handlers[BUTTON_ID_BACK](NULL, s_click_config_context);

  cl_assert_equal_i(0, s_pin_window.entered);
  for (int i = 0; i < SECURITY_LOCK_PIN_MAX_LEN; ++i) {
    cl_assert_equal_i('\0', s_pin_window.digits[i]);
  }
  cl_assert_equal_i(0, s_submit_count);
}

void test_pin_entry_window__reset_clears_entry_in_progress(void) {
  prv_tap_pin("12");
  security_pin_entry_window_reset(&s_pin_window);
  cl_assert_equal_i(0, s_pin_window.entered);
  cl_assert_equal_i(0, s_submit_count);
}

// Settings needs a prompt the user can walk away from, but the lock screen must
// never get one, so the default has to stay "not cancelable".
void test_pin_entry_window__cancelable_only_when_asked_for(void) {
  security_pin_entry_window_init(&s_pin_window, 4, prv_submit_cb, NULL);
  cl_assert(s_overrides_back_button);

  security_pin_entry_window_set_cancelable(&s_pin_window, true);
  cl_assert(!s_overrides_back_button);

  // And with no BACK handler bound, so the stack below pops the window.
  memset(s_handlers, 0, sizeof(s_handlers));
  s_click_config_provider(s_click_config_context);
  cl_assert(s_handlers[BUTTON_ID_BACK] == NULL);
}

// Message
////////////////////////////////////

void test_pin_entry_window__message_is_copied_and_truncated(void) {
  security_pin_entry_window_set_message(&s_pin_window, "Wrong PIN, 2 tries left");
  cl_assert_equal_s("Wrong PIN, 2 tries left", s_pin_window.message);

  char overlong[SECURITY_PIN_MESSAGE_BUF_SIZE * 2];
  memset(overlong, 'x', sizeof(overlong) - 1);
  overlong[sizeof(overlong) - 1] = '\0';
  security_pin_entry_window_set_message(&s_pin_window, overlong);
  cl_assert_equal_i(SECURITY_PIN_MESSAGE_BUF_SIZE - 1, strlen(s_pin_window.message));

  security_pin_entry_window_set_message(&s_pin_window, NULL);
  cl_assert_equal_s("", s_pin_window.message);
}
