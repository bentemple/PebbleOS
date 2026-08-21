/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include "clar.h"

#include <string.h>

#include "popups/security/pin_entry_window.h"

// Stubs
////////////////////////////////////
#include "stubs_fonts.h"
#include "stubs_graphics.h"
#include "stubs_graphics_context.h"
#include "stubs_layer.h"
#include "stubs_logging.h"
#include "stubs_passert.h"
#include "stubs_pbl_malloc.h"
#include "stubs_pebble_tasks.h"
#include "stubs_print.h"
#include "stubs_serial.h"

// Window fakes
////////////////////////////////////
// The window under test only talks to the UI through these, and capturing the
// click handlers here is what lets the test drive buttons without standing up a
// ClickManager and a window stack.

static ClickConfigProvider s_click_config_provider;
static void *s_click_config_context;
static ClickHandler s_handlers[NUM_BUTTONS];
static bool s_overrides_back_button;

void window_init(Window *window, const char *debug_name) {
  memset(window, 0, sizeof(*window));
}

void window_set_overrides_back_button(Window *window, bool overrides_back_button) {
  s_overrides_back_button = overrides_back_button;
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

// Helpers
////////////////////////////////////

static SecurityPinEntryWindow s_pin_window;

static int s_submit_count;
static char s_submitted[SECURITY_LOCK_PIN_MAX_LEN + 1];
static uint8_t s_submitted_len;
//! Proves the window has already cleared itself by the time the callback runs.
static char s_digits_at_submit_time[SECURITY_LOCK_PIN_MAX_LEN];
static uint8_t s_cursor_at_submit_time;

static void prv_submit(const char *digits, uint8_t len, void *context) {
  s_submit_count++;
  s_submitted_len = len;
  memcpy(s_submitted, digits, len);
  s_submitted[len] = '\0';
  memcpy(s_digits_at_submit_time, s_pin_window.digits, sizeof(s_digits_at_submit_time));
  s_cursor_at_submit_time = s_pin_window.cursor;
}

static void prv_press(ButtonId button) {
  cl_assert(s_handlers[button] != NULL);
  s_handlers[button](NULL, s_click_config_context);
}

//! Dial `digit` into the cell under the cursor and move on.
static void prv_enter_digit(char digit) {
  for (int i = 0; i < (digit - '0'); ++i) {
    prv_press(BUTTON_ID_UP);
  }
  prv_press(BUTTON_ID_SELECT);
}

static void prv_enter_pin(const char *pin) {
  for (const char *c = pin; *c != '\0'; ++c) {
    prv_enter_digit(*c);
  }
}

void test_pin_entry_window__initialize(void) {
  memset(s_handlers, 0, sizeof(s_handlers));
  s_click_config_provider = NULL;
  s_click_config_context = NULL;
  s_overrides_back_button = false;
  s_submit_count = 0;
  s_submitted_len = 0;
  memset(s_submitted, 0, sizeof(s_submitted));
  memset(s_digits_at_submit_time, 0, sizeof(s_digits_at_submit_time));
  s_cursor_at_submit_time = 0xff;

  security_pin_entry_window_init(&s_pin_window, 4, prv_submit, NULL);
  cl_assert(s_click_config_provider != NULL);
  s_click_config_provider(s_click_config_context);
}

void test_pin_entry_window__cleanup(void) {}

// Setup
////////////////////////////////////

void test_pin_entry_window__starts_on_the_first_zero(void) {
  cl_assert_equal_i(4, s_pin_window.pin_len);
  cl_assert_equal_i(0, s_pin_window.cursor);
  for (int i = 0; i < SECURITY_LOCK_PIN_MAX_LEN; ++i) {
    cl_assert_equal_i('0', s_pin_window.digits[i]);
  }
}

// BACK must not dismiss the lock screen. The window overriding it is half of
// that; leaving it unsubscribed is the other half.
void test_pin_entry_window__back_is_overridden_and_unbound(void) {
  cl_assert(s_overrides_back_button);
  cl_assert(s_handlers[BUTTON_ID_BACK] == NULL);
}

void test_pin_entry_window__pin_len_is_clamped(void) {
  security_pin_entry_window_init(&s_pin_window, 0, prv_submit, NULL);
  cl_assert_equal_i(SECURITY_LOCK_PIN_MIN_LEN, s_pin_window.pin_len);

  security_pin_entry_window_init(&s_pin_window, 200, prv_submit, NULL);
  cl_assert_equal_i(SECURITY_LOCK_PIN_MAX_LEN, s_pin_window.pin_len);
}

// Digit entry
////////////////////////////////////

void test_pin_entry_window__up_and_down_wrap(void) {
  prv_press(BUTTON_ID_DOWN);
  cl_assert_equal_i('9', s_pin_window.digits[0]);
  prv_press(BUTTON_ID_UP);
  cl_assert_equal_i('0', s_pin_window.digits[0]);

  for (int i = 0; i < 10; ++i) {
    prv_press(BUTTON_ID_UP);
  }
  cl_assert_equal_i('0', s_pin_window.digits[0]);
}

void test_pin_entry_window__select_advances_the_cursor(void) {
  prv_press(BUTTON_ID_UP);
  prv_press(BUTTON_ID_SELECT);
  cl_assert_equal_i(1, s_pin_window.cursor);
  // The digit left behind must not follow the cursor.
  cl_assert_equal_i('1', s_pin_window.digits[0]);
  cl_assert_equal_i('0', s_pin_window.digits[1]);

  prv_press(BUTTON_ID_UP);
  cl_assert_equal_i('1', s_pin_window.digits[0]);
  cl_assert_equal_i('1', s_pin_window.digits[1]);
}

// Submission
////////////////////////////////////

void test_pin_entry_window__submits_on_the_last_digit(void) {
  prv_enter_digit('1');
  prv_enter_digit('2');
  prv_enter_digit('3');
  cl_assert_equal_i(0, s_submit_count);

  prv_enter_digit('4');
  cl_assert_equal_i(1, s_submit_count);
  cl_assert_equal_i(4, s_submitted_len);
  cl_assert_equal_s("1234", s_submitted);
}

void test_pin_entry_window__submits_the_full_length_of_a_long_pin(void) {
  security_pin_entry_window_init(&s_pin_window, 8, prv_submit, NULL);
  s_click_config_provider(s_click_config_context);

  prv_enter_pin("13570246");
  cl_assert_equal_i(1, s_submit_count);
  cl_assert_equal_i(8, s_submitted_len);
  cl_assert_equal_s("13570246", s_submitted);
}

// The callback may pop and forget the window, so the buffer has to be clear
// before it runs rather than after.
void test_pin_entry_window__digits_are_gone_before_the_callback_runs(void) {
  prv_enter_pin("1234");
  cl_assert_equal_i(1, s_submit_count);
  cl_assert_equal_i(0, s_cursor_at_submit_time);
  for (int i = 0; i < SECURITY_LOCK_PIN_MAX_LEN; ++i) {
    cl_assert_equal_i('0', s_digits_at_submit_time[i]);
  }
}

void test_pin_entry_window__entry_restarts_after_a_rejected_pin(void) {
  prv_enter_pin("1234");
  prv_enter_pin("5678");
  cl_assert_equal_i(2, s_submit_count);
  cl_assert_equal_s("5678", s_submitted);
}

void test_pin_entry_window__reset_clears_entry_in_progress(void) {
  prv_enter_digit('9');
  prv_press(BUTTON_ID_UP);
  security_pin_entry_window_reset(&s_pin_window);

  cl_assert_equal_i(0, s_pin_window.cursor);
  for (int i = 0; i < SECURITY_LOCK_PIN_MAX_LEN; ++i) {
    cl_assert_equal_i('0', s_pin_window.digits[i]);
  }
  cl_assert_equal_i(0, s_submit_count);
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
