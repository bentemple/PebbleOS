/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include "clar.h"

#include <string.h>

#include "applib/graphics/perimeter.h"
#include "applib/touch_service.h"
#include "applib/ui/vibes.h"
#include "popups/security/pin_entry_window.h"
#include "pbl/util/math.h"

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

// Vibe fake
////////////////////////////////////
// The window's only vibe is the key tick, so counting patterns and totalling
// the last one's segments is enough to say what a press felt like.

static int s_vibe_count;
static uint32_t s_vibe_segments;
static uint32_t s_vibe_total_ms;

void vibes_enqueue_custom_pattern(VibePattern pattern) {
  s_vibe_count++;
  s_vibe_segments = pattern.num_segments;
  s_vibe_total_ms = 0;
  for (uint32_t i = 0; i < pattern.num_segments; ++i) {
    s_vibe_total_ms += pattern.durations[i];
  }
}

// Helpers
////////////////////////////////////

//! The real display, so the layout is checked at the size it ships at. This
//! test builds once per display shape, and the round arm of the layout is
//! chosen by the preprocessor -- feeding it a rect resolution would test a pad
//! that exists on no watch.
#define TEST_W PBL_DISPLAY_WIDTH
#define TEST_H PBL_DISPLAY_HEIGHT

//! Which columns the display actually shows for the horizontal band
//! `y`..`y + h`. Full width on a rect display; on a round one it is the chord
//! of the circle, which is what makes a key at the edge of the bounding box
//! invisible rather than merely awkward.
static GRangeHorizontal prv_visible_span(int16_t y, int16_t h) {
  const GSize size = GSize(TEST_W, TEST_H);
  const GRangeVertical band = {.origin_y = y, .size_h = h};
  return g_perimeter_for_display->callback(g_perimeter_for_display, &size, band, 0);
}

//! Both edges of a rect inside the columns the display shows for its own rows.
static void prv_assert_horizontally_visible(GRect rect) {
  const GRangeHorizontal span = prv_visible_span(rect.origin.y, rect.size.h);
  cl_assert(rect.origin.x >= span.origin_x);
  cl_assert(rect.origin.x + rect.size.w <= span.origin_x + span.size_w);
}

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

static int s_dismiss_count;
static void *s_dismiss_context;
//! Proves the window has already cleared itself by the time the callback runs.
static char s_digits_at_dismiss_time[SECURITY_LOCK_PIN_MAX_LEN];
static uint8_t s_entered_at_dismiss_time;

static void prv_dismiss_cb(void *context) {
  s_dismiss_count++;
  s_dismiss_context = context;
  memcpy(s_digits_at_dismiss_time, s_pin_window.digits, sizeof(s_digits_at_dismiss_time));
  s_entered_at_dismiss_time = s_pin_window.entered;
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

//! Re-run the click config provider, as the window stack does on every push.
//! The BACK binding is decided there, so anything that changes it only takes
//! effect once this has run.
static void prv_reconfigure_clicks(void) {
  memset(s_handlers, 0, sizeof(s_handlers));
  cl_assert(s_click_config_provider != NULL);
  s_click_config_provider(s_click_config_context);
}

static void prv_press_back(void) {
  cl_assert(s_handlers[BUTTON_ID_BACK] != NULL);
  s_handlers[BUTTON_ID_BACK](NULL, s_click_config_context);
}

static void prv_press_back_times(int times) {
  for (int i = 0; i < times; ++i) {
    prv_press_back();
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
  s_dismiss_count = 0;
  s_dismiss_context = NULL;
  memset(s_digits_at_dismiss_time, 0, sizeof(s_digits_at_dismiss_time));
  s_entered_at_dismiss_time = 0xff;
  s_vibe_count = 0;
  s_vibe_segments = 0;
  s_vibe_total_ms = 0;

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

//! The bounding box of a key, recovered from the hit test rather than from the
//! layout arithmetic, so this measures what a finger would actually meet.
static GRect prv_key_extent(char digit) {
  int16_t min_x = TEST_W, min_y = TEST_H, max_x = -1, max_y = -1;
  for (int16_t y = 0; y < TEST_H; ++y) {
    for (int16_t x = 0; x < TEST_W; ++x) {
      if (security_pin_entry_window_digit_at(&s_pin_window, GPoint(x, y)) == digit) {
        min_x = MIN(min_x, x);
        min_y = MIN(min_y, y);
        max_x = MAX(max_x, x);
        max_y = MAX(max_y, y);
      }
    }
  }
  cl_assert(max_x >= 0);
  return GRect(min_x, min_y, max_x - min_x + 1, max_y - min_y + 1);
}

// A key too small to hit reliably is a lock screen the user fights. Checked
// against the hit test, not the drawing, because the hit test is what decides
// whether the tap counted.
void test_pin_entry_window__keys_are_big_enough_to_hit(void) {
  for (int i = 0; i < SECURITY_PIN_PAD_KEYS; ++i) {
    const GRect key = prv_key_extent((char)('1' + i));
    cl_assert(key.size.w >= 30);
    cl_assert(key.size.h >= 30);
  }
}

void test_pin_entry_window__keys_stay_inside_the_screen(void) {
  for (int i = 0; i < SECURITY_PIN_PAD_KEYS; ++i) {
    const GRect key = prv_key_extent((char)('1' + i));
    cl_assert(key.origin.x >= 0);
    cl_assert(key.origin.y >= 0);
    cl_assert(key.origin.x + key.size.w <= TEST_W);
    cl_assert(key.origin.y + key.size.h <= TEST_H);
  }
}

// All nine the same size, or the pad looks broken and the edge keys are harder
// to hit than the middle one.
void test_pin_entry_window__keys_are_uniform(void) {
  const GRect first = prv_key_extent('1');
  for (int i = 1; i < SECURITY_PIN_PAD_KEYS; ++i) {
    const GRect key = prv_key_extent((char)('1' + i));
    cl_assert_equal_i(first.size.w, key.size.w);
    cl_assert_equal_i(first.size.h, key.size.h);
  }
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

// Round display
////////////////////////////////////
//
// A round display shows a circle inscribed in its bounds, so staying inside
// the bounding box is not enough: the corners of that box are not on the
// watch. These run on both shapes -- on a rect one the visible span is the
// full width and the assertions are simply always satisfiable -- which is what
// stops the round arm of the layout being the only one nobody ever compiles.

void test_pin_entry_window__every_key_is_on_the_visible_display(void) {
  for (int i = 0; i < SECURITY_PIN_PAD_KEYS; ++i) {
    prv_assert_horizontally_visible(prv_key_extent((char)('1' + i)));
  }
}

// The bar and the text are drawn inline with no layer of their own, so nothing
// else would notice them sliding off the side of a circle.
void test_pin_entry_window__chrome_is_on_the_visible_display(void) {
  const GRect bar = security_pin_entry_window_bar_rect(&s_pin_window);
  const GRect text = security_pin_entry_window_text_rect(&s_pin_window);

  cl_assert(bar.size.w > 0);
  cl_assert(bar.size.h > 0);
  cl_assert(text.size.w > 0);
  cl_assert(text.size.h > 0);

  cl_assert(bar.origin.y >= 0);
  cl_assert(text.origin.y + text.size.h <= TEST_H);

  prv_assert_horizontally_visible(bar);
  prv_assert_horizontally_visible(text);
}

static bool prv_rects_overlap(GRect a, GRect b) {
  return (a.origin.x < b.origin.x + b.size.w) && (b.origin.x < a.origin.x + a.size.w) &&
         (a.origin.y < b.origin.y + b.size.h) && (b.origin.y < a.origin.y + a.size.h);
}

// No pixel may resolve to two digits, or a tap near an edge enters whichever
// key the hit test happens to check first.
void test_pin_entry_window__keys_do_not_overlap(void) {
  GRect keys[SECURITY_PIN_PAD_KEYS];
  for (int i = 0; i < SECURITY_PIN_PAD_KEYS; ++i) {
    keys[i] = prv_key_extent((char)('1' + i));
  }

  for (int i = 0; i < SECURITY_PIN_PAD_KEYS; ++i) {
    for (int j = i + 1; j < SECURITY_PIN_PAD_KEYS; ++j) {
      cl_assert(!prv_rects_overlap(keys[i], keys[j]));
    }
  }

  // And each key is a solid rectangle rather than one with a bite taken out of
  // it, so a key hidden under another cannot pass the disjointness above.
  for (int i = 0; i < SECURITY_PIN_PAD_KEYS; ++i) {
    const char digit = (char)('1' + i);
    for (int16_t y = keys[i].origin.y; y < keys[i].origin.y + keys[i].size.h; ++y) {
      for (int16_t x = keys[i].origin.x; x < keys[i].origin.x + keys[i].size.w; ++x) {
        cl_assert_equal_i(digit, security_pin_entry_window_digit_at(&s_pin_window, GPoint(x, y)));
      }
    }
  }
}

//! The layout's own gap. Kept here rather than reached for from the source so
//! that shrinking it to nothing has to be a deliberate edit in two places.
#define TEST_PAD_GAP 3

// Keys that touch would make a tap aimed at the seam enter a digit the user
// did not mean. The dead strip between them is what gives a mis-aimed finger
// somewhere harmless to land.
void test_pin_entry_window__keys_are_separated_by_a_gap(void) {
  GRect keys[SECURITY_PIN_PAD_KEYS];
  for (int i = 0; i < SECURITY_PIN_PAD_KEYS; ++i) {
    keys[i] = prv_key_extent((char)('1' + i));
  }

  for (int row = 0; row < SECURITY_PIN_PAD_ROWS; ++row) {
    for (int col = 0; col + 1 < SECURITY_PIN_PAD_COLS; ++col) {
      const GRect left = keys[(row * SECURITY_PIN_PAD_COLS) + col];
      const GRect right = keys[(row * SECURITY_PIN_PAD_COLS) + col + 1];
      const int16_t edge = left.origin.x + left.size.w;
      cl_assert_equal_i(TEST_PAD_GAP, right.origin.x - edge);
      for (int16_t x = edge; x < right.origin.x; ++x) {
        cl_assert_equal_i(
            '\0', security_pin_entry_window_digit_at(&s_pin_window, GPoint(x, left.origin.y)));
      }
    }
  }

  for (int col = 0; col < SECURITY_PIN_PAD_COLS; ++col) {
    for (int row = 0; row + 1 < SECURITY_PIN_PAD_ROWS; ++row) {
      const GRect above = keys[(row * SECURITY_PIN_PAD_COLS) + col];
      const GRect below = keys[((row + 1) * SECURITY_PIN_PAD_COLS) + col];
      const int16_t edge = above.origin.y + above.size.h;
      cl_assert_equal_i(TEST_PAD_GAP, below.origin.y - edge);
      for (int16_t y = edge; y < below.origin.y; ++y) {
        cl_assert_equal_i(
            '\0', security_pin_entry_window_digit_at(&s_pin_window, GPoint(above.origin.x, y)));
      }
    }
  }
}

// The layout assertions above all go through digit_at(). This drives the touch
// handler instead, so a pad that hit tests perfectly but enters nothing still
// fails.
void test_pin_entry_window__every_key_can_be_tapped(void) {
  for (int i = 0; i < SECURITY_PIN_PAD_KEYS; ++i) {
    const char digit = (char)('1' + i);
    const int vibes_before = s_vibe_count;

    prv_tap(digit);

    cl_assert_equal_i(1, s_pin_window.entered);
    cl_assert_equal_i(digit, s_pin_window.digits[0]);
    cl_assert_equal_i(vibes_before + 1, s_vibe_count);

    security_pin_entry_window_reset(&s_pin_window);
  }
  cl_assert_equal_i(0, s_submit_count);
}

// Setup
////////////////////////////////////

void test_pin_entry_window__starts_empty(void) {
  cl_assert_equal_i(4, s_pin_window.pin_len);
  cl_assert_equal_i(0, s_pin_window.entered);
  cl_assert_equal_i(-1, s_pin_window.pressed_key);
}

// BACK must not dismiss the lock screen out from under the window. The window
// overriding it is half of that; the other half is that it is bound to a
// handler of its own.
void test_pin_entry_window__back_is_overridden_and_bound(void) {
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

// Feedback
////////////////////////////////////
//
// The keys are painted on glass and have no travel of their own, so the tick
// is the only thing that tells the user a tap landed on one -- the digits are
// never shown, and one more filled segment on a bar at the top of the screen
// is not something a finger notices.

void test_pin_entry_window__tapping_a_key_ticks(void) {
  prv_tap('7');
  cl_assert_equal_i(1, s_vibe_count);
}

// One pulse, and short enough to read as a tick rather than as an alert.
void test_pin_entry_window__the_tick_is_a_single_short_pulse(void) {
  prv_tap('7');
  cl_assert_equal_i(1, s_vibe_segments);
  cl_assert(s_vibe_total_ms > 0);
  cl_assert(s_vibe_total_ms <= 100);
}

void test_pin_entry_window__every_digit_ticks_including_the_last(void) {
  prv_tap_pin("1234");
  cl_assert_equal_i(1, s_submit_count);
  cl_assert_equal_i(4, s_vibe_count);
}

// A tap that entered nothing must not feel like one that did, or the tick
// stops being worth anything.
void test_pin_entry_window__a_tap_that_enters_nothing_does_not_tick(void) {
  prv_touch(TouchEvent_Touchdown, prv_point_for('1'));
  prv_touch(TouchEvent_Liftoff, prv_point_for('9'));
  cl_assert_equal_i(0, s_pin_window.entered);
  cl_assert_equal_i(0, s_vibe_count);
}

// BACK is a physical button with travel of its own, so it needs no stand-in
// for the feedback the pad is missing.
void test_pin_entry_window__back_does_not_tick(void) {
  prv_tap('1');
  cl_assert_equal_i(1, s_vibe_count);

  prv_press_back();
  cl_assert_equal_i(1, s_vibe_count);
}

// Deleting
////////////////////////////////////

void test_pin_entry_window__back_deletes_the_last_digit(void) {
  prv_tap_pin("123");
  cl_assert_equal_i(3, s_pin_window.entered);

  prv_press_back();

  cl_assert_equal_i(2, s_pin_window.entered);
  cl_assert_equal_i('1', s_pin_window.digits[0]);
  cl_assert_equal_i('2', s_pin_window.digits[1]);
  cl_assert_equal_i(0, s_submit_count);
}

// Dropping the count alone would leave the digit sitting in the buffer, which
// is the one thing this window is careful never to do.
void test_pin_entry_window__the_deleted_digit_is_zeroed(void) {
  prv_tap_pin("123");
  prv_press_back();

  for (int i = s_pin_window.entered; i < SECURITY_LOCK_PIN_MAX_LEN; ++i) {
    cl_assert_equal_i('\0', s_pin_window.digits[i]);
  }
}

void test_pin_entry_window__repeated_backs_empty_the_entry(void) {
  prv_tap_pin("123");
  prv_press_back_times(3);

  cl_assert_equal_i(0, s_pin_window.entered);
  for (int i = 0; i < SECURITY_LOCK_PIN_MAX_LEN; ++i) {
    cl_assert_equal_i('\0', s_pin_window.digits[i]);
  }
  cl_assert_equal_i(0, s_submit_count);
}

// The point of deleting one digit rather than all of them: a mistyped digit
// costs one press, not the whole PIN.
void test_pin_entry_window__a_corrected_pin_submits(void) {
  prv_tap_pin("129");
  prv_press_back();
  prv_tap_pin("34");

  cl_assert_equal_i(1, s_submit_count);
  cl_assert_equal_s("1234", s_submitted);
}

// Nothing to delete and no owner to hand the button to: the press does nothing
// rather than running off the front of the buffer.
void test_pin_entry_window__back_on_an_empty_entry_is_harmless(void) {
  prv_press_back_times(3);

  cl_assert_equal_i(0, s_pin_window.entered);
  cl_assert_equal_i(0, s_submit_count);
  cl_assert_equal_i(0, s_dismiss_count);
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
  prv_reconfigure_clicks();
  cl_assert(s_handlers[BUTTON_ID_BACK] == NULL);
}

// Dismissal
////////////////////////////////////
//
// A third BACK behaviour, alongside deleting and letting the stack pop: hand
// the button to the owner, once there is nothing left to delete. The lock
// screen needs it because dismissing that window means more than taking it off
// a stack -- it also has to stop claiming to be visible, and put back the touch
// setting it forced on for the pad.

void test_pin_entry_window__a_dismiss_handler_keeps_back_overridden(void) {
  security_pin_entry_window_set_dismiss_cb(&s_pin_window, prv_dismiss_cb);
  prv_reconfigure_clicks();

  // Overridden, so the window stack cannot pop this from under the owner: the
  // dismissal is the owner's to do.
  cl_assert(s_overrides_back_button);
  cl_assert(s_handlers[BUTTON_ID_BACK] != NULL);
}

void test_pin_entry_window__back_on_an_empty_entry_calls_the_dismiss_handler(void) {
  security_pin_entry_window_set_dismiss_cb(&s_pin_window, prv_dismiss_cb);
  prv_reconfigure_clicks();

  prv_press_back();
  cl_assert_equal_i(1, s_dismiss_count);
}

// BACK does two jobs and deleting comes first, so the pad only leaves once
// there is nothing left to take back.
void test_pin_entry_window__back_deletes_before_it_dismisses(void) {
  security_pin_entry_window_set_dismiss_cb(&s_pin_window, prv_dismiss_cb);
  prv_reconfigure_clicks();

  prv_tap_pin("12");

  prv_press_back();
  cl_assert_equal_i(1, s_pin_window.entered);
  cl_assert_equal_i(0, s_dismiss_count);

  prv_press_back();
  cl_assert_equal_i(0, s_pin_window.entered);
  cl_assert_equal_i(0, s_dismiss_count);

  prv_press_back();
  cl_assert_equal_i(1, s_dismiss_count);
}

void test_pin_entry_window__the_dismiss_handler_gets_the_window_context(void) {
  int context;
  security_pin_entry_window_init(&s_pin_window, 4, prv_submit_cb, &context);
  security_pin_entry_window_set_dismiss_cb(&s_pin_window, prv_dismiss_cb);
  prv_reconfigure_clicks();

  prv_press_back();
  cl_assert(s_dismiss_context == &context);
}

// The digits must not be left sitting in a window that is off screen. Deleting
// them is what empties the buffer here, but the check still has to be made
// against the moment the callback runs: it is free to pop and forget the
// window.
void test_pin_entry_window__dismissing_leaves_no_digits_behind(void) {
  security_pin_entry_window_set_dismiss_cb(&s_pin_window, prv_dismiss_cb);
  prv_reconfigure_clicks();

  prv_tap_pin("12");
  cl_assert_equal_i(2, s_pin_window.entered);

  // Two deletes, then the dismiss.
  prv_press_back_times(3);

  cl_assert_equal_i(1, s_dismiss_count);
  cl_assert_equal_i(0, s_entered_at_dismiss_time);
  for (int i = 0; i < SECURITY_LOCK_PIN_MAX_LEN; ++i) {
    cl_assert_equal_i('\0', s_digits_at_dismiss_time[i]);
  }
  cl_assert_equal_i(0, s_pin_window.entered);
}

// Dismissing is not a failed attempt. Nothing is submitted, so nothing above
// this window is given a PIN to check or an attempt to count.
void test_pin_entry_window__dismissing_does_not_submit(void) {
  security_pin_entry_window_set_dismiss_cb(&s_pin_window, prv_dismiss_cb);
  prv_reconfigure_clicks();

  prv_tap_pin("123");
  prv_press_back_times(4);
  cl_assert_equal_i(1, s_dismiss_count);
  cl_assert_equal_i(0, s_submit_count);
}

// What the user types once the pad is back is a whole PIN, not the tail of the
// one they walked away from.
void test_pin_entry_window__a_dismissed_pad_starts_over(void) {
  security_pin_entry_window_set_dismiss_cb(&s_pin_window, prv_dismiss_cb);
  prv_reconfigure_clicks();

  prv_tap_pin("12");
  prv_press_back_times(3);

  prv_tap_pin("1234");
  cl_assert_equal_i(1, s_submit_count);
  cl_assert_equal_s("1234", s_submitted);
}

// A pad whose owner has not claimed dismissal must not become dismissable by
// accident, so without a callback BACK only ever deletes.
void test_pin_entry_window__back_deletes_without_a_dismiss_handler(void) {
  prv_tap_pin("12");

  prv_press_back();
  cl_assert_equal_i(1, s_pin_window.entered);

  prv_press_back_times(2);
  cl_assert_equal_i(0, s_pin_window.entered);
  cl_assert_equal_i(0, s_dismiss_count);
}

// The two are alternatives, not layers: BACK cannot both reach a handler and
// pop the window. Asserted both ways round, so the outcome does not depend on
// the order the owner happens to call the setters in.
void test_pin_entry_window__a_dismiss_handler_wins_over_cancelable(void) {
  security_pin_entry_window_set_cancelable(&s_pin_window, true);
  security_pin_entry_window_set_dismiss_cb(&s_pin_window, prv_dismiss_cb);
  prv_reconfigure_clicks();

  cl_assert(s_overrides_back_button);
  prv_press_back();
  cl_assert_equal_i(1, s_dismiss_count);
}

void test_pin_entry_window__cancelable_does_not_take_back_off_a_dismiss_handler(void) {
  security_pin_entry_window_set_dismiss_cb(&s_pin_window, prv_dismiss_cb);
  security_pin_entry_window_set_cancelable(&s_pin_window, true);
  prv_reconfigure_clicks();

  cl_assert(s_overrides_back_button);
  prv_press_back();
  cl_assert_equal_i(1, s_dismiss_count);
}

// Settings sets no dismiss handler, so its prompts keep being popped by the
// stack exactly as before.
void test_pin_entry_window__cancelable_alone_is_unchanged(void) {
  security_pin_entry_window_set_cancelable(&s_pin_window, true);
  prv_reconfigure_clicks();

  cl_assert(!s_overrides_back_button);
  cl_assert(s_handlers[BUTTON_ID_BACK] == NULL);
}

// Deleting needs BACK, and a cancelable window has already given BACK away, so
// half typed or not its prompts are still popped by the stack. Handing the
// button back and forth as digits come and go would make what BACK does depend
// on when the stack last read the click config.
void test_pin_entry_window__cancelable_keeps_giving_back_away_once_digits_are_in(void) {
  security_pin_entry_window_set_cancelable(&s_pin_window, true);
  prv_reconfigure_clicks();

  prv_tap_pin("12");
  cl_assert_equal_i(2, s_pin_window.entered);
  cl_assert(!s_overrides_back_button);
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

// Introspection
////////////////////////////////////
//
// These back the `security ui` console command, which an end-to-end test reads
// instead of the framebuffer. Asserted against the same behaviour the tests
// above drive, so a getter that stops tracking the window is caught here.

void test_pin_entry_window__getters_track_entry_progress(void) {
  cl_assert_equal_i(4, security_pin_entry_window_get_pin_len(&s_pin_window));
  cl_assert_equal_i(0, security_pin_entry_window_get_entered(&s_pin_window));

  prv_tap_pin("12");
  cl_assert_equal_i(2, security_pin_entry_window_get_entered(&s_pin_window));

  security_pin_entry_window_reset(&s_pin_window);
  cl_assert_equal_i(0, security_pin_entry_window_get_entered(&s_pin_window));

  security_pin_entry_window_set_pin_len(&s_pin_window, 6);
  cl_assert_equal_i(6, security_pin_entry_window_get_pin_len(&s_pin_window));
}

// Never NULL, so the console can print them without a null check of its own.
void test_pin_entry_window__getters_report_title_and_message(void) {
  cl_assert_equal_s("", security_pin_entry_window_get_title(&s_pin_window));
  cl_assert_equal_s("", security_pin_entry_window_get_message(&s_pin_window));

  security_pin_entry_window_set_title(&s_pin_window, "Locked");
  security_pin_entry_window_set_message(&s_pin_window, "Wrong PIN, 2 tries left");
  cl_assert_equal_s("Locked", security_pin_entry_window_get_title(&s_pin_window));
  cl_assert_equal_s("Wrong PIN, 2 tries left",
                    security_pin_entry_window_get_message(&s_pin_window));
}

void test_pin_entry_window__getters_report_the_pressed_key(void) {
  cl_assert_equal_i(-1, security_pin_entry_window_get_pressed_key(&s_pin_window));

  prv_touch(TouchEvent_Touchdown, prv_point_for('5'));
  cl_assert_equal_i(4, security_pin_entry_window_get_pressed_key(&s_pin_window));

  prv_touch(TouchEvent_Liftoff, prv_point_for('5'));
  cl_assert_equal_i(-1, security_pin_entry_window_get_pressed_key(&s_pin_window));
}

// The console is reachable from a seized watch, so nothing reachable through
// these may carry the digits themselves.
void test_pin_entry_window__getters_never_expose_the_digits(void) {
  // Set, so the assertion is that entering digits leaves these alone rather
  // than that they happen to be empty.
  security_pin_entry_window_set_title(&s_pin_window, "Locked");
  security_pin_entry_window_set_message(&s_pin_window, "Wrong PIN, 2 tries left");

  prv_tap_pin("123");

  cl_assert_equal_i(3, security_pin_entry_window_get_entered(&s_pin_window));
  cl_assert_equal_s("Locked", security_pin_entry_window_get_title(&s_pin_window));
  cl_assert_equal_s("Wrong PIN, 2 tries left",
                    security_pin_entry_window_get_message(&s_pin_window));

  // How many digits are in, never which. The pressed key is the one under the
  // finger right now, which is nothing between taps.
  cl_assert_equal_i(-1, security_pin_entry_window_get_pressed_key(&s_pin_window));
  cl_assert(strstr(security_pin_entry_window_get_title(&s_pin_window), "123") == NULL);
  cl_assert(strstr(security_pin_entry_window_get_message(&s_pin_window), "123") == NULL);
}
