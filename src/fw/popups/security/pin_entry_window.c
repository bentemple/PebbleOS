/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include "popups/security/pin_entry_window.h"

#include <stddef.h>
#include <string.h>

#include "applib/fonts/fonts.h"
#include "applib/graphics/graphics.h"
#include "applib/graphics/text.h"
#include "applib/ui/click.h"
#include "applib/ui/layer.h"
#include "applib/ui/window_private.h"
#include "pbl/util/math.h"

//! Held UP/DOWN walks the digits at a readable speed rather than spinning.
#define DIGIT_REPEAT_MS 150

#define CELL_H 30
#define CELL_MAX_W 22
#define CELL_GAP 3

static char prv_cell_char(const SecurityPinEntryWindow *pin_window, uint8_t idx) {
  if (idx == pin_window->cursor) {
    return pin_window->digits[idx];
  }
  // Entered digits are masked: the screen is the one place someone standing
  // behind the wearer can read the PIN off.
  return (idx < pin_window->cursor) ? '*' : '_';
}

static void prv_draw_cells(SecurityPinEntryWindow *pin_window, GContext *ctx, GRect row) {
  const int16_t cell_w = MAX(8, MIN(CELL_MAX_W, (int16_t)(row.size.w / pin_window->pin_len) -
                                                    CELL_GAP));
  const int16_t total_w = pin_window->pin_len * (cell_w + CELL_GAP) - CELL_GAP;
  GFont font = fonts_get_system_font(FONT_KEY_GOTHIC_24_BOLD);
  int16_t x = row.origin.x + (row.size.w - total_w) / 2;

  for (uint8_t i = 0; i < pin_window->pin_len; ++i) {
    const GRect cell = GRect(x, row.origin.y, cell_w, CELL_H);
    const char text[2] = {prv_cell_char(pin_window, i), '\0'};

    if (i == pin_window->cursor) {
      graphics_context_set_fill_color(ctx, GColorBlack);
      graphics_fill_rect(ctx, &cell);
      graphics_context_set_text_color(ctx, GColorWhite);
    } else {
      graphics_context_set_text_color(ctx, GColorBlack);
    }
    graphics_draw_text(ctx, text, font, cell, GTextOverflowModeFill, GTextAlignmentCenter, NULL);

    x += cell_w + CELL_GAP;
  }
}

static void prv_update_proc(Layer *layer, GContext *ctx) {
  _Static_assert(offsetof(Window, layer) == 0, "");
  _Static_assert(offsetof(SecurityPinEntryWindow, window) == 0, "");
  SecurityPinEntryWindow *pin_window = (SecurityPinEntryWindow *)layer;

  const GRect bounds = layer->bounds;
  graphics_context_set_fill_color(ctx, GColorWhite);
  graphics_fill_rect(ctx, &bounds);

  // Derived from the bounds rather than hard-coded, so this lays out sanely on
  // every display size without a per-board table.
  const int16_t x_margin = PBL_IF_ROUND_ELSE(30, 8);
  const int16_t title_y = bounds.size.h / 12;
  const int16_t cells_y = bounds.size.h / 3;
  const int16_t message_y = cells_y + CELL_H + 8;
  const GRect content = GRect(bounds.origin.x + x_margin, bounds.origin.y,
                              bounds.size.w - (2 * x_margin), bounds.size.h);

  graphics_context_set_text_color(ctx, GColorBlack);
  if (pin_window->title) {
    graphics_draw_text(ctx, pin_window->title, fonts_get_system_font(FONT_KEY_GOTHIC_24_BOLD),
                       GRect(content.origin.x, title_y, content.size.w, 28),
                       GTextOverflowModeTrailingEllipsis, GTextAlignmentCenter, NULL);
  }

  prv_draw_cells(pin_window, ctx, GRect(content.origin.x, cells_y, content.size.w, CELL_H));

  if (pin_window->message[0] != '\0') {
    graphics_context_set_text_color(ctx, GColorBlack);
    graphics_draw_text(ctx, pin_window->message, fonts_get_system_font(FONT_KEY_GOTHIC_18),
                       GRect(content.origin.x, message_y, content.size.w,
                             bounds.size.h - message_y),
                       GTextOverflowModeWordWrap, GTextAlignmentCenter, NULL);
  }
}

static void prv_step_digit(SecurityPinEntryWindow *pin_window, int delta) {
  char *digit = &pin_window->digits[pin_window->cursor];
  *digit = (char)('0' + (((*digit - '0') + delta + 10) % 10));
  layer_mark_dirty(&pin_window->window.layer);
}

static void prv_up_click_handler(ClickRecognizerRef recognizer, void *context) {
  prv_step_digit(context, 1);
}

static void prv_down_click_handler(ClickRecognizerRef recognizer, void *context) {
  prv_step_digit(context, -1);
}

static void prv_select_click_handler(ClickRecognizerRef recognizer, void *context) {
  SecurityPinEntryWindow *pin_window = context;

  if (pin_window->cursor + 1 < pin_window->pin_len) {
    pin_window->cursor++;
    layer_mark_dirty(&pin_window->window.layer);
    return;
  }

  // Hand out a copy and clear the window's own buffer first: the callback is
  // free to pop and forget this window, and nothing should be left holding the
  // PIN afterwards either way.
  char digits[SECURITY_LOCK_PIN_MAX_LEN];
  const uint8_t len = pin_window->pin_len;
  memcpy(digits, pin_window->digits, len);
  security_pin_entry_window_reset(pin_window);

  if (pin_window->submit) {
    pin_window->submit(digits, len, pin_window->context);
  }
  memset(digits, 0, sizeof(digits));
}

static void prv_click_config_provider(void *context) {
  window_single_repeating_click_subscribe(BUTTON_ID_UP, DIGIT_REPEAT_MS, prv_up_click_handler);
  window_single_repeating_click_subscribe(BUTTON_ID_DOWN, DIGIT_REPEAT_MS, prv_down_click_handler);
  window_single_click_subscribe(BUTTON_ID_SELECT, prv_select_click_handler);
  // BACK is deliberately left unsubscribed.
}

void security_pin_entry_window_init(SecurityPinEntryWindow *pin_window, uint8_t pin_len,
                                    SecurityPinEntrySubmitCb submit, void *context) {
  *pin_window = (SecurityPinEntryWindow){
      .pin_len = MAX(SECURITY_LOCK_PIN_MIN_LEN, MIN(SECURITY_LOCK_PIN_MAX_LEN, pin_len)),
      .submit = submit,
      .context = context,
  };
  memset(pin_window->digits, '0', sizeof(pin_window->digits));

  window_init(&pin_window->window, WINDOW_NAME("Security PIN"));
  window_set_overrides_back_button(&pin_window->window, true);
  window_set_click_config_provider_with_context(&pin_window->window, prv_click_config_provider,
                                                pin_window);
  layer_set_update_proc(&pin_window->window.layer, prv_update_proc);
}

void security_pin_entry_window_set_cancelable(SecurityPinEntryWindow *pin_window, bool cancelable) {
  // Nothing subscribes BACK either way; this only decides whether the stack
  // below is allowed to act on it.
  window_set_overrides_back_button(&pin_window->window, !cancelable);
}

void security_pin_entry_window_set_title(SecurityPinEntryWindow *pin_window, const char *title) {
  pin_window->title = title;
  layer_mark_dirty(&pin_window->window.layer);
}

void security_pin_entry_window_set_message(SecurityPinEntryWindow *pin_window,
                                           const char *message) {
  if (message) {
    strncpy(pin_window->message, message, sizeof(pin_window->message) - 1);
    pin_window->message[sizeof(pin_window->message) - 1] = '\0';
  } else {
    pin_window->message[0] = '\0';
  }
  layer_mark_dirty(&pin_window->window.layer);
}

void security_pin_entry_window_set_pin_len(SecurityPinEntryWindow *pin_window, uint8_t pin_len) {
  pin_window->pin_len = MAX(SECURITY_LOCK_PIN_MIN_LEN, MIN(SECURITY_LOCK_PIN_MAX_LEN, pin_len));
  security_pin_entry_window_reset(pin_window);
}

void security_pin_entry_window_reset(SecurityPinEntryWindow *pin_window) {
  memset(pin_window->digits, '0', sizeof(pin_window->digits));
  pin_window->cursor = 0;
  layer_mark_dirty(&pin_window->window.layer);
}

Window *security_pin_entry_window_get_window(SecurityPinEntryWindow *pin_window) {
  return &pin_window->window;
}
