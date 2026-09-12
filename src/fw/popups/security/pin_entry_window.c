/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include "popups/security/pin_entry_window.h"

#include <stddef.h>
#include <string.h>

#include "applib/fonts/fonts.h"
#include "applib/graphics/graphics.h"
#include "applib/graphics/text.h"
#include "applib/touch_service.h"
#include "applib/ui/click.h"
#include "applib/ui/layer.h"
#include "applib/ui/vibes.h"
#include "applib/ui/window_private.h"
#include "pbl/util/math.h"
#include "pbl/util/size.h"

#define PAD_GAP 3
#define PAD_KEY_RADIUS 4
#define BAR_H 10
//! Long enough to feel, short enough not to outlast the tap that caused it.
#define KEY_TICK_MS 40
//! Two lines. The messages that matter most here are sentences, not labels --
//! "Connect your phone to change your PIN" does not fit on one line of any font
//! big enough to read.
#define TEXT_LINE_H 20
#define TEXT_H (2 * TEXT_LINE_H)

//! Where everything sits, derived from the window bounds so one description
//! serves both the drawing and the hit testing. Anything computed twice here
//! would eventually be computed differently, and the keys would stop lining up
//! with what the finger hits.
typedef struct PadGeometry {
  GRect bar;
  GRect text;
  //! Top left key; the rest step by (key.size + PAD_GAP).
  GRect key;
} PadGeometry;

static PadGeometry prv_geometry(const GRect *bounds) {
  // Round displays lose the corners, so the whole layout pulls in far enough
  // that the four corner keys stay inside the circle.
  const int16_t margin_x = PBL_IF_ROUND_ELSE(bounds->size.w / 6, 6);
  const int16_t top = PBL_IF_ROUND_ELSE(bounds->size.h / 6, 6);
  const int16_t bottom = bounds->size.h - PBL_IF_ROUND_ELSE(bounds->size.h / 6, 4);

  const int16_t x = bounds->origin.x + margin_x;
  const int16_t w = bounds->size.w - (2 * margin_x);

  PadGeometry geom;
  geom.bar = GRect(x, bounds->origin.y + top, w, BAR_H);
  geom.text = GRect(x, geom.bar.origin.y + BAR_H + 2, w, TEXT_H);

  const int16_t grid_top = geom.text.origin.y + TEXT_H;
  const int16_t grid_h = bottom - grid_top;
  geom.key = GRect(x, grid_top, (w - (2 * PAD_GAP)) / SECURITY_PIN_PAD_COLS,
                   (grid_h - (2 * PAD_GAP)) / SECURITY_PIN_PAD_ROWS);
  return geom;
}

static GRect prv_key_rect(const PadGeometry *geom, uint8_t key) {
  const int16_t col = key % SECURITY_PIN_PAD_COLS;
  const int16_t row = key / SECURITY_PIN_PAD_COLS;
  return GRect(geom->key.origin.x + (col * (geom->key.size.w + PAD_GAP)),
               geom->key.origin.y + (row * (geom->key.size.h + PAD_GAP)), geom->key.size.w,
               geom->key.size.h);
}

//! @return the key under @p point, or -1 if the point is in a gap or off the pad.
static int8_t prv_key_at(const GRect *bounds, GPoint point) {
  const PadGeometry geom = prv_geometry(bounds);
  for (uint8_t key = 0; key < SECURITY_PIN_PAD_KEYS; ++key) {
    const GRect rect = prv_key_rect(&geom, key);
    if (grect_contains_point(&rect, &point)) {
      return (int8_t)key;
    }
  }
  return -1;
}

// Drawing
//////////////////////////////////////////////////////////////////////////////

static void prv_draw_progress(const SecurityPinEntryWindow *pin_window, GContext *ctx,
                              GRect bar) {
  // One segment per digit rather than a continuous fill: the segments are what
  // tell the user how many are still wanted, which matters more the longer the
  // PIN is. Ten of them still read clearly on the narrowest screen.
  const int16_t seg_w = bar.size.w / pin_window->pin_len;

  graphics_context_set_stroke_color(ctx, GColorBlack);
  graphics_context_set_fill_color(ctx, GColorBlack);

  for (uint8_t i = 0; i < pin_window->pin_len; ++i) {
    const GRect seg = GRect(bar.origin.x + (i * seg_w), bar.origin.y, seg_w - 1, bar.size.h);
    if (i < pin_window->entered) {
      graphics_fill_rect(ctx, &seg);
    } else {
      graphics_draw_rect(ctx, &seg);
    }
  }
}

static void prv_draw_keys(const SecurityPinEntryWindow *pin_window, GContext *ctx,
                          const PadGeometry *geom) {
  GFont font = fonts_get_system_font(FONT_KEY_GOTHIC_28_BOLD);

  for (uint8_t key = 0; key < SECURITY_PIN_PAD_KEYS; ++key) {
    const GRect rect = prv_key_rect(geom, key);
    const bool pressed = (pin_window->pressed_key == (int8_t)key);

    graphics_context_set_fill_color(ctx, pressed ? GColorBlack : GColorWhite);
    graphics_fill_round_rect(ctx, &rect, PAD_KEY_RADIUS, GCornersAll);
    graphics_context_set_stroke_color(ctx, GColorBlack);
    graphics_draw_round_rect(ctx, &rect, PAD_KEY_RADIUS);

    // Nudge the glyph box down so the digit sits optically centred rather than
    // hanging from the top of the key.
    GRect text = rect;
    text.origin.y += (rect.size.h - 30) / 2;
    text.size.h = 30;

    const char label[2] = {(char)('1' + key), '\0'};
    graphics_context_set_text_color(ctx, pressed ? GColorWhite : GColorBlack);
    graphics_draw_text(ctx, label, font, text, GTextOverflowModeFill, GTextAlignmentCenter, NULL);
  }
}

static void prv_update_proc(Layer *layer, GContext *ctx) {
  _Static_assert(offsetof(Window, layer) == 0, "");
  _Static_assert(offsetof(SecurityPinEntryWindow, window) == 0, "");
  SecurityPinEntryWindow *pin_window = (SecurityPinEntryWindow *)layer;

  const GRect bounds = layer->bounds;
  graphics_context_set_fill_color(ctx, GColorWhite);
  graphics_fill_rect(ctx, &bounds);

  const PadGeometry geom = prv_geometry(&bounds);

  prv_draw_progress(pin_window, ctx, geom.bar);

  // The message displaces the title: when there is something to say about the
  // last attempt, that matters more than the heading.
  const char *text = (pin_window->message[0] != '\0') ? pin_window->message : pin_window->title;
  if (text) {
    graphics_context_set_text_color(ctx, GColorBlack);
    graphics_draw_text(ctx, text, fonts_get_system_font(FONT_KEY_GOTHIC_18_BOLD), geom.text,
                       GTextOverflowModeWordWrap, GTextAlignmentCenter, NULL);
  }

  prv_draw_keys(pin_window, ctx, &geom);
}

// Entry
//////////////////////////////////////////////////////////////////////////////

//! A single short pulse per accepted key, so a pad with no travel still feels
//! like one. It is the only feedback a finger gets -- the digits are never
//! shown, and a bar at the top of the screen is not where the user is looking.
//!
//! Not vibes_short_pulse(), whose quarter second outlasts the tap and whose
//! tail would swallow the next key's tick: the vibe service drops a pattern
//! queued while one is still running.
//!
//! Not gated on Quiet Time, which suppresses alerts arriving at the user, not
//! answers to something the user just did. Strength and the global vibe
//! disable are applied by the service underneath.
static void prv_key_tick(void) {
  static const uint32_t durations[] = {KEY_TICK_MS};
  vibes_enqueue_custom_pattern((VibePattern){
      .durations = durations,
      .num_segments = ARRAY_LENGTH(durations),
  });
}

static void prv_press_key(SecurityPinEntryWindow *pin_window, uint8_t key) {
  if (pin_window->entered >= pin_window->pin_len) {
    return;
  }
  pin_window->digits[pin_window->entered++] = (char)('1' + key);
  prv_key_tick();

  if (pin_window->entered < pin_window->pin_len) {
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

static void prv_touch_handler(const TouchEvent *event, void *context) {
  SecurityPinEntryWindow *pin_window = context;
  const GRect bounds = pin_window->window.layer.bounds;
  const GPoint point = GPoint(event->x, event->y);

  switch (event->type) {
    case TouchEvent_Touchdown:
      pin_window->pressed_key = prv_key_at(&bounds, point);
      layer_mark_dirty(&pin_window->window.layer);
      return;

    case TouchEvent_PositionUpdate:
      // Sliding off a key abandons it, the way a button does, so a mis-aimed
      // touch can be corrected without lifting into the wrong digit.
      if ((pin_window->pressed_key >= 0) &&
          (prv_key_at(&bounds, point) != pin_window->pressed_key)) {
        pin_window->pressed_key = -1;
        layer_mark_dirty(&pin_window->window.layer);
      }
      return;

    case TouchEvent_Liftoff: {
      const int8_t key = pin_window->pressed_key;
      pin_window->pressed_key = -1;
      if ((key >= 0) && (prv_key_at(&bounds, point) == key)) {
        prv_press_key(pin_window, (uint8_t)key);
      } else {
        layer_mark_dirty(&pin_window->window.layer);
      }
      return;
    }

    default:
      return;
  }
}

//! Take back one digit.
//!
//! No tick: BACK is a physical button with travel of its own, so it does not
//! need the stand-in the painted keys do.
//!
//! @return true if there was a digit to take back.
static bool prv_delete_last_digit(SecurityPinEntryWindow *pin_window) {
  if (pin_window->entered == 0) {
    return false;
  }
  // Zeroed, not merely uncounted. Everything else here is careful to leave no
  // PIN material behind, and a digit sitting past `entered` would be the one
  // place it did.
  pin_window->digits[--pin_window->entered] = '\0';
  layer_mark_dirty(&pin_window->window.layer);
  return true;
}

static void prv_back_click_handler(ClickRecognizerRef recognizer, void *context) {
  SecurityPinEntryWindow *pin_window = context;
  prv_delete_last_digit(pin_window);
}

//! Deleting comes first, so the button that gets the user off the pad is also
//! the one that fixes a mistyped digit, and neither has to guess which was
//! meant. Nothing is checked until a full length is entered, so taking a digit
//! back gives away nothing and costs no attempt.
static void prv_dismiss_click_handler(ClickRecognizerRef recognizer, void *context) {
  SecurityPinEntryWindow *pin_window = context;
  if (prv_delete_last_digit(pin_window)) {
    return;
  }
  // Reset anyway rather than trust the entry to be empty: the callback is free
  // to leave this window allocated but off screen.
  security_pin_entry_window_reset(pin_window);
  pin_window->dismiss(pin_window->context);
}

//! Whether the enclosing stack owns BACK, or this window does.
//!
//! A dismiss callback needs the button, so it wins over cancelable: BACK
//! cannot both reach a handler and pop the window. Derived in one place so the
//! answer does not depend on the order the setters are called in.
static void prv_update_back_override(SecurityPinEntryWindow *pin_window) {
  const bool stack_pops_it = pin_window->cancelable && (pin_window->dismiss == NULL);
  window_set_overrides_back_button(&pin_window->window, !stack_pops_it);
}

//! Both bound handlers delete a digit first. The third case, cancelable with no
//! dismiss callback, binds nothing and so cannot delete: the stack pops the
//! window, half typed or not. Handing BACK back and forth as digits come and go
//! would make what the button does depend on when the stack last read this.
static void prv_click_config_provider(void *context) {
  SecurityPinEntryWindow *pin_window = context;
  if (pin_window->dismiss) {
    window_single_click_subscribe(BUTTON_ID_BACK, prv_dismiss_click_handler);
  } else if (!pin_window->cancelable) {
    // Deletes, and nothing else: with no owner to hand the pad to, an empty
    // entry has nowhere to go. Subscribing also overrides the back button,
    // which is what stops the pad being taken off the stack with it.
    window_single_click_subscribe(BUTTON_ID_BACK, prv_back_click_handler);
  }
  // Nothing is bound to UP, DOWN or SELECT: the pad is the input.
}

static void prv_window_appear(Window *window) {
  SecurityPinEntryWindow *pin_window = (SecurityPinEntryWindow *)window;
  if (!pin_window->touch_subscribed) {
    // The raw slot, not the navigation bridge: that bridge is gated on the
    // user's Touch Navigation preference, and a lock screen the user can turn
    // off in Settings is not a lock screen.
    touch_service_subscribe(prv_touch_handler, pin_window);
    pin_window->touch_subscribed = true;
  }
}

static void prv_window_disappear(Window *window) {
  SecurityPinEntryWindow *pin_window = (SecurityPinEntryWindow *)window;
  if (pin_window->touch_subscribed) {
    touch_service_unsubscribe();
    pin_window->touch_subscribed = false;
  }
  pin_window->pressed_key = -1;
}

// Public
//////////////////////////////////////////////////////////////////////////////

void security_pin_entry_window_init(SecurityPinEntryWindow *pin_window, uint8_t pin_len,
                                    SecurityPinEntrySubmitCb submit, void *context) {
  *pin_window = (SecurityPinEntryWindow){
      .pin_len = MAX(SECURITY_LOCK_PIN_MIN_LEN, MIN(SECURITY_LOCK_PIN_MAX_LEN, pin_len)),
      .submit = submit,
      .context = context,
      .pressed_key = -1,
  };

  window_init(&pin_window->window, WINDOW_NAME("Security PIN"));
  window_set_overrides_back_button(&pin_window->window, true);
  // Opt out of the shared navigation recognizers, which would otherwise read a
  // tap on a key as a select and a swipe as a back.
  window_set_touch_bridge_disabled(&pin_window->window, true);
  window_set_click_config_provider_with_context(&pin_window->window, prv_click_config_provider,
                                                pin_window);
  window_set_window_handlers(&pin_window->window, &(WindowHandlers){
    .appear = prv_window_appear,
    .disappear = prv_window_disappear,
  });
  layer_set_update_proc(&pin_window->window.layer, prv_update_proc);
}

void security_pin_entry_window_set_cancelable(SecurityPinEntryWindow *pin_window, bool cancelable) {
  pin_window->cancelable = cancelable;
  prv_update_back_override(pin_window);
}

void security_pin_entry_window_set_dismiss_cb(SecurityPinEntryWindow *pin_window,
                                              SecurityPinEntryDismissCb dismiss) {
  pin_window->dismiss = dismiss;
  prv_update_back_override(pin_window);
}

void security_pin_entry_window_set_pin_len(SecurityPinEntryWindow *pin_window, uint8_t pin_len) {
  pin_window->pin_len = MAX(SECURITY_LOCK_PIN_MIN_LEN, MIN(SECURITY_LOCK_PIN_MAX_LEN, pin_len));
  security_pin_entry_window_reset(pin_window);
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

void security_pin_entry_window_reset(SecurityPinEntryWindow *pin_window) {
  memset(pin_window->digits, 0, sizeof(pin_window->digits));
  pin_window->entered = 0;
  pin_window->pressed_key = -1;
  layer_mark_dirty(&pin_window->window.layer);
}

Window *security_pin_entry_window_get_window(SecurityPinEntryWindow *pin_window) {
  return &pin_window->window;
}

uint8_t security_pin_entry_window_get_entered(const SecurityPinEntryWindow *pin_window) {
  return pin_window->entered;
}

uint8_t security_pin_entry_window_get_pin_len(const SecurityPinEntryWindow *pin_window) {
  return pin_window->pin_len;
}

const char *security_pin_entry_window_get_message(const SecurityPinEntryWindow *pin_window) {
  return pin_window->message;
}

const char *security_pin_entry_window_get_title(const SecurityPinEntryWindow *pin_window) {
  return (pin_window->title != NULL) ? pin_window->title : "";
}

int8_t security_pin_entry_window_get_pressed_key(const SecurityPinEntryWindow *pin_window) {
  return pin_window->pressed_key;
}

char security_pin_entry_window_digit_at(const SecurityPinEntryWindow *pin_window, GPoint point) {
  const int8_t key = prv_key_at(&pin_window->window.layer.bounds, point);
  return (key < 0) ? '\0' : (char)('1' + key);
}

GRect security_pin_entry_window_bar_rect(const SecurityPinEntryWindow *pin_window) {
  return prv_geometry(&pin_window->window.layer.bounds).bar;
}

GRect security_pin_entry_window_text_rect(const SecurityPinEntryWindow *pin_window) {
  return prv_geometry(&pin_window->window.layer.bounds).text;
}
