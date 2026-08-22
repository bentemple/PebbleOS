/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "applib/ui/window.h"
#include "pbl/services/security_lock.h"

//! A window that prompts for a PIN on a 3x3 touch pad.
//!
//! Digits are 1 to 9, one key each. There is no zero: nine keys divide evenly
//! into a square grid, and a tenth key would either shrink the other nine or
//! sit on its own row.
//!
//! A progress bar along the top carries all the feedback -- one segment per
//! digit, filled as they are entered. The digits themselves are never shown,
//! so the pad is safe to use with someone standing behind you.
//!
//! BACK clears the whole entry rather than the last digit: there is no cursor
//! to walk back along, and a lock screen should not reward guessing one digit
//! at a time. A cancelable window has no BACK handler at all and is popped by
//! the enclosing stack instead; a window with a dismiss callback hands BACK to
//! its owner.

#define SECURITY_PIN_MESSAGE_BUF_SIZE 48

//! Digits 1..9, laid out 3x3.
#define SECURITY_PIN_PAD_KEYS 9
#define SECURITY_PIN_PAD_COLS 3
#define SECURITY_PIN_PAD_ROWS 3

//! @param digits ASCII '1'-'9', `len` long and not NUL terminated. Only valid
//!        for the duration of the call.
typedef void (*SecurityPinEntrySubmitCb)(const char *digits, uint8_t len, void *context);

//! @param context the context passed to security_pin_entry_window_init().
typedef void (*SecurityPinEntryDismissCb)(void *context);

typedef struct SecurityPinEntryWindow {
  //! Must stay first: the update proc casts the root Layer back to this.
  Window window;
  uint8_t pin_len;
  uint8_t entered;
  char digits[SECURITY_LOCK_PIN_MAX_LEN];
  //! Not copied, so it has to outlive the window.
  const char *title;
  char message[SECURITY_PIN_MESSAGE_BUF_SIZE];
  SecurityPinEntrySubmitCb submit;
  //! NULL unless the owner wants BACK for itself.
  SecurityPinEntryDismissCb dismiss;
  void *context;
  bool cancelable;
  //! Whether the raw touch subscription is currently held. Taken on appear and
  //! dropped on disappear, so a window pushed over this one does not have its
  //! taps stolen.
  bool touch_subscribed;
  //! Key under the finger, or -1 for none. Drawn pressed, and only committed if
  //! the finger is still on it at liftoff.
  int8_t pressed_key;
} SecurityPinEntryWindow;

//! Initialises as NOT cancelable, which is what the lock screen wants.
//! @param pin_len clamped to SECURITY_LOCK_PIN_MIN_LEN..MAX_LEN.
void security_pin_entry_window_init(SecurityPinEntryWindow *pin_window, uint8_t pin_len,
                                    SecurityPinEntrySubmitCb submit, void *context);

//! Let BACK dismiss the window instead of clearing the entry, by stopping it
//! overriding the back button so the enclosing stack pops it as usual.
//!
//! For prompts the user is allowed to walk away from -- setting or changing a
//! PIN from Settings. Never for the lock screen, where BACK dismissing the
//! window is exactly the thing being defended against.
void security_pin_entry_window_set_cancelable(SecurityPinEntryWindow *pin_window, bool cancelable);

//! Hand BACK to the owner instead of clearing the entry.
//!
//! For a window whose dismissal is more than taking it off a stack. The lock
//! screen has to stop reporting itself visible and put back the touch setting
//! it forced on for the pad, neither of which the window stack knows about, so
//! it does the removal itself rather than find the window gone from under it.
//!
//! The entry is cleared before the callback runs, so a half typed PIN is never
//! left behind in a window that is off screen. Nothing is submitted, so this
//! costs no attempt.
//!
//! Wins over `cancelable`, whichever order the two are set in.
void security_pin_entry_window_set_dismiss_cb(SecurityPinEntryWindow *pin_window,
                                              SecurityPinEntryDismissCb dismiss);

void security_pin_entry_window_set_title(SecurityPinEntryWindow *pin_window, const char *title);

//! Copied into the window; may be NULL to clear.
void security_pin_entry_window_set_message(SecurityPinEntryWindow *pin_window, const char *message);

//! Change how many digits are prompted for, clamped as in init. Resets entry,
//! since anything typed so far was for a different length.
//!
//! Safe while the window is on a stack: it touches nothing the stack owns.
void security_pin_entry_window_set_pin_len(SecurityPinEntryWindow *pin_window, uint8_t pin_len);

//! Zero the entered digits and empty the progress bar.
void security_pin_entry_window_reset(SecurityPinEntryWindow *pin_window);

Window *security_pin_entry_window_get_window(SecurityPinEntryWindow *pin_window);

//! Read back what the pad is showing, for the console's `security ui` command.
//!
//! The pad draws its text inline rather than through a TextLayer, so there is
//! no child layer for a generic walker to find and an automated test has no way
//! to see the screen without these.
//!
//! `digits` is deliberately absent and must stay that way: it is the PIN as it
//! is being typed, and the console is reachable from a seized watch.
uint8_t security_pin_entry_window_get_entered(const SecurityPinEntryWindow *pin_window);
uint8_t security_pin_entry_window_get_pin_len(const SecurityPinEntryWindow *pin_window);
//! Never NULL; empty when nothing is set.
const char *security_pin_entry_window_get_message(const SecurityPinEntryWindow *pin_window);
const char *security_pin_entry_window_get_title(const SecurityPinEntryWindow *pin_window);
//! The key under the finger, or -1 for none.
int8_t security_pin_entry_window_get_pressed_key(const SecurityPinEntryWindow *pin_window);

//! Which key a point lands on, in the window's own coordinates.
//!
//! The one place the pad geometry is interpreted, so drawing and hit testing
//! cannot drift apart and leave keys that do not do what they look like.
//!
//! @return the digit '1'..'9', or '\0' for a gap between keys or a point off
//!         the pad entirely.
char security_pin_entry_window_digit_at(const SecurityPinEntryWindow *pin_window, GPoint point);
