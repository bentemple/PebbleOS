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
//! A progress bar along the top carries all the visible feedback -- one
//! segment per digit, filled as they are entered. The digits themselves are
//! never shown, so the pad is safe to use with someone standing behind you.
//! Each accepted key also gives a short vibe, since keys painted on glass have
//! no travel and the bar is not where the user is looking.
//!
//! BACK takes back the last digit. Nothing is checked until a full length is
//! entered, so this gives nothing away and costs no attempt; it just means a
//! mistyped digit costs one press instead of the whole PIN. With the entry
//! already empty, BACK falls through to whatever the owner asked for: a window
//! with a dismiss callback hands the button over, and anything else absorbs
//! it. A cancelable window has no BACK handler at all -- the enclosing stack
//! pops it -- so it never deletes.

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

//! Let BACK pop the window, by stopping it overriding the back button so the
//! enclosing stack pops it as usual. The window then sees no BACK presses at
//! all, so it cannot delete digits either.
//!
//! For prompts the user is allowed to walk away from -- setting or changing a
//! PIN from Settings. Never for the lock screen, where BACK dismissing the
//! window is exactly the thing being defended against.
void security_pin_entry_window_set_cancelable(SecurityPinEntryWindow *pin_window, bool cancelable);

//! Hand BACK to the owner, once there is nothing left to delete.
//!
//! For a window whose dismissal is more than taking it off a stack. The lock
//! screen has to stop reporting itself visible and put back the touch setting
//! it forced on for the pad, neither of which the window stack knows about, so
//! it does the removal itself rather than find the window gone from under it.
//!
//! The entry is empty by the time the callback runs -- emptying it is what the
//! earlier presses did -- so a half typed PIN is never left behind in a window
//! that is off screen. Nothing is submitted, so this costs no attempt.
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

//! Where the progress bar and the title/message text sit, in the window's own
//! coordinates.
//!
//! Taken from the same layout the update proc draws from, for the same reason
//! digit_at() is: a test that re-derived these would be checking its own
//! arithmetic rather than the pad's, and would go on passing after the layout
//! moved out from under it.
GRect security_pin_entry_window_bar_rect(const SecurityPinEntryWindow *pin_window);
GRect security_pin_entry_window_text_rect(const SecurityPinEntryWindow *pin_window);
