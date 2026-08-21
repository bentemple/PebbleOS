/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdint.h>

#include "applib/ui/window.h"
#include "pbl/services/security_lock.h"

//! A window that prompts for a fixed-length numeric PIN.
//!
//! selection_layer is the usual multi-cell entry widget, but it caps at
//! MAX_SELECTION_LAYER_CELLS == 3 and raising that constant would grow every
//! other SelectionLayer in the firmware. This is the same idea in the handful
//! of bytes a PIN actually needs.
//!
//! UP/DOWN change the digit under the cursor, SELECT advances, and SELECT on
//! the last digit submits. BACK is never bound to a handler; whether it does
//! anything at all is up to security_pin_entry_window_set_cancelable(), and the
//! default of "it does nothing" is the one the lock screen needs.

#define SECURITY_PIN_MESSAGE_BUF_SIZE 48

//! @param digits ASCII '0'-'9', `len` long and not NUL terminated. Only valid
//!        for the duration of the call.
typedef void (*SecurityPinEntrySubmitCb)(const char *digits, uint8_t len, void *context);

typedef struct SecurityPinEntryWindow {
  //! Must stay first: the update proc casts the root Layer back to this.
  Window window;
  uint8_t pin_len;
  uint8_t cursor;
  char digits[SECURITY_LOCK_PIN_MAX_LEN];
  //! Not copied, so it has to outlive the window.
  const char *title;
  char message[SECURITY_PIN_MESSAGE_BUF_SIZE];
  SecurityPinEntrySubmitCb submit;
  void *context;
} SecurityPinEntryWindow;

//! Initialises as NOT cancelable, which is what the lock screen wants.
//! @param pin_len clamped to SECURITY_LOCK_PIN_MIN_LEN..MAX_LEN.
void security_pin_entry_window_init(SecurityPinEntryWindow *pin_window, uint8_t pin_len,
                                    SecurityPinEntrySubmitCb submit, void *context);

//! Let BACK dismiss the window by stopping it overriding the back button, so
//! the enclosing stack pops it as usual.
//!
//! For prompts the user is allowed to walk away from -- setting or changing a
//! PIN from Settings. Never for the lock screen, where BACK dismissing the
//! window is exactly the thing being defended against.
void security_pin_entry_window_set_cancelable(SecurityPinEntryWindow *pin_window, bool cancelable);

void security_pin_entry_window_set_title(SecurityPinEntryWindow *pin_window, const char *title);

//! Copied into the window; may be NULL to clear.
void security_pin_entry_window_set_message(SecurityPinEntryWindow *pin_window, const char *message);

//! Change how many digits are prompted for, clamped as in init. Resets entry,
//! since anything typed so far was for a different length.
//!
//! Safe while the window is on a stack: it touches nothing the stack owns.
void security_pin_entry_window_set_pin_len(SecurityPinEntryWindow *pin_window, uint8_t pin_len);

//! Zero the entered digits and put the cursor back on the first one.
void security_pin_entry_window_reset(SecurityPinEntryWindow *pin_window);

Window *security_pin_entry_window_get_window(SecurityPinEntryWindow *pin_window);
