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
//! the last digit submits. BACK is left unbound and the window overrides it, so
//! a hosting modal cannot be dismissed with it.

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

//! @param pin_len clamped to SECURITY_LOCK_PIN_MIN_LEN..MAX_LEN.
void security_pin_entry_window_init(SecurityPinEntryWindow *pin_window, uint8_t pin_len,
                                    SecurityPinEntrySubmitCb submit, void *context);

void security_pin_entry_window_set_title(SecurityPinEntryWindow *pin_window, const char *title);

//! Copied into the window; may be NULL to clear.
void security_pin_entry_window_set_message(SecurityPinEntryWindow *pin_window, const char *message);

//! Zero the entered digits and put the cursor back on the first one.
void security_pin_entry_window_reset(SecurityPinEntryWindow *pin_window);

Window *security_pin_entry_window_get_window(SecurityPinEntryWindow *pin_window);
