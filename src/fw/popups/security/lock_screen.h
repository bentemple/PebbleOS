/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdbool.h>

#include "kernel/ui/modals/modal_manager.h"
#include "popups/security/pin_entry_window.h"

//! The PIN screen shown while the watch is in SecurityLockStateLocked.
//!
//! A modal, not an app: launcher_handle_button_event() force-quits any app at
//! ProcessAppRunLevelNormal when BACK is held, which would pop a lock screen
//! implemented as an app. Modals are not reachable from that path.
//!
//! It is not pushed when the watch locks -- the clock stays up and the first
//! button press raises this, from launcher_handle_button_event(). BACK puts it
//! away again, returning to that same state: still locked, still inaccessible,
//! and one button press away from the pad.

//! A level of its own, above every other modal, so nothing can be pushed over
//! the pad or take its buttons. Not ModalPriorityMax, which is the "no modals
//! at all" sentinel and would stop the lock screen itself being pushed.
#define SECURITY_LOCK_MODAL_PRIORITY ModalPrioritySecurityLock

//! No-op if it is already up, or if no PIN is configured to prompt for.
//! KernelMain only.
void security_lock_screen_push(void);

//! Takes the pad off the screen and clears anything typed into it. Says nothing
//! about the lock state: unlocking pops the screen, but so does BACK.
void security_lock_screen_pop(void);

bool security_lock_screen_is_visible(void);

//! The pad behind the lock screen, for console introspection, or NULL when the
//! screen is not up -- the window is only meaningful once it has been
//! initialised by a push.
//!
//! const because the caller has no business driving it: entering a PIN from
//! the console would defeat the attempt counter.
const SecurityPinEntryWindow *security_lock_screen_get_pin_window(void);
