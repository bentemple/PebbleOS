/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include "pbl/services/security_lock_shred.h"

//! Entering and leaving the locked state, and the input lockout that goes with
//! it. See docs/architecture/security_lock.md.

//! Enter the locked state: kill the running app, drop to the watchface, and
//! shred.
//!
//! The lock screen is deliberately not pushed here. The clock stays visible and
//! the first button press raises it, which keeps the watch useful as a watch
//! while locked.
//!
//! Blocks for the duration of the shred, which is seconds. KernelMain only.
//! Safe to call when already locked, in which case it re-shreds.
//!
//! Does nothing at all when the feature is off, or when it is on with a PIN
//! length the lock screen could not prompt for. Erasing without locking would
//! destroy the content of a watch that was never protected and leave it open
//! afterwards, which is neither half of what this is for.
//!
//! Callers must not assume it took: check security_lock_is_locked().
void security_lock_engage(SecurityShredReason reason);

//! Enter the locked state without shredding and without arming anything.
//! KernelMain only.
//!
//! For the disconnect lock deadline, where the shred deadline was armed by the
//! same disconnect and already decides when -- or whether -- the content goes.
//! Same refusals as above.
void security_lock_engage_lock_only(SecurityShredReason reason);

//! Enter the locked state and start the erase countdown. KernelMain only.
//!
//! What every manual trigger does: the Lock app, the Quick Launch chord,
//! the Settings row and the phone's LOCK. The watch locks at once and erases
//! at the configured Erase After unless the PIN is entered first, exactly as a
//! disconnect countdown behaves -- so a lockdown hit by accident costs a PIN
//! entry rather than the watch's content.
//!
//! With Erase After set to Never this locks and arms nothing. That is how a
//! user gets lock-without-erase, and it is why there is no separate lock-only
//! action on any menu.
//!
//! The countdown is recorded as manual, so a reconnect cannot cancel it and a
//! later disconnect cannot reschedule it. It never postpones an erase that was
//! already scheduled: a disconnect countdown already closer than the configured
//! delay is kept, and merely promoted to manual.
//!
//! Same refusals as above.
void security_lock_engage_with_countdown(SecurityShredReason reason);

//! Leave the locked state after a correct PIN. KernelMain only.
void security_lock_disengage(void);

//! Apply the input lockout that belongs to the locked state: no popups over the
//! clock, and no modal below the lock screen's own priority.
//!
//! Idempotent, because launcher_block_popups() is reference counted and both
//! security_lock_engage() and the lock screen want this applied -- a watch that
//! rebooted straight into the locked state never ran engage().
void security_lock_ui_lockout(void);

//! Get everything that could be showing, holding or re-reading the content off
//! the screen, and repaint. KernelMain only.
//!
//! Called by the shred itself before the first file is zeroed, so no trigger
//! can forget. A consumer left up over a wipe does not merely show stale text:
//! the notification window re-reads its backing record on every reload and
//! dereferences the NULL layout it gets back when the read fails.
//!
//! Leaves the lock screen alone -- it displays nothing that gets shredded, and
//! the duress and attempts-exhausted wipes are triggered from it.
void security_lock_ui_quiesce(void);
