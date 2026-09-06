/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdbool.h>

//! @addtogroup Foundation
//! @{
//!   @addtogroup EventService
//!   @{
//!     @addtogroup SecurityLockService
//!
//! \brief Tells your app whether the watch is locked, and when that changes.
//!
//! The watch can be set to demand a PIN before it will do anything. It locks
//! when the user asks it to, and it can lock itself when the phone goes away.
//! While it is locked the lock screen owns the display, so your app is not what
//! the wearer is looking at -- but it may still be running behind it, and this
//! is how it finds out.
//!
//! Subscribe if your app should draw a lock indicator, or should stop work that
//! only makes sense while someone can see the screen. Use
//! \ref security_lock_service_peek_is_locked() for the state right now, which
//! is what a watchface needs on its first render: an app that only subscribes
//! hears nothing until the next transition.
//!
//! Only locked or unlocked is reported. Why the watch locked, how many PIN
//! attempts are left and which PIN ended the lock are deliberately absent: some
//! of what the lock screen knows is what the user needs kept private even from
//! software they installed themselves, so every unlock looks the same here and
//! nothing should be added that would tell two of them apart. That is also why
//! \ref security_shred_service_subscribe() stays silent for those wipes: the
//! guarantee is about what the two services say together, not about either one
//! read on its own.
//!
//! See \ref security_shred_service_subscribe() for erasing your own data when
//! the watch destroys its own.
//!     @{

//! Callback type for security lock events.
//! @param is_locked true when the watch has just locked, false when it has just
//!   unlocked.
typedef void (*SecurityLockHandler)(bool is_locked);

//! Query whether the watch is currently locked.
//! @return true if the watch is locked, false otherwise. Always false on a
//!   watch where the feature is unavailable or switched off.
bool security_lock_service_peek_is_locked(void);

//! Subscribe to the security lock event service. Once subscribed, the handler
//! is called every time the watch locks or unlocks.
//! @param handler A callback to be executed on a security lock event.
void security_lock_service_subscribe(SecurityLockHandler handler);

//! Unsubscribe from the security lock event service. Once unsubscribed, the
//! previously registered handler will no longer be called.
void security_lock_service_unsubscribe(void);

//!     @} // end addtogroup SecurityLockService
//!   @} // end addtogroup EventService
//! @} // end addtogroup Foundation
