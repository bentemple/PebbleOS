/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

//! @addtogroup Foundation
//! @{
//!   @addtogroup EventService
//!   @{
//!     @addtogroup SecurityShredService
//!
//! \brief Notifies your app that the watch is destroying its sensitive data.
//!
//! The watch can be told to destroy the personal data it holds -- notifications,
//! calendar pins, reminders, contacts, weather and so on -- either from the
//! phone or by a watch-side trigger such as too many failed PIN attempts. The
//! system does not touch your app's persist storage when it does this, because
//! nothing could restore it afterwards. This service is how your app gets to
//! make that call for itself.
//!
//! Subscribe if your app stores anything the user would not want read off a
//! watch they no longer control, and delete it with \ref persist_delete() from
//! the handler. Be clear on what that buys: persist_delete() unlinks the value,
//! it does not overwrite it, so the bytes stay in your store's flash until the
//! store is next compacted. Rewriting the key with zeroes is no better, because
//! a write appends a new record and marks the old one superseded rather than
//! erasing it. Deleting is still the strongest thing this API offers, but if
//! something has to be provably unrecoverable within seconds, do not keep it on
//! the watch to begin with.
//!
//! The callback is best-effort, not a barrier. It is queued when the wipe
//! begins, but only queued: your handler runs on your own task while the
//! system's wipe runs to completion first, so it always arrives after the
//! system's own data is already gone. It reaches only an app or worker that is
//! running and subscribed at that moment, and the wipe closes a running
//! foreground app before it announces anything, so in practice this is
//! delivered to a watchface or a background worker and to nothing else. Treat
//! it as an opportunity, not a guarantee.
//!
//! No reason for the wipe is reported, and some wipes are not reported at all.
//! A few of the triggers are ones the user needs kept private even from
//! software they installed themselves; for those the system says nothing here,
//! rather than let a subscriber line this callback up against anything else it
//! can observe -- \ref security_lock_service_subscribe() above all. For the
//! same reason a handler should erase what it needs to erase and return:
//! showing something on screen, vibrating or playing a sound makes the wipe
//! observable to whoever is holding the watch.
//!     @{

//! Callback type for security shred events.
typedef void (*SecurityShredHandler)(void);

//! Subscribe to the security shred event service. Once subscribed, the handler
//! is called when the watch is about to destroy the sensitive data it holds.
//! @param handler A callback to be executed on a security shred event.
void security_shred_service_subscribe(SecurityShredHandler handler);

//! Unsubscribe from the security shred event service. Once unsubscribed, the
//! previously registered handler will no longer be called.
void security_shred_service_unsubscribe(void);

//!     @} // end addtogroup SecurityShredService
//!   @} // end addtogroup EventService
//! @} // end addtogroup Foundation
