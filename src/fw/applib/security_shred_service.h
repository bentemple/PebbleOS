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
//! watch they no longer control, and erase it with \ref persist_delete() from
//! the handler.
//!
//! The callback is best-effort, not a barrier: it is sent just before the wipe
//! starts, but it is delivered asynchronously and your handler runs on your own
//! task, so it may run alongside or after the system's own wipe. It is only
//! delivered to an app or worker that is running and subscribed at that moment,
//! which for most apps means it will never arrive -- treat it as an
//! opportunity, not a guarantee.
//!
//! No reason for the wipe is reported. Some of the triggers are ones the user
//! needs to keep private even from software they installed themselves, so the
//! callback deliberately carries no information beyond the fact that it
//! happened. For the same reason, a handler should erase what it needs to erase
//! and return: showing something on screen, vibrating or playing a sound makes
//! the wipe observable to whoever is holding the watch.
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
