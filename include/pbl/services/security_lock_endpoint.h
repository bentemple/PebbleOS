/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "pbl/services/security_lock.h"
#include "pbl/services/security_lock_shred.h"

typedef struct CommSession CommSession;
typedef struct PebbleCommSessionEvent PebbleCommSessionEvent;

//! Inbound handler for the security endpoint. Registered in
//! src/fw/services/comm_session/protocol_endpoints_table.json.
void security_lock_protocol_msg_callback(CommSession *session, const uint8_t *msg, size_t len);

//! Tell the phone its copy is authoritative for these databases, so it resends
//! what the watch no longer holds.
//!
//! Carried on SHRED_COMPLETE. Nothing was necessarily shredded -- writes
//! refused at the door are asked for the same way -- but the request the phone
//! acts on is identical, so the reason code is what distinguishes them.
//!
//! Queued rather than dropped when there is no session, and flushed on the next
//! one. The two cases that need this are precisely the ones with no phone
//! attached: a wipe triggered by the phone going away, and a lock that held the
//! radio down until a moment ago.
//!
//! @param dbs bitmap in SECURITY_SHRED_DB_BIT form. 0 sends nothing.
void security_lock_endpoint_report_resync_needed(SecurityShredReason reason, uint32_t dbs);

//! Tell the phone the lock state changed.
void security_lock_endpoint_send_state_changed(SecurityLockState state);

//! Track connect/disconnect so a locked watch that loses the phone for too
//! long shreds. Called from the kernel event loop.
//!
//! A session opening retires a disconnect countdown and never a manual one:
//! the phone coming back makes the first moot and says nothing at all about the
//! second. A session closing arms a disconnect countdown, and leaves a manual
//! one exactly as it found it.
void security_lock_handle_comm_session_event(const PebbleCommSessionEvent *event);

//! Start the periodic deadline check. Called during service init.
void security_lock_endpoint_init(void);

//! Arm the erase countdown for a lockdown the user asked for, and make sure the
//! periodic check is running.
//!
//! Lives here rather than beside the lock funnel because the deadline record and
//! the timer that reads it are one mechanism, and splitting them would allow a
//! deadline written with nothing running to notice it expire.
//!
//! Arms nothing when Erase After is Never. Keeps a disconnect countdown that was
//! already closer than the configured delay, so pressing Lockdown can only ever
//! bring an erase forward -- but records it as manual either way, which is what
//! stops a reconnect retiring it.
//!
//! Called from security_lock_engage_with_countdown() once the lock has actually
//! taken, so a refused lock leaves no countdown behind.
void security_lock_endpoint_arm_manual_countdown(void);
