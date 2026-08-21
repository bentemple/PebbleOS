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

//! Tell the phone a shred finished, so it knows to resend what it holds.
//! @param wiped_dbs bitmap from security_lock_shred()
void security_lock_endpoint_send_shred_complete(SecurityShredReason reason, uint32_t wiped_dbs);

//! Tell the phone the lock state changed.
void security_lock_endpoint_send_state_changed(SecurityLockState state);

//! Track connect/disconnect so a locked watch that loses the phone for too
//! long shreds. Called from the kernel event loop.
void security_lock_handle_comm_session_event(const PebbleCommSessionEvent *event);

//! Start the periodic deadline check. Called during service init.
void security_lock_endpoint_init(void);
