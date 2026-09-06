/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include "event_service_client.h"
#include "security_lock_service.h"

typedef struct __attribute__((packed)) SecurityLockServiceState {
  SecurityLockHandler handler;
  EventServiceInfo sls_info;
} SecurityLockServiceState;

void security_lock_service_state_init(SecurityLockServiceState *state);
