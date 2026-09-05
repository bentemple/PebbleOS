/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include "event_service_client.h"
#include "security_shred_service.h"

typedef struct __attribute__((packed)) SecurityShredServiceState {
  SecurityShredHandler handler;
  EventServiceInfo sss_info;
} SecurityShredServiceState;

void security_shred_service_state_init(SecurityShredServiceState *state);
