/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include "process_management/pebble_process_md.h"

// UUID: 547506fb-3c7e-4377-bab0-3e330330afa8
#define LOCKDOWN_UUID {0x54, 0x75, 0x06, 0xfb, 0x3c, 0x7e, 0x43, 0x77, \
                       0xba, 0xb0, 0x3e, 0x33, 0x03, 0x30, 0xaf, 0xa8}

const PebbleProcessMd *lockdown_app_get_app_info(void);
