/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include "process_management/pebble_process_md.h"

// UUID: 547506fb-3c7e-4377-bab0-3e330330afa8
#define LOCKDOWN_UUID {0x54, 0x75, 0x06, 0xfb, 0x3c, 0x7e, 0x43, 0x77, \
                       0xba, 0xb0, 0x3e, 0x33, 0x03, 0x30, 0xaf, 0xa8}

// UUID: 3e85808e-a741-466a-8e8c-486e696f7033
#define LOCKDOWN_ERASE_UUID {0x3e, 0x85, 0x80, 0x8e, 0xa7, 0x41, 0x46, 0x6a, \
                             0x8e, 0x8c, 0x48, 0x6e, 0x69, 0x6f, 0x70, 0x33}

const PebbleProcessMd *lockdown_app_get_app_info(void);

//! The erasing counterpart, Quick Launch only and only while Erase After is
//! set. Its own UUID because Quick Launch binds one, so the two have to be
//! separately bindable.
const PebbleProcessMd *lockdown_erase_app_get_app_info(void);
