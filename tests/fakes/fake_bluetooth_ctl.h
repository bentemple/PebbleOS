/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdbool.h>

#include "pbl/services/bluetooth/bluetooth_ctl.h"

//! Airplane mode as bt_ctl would report it, and a count of the writes so a test
//! can tell "was left alone" apart from "was set to the value it already had".
static bool s_fake_bt_ctl_airplane_mode = false;
static int s_fake_bt_ctl_airplane_writes = 0;

void fake_bt_ctl_reset(void) {
  s_fake_bt_ctl_airplane_mode = false;
  s_fake_bt_ctl_airplane_writes = 0;
}

//! Stand in for the user having set airplane mode themselves.
void fake_bt_ctl_set_airplane_mode(bool on) {
  s_fake_bt_ctl_airplane_mode = on;
}

int fake_bt_ctl_get_airplane_writes(void) {
  return s_fake_bt_ctl_airplane_writes;
}

bool bt_ctl_is_airplane_mode_on(void) {
  return s_fake_bt_ctl_airplane_mode;
}

void bt_ctl_set_airplane_mode_async(bool enabled) {
  s_fake_bt_ctl_airplane_mode = enabled;
  s_fake_bt_ctl_airplane_writes++;
}
