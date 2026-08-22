/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include "pbl/services/security_lock.h"

static bool s_fake_security_lock_locked = false;
static bool s_fake_security_lock_shredding = false;

void fake_security_lock_set_locked(bool locked) {
  s_fake_security_lock_locked = locked;
}

void fake_security_lock_set_shredding(bool shredding) {
  s_fake_security_lock_shredding = shredding;
}

void fake_security_lock_reset(void) {
  s_fake_security_lock_locked = false;
  s_fake_security_lock_shredding = false;
}

bool security_lock_is_locked(void) {
  return s_fake_security_lock_locked;
}

bool security_lock_is_shredding(void) {
  return s_fake_security_lock_shredding;
}
