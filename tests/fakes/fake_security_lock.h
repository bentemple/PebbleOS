/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include "pbl/services/security_lock.h"

static bool s_fake_security_lock_locked = false;
static bool s_fake_security_lock_shredding = false;
//! Counts calls rather than tracking a flag, so tests can assert that a write
//! path marks at all and that it does not mark more than once per write.
static int s_fake_security_lock_dirty_marks = 0;

void fake_security_lock_set_locked(bool locked) {
  s_fake_security_lock_locked = locked;
}

void fake_security_lock_set_shredding(bool shredding) {
  s_fake_security_lock_shredding = shredding;
}

int fake_security_lock_get_dirty_marks(void) {
  return s_fake_security_lock_dirty_marks;
}

void fake_security_lock_reset(void) {
  s_fake_security_lock_locked = false;
  s_fake_security_lock_shredding = false;
  s_fake_security_lock_dirty_marks = 0;
}

void security_lock_mark_dirty_since_shred(void) {
  s_fake_security_lock_dirty_marks++;
}

bool security_lock_is_locked(void) {
  return s_fake_security_lock_locked;
}

bool security_lock_is_shredding(void) {
  return s_fake_security_lock_shredding;
}
