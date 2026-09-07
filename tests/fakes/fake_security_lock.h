/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include "pbl/services/security_lock.h"
#include "pbl/services/security_lock_shred.h"

static bool s_fake_security_lock_locked = false;
static bool s_fake_security_lock_shredding = false;
//! Counts calls rather than tracking a flag, so tests can assert that a write
//! path marks at all and that it does not mark more than once per write.
static int s_fake_security_lock_dirty_marks = 0;
//! Databases whose writes were refused. The real accumulator lives in the lock
//! service; a write path only feeds it.
static uint32_t s_fake_security_lock_refused_dbs = 0;

uint32_t fake_security_lock_get_refused_dbs(void) {
  return s_fake_security_lock_refused_dbs;
}

void fake_security_lock_set_locked(bool locked) {
  s_fake_security_lock_locked = locked;
}

void fake_security_lock_set_shredding(bool shredding) {
  s_fake_security_lock_shredding = shredding;
}

//! Mirrors the block-notifications-when-locked setting, which is on by default.
static bool s_fake_security_lock_block_notifs = true;

void fake_security_lock_set_block_notifications(bool block) {
  s_fake_security_lock_block_notifs = block;
}

int fake_security_lock_get_dirty_marks(void) {
  return s_fake_security_lock_dirty_marks;
}

void fake_security_lock_reset(void) {
  s_fake_security_lock_locked = false;
  s_fake_security_lock_shredding = false;
  s_fake_security_lock_dirty_marks = 0;
  s_fake_security_lock_refused_dbs = 0;
  s_fake_security_lock_block_notifs = true;
}

void security_lock_mark_dirty_since_shred(void) {
  s_fake_security_lock_dirty_marks++;
}

void security_lock_note_write_refused(BlobDBId db_id) {
  s_fake_security_lock_refused_dbs |= SECURITY_SHRED_DB_BIT(db_id);
}

uint32_t security_lock_take_refused_dbs(void) {
  const uint32_t dbs = s_fake_security_lock_refused_dbs;
  s_fake_security_lock_refused_dbs = 0;
  return dbs;
}

bool security_lock_is_locked(void) {
  return s_fake_security_lock_locked;
}

bool security_lock_is_shredding(void) {
  return s_fake_security_lock_shredding;
}

//! Mirrors security_lock_should_drop_notifications() in
//! src/fw/services/security_lock/service.c.
bool security_lock_should_drop_notifications(void) {
  if (s_fake_security_lock_shredding) {
    return true;
  }
  return s_fake_security_lock_locked && s_fake_security_lock_block_notifs;
}
