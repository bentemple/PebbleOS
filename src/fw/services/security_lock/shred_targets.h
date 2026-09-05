/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stddef.h>

#include "pbl/services/blob_db/api.h"

//! A file the shred zeroes, and the BlobDB it backs.
typedef struct {
  const char *filename;
  BlobDBId db_id;
} SecurityShredTarget;

//! The list the wipe walks.
//!
//! Lives in its own translation unit because security_lock_shred_covers_db()
//! answers from it too: the guard that refuses fresh content while locked has
//! to cover exactly what the wipe destroys, and a second copy of the list would
//! drift.
const SecurityShredTarget *security_lock_shred_targets(size_t *count_out);
