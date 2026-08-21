/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdint.h>

#include "pbl/services/blob_db/api_types.h"

//! Why a shred was run. Mirrors the reason codes on the security protocol
//! endpoint; see docs/proposals/security-lockdown.md.
typedef enum {
  SecurityShredReasonUnknown = 0x00,
  SecurityShredReasonPhoneLockdown = 0x01,
  SecurityShredReasonManualPanic = 0x02,
  SecurityShredReasonDisconnectTimeout = 0x03,
  SecurityShredReasonRebootWhileLocked = 0x04,
  SecurityShredReasonPinAttemptsExhausted = 0x05,
  SecurityShredReasonClockRollback = 0x06,
  //! A duress PIN was entered. The watch unlocks normally and wipes without
  //! any visible sign, so someone watching over the user's shoulder sees an
  //! ordinary unlock.
  SecurityShredReasonDuressPin = 0x07,
} SecurityShredReason;

//! Bit position in the wiped-database bitmap for a given BlobDBId.
#define SECURITY_SHRED_DB_BIT(id) (1u << (id))

//! Set when content outside any BlobDB was wiped too (notification storage
//! backing file, datalogging buffers, coredumps). Informational.
#define SECURITY_SHRED_NON_BLOBDB_BIT (1u << 31)

//! Destroy the sensitive content the watch holds.
//!
//! Wipes notifications, calendar pins, reminders, contacts, weather, iOS
//! notification prefs, app glances and pending datalogging buffers, then
//! sweeps the filesystem so stale copies left by earlier deletes and
//! compactions are physically erased. Also erases the coredump and debug-log
//! flash regions, which sit outside the filesystem and can contain a RAM
//! snapshot including notification text.
//!
//! Deliberately does NOT touch health/activity storage, third-party app
//! persist storage, the app database, or Bluetooth pairing keys. Everything
//! wiped here can be restored by the phone on reconnect, which is what makes
//! the shred safe to trigger aggressively. See the proposal for the reasoning.
//!
//! Marks the watch unfaithful so the phone knows to resend, and leaves a
//! shred-pending flag set for the duration so an interrupted run resumes at
//! next boot.
//!
//! Blocking and slow (seconds to tens of seconds, dominated by sector erases).
//! Must not be called from a task that cannot tolerate that.
//!
//! @param reason why the shred was triggered, for logging and the phone
//! @return bitmap of what was wiped, for SHRED_COMPLETE
uint32_t security_lock_shred(SecurityShredReason reason);

//! Shred from early boot, before the blob dbs and Bluetooth stack exist.
//!
//! Skips the database close/reopen dance (nothing has opened them yet) and
//! defers marking the watch unfaithful until security_lock_finish_boot_shred().
//! Callable from services_normal_early_init(), i.e. after PFS is mounted but
//! before any pixel is drawn or the radio is brought up.
uint32_t security_lock_shred_early(SecurityShredReason reason);

//! Apply the phone-facing side effects of a boot shred once Bluetooth
//! persistent storage is available. No-op if no boot shred happened.
void security_lock_finish_boot_shred(void);

//! Decide whether a shred is owed at boot and run it if so.
//!
//! Owed when a previous shred was interrupted, when the watch is still locked
//! (a reboot is the one way past the lock screen, so it has to cost the data),
//! when a disconnect deadline lapsed while powered off, or when the clock has
//! been wound back.
//!
//! Call from services_normal_early_init() immediately after pfs_init().
void security_lock_handle_boot(void);

//! Name of the shred reason, for logs and the console.
const char *security_lock_shred_reason_str(SecurityShredReason reason);
