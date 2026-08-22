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

//! Set when content outside any BlobDB was wiped too: the coredump and
//! debug-log flash regions. Informational.
#define SECURITY_SHRED_NON_BLOBDB_BIT (1u << 31)

//! Destroy the sensitive content the watch holds.
//!
//! Wipes notifications, calendar pins, reminders, contacts, weather, iOS
//! notification prefs and app glances, then sweeps the filesystem so stale
//! copies left by earlier deletes and compactions are physically erased. Also
//! erases the coredump and debug-log flash regions, which sit outside the
//! filesystem and can contain a RAM snapshot including notification text.
//!
//! Deliberately does NOT touch health/activity storage, third-party app
//! persist storage, the app database, Bluetooth pairing keys, or the pending
//! datalogging queue. Everything wiped here can be restored by the phone on
//! reconnect, which is what makes the shred safe to trigger aggressively. See
//! the proposal for the reasoning.
//!
//! Marks the watch unfaithful so the phone knows to resend, and leaves a
//! shred-pending flag set for the duration so an interrupted run resumes at
//! next boot.
//!
//! Blocking (seconds, dominated by the raw-flash region erases). The
//! filesystem sweep is scheduled rather than run inline, so it outlives the
//! call. Must not be called from a task that cannot tolerate the blocking.
//!
//! @param reason why the shred was triggered, for logging and the phone
//! @return bitmap of what was wiped, for SHRED_COMPLETE
uint32_t security_lock_shred(SecurityShredReason reason);

//! Finish a shred that ran at early boot: sweep the filesystem, tell the phone
//! its copy is authoritative, and clear the shred-pending flag. No-op if no
//! boot shred happened.
//!
//! Split out because none of it can run from early boot -- Bluetooth
//! persistent storage does not exist yet, and the sweep is slow cleanup that
//! has no business holding up the boot. Call from services_normal_init().
void security_lock_finish_boot_shred(void);

//! Decide whether a shred is owed at boot and run it if so.
//!
//! Owed when a previous shred was interrupted, when the watch is still locked
//! (a reboot is the one way past the lock screen, so it has to cost the data),
//! when a disconnect deadline lapsed while powered off, or when the clock has
//! been wound back.
//!
//! Zeroes the files inline, which is what puts the data out of reach before a
//! pixel is drawn or the radio comes up. Skips the blob-db close/reopen
//! (nothing has opened them yet) and leaves the sector sweep to
//! security_lock_finish_boot_shred().
//!
//! Call from services_normal_early_init() immediately after pfs_init().
void security_lock_handle_boot(void);

//! Name of the shred reason, for logs and the console.
const char *security_lock_shred_reason_str(SecurityShredReason reason);
