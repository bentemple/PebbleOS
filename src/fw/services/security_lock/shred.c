/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include "pbl/services/security_lock_shred.h"

#include <inttypes.h>
#include <string.h>

#include <pbl/drivers/flash.h>
#include <pbl/drivers/rtc.h>
#include <pbl/drivers/task_watchdog.h>
#include <pbl/logging/logging.h>
#include "flash_region/flash_region.h"
#include "kernel/pebble_tasks.h"
#include "pbl/services/blob_db/pin_db.h"
#include "pbl/services/blob_db/reminder_db.h"
#include "pbl/services/filesystem/pfs.h"
#include "pbl/services/notifications/notification_storage.h"
#include "pbl/services/security_lock.h"
#include "pbl/services/timeline/event.h"
#include "pbl/util/size.h"

#if !defined(CONFIG_RECOVERY_FW)
#include "pbl/services/bluetooth/bluetooth_persistent_storage.h"
#endif

PBL_LOG_MODULE_DECLARE(service_security_lock, CONFIG_SERVICE_SECURITY_LOCK_LOG_LEVEL);

//! Files whose entire contents are destroyed, and the BlobDB each one backs.
//!
//! Health/activity ("activity", "healthdb"), app persist storage ("ps<uuid>"),
//! the app database ("appdb") and the BT bonding store are deliberately absent:
//! the phone cannot restore them, so wiping them would make the feature
//! destructive enough that nobody would turn it on. That is a conscious trade
//! and it means a seized watch still yields step and sleep history.
static const struct {
  const char *filename;
  BlobDBId db_id;
} s_shred_targets[] = {
    // Notification bodies and senders mirrored from the phone.
    {"notifstr", BlobDBIdNotifs},
    // Calendar events: titles, times, locations, attendees.
    {"pindb", BlobDBIdPins},
    {"reminderdb", BlobDBIdReminders},
    // Names, phone numbers and email addresses.
    {"contactsdb", BlobDBIdContacts},
    // Reveals the locations the user watches.
    {"weatherdb", BlobDBIdWeather},
    // Reveals which apps the user has and their reply configuration.
    {"iosnotifprefdb", BlobDBIdiOSNotifPref},
    {"appglancedb", BlobDBIdAppGlance},
};

//! Datalogging session files are named "<prefix><session id>", so they have to
//! be matched by prefix rather than listed.
static const char *DLS_PREFIX = "dls";

const char *security_lock_shred_reason_str(SecurityShredReason reason) {
  switch (reason) {
    case SecurityShredReasonPhoneLockdown:
      return "phone lockdown";
    case SecurityShredReasonManualPanic:
      return "manual panic";
    case SecurityShredReasonDisconnectTimeout:
      return "disconnect timeout";
    case SecurityShredReasonRebootWhileLocked:
      return "reboot while locked";
    case SecurityShredReasonPinAttemptsExhausted:
      return "PIN attempts exhausted";
    case SecurityShredReasonClockRollback:
      return "clock rollback";
    case SecurityShredReasonUnknown:
    default:
      return "unknown";
  }
}

static bool prv_is_dls_file(const char *name) {
  return strncmp(name, DLS_PREFIX, strlen(DLS_PREFIX)) == 0;
}

//! Shred every datalogging buffer still waiting to be uploaded.
static bool prv_shred_dls_files(void) {
  PFSFileListEntry *list = pfs_create_file_list(prv_is_dls_file);
  if (list == NULL) {
    return false;
  }

  bool any = false;
  PFSFileListEntry *entry = list;
  while (entry != NULL) {
    if (pfs_shred(entry->name) == S_SUCCESS) {
      any = true;
    }
    entry = (PFSFileListEntry *)list_get_next(&entry->list_node);
  }

  pfs_delete_file_list(list);
  return any;
}

//! Erase a raw flash region that sits outside the filesystem.
static void prv_erase_flash_region(uint32_t begin, uint32_t end, const char *what) {
  if (begin >= end) {
    return;
  }
  PBL_LOG_DBG("Erasing %s region", what);
  flash_region_erase_optimal_range_no_watchdog(begin, begin, end, end);
  task_watchdog_bit_set(pebble_task_get_current());
}

//! Set when a shred ran before the blob dbs were up, so the phone can be told
//! once the Bluetooth stack exists. See security_lock_finish_boot_shred().
static bool s_boot_shred_pending_notify;

static uint32_t prv_shred(SecurityShredReason reason, bool dbs_running) {
  PBL_LOG_INFO("Shredding: %s", security_lock_shred_reason_str(reason));

  // Set before anything is destroyed so a shred interrupted by power loss is
  // resumed at next boot rather than left half done.
  security_lock_set_shred_pending(true);

  // These databases hold their settings files open, so they have to be closed
  // or the wipe races their cached handles and the file is recreated from
  // stale state afterwards. At early boot they have not been initialised yet
  // and calling into them would be a use-before-init.
  if (dbs_running) {
    timeline_event_deinit();
    reminder_db_deinit();
    pin_db_deinit();
  }

  uint32_t wiped = 0;
  for (size_t i = 0; i < ARRAY_LENGTH(s_shred_targets); ++i) {
    status_t rv = pfs_shred(s_shred_targets[i].filename);
    if (rv == S_SUCCESS) {
      wiped |= SECURITY_SHRED_DB_BIT(s_shred_targets[i].db_id);
    } else {
      PBL_LOG_ERR("Failed to shred %s: %" PRId32, s_shred_targets[i].filename, (int32_t)rv);
    }
    task_watchdog_bit_set(pebble_task_get_current());
  }

  if (prv_shred_dls_files()) {
    wiped |= SECURITY_SHRED_NON_BLOBDB_BIT;
  }

  // A coredump is a snapshot of RAM and can contain notification text or
  // contact details that were resident at the moment of the crash. It lives
  // outside PFS, so a filesystem wipe misses it entirely. Not every flash
  // layout carves out these regions.
#ifdef FLASH_REGION_CD_BEGIN
  prv_erase_flash_region(FLASH_REGION_CD_BEGIN, FLASH_REGION_CD_END, "coredump");
#endif
#ifdef FLASH_REGION_DEBUG_DB_BEGIN
  prv_erase_flash_region(FLASH_REGION_DEBUG_DB_BEGIN, FLASH_REGION_DEBUG_DB_END, "debug log");
#endif
  wiped |= SECURITY_SHRED_NON_BLOBDB_BIT;

  // Zeroing each file kills the live copy, but earlier garbage collection,
  // settings_file compaction and OP_FLAG_OVERWRITE writes scatter superseded
  // copies with no record of where. This is the only thing that reaches those.
  status_t gc_rv = pfs_gc_deleted_sectors();
  if (gc_rv != S_SUCCESS) {
    PBL_LOG_ERR("Shred sweep incomplete: %" PRId32, (int32_t)gc_rv);
  }

  if (dbs_running) {
    // Bring the databases back up against the now-empty files.
    pin_db_init();
    reminder_db_init();
    timeline_event_init();
    notification_storage_reset_and_init();
  }

#if !defined(CONFIG_RECOVERY_FW)
  // Tell the phone its copy is authoritative. Gadgetbridge does not currently
  // read this flag (an explicit SHRED_COMPLETE message covers that), but the
  // official app does, and it costs nothing to be correct for both.
  if (dbs_running) {
    bt_persistent_storage_set_unfaithful(true);
  } else {
    // Bonding storage is not up this early; defer to finish_boot_shred().
    s_boot_shred_pending_notify = true;
  }
#endif

  security_lock_set_shred_pending(false);

  PBL_LOG_INFO("Shred complete, wiped bitmap 0x%" PRIx32, wiped);
  return wiped;
}

uint32_t security_lock_shred(SecurityShredReason reason) {
  return prv_shred(reason, true /* dbs_running */);
}

uint32_t security_lock_shred_early(SecurityShredReason reason) {
  return prv_shred(reason, false /* dbs_running */);
}

void security_lock_handle_boot(void) {
  const time_t now = rtc_get_time();

  // A backwards jump is the only rollback signal available: there is no
  // reboot-persistent monotonic clock on this hardware, so an attacker could
  // otherwise wind the clock back to dodge the disconnect deadline.
  const bool rolled_back = security_lock_note_time(now);

  SecurityShredReason reason;
  if (security_lock_is_shred_pending()) {
    // A previous shred did not finish. Whatever it was, redo it.
    reason = SecurityShredReasonUnknown;
  } else if (security_lock_disconnect_deadline_expired(now)) {
    reason = SecurityShredReasonDisconnectTimeout;
  } else if (rolled_back && security_lock_is_locked()) {
    reason = SecurityShredReasonClockRollback;
  } else if (security_lock_is_locked()) {
    // Holding SELECT+BACK for five seconds hard resets from the button ISR,
    // below anything software can intercept, so rebooting is the one reliable
    // way past the lock screen. Making it a shred trigger is what stops that
    // being a way past the shred as well.
    reason = SecurityShredReasonRebootWhileLocked;
  } else {
    return;
  }

  security_lock_shred_early(reason);
}

void security_lock_finish_boot_shred(void) {
#if !defined(CONFIG_RECOVERY_FW)
  if (!s_boot_shred_pending_notify) {
    return;
  }
  s_boot_shred_pending_notify = false;
  bt_persistent_storage_set_unfaithful(true);
  PBL_LOG_DBG("Marked unfaithful after boot shred");
#endif
}
