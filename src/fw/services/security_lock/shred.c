/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include "pbl/services/security_lock_shred.h"

#include <inttypes.h>
#include <string.h>

#include <pbl/drivers/flash.h>
#include <pbl/drivers/rtc.h>
#include <pbl/drivers/task_watchdog.h>
#include <pbl/logging/logging.h>
#include "debug/flash_logging.h"
#include "flash_region/flash_region.h"
#include "kernel/event_loop.h"
#include "kernel/events.h"
#include "kernel/pebble_tasks.h"
#include "pbl/services/blob_db/pin_db.h"
#include "pbl/services/blob_db/reminder_db.h"
#include "pbl/services/filesystem/pfs.h"
#include "pbl/services/notifications/notification_storage.h"
#include "pbl/services/new_timer/new_timer.h"
#include "pbl/services/security_lock.h"
#include "pbl/services/security_lock_endpoint.h"
#include "pbl/services/system_task.h"
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
    case SecurityShredReasonDuressPin:
      return "duress PIN";
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
  task_watchdog_bit_set_all();
}

//! Sectors collected per pass, and the gap between passes.
//!
//! The gap is the important half. Rescheduling immediately hands the task back
//! but instantly takes it again, so KernelBG stays saturated for the whole
//! sweep and anything else queued on it -- the console among them -- waits
//! minutes. The urgent part of the wipe is already done by the time this runs;
//! this is cleanup and can afford to be slow.
#define SWEEP_SECTORS_PER_PASS 4
#define SWEEP_PASS_GAP_MS 250

//! Hard ceiling on a whole sweep.
//!
//! Collecting a sector relocates the live pages in it, which leaves fresh
//! deleted pages behind, so "collected nothing this pass" is not a state the
//! sweep reliably reaches -- without a ceiling it reschedules itself forever
//! and starves the task it runs on. One pass over the filesystem is what the
//! shred needs; anything beyond that is chasing its own tail.
#define SWEEP_SECTORS_MAX 384

static int s_sweep_budget;
static TimerID s_sweep_timer = TIMER_INVALID_ID;

static void prv_schedule_next_pass(void);

//! Erase stale sectors a few at a time, rescheduling until there are none left.
//!
//! Doing the whole filesystem in one call blocks whichever task runs it for
//! minutes -- long enough that the console stops answering and the watch looks
//! hung. The work is idempotent and resumable, because a collected sector no
//! longer contains deleted pages, so it can be chopped up freely.
static void prv_sweep_pass(void *unused) {
  const PebbleTask task = pebble_task_get_current();
  task_watchdog_mask_clear(task);
  const int collected = pfs_gc_deleted_sectors(SWEEP_SECTORS_PER_PASS);
  task_watchdog_mask_set(task);

  s_sweep_budget -= collected;
  // Logged every pass: this is the slow part of the wipe, and without it a
  // sweep that is merely grinding is indistinguishable from one that is stuck.
  PBL_LOG_DBG("Shred sweep pass: %d sector(s), %d of budget left", collected, s_sweep_budget);
  if ((collected > 0) && (s_sweep_budget > 0)) {
    prv_schedule_next_pass();
    return;
  }
  PBL_LOG_DBG("Shred sweep finished, %d of budget left", s_sweep_budget);
}

static void prv_sweep_timer_cb(void *unused) {
  system_task_add_callback(prv_sweep_pass, NULL);
}

static void prv_schedule_next_pass(void) {
  if (s_sweep_timer == TIMER_INVALID_ID) {
    s_sweep_timer = new_timer_create();
  }
  if (s_sweep_timer == TIMER_INVALID_ID) {
    // No timer to be had; fall back to running straight on, which is worse for
    // responsiveness but still finishes.
    system_task_add_callback(prv_sweep_pass, NULL);
    return;
  }
  new_timer_start(s_sweep_timer, SWEEP_PASS_GAP_MS, prv_sweep_timer_cb, NULL, 0 /* flags */);
}

static void prv_start_sweep(void) {
  s_sweep_budget = SWEEP_SECTORS_MAX;
  prv_schedule_next_pass();
}

static uint32_t prv_shred(SecurityShredReason reason, bool dbs_running, bool sweep) {
  PBL_LOG_INFO("Shredding: %s", security_lock_shred_reason_str(reason));

  // Erasing takes seconds and there is no way to yield through it, so the
  // watchdog has to stop supervising this task or it resets us mid-wipe --
  // which, since a reboot while locked shreds again, is a boot loop rather
  // than a one-off. factory_reset_fast() does the same for the same reason.
  const PebbleTask task = pebble_task_get_current();
  task_watchdog_mask_clear(task);

  // Set before anything is destroyed so a shred interrupted by power loss is
  // resumed at next boot rather than left half done.
  security_lock_set_shred_pending(true);

  // Announce before wiping, so anything holding data of its own gets the
  // chance to destroy it rather than being told afterwards. Not emitted at
  // early boot: nothing is subscribed yet and the event system is not up.
  if (dbs_running) {
    PebbleEvent event = {
        .type = PEBBLE_SECURITY_SHRED_EVENT,
        .security_shred = {.reason = (uint8_t)reason},
    };
    event_put(&event);
  }

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
    task_watchdog_bit_set_all();
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
  // flash_logging caches an address inside this region, so erasing it without
  // telling the logger leaves that pointing at erased flash. Everything logs,
  // so a confused logger takes the task with it -- which presented as the
  // console going silent for good while the display carried on fine.
  flash_logging_set_enabled(false);
  prv_erase_flash_region(FLASH_REGION_DEBUG_DB_BEGIN, FLASH_REGION_DEBUG_DB_END, "debug log");
  flash_logging_init();
  flash_logging_set_enabled(true);
#endif
  wiped |= SECURITY_SHRED_NON_BLOBDB_BIT;

  // Zeroing each file kills the live copy, but earlier garbage collection,
  // settings_file compaction and OP_FLAG_OVERWRITE writes scatter superseded
  // copies with no record of where. This is the only thing that reaches those.
  //
  // It is also the slow half: a sector erase is ~150ms and the filesystem is
  // hundreds of sectors. At early boot it is deferred rather than run inline,
  // because blocking services_normal_early_init() for that long leaves the
  // watch sitting on the boot splash looking dead.
  if (sweep) {
    prv_start_sweep();
  }

  if (dbs_running) {
    // Bring the databases back up against the now-empty files.
    pin_db_init();
    reminder_db_init();
    timeline_event_init();
    notification_storage_reset_and_init();
  }

#if !defined(CONFIG_RECOVERY_FW)
  // A duress wipe must not ask the phone to resend: the phone would cheerfully
  // restore everything within seconds and the duress PIN would accomplish
  // nothing. It stays gone until the user deliberately resyncs.
  const bool notify_phone = (reason != SecurityShredReasonDuressPin);

  // Tell the phone its copy is authoritative. Gadgetbridge does not currently
  // read this flag (an explicit SHRED_COMPLETE message covers that), but the
  // official app does, and it costs nothing to be correct for both.
  if (notify_phone) {
    bt_persistent_storage_set_unfaithful(true);
  }
#endif

  security_lock_set_shred_pending(false);

  task_watchdog_mask_set(task);
  PBL_LOG_INFO("Shred complete, wiped bitmap 0x%" PRIx32, wiped);

#if !defined(CONFIG_RECOVERY_FW)
  // Reported from here rather than from each caller so no trigger can forget:
  // this is what tells the phone to resend what it holds. A no-op when there is
  // no session, which is the common case when the phone going away is what
  // caused the shred -- the boot-time unfaithful flag covers that.
  if (dbs_running && (reason != SecurityShredReasonDuressPin)) {
    security_lock_endpoint_send_shred_complete(reason, wiped);
  }
#endif
  return wiped;
}

uint32_t security_lock_shred(SecurityShredReason reason) {
  return prv_shred(reason, true /* dbs_running */, true /* sweep */);
}

void security_lock_handle_boot(void) {
  const time_t now = rtc_get_time();

  // A backwards jump is the only rollback signal available: there is no
  // reboot-persistent monotonic clock on this hardware, so an attacker could
  // otherwise wind the clock back to dodge the disconnect deadline.
  const bool rolled_back = security_lock_note_time(now);

  // Rebooting is the one reliable way past the lock screen: SELECT+BACK held
  // for five seconds hard resets from the button ISR, below anything software
  // can intercept. So any reboot while a response was armed -- locked, or
  // counting down towards it -- owes a wipe. Restarting must never be cheaper
  // than waiting, and everything destroyed comes back from the phone.
  const bool was_armed = security_lock_is_locked() ||
                         (security_lock_get_lock_deadline() != 0) ||
                         (security_lock_get_shred_deadline() != 0);

  if (!security_lock_is_shred_pending() && !was_armed &&
      !security_lock_shred_deadline_expired(now) && !rolled_back) {
    return;
  }

  // Deliberately does not wipe anything here. This runs inside
  // services_normal_early_init(), before the display, the radio or the task
  // that owns the databases exist, and erasing flash from it blocks the boot
  // for as long as it takes -- which presented as a watch sitting on the boot
  // splash, apparently dead. Record what is owed and let
  // security_lock_finish_boot_shred() run it once the system is up.
  //
  // The delay is safe: the flag persists, so the wipe survives power being
  // pulled and simply happens on a later boot, and the watch comes back locked
  // in the meantime.
  security_lock_set_shred_pending(true);
  if (!security_lock_is_locked() && (security_lock_get_pin_len() != 0)) {
    security_lock_set_state(SecurityLockStateLocked);
  }
  PBL_LOG_INFO("Wipe owed at boot; deferred until the system is up");
}

//! Runs the wipe that security_lock_handle_boot() deferred.
static void prv_boot_shred_callback(void *unused) {
  security_lock_shred(SecurityShredReasonRebootWhileLocked);
}

void security_lock_finish_boot_shred(void) {
  if (!security_lock_is_shred_pending()) {
    return;
  }
  // On the launcher task, like every other path: the wipe closes and reopens
  // databases and deadlocks if driven from KernelBG.
  PBL_LOG_INFO("Running the wipe deferred from boot");
  launcher_task_add_callback(prv_boot_shred_callback, NULL);
}
