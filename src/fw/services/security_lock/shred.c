/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include "pbl/services/security_lock_shred.h"

#include "shred_targets.h"

#include <inttypes.h>

#include <pbl/drivers/flash.h>
#include <pbl/drivers/rtc.h>
#include <pbl/drivers/task_watchdog.h>
#include <pbl/logging/logging.h>
#include "debug/flash_logging.h"
#include "flash_region/flash_region.h"
#include "kernel/events.h"
#include "kernel/pebble_tasks.h"
#include "pbl/services/blob_db/pin_db.h"
#include "pbl/services/blob_db/reminder_db.h"
#include "pbl/services/filesystem/pfs.h"
#include "pbl/services/notifications/notification_storage.h"
#include "pbl/services/new_timer/new_timer.h"
#include "pbl/services/security_lock.h"
#include "pbl/services/security_lock_endpoint.h"
#include "pbl/services/security_lock_ui.h"
#include "pbl/services/system_task.h"
#include "pbl/services/timeline/event.h"
#include "system/bootbits.h"
#include "system/passert.h"

#if !defined(CONFIG_RECOVERY_FW)
#include "pbl/services/bluetooth/bluetooth_persistent_storage.h"
#endif

PBL_LOG_MODULE_DECLARE(service_security_lock, CONFIG_SERVICE_SECURITY_LOCK_LOG_LEVEL);

//! True for the duration of prv_shred(). See security_lock_is_shredding().
static bool s_shredding;

bool security_lock_is_shredding(void) {
  return s_shredding;
}

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

//! Erase a raw flash region that sits outside the filesystem.
static void prv_erase_flash_region(uint32_t begin, uint32_t end, const char *what) {
  if (begin >= end) {
    return;
  }
  PBL_LOG_DBG("Erasing %s region", what);
  flash_region_erase_optimal_range_no_watchdog(begin, begin, end, end);
  task_watchdog_bit_set(pebble_task_get_current());
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

//! Hard ceiling on a whole sweep: one pass over the filesystem, sized from the
//! filesystem itself rather than guessed.
//!
//! Collecting a sector relocates the live pages in it, which leaves fresh
//! deleted pages behind, so "collected nothing this pass" is not a state the
//! sweep reliably reaches -- without a ceiling it reschedules itself forever
//! and starves the task it runs on. Every sector holding stale payload is
//! reachable within one pass; anything beyond that is chasing its own tail.
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
  if (collected == 0) {
    PBL_LOG_DBG("Shred sweep finished, %d of budget left", s_sweep_budget);
    return;
  }
  if (s_sweep_budget <= 0) {
    // A whole pass over the filesystem was not enough. Loud, because stopping
    // here leaves stale copies on flash and nothing else will notice.
    PBL_LOG_WRN("Shred sweep hit its ceiling with sectors still to collect");
    return;
  }
  prv_schedule_next_pass();
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
  s_sweep_budget = pfs_get_erase_region_count();
  prv_schedule_next_pass();
}

//! True when the filesystem half of a wipe would destroy nothing.
//!
//! Almost everything a wipe erases came from the phone, so if the phone has not
//! written anything back since the last wipe there is nothing new to reach.
//! shred_pending outranks the flag: an interrupted wipe has to finish, or a
//! half-wiped filesystem passes for a clean one.
static bool prv_storage_is_clean(void) {
  return !security_lock_is_shred_pending() && !security_lock_is_dirty_since_shred();
}

//! @param dbs_running the blob dbs are up, so they have to be closed and
//!                    reopened around the wipe and events can be published
//! @param finish      run the tail here -- sector sweep, unfaithful flag,
//!                    clearing shred_pending. False at early boot, where
//!                    security_lock_finish_boot_shred() does it instead.
static uint32_t prv_shred(SecurityShredReason reason, bool dbs_running, bool finish) {
  // Nothing written back since the last wipe means nothing new to destroy, so
  // the filesystem half is skipped. The raw-flash regions below are not covered
  // by the flag -- a crash writes a coredump whether or not the phone synced --
  // so those are erased either way.
  const bool clean = prv_storage_is_clean();

  PBL_LOG_INFO("Shredding: %s%s", security_lock_shred_reason_str(reason),
               clean ? " (nothing written since the last wipe)" : "");

  // Refuse fresh content for the duration. security_lock_is_locked() does not
  // cover this: the duress PIN and the clock-rollback trigger both wipe while
  // the watch is unlocked. Set before anything else so nothing slips in during
  // the teardown below.
  s_shredding = true;

  if (!clean) {
    // Set before anything is destroyed so a shred interrupted by power loss is
    // resumed at next boot rather than left half done, and before the flag
    // below is cleared because the two are separate flash writes: the gap
    // between them has to read "a wipe was in progress", never "there is
    // nothing to destroy". The clean path leaves it alone -- it is only reached
    // when the flag is already clear, and it destroys nothing needing resuming.
    security_lock_set_shred_pending(true);

    // Cleared the moment the decision above is taken, not at the end.
    // Everything from here on -- including the quiesce, which yields -- can
    // re-mark, so a write racing the wipe leaves the flag dirty and the next
    // wipe runs in full. The write guards make that nearly unreachable, but
    // this is the direction the flag must fail in.
    security_lock_clear_dirty_since_shred();
  }

  if (dbs_running) {
    // Not merely where every trigger already happens to run -- the teardown
    // below drives the app and modal stacks, which only this task may touch.
    PBL_ASSERT_TASK(PebbleTask_KernelMain);

    // Close anything that is showing, holding or about to re-read what is
    // being destroyed, before a single byte goes. Consumers do not survive the
    // wipe gracefully: the notification window re-reads its backing record on
    // every reload and dereferences the NULL layout it gets back when that
    // read fails, which is a wild jump on KernelMain, not a blank screen.
    //
    // Synchronous and inline on purpose. security_lock_engage() used to do
    // this for itself, which is exactly why the lock trigger was safe and the
    // bare shred triggers were not; doing it here means no caller can forget.
    //
    // Run even when there is nothing to destroy: the lock triggers rely on it
    // to take a notification off the screen, and that is true whether or not
    // the file behind it has already been zeroed.
    security_lock_ui_quiesce();
  }

  // Erasing takes seconds and there is no way to yield through it, so the
  // watchdog has to stop supervising this task or it resets us mid-wipe --
  // which, since a reboot while locked shreds again, is a boot loop rather
  // than a one-off. factory_reset_fast() does the same for the same reason.
  const PebbleTask task = pebble_task_get_current();
  task_watchdog_mask_clear(task);

  // Announce before wiping, so anything holding data of its own gets the
  // chance to destroy it rather than being told afterwards. Not emitted at
  // early boot: nothing is subscribed yet and the event system is not up.
  //
  // For apps, which run on their own task -- this is destined for the SDK so a
  // watchapp can erase its own persist storage. It is NOT a general "everyone
  // cleans up first" hook: event_put() is asynchronous and the launcher task
  // drains the queue, which is the task this function is holding, so a
  // KernelMain-resident subscriber could not be reached until the wipe was
  // over. Anything of ours goes in security_lock_ui_quiesce() above instead.
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
  if (!clean && dbs_running) {
    timeline_event_deinit();
    reminder_db_deinit();
    pin_db_deinit();
  }

  size_t num_targets;
  const SecurityShredTarget *targets = security_lock_shred_targets(&num_targets);

  uint32_t wiped = 0;
  for (size_t i = 0; !clean && (i < num_targets); ++i) {
    status_t rv = pfs_shred(targets[i].filename);
    if (rv == S_SUCCESS) {
      wiped |= SECURITY_SHRED_DB_BIT(targets[i].db_id);
    } else {
      PBL_LOG_ERR("Failed to shred %s: %" PRId32, targets[i].filename, (int32_t)rv);
    }
    task_watchdog_bit_set(pebble_task_get_current());
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
  PBL_LOG_INFO("SECSTAGE debug log erased");
#endif
  // The raw-flash erases above. Every layout defines at least the debug-log
  // region, so this reports the same as it always has.
  wiped |= SECURITY_SHRED_NON_BLOBDB_BIT;

  // Zeroing each file kills the live copy, but earlier garbage collection,
  // settings_file compaction and OP_FLAG_OVERWRITE writes scatter superseded
  // copies with no record of where. This is the only thing that reaches those.
  //
  // It is also the slow half, and the least urgent: the live data is already
  // gone by this point, so this is cleanup. It runs in scheduled slices, and
  // at early boot it is left to security_lock_finish_boot_shred() entirely.
  const bool sweeping = (!clean && finish);
  if (sweeping) {
    prv_start_sweep();
  }
  PBL_LOG_INFO("SECSTAGE sweep started=%d", (int)sweeping);

  if (!clean && dbs_running) {
    // Bring the databases back up against the now-empty files.
    pin_db_init();
    PBL_LOG_INFO("SECSTAGE pin_db_init done");
    reminder_db_init();
    PBL_LOG_INFO("SECSTAGE reminder_db_init done");
    timeline_event_init();
    PBL_LOG_INFO("SECSTAGE timeline_event_init done");
    notification_storage_reset_and_init();
    PBL_LOG_INFO("SECSTAGE notification_storage done");
  }

#if !defined(CONFIG_RECOVERY_FW)
  // A duress wipe must not ask the phone to resend: the phone would cheerfully
  // restore everything within seconds and the duress PIN would accomplish
  // nothing. It stays gone until the user deliberately resyncs.
  const bool notify_phone = (reason != SecurityShredReasonDuressPin);

  // Tell the phone its copy is authoritative. Gadgetbridge does not currently
  // read this flag (an explicit SHRED_COMPLETE message covers that), but the
  // official app does, and it costs nothing to be correct for both.
  //
  // Not on the clean path: nothing of the phone's was destroyed, and asking for
  // a resend there would only produce the writes that make the next wipe real.
  if (!clean && finish && notify_phone) {
    bt_persistent_storage_set_unfaithful(true);
  }
#endif

  if (!clean && finish) {
    security_lock_set_shred_pending(false);
  }

  task_watchdog_mask_set(task);

  // The files are gone and the databases are back up, so new content is safe
  // to accept again. Deliberately not held for the sector sweep: that runs in
  // scheduled slices for minutes and only touches already-deleted sectors, and
  // dropping notifications for that long would be a far worse bug.
  s_shredding = false;

  PBL_LOG_INFO("Shred complete, wiped bitmap 0x%" PRIx32, wiped);

#if !defined(CONFIG_RECOVERY_FW)
  // Writes refused while the watch was locked, or while this was running, were
  // acked to the phone as successes, so it has them recorded as delivered. They
  // ride along with what was destroyed rather than waiting for an unlock that
  // may be hours away. Drained unconditionally: a duress wipe must swallow them
  // rather than leave them for the next unlock to ask on its behalf.
  const uint32_t refused = security_lock_take_refused_dbs();

  // Reported from here rather than from each caller so no trigger can forget:
  // this is what tells the phone to resend what it holds. Queued when there is
  // no session -- the common case, since the phone going away is what causes
  // most wipes -- and sent on the next one.
  if (dbs_running && (reason != SecurityShredReasonDuressPin)) {
    security_lock_endpoint_report_resync_needed(reason, wiped | refused);
  }
#endif
  return wiped;
}

uint32_t security_lock_shred(SecurityShredReason reason) {
  // The master switch, enforced here rather than at each trigger so a future
  // one is covered by construction. security_lock_engage() holds the other
  // funnel; between them nothing locks and nothing erases while the feature is
  // off. security_lock_handle_boot() deliberately does not come through here.
  if (!security_lock_is_enabled()) {
    PBL_LOG_WRN("Security lock is off; not shredding (%s)",
                security_lock_shred_reason_str(reason));
    return 0;
  }

  // A wipe arriving while one is running has no correct behaviour other than
  // "don't": the teardown closes and reopens databases whose re-init is
  // asynchronous, so a second run walks into half-built state.
  //
  // Scoped to the synchronous body, not to the sector sweep that outlives it.
  // The sweep runs for minutes over already-deleted sectors under the recursive
  // filesystem mutex, so an overlapping wipe only ever waits out one pass --
  // whereas refusing wipes for minutes would swallow a real duress or
  // attempts-exhausted trigger, and this must only ever err towards shredding.
  // The redundancy the sweep window used to cost is handled instead by the
  // dirty flag, which stays clear across a sweep because a sweep writes nothing.
  if (s_shredding) {
    PBL_LOG_WRN("Shred already running; ignoring %s", security_lock_shred_reason_str(reason));
    return 0;
  }
  const uint32_t wiped = prv_shred(reason, true /* dbs_running */, true /* finish */);

  // Keyed on the locked state rather than on the wipe, so no trigger needs a
  // special case here. The duress PIN unlocks first and wipes in the
  // background, so it arrives unlocked -- which is what has to happen, because
  // an airplane-mode icon appearing right after an unlock is exactly the tell
  // it exists to avoid, and because a watch that is already unlocked would
  // never reach the release. The clock-rollback wipe follows the same rule:
  // dark only if the lock delay had already elapsed.
  if (security_lock_is_locked()) {
    security_lock_radio_blackout_engage();
  }
  return wiped;
}

//! Set when a wipe ran at early boot, so the half that needs a running system
//! can follow. RAM only: the persisted shred_pending flag is what survives a
//! power cut, and it stays set until the tail has run.
static bool s_boot_shred_tail_owed;
//! What that wipe destroyed and why, carried to the tail because telling the
//! phone is one of the things that cannot be done this early.
static uint32_t s_boot_shred_wiped;
static SecurityShredReason s_boot_shred_reason;

void security_lock_handle_boot(void) {
  PBL_LOG_INFO("SECBOOT handle_boot enter");

#if defined(CONFIG_SERVICE_SECURITY_LOCK_TEST_HOOKS)
  // Test/debug affordance. A watch that wipes on every boot cannot be
  // instrumented, because each run starts from a different filesystem and the
  // wipe is the thing under suspicion. `boot bit set` is itself ungated, so the
  // check has to be compiled out with the rest of the hooks: without the hooks
  // nothing can talk the watch out of the wipe.
  if (boot_bit_test(BOOT_BIT_SECURITY_SKIP_BOOT_WIPE)) {
    s_boot_shred_tail_owed = false;
    PBL_LOG_INFO("SECBOOT handle_boot leave owed=0 skipped=1");
    return;
  }
#endif

  const time_t now = rtc_get_time();

  // There is no reboot-persistent monotonic clock, so the high-water mark is
  // the only rollback signal there is. Noting it here is also what advances
  // it, so it has to happen on every boot and not only when a wipe is owed.
  const bool rolled_back = security_lock_note_time(now);

  // Rebooting is the one reliable way past the lock screen: SELECT+BACK held
  // for five seconds hard resets from the button ISR, below anything software
  // can intercept. So any reboot while a response was armed shreds. Restarting
  // must never be cheaper than waiting, and everything destroyed comes back
  // from the phone.
  const bool was_armed = security_lock_is_locked() || (security_lock_get_lock_deadline() != 0) ||
                         (security_lock_get_shred_deadline() != 0);

  SecurityShredReason reason;
  if (security_lock_is_shred_pending()) {
    // A previous shred did not finish. Whatever it was, redo it -- including
    // when the feature has since been turned off. The content is already
    // half destroyed, and a half-wiped filesystem passes for an untouched one:
    // finishing costs nothing that is not already gone, while stopping here
    // leaves recoverable fragments behind for good.
    reason = SecurityShredReasonUnknown;
  } else if (!security_lock_is_enabled()) {
    // The master switch. Below this point every branch is a trigger, and none
    // of them may fire while the feature is off. Note the high-water mark was
    // still advanced above: leaving it stale would make turning the feature
    // back on read an old, legitimate timestamp as a rollback.
    PBL_LOG_INFO("SECBOOT handle_boot leave owed=0 disabled=1");
    return;
  } else if (security_lock_shred_deadline_expired(now)) {
    // A countdown that lapsed while the watch was powered off, reported as
    // whatever armed it. The phone acts on the reason, and a lockdown the user
    // asked for is not a disconnect timeout.
    reason = (security_lock_get_countdown_source() == SecurityCountdownManual)
                 ? SecurityShredReasonManualPanic
                 : SecurityShredReasonDisconnectTimeout;
  } else if (rolled_back) {
    // Winding the clock back is how a deadline gets outrun.
    reason = SecurityShredReasonClockRollback;
  } else if (was_armed) {
    reason = SecurityShredReasonRebootWhileLocked;
  } else {
    PBL_LOG_INFO("SECBOOT handle_boot leave owed=0 skipped=0");
    return;
  }

  // A watch that was still counting down never reached the lock screen, and the
  // reboot has just destroyed its content anyway. Lock it, so a shred is not
  // followed by a watch that opens straight up.
  //
  // Not when the feature is off: the only way to get here with it off is
  // finishing an interrupted wipe, and locking would turn the feature back on
  // as a side effect of cleanup.
  if (security_lock_is_enabled() && !security_lock_is_locked() &&
      (security_lock_get_pin_len() != 0)) {
    security_lock_set_state(SecurityLockStateLocked);
  }

  // Zeroing the files happens here, inline, before the display or the radio
  // exist -- that is the whole point of hooking early boot, and it is the fast
  // part. The sector sweep only erases superseded copies, so it waits for
  // security_lock_finish_boot_shred() rather than holding up the boot.
  // Read before the wipe, which clears the flag it is derived from. A clean
  // wipe touches no filesystem file, so there are no superseded copies for the
  // sweep to find and no resend to ask the phone for.
  const bool tail_owed = !prv_storage_is_clean();
  s_boot_shred_wiped = prv_shred(reason, false /* dbs_running */, false /* finish */);
  s_boot_shred_reason = reason;
  s_boot_shred_tail_owed = tail_owed;

  PBL_LOG_INFO("SECBOOT handle_boot leave owed=%d skipped=0 locked=%d reason=%s", (int)tail_owed,
               (int)security_lock_is_locked(), security_lock_shred_reason_str(reason));
}

void security_lock_finish_boot_shred(void) {
  if (!s_boot_shred_tail_owed) {
    return;
  }
  s_boot_shred_tail_owed = false;

  PBL_LOG_INFO("Finishing the boot shred");

  // Slices scheduled on KernelBG, so nothing blocks here.
  prv_start_sweep();

#if !defined(CONFIG_RECOVERY_FW)
  // Bonding storage did not exist when the wipe ran. A boot shred is never a
  // duress shred, so the phone is always told to resend.
  bt_persistent_storage_set_unfaithful(true);

  // Neither did the radio, so the wipe could not say this for itself. Queued
  // here and sent on the first session, which is what keeps a reboot while
  // locked from being a silent loss -- Gadgetbridge never reads the flag above.
  security_lock_endpoint_report_resync_needed(s_boot_shred_reason, s_boot_shred_wiped);
#endif

  // The data is gone; what is left is cleanup, which does not need resuming on
  // a later boot.
  security_lock_set_shred_pending(false);
}
