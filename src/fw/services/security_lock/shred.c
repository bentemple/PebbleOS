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
#include "pbl/services/activity/activity.h"
#include "pbl/services/blob_db/health_db.h"
#include "pbl/services/blob_db/pin_db.h"
#include "pbl/services/data_logging/data_logging_service.h"
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
//!
//! @return true if the region existed and was erased
static bool prv_erase_flash_region(uint32_t begin, uint32_t end, const char *what) {
  if (begin >= end) {
    return false;
  }
  PBL_LOG_DBG("Erasing %s region", what);
  flash_region_erase_optimal_range_no_watchdog(begin, begin, end, end);
  task_watchdog_bit_set(pebble_task_get_current());
  return true;
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

//! Backoff before a fresh round when one runs out of budget. Long on purpose: a
//! round that spent a whole pass over the filesystem without draining it is
//! either grinding through a very full one or chasing the reserved block
//! around, and neither is helped by starting again immediately.
#define SWEEP_RETRY_GAP_MS 60000

//! Ceiling on a single round: one pass over the filesystem, sized from the
//! filesystem itself rather than guessed.
//!
//! Collecting a sector can relocate the reserved GC block, which leaves fresh
//! deleted pages behind, so "collected nothing this pass" is not a state a
//! round reaches immediately -- without a ceiling it reschedules itself at the
//! pass gap forever and starves the task it runs on.
//!
//! Hitting the ceiling ends the round, not the sweep.
static int s_sweep_budget;

//! Ceiling on the whole sweep, across every round, as a multiple of the
//! filesystem size.
//!
//! Draining the filesystem is the exit this wants, but on a running watch it is
//! not reliably reachable: the sweep's own GC block relocation leaves deleted
//! pages behind, and so does ordinary operation -- expiring notifications, pin
//! updates, every settings_file write. Rounds then chase their own tail, and
//! because shred_pending is cleared nowhere else it stays set, which makes
//! security_lock_handle_boot() redo the entire wipe on every subsequent boot.
//! The observed cost of that was continuous 64K sector erasing and a
//! notification store wiped at each boot.
//!
//! So the sweep is bounded by work done instead. Two filesystems' worth of
//! sector erases is far more than the stale copies of one wipe can occupy;
//! anything still being collected past that is churn generated after the wipe,
//! which is not what the wipe is responsible for destroying. Reaching the cap
//! records the wipe as finished, because the alternative -- never finishing --
//! leaves the flag set forever and re-wipes at every boot, which destroys the
//! same data again while protecting nothing extra.
#define SWEEP_TOTAL_BUDGET_MULTIPLE 2
//! Sectors left before the whole sweep gives up. Spans rounds, unlike
//! s_sweep_budget.
static int s_sweep_total_budget;
//! A round is in flight. Guards against a wipe arriving mid-sweep starting a
//! second chain against the one timer.
static bool s_sweep_running;
static TimerID s_sweep_timer = TIMER_INVALID_ID;

//! Budget a round gets, in sectors.
//!
//! A filesystem that cannot say how big it is would otherwise hand out a
//! budget of zero, which ends the round on its first pass and records the wipe
//! as finished over a filesystem nothing swept.
#define SWEEP_FALLBACK_BUDGET 32

static int prv_round_budget(void) {
  const int regions = pfs_get_erase_region_count();
  if (regions <= 0) {
    PBL_LOG_WRN("Filesystem reports no erase regions; sweeping on a nominal budget");
    return SWEEP_FALLBACK_BUDGET;
  }
  return regions;
}

static void prv_schedule_pass(uint32_t gap_ms);

//! End the sweep and record the wipe as complete.
//!
//! The only place shred_pending is cleared. Clearing it is what stops the next
//! boot redoing the whole wipe, so every exit that means the wipe is done has
//! to come through here -- an exit that just stops rescheduling would leave the
//! watch wiping itself at every boot for good.
static void prv_finish_sweep(const char *why) {
  s_sweep_running = false;
  PBL_LOG_INFO("Shred sweep finished (%s)", why);
  security_lock_set_shred_pending(false);
}

//! Stop the sweep without recording the wipe as complete.
//!
//! For the case the sweep cannot do anything about: shred_pending stays set, so
//! the payload this sweep could not reach is revisited by the next wipe instead
//! of being written off as destroyed while the phone is told the wipe finished.
static void prv_abandon_sweep(const char *why) {
  s_sweep_running = false;
  PBL_LOG_WRN("Shred sweep stopped without finishing (%s)", why);
}

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

  if (collected == PFS_GC_NO_PROGRESS) {
    // Stale payload the filesystem could not reach: no GC scratch block, a
    // collection that failed, or no mounted filesystem at all. Rescheduling
    // does not help -- none of those clear within a sweep -- but this is not a
    // drained filesystem either, so the wipe stays owed and a later one gets
    // another go at what is still on flash.
    prv_abandon_sweep("no progress");
    return;
  }

  s_sweep_budget -= collected;
  s_sweep_total_budget -= collected;
  // Logged every pass: this is the slow part of the wipe, and without it a
  // sweep that is merely grinding is indistinguishable from one that is stuck.
  PBL_LOG_DBG("Shred sweep pass: %d sector(s), %d of budget left", collected, s_sweep_budget);
  if (collected == 0) {
    // The filesystem is drained, so the stale copies really are gone. Files that
    // were removed rather than zeroed -- cleared notifications, above all -- are
    // reachable only from here, which is why the sweep exists at all.
    prv_finish_sweep("drained");
    return;
  }
  if (s_sweep_total_budget <= 0) {
    // See SWEEP_TOTAL_BUDGET_MULTIPLE. Loud, because a sweep that needed this
    // much work either met a pathologically full filesystem or is chasing pages
    // being created behind it, and both are worth knowing about.
    PBL_LOG_WRN("Shred sweep hit its overall ceiling; recording the wipe as done");
    prv_finish_sweep("ceiling");
    return;
  }
  if (s_sweep_budget <= 0) {
    // A whole pass over the filesystem was not enough. Take a fresh budget
    // rather than stopping: stopping leaves stale copies on flash while the
    // watch tells the phone the wipe is done, and the cleared flag stops any
    // later wipe revisiting them.
    PBL_LOG_WRN("Shred sweep round hit its ceiling; starting another");
    s_sweep_budget = prv_round_budget();
    prv_schedule_pass(SWEEP_RETRY_GAP_MS);
    return;
  }
  prv_schedule_pass(SWEEP_PASS_GAP_MS);
}

static void prv_sweep_timer_cb(void *unused) {
  system_task_add_callback(prv_sweep_pass, NULL);
}

static void prv_schedule_pass(uint32_t gap_ms) {
  if (s_sweep_timer == TIMER_INVALID_ID) {
    s_sweep_timer = new_timer_create();
  }
  if (s_sweep_timer == TIMER_INVALID_ID) {
    // No timer to be had; fall back to running straight on, which is worse for
    // responsiveness but still finishes.
    system_task_add_callback(prv_sweep_pass, NULL);
    return;
  }
  new_timer_start(s_sweep_timer, gap_ms, prv_sweep_timer_cb, NULL, 0 /* flags */);
}

static void prv_start_sweep(void) {
  // Fresh budget on every call: a wipe landing while a sweep is in flight has
  // just created more deleted pages for it to reach.
  const int round_budget = prv_round_budget();
  s_sweep_budget = round_budget;
  // Refilled here too, for the same reason -- a fresh wipe is entitled to a
  // fresh allowance -- but only ever from a wipe, never from a round rolling
  // over. That is what keeps the overall ceiling a ceiling.
  s_sweep_total_budget = round_budget * SWEEP_TOTAL_BUDGET_MULTIPLE;
  if (s_sweep_running) {
    // The chain already running picks the new budget up on its next pass.
    return;
  }
  s_sweep_running = true;
  prv_schedule_pass(SWEEP_PASS_GAP_MS);
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
  // everything that destroys is skipped, the raw-flash region erases included:
  // repeated triggers with nothing to wipe would otherwise cost thousands of
  // 64K sector erases apiece.
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
    // Synchronous and inline on purpose, and done here rather than by each
    // trigger so no caller can forget it.
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

  // Announce the wipe, so anything holding data of its own gets a chance to
  // destroy it too. Not emitted at early boot: nothing is subscribed yet and
  // the event system is not up.
  //
  // For apps, which run on their own task -- this is destined for the SDK so a
  // watchapp can erase its own persist storage. It is NOT a general "everyone
  // cleans up first" hook, and it is not even ordered before the wipe in
  // practice: event_put() only queues, and this runs on KernelMain, which is
  // the task that drains the queue, so no subscriber is reached until this
  // function has returned and the wipe is already done. Anything of ours goes
  // in security_lock_ui_quiesce() above instead.
  //
  // Sent for a duress wipe too. A subscriber that also watches
  // PEBBLE_SECURITY_LOCK_EVENT sees unlock-then-shred, which no other trigger
  // produces, so this is one more of the residual tells the duress PIN cannot
  // close (see docs/architecture/security_lock.md). Withholding it would cost
  // an app the chance to erase its own storage on the wipe that most needs it.
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
  if (!clean) {
    for (size_t i = 0; i < num_targets; ++i) {
      status_t rv = pfs_shred(targets[i].filename);
      if (rv == S_SUCCESS) {
        wiped |= SECURITY_SHRED_DB_BIT(targets[i].db_id);
      } else {
        PBL_LOG_ERR("Failed to shred %s: %" PRId32, targets[i].filename, (int32_t)rv);
      }
      task_watchdog_bit_set(pebble_task_get_current());
    }

    // Health data, only if the wearer asked for it.
    //
    // Not an entry in the list above because each module has to destroy its own
    // rather than have two more filenames walked here: the activity service
    // holds a day's worth of counters in RAM that the next minute handler would
    // write straight back to a fresh file.
    //
    // It does claim its resync bit, though. The phone is the system of record
    // for health -- the watch datalogs raw samples up, the phone aggregates
    // them and pushes the result back down through this very BlobDB -- so
    // asking it to resend is a request it can largely satisfy. What it resends
    // is the last six completed days plus the typicals, not today and not the
    // weeks beyond that, which is why this is still opt-in and still warns.
    if (security_lock_get_shred_health()) {
      health_db_shred();
      activity_shred();
      wiped |= SECURITY_SHRED_DB_BIT(BlobDBIdHealth);
      task_watchdog_bit_set(pebble_task_get_current());
    }

    // The outbound queue, unconditionally.
    //
    // This one was spared on the grounds that it holds, by definition, the only
    // thing the phone does not have -- so destroying it breaks the invariant
    // that everything the wipe destroys comes back. That reasoning inverts the
    // priority: after a wipe there must be nothing left to recover, and a queue
    // of notification text, health samples and whatever apps chose to log is
    // exactly something to recover. The coredump and debug-log regions below
    // are already erased on the same grounds, and the phone does not have those
    // either.
    //
    // Not gated on Erase Health Data. That switch is about the stored history;
    // the queue is not a health store -- any app can write to it through the
    // SDK -- so keying it on a health setting would be the wrong question.
    dls_shred();
    task_watchdog_bit_set(pebble_task_get_current());
  }

  // A coredump is a snapshot of RAM and can contain notification text or
  // contact details that were resident at the moment of the crash. It lives
  // outside PFS, so a filesystem wipe misses it entirely.
  //
  // Skipped on the clean path with the rest. These regions are not covered by
  // the dirty flag, so this does leave a coredump written since the last wipe
  // in place until the next wipe that has something else to do -- the price of
  // not spending thousands of 64K sector erases on repeated triggers that have
  // nothing to destroy.
  bool raw_erased = false;
  if (!clean) {
#ifdef FLASH_REGION_CD_BEGIN
    raw_erased |= prv_erase_flash_region(FLASH_REGION_CD_BEGIN, FLASH_REGION_CD_END, "coredump");
#else
    // Spelled out rather than left to an #ifdef that silently does nothing: a
    // layout without the region keeps its coredumps through a wipe.
#warning "No coredump flash region: a shred cannot erase coredumps on this board"
#endif
#ifdef FLASH_REGION_DEBUG_DB_BEGIN
    // flash_logging caches an address inside this region, so erasing it without
    // telling the logger leaves that pointing at erased flash. Everything logs,
    // so a confused logger takes the task with it.
    flash_logging_set_enabled(false);
    raw_erased |=
        prv_erase_flash_region(FLASH_REGION_DEBUG_DB_BEGIN, FLASH_REGION_DEBUG_DB_END, "debug log");
    flash_logging_init();
    flash_logging_set_enabled(true);
#endif
  }
  // Only when a region really went. Reporting it unconditionally makes the
  // bitmap non-zero on a run that destroyed nothing, and a non-zero bitmap is
  // what asks the phone for a full re-push it does not need.
  if (raw_erased) {
    wiped |= SECURITY_SHRED_NON_BLOBDB_BIT;
  }

  // Zeroing each file kills the live copy, but earlier garbage collection,
  // settings_file compaction and OP_FLAG_OVERWRITE writes scatter superseded
  // copies with no record of where. This is the only thing that reaches those.
  //
  // It is also the slow half, and the least urgent: the live data is already
  // gone by this point, so this is cleanup. It runs in scheduled slices, and
  // at early boot it is left to security_lock_finish_boot_shred() entirely.
  if (!clean && finish) {
    prv_start_sweep();
  }

  if (!clean && dbs_running) {
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
  //
  // Not on the clean path: nothing of the phone's was destroyed, and asking for
  // a resend there would only produce the writes that make the next wipe real.
  if (!clean && finish && notify_phone) {
    bt_persistent_storage_set_unfaithful(true);
  }
#endif

  // shred_pending is deliberately still set here. It is cleared by the sweep,
  // and only once the sweep has drained the filesystem: everything above
  // destroys live copies, but a file that was removed rather than zeroed leaves
  // its payload in deleted pages that only the sweep reaches. Clearing it here
  // would call the wipe done while that payload was still readable, and would
  // also stop any later wipe from retrying -- prv_storage_is_clean() would say
  // there was nothing left to do.

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
#if defined(CONFIG_SERVICE_SECURITY_LOCK_TEST_HOOKS)
  // Test/debug affordance. A watch that wipes on every boot cannot be
  // instrumented, because each run starts from a different filesystem and the
  // wipe is the thing under suspicion. `boot bit set` is itself ungated, so the
  // check has to be compiled out with the rest of the hooks: without the hooks
  // nothing can talk the watch out of the wipe.
  if (boot_bit_test(BOOT_BIT_SECURITY_SKIP_BOOT_WIPE)) {
    s_boot_shred_tail_owed = false;
    PBL_LOG_DBG("Boot wipe skipped by boot bit");
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
    PBL_LOG_DBG("Security lock is off; nothing owed at boot");
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
    PBL_LOG_DBG("Nothing armed at boot; nothing owed");
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

  PBL_LOG_DBG("Boot wipe done, tail owed=%d, locked=%d", (int)tail_owed,
              (int)security_lock_is_locked());
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

  // shred_pending stays set until the sweep above reports the filesystem
  // drained. A reboot before that happens finds the flag and shreds again,
  // which is what makes an interrupted sweep resume rather than be forgotten.
}
