/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

//! Tests for what a shred does and, more importantly, what it declines to do.
//!
//! Everything the shred touches is faked, because the point here is the shape
//! of the sequence -- which teardowns run, how many files are zeroed, whether
//! the sector sweep is started -- rather than the behaviour of any one of them.

#include "clar.h"

#include <string.h>

#include "pbl/services/filesystem/pfs.h"
#include "pbl/services/security_lock.h"
#include "pbl/services/security_lock_shred.h"
#include "pbl/util/size.h"

// Stubs
////////////////////////////////////
#include "stubs_bootbits.h"
#include "stubs_logging.h"
#include "stubs_passert.h"
#include "stubs_pebble_tasks.h"
#include "stubs_print.h"
#include "stubs_serial.h"
#include "stubs_task_watchdog.h"

// Fakes
////////////////////////////////////

//! Every observable effect of a shred, so a test can state the whole shape of
//! a run rather than probing one call at a time.
typedef struct {
  int quiesces;
  int events;
  int shred_completes;
  int timeline_deinits;
  int timeline_inits;
  int reminder_deinits;
  int reminder_inits;
  int pin_deinits;
  int pin_inits;
  int notif_resets;
  int files_shredded;
  int region_erases;
  int sweeps_started;
  int unfaithful_marks;
  int blackouts;
  uint32_t last_complete_bitmap;
  SecurityShredReason last_complete_reason;
} ShredTrace;

static ShredTrace s_trace;

//! Standing in for the settings-backed service, so the shred's decisions can be
//! driven directly. The real record store is covered by test_security_lock.
static bool s_shred_pending;
static bool s_dirty;
static bool s_locked;
static uint8_t s_pin_len;
static SecurityLockState s_state;

//! Run inside security_lock_ui_quiesce(), which is called from within the shred
//! with the in-flight flag already set. That is the only place a re-entrant
//! trigger can be injected from.
static void (*s_during_quiesce)(void);

bool security_lock_is_shred_pending(void) {
  return s_shred_pending;
}

status_t security_lock_set_shred_pending(bool pending) {
  s_shred_pending = pending;
  return S_SUCCESS;
}

bool security_lock_is_dirty_since_shred(void) {
  return s_dirty;
}

void security_lock_mark_dirty_since_shred(void) {
  s_dirty = true;
}

//! Whether the resume marker was already armed at the moment the dirty flag was
//! cleared. The two are separate flash writes, so the order between them is the
//! whole of what a power cut in the gap sees.
static bool s_pending_when_cleared;

status_t security_lock_clear_dirty_since_shred(void) {
  s_pending_when_cleared = s_shred_pending;
  s_dirty = false;
  return S_SUCCESS;
}

bool security_lock_is_locked(void) {
  return s_locked;
}

SecurityLockState security_lock_get_state(void) {
  return s_state;
}

status_t security_lock_set_state(SecurityLockState state) {
  s_state = state;
  s_locked = (state == SecurityLockStateLocked);
  return S_SUCCESS;
}

uint8_t security_lock_get_pin_len(void) {
  return s_pin_len;
}

void security_lock_radio_blackout_engage(void) {
  s_trace.blackouts++;
}

time_t security_lock_get_lock_deadline(void) {
  return 0;
}

//! The shred countdown, as the record store would report it after a reboot:
//! whether one was armed, whether it lapsed while the watch was off, and what
//! armed it. The phone acts on the reason, so the last of those decides what it
//! is told.
static time_t s_shred_deadline;
static bool s_shred_deadline_expired;
static SecurityCountdownSource s_countdown_source;

time_t security_lock_get_shred_deadline(void) {
  return s_shred_deadline;
}

bool security_lock_shred_deadline_expired(time_t now) {
  return s_shred_deadline_expired;
}

SecurityCountdownSource security_lock_get_countdown_source(void) {
  return s_countdown_source;
}

//! Whether the clock looks wound back. Driven directly: it is one of the boot
//! triggers the master switch has to gate.
static bool s_rolled_back;

bool security_lock_note_time(time_t now) {
  return s_rolled_back;
}

time_t rtc_get_time(void) {
  return 1000;
}

void security_lock_ui_quiesce(void) {
  s_trace.quiesces++;
  if (s_during_quiesce) {
    void (*cb)(void) = s_during_quiesce;
    s_during_quiesce = NULL;
    cb();
  }
}

void security_lock_endpoint_report_resync_needed(SecurityShredReason reason, uint32_t dbs) {
  s_trace.shred_completes++;
  s_trace.last_complete_reason = reason;
  s_trace.last_complete_bitmap = dbs;
}

//! Databases whose inbound writes were refused while the watch was shut. Owned
//! by the lock service; a wipe only drains it.
static uint32_t s_refused_dbs;

uint32_t security_lock_take_refused_dbs(void) {
  const uint32_t dbs = s_refused_dbs;
  s_refused_dbs = 0;
  return dbs;
}

void timeline_event_init(void) {
  s_trace.timeline_inits++;
}

void timeline_event_deinit(void) {
  s_trace.timeline_deinits++;
}

void reminder_db_init(void) {
  s_trace.reminder_inits++;
}

void reminder_db_deinit(void) {
  s_trace.reminder_deinits++;
}

void pin_db_init(void) {
  s_trace.pin_inits++;
}

void pin_db_deinit(void) {
  s_trace.pin_deinits++;
}

void notification_storage_reset_and_init(void) {
  s_trace.notif_resets++;
}

//! Index into the target list whose shred fails, or -1 for none. A file that
//! cannot be zeroed is the case the wipe has to report honestly.
static int s_pfs_shred_fail_on = -1;

status_t pfs_shred(const char *name) {
  const int index = s_trace.files_shredded++;
  return (index == s_pfs_shred_fail_on) ? E_INTERNAL : S_SUCCESS;
}

//! Erase regions the fake filesystem claims, and so the budget one sweep round
//! gets. Small enough that a test can spend it.
#define FAKE_ERASE_REGIONS 64
//! Sectors a pass collects when the tests want one that is still finding work.
#define FAKE_COLLECTED_PER_PASS 4

//! What the next pass reports collecting. Zero means the filesystem is drained,
//! which is the only thing that finishes a wipe; PFS_GC_NO_PROGRESS means there
//! is stale payload the filesystem could not reach, which is not the same thing
//! at all.
static int s_gc_collected;

//! Erase regions the filesystem admits to. Driven, because a filesystem that
//! reports none must not silently cancel the sweep.
static int s_erase_regions;

int pfs_gc_deleted_sectors(int max_sectors) {
  return s_gc_collected;
}

int pfs_get_erase_region_count(void) {
  return s_erase_regions;
}

void flash_region_erase_optimal_range_no_watchdog(uint32_t min_start, uint32_t max_start,
                                                  uint32_t min_end, uint32_t max_end) {
  s_trace.region_erases++;
}

void flash_logging_init(void) {}

void flash_logging_set_enabled(bool enabled) {}

void bt_persistent_storage_set_unfaithful(bool unfaithful) {
  s_trace.unfaithful_marks++;
}

typedef void (*SystemTaskEventCallback)(void *data);
//! Run inline. A pass hops timer -> system task -> pass, and the tests have to
//! be able to get the pass to actually run.
bool system_task_add_callback(SystemTaskEventCallback cb, void *data) {
  cb(data);
  return true;
}

typedef uint32_t TimerID;
typedef void (*NewTimerCallback)(void *data);
TimerID new_timer_create(void) {
  return 1;
}

//! The pass the sweep has scheduled and not yet run.
static NewTimerCallback s_sweep_cb;
static void *s_sweep_cb_data;

bool new_timer_start(TimerID timer, uint32_t timeout_ms, NewTimerCallback cb, void *cb_data,
                     uint32_t flags) {
  // The sweep is the only thing this module schedules on a timer. Held rather
  // than run, so a sweep cannot finish inside security_lock_shred() and hide
  // the fact that it is the slow half; prv_run_sweep_pass() runs it by hand.
  s_trace.sweeps_started++;
  s_sweep_cb = cb;
  s_sweep_cb_data = cb_data;
  return true;
}

//! Run the pass the sweep is waiting on.
static void prv_run_sweep_pass(void) {
  cl_assert(s_sweep_cb != NULL);
  NewTimerCallback cb = s_sweep_cb;
  void *data = s_sweep_cb_data;
  s_sweep_cb = NULL;
  cb(data);
}

//! Let the sweep reach a drained filesystem. A wipe is only recorded as
//! finished here, so a test asserting a completed wipe has to come through it.
static void prv_drain_sweep(void) {
  s_gc_collected = 0;
  while (s_sweep_cb != NULL) {
    prv_run_sweep_pass();
  }
}

void event_put(void *event) {
  s_trace.events++;
}

// Helpers
////////////////////////////////////

//! Number of files security_lock_shred() zeroes on a full run. Spelled out
//! rather than derived, so shrinking the list has to be a deliberate edit here
//! too.
#define SHRED_TARGET_COUNT 7

void test_security_lock_shred__initialize(void) {
  // A sweep the previous test left in flight is still marked running inside the
  // module, which would stop this test's sweep from ever starting. Drained
  // before the trace is cleared, so the passes it costs are not counted here.
  prv_drain_sweep();

  memset(&s_trace, 0, sizeof(s_trace));
  s_gc_collected = 0;
  s_erase_regions = FAKE_ERASE_REGIONS;
  s_pfs_shred_fail_on = -1;
  s_shred_deadline = 0;
  s_shred_deadline_expired = false;
  s_countdown_source = SecurityCountdownNone;
  s_sweep_cb = NULL;
  s_during_quiesce = NULL;
  s_refused_dbs = 0;
  s_shred_pending = false;
  s_pending_when_cleared = false;
  s_dirty = true;
  s_locked = false;
  s_pin_len = 4;
  s_state = SecurityLockStateArmed;
  s_rolled_back = false;
}

void test_security_lock_shred__cleanup(void) {}

// A wipe with something to destroy
////////////////////////////////////

void test_security_lock_shred__dirty_storage_runs_the_whole_wipe(void) {
  const uint32_t wiped = security_lock_shred(SecurityShredReasonManualPanic);

  cl_assert_equal_i(SHRED_TARGET_COUNT, s_trace.files_shredded);
  cl_assert_equal_i(1, s_trace.timeline_deinits);
  cl_assert_equal_i(1, s_trace.reminder_deinits);
  cl_assert_equal_i(1, s_trace.pin_deinits);
  cl_assert_equal_i(1, s_trace.timeline_inits);
  cl_assert_equal_i(1, s_trace.reminder_inits);
  cl_assert_equal_i(1, s_trace.pin_inits);
  cl_assert_equal_i(1, s_trace.notif_resets);
  cl_assert_equal_i(1, s_trace.sweeps_started);
  cl_assert_equal_i(1, s_trace.unfaithful_marks);
  cl_assert(s_trace.region_erases > 0);

  // The databases it names, plus the raw-flash regions.
  cl_assert(wiped & SECURITY_SHRED_NON_BLOBDB_BIT);
  cl_assert(wiped & ~SECURITY_SHRED_NON_BLOBDB_BIT);

  // Still owed: the files are zeroed, but a file that was removed rather than
  // zeroed leaves payload in deleted pages only the sweep reaches.
  cl_assert(security_lock_is_shred_pending());

  // Nothing left half done, and the wipe consumed the reason it ran.
  prv_drain_sweep();
  cl_assert(!security_lock_is_shred_pending());
  cl_assert(!security_lock_is_dirty_since_shred());
}

//! The flag is cleared before anything is destroyed, so a write that lands
//! while the wipe is running is not swallowed by it -- the next wipe has to
//! know that write happened.
void test_security_lock_shred__a_write_during_the_wipe_leaves_it_dirty(void) {
  s_during_quiesce = security_lock_mark_dirty_since_shred;
  security_lock_shred(SecurityShredReasonManualPanic);
  cl_assert(security_lock_is_dirty_since_shred());
}

//! Clearing the flag and arming the resume marker are two separate flash
//! writes, so power can be lost between them. The marker goes first, or the gap
//! reads "nothing to destroy" over a filesystem nothing has touched yet -- and
//! that answer is persisted, so the next wipe would skip it for good. Armed
//! first, the worst a cut in the gap costs is one redundant wipe.
void test_security_lock_shred__the_resume_marker_is_armed_before_the_flag_is_cleared(void) {
  security_lock_shred(SecurityShredReasonManualPanic);
  cl_assert(s_pending_when_cleared);
}

// A wipe with nothing to destroy
////////////////////////////////////

//! The property the flag exists for, stated end to end at what a watch actually
//! shows: two wipes back to back with nothing written in between, and the
//! second destroys nothing.
//!
//! Kept separate from the driven-flag tests below because those set s_dirty by
//! hand and so cannot notice a first wipe that leaves the watch dirty behind
//! it. This one only ever runs wipes.
void test_security_lock_shred__a_second_wipe_with_nothing_written_is_a_no_op(void) {
  const uint32_t first = security_lock_shred(SecurityShredReasonManualPanic);
  cl_assert_equal_i(SHRED_TARGET_COUNT, s_trace.files_shredded);
  // Every target database, plus the raw-flash regions.
  cl_assert(first & ~SECURITY_SHRED_NON_BLOBDB_BIT);

  // The first wipe has to actually finish, or the second one is only a no-op
  // because the first is still owed.
  prv_drain_sweep();

  memset(&s_trace, 0, sizeof(s_trace));
  const uint32_t second = security_lock_shred(SecurityShredReasonManualPanic);

  // Nothing at all, which is all it destroyed.
  cl_assert_equal_i(0, second);
  cl_assert_equal_i(0, s_trace.files_shredded);
  cl_assert_equal_i(0, s_trace.region_erases);
  cl_assert_equal_i(0, s_trace.timeline_deinits);
  cl_assert_equal_i(0, s_trace.reminder_deinits);
  cl_assert_equal_i(0, s_trace.pin_deinits);
  cl_assert_equal_i(0, s_trace.timeline_inits);
  cl_assert_equal_i(0, s_trace.reminder_inits);
  cl_assert_equal_i(0, s_trace.pin_inits);
  cl_assert_equal_i(0, s_trace.notif_resets);
  cl_assert_equal_i(0, s_trace.sweeps_started);
}

//! One write in between is enough to make the second real again, so the test
//! above measures "nothing was written" rather than "a second wipe never runs".
void test_security_lock_shred__a_write_between_two_wipes_makes_the_second_real(void) {
  const uint32_t first = security_lock_shred(SecurityShredReasonManualPanic);
  prv_drain_sweep();

  memset(&s_trace, 0, sizeof(s_trace));
  security_lock_mark_dirty_since_shred();
  const uint32_t second = security_lock_shred(SecurityShredReasonManualPanic);

  cl_assert_equal_i(first, second);
  cl_assert_equal_i(SHRED_TARGET_COUNT, s_trace.files_shredded);
  cl_assert_equal_i(1, s_trace.pin_deinits);
  cl_assert_equal_i(1, s_trace.sweeps_started);
}

//! Almost everything a wipe erases came from the phone, so a wipe that arrives
//! before the phone has written anything back has nothing new to reach. The
//! filesystem half is where both the cost and the hang live, so that is what is
//! skipped.
void test_security_lock_shred__clean_storage_skips_the_filesystem(void) {
  s_dirty = false;

  security_lock_shred(SecurityShredReasonManualPanic);

  cl_assert_equal_i(0, s_trace.files_shredded);
  cl_assert_equal_i(0, s_trace.timeline_deinits);
  cl_assert_equal_i(0, s_trace.reminder_deinits);
  cl_assert_equal_i(0, s_trace.pin_deinits);
  cl_assert_equal_i(0, s_trace.timeline_inits);
  cl_assert_equal_i(0, s_trace.reminder_inits);
  cl_assert_equal_i(0, s_trace.pin_inits);
  cl_assert_equal_i(0, s_trace.notif_resets);
  cl_assert_equal_i(0, s_trace.sweeps_started);
  // Nothing of the phone's was destroyed, so there is nothing to ask it to
  // resend -- and asking would only produce the writes that make the next wipe
  // real.
  cl_assert_equal_i(0, s_trace.unfaithful_marks);
}

//! The raw-flash regions go with the rest. Erasing them on a run that destroys
//! nothing means every repeated trigger -- a locked watch being mashed at, most
//! of all -- costs thousands of 64K sector erases and stalls the task driving
//! them. A coredump written since the last wipe is caught by the next wipe that
//! has anything else to do.
void test_security_lock_shred__clean_storage_leaves_the_raw_flash_alone(void) {
  s_dirty = false;
  security_lock_shred(SecurityShredReasonManualPanic);
  cl_assert_equal_i(0, s_trace.region_erases);
}

//! The other half of the rule above: a wipe with something to destroy still
//! erases them, so the coredump is not simply never reached.
void test_security_lock_shred__dirty_storage_erases_the_raw_flash(void) {
  security_lock_shred(SecurityShredReasonManualPanic);
  cl_assert(s_trace.region_erases > 0);
}

//! An app's own persist storage is not tracked by the flag and only the app
//! knows what it holds, so it has to be told regardless.
void test_security_lock_shred__clean_storage_still_announces(void) {
  s_dirty = false;
  security_lock_shred(SecurityShredReasonManualPanic);
  cl_assert_equal_i(1, s_trace.events);
  cl_assert_equal_i(1, s_trace.shred_completes);
  // Honest about what it did: nothing. An empty bitmap is what stops the
  // endpoint asking the phone for a re-push it does not need.
  cl_assert_equal_i(0, s_trace.last_complete_bitmap);
}

//! The lock triggers rely on the shred to take a notification off the screen,
//! and that is needed whether or not the file behind it still has contents.
void test_security_lock_shred__clean_storage_still_quiesces_the_ui(void) {
  s_dirty = false;
  security_lock_shred(SecurityShredReasonManualPanic);
  cl_assert_equal_i(1, s_trace.quiesces);
}

//! An interrupted wipe has to finish or a half-wiped filesystem is mistaken for
//! a clean one, so the pending flag outranks the dirty flag in both directions.
void test_security_lock_shred__pending_outranks_a_clean_flag(void) {
  s_dirty = false;
  s_shred_pending = true;

  security_lock_shred(SecurityShredReasonUnknown);

  cl_assert_equal_i(SHRED_TARGET_COUNT, s_trace.files_shredded);
  cl_assert_equal_i(1, s_trace.sweeps_started);

  prv_drain_sweep();
  cl_assert(!security_lock_is_shred_pending());
}

// The sweep is what finishes a wipe
////////////////////////////////////
//
// Zeroing a file destroys the live copy, but "Clear Notifications" removes the
// notification file rather than rewriting it, and pfs_shred() on a file that is
// already gone zeroes nothing at all. That payload sits in deleted pages until
// the sweep erases the sector, so the sweep -- not the file half -- is what
// decides whether a wipe actually finished.

//! shred_pending outlives the synchronous half. Clearing it there reported a
//! complete wipe over notification text still readable on flash.
void test_security_lock_shred__the_wipe_is_not_finished_until_the_sweep_drains(void) {
  security_lock_shred(SecurityShredReasonManualPanic);

  cl_assert_equal_i(SHRED_TARGET_COUNT, s_trace.files_shredded);
  cl_assert_equal_i(1, s_trace.sweeps_started);
  cl_assert(security_lock_is_shred_pending());

  prv_drain_sweep();
  cl_assert(!security_lock_is_shred_pending());
}

//! A round that spends its budget starts another rather than giving up. Giving
//! up also cleared the flag, which made the leftovers unreachable for good: the
//! next wipe read prv_storage_is_clean() as true and skipped the sweep too.
void test_security_lock_shred__a_sweep_out_of_budget_starts_another_round(void) {
  security_lock_shred(SecurityShredReasonManualPanic);

  // A filesystem that never drains: every pass reports work, so the round's
  // budget runs out and a second round begins. One round's worth of passes,
  // which is inside the overall ceiling.
  s_gc_collected = FAKE_COLLECTED_PER_PASS;
  const int passes_per_round = FAKE_ERASE_REGIONS / FAKE_COLLECTED_PER_PASS;
  for (int i = 0; i < passes_per_round; ++i) {
    prv_run_sweep_pass();
  }

  // Still going, and still owed.
  cl_assert(s_sweep_cb != NULL);
  cl_assert(security_lock_is_shred_pending());

  // And it still finishes the moment the filesystem does drain.
  prv_drain_sweep();
  cl_assert(!security_lock_is_shred_pending());
}

//! A filesystem that never drains stops the sweep anyway, once it has done more
//! work than one wipe's leftovers could possibly amount to.
//!
//! Rounds used to roll over without limit. On a running watch the drain never
//! arrives -- the sweep's own GC block relocation leaves deleted pages behind,
//! and so does every expiring notification and settings_file write -- so the
//! sweep ground through 64K sector erases indefinitely. Worse, shred_pending is
//! cleared nowhere else, so it stayed set and security_lock_handle_boot() redid
//! the whole wipe on every subsequent boot, taking the notification store with
//! it each time.
void test_security_lock_shred__a_sweep_that_never_drains_gives_up(void) {
  security_lock_shred(SecurityShredReasonManualPanic);

  s_gc_collected = FAKE_COLLECTED_PER_PASS;
  // Enough passes to exhaust the overall ceiling several times over, had it not
  // stopped. The loop ends early because prv_run_sweep_pass() asserts there is
  // a callback to run.
  const int passes_per_round = FAKE_ERASE_REGIONS / FAKE_COLLECTED_PER_PASS;
  for (int i = 0; (i < (passes_per_round * 8)) && (s_sweep_cb != NULL); ++i) {
    prv_run_sweep_pass();
  }

  // Stopped rescheduling, and recorded the wipe as done so the next boot does
  // not redo it.
  cl_assert(s_sweep_cb == NULL);
  cl_assert(!security_lock_is_shred_pending());
}

//! A file that could not be zeroed is not a file that was wiped. The bitmap is
//! what the phone resends from, so claiming a database that is still on flash
//! would have the phone overwrite a store that was never destroyed -- and the
//! wipe has to stay owed so a later one gets another go at it.
void test_security_lock_shred__a_file_that_fails_to_shred_is_not_reported_wiped(void) {
  // The first target: notifications, whose file holds message bodies.
  s_pfs_shred_fail_on = 0;

  const uint32_t wiped = security_lock_shred(SecurityShredReasonManualPanic);

  // Every target was still attempted; one of them did not take.
  cl_assert_equal_i(SHRED_TARGET_COUNT, s_trace.files_shredded);
  cl_assert_equal_i(0, wiped & SECURITY_SHRED_DB_BIT(BlobDBIdNotifs));
  // The ones that did take are still reported, so a single failure does not
  // cost the phone a resend of everything else.
  cl_assert(wiped & SECURITY_SHRED_DB_BIT(BlobDBIdPins));
  cl_assert(wiped & SECURITY_SHRED_DB_BIT(BlobDBIdContacts));
  cl_assert(security_lock_is_shred_pending());
}

//! A sweep that cannot collect anything has not drained the filesystem, and
//! saying it has clears the flag that is the only thing keeping the payload
//! reachable: the next wipe reads prv_storage_is_clean() as true and skips it
//! for good, while the phone is told the wipe finished.
void test_security_lock_shred__a_sweep_that_cannot_collect_leaves_the_wipe_owed(void) {
  security_lock_shred(SecurityShredReasonManualPanic);

  s_gc_collected = PFS_GC_NO_PROGRESS;
  prv_run_sweep_pass();

  // Stopped, because rescheduling would not help -- but still owed.
  cl_assert(s_sweep_cb == NULL);
  cl_assert(security_lock_is_shred_pending());

  // And a later wipe does get another go at what was left behind.
  security_lock_mark_dirty_since_shred();
  security_lock_shred(SecurityShredReasonManualPanic);
  cl_assert_equal_i(2, s_trace.sweeps_started);

  prv_drain_sweep();
  cl_assert(!security_lock_is_shred_pending());
}

//! The round budget is sized from the filesystem, and a filesystem that reports
//! no erase regions would size it to zero -- ending the round on its first pass
//! and recording the wipe as done over a filesystem nothing swept.
void test_security_lock_shred__a_filesystem_that_reports_no_regions_still_sweeps(void) {
  s_erase_regions = 0;

  security_lock_shred(SecurityShredReasonManualPanic);

  s_gc_collected = FAKE_COLLECTED_PER_PASS;
  for (int i = 0; (i < 4) && (s_sweep_cb != NULL); ++i) {
    prv_run_sweep_pass();
  }

  cl_assert(s_sweep_cb != NULL);
  cl_assert(security_lock_is_shred_pending());
}

//! A power cut mid-sweep leaves the flag set on flash, which is what makes the
//! next boot redo the wipe instead of trusting a half-swept filesystem.
void test_security_lock_shred__a_sweep_interrupted_by_a_reboot_is_owed_again(void) {
  security_lock_shred(SecurityShredReasonManualPanic);
  cl_assert(security_lock_is_shred_pending());

  // The reboot: nothing drained the sweep, and the persisted flag is all that
  // survives. Everything else about the watch reads clean.
  s_dirty = false;
  memset(&s_trace, 0, sizeof(s_trace));

  security_lock_handle_boot();
  cl_assert_equal_i(SHRED_TARGET_COUNT, s_trace.files_shredded);
}

//! The sweep outlives the wipe, so a second wipe can land while one is running.
//! It has to feed the round already going rather than start a second chain
//! against the one timer.
void test_security_lock_shred__a_wipe_during_a_sweep_does_not_start_a_second(void) {
  security_lock_shred(SecurityShredReasonManualPanic);
  cl_assert_equal_i(1, s_trace.sweeps_started);

  security_lock_mark_dirty_since_shred();
  security_lock_shred(SecurityShredReasonDuressPin);

  // The second wipe ran in full, but did not start a sweep of its own.
  cl_assert_equal_i(2 * SHRED_TARGET_COUNT, s_trace.files_shredded);
  cl_assert_equal_i(1, s_trace.sweeps_started);
  cl_assert(security_lock_is_shred_pending());
}

// Re-entrancy
////////////////////////////////////

static void prv_shred_again(void) {
  cl_assert(security_lock_is_shredding());
  // Nothing was wiped, because nothing ran.
  cl_assert_equal_i(0, security_lock_shred(SecurityShredReasonDuressPin));
}

//! A wipe arriving while one is running has no correct behaviour other than
//! "don't": the teardown closes databases whose re-init is asynchronous, so a
//! second run walks into half-built state and blocks on it forever.
void test_security_lock_shred__a_wipe_during_a_wipe_is_refused(void) {
  s_during_quiesce = prv_shred_again;

  security_lock_shred(SecurityShredReasonManualPanic);

  // Exactly one wipe's worth of work, not two.
  cl_assert_equal_i(SHRED_TARGET_COUNT, s_trace.files_shredded);
  cl_assert_equal_i(1, s_trace.timeline_deinits);
  cl_assert_equal_i(1, s_trace.timeline_inits);
  cl_assert_equal_i(1, s_trace.quiesces);
  cl_assert_equal_i(1, s_trace.sweeps_started);
}

//! The guard covers the wipe, not the sector sweep that outlives it. The sweep
//! runs for minutes, and refusing wipes for that long would swallow a real
//! duress trigger.
void test_security_lock_shred__a_wipe_after_one_finishes_is_not_refused(void) {
  security_lock_shred(SecurityShredReasonManualPanic);
  cl_assert(!security_lock_is_shredding());

  security_lock_mark_dirty_since_shred();
  security_lock_shred(SecurityShredReasonDuressPin);

  cl_assert_equal_i(2 * SHRED_TARGET_COUNT, s_trace.files_shredded);
}

// Radio blackout
////////////////////////////////////

//! A locked watch that has just been wiped has nothing left to receive, and
//! every message it drops instead is an ack the phone reads as a successful
//! sync. Taking the radio down makes it an ordinary disconnect.
void test_security_lock_shred__a_wipe_while_locked_takes_the_radio_down(void) {
  s_locked = true;
  s_state = SecurityLockStateLocked;

  security_lock_shred(SecurityShredReasonPinAttemptsExhausted);

  cl_assert_equal_i(1, s_trace.blackouts);
}

//! The rule is keyed on the locked state, not on the wipe. The duress PIN
//! unlocks first and wipes in the background, so it arrives here unlocked --
//! and a visible airplane-mode icon straight after an unlock is exactly the
//! tell the duress PIN exists to avoid. It is also unlocked, so nothing would
//! ever release the blackout again.
void test_security_lock_shred__a_duress_wipe_leaves_the_radio_alone(void) {
  s_locked = false;
  s_state = SecurityLockStateArmed;

  security_lock_shred(SecurityShredReasonDuressPin);

  cl_assert_equal_i(SHRED_TARGET_COUNT, s_trace.files_shredded);
  cl_assert_equal_i(0, s_trace.blackouts);
}

//! The clock-rollback wipe runs whenever the tamper is spotted, which may be
//! before or after the lock delay elapsed. The same rule covers both with no
//! special case: dark if it was already locked, untouched if it was not.
void test_security_lock_shred__a_rollback_wipe_follows_the_locked_state(void) {
  s_locked = false;
  s_state = SecurityLockStateArmed;
  security_lock_shred(SecurityShredReasonClockRollback);
  cl_assert_equal_i(0, s_trace.blackouts);

  s_locked = true;
  s_state = SecurityLockStateLocked;
  security_lock_mark_dirty_since_shred();
  security_lock_shred(SecurityShredReasonClockRollback);
  cl_assert_equal_i(1, s_trace.blackouts);
}

//! Nothing to receive is nothing to receive whether or not the wipe found
//! anything to destroy.
void test_security_lock_shred__a_clean_wipe_while_locked_still_goes_dark(void) {
  s_dirty = false;
  s_locked = true;
  s_state = SecurityLockStateLocked;

  security_lock_shred(SecurityShredReasonManualPanic);

  cl_assert_equal_i(0, s_trace.files_shredded);
  cl_assert_equal_i(1, s_trace.blackouts);
}

//! A wipe with no PIN configured cannot lock, and a watch with no PIN has no
//! way to release the blackout again.
void test_security_lock_shred__a_wipe_without_a_lock_leaves_the_radio_alone(void) {
  s_pin_len = 0;
  s_locked = false;

  security_lock_shred(SecurityShredReasonManualPanic);

  cl_assert_equal_i(0, s_trace.blackouts);
}

// What the wipe tells apps
////////////////////////////////////

//! The duress PIN unlocks first and wipes afterwards, so it is the only trigger
//! that publishes an unlock and then a shred. An app subscribed to both SDK
//! services would read that pair as "the duress PIN was entered" -- and because
//! a duress wipe deliberately skips the radio blackout, it could send the
//! inference straight to the phone, which in a duress is quite possibly in the
//! coercer's hands. So this wipe announces nothing at all.
void test_security_lock_shred__a_duress_wipe_announces_nothing(void) {
  security_lock_shred(SecurityShredReasonDuressPin);

  cl_assert_equal_i(0, s_trace.events);
  // Silent, not skipped: the wipe itself still ran in full.
  cl_assert_equal_i(SHRED_TARGET_COUNT, s_trace.files_shredded);
}

//! The other half of the rule above, so the silence is a property of the duress
//! reason rather than of an announcement that never fires for anything.
void test_security_lock_shred__every_other_reason_still_announces(void) {
  const SecurityShredReason reasons[] = {
      SecurityShredReasonUnknown,           SecurityShredReasonPhoneLockdown,
      SecurityShredReasonManualPanic,       SecurityShredReasonDisconnectTimeout,
      SecurityShredReasonRebootWhileLocked, SecurityShredReasonPinAttemptsExhausted,
      SecurityShredReasonClockRollback,
  };

  for (size_t i = 0; i < ARRAY_LENGTH(reasons); ++i) {
    security_lock_mark_dirty_since_shred();
    security_lock_shred(reasons[i]);
  }

  cl_assert_equal_i((int)ARRAY_LENGTH(reasons), s_trace.events);
}

// Boot
////////////////////////////////////

//! The boot wipe zeroes files inline and leaves the slow half to
//! security_lock_finish_boot_shred(), which is a no-op unless the wipe that ran
//! actually destroyed something.
void test_security_lock_shred__boot_wipe_with_something_to_destroy_owes_a_tail(void) {
  s_locked = true;
  s_state = SecurityLockStateLocked;

  security_lock_handle_boot();
  // bt_ctl does not exist this early. The blackout the boot wipe owes is taken
  // by security_lock_endpoint_init() once it does.
  cl_assert_equal_i(0, s_trace.blackouts);
  cl_assert_equal_i(SHRED_TARGET_COUNT, s_trace.files_shredded);
  // Deferred out of the boot path, so nothing yet.
  cl_assert_equal_i(0, s_trace.sweeps_started);

  security_lock_finish_boot_shred();
  cl_assert_equal_i(1, s_trace.sweeps_started);
  cl_assert_equal_i(1, s_trace.unfaithful_marks);
  // The tail started the sweep; it does not get to declare the wipe done.
  cl_assert(security_lock_is_shred_pending());

  prv_drain_sweep();
  cl_assert(!security_lock_is_shred_pending());
}

//! A clean boot wipe touches no file, so there are no superseded copies for the
//! sweep to find and no resend to ask the phone for.
void test_security_lock_shred__clean_boot_wipe_owes_no_tail(void) {
  s_dirty = false;
  s_locked = true;
  s_state = SecurityLockStateLocked;

  security_lock_handle_boot();
  cl_assert_equal_i(0, s_trace.files_shredded);
  cl_assert_equal_i(0, s_trace.region_erases);

  security_lock_finish_boot_shred();
  cl_assert_equal_i(0, s_trace.sweeps_started);
  cl_assert_equal_i(0, s_trace.unfaithful_marks);
}

//! An interrupted wipe has to complete on the next boot however clean the flag
//! claims to be, or a half-wiped filesystem is mistaken for an untouched one.
void test_security_lock_shred__a_pending_wipe_still_runs_at_boot_when_clean(void) {
  s_dirty = false;
  s_shred_pending = true;

  security_lock_handle_boot();
  cl_assert_equal_i(SHRED_TARGET_COUNT, s_trace.files_shredded);

  security_lock_finish_boot_shred();
  cl_assert_equal_i(1, s_trace.sweeps_started);

  prv_drain_sweep();
  cl_assert(!security_lock_is_shred_pending());
}

//! A countdown that lapsed while the watch was powered off. The phone acts on
//! the reason, and a lockdown the user asked for is not a disconnect timeout,
//! so the two have to arrive labelled differently.
void test_security_lock_shred__a_lapsed_manual_countdown_reports_a_manual_panic(void) {
  s_shred_deadline = 500;
  s_shred_deadline_expired = true;
  s_countdown_source = SecurityCountdownManual;

  security_lock_handle_boot();
  security_lock_finish_boot_shred();

  cl_assert_equal_i(SHRED_TARGET_COUNT, s_trace.files_shredded);
  cl_assert_equal_i(SecurityShredReasonManualPanic, s_trace.last_complete_reason);
}

void test_security_lock_shred__a_lapsed_disconnect_countdown_reports_a_timeout(void) {
  s_shred_deadline = 500;
  s_shred_deadline_expired = true;
  s_countdown_source = SecurityCountdownDisconnect;

  security_lock_handle_boot();
  security_lock_finish_boot_shred();

  cl_assert_equal_i(SHRED_TARGET_COUNT, s_trace.files_shredded);
  cl_assert_equal_i(SecurityShredReasonDisconnectTimeout, s_trace.last_complete_reason);
}

//! A countdown that was armed but had not lapsed. Rebooting is the one reliable
//! way past the lock screen, so it still wipes -- but as a reboot, not as a
//! deadline that never came.
void test_security_lock_shred__an_armed_countdown_that_has_not_lapsed_is_a_reboot(void) {
  s_shred_deadline = 500;
  s_shred_deadline_expired = false;
  s_countdown_source = SecurityCountdownDisconnect;

  security_lock_handle_boot();
  security_lock_finish_boot_shred();

  cl_assert_equal_i(SHRED_TARGET_COUNT, s_trace.files_shredded);
  cl_assert_equal_i(SecurityShredReasonRebootWhileLocked, s_trace.last_complete_reason);
}

//! Nothing armed and nothing pending is an ordinary boot: no wipe at all, not
//! even the cheap half.
void test_security_lock_shred__an_ordinary_boot_wipes_nothing(void) {
  s_state = SecurityLockStateDisabled;

  security_lock_handle_boot();

  cl_assert_equal_i(0, s_trace.files_shredded);
  cl_assert_equal_i(0, s_trace.region_erases);
}

// The master switch
////////////////////////////////////
//
// Enforced here rather than at each trigger, so this is where the property is
// stated: with the feature off, the funnel every trigger goes through does
// nothing at all.

void test_security_lock_shred__the_feature_being_off_wipes_nothing(void) {
  s_state = SecurityLockStateDisabled;

  const uint32_t wiped = security_lock_shred(SecurityShredReasonPhoneLockdown);

  cl_assert_equal_i(0, wiped);
  cl_assert_equal_i(0, s_trace.files_shredded);
  cl_assert_equal_i(0, s_trace.region_erases);
  cl_assert_equal_i(0, s_trace.quiesces);
  cl_assert_equal_i(0, s_trace.shred_completes);
  cl_assert_equal_i(0, s_trace.blackouts);
  // And nothing was left half done for the next boot to pick up.
  cl_assert(!security_lock_is_shred_pending());
}

//! Every trigger, not just the one the defect was found on: the guard is at the
//! funnel, so refusing must not depend on why.
void test_security_lock_shred__no_reason_gets_past_the_feature_being_off(void) {
  s_state = SecurityLockStateDisabled;

  const SecurityShredReason reasons[] = {
      SecurityShredReasonPhoneLockdown,     SecurityShredReasonManualPanic,
      SecurityShredReasonDisconnectTimeout, SecurityShredReasonRebootWhileLocked,
      SecurityShredReasonPinAttemptsExhausted, SecurityShredReasonClockRollback,
      SecurityShredReasonDuressPin,         SecurityShredReasonUnknown,
  };
  for (size_t i = 0; i < ARRAY_LENGTH(reasons); ++i) {
    cl_assert_equal_i(0, security_lock_shred(reasons[i]));
  }

  cl_assert_equal_i(0, s_trace.files_shredded);
}

//! The switch is not a way to get a wipe half done and leave it that way. A
//! shred that already started is finished at the next boot whatever the switch
//! says: the content is gone either way, and stopping leaves fragments that
//! pass for an untouched filesystem.
void test_security_lock_shred__an_interrupted_wipe_finishes_even_when_off(void) {
  s_state = SecurityLockStateDisabled;
  s_shred_pending = true;

  security_lock_handle_boot();
  cl_assert_equal_i(SHRED_TARGET_COUNT, s_trace.files_shredded);

  security_lock_finish_boot_shred();
  prv_drain_sweep();
  cl_assert(!security_lock_is_shred_pending());
}

//! Finishing that wipe is cleanup, not a lock. Locking here would turn the
//! feature back on as a side effect.
void test_security_lock_shred__finishing_an_interrupted_wipe_does_not_lock(void) {
  s_state = SecurityLockStateDisabled;
  s_shred_pending = true;

  security_lock_handle_boot();

  cl_assert_equal_i(SecurityLockStateDisabled, s_state);
  cl_assert(!s_locked);
}

//! A deadline left in the record from before the switch was thrown must not
//! fire at boot. Nothing arms one while off, so this is a stale record rather
//! than a live countdown.
void test_security_lock_shred__a_stale_deadline_does_not_fire_at_boot_when_off(void) {
  s_state = SecurityLockStateDisabled;
  s_locked = true;

  security_lock_handle_boot();

  cl_assert_equal_i(0, s_trace.files_shredded);
  cl_assert_equal_i(0, s_trace.region_erases);
}

//! Winding the clock back is the one tamper that outruns a deadline. With the
//! feature off there is no deadline and nothing to outrun.
void test_security_lock_shred__a_rollback_at_boot_is_ignored_when_off(void) {
  s_state = SecurityLockStateDisabled;
  s_rolled_back = true;

  security_lock_handle_boot();

  cl_assert_equal_i(0, s_trace.files_shredded);
}

//! The same rollback with the feature on still wipes, so the test above is
//! measuring the switch and not a rollback path that never worked.
void test_security_lock_shred__a_rollback_at_boot_still_wipes_when_on(void) {
  s_state = SecurityLockStateArmed;
  s_rolled_back = true;

  security_lock_handle_boot();

  cl_assert_equal_i(SHRED_TARGET_COUNT, s_trace.files_shredded);
  // And locks, so a wipe is not followed by a watch that opens straight up: a
  // watch counting down never reached the lock screen.
  cl_assert_equal_i(SecurityLockStateLocked, security_lock_get_state());
}

// What the wipe covers
////////////////////////////////////

//! The predicate the write guard in blob_db_insert() consults. It answers from
//! the same list the wipe walks, which is the point: a second list would drift
//! and the watch would accept back, in cleartext, a store it had just erased.
void test_security_lock_shred__covered_dbs_are_the_ones_the_wipe_destroys(void) {
  cl_assert(security_lock_shred_covers_db(BlobDBIdNotifs));
  cl_assert(security_lock_shred_covers_db(BlobDBIdPins));
  cl_assert(security_lock_shred_covers_db(BlobDBIdReminders));
  cl_assert(security_lock_shred_covers_db(BlobDBIdContacts));
  cl_assert(security_lock_shred_covers_db(BlobDBIdWeather));
  cl_assert(security_lock_shred_covers_db(BlobDBIdiOSNotifPref));
  cl_assert(security_lock_shred_covers_db(BlobDBIdAppGlance));
}

//! The stores the wipe deliberately spares. Blocking writes to these while
//! locked would break things for no gain: none of them holds message, calendar
//! or contact content.
void test_security_lock_shred__spared_dbs_are_not_covered(void) {
  cl_assert(!security_lock_shred_covers_db(BlobDBIdApps));
  cl_assert(!security_lock_shred_covers_db(BlobDBIdPrefs));
  cl_assert(!security_lock_shred_covers_db(BlobDBIdWatchAppPrefs));
  cl_assert(!security_lock_shred_covers_db(BlobDBIdHealth));
  cl_assert(!security_lock_shred_covers_db(BlobDBIdSettings));
  cl_assert(!security_lock_shred_covers_db(BlobDBIdTest));
}

//! The anti-drift check, stated against the wipe's own output rather than
//! against a list written out here: every database bit the wipe reports having
//! erased is one the guard refuses writes to, and no other id is.
void test_security_lock_shred__coverage_matches_the_wiped_bitmap(void) {
  const uint32_t wiped = security_lock_shred(SecurityShredReasonManualPanic);

  for (int id = 0; id < NumBlobDBs; ++id) {
    const bool in_bitmap = ((wiped & SECURITY_SHRED_DB_BIT(id)) != 0);
    cl_assert_equal_b(in_bitmap, security_lock_shred_covers_db((BlobDBId)id));
  }
}

// Writes refused while the watch was shut
////////////////////////////////////

//! A refused write was acked to the phone as a success, so the phone has it
//! recorded as delivered. Those databases ride along with what the wipe
//! destroyed rather than waiting for an unlock that may be hours away.
void test_security_lock_shred__a_wipe_asks_for_refused_writes_too(void) {
  s_refused_dbs = SECURITY_SHRED_DB_BIT(BlobDBIdPins);

  const uint32_t wiped = security_lock_shred(SecurityShredReasonDisconnectTimeout);

  cl_assert_equal_i(1, s_trace.shred_completes);
  cl_assert_equal_i(wiped | SECURITY_SHRED_DB_BIT(BlobDBIdPins), s_trace.last_complete_bitmap);
}

//! Two wipes must not ask twice: the first drains the record.
void test_security_lock_shred__refusals_are_reported_once(void) {
  s_refused_dbs = SECURITY_SHRED_DB_BIT(BlobDBIdPins);
  security_lock_shred(SecurityShredReasonDisconnectTimeout);

  security_lock_mark_dirty_since_shred();
  const uint32_t wiped = security_lock_shred(SecurityShredReasonManualPanic);

  cl_assert_equal_i(2, s_trace.shred_completes);
  cl_assert_equal_i(wiped, s_trace.last_complete_bitmap);
}

//! A duress wipe asks for nothing -- the phone would restore everything within
//! seconds -- but it still has to drain the record, or the next unlock would
//! ask on its behalf and undo the whole point of the duress PIN.
void test_security_lock_shred__a_duress_wipe_swallows_the_refusals(void) {
  s_refused_dbs = SECURITY_SHRED_DB_BIT(BlobDBIdPins);

  security_lock_shred(SecurityShredReasonDuressPin);

  cl_assert_equal_i(0, s_trace.shred_completes);
  cl_assert_equal_i(0, security_lock_take_refused_dbs());
}

//! The boot wipe runs before the radio exists, so it cannot say anything. The
//! tail is the first point that can, and the request waits there for a session
//! rather than being sent into one that does not exist.
void test_security_lock_shred__the_boot_wipe_asks_from_its_tail(void) {
  s_locked = true;
  s_state = SecurityLockStateLocked;

  security_lock_handle_boot();
  cl_assert_equal_i(0, s_trace.shred_completes);

  security_lock_finish_boot_shred();

  cl_assert_equal_i(1, s_trace.shred_completes);
  cl_assert(s_trace.last_complete_bitmap & SECURITY_SHRED_NON_BLOBDB_BIT);
  cl_assert_equal_i(SecurityShredReasonRebootWhileLocked, s_trace.last_complete_reason);
}

//! A clean boot wipe destroyed nothing of the phone's, so it asks for nothing.
void test_security_lock_shred__a_clean_boot_wipe_asks_for_nothing(void) {
  s_dirty = false;
  s_locked = true;
  s_state = SecurityLockStateLocked;

  security_lock_handle_boot();
  security_lock_finish_boot_shred();

  cl_assert_equal_i(0, s_trace.shred_completes);
}
