/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

//! timeline_event_init() only queues its work while timeline_event_deinit()
//! runs synchronously, so a deinit can land before the queued init has run.
//! These tests use the queuing system-task fake rather than the stub that runs
//! callbacks inline, because the inline stub closes the very window under test.

#include "kernel/events.h"
#include "pbl/services/blob_db/pin_db.h"
#include "pbl/services/timeline/calendar.h"
#include "pbl/services/timeline/event.h"
#include "pbl/services/timeline/timeline.h"
#include <pbl/logging/logging.h>

#include "clar.h"

// Stubs
////////////////////////////////////////////////////////////////
#include "stubs_alarm.h"
#include "stubs_analytics.h"
#include "stubs_ancs.h"
#include "stubs_ancs_notifications.h"
#include "stubs_app_cache.h"
#include "stubs_app_install_manager.h"
#include "stubs_app_manager.h"
#include "stubs_blob_db.h"
#include "stubs_blob_db_sync.h"
#include "stubs_blob_db_sync_util.h"
#include "stubs_event_loop.h"
#include "stubs_event_service_client.h"
#include "stubs_hexdump.h"
#include "stubs_i18n.h"
#include "stubs_layout_layer.h"
#include "stubs_logging.h"
#include "stubs_modal_manager.h"
#include "stubs_mutex.h"
#include "stubs_notification_storage.h"
#include "stubs_notifications.h"
#include "stubs_passert.h"
#include "stubs_phone_call_util.h"
#include "stubs_prompt.h"
#include "stubs_rand_ptr.h"
#include "stubs_regular_timer.h"
#include "stubs_reminder_db.h"
#include "stubs_session.h"
#include "stubs_sleep.h"
#include "stubs_task_watchdog.h"
#include "stubs_text_layer_flow.h"
#include "stubs_timeline.h"
#include "stubs_timeline_pin_window.h"
#include "stubs_window_stack.h"

// Fakes
////////////////////////////////////////////////////////////////
#include "fake_events.h"
#include "fake_new_timer.h"
#include "fake_pbl_malloc.h"
#include "fake_pebble_tasks.h"
#include "fake_rtc.h"
#include "fake_settings_file.h"
#include "fake_system_task.h"

bool calendar_layout_verify(bool existing_attributes[]) {
  return true;
}

bool weather_layout_verify(bool existing_attributes[]) {
  return true;
}

const TimelineEventImpl *timeline_peek_get_event_service(void) {
  return NULL;
}

// Setup
////////////////////////////////////////////////////////////////

void test_timeline_event_lifecycle__initialize(void) {
  rtc_set_time(0);
  fake_event_init();
  pin_db_init();
}

void test_timeline_event_lifecycle__cleanup(void) {
  timeline_event_deinit();
  fake_system_task_callbacks_cleanup();
  stub_new_timer_cleanup();
  fake_settings_file_reset();
}

// Tests
////////////////////////////////////////////////////////////////

//! The baseline: a queued init that nothing retires still brings the service up.
void test_timeline_event_lifecycle__queued_init_completes(void) {
  timeline_event_init();
  // Still only queued, so nothing has happened yet.
  cl_assert_equal_i(fake_event_get_count(), 0);

  fake_system_task_callbacks_invoke_pending();
  cl_assert_equal_i(fake_event_get_count(), 1);
}

//! Deleting a timer that was never created walks a NULL node. Surviving that
//! is the point, but surviving it inertly is the other half: the deinit must
//! not bring anything up, and must not leave the module refusing a later init.
void test_timeline_event_lifecycle__deinit_without_init(void) {
  timeline_event_deinit();
  cl_assert_equal_i(fake_event_get_count(), 0);

  timeline_event_init();
  fake_system_task_callbacks_invoke_pending();
  cl_assert_equal_i(fake_event_get_count(), 1);
}

//! Deinit runs on the caller's task and can overtake the queued init. The init
//! must not come up afterwards: the caller has already torn the service down
//! and, in the shred path, wiped the databases it would read.
void test_timeline_event_lifecycle__deinit_retires_queued_init(void) {
  timeline_event_init();
  timeline_event_deinit();

  fake_system_task_callbacks_invoke_pending();
  cl_assert_equal_i(fake_event_get_count(), 0);
  cl_assert_equal_i(stub_new_timer_get_next(), TIMER_INVALID_ID);
}

//! A deinit/init pair either side of a wipe, with the previous init still
//! queued -- two shreds in quick succession. The service must come up exactly
//! once, not twice.
//!
//! Which of the two queued callbacks does it is decided by a bool with no
//! generation behind it: the older one -- the one the deinit was meant to
//! retire -- finds the flag the live init has just set, consumes it and brings
//! the service up, and the live callback then finds it clear and returns.
//! Harmless while the two are the same function with the same argument, and
//! not harmless the moment prv_init carries anything per-cycle. So the
//! callbacks are run one at a time: a count taken after both have run is the
//! same either way and says nothing about which did the work.
void test_timeline_event_lifecycle__second_cycle_supersedes_the_first(void) {
  timeline_event_init();
  timeline_event_deinit();
  timeline_event_init();

  // The older callback first, which is the retired one.
  fake_system_task_callbacks_invoke(1);
  cl_assert_equal_i(fake_event_get_count(), 1);

  // The live one, which finds the flag already spent.
  fake_system_task_callbacks_invoke_pending();
  cl_assert_equal_i(fake_event_get_count(), 1);
}
