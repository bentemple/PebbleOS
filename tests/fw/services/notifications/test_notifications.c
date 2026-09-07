/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include "clar.h"

#include "pbl/services/notifications/notifications.h"
#include "pbl/services/timeline/item.h"

// Stubs
////////////////////////////////////////////////////////////////
#include "stubs_analytics.h"
#include "stubs_layout_layer.h"
#include "stubs_logging.h"
#include "stubs_passert.h"
#include "stubs_pbl_malloc.h"
#include "stubs_uuid.h"

// Fakes
////////////////////////////////////////////////////////////////
#include "fake_events.h"
#include "fake_notification_storage.h"
#include "fake_security_lock.h"

static TimelineItem *prv_create_notification(void) {
  AttributeList attr_list = {};
  attribute_list_add_cstring(&attr_list, AttributeIdTitle, "Alice");
  attribute_list_add_cstring(&attr_list, AttributeIdBody, "secret");

  TimelineItem *item = timeline_item_create_with_attributes(
      0, 0, TimelineItemTypeNotification, LayoutIdNotification, &attr_list, NULL);
  attribute_list_destroy_list(&attr_list);

  cl_assert(item != NULL);
  return item;
}

void test_notifications__initialize(void) {
  fake_notification_storage_reset();
  fake_event_init();
  fake_security_lock_reset();
}

void test_notifications__cleanup(void) {
}

void test_notifications__unlocked_stores_and_notifies(void) {
  TimelineItem *item = prv_create_notification();

  fake_security_lock_set_locked(false);
  notifications_add_notification(item);

  cl_assert_equal_i(fake_notification_storage_get_store_count(), 1);
  cl_assert_equal_i(fake_event_get_count(), 1);

  PebbleEvent event = fake_event_get_last();
  cl_assert_equal_i(event.type, PEBBLE_SYS_NOTIFICATION_EVENT);
  cl_assert_equal_i(event.sys_notification.type, NotificationAdded);

  // The caller still owns the item.
  timeline_item_destroy(item);
}

void test_notifications__locked_drops(void) {
  TimelineItem *item = prv_create_notification();

  fake_security_lock_set_locked(true);
  notifications_add_notification(item);

  // Not stored, and no added-event that would point at a missing item.
  cl_assert_equal_i(fake_notification_storage_get_store_count(), 0);
  cl_assert_equal_i(fake_event_get_count(), 0);

  // Ownership is unchanged by the drop, so this must not double-free.
  timeline_item_destroy(item);
}

void test_notifications__shredding_drops_while_unlocked(void) {
  TimelineItem *item = prv_create_notification();

  // A duress wipe unlocks first by design, so the lock state alone does not
  // cover it -- and that is the case where a notification window is most
  // likely to be open, because the user has just unlocked and is watching.
  fake_security_lock_set_locked(false);
  fake_security_lock_set_shredding(true);
  notifications_add_notification(item);

  cl_assert_equal_i(fake_notification_storage_get_store_count(), 0);
  cl_assert_equal_i(fake_event_get_count(), 0);

  timeline_item_destroy(item);
}

void test_notifications__unlocking_resumes_storing(void) {
  TimelineItem *dropped = prv_create_notification();
  fake_security_lock_set_locked(true);
  notifications_add_notification(dropped);
  timeline_item_destroy(dropped);

  TimelineItem *stored = prv_create_notification();
  fake_security_lock_set_locked(false);
  notifications_add_notification(stored);
  timeline_item_destroy(stored);

  cl_assert_equal_i(fake_notification_storage_get_store_count(), 1);
  cl_assert_equal_i(fake_event_get_count(), 1);
}

// The block-notifications-when-locked setting
////////////////////////////////////

//! Off keeps them. Nothing has been destroyed while the watch is merely shut,
//! so there is nothing to write back, and the user gets what arrived while they
//! were away. Never shown either way: the lock screen outranks the modal.
void test_notifications__locked_stores_when_the_setting_is_off(void) {
  TimelineItem *item = prv_create_notification();

  fake_security_lock_set_locked(true);
  fake_security_lock_set_block_notifications(false);
  notifications_add_notification(item);

  cl_assert_equal_i(fake_notification_storage_get_store_count(), 1);

  timeline_item_destroy(item);
}

//! And the setting does not reach the wipe. A store landing mid-erase would put
//! cleartext back as fast as it is destroyed, whatever the user chose.
void test_notifications__shredding_drops_even_when_the_setting_is_off(void) {
  TimelineItem *item = prv_create_notification();

  fake_security_lock_set_locked(false);
  fake_security_lock_set_shredding(true);
  fake_security_lock_set_block_notifications(false);
  notifications_add_notification(item);

  cl_assert_equal_i(fake_notification_storage_get_store_count(), 0);

  timeline_item_destroy(item);
}
