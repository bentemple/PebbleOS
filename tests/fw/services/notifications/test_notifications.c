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
//! were away.
void test_notifications__locked_stores_when_the_setting_is_off(void) {
  TimelineItem *item = prv_create_notification();

  fake_security_lock_set_locked(true);
  fake_security_lock_set_block_notifications(false);
  notifications_add_notification(item);

  cl_assert_equal_i(fake_notification_storage_get_store_count(), 1);
  // The body really is on flash, not merely counted.
  cl_assert(fake_notification_storage_get_last_notification() != NULL);

  timeline_item_destroy(item);
}

//! Keeping a notification and showing it are separate decisions, and this
//! module only makes the first one.
//!
//! It stores, and then announces the arrival exactly as it would on an unlocked
//! watch -- the announcement is what drives the unread count, the vibe, and the
//! pop-up, and only the last of those must be withheld. Whether anything is
//! drawn is decided later, by the launcher's event dispatch, which drops
//! pop-up events while the lock is shut.
//!
//! Written down because the tempting fix for "a notification appeared on a
//! locked watch" is to stop announcing it here, and that fix silently throws
//! the notification away as well: the store and the announcement share this one
//! early return. Off would then mean the same thing as on.
void test_notifications__a_locked_store_still_announces_the_arrival(void) {
  TimelineItem *item = prv_create_notification();

  fake_security_lock_set_locked(true);
  fake_security_lock_set_block_notifications(false);
  notifications_add_notification(item);

  cl_assert_equal_i(fake_notification_storage_get_store_count(), 1);
  cl_assert_equal_i(fake_event_get_count(), 1);

  const PebbleEvent event = fake_event_get_last();
  cl_assert_equal_i(event.type, PEBBLE_SYS_NOTIFICATION_EVENT);
  cl_assert_equal_i(event.sys_notification.type, NotificationAdded);

  timeline_item_destroy(item);
}

//! And with the setting on it neither stores nor announces. Announcing a
//! notification that was discarded would leave the unread count claiming
//! something the store cannot produce.
void test_notifications__a_dropped_notification_announces_nothing(void) {
  TimelineItem *item = prv_create_notification();

  fake_security_lock_set_locked(true);
  fake_security_lock_set_block_notifications(true);
  notifications_add_notification(item);

  cl_assert_equal_i(fake_notification_storage_get_store_count(), 0);
  cl_assert_equal_i(fake_event_get_count(), 0);

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
