/* SPDX-FileCopyrightText: 2024 Google LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include "clar.h"

#include "pbl/services/notifications/alerts_preferences.h"
#include "pbl/services/notifications/ancs/ancs_notifications.h"
#include "pbl/services/blob_db/ios_notif_pref_db.h"


// Stubs
////////////////////////////////////////////////////////////////
#include "stubs_analytics.h"
#include "stubs_i18n.h"
#include "stubs_layout_layer.h"
#include "stubs_logging.h"
#include "stubs_notifications.h"
#include "stubs_passert.h"
#include "stubs_pbl_malloc.h"
#include "stubs_pin_db.h"
#include "stubs_regular_timer.h"
#include "stubs_reminder_db.h"
#include "stubs_timeline.h"
#include "stubs_uuid.h"
#include "stubs_nexmo.h"

iOSNotifPrefs* ios_notif_pref_db_get_prefs(const uint8_t *app_id, int length) {
  return NULL;
}

void ios_notif_pref_db_free_prefs(iOSNotifPrefs *prefs) {
  return;
}

void ancs_filtering_record_app(iOSNotifPrefs **app_notif_prefs,
                               const ANCSAttribute *app_id,
                               const ANCSAttribute *display_name,
                               const ANCSAttribute *title) {
}

bool ancs_filtering_is_muted(const iOSNotifPrefs *app_notif_prefs) {
  return false;
}

bool ancs_filtering_matches_rules(const iOSNotifPrefs *app_notif_prefs,
                                  const ANCSAttribute *title,
                                  const ANCSAttribute *subtitle,
                                  const ANCSAttribute *body) {
  return false;
}


// Fakes
////////////////////////////////////////////////////////////////
#include "fake_events.h"
#include "fake_notification_storage.h"
#include "fake_security_lock.h"

static time_t s_now;
time_t rtc_get_time(void) {
  return s_now;
}

RtcTicks rtc_get_ticks(void) {
  return 0;
}

void test_ancs_notifications__initialize(void) {
  s_now = 1;
  fake_notification_storage_reset();
  fake_event_init();
  fake_security_lock_reset();
}

void test_ancs_notifications__cleanup(void) {
}

void test_ancs_notifications__handle_phone_call_message(void) {

  const uint8_t app_id[] = {
      0x00,
      21, 0x00,
      'c', 'o', 'm', '.', 'a', 'p', 'p', 'l', 'e', '.',
      'm', 'o', 'b', 'i', 'l', 'e', 'p', 'h', 'o', 'n', 'e',
  };
  const uint8_t title[] = {
      0x01,
      23, 0x00,
      // Add some formatting modifiers before and after. iOS 10 seems to be sending phone numbers with them now.
      0xe2, 0x80, 0xad, '+', '1', ' ', '(', '5', '1', '0', ')', ' ', '4', '4', '4', '-', '3', '3', '3', '3', 0xe2, 0x80, 0xac,
  };
  const uint8_t subtitle[] = {
      0x02,
      8, 0x00,
      'P', 'e', 'b', 'b', 'l', 'e', 'H', 'Q',
  };
  const uint8_t message[] = {
      0x03,
      13, 0x00,
      'I', 'n', 'c', 'o', 'm', 'i', 'n', 'g', ' ', 'C', 'a', 'l', 'l',
  };
  const uint8_t date[] = {
      0x05,
      0x00, 0x00,
  };
  const uint8_t positive_action[] = {
      0x06,
      6, 0x00,
      'A', 'n', 's', 'w', 'e', 'r',
  };
  const uint8_t negative_action[] = {
      0x07,
      7, 0x00,
      'D', 'e', 'c', 'l', 'i', 'n', 'e',
  };

  ANCSAttribute *notif_attributes[] = {
    [FetchedNotifAttributeIndexAppID] = (ANCSAttribute *)&app_id,
    [FetchedNotifAttributeIndexTitle] = (ANCSAttribute *)&title,
    [FetchedNotifAttributeIndexSubtitle] = (ANCSAttribute *)&subtitle,
    [FetchedNotifAttributeIndexMessage] = (ANCSAttribute *)&message,
    [FetchedNotifAttributeIndexDate]= (ANCSAttribute *)&date,
    [FetchedNotifAttributeIndexPositiveActionLabel] = (ANCSAttribute *)&positive_action,
    [FetchedNotifAttributeIndexNegativeActionLabel] = (ANCSAttribute *)&negative_action,
  };

  const uint8_t app_display_name[] = {
    0x00,
    5, 0x0,
    'P', 'h', 'o', 'n', 'e',
  };

  ANCSAttribute *app_attributes[] = {
    [FetchedAppAttributeIndexDisplayName] = (ANCSAttribute *)&app_display_name,
  };

  ANCSProperty properties = ANCSProperty_IncomingCall;

  ancs_notifications_handle_message(37, properties, notif_attributes, app_attributes);

  // We just processed an incomming phone call event, there better be a phone event scheduled!
  PebbleEvent event = fake_event_get_last();

  cl_assert_equal_i(event.type, PEBBLE_PHONE_EVENT);
  cl_assert_equal_i(event.phone.type, PhoneEventType_Incoming);
  cl_assert_equal_i(event.phone.source, PhoneCallSource_ANCS_Legacy);
}

void test_ancs_notifications__handle_phone_call_removed(void) {
  const uint32_t uid = 5;

  // Make sure we don't send any events when this isn't iOS9
  ancs_notifications_handle_notification_removed(uid, ANCSProperty_IncomingCall);
  cl_assert_equal_i(fake_event_get_count(), 0);

  // Make sure that we trigger an event when this is iOS9
  ancs_notifications_handle_notification_removed(uid,
                                                 ANCSProperty_IncomingCall | ANCSProperty_iOS9);
  PebbleEvent event = fake_event_get_last();
  cl_assert_equal_i(fake_event_get_count(), 1);
  cl_assert_equal_i(event.type, PEBBLE_PHONE_EVENT);
  cl_assert_equal_i(event.phone.type, PhoneEventType_Hide);
  cl_assert_equal_i(event.phone.source, PhoneCallSource_ANCS);
  cl_assert_equal_i(event.phone.call_identifier, uid);

  // Make sure that having a matching notification in notif_db still results in a call hide event
  fake_notification_storage_set_existing_ancs_notification(&(Uuid)UUID_SYSTEM, uid);
  ancs_notifications_handle_notification_removed(uid,
                                                 ANCSProperty_IncomingCall | ANCSProperty_iOS9);
  event = fake_event_get_last();
  cl_assert_equal_i(fake_event_get_count(), 2);
  cl_assert_equal_i(event.type, PEBBLE_PHONE_EVENT);
  cl_assert_equal_i(event.phone.type, PhoneEventType_Hide);
  cl_assert_equal_i(event.phone.source, PhoneCallSource_ANCS);
  cl_assert_equal_i(event.phone.call_identifier, uid);
}

// Security lock
////////////////////////////////////////////////////////////////

static const uint8_t s_msg_app_id[] = {
  0x00,
  11, 0x00,
  'c', 'o', 'm', '.', 'a', 'c', 'm', 'e', '.', 'i', 'm',
};
static const uint8_t s_msg_title[] = {
  0x01,
  5, 0x00,
  'A', 'l', 'i', 'c', 'e',
};
static const uint8_t s_msg_subtitle[] = {
  0x02,
  0, 0x00,
};
static const uint8_t s_msg_body[] = {
  0x03,
  6, 0x00,
  's', 'e', 'c', 'r', 'e', 't',
};
static const uint8_t s_msg_date[] = {
  0x05,
  0x00, 0x00,
};
static const uint8_t s_msg_negative_action[] = {
  0x07,
  5, 0x00,
  'C', 'l', 'e', 'a', 'r',
};
static const uint8_t s_msg_display_name[] = {
  0x00,
  4, 0x00,
  'A', 'c', 'm', 'e',
};

static void prv_handle_message(uint32_t uid, ANCSProperty properties) {
  ANCSAttribute *notif_attributes[] = {
    [FetchedNotifAttributeIndexAppID] = (ANCSAttribute *)&s_msg_app_id,
    [FetchedNotifAttributeIndexTitle] = (ANCSAttribute *)&s_msg_title,
    [FetchedNotifAttributeIndexSubtitle] = (ANCSAttribute *)&s_msg_subtitle,
    [FetchedNotifAttributeIndexMessage] = (ANCSAttribute *)&s_msg_body,
    [FetchedNotifAttributeIndexDate] = (ANCSAttribute *)&s_msg_date,
    [FetchedNotifAttributeIndexNegativeActionLabel] =
        (ANCSAttribute *)&s_msg_negative_action,
  };
  ANCSAttribute *app_attributes[] = {
    [FetchedAppAttributeIndexDisplayName] = (ANCSAttribute *)&s_msg_display_name,
  };

  ancs_notifications_handle_message(uid, properties, notif_attributes, app_attributes);
}

void test_ancs_notifications__update_stores_when_unlocked(void) {
  // An ANCS update reaches notification_storage_store() without going through
  // notifications_add_notification().
  fake_notification_storage_set_existing_ancs_notification(&(Uuid)UUID_SYSTEM, 41);
  fake_security_lock_set_locked(false);

  prv_handle_message(42, ANCSProperty_iOS9);

  cl_assert_equal_i(fake_notification_storage_get_store_count(), 1);
}

void test_ancs_notifications__update_dropped_when_locked(void) {
  fake_notification_storage_set_existing_ancs_notification(&(Uuid)UUID_SYSTEM, 41);
  fake_security_lock_set_locked(true);

  prv_handle_message(42, ANCSProperty_iOS9);

  cl_assert_equal_i(fake_notification_storage_get_store_count(), 0);
  cl_assert_equal_i(fake_notification_storage_get_remove_count(), 0);
  cl_assert_equal_i(fake_event_get_count(), 0);
}

void test_ancs_notifications__update_dropped_while_shredding_unlocked(void) {
  fake_notification_storage_set_existing_ancs_notification(&(Uuid)UUID_SYSTEM, 41);
  // Unlocked but wiping: the duress and clock-rollback triggers both look
  // like this, and the phone keeps pushing ANCS updates throughout.
  fake_security_lock_set_locked(false);
  fake_security_lock_set_shredding(true);

  prv_handle_message(42, ANCSProperty_iOS9);

  cl_assert_equal_i(fake_notification_storage_get_store_count(), 0);
  cl_assert_equal_i(fake_notification_storage_get_remove_count(), 0);
  cl_assert_equal_i(fake_event_get_count(), 0);
}

void test_ancs_notifications__incoming_call_dropped_when_locked(void) {
  // The caller ID is exactly the kind of content the lock exists to hide, so
  // the phone event must not be raised either.
  const uint8_t phone_app_id[] = {
    0x00,
    21, 0x00,
    'c', 'o', 'm', '.', 'a', 'p', 'p', 'l', 'e', '.',
    'm', 'o', 'b', 'i', 'l', 'e', 'p', 'h', 'o', 'n', 'e',
  };
  ANCSAttribute *notif_attributes[] = {
    [FetchedNotifAttributeIndexAppID] = (ANCSAttribute *)&phone_app_id,
    [FetchedNotifAttributeIndexTitle] = (ANCSAttribute *)&s_msg_title,
    [FetchedNotifAttributeIndexSubtitle] = (ANCSAttribute *)&s_msg_subtitle,
    [FetchedNotifAttributeIndexMessage] = (ANCSAttribute *)&s_msg_body,
    [FetchedNotifAttributeIndexDate] = (ANCSAttribute *)&s_msg_date,
    [FetchedNotifAttributeIndexNegativeActionLabel] =
        (ANCSAttribute *)&s_msg_negative_action,
  };
  ANCSAttribute *app_attributes[] = {
    [FetchedAppAttributeIndexDisplayName] = (ANCSAttribute *)&s_msg_display_name,
  };

  fake_security_lock_set_locked(true);

  ancs_notifications_handle_message(37, ANCSProperty_IncomingCall, notif_attributes,
                                    app_attributes);

  cl_assert_equal_i(fake_event_get_count(), 0);
}
