/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include "shred_targets.h"

#include "pbl/services/security_lock_shred.h"
#include "pbl/util/size.h"

//! Files whose entire contents are destroyed, and the BlobDB each one backs.
//!
//! App persist storage ("ps<uuid>"), the app database ("appdb"), the BT bonding
//! store and the datalogging queue ("dls<session>") are deliberately absent:
//! the phone cannot restore them, so wiping them would make the feature
//! destructive enough that nobody would turn it on.
//!
//! Health/activity ("activity", "healthdb") is absent because it is opt-in --
//! Settings > Security > Erase Health Data -- and because destroying it takes
//! more than zeroing two files: the activity service has a day of counters in
//! RAM that the next minute handler would write straight back. The wipe calls
//! health_db_shred() and activity_shred() directly, and ORs in the health bit
//! itself.
//!
//! It stays out of security_lock_shred_covers_db() on purpose, though, which is
//! what refuses inbound writes while the watch is shut. Whether health is a
//! target depends on a setting, and a switch that silently changed which of the
//! phone's writes get refused mid-lock would buy nothing: those records are
//! re-pushed on the next reconnect either way.
//!
//! Datalogging is the sharpest case. It is the outbound watch-to-phone queue,
//! so by definition it holds the one thing the phone does not have yet, and
//! most of what it holds is the activity data this list already spares.
static const SecurityShredTarget s_shred_targets[] = {
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

const SecurityShredTarget *security_lock_shred_targets(size_t *count_out) {
  *count_out = ARRAY_LENGTH(s_shred_targets);
  return s_shred_targets;
}

bool security_lock_shred_covers_db(BlobDBId db_id) {
  for (size_t i = 0; i < ARRAY_LENGTH(s_shred_targets); ++i) {
    if (s_shred_targets[i].db_id == db_id) {
      return true;
    }
  }
  return false;
}
