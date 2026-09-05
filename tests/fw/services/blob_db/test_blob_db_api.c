/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

//! Tests for the write guard in blob_db_insert(): which stores a locked or
//! shredding watch refuses, which it keeps accepting, and what a refused write
//! is careful not to leave behind.

#include "clar.h"

#include "pbl/services/blob_db/api.h"
#include "pbl/services/security_lock_shred.h"
#include "pbl/util/size.h"

// Fakes
////////////////////////////////////
#include "fake_security_lock.h"

// Stubs
////////////////////////////////////
#include "stubs_analytics.h"
#include "stubs_app_db.h"
#include "stubs_app_glance_db.h"
#include "stubs_contacts_db.h"
#include "stubs_health_db.h"
#include "stubs_ios_notif_pref_db.h"
#include "stubs_logging.h"
#include "stubs_notif_db.h"
#include "stubs_passert.h"
#include "stubs_pbl_malloc.h"
#include "stubs_reminder_db.h"
#include "stubs_settings_blob_db.h"
#include "stubs_watch_app_prefs_db.h"
#include "stubs_weather_db.h"

// Instrumented databases
////////////////////////////////////

//! pin_db and prefs_db are hand-rolled rather than taken from tests/stubs so
//! they can count. One is a store the wipe destroys, the other one it spares,
//! which is the whole distinction under test.
static int s_pin_db_inserts;
static int s_prefs_db_inserts;

void pin_db_init(void) {}

status_t pin_db_insert(const uint8_t *key, int key_len, const uint8_t *val, int val_len) {
  s_pin_db_inserts++;
  return S_SUCCESS;
}

int pin_db_get_len(const uint8_t *key, int key_len) {
  return 0;
}

status_t pin_db_read(const uint8_t *key, int key_len, uint8_t *val_out, int val_out_len) {
  return S_SUCCESS;
}

status_t pin_db_delete(const uint8_t *key, int key_len) {
  return S_SUCCESS;
}

status_t pin_db_flush(void) {
  return S_SUCCESS;
}

status_t pin_db_compact(void) {
  return S_SUCCESS;
}

status_t pin_db_is_dirty(bool *is_dirty_out) {
  *is_dirty_out = false;
  return S_SUCCESS;
}

BlobDBDirtyItem *pin_db_get_dirty_list(void) {
  return NULL;
}

status_t pin_db_mark_synced(const uint8_t *key, int key_len) {
  return S_SUCCESS;
}

void prefs_db_init(void) {}

status_t prefs_db_insert(const uint8_t *key, int key_len, const uint8_t *val, int val_len) {
  s_prefs_db_inserts++;
  return S_SUCCESS;
}

int prefs_db_get_len(const uint8_t *key, int key_len) {
  return 0;
}

status_t prefs_db_read(const uint8_t *key, int key_len, uint8_t *val_out, int val_out_len) {
  return S_SUCCESS;
}

status_t prefs_db_delete(const uint8_t *key, int key_len) {
  return S_SUCCESS;
}

status_t prefs_db_flush(void) {
  return S_SUCCESS;
}

//! Counted rather than stubbed out: an insert event for a record that was never
//! stored would send every subscriber looking for something that is not there.
static int s_insert_events;

void event_put(PebbleEvent *event) {
  if (event->type == PEBBLE_BLOBDB_EVENT) {
    if (event->blob_db.type == BlobDBEventTypeInsert) {
      s_insert_events++;
    }
    kernel_free(event->blob_db.key);
  }
}

// Helpers
////////////////////////////////////

//! Every database a shred destroys, so the tests can state the rule once
//! instead of per store.
static const BlobDBId s_covered_dbs[] = {
    BlobDBIdNotifs,  BlobDBIdPins,         BlobDBIdReminders, BlobDBIdContacts,
    BlobDBIdWeather, BlobDBIdiOSNotifPref, BlobDBIdAppGlance,
};

//! Everything else that is routable. None of these holds message, calendar or
//! contact content, and the phone has no other way to reach them.
static const BlobDBId s_spared_dbs[] = {
    BlobDBIdApps, BlobDBIdPrefs, BlobDBIdWatchAppPrefs, BlobDBIdHealth, BlobDBIdSettings,
};

//! Every routable store has to be in exactly one of the two lists above, or a
//! newly added one is silently neither -- not asserted to be destroyed, not
//! asserted to be spared, and so free to hold phone content through a wipe
//! with nothing here noticing. BlobDBIdTest is the one exclusion: it is a
//! fixture with no store behind it, not a database a shred could reach.
_Static_assert(ARRAY_LENGTH(s_covered_dbs) + ARRAY_LENGTH(s_spared_dbs) + 1 == NumBlobDBs,
               "every BlobDBId but BlobDBIdTest must be listed as covered or spared");

static const uint8_t s_key[] = {0xde, 0xad, 0xbe, 0xef};
static const uint8_t s_val[] = {1, 2, 3, 4, 5, 6, 7, 8};

static status_t prv_insert(BlobDBId db_id) {
  return blob_db_insert(db_id, s_key, sizeof(s_key), s_val, sizeof(s_val));
}

void test_blob_db_api__initialize(void) {
  fake_security_lock_reset();
  s_pin_db_inserts = 0;
  s_prefs_db_inserts = 0;
  s_insert_events = 0;
}

void test_blob_db_api__cleanup(void) {}

// Locked
////////////////////////////////////

//! Calendar titles, contact numbers and the rest are as sensitive as messages,
//! and until now only notifications were refused -- so a locked watch wrote
//! back in cleartext the very records the wipe had just erased.
void test_blob_db_api__locked_drops_every_store_the_wipe_covers(void) {
  fake_security_lock_set_locked(true);

  for (size_t i = 0; i < ARRAY_LENGTH(s_covered_dbs); ++i) {
    // Success on purpose: the phone gets its usual ack, does not retry, and
    // learns nothing about the state of the watch.
    cl_assert_equal_i(S_SUCCESS, prv_insert(s_covered_dbs[i]));
  }

  cl_assert_equal_i(0, s_pin_db_inserts);
  cl_assert_equal_i(0, s_insert_events);
}

//! The stores a wipe spares stay writable. Blocking them would break app
//! installs and settings sync for no security gain.
void test_blob_db_api__locked_still_accepts_the_stores_the_wipe_spares(void) {
  fake_security_lock_set_locked(true);

  for (size_t i = 0; i < ARRAY_LENGTH(s_spared_dbs); ++i) {
    cl_assert_equal_i(S_SUCCESS, prv_insert(s_spared_dbs[i]));
  }

  cl_assert_equal_i(1, s_prefs_db_inserts);
  cl_assert_equal_i((int)ARRAY_LENGTH(s_spared_dbs), s_insert_events);
}

// Shredding
////////////////////////////////////

//! Not redundant with the locked check: the duress PIN and the clock-rollback
//! trigger both wipe while the watch is unlocked, and a write landing mid-wipe
//! is exactly the one the wipe would miss.
void test_blob_db_api__shredding_while_unlocked_drops_the_same_stores(void) {
  fake_security_lock_set_shredding(true);

  for (size_t i = 0; i < ARRAY_LENGTH(s_covered_dbs); ++i) {
    cl_assert_equal_i(S_SUCCESS, prv_insert(s_covered_dbs[i]));
  }

  cl_assert_equal_i(0, s_pin_db_inserts);
  cl_assert_equal_i(0, s_insert_events);
}

// Unlocked
////////////////////////////////////

void test_blob_db_api__unlocked_accepts_everything(void) {
  for (size_t i = 0; i < ARRAY_LENGTH(s_covered_dbs); ++i) {
    cl_assert_equal_i(S_SUCCESS, prv_insert(s_covered_dbs[i]));
  }
  for (size_t i = 0; i < ARRAY_LENGTH(s_spared_dbs); ++i) {
    cl_assert_equal_i(S_SUCCESS, prv_insert(s_spared_dbs[i]));
  }

  cl_assert_equal_i(1, s_pin_db_inserts);
  cl_assert_equal_i(1, s_prefs_db_inserts);
}

//! Writes resume the moment the watch is unlocked; nothing latches.
void test_blob_db_api__unlocking_lets_writes_through_again(void) {
  fake_security_lock_set_locked(true);
  cl_assert_equal_i(S_SUCCESS, prv_insert(BlobDBIdPins));
  cl_assert_equal_i(0, s_pin_db_inserts);

  fake_security_lock_set_locked(false);
  cl_assert_equal_i(S_SUCCESS, prv_insert(BlobDBIdPins));
  cl_assert_equal_i(1, s_pin_db_inserts);
}

// The dirty flag
////////////////////////////////////

//! The ordering that matters. A dropped write stores nothing, so marking the
//! watch dirty would have the next wipe zero seven already-empty files and
//! start a multi-minute sector sweep for nothing -- and the flag is persisted,
//! so it would survive a reboot.
void test_blob_db_api__a_dropped_write_does_not_mark_the_watch_dirty(void) {
  fake_security_lock_set_locked(true);

  for (size_t i = 0; i < ARRAY_LENGTH(s_covered_dbs); ++i) {
    cl_assert_equal_i(S_SUCCESS, prv_insert(s_covered_dbs[i]));
  }

  cl_assert_equal_i(0, fake_security_lock_get_dirty_marks());
}

//! Same for a wipe in flight. The flag is cleared as the wipe starts precisely
//! so a write racing it re-marks -- a write that was refused did not happen.
void test_blob_db_api__a_write_dropped_mid_wipe_does_not_mark_the_watch_dirty(void) {
  fake_security_lock_set_shredding(true);

  cl_assert_equal_i(S_SUCCESS, prv_insert(BlobDBIdNotifs));

  cl_assert_equal_i(0, fake_security_lock_get_dirty_marks());
}

//! The other half of the rule: anything that does land still marks, including
//! the stores the wipe spares -- their files sit in the same filesystem the
//! sweep walks.
void test_blob_db_api__an_accepted_write_still_marks_the_watch_dirty(void) {
  cl_assert_equal_i(S_SUCCESS, prv_insert(BlobDBIdPins));
  cl_assert_equal_i(1, fake_security_lock_get_dirty_marks());

  fake_security_lock_set_locked(true);
  cl_assert_equal_i(S_SUCCESS, prv_insert(BlobDBIdPrefs));
  cl_assert_equal_i(2, fake_security_lock_get_dirty_marks());
}

// Everything else the guard must not touch
////////////////////////////////////

//! An unroutable id is still an error, locked or not. Answering success there
//! would tell the phone a write it could never satisfy had succeeded.
void test_blob_db_api__an_unknown_db_is_still_out_of_range(void) {
  fake_security_lock_set_locked(true);
  cl_assert_equal_i(E_RANGE, prv_insert((BlobDBId)NumBlobDBs));
}

//! Reads and deletes are untouched. A locked watch has nothing left to read,
//! and refusing deletes would leave the phone unable to retract anything.
void test_blob_db_api__reads_and_deletes_are_not_guarded(void) {
  fake_security_lock_set_locked(true);

  uint8_t val[4];
  cl_assert_equal_i(S_SUCCESS, blob_db_read(BlobDBIdPins, s_key, sizeof(s_key), val, sizeof(val)));
  cl_assert_equal_i(S_SUCCESS, blob_db_delete(BlobDBIdPins, s_key, sizeof(s_key)));
}

// The record of what was refused
////////////////////////////////////

//! A refused write is acked as a success, so the phone records it delivered and
//! never offers it again unless its own content changes. This bitmap is the
//! only thing that remembers, and it is what the watch asks the phone to resend
//! once it is open again.
void test_blob_db_api__a_dropped_write_records_its_database(void) {
  fake_security_lock_set_locked(true);

  cl_assert_equal_i(S_SUCCESS, prv_insert(BlobDBIdPins));

  cl_assert_equal_i(SECURITY_SHRED_DB_BIT(BlobDBIdPins), fake_security_lock_get_refused_dbs());
}

//! A bitmap rather than a count, because the resend request the phone
//! understands names the databases.
void test_blob_db_api__every_dropped_database_is_recorded(void) {
  fake_security_lock_set_locked(true);

  uint32_t expected = 0;
  for (size_t i = 0; i < ARRAY_LENGTH(s_covered_dbs); ++i) {
    cl_assert_equal_i(S_SUCCESS, prv_insert(s_covered_dbs[i]));
    expected |= SECURITY_SHRED_DB_BIT(s_covered_dbs[i]);
  }

  cl_assert_equal_i(expected, fake_security_lock_get_refused_dbs());
}

//! Nothing refused means nothing asked for. A resync the phone did not need
//! costs it a full calendar re-push, so silence has to be the default.
void test_blob_db_api__an_accepted_write_records_nothing(void) {
  for (size_t i = 0; i < ARRAY_LENGTH(s_covered_dbs); ++i) {
    cl_assert_equal_i(S_SUCCESS, prv_insert(s_covered_dbs[i]));
  }

  cl_assert_equal_i(0, fake_security_lock_get_refused_dbs());
}

//! The stores a wipe spares are never refused, so they can never appear in a
//! resend request either.
void test_blob_db_api__a_spared_store_is_never_recorded(void) {
  fake_security_lock_set_locked(true);

  for (size_t i = 0; i < ARRAY_LENGTH(s_spared_dbs); ++i) {
    cl_assert_equal_i(S_SUCCESS, prv_insert(s_spared_dbs[i]));
  }

  cl_assert_equal_i(0, fake_security_lock_get_refused_dbs());
}

//! Refusals mid-wipe count too. The duress and clock-rollback wipes both run
//! unlocked, so there is no unlock coming to report them -- the wipe itself
//! carries them.
void test_blob_db_api__a_write_dropped_mid_wipe_is_recorded(void) {
  fake_security_lock_set_shredding(true);

  cl_assert_equal_i(S_SUCCESS, prv_insert(BlobDBIdNotifs));

  cl_assert_equal_i(SECURITY_SHRED_DB_BIT(BlobDBIdNotifs), fake_security_lock_get_refused_dbs());
}
