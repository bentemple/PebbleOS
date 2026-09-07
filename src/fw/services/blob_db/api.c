/* SPDX-FileCopyrightText: 2024 Google LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include "pbl/services/blob_db/api.h"

#include <stddef.h>
#include <stdbool.h>

#include "pbl/services/blob_db/app_db.h"
#include "pbl/services/blob_db/app_glance_db.h"
#include "pbl/services/blob_db/contacts_db.h"
#include "pbl/services/blob_db/health_db.h"
#include "pbl/services/blob_db/ios_notif_pref_db.h"
#include "pbl/services/blob_db/notif_db.h"
#include "pbl/services/blob_db/pin_db.h"
#include "pbl/services/blob_db/prefs_db.h"
#include "pbl/services/blob_db/reminder_db.h"
#include "pbl/services/blob_db/settings_blob_db.h"
#include "pbl/services/blob_db/watch_app_prefs_db.h"
#include "pbl/services/blob_db/weather_db.h"

#include "kernel/events.h"
#include "kernel/pbl_malloc.h"
#include "pbl/services/security_lock.h"
#include "pbl/services/security_lock_shred.h"
#include <pbl/logging/logging.h>

#include <inttypes.h>

PBL_LOG_MODULE_DEFINE(service_blob_db, CONFIG_SERVICE_BLOB_DB_LOG_LEVEL);

typedef struct {
  BlobDBInitImpl init;
  BlobDBInsertImpl insert;
  BlobDBGetLenImpl get_len;
  BlobDBReadImpl read;
  BlobDBDeleteImpl del;
  BlobDBFlushImpl flush;
  BlobDBIsDirtyImpl is_dirty;
  BlobDBGetDirtyListImpl get_dirty_list;
  BlobDBMarkSyncedImpl mark_synced;
  BlobDBCompactImpl compact;
  const char *name;
  bool disabled;
} BlobDB;

static const BlobDB s_blob_dbs[NumBlobDBs] = {
  [BlobDBIdPins] =
      {
        .init = pin_db_init,
        .insert = pin_db_insert,
        .get_len = pin_db_get_len,
        .read = pin_db_read,
        .del = pin_db_delete,
        .flush = pin_db_flush,
        .is_dirty = pin_db_is_dirty,
        .get_dirty_list = pin_db_get_dirty_list,
        .mark_synced = pin_db_mark_synced,
        .compact = pin_db_compact,
        .name = "pin_db",
      },
  [BlobDBIdApps] =
      {
        .init = app_db_init,
        .insert = app_db_insert,
        .get_len = app_db_get_len,
        .read = app_db_read,
        .del = app_db_delete,
        .flush = app_db_flush,
        .compact = app_db_compact,
        .name = "app_db",
      },
  [BlobDBIdReminders] =
      {
        .init = reminder_db_init,
        .insert = reminder_db_insert,
        .get_len = reminder_db_get_len,
        .read = reminder_db_read,
        .del = reminder_db_delete,
        .flush = reminder_db_flush,
        .is_dirty = reminder_db_is_dirty,
        .get_dirty_list = reminder_db_get_dirty_list,
        .mark_synced = reminder_db_mark_synced,
        .compact = reminder_db_compact,
        .name = "reminder_db",
      },
  [BlobDBIdNotifs] =
      {
        .init = notif_db_init,
        .insert = notif_db_insert,
        .get_len = notif_db_get_len,
        .read = notif_db_read,
        .del = notif_db_delete,
        .flush = notif_db_flush,
        .name = "notif_db",
      },
  [BlobDBIdWeather] =
      {
        .init = weather_db_init,
        .insert = weather_db_insert,
        .get_len = weather_db_get_len,
        .read = weather_db_read,
        .del = weather_db_delete,
        .flush = weather_db_flush,
        .compact = weather_db_compact,
        .name = "weather_db",
      },
  [BlobDBIdiOSNotifPref] =
      {
        .init = ios_notif_pref_db_init,
        .insert = ios_notif_pref_db_insert,
        .get_len = ios_notif_pref_db_get_len,
        .read = ios_notif_pref_db_read,
        .del = ios_notif_pref_db_delete,
        .flush = ios_notif_pref_db_flush,
        .is_dirty = ios_notif_pref_db_is_dirty,
        .get_dirty_list = ios_notif_pref_db_get_dirty_list,
        .mark_synced = ios_notif_pref_db_mark_synced,
        .compact = ios_notif_pref_db_compact,
        .name = "ios_notif_pref_db",
      },
  [BlobDBIdPrefs] =
      {
        .init = prefs_db_init,
        .insert = prefs_db_insert,
        .get_len = prefs_db_get_len,
        .read = prefs_db_read,
        .del = prefs_db_delete,
        .flush = prefs_db_flush,
        .name = "prefs_db",
      },
  [BlobDBIdContacts] =
      {
        .init = contacts_db_init,
        .insert = contacts_db_insert,
        .get_len = contacts_db_get_len,
        .read = contacts_db_read,
        .del = contacts_db_delete,
        .flush = contacts_db_flush,
        .compact = contacts_db_compact,
        .name = "contacts_db",
      },
  [BlobDBIdWatchAppPrefs] =
      {
        .init = watch_app_prefs_db_init,
        .insert = watch_app_prefs_db_insert,
        .get_len = watch_app_prefs_db_get_len,
        .read = watch_app_prefs_db_read,
        .del = watch_app_prefs_db_delete,
        .flush = watch_app_prefs_db_flush,
        .compact = watch_app_prefs_db_compact,
        .name = "watch_app_prefs_db",
      },
  [BlobDBIdHealth] =
      {
        .init = health_db_init,
        .insert = health_db_insert,
        .get_len = health_db_get_len,
        .read = health_db_read,
        .del = health_db_delete,
        .flush = health_db_flush,
        .compact = health_db_compact,
        .name = "health_db",
      },
  [BlobDBIdAppGlance] =
      {
        .init = app_glance_db_init,
        .insert = app_glance_db_insert,
        .get_len = app_glance_db_get_len,
        .read = app_glance_db_read,
        .del = app_glance_db_delete,
        .flush = app_glance_db_flush,
        .compact = app_glance_db_compact,
        .name = "app_glance_db",
      },
  [BlobDBIdSettings] = {
    .init = settings_blob_db_init,
    .insert = settings_blob_db_insert,
    .get_len = settings_blob_db_get_len,
    .read = settings_blob_db_read,
    .del = settings_blob_db_delete,
    .flush = settings_blob_db_flush,
    .is_dirty = settings_blob_db_is_dirty,
    .get_dirty_list = settings_blob_db_get_dirty_list,
    .mark_synced = settings_blob_db_mark_synced,
    .name = "settings_blob_db",
  },
};

static bool prv_db_valid(BlobDBId db_id) {
  return (db_id < NumBlobDBs) && (!s_blob_dbs[db_id].disabled);
}

#ifdef CONFIG_SERVICE_SECURITY_LOCK
//! Writes dropped since the last one was accepted. Bookkeeping for the log
//! below, not a statistic anybody reads.
static uint32_t s_writes_dropped;

//! True when an inbound write must not reach flash.
//!
//! A locked or shredding watch that accepted these would write back in
//! cleartext exactly what the wipe just erased. Scoped to the databases the
//! wipe destroys, asked of the wipe's own list: the ones it spares are not
//! sensitive in this sense and blocking them would break things for no gain.
//!
//! The in-flight check is not redundant with the lock state -- the duress and
//! clock-rollback wipes both run unlocked.
//!
//! The notification store is the one the user has a say over: while the watch
//! is merely locked it follows the block-notifications-when-locked setting, so
//! turning that off keeps messages for whoever unlocks. Everything else stays
//! refused for as long as the watch is shut, and nothing is exempt mid-wipe.
//!
//! Also owns the log bookkeeping: one line when the drops start and one when
//! they stop, never one per write.
//!
//! Records which database was refused as it goes. The success we report is what
//! makes that necessary: the phone marks the record delivered and will not
//! offer it again, so the watch has to ask for it back once it is open.
static bool prv_should_drop_write(BlobDBId db_id) {
  if (!security_lock_is_locked() && !security_lock_is_shredding()) {
    if (s_writes_dropped != 0) {
      PBL_LOG_INFO("Accepting blob db writes again, %" PRIu32 " dropped", s_writes_dropped);
      s_writes_dropped = 0;
    }
    return false;
  }

  if (!security_lock_shred_covers_db(db_id)) {
    return false;
  }

  if ((db_id == BlobDBIdNotifs) && !security_lock_should_drop_notifications()) {
    return false;
  }

  security_lock_note_write_refused(db_id);

  if (s_writes_dropped++ == 0) {
    PBL_LOG_INFO("Locked or shredding, dropping writes to blob db %d", (int)db_id);
  }
  return true;
}
#endif

void blob_db_event_put(BlobDBEventType type, BlobDBId db_id, const uint8_t *key, int key_len) {
  // copy key for event
  uint8_t *key_bytes = NULL;
  if (key_len > 0) {
    key_bytes = kernel_malloc(key_len);
    memcpy(key_bytes, key, key_len);
  }

  PebbleEvent e = {
    .type = PEBBLE_BLOBDB_EVENT,
    .blob_db = {
      .db_id = db_id,
      .type = type,
      .key = key_bytes,
      .key_len = (uint8_t)key_len,
    }
  };
  event_put(&e);
}

void blob_db_init_dbs(void) {
  const BlobDB *db = s_blob_dbs;
  for (int i = 0; i < NumBlobDBs; ++i, ++db) {
    if (db->init) {
      db->init();
    }
  }
}

void blob_db_compact_growable_dbs(void) {
  PBL_LOG_INFO("blob_db_compact_growable_dbs: start");
  const BlobDB *db = s_blob_dbs;
  for (int i = 0; i < NumBlobDBs; ++i, ++db) {
    if (!db->compact) {
      continue;
    }
    const status_t rv = db->compact();
    PBL_LOG_INFO("blob_db_compact_growable_dbs: %s -> %" PRIi32, db->name ? db->name : "?", rv);
  }
  PBL_LOG_INFO("blob_db_compact_growable_dbs: done");
}

void blob_db_get_dirty_dbs(uint8_t *ids, uint8_t *num_ids) {
  const BlobDB *db = s_blob_dbs;
  *num_ids = 0;
  for (uint8_t i = 0; i < NumBlobDBs; ++i, ++db) {
    bool is_dirty = false;
    if (db->is_dirty && (db->is_dirty(&is_dirty) == S_SUCCESS) && is_dirty) {
      ids[*num_ids] = i;
      *num_ids += 1;
    }
  }
}

status_t blob_db_insert(BlobDBId db_id, const uint8_t *key, int key_len, const uint8_t *val,
                        int val_len) {
  if (!prv_db_valid(db_id)) {
    return E_RANGE;
  }

#ifdef CONFIG_SERVICE_SECURITY_LOCK
  // Ahead of the dirty marking below, deliberately. Nothing is stored, so
  // marking would have the next wipe do real work for no reason -- and the flag
  // is persisted, so it would survive a reboot.
  //
  // Success so the phone gets its usual ack, does not retry, and learns nothing
  // about the watch's state. That is what notif_db_insert() has always
  // reported, and Gadgetbridge ignores blob db acks anyway.
  if (prv_should_drop_write(db_id)) {
    return S_SUCCESS;
  }
#endif

  const BlobDB *db = &s_blob_dbs[db_id];
  if (db->insert) {
    // The single dispatch point for every write into a blob db, which is what
    // makes this the one place a security shred can learn that its targets may
    // hold something new. Marked before dispatching and regardless of the
    // result: a write that fails part way through has still landed on flash.
    security_lock_mark_dirty_since_shred();

    status_t rv = db->insert(key, key_len, val, val_len);
    if (rv == S_SUCCESS) {
      blob_db_event_put(BlobDBEventTypeInsert, db_id, key, key_len);
    }

    return rv;
  }

  return E_INVALID_OPERATION;
}

int blob_db_get_len(BlobDBId db_id, const uint8_t *key, int key_len) {
  if (!prv_db_valid(db_id)) {
    return E_RANGE;
  }

  const BlobDB *db = &s_blob_dbs[db_id];
  if (db->get_len) {
    return db->get_len(key, key_len);
  }

  return E_INVALID_OPERATION;
}

status_t blob_db_read(BlobDBId db_id, const uint8_t *key, int key_len, uint8_t *val_out,
                      int val_len) {
  if (!prv_db_valid(db_id)) {
    return E_RANGE;
  }

  const BlobDB *db = &s_blob_dbs[db_id];
  if (db->read) {
    return db->read(key, key_len, val_out, val_len);
  }

  return E_INVALID_OPERATION;
}

status_t blob_db_delete(BlobDBId db_id, const uint8_t *key, int key_len) {
  if (!prv_db_valid(db_id)) {
    return E_RANGE;
  }

  const BlobDB *db = &s_blob_dbs[db_id];
  if (db->del) {
    status_t rv = db->del(key, key_len);
    if (rv == S_SUCCESS) {
      blob_db_event_put(BlobDBEventTypeDelete, db_id, key, key_len);
    }
    return rv;
  }

  return E_INVALID_OPERATION;
}

status_t blob_db_flush(BlobDBId db_id) {
  if (!prv_db_valid(db_id)) {
    return E_RANGE;
  }

  const BlobDB *db = &s_blob_dbs[db_id];
  if (db->flush) {
    status_t rv = db->flush();
    if (rv == S_SUCCESS) {
      PBL_LOG_INFO("Flushing BlobDB with Id %d", db_id);
      blob_db_event_put(BlobDBEventTypeFlush, db_id, NULL, 0);
    }
    return rv;
  }

  return E_INVALID_OPERATION;
}

BlobDBDirtyItem *blob_db_get_dirty_list(BlobDBId db_id) {
  if (!prv_db_valid(db_id)) {
    return NULL;
  }

  const BlobDB *db = &s_blob_dbs[db_id];
  if (db->get_dirty_list) {
    return db->get_dirty_list();
  }

  return NULL;
}

status_t blob_db_mark_synced(BlobDBId db_id, uint8_t *key, int key_len) {
  if (!prv_db_valid(db_id)) {
    return E_RANGE;
  }

  const BlobDB *db = &s_blob_dbs[db_id];
  if (db->mark_synced) {
    status_t rv = db->mark_synced(key, key_len);
    // TODO event?
    return rv;
  }

  return E_INVALID_OPERATION;
}
