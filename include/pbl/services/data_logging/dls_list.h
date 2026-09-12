/* SPDX-FileCopyrightText: 2024 Google LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include "dls_private.h"
#include "applib/data_logging.h"

#include <stdint.h>
#include <time.h>

//! Find a session by id and take a hold on it, under one lock.
//!
//! The hold is what makes the returned pointer safe to dereference at all. Finding and then
//! using are two operations, and between them the list mutex is not held -- so without a hold,
//! whoever frees the session next turns the caller's pointer into freed heap. The wipe and the
//! `dls clear` console command both free from a different task than these callers run on.
//!
//! A hold, deliberately, and not dls_lock_session(): that also takes the session's own mutex,
//! which serialises the holder against writers and cannot be held across the send and storage
//! calls these callers make, since those take it themselves. All that is wanted is for the
//! memory to stay put.
//!
//! @return NULL if there is no such session. Release every non-NULL return with
//!         dls_list_release_session(), on every path out.
DataLoggingSession *dls_list_find_and_ref_by_session_id(uint8_t session_id);

//! As above, for the active session matching a tag and app.
DataLoggingSession *dls_list_find_and_ref_active_session(uint32_t tag, const Uuid *app_uuid);

//! Whether a session with this id exists, for callers that only want the answer.
//!
//! No pointer, so nothing to hold and nothing to release. Prefer this wherever the session
//! itself is never touched.
bool dls_list_has_session_id(uint8_t session_id);

//! Drop a hold taken by dls_list_find_and_ref_*().
//!
//! Frees the session if it was unlinked while held and this was the last hold on it.
void dls_list_release_session(DataLoggingSession *session);

//! Unlink a session and free it.
//!
//! Safe against a holder: a session someone has dls_lock_session()'d is unlinked and marked
//! inactive here, and freed by the last dls_unlock_session() instead. Freeing it on the spot
//! would pull the memory, and the mutex, out from under whoever is inside it.
void dls_list_remove_session(DataLoggingSession *logging_session);

//! Deletes all session state in memory without changing the flash state.
//!
//! Callable from any task -- the security lock's wipe reaches it from KernelMain -- and safe
//! against a holder in the same way dls_list_remove_session() is. It does not *wait* for one,
//! though: a locked session outlives this call by however long its holder takes.
void dls_list_remove_all(void);

//! Add logging_session and assign ID
uint8_t dls_list_add_new_session(DataLoggingSession *logging_session);

//! Add logging session with an already assigned ID. Used at startup when restoring previous
//! sessions from flash.
void dls_list_insert_session(DataLoggingSession *logging_session);

//! Creates a new DataLoggingSession object that is only initialized with the parameters given. The
//! session will only be initialized with the given parameters. The .storage and .comm members must
//! be separately initialized. Also, the resulting object will need to be added to the list of
//! sessions using one of dls_list_add_new_session and dls_list_insert_session. May return NULL if
//! we've created too many sessions.
DataLoggingSession *dls_list_create_session(uint32_t tag, DataLoggingItemType type, uint16_t size,
                                            const Uuid *app_uuid, time_t timestamp,
                                            DataLoggingStatus status);

DataLoggingSession *dls_list_get_next(DataLoggingSession *cur);

void dls_list_rebuild_from_storage(void);

//! Call callback for each session we have. Pass the data param through to the callback each time.
//! If the callback returns false, stop iterating immediately and return false. Returns true
//! otherwise.
typedef bool (*DlsListCallback)(DataLoggingSession *, void *);
bool dls_list_for_each_session(DlsListCallback cb, void *data);

void dls_list_init(void);

//! Checks to see if this is an actual valid data session
//! Note that we pass in the logging_session parameter without making sure it's same. Make sure
//! this function handles passing in random pointers that don't actually point to valid sessions or
//! even valid memory.
bool dls_list_is_session_valid(DataLoggingSession *logging_session);

//! Lock a session (if active). If session was active, locks it and returns true.
//! If session is not active, returns false
bool dls_lock_session(DataLoggingSession *session);

//! Unlock a session previous locked by dls_lock_session()
void dls_unlock_session(DataLoggingSession *session, bool inactivate);

//! Return session status
DataLoggingStatus dls_get_session_status(DataLoggingSession *session);

//! Assert that the current task owns the list mutex
void dls_assert_own_list_mutex(void);

//! Lock the list mutex (recursive lock).
void dls_list_lock(void);

//! Unlock the list mutex (recursive unlock)
void dls_list_unlock(void);
