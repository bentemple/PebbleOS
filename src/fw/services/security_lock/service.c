/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include "pbl/services/security_lock.h"
#include "pbl/services/security_lock_pin_hash.h"

#include <inttypes.h>
#include <string.h>

#include <pbl/drivers/rng.h>
#include <pbl/drivers/rtc.h>
#include <pbl/logging/logging.h>
#include "kernel/event_loop.h"
#include "pbl/os/mutex.h"
#include "pbl/services/bluetooth/bluetooth_ctl.h"
#include "pbl/services/security_lock_shred.h"
#include "pbl/services/settings/settings_file.h"
#if !defined(CONFIG_RECOVERY_FW)
#include "pbl/services/bluetooth/bluetooth_persistent_storage.h"
#include "pbl/services/security_lock_endpoint.h"
#endif
#include "pbl/services/system_task.h"
#include "system/passert.h"
#include "pbl/util/size.h"
#include "util/units.h"

PBL_LOG_MODULE_DEFINE(service_security_lock, CONFIG_SERVICE_SECURITY_LOCK_LOG_LEVEL);

#define SETTINGS_FILE_NAME "seclock"
#define SETTINGS_FILE_SIZE KiBYTES(2)

//! Versioned independently, because an unrecognised record is discarded and
//! discarding the config record throws the PIN away. Sharing one number meant a
//! runtime-only field could disarm the lock on upgrade; these cannot.
#define CFG_RECORD_VERSION 4
#define RT_RECORD_VERSION 5

//! Config: written rarely (only when the PIN changes).
static const char *CFG_KEY = "cfg";
//! Runtime: written often (state changes, failed attempts, deadlines), kept
//! separate so a failed-attempt write does not rewrite the PIN verifier.
static const char *RT_KEY = "rt";

typedef struct PACKED {
  uint16_t version;
  uint8_t pin_len;
  uint8_t salt[SECURITY_LOCK_SALT_LEN];
  uint8_t pin_hash[SECURITY_LOCK_HASH_LEN];
  //! Second PIN that unlocks and silently wipes. Its own salt, so the two
  //! verifiers share nothing.
  bool has_duress_pin;
  uint8_t duress_len;
  uint8_t duress_salt[SECURITY_LOCK_SALT_LEN];
  uint8_t duress_hash[SECURITY_LOCK_HASH_LEN];
} SecurityLockConfig;

typedef struct PACKED {
  uint16_t version;
  uint8_t state;
  uint8_t failed_attempts;
  bool shred_pending;
  //! Something has been written to the storage a shred destroys since the last
  //! one ran. False means a shred has nothing new to destroy.
  bool dirty_since_shred;
  //! Both measured from the disconnect, not from each other.
  time_t lock_deadline;
  time_t shred_deadline;
  time_t time_high_water;
  uint32_t lock_delay_s;
  uint32_t shred_delay_s;
  //! Airplane mode is being held on because the watch is locked and has
  //! shredded, and what the user had it set to before we took it. Persisted
  //! because a reboot while locked is a designed-for case: a RAM-only copy
  //! would be lost and unlocking would restore the wrong state.
  bool radio_blackout;
  bool airplane_was_on;
} SecurityLockRuntime;

//! Keeps two salts derived in the same tick from coming out identical.
static uint32_t s_salt_counter;

static PebbleMutex *s_mutex;
static bool s_initialized;

//! Cached so the hot path (is_locked, called from the button handler) does not
//! touch flash. Flash remains authoritative; the cache is refreshed on write.
static SecurityLockRuntime s_runtime_cache;

//! Databases whose inbound writes were refused while the watch was shut.
//!
//! RAM only, unlike the rest of the record: a reboot while locked wipes, and
//! the wipe asks for its own resend, so nothing is lost by not persisting this
//! -- while persisting it would mean a flash write per refused write.
static uint32_t s_refused_dbs;

static void prv_runtime_defaults(SecurityLockRuntime *rt) {
  *rt = (SecurityLockRuntime){
      .version = RT_RECORD_VERSION,
      .state = SecurityLockStateDisabled,
      // Defaults are what a missing or unreadable record falls back to, so this
      // is the answer given whenever the real state is unknown. It must be
      // "dirty": a redundant shred is waste, a skipped one is a data leak.
      .dirty_since_shred = true,
      .lock_delay_s = SECURITY_LOCK_DEFAULT_LOCK_DELAY_S,
      .shred_delay_s = SECURITY_LOCK_DEFAULT_SHRED_DELAY_S,
  };
}

static status_t prv_read(const char *key, void *out, size_t len) {
  SettingsFile file;
  status_t rv = settings_file_open(&file, SETTINGS_FILE_NAME, SETTINGS_FILE_SIZE);
  if (rv != S_SUCCESS) {
    return rv;
  }
  rv = settings_file_get(&file, key, strlen(key), out, len);
  settings_file_close(&file);
  return rv;
}

static status_t prv_write(const char *key, const void *val, size_t len) {
  SettingsFile file;
  status_t rv = settings_file_open(&file, SETTINGS_FILE_NAME, SETTINGS_FILE_SIZE);
  if (rv != S_SUCCESS) {
    return rv;
  }
  rv = settings_file_set(&file, key, strlen(key), val, len);
  settings_file_close(&file);
  return rv;
}

static status_t prv_read_config(SecurityLockConfig *cfg) {
  status_t rv = prv_read(CFG_KEY, cfg, sizeof(*cfg));
  if (rv == S_SUCCESS && cfg->version != CFG_RECORD_VERSION) {
    PBL_LOG_WRN("Ignoring config record with unknown version %" PRIu16, cfg->version);
    return E_INVALID_ARGUMENT;
  }
  return rv;
}

//! Flush the cache to flash. The caller must hold the mutex.
static status_t prv_flush_runtime(void) {
  return prv_write(RT_KEY, &s_runtime_cache, sizeof(s_runtime_cache));
}

void security_lock_init(void) {
  PBL_LOG_INFO("SECBOOT init enter");
  PBL_ASSERTN(!s_initialized);
  s_mutex = mutex_create();

  mutex_lock(s_mutex);
  SecurityLockRuntime rt;
  // Bracketed by markers because this is not the read-only operation it looks
  // like: settings_file_open() opens with OP_FLAG_WRITE and creates the file
  // when it is missing, which allocates a page and can take a synchronous
  // garbage collect with it. This runs before anything else is up, so a boot
  // that dies in here dies with nothing at all on the wire.
  PBL_LOG_INFO("SECBOOT init read enter");
  status_t rv = prv_read(RT_KEY, &rt, sizeof(rt));
  PBL_LOG_INFO("SECBOOT init read leave rv=%" PRId32, (int32_t)rv);
  if (rv == S_SUCCESS && rt.version == RT_RECORD_VERSION) {
    s_runtime_cache = rt;
  } else {
    // Absent or from a future/unknown version: fall back to a safe default
    // rather than guessing at the contents.
    if (rv == S_SUCCESS) {
      PBL_LOG_WRN("Discarding runtime record with unknown version %" PRIu16, rt.version);
    }
    prv_runtime_defaults(&s_runtime_cache);

    // The config record versions separately and survives a runtime-only change,
    // so a discarded runtime record must not be read as "no PIN". Defaulting to
    // Disabled with a PIN still stored would leave the watch configured but not
    // watching -- every trigger is gated on the state -- which is an upgrade
    // that silently disarms the lock.
    //
    // A stored PIN is the whole of "on" now, so this is not a guess about what
    // the user wanted: turning the feature off discards the PIN, and a watch
    // that still has one was never turned off. The two records losing step is
    // the only way to reach here.
    //
    // Armed rather than Locked: a firmware upgrade is a deliberate act by
    // someone who already had the watch open, and locking them out of it is the
    // worse failure. Only reached on the fallback path, so the extra read costs
    // an ordinary boot nothing.
    SecurityLockConfig cfg;
    if ((prv_read_config(&cfg) == S_SUCCESS) && (cfg.pin_len != 0)) {
      PBL_LOG_INFO("Runtime record gone but a PIN remains; coming back armed");
      s_runtime_cache.state = SecurityLockStateArmed;
    }
    memset(&cfg, 0, sizeof(cfg));
  }
  s_initialized = true;
  mutex_unlock(s_mutex);

  PBL_LOG_INFO("SECBOOT init leave state=%" PRIu8 " attempts=%" PRIu8 " shred_pending=%d",
               s_runtime_cache.state, s_runtime_cache.failed_attempts,
               (int)s_runtime_cache.shred_pending);
}

void security_lock_deinit(void) {
  if (!s_initialized) {
    return;
  }
  mutex_destroy(s_mutex);
  s_mutex = NULL;
  s_initialized = false;
  s_refused_dbs = 0;
  prv_runtime_defaults(&s_runtime_cache);
}

void security_lock_note_write_refused(BlobDBId db_id) {
  if (!s_initialized) {
    return;
  }
  // Under the mutex because the bitmap is read and cleared from another task,
  // and a plain read-modify-write of it is not atomic on this hardware. Only
  // refused writes reach here, so the cost is bounded by how fast the phone can
  // talk to a watch that is answering nothing.
  mutex_lock(s_mutex);
  s_refused_dbs |= SECURITY_SHRED_DB_BIT(db_id);
  mutex_unlock(s_mutex);
}

uint32_t security_lock_take_refused_dbs(void) {
  if (!s_initialized) {
    return 0;
  }
  mutex_lock(s_mutex);
  const uint32_t dbs = s_refused_dbs;
  s_refused_dbs = 0;
  mutex_unlock(s_mutex);
  return dbs;
}

//! Ask the phone to resend anything that was refused while the watch was shut.
//!
//! Nothing was destroyed, so this is not a shred -- but a refused write was
//! acked as a success, and the phone records it delivered on that ack alone. It
//! will never offer that record again unless its own content changes, so this
//! is the only thing that undoes it.
//!
//! Silent when nothing was refused: a resync the phone did not need costs it a
//! full calendar re-push, and every unlock reaches here.
static void prv_report_refused_writes(void) {
  const uint32_t dbs = security_lock_take_refused_dbs();
  if (dbs == 0) {
    return;
  }
#if !defined(CONFIG_RECOVERY_FW)
  PBL_LOG_INFO("Asking the phone to resend databases 0x%" PRIx32 " refused while shut", dbs);

  // The same request in the form the version handshake carries. Gadgetbridge
  // stops parsing that message long before this byte, so it cannot be the only
  // mechanism, but the official app reads it.
  bt_persistent_storage_set_unfaithful(true);

  // Queued if there is no session yet -- see the ordering note in
  // security_lock_set_state().
  security_lock_endpoint_report_resync_needed(SecurityShredReasonWritesRefused, dbs);
#endif
}

SecurityLockState security_lock_get_state(void) {
  if (!s_initialized) {
    return SecurityLockStateDisabled;
  }
  return (SecurityLockState)s_runtime_cache.state;
}

bool security_lock_is_locked(void) {
  return security_lock_get_state() == SecurityLockStateLocked;
}

status_t security_lock_set_state(SecurityLockState state) {
  if (!s_initialized) {
    return E_INVALID_OPERATION;
  }
  mutex_lock(s_mutex);
  s_runtime_cache.state = (uint8_t)state;
  if (state != SecurityLockStateLocked) {
    // Leaving the locked state retires any pending disconnect deadline and
    // the attempt counter along with it.
    // Unlocking retires any countdown. It does not re-arm on reconnect --
    // only the next unexpected disconnect arms it again.
    s_runtime_cache.failed_attempts = 0;
    s_runtime_cache.lock_deadline = 0;
    s_runtime_cache.shred_deadline = 0;
  }
  status_t rv = prv_flush_runtime();
  mutex_unlock(s_mutex);

  if (state != SecurityLockStateLocked) {
    // The radio was taken down because the watch was locked, so leaving that
    // state is what gives it back -- whatever the reason for leaving it. Called
    // outside the mutex: it drops into bt_ctl, which takes a lock of its own.
    security_lock_radio_blackout_release();

    // After the release, not before: this needs a radio and the release is what
    // gives it back. The ordering alone is not enough, though. Airplane mode
    // comes back asynchronously and the session is rebuilt later still, so
    // there is reliably none by the time this runs -- the STATE_CHANGED that
    // unlocking sends a few frames later finds none either. The report queues
    // itself and goes out when the session reopens.
    prv_report_refused_writes();
  }
  return rv;
}

status_t security_lock_disable(void) {
  if (!s_initialized) {
    return E_INVALID_OPERATION;
  }
  const SecurityLockState state = security_lock_get_state();
  if (state == SecurityLockStateDisabled) {
    return S_NO_ACTION_REQUIRED;
  }
  // Turning the feature off is not a way past the lock screen. Nothing reaches
  // this from a locked watch today, but keeping the rule here is what makes
  // that true of every caller rather than of the one that exists.
  if (state == SecurityLockStateLocked) {
    PBL_LOG_WRN("Refusing to disable the security lock while locked");
    return E_INVALID_OPERATION;
  }
  PBL_LOG_INFO("Security lock disabled; discarding the PIN");
  // Which is the whole of turning it off: the config record goes, and the
  // runtime record goes back to its defaults -- state, deadlines and delays.
  return security_lock_clear_pin();
}

void security_lock_radio_blackout_engage(void) {
  if (!s_initialized) {
    return;
  }

  mutex_lock(s_mutex);
  if (!s_runtime_cache.radio_blackout) {
    // Saved once, on the way in.
    s_runtime_cache.airplane_was_on = bt_ctl_is_airplane_mode_on();
    s_runtime_cache.radio_blackout = true;
    // Recorded before the radio goes down, so a power cut in between leaves a
    // watch that knows to restore rather than one stuck in airplane mode.
    prv_flush_runtime();
    PBL_LOG_INFO("Locked and shredded; taking the radio down (airplane was %d)",
                 (int)s_runtime_cache.airplane_was_on);
  }
  mutex_unlock(s_mutex);

  // Unconditional, so this doubles as "make the radio match the record" for the
  // re-assert at boot. bt_ctl ignores a write of the value it already holds.
  bt_ctl_set_airplane_mode_async(true);
}

void security_lock_radio_blackout_release(void) {
  if (!s_initialized) {
    return;
  }

  mutex_lock(s_mutex);
  const bool held = s_runtime_cache.radio_blackout;
  const bool restore = s_runtime_cache.airplane_was_on;
  if (held) {
    s_runtime_cache.radio_blackout = false;
    s_runtime_cache.airplane_was_on = false;
    prv_flush_runtime();
  }
  mutex_unlock(s_mutex);

  if (held) {
    PBL_LOG_INFO("Unlocked; restoring airplane mode to %d", (int)restore);
    bt_ctl_set_airplane_mode_async(restore);
  }
}

bool security_lock_is_radio_blackout(void) {
  if (!s_initialized) {
    return false;
  }
  return s_runtime_cache.radio_blackout;
}

//! Fill a salt.
//!
//! On a board with real RNG hardware a failure means that hardware is broken,
//! and deriving a verifier from a predictable salt would be the wrong answer:
//! we refuse instead, and the PIN is not set.
//!
//! CONFIG_RNG_STUB boards have no RNG by design -- qemu_emery among them, where
//! rng_rand() always fails -- so refusing there would make the feature
//! impossible to use or test at all. Those fall back to clock entropy. That is
//! acceptable only because of what the salt is for: it stops one precomputed
//! table covering every watch. It is not a secret and it is not what protects
//! the PIN, which against someone reading the flash is 10^4 candidates whatever
//! the salt. The attempt counter is the real control.
//!
//! @return false if no usable salt could be produced, in which case the caller
//!         must not store anything.
static bool prv_make_salt(uint8_t salt[SECURITY_LOCK_SALT_LEN]) {
  bool have_rng = true;
  for (size_t i = 0; i < SECURITY_LOCK_SALT_LEN; i += sizeof(uint32_t)) {
    uint32_t r;
    if (!rng_rand(&r)) {
      have_rng = false;
      break;
    }
    memcpy(&salt[i], &r, sizeof(r));
  }
  if (have_rng) {
    return true;
  }

#if defined(CONFIG_RNG_STUB)
  PBL_LOG_WRN("No RNG on this board; salting from the clock instead");
  const uint32_t seeds[] = {(uint32_t)rtc_get_time(), (uint32_t)rtc_get_ticks(),
                            (uint32_t)(uintptr_t)salt, s_salt_counter++};
  for (size_t i = 0; i < SECURITY_LOCK_SALT_LEN; ++i) {
    salt[i] = (uint8_t)(seeds[i % ARRAY_LENGTH(seeds)] >> (8 * ((i / 4) % 4)));
  }
  return true;
#else
  PBL_LOG_ERR("RNG failed on a board that has one; refusing to set a PIN");
  return false;
#endif
}

//! Exactly 4 or 6 digits of 1-9. '0' is absent from the pad, so a PIN
//! containing one could never be typed.
static bool prv_pin_is_well_formed(const char *digits, uint8_t len) {
  if (digits == NULL ||
      (len != SECURITY_LOCK_PIN_MIN_LEN && len != SECURITY_LOCK_PIN_MAX_LEN)) {
    return false;
  }
  for (uint8_t i = 0; i < len; ++i) {
    if (digits[i] < '1' || digits[i] > '9') {
      return false;
    }
  }
  return true;
}

status_t security_lock_set_pin(const char *digits, uint8_t len) {
  if (!s_initialized) {
    return E_INVALID_OPERATION;
  }
  if (!prv_pin_is_well_formed(digits, len)) {
    return E_INVALID_ARGUMENT;
  }

  mutex_lock(s_mutex);

  // Preserve any duress PIN across a change of the real one: the two are set
  // independently and forgetting the duress PIN here would silently disarm it.
  SecurityLockConfig cfg;
  if (prv_read_config(&cfg) != S_SUCCESS) {
    memset(&cfg, 0, sizeof(cfg));
  }
  cfg.version = CFG_RECORD_VERSION;
  cfg.pin_len = len;

  status_t rv;
  if (!prv_make_salt(cfg.salt)) {
    rv = E_INTERNAL;
    goto unlock;
  }
  rv = security_lock_pin_hash(digits, len, cfg.salt, cfg.pin_hash);
  if (rv != S_SUCCESS) {
    goto unlock;
  }

  // A duress PIN that now matches the real one would be unreachable.
  if (cfg.has_duress_pin && (cfg.duress_len == len) &&
      security_lock_hash_equal(cfg.duress_hash, cfg.pin_hash)) {
    cfg.has_duress_pin = false;
  }

  rv = prv_write(CFG_KEY, &cfg, sizeof(cfg));
  if (rv == S_SUCCESS) {
    s_runtime_cache.state = SecurityLockStateArmed;
    s_runtime_cache.failed_attempts = 0;
    rv = prv_flush_runtime();
  }

unlock:
  mutex_unlock(s_mutex);
  memset(&cfg, 0, sizeof(cfg));
  return rv;
}

status_t security_lock_set_duress_pin(const char *digits, uint8_t len) {
  if (!s_initialized) {
    return E_INVALID_OPERATION;
  }
  if (!prv_pin_is_well_formed(digits, len)) {
    return E_INVALID_ARGUMENT;
  }

  mutex_lock(s_mutex);

  SecurityLockConfig cfg;
  status_t rv = prv_read_config(&cfg);
  if (rv != S_SUCCESS) {
    // No real PIN means nothing to be under duress about.
    mutex_unlock(s_mutex);
    return E_INVALID_OPERATION;
  }

  // Identical PINs would make the duress one unreachable -- the real check runs
  // first and would always win.
  uint8_t candidate[SECURITY_LOCK_HASH_LEN];
  if ((cfg.pin_len == len) &&
      security_lock_pin_hash(digits, len, cfg.salt, candidate) == S_SUCCESS &&
      security_lock_hash_equal(candidate, cfg.pin_hash)) {
    rv = E_INVALID_ARGUMENT;
    goto unlock;
  }

  cfg.duress_len = len;
  if (!prv_make_salt(cfg.duress_salt)) {
    rv = E_INTERNAL;
    goto unlock;
  }
  rv = security_lock_pin_hash(digits, len, cfg.duress_salt, cfg.duress_hash);
  if (rv != S_SUCCESS) {
    goto unlock;
  }
  cfg.has_duress_pin = true;
  rv = prv_write(CFG_KEY, &cfg, sizeof(cfg));

unlock:
  mutex_unlock(s_mutex);
  memset(candidate, 0, sizeof(candidate));
  memset(&cfg, 0, sizeof(cfg));
  return rv;
}

status_t security_lock_clear_duress_pin(void) {
  if (!s_initialized) {
    return E_INVALID_OPERATION;
  }
  mutex_lock(s_mutex);
  SecurityLockConfig cfg;
  status_t rv = prv_read_config(&cfg);
  if (rv == S_SUCCESS) {
    cfg.has_duress_pin = false;
    memset(cfg.duress_hash, 0, sizeof(cfg.duress_hash));
    memset(cfg.duress_salt, 0, sizeof(cfg.duress_salt));
    cfg.duress_len = 0;
    rv = prv_write(CFG_KEY, &cfg, sizeof(cfg));
  }
  mutex_unlock(s_mutex);
  memset(&cfg, 0, sizeof(cfg));
  return rv;
}

bool security_lock_has_duress_pin(void) {
  if (!s_initialized) {
    return false;
  }
  mutex_lock(s_mutex);
  SecurityLockConfig cfg;
  const bool has = (prv_read_config(&cfg) == S_SUCCESS) && cfg.has_duress_pin;
  memset(&cfg, 0, sizeof(cfg));
  mutex_unlock(s_mutex);
  return has;
}

status_t security_lock_clear_pin(void) {
  if (!s_initialized) {
    return E_INVALID_OPERATION;
  }
  // Before the runtime record goes: that record is the only thing that knows
  // the radio was taken down and what to put back.
  security_lock_radio_blackout_release();

  // Turning the feature off is another way out of the locked state, and it does
  // not go through security_lock_set_state().
  prv_report_refused_writes();

  // Deleting the config record takes the duress PIN with it, which is what we
  // want: a watch with no real PIN has nothing to be under duress about.
  mutex_lock(s_mutex);
  SettingsFile file;
  status_t rv = settings_file_open(&file, SETTINGS_FILE_NAME, SETTINGS_FILE_SIZE);
  if (rv == S_SUCCESS) {
    rv = settings_file_delete(&file, CFG_KEY, strlen(CFG_KEY));
    settings_file_close(&file);
  }
  if (rv == S_SUCCESS) {
    prv_runtime_defaults(&s_runtime_cache);
    rv = prv_flush_runtime();
  }
  mutex_unlock(s_mutex);
  return rv;
}

uint8_t security_lock_get_pin_len(void) {
  if (!s_initialized) {
    return 0;
  }
  mutex_lock(s_mutex);
  SecurityLockConfig cfg;
  uint8_t len = (prv_read_config(&cfg) == S_SUCCESS) ? cfg.pin_len : 0;
  memset(&cfg, 0, sizeof(cfg));
  mutex_unlock(s_mutex);
  return len;
}

static void prv_duress_shred_callback(void *unused) {
  security_lock_shred(SecurityShredReasonDuressPin);
}

//! The comparison itself, which triggers nothing. What a duress match is worth
//! doing about is the caller's decision, and the two public entry points below
//! make it differently.
static SecurityPinVerdict prv_verify_pin(const char *digits, uint8_t len,
                                         uint8_t *attempts_remaining_out) {
  if (attempts_remaining_out) {
    *attempts_remaining_out = 0;
  }
  if (!s_initialized || digits == NULL) {
    return SecurityPinVerdictWrong;
  }

  mutex_lock(s_mutex);

  // Burn the attempt before doing any comparison. If power is pulled between
  // here and the check below, the attempt is still counted -- otherwise an
  // attacker could brute force the PIN by cutting power on each wrong guess.
  if (s_runtime_cache.failed_attempts < UINT8_MAX) {
    s_runtime_cache.failed_attempts++;
  }
  status_t flush_rv = prv_flush_runtime();
  if (flush_rv != S_SUCCESS) {
    // Could not record the attempt, so we cannot bound guesses. Refuse rather
    // than allow unlimited free tries.
    PBL_LOG_ERR("Failed to persist PIN attempt (%" PRId32 "); rejecting", (int32_t)flush_rv);
    mutex_unlock(s_mutex);
    return SecurityPinVerdictWrong;
  }

  SecurityLockConfig cfg;
  SecurityPinVerdict verdict = SecurityPinVerdictWrong;
  if (prv_read_config(&cfg) == S_SUCCESS) {
    uint8_t attempt_hash[SECURITY_LOCK_HASH_LEN];
    if ((cfg.pin_len == len) &&
        security_lock_pin_hash(digits, len, cfg.salt, attempt_hash) == S_SUCCESS &&
        security_lock_hash_equal(attempt_hash, cfg.pin_hash)) {
      verdict = SecurityPinVerdictReal;
    }
    if ((verdict == SecurityPinVerdictWrong) && cfg.has_duress_pin && (cfg.duress_len == len) &&
        security_lock_pin_hash(digits, len, cfg.duress_salt, attempt_hash) == S_SUCCESS &&
        security_lock_hash_equal(attempt_hash, cfg.duress_hash)) {
      verdict = SecurityPinVerdictDuress;
    }
    memset(attempt_hash, 0, sizeof(attempt_hash));
  }
  memset(&cfg, 0, sizeof(cfg));

  // A match is a match whichever PIN it was: a duress entry is a success, not a
  // guess that failed.
  if (verdict != SecurityPinVerdictWrong) {
    s_runtime_cache.failed_attempts = 0;
    prv_flush_runtime();
  }

  if (attempts_remaining_out) {
    uint8_t used = s_runtime_cache.failed_attempts;
    *attempts_remaining_out =
        (used >= SECURITY_LOCK_MAX_PIN_ATTEMPTS) ? 0 : SECURITY_LOCK_MAX_PIN_ATTEMPTS - used;
  }

  mutex_unlock(s_mutex);
  return verdict;
}

bool security_lock_verify_pin(const char *digits, uint8_t len, uint8_t *attempts_remaining_out) {
  const SecurityPinVerdict verdict = prv_verify_pin(digits, len, attempts_remaining_out);

  if (verdict == SecurityPinVerdictDuress) {
    // Deferred so the unlock completes first and the watch looks ordinary,
    // but onto KernelMain: the wipe closes and reopens databases and
    // deadlocks if driven from KernelBG.
    //
    // Queued here rather than inside the comparison so that the variant below
    // can decline it: a caller whose own next step would stop the wipe from
    // running has to be the one that orders the two.
    launcher_task_add_callback(prv_duress_shred_callback, NULL);
  }

  // Reported as an ordinary success. Nothing above this layer is told the
  // difference, so nothing can leak it into the UI.
  return verdict != SecurityPinVerdictWrong;
}

SecurityPinVerdict security_lock_verify_pin_verdict(const char *digits, uint8_t len) {
  return prv_verify_pin(digits, len, NULL);
}

uint8_t security_lock_get_failed_attempts(void) {
  if (!s_initialized) {
    return 0;
  }
  return s_runtime_cache.failed_attempts;
}

status_t security_lock_reset_failed_attempts(void) {
  if (!s_initialized) {
    return E_INVALID_OPERATION;
  }
  mutex_lock(s_mutex);
  s_runtime_cache.failed_attempts = 0;
  status_t rv = prv_flush_runtime();
  mutex_unlock(s_mutex);
  return rv;
}

bool security_lock_attempts_exhausted(void) {
  return security_lock_get_failed_attempts() >= SECURITY_LOCK_MAX_PIN_ATTEMPTS;
}

bool security_lock_is_shred_pending(void) {
  if (!s_initialized) {
    return false;
  }
  return s_runtime_cache.shred_pending;
}

status_t security_lock_set_shred_pending(bool pending) {
  if (!s_initialized) {
    return E_INVALID_OPERATION;
  }
  mutex_lock(s_mutex);
  s_runtime_cache.shred_pending = pending;
  status_t rv = prv_flush_runtime();
  mutex_unlock(s_mutex);
  return rv;
}

bool security_lock_is_dirty_since_shred(void) {
  if (!s_initialized) {
    // The record has not been read yet, so nothing is known about it.
    return true;
  }
  return s_runtime_cache.dirty_since_shred;
}

void security_lock_mark_dirty_since_shred(void) {
  if (!s_initialized) {
    return;
  }
  // Unlocked fast path. This runs on every stored notification and every
  // inbound BlobDB write, and the flag stays set until a shred clears it, so
  // all but the first of those must cost nothing and touch no flash.
  if (s_runtime_cache.dirty_since_shred) {
    return;
  }

  mutex_lock(s_mutex);
  // Re-read under the lock: two writers racing the check above would otherwise
  // both flush.
  if (!s_runtime_cache.dirty_since_shred) {
    s_runtime_cache.dirty_since_shred = true;
    status_t rv = prv_flush_runtime();
    if (rv != S_SUCCESS) {
      // RAM still reads dirty, so this boot shreds; a reboot before the next
      // successful write would not. Loud, because the consequence is a wipe
      // that decides it has nothing to do.
      PBL_LOG_ERR("Failed to persist the dirty flag: %" PRId32, (int32_t)rv);
    }
  }
  mutex_unlock(s_mutex);
}

status_t security_lock_clear_dirty_since_shred(void) {
  if (!s_initialized) {
    return E_INVALID_OPERATION;
  }
  mutex_lock(s_mutex);
  s_runtime_cache.dirty_since_shred = false;
  status_t rv = prv_flush_runtime();
  if (rv != S_SUCCESS) {
    // Flash still says dirty. Match it rather than leave RAM claiming clean,
    // which would talk the next shred out of running.
    s_runtime_cache.dirty_since_shred = true;
  }
  mutex_unlock(s_mutex);
  return rv;
}

uint32_t security_lock_get_lock_delay_s(void) {
  if (!s_initialized) {
    return SECURITY_LOCK_DEFAULT_LOCK_DELAY_S;
  }
  return s_runtime_cache.lock_delay_s;
}

uint32_t security_lock_get_shred_delay_s(void) {
  if (!s_initialized) {
    return SECURITY_LOCK_DEFAULT_SHRED_DELAY_S;
  }
  return s_runtime_cache.shred_delay_s;
}

status_t security_lock_set_delays(uint32_t lock_delay_s, uint32_t shred_delay_s) {
  if (!s_initialized) {
    return E_INVALID_OPERATION;
  }
  // Shredding before locking would destroy the data without ever showing the
  // user a chance to stop it, so the order is enforced rather than trusted.
  // Never is exempt: it schedules nothing, so there is no order to get wrong.
  if ((shred_delay_s != SECURITY_LOCK_SHRED_DELAY_NEVER) && (shred_delay_s < lock_delay_s)) {
    return E_INVALID_ARGUMENT;
  }
  mutex_lock(s_mutex);
  s_runtime_cache.lock_delay_s = lock_delay_s;
  s_runtime_cache.shred_delay_s = shred_delay_s;
  status_t rv = prv_flush_runtime();
  mutex_unlock(s_mutex);
  return rv;
}

time_t security_lock_get_lock_deadline(void) {
  if (!s_initialized) {
    return 0;
  }
  return s_runtime_cache.lock_deadline;
}

time_t security_lock_get_shred_deadline(void) {
  if (!s_initialized) {
    return 0;
  }
  return s_runtime_cache.shred_deadline;
}

status_t security_lock_set_deadlines(time_t lock_deadline, time_t shred_deadline) {
  if (!s_initialized) {
    return E_INVALID_OPERATION;
  }
  mutex_lock(s_mutex);
  s_runtime_cache.lock_deadline = lock_deadline;
  s_runtime_cache.shred_deadline = shred_deadline;
  status_t rv = prv_flush_runtime();
  mutex_unlock(s_mutex);
  return rv;
}

status_t security_lock_clear_deadlines(void) {
  return security_lock_set_deadlines(0, 0);
}

bool security_lock_lock_deadline_expired(time_t now) {
  const time_t deadline = security_lock_get_lock_deadline();
  return (deadline != 0) && (now >= deadline);
}

bool security_lock_shred_deadline_expired(time_t now) {
  const time_t deadline = security_lock_get_shred_deadline();
  return (deadline != 0) && (now >= deadline);
}

bool security_lock_note_time(time_t now) {
  if (!s_initialized) {
    return false;
  }

  mutex_lock(s_mutex);
  bool rolled_back = false;
  if (s_runtime_cache.time_high_water != 0 &&
      now < s_runtime_cache.time_high_water - SECURITY_LOCK_TIME_ROLLBACK_SLACK_S) {
    PBL_LOG_WRN("Clock rolled back: now=%" PRId32 " high_water=%" PRId32, (int32_t)now,
                (int32_t)s_runtime_cache.time_high_water);
    rolled_back = true;
  }
  if (now > s_runtime_cache.time_high_water) {
    s_runtime_cache.time_high_water = now;
    prv_flush_runtime();
  }
  mutex_unlock(s_mutex);
  return rolled_back;
}

time_t security_lock_get_time_high_water(void) {
  if (!s_initialized) {
    return 0;
  }
  return s_runtime_cache.time_high_water;
}
