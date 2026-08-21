/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include "pbl/services/security_lock.h"
#include "pbl/services/security_lock_pin_hash.h"

#include <inttypes.h>
#include <string.h>

#include <pbl/drivers/rng.h>
#include <pbl/logging/logging.h>
#include "pbl/os/mutex.h"
#include "pbl/services/settings/settings_file.h"
#include "system/passert.h"
#include "util/units.h"

PBL_LOG_MODULE_DEFINE(service_security_lock, CONFIG_SERVICE_SECURITY_LOCK_LOG_LEVEL);

#define SETTINGS_FILE_NAME "seclock"
#define SETTINGS_FILE_SIZE KiBYTES(2)

#define RECORD_VERSION 1

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
} SecurityLockConfig;

typedef struct PACKED {
  uint16_t version;
  uint8_t state;
  uint8_t failed_attempts;
  bool shred_pending;
  time_t disconnect_deadline;
  time_t time_high_water;
} SecurityLockRuntime;

static PebbleMutex *s_mutex;
static bool s_initialized;

//! Cached so the hot path (is_locked, called from the button handler) does not
//! touch flash. Flash remains authoritative; the cache is refreshed on write.
static SecurityLockRuntime s_runtime_cache;

static void prv_runtime_defaults(SecurityLockRuntime *rt) {
  *rt = (SecurityLockRuntime){
      .version = RECORD_VERSION,
      .state = SecurityLockStateDisabled,
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
  if (rv == S_SUCCESS && cfg->version != RECORD_VERSION) {
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
  PBL_ASSERTN(!s_initialized);
  s_mutex = mutex_create();

  mutex_lock(s_mutex);
  SecurityLockRuntime rt;
  status_t rv = prv_read(RT_KEY, &rt, sizeof(rt));
  if (rv == S_SUCCESS && rt.version == RECORD_VERSION) {
    s_runtime_cache = rt;
  } else {
    // Absent or from a future/unknown version: fall back to a safe default
    // rather than guessing at the contents.
    if (rv == S_SUCCESS) {
      PBL_LOG_WRN("Discarding runtime record with unknown version %" PRIu16, rt.version);
    }
    prv_runtime_defaults(&s_runtime_cache);
  }
  s_initialized = true;
  mutex_unlock(s_mutex);

  PBL_LOG_DBG("Security lock init: state=%" PRIu8 " attempts=%" PRIu8 " shred_pending=%d",
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
  prv_runtime_defaults(&s_runtime_cache);
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
    s_runtime_cache.failed_attempts = 0;
    s_runtime_cache.disconnect_deadline = 0;
  }
  status_t rv = prv_flush_runtime();
  mutex_unlock(s_mutex);
  return rv;
}

status_t security_lock_set_pin(const char *digits, uint8_t len) {
  if (!s_initialized) {
    return E_INVALID_OPERATION;
  }
  if (digits == NULL || len < SECURITY_LOCK_PIN_MIN_LEN || len > SECURITY_LOCK_PIN_MAX_LEN) {
    return E_INVALID_ARGUMENT;
  }
  for (uint8_t i = 0; i < len; ++i) {
    if (digits[i] < '0' || digits[i] > '9') {
      return E_INVALID_ARGUMENT;
    }
  }

  SecurityLockConfig cfg = {
      .version = RECORD_VERSION,
      .pin_len = len,
  };
  for (size_t i = 0; i < sizeof(cfg.salt); i += sizeof(uint32_t)) {
    uint32_t r;
    if (!rng_rand(&r)) {
      PBL_LOG_ERR("RNG failed; refusing to set a PIN with a weak salt");
      return E_INTERNAL;
    }
    memcpy(&cfg.salt[i], &r, sizeof(r));
  }

  status_t rv = security_lock_pin_hash(digits, len, cfg.salt, cfg.pin_hash);
  if (rv != S_SUCCESS) {
    return rv;
  }

  mutex_lock(s_mutex);
  rv = prv_write(CFG_KEY, &cfg, sizeof(cfg));
  if (rv == S_SUCCESS) {
    s_runtime_cache.state = SecurityLockStateArmed;
    s_runtime_cache.failed_attempts = 0;
    rv = prv_flush_runtime();
  }
  mutex_unlock(s_mutex);

  // Don't leave the derived verifier sitting on the stack.
  memset(&cfg, 0, sizeof(cfg));
  return rv;
}

status_t security_lock_clear_pin(void) {
  if (!s_initialized) {
    return E_INVALID_OPERATION;
  }
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

bool security_lock_verify_pin(const char *digits, uint8_t len, uint8_t *attempts_remaining_out) {
  if (attempts_remaining_out) {
    *attempts_remaining_out = 0;
  }
  if (!s_initialized || digits == NULL) {
    return false;
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
    return false;
  }

  SecurityLockConfig cfg;
  bool matched = false;
  if (prv_read_config(&cfg) == S_SUCCESS && cfg.pin_len == len) {
    uint8_t attempt_hash[SECURITY_LOCK_HASH_LEN];
    if (security_lock_pin_hash(digits, len, cfg.salt, attempt_hash) == S_SUCCESS) {
      matched = security_lock_hash_equal(attempt_hash, cfg.pin_hash);
    }
    memset(attempt_hash, 0, sizeof(attempt_hash));
  }
  memset(&cfg, 0, sizeof(cfg));

  if (matched) {
    s_runtime_cache.failed_attempts = 0;
    prv_flush_runtime();
  }

  if (attempts_remaining_out) {
    uint8_t used = s_runtime_cache.failed_attempts;
    *attempts_remaining_out =
        (used >= SECURITY_LOCK_MAX_PIN_ATTEMPTS) ? 0 : SECURITY_LOCK_MAX_PIN_ATTEMPTS - used;
  }

  mutex_unlock(s_mutex);
  return matched;
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

time_t security_lock_get_disconnect_deadline(void) {
  if (!s_initialized) {
    return 0;
  }
  return s_runtime_cache.disconnect_deadline;
}

status_t security_lock_set_disconnect_deadline(time_t deadline) {
  if (!s_initialized) {
    return E_INVALID_OPERATION;
  }
  mutex_lock(s_mutex);
  s_runtime_cache.disconnect_deadline = deadline;
  status_t rv = prv_flush_runtime();
  mutex_unlock(s_mutex);
  return rv;
}

status_t security_lock_clear_disconnect_deadline(void) {
  return security_lock_set_disconnect_deadline(0);
}

bool security_lock_disconnect_deadline_expired(time_t now) {
  time_t deadline = security_lock_get_disconnect_deadline();
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
