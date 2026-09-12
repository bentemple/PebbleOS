/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include "pbl/services/security_lock_pin_hash.h"

#include <string.h>

#include "sha256.h"

//! Iterated to make casual recovery of the PIN string cost something. At
//! roughly 35us per SHA-256 block on a 64MHz M4 this is a few hundred
//! milliseconds, which is tolerable on an unlock and irrelevant to an attacker
//! running offline against 10^4 candidates.
#define HASH_ITERATIONS 10000

status_t security_lock_pin_hash(const char *digits, uint8_t len,
                                const uint8_t salt[SECURITY_LOCK_SALT_LEN],
                                uint8_t hash_out[SECURITY_LOCK_HASH_LEN]) {
  if (digits == NULL || salt == NULL || hash_out == NULL) {
    return E_INVALID_ARGUMENT;
  }
  if (!security_lock_pin_len_is_valid(len)) {
    return E_INVALID_ARGUMENT;
  }

  // First round covers salt || digits; subsequent rounds re-hash salt || prev
  // so the salt keeps contributing and rainbow tables stay useless.
  uint8_t buf[SECURITY_LOCK_SALT_LEN + SECURITY_LOCK_HASH_LEN];
  memcpy(buf, salt, SECURITY_LOCK_SALT_LEN);
  memcpy(buf + SECURITY_LOCK_SALT_LEN, digits, len);

  sha256(buf, SECURITY_LOCK_SALT_LEN + len, hash_out);

  for (uint32_t i = 1; i < HASH_ITERATIONS; ++i) {
    memcpy(buf + SECURITY_LOCK_SALT_LEN, hash_out, SECURITY_LOCK_HASH_LEN);
    sha256(buf, sizeof(buf), hash_out);
  }

  // Leaves salt || final digest; the first iteration already overwrote the
  // digits. Scrubbed anyway so no key material outlives the frame.
  memset(buf, 0, sizeof(buf));
  return S_SUCCESS;
}

// Compares every byte before returning. Do not replace with memcmp(): the
// early exit leaks how far the digests matched, and no test can catch the
// swap, since both forms return the same value for every input.
bool security_lock_hash_equal(const uint8_t a[SECURITY_LOCK_HASH_LEN],
                              const uint8_t b[SECURITY_LOCK_HASH_LEN]) {
  uint8_t diff = 0;
  for (size_t i = 0; i < SECURITY_LOCK_HASH_LEN; ++i) {
    diff |= (uint8_t)(a[i] ^ b[i]);
  }
  return diff == 0;
}
