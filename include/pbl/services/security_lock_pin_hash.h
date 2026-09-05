/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdint.h>

#include "pbl/services/security_lock.h"
#include "system/status_codes.h"

//! Derive the stored verifier for a PIN.
//!
//! Deliberately a separate translation unit so unit tests can substitute a
//! cheap fake instead of linking mbedtls.
//!
//! This is not a meaningful security boundary and must not be described as
//! one: a 4-digit PIN has 10^4 candidates, so anyone who can read the flash
//! recovers it regardless of the KDF. Its only job is to keep the PIN string
//! itself out of cleartext storage, since users reuse PINs elsewhere. The
//! failed-attempt counter is what actually protects the data.
//!
//! @param digits ASCII '0'-'9', not NUL-terminated.
//! @param len number of digits, SECURITY_LOCK_PIN_MIN_LEN..MAX_LEN.
//! @param salt SECURITY_LOCK_SALT_LEN bytes.
//! @param[out] hash_out SECURITY_LOCK_HASH_LEN bytes.
status_t security_lock_pin_hash(const char *digits, uint8_t len,
                                const uint8_t salt[SECURITY_LOCK_SALT_LEN],
                                uint8_t hash_out[SECURITY_LOCK_HASH_LEN]);

//! Constant-time comparison of two stored verifiers.
bool security_lock_hash_equal(const uint8_t a[SECURITY_LOCK_HASH_LEN],
                              const uint8_t b[SECURITY_LOCK_HASH_LEN]);
