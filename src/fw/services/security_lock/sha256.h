/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stddef.h>
#include <stdint.h>

//! FIPS 180-4 SHA-256.
//!
//! Local to the security lock rather than taken from mbedtls, because mbedtls
//! is only built when CONFIG_BT_FW_NIMBLE is set (see third_party/wscript_build)
//! and boards on the QEMU or other Bluetooth stacks do not get it. A lock that
//! silently fails to build on some boards is worse than a few KB of duplicated
//! hash code.

#define SHA256_DIGEST_LEN 32
#define SHA256_BLOCK_LEN 64

typedef struct {
  uint32_t state[8];
  uint64_t bit_len;
  uint8_t block[SHA256_BLOCK_LEN];
  size_t block_used;
} Sha256Context;

void sha256_init(Sha256Context *ctx);
void sha256_update(Sha256Context *ctx, const void *data, size_t len);
void sha256_final(Sha256Context *ctx, uint8_t out[SHA256_DIGEST_LEN]);

//! One-shot convenience wrapper.
void sha256(const void *data, size_t len, uint8_t out[SHA256_DIGEST_LEN]);
