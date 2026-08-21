/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

//! Known-answer tests for the local SHA-256 used by the PIN verifier.
//!
//! This implementation is vendored rather than taken from mbedtls (which is
//! not built on every board), so it has to carry its own proof of
//! correctness. Vectors are from FIPS 180-4 and the NIST CAVP examples.

#include "clar.h"

#include <string.h>

#include "services/security_lock/sha256.h"

#include "stubs_logging.h"
#include "stubs_passert.h"

static void prv_assert_digest(const void *data, size_t len, const char *expect_hex) {
  uint8_t digest[SHA256_DIGEST_LEN];
  sha256(data, len, digest);

  char hex[SHA256_DIGEST_LEN * 2 + 1];
  for (int i = 0; i < SHA256_DIGEST_LEN; ++i) {
    snprintf(&hex[i * 2], 3, "%02x", digest[i]);
  }
  cl_assert_equal_s(expect_hex, hex);
}

void test_sha256__empty(void) {
  prv_assert_digest("", 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

void test_sha256__abc(void) {
  prv_assert_digest("abc", 3, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

//! 448 bits: forces the length to spill into a second padding block.
void test_sha256__two_block_message(void) {
  const char *msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  prv_assert_digest(msg, strlen(msg),
                    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

//! Exactly one block, so padding needs a whole extra block of its own.
void test_sha256__exactly_64_bytes(void) {
  char msg[64];
  memset(msg, 'a', sizeof(msg));
  prv_assert_digest(msg, sizeof(msg),
                    "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb");
}

//! 55 bytes is the largest message whose padding still fits in the first block.
void test_sha256__fifty_five_bytes(void) {
  char msg[55];
  memset(msg, 'a', sizeof(msg));
  prv_assert_digest(msg, sizeof(msg),
                    "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318");
}

//! 56 bytes is the first size that pushes the length field into a new block.
void test_sha256__fifty_six_bytes(void) {
  char msg[56];
  memset(msg, 'a', sizeof(msg));
  prv_assert_digest(msg, sizeof(msg),
                    "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a");
}

void test_sha256__million_a(void) {
  // The classic FIPS 180-4 long vector, fed in awkward chunks so the buffering
  // in sha256_update() is exercised rather than a single aligned pass.
  Sha256Context ctx;
  sha256_init(&ctx);
  char chunk[1000];
  memset(chunk, 'a', sizeof(chunk));
  for (int i = 0; i < 1000; ++i) {
    sha256_update(&ctx, chunk, sizeof(chunk));
  }
  uint8_t digest[SHA256_DIGEST_LEN];
  sha256_final(&ctx, digest);

  char hex[SHA256_DIGEST_LEN * 2 + 1];
  for (int i = 0; i < SHA256_DIGEST_LEN; ++i) {
    snprintf(&hex[i * 2], 3, "%02x", digest[i]);
  }
  cl_assert_equal_s("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", hex);
}

//! Streaming in one byte at a time must match the one-shot result.
void test_sha256__incremental_matches_oneshot(void) {
  const char *msg = "The quick brown fox jumps over the lazy dog";
  uint8_t oneshot[SHA256_DIGEST_LEN];
  sha256(msg, strlen(msg), oneshot);

  Sha256Context ctx;
  sha256_init(&ctx);
  for (size_t i = 0; i < strlen(msg); ++i) {
    sha256_update(&ctx, &msg[i], 1);
  }
  uint8_t streamed[SHA256_DIGEST_LEN];
  sha256_final(&ctx, streamed);

  cl_assert_equal_i(0, memcmp(oneshot, streamed, SHA256_DIGEST_LEN));
}

//! A one-bit change must not leave the digest recognisably similar.
void test_sha256__avalanche(void) {
  uint8_t a[SHA256_DIGEST_LEN];
  uint8_t b[SHA256_DIGEST_LEN];
  sha256("1234", 4, a);
  sha256("1235", 4, b);
  cl_assert(memcmp(a, b, SHA256_DIGEST_LEN) != 0);
}

//! sha256_final() must not leave the message or state in the context.
void test_sha256__context_is_wiped(void) {
  Sha256Context ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, "secret", 6);
  uint8_t digest[SHA256_DIGEST_LEN];
  sha256_final(&ctx, digest);

  Sha256Context zeroed;
  memset(&zeroed, 0, sizeof(zeroed));
  cl_assert_equal_i(0, memcmp(&ctx, &zeroed, sizeof(ctx)));
}
