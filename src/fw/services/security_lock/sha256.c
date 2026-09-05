/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include "sha256.h"

#include <string.h>

// FIPS 180-4. Straightforward reference implementation: this runs a few
// thousand times on a PIN entry and nowhere else, so clarity beats speed.

static const uint32_t s_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static uint32_t prv_rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void prv_compress(Sha256Context *ctx, const uint8_t block[SHA256_BLOCK_LEN]) {
  uint32_t w[64];

  for (int i = 0; i < 16; ++i) {
    w[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) |
           ((uint32_t)block[i * 4 + 2] << 8) | (uint32_t)block[i * 4 + 3];
  }
  for (int i = 16; i < 64; ++i) {
    const uint32_t s0 = prv_rotr(w[i - 15], 7) ^ prv_rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
    const uint32_t s1 = prv_rotr(w[i - 2], 17) ^ prv_rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
  uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];

  for (int i = 0; i < 64; ++i) {
    const uint32_t s1 = prv_rotr(e, 6) ^ prv_rotr(e, 11) ^ prv_rotr(e, 25);
    const uint32_t ch = (e & f) ^ ((~e) & g);
    const uint32_t temp1 = h + s1 + ch + s_k[i] + w[i];
    const uint32_t s0 = prv_rotr(a, 2) ^ prv_rotr(a, 13) ^ prv_rotr(a, 22);
    const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    const uint32_t temp2 = s0 + maj;

    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;

  // The message schedule is derived from the input; don't leave it on the stack.
  memset(w, 0, sizeof(w));
}

void sha256_init(Sha256Context *ctx) {
  *ctx = (Sha256Context){
      .state = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19},
  };
}

void sha256_update(Sha256Context *ctx, const void *data, size_t len) {
  const uint8_t *bytes = data;

  while (len > 0) {
    const size_t space = SHA256_BLOCK_LEN - ctx->block_used;
    const size_t take = (len < space) ? len : space;

    memcpy(&ctx->block[ctx->block_used], bytes, take);
    ctx->block_used += take;
    bytes += take;
    len -= take;

    if (ctx->block_used == SHA256_BLOCK_LEN) {
      prv_compress(ctx, ctx->block);
      ctx->bit_len += SHA256_BLOCK_LEN * 8;
      ctx->block_used = 0;
    }
  }
}

void sha256_final(Sha256Context *ctx, uint8_t out[SHA256_DIGEST_LEN]) {
  const uint64_t total_bits = ctx->bit_len + ((uint64_t)ctx->block_used * 8);

  // Append 0x80, pad with zeroes, then the 64-bit big-endian length.
  ctx->block[ctx->block_used++] = 0x80;
  if (ctx->block_used > SHA256_BLOCK_LEN - 8) {
    memset(&ctx->block[ctx->block_used], 0, SHA256_BLOCK_LEN - ctx->block_used);
    prv_compress(ctx, ctx->block);
    ctx->block_used = 0;
  }
  memset(&ctx->block[ctx->block_used], 0, SHA256_BLOCK_LEN - 8 - ctx->block_used);
  for (int i = 0; i < 8; ++i) {
    ctx->block[SHA256_BLOCK_LEN - 1 - i] = (uint8_t)(total_bits >> (8 * i));
  }
  prv_compress(ctx, ctx->block);

  for (int i = 0; i < 8; ++i) {
    out[i * 4] = (uint8_t)(ctx->state[i] >> 24);
    out[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
    out[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
    out[i * 4 + 3] = (uint8_t)ctx->state[i];
  }

  memset(ctx, 0, sizeof(*ctx));
}

void sha256(const void *data, size_t len, uint8_t out[SHA256_DIGEST_LEN]) {
  Sha256Context ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, data, len);
  sha256_final(&ctx, out);
}
