/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

//! Tests for the PIN key derivation itself, built against the real pin_hash.c.
//!
//! Every other suite in this directory substitutes a cheap fake for this file,
//! which is exactly why it needs a suite of its own: the fake is salt- and
//! PIN-sensitive but it is not this derivation, so nothing else on the branch
//! would notice if the iteration count collapsed, the salt stopped feeding the
//! rounds, or the comparator started reading fewer bytes than it compares.
//!
//! The expected digests below were computed independently, from the written
//! description of the derivation, with Python's hashlib -- not by running this
//! code and recording what it emitted. A self-recorded golden value pins
//! whatever the code does today, including the bug.

#include "clar.h"

#include <string.h>

#include "pbl/services/security_lock.h"
#include "pbl/services/security_lock_pin_hash.h"

// Reference vectors
////////////////////////////////////
//
// The derivation, as documented in pin_hash.c:
//
//   buf   = salt || digits
//   out   = SHA256(buf[0 .. SALT_LEN + len])
//   repeat HASH_ITERATIONS - 1 times:
//     buf = salt || out
//     out = SHA256(buf)                      // the full SALT_LEN + HASH_LEN
//
// Reproduced in Python as:
//
//   buf = bytearray(48)
//   buf[0:16] = salt
//   buf[16:16+len(pin)] = pin
//   out = sha256(bytes(buf[0:16+len(pin)])).digest()
//   for _ in range(1, 10000):
//       buf[16:48] = out
//       out = sha256(bytes(buf)).digest()

static const uint8_t SALT_A[SECURITY_LOCK_SALT_LEN] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

//! SALT_A with one byte changed, so a derivation that ignored the salt after
//! the first round -- or ignored it entirely -- would collide with SALT_A.
static const uint8_t SALT_B[SECURITY_LOCK_SALT_LEN] = {
    0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

static const uint8_t EXPECT_1234_A[SECURITY_LOCK_HASH_LEN] = {
    0x84, 0x56, 0x01, 0x7d, 0xa4, 0xce, 0xce, 0xfa, 0xe3, 0xfd, 0x39,
    0x9a, 0x2e, 0x7a, 0xf8, 0x0f, 0x5b, 0x32, 0x6b, 0x16, 0x21, 0x2c,
    0x9e, 0x8c, 0x39, 0x7f, 0x2d, 0x8c, 0x41, 0x26, 0xa3, 0x72,
};

static const uint8_t EXPECT_123456_A[SECURITY_LOCK_HASH_LEN] = {
    0xd5, 0x9d, 0xf9, 0xd8, 0x3a, 0x0c, 0xe1, 0x62, 0x45, 0xf9, 0xd2,
    0x37, 0x2d, 0x2a, 0x65, 0x46, 0xbe, 0xa1, 0xb8, 0x93, 0x4c, 0x26,
    0x71, 0x95, 0xe3, 0x60, 0xf0, 0x68, 0xcb, 0x06, 0x1d, 0xa6,
};

static const uint8_t EXPECT_1234_B[SECURITY_LOCK_HASH_LEN] = {
    0x98, 0x27, 0xbb, 0x18, 0x6d, 0x04, 0xeb, 0xc2, 0xad, 0x70, 0xea,
    0x13, 0x5c, 0x01, 0xde, 0x41, 0x92, 0x33, 0x41, 0x61, 0x42, 0x46,
    0xc4, 0x21, 0xce, 0x21, 0x55, 0xd8, 0xbf, 0x27, 0x89, 0x3c,
};

//! What "1234" with SALT_A derives to after a single round. Pinned as a value
//! the derivation must NOT produce, so a collapsed HASH_ITERATIONS is named
//! rather than merely failing the vector above with an unexplained digest.
static const uint8_t ONE_ROUND_1234_A[SECURITY_LOCK_HASH_LEN] = {
    0xba, 0xd0, 0xb4, 0xf7, 0xca, 0xe0, 0x8e, 0xb7, 0xc1, 0xb5, 0xac,
    0xc7, 0x63, 0xa8, 0xed, 0x25, 0x24, 0x2e, 0x2c, 0x91, 0x73, 0xe8,
    0x1f, 0x3f, 0x62, 0x4b, 0x1f, 0xa5, 0x30, 0x3c, 0xf6, 0xce,
};

// Helpers
////////////////////////////////////

static void prv_hash(const char *digits, const uint8_t *salt, uint8_t out[SECURITY_LOCK_HASH_LEN]) {
  memset(out, 0xa5, SECURITY_LOCK_HASH_LEN);
  cl_assert_equal_i(S_SUCCESS,
                    security_lock_pin_hash(digits, (uint8_t)strlen(digits), salt, out));
}

static void prv_assert_digest(const uint8_t *actual, const uint8_t *expected) {
  for (int i = 0; i < SECURITY_LOCK_HASH_LEN; ++i) {
    // Reported per byte: a whole-digest cl_assert says only "different".
    cl_assert_equal_i(expected[i], actual[i]);
  }
}

void test_security_lock_pin_hash__initialize(void) {}
void test_security_lock_pin_hash__cleanup(void) {}

// The derivation
////////////////////////////////////

//! The vector. Everything the derivation is made of -- the salt prefix, the
//! digits, the iteration count and the re-salting inside the loop -- is pinned
//! by this one value, because changing any of them changes it.
void test_security_lock_pin_hash__matches_the_reference_derivation(void) {
  uint8_t out[SECURITY_LOCK_HASH_LEN];
  prv_hash("1234", SALT_A, out);
  prv_assert_digest(out, EXPECT_1234_A);
}

void test_security_lock_pin_hash__matches_the_reference_for_a_six_digit_pin(void) {
  uint8_t out[SECURITY_LOCK_HASH_LEN];
  prv_hash("123456", SALT_A, out);
  prv_assert_digest(out, EXPECT_123456_A);
}

//! The iteration count is the only thing keeping offline recovery of a 4-digit
//! PIN from being free, and it is a number nothing else in the tree reads. A
//! stray edit dropping it to 1 leaves a derivation that still hashes, still
//! salts, and still differs per PIN -- so it is named here explicitly.
void test_security_lock_pin_hash__is_not_a_single_round(void) {
  uint8_t out[SECURITY_LOCK_HASH_LEN];
  prv_hash("1234", SALT_A, out);
  cl_assert(memcmp(out, ONE_ROUND_1234_A, sizeof(out)) != 0);
}

//! The salt is what makes a stolen record useless against a precomputed table.
//! One changed salt byte has to change the whole digest.
void test_security_lock_pin_hash__a_different_salt_gives_a_different_digest(void) {
  uint8_t a[SECURITY_LOCK_HASH_LEN];
  uint8_t b[SECURITY_LOCK_HASH_LEN];
  prv_hash("1234", SALT_A, a);
  prv_hash("1234", SALT_B, b);

  cl_assert(memcmp(a, b, sizeof(a)) != 0);
  // And the second one is the independently computed answer too, so this is
  // measuring the salt rather than merely two runs disagreeing.
  prv_assert_digest(b, EXPECT_1234_B);
}

//! The salt is folded in on every round, not only the first: a derivation that
//! dropped it after round one would still pass the test above.
void test_security_lock_pin_hash__the_salt_feeds_every_round(void) {
  uint8_t out[SECURITY_LOCK_HASH_LEN];
  prv_hash("1234", SALT_B, out);
  // EXPECT_1234_B is SALT_B carried through all 10000 rounds. A loop that
  // re-hashed only the previous digest would land somewhere else.
  prv_assert_digest(out, EXPECT_1234_B);
}

void test_security_lock_pin_hash__a_different_pin_gives_a_different_digest(void) {
  uint8_t a[SECURITY_LOCK_HASH_LEN];
  uint8_t b[SECURITY_LOCK_HASH_LEN];
  prv_hash("1234", SALT_A, a);
  prv_hash("9999", SALT_A, b);
  cl_assert(memcmp(a, b, sizeof(a)) != 0);
}

//! Same digits, different length. The length is part of what is hashed, so a
//! short PIN must not be a prefix-collision of a longer one.
void test_security_lock_pin_hash__length_is_part_of_the_input(void) {
  uint8_t four[SECURITY_LOCK_HASH_LEN];
  uint8_t six[SECURITY_LOCK_HASH_LEN];
  prv_hash("1234", SALT_A, four);
  prv_hash("123456", SALT_A, six);
  cl_assert(memcmp(four, six, sizeof(four)) != 0);
}

void test_security_lock_pin_hash__is_deterministic(void) {
  uint8_t a[SECURITY_LOCK_HASH_LEN];
  uint8_t b[SECURITY_LOCK_HASH_LEN];
  prv_hash("1234", SALT_A, a);
  prv_hash("1234", SALT_A, b);
  cl_assert_equal_i(0, memcmp(a, b, sizeof(a)));
}

// Argument handling
////////////////////////////////////

//! What this layer accepts is the closed range MIN..MAX, which is 4, 5 and 6.
//! Exactly 4 or 6 -- the rule the pad and the lock screen are built to -- is
//! enforced one layer up, by prv_pin_is_well_formed() in service.c, and this
//! records that the two are not the same test. A 5-digit PIN never reaches
//! here in the firmware; if that gate is ever removed, 5 will silently start
//! working rather than being refused.
void test_security_lock_pin_hash__accepts_the_documented_length_range(void) {
  uint8_t out[SECURITY_LOCK_HASH_LEN];
  cl_assert_equal_i(S_SUCCESS, security_lock_pin_hash("1234", 4, SALT_A, out));
  cl_assert_equal_i(S_SUCCESS, security_lock_pin_hash("12345", 5, SALT_A, out));
  cl_assert_equal_i(S_SUCCESS, security_lock_pin_hash("123456", 6, SALT_A, out));
}

//! Both boundaries, one either side. Too short is a weaker PIN than the record
//! claims; too long would read past the digits the caller supplied and hash
//! whatever followed them in memory.
void test_security_lock_pin_hash__rejects_lengths_outside_the_range(void) {
  uint8_t out[SECURITY_LOCK_HASH_LEN];
  cl_assert_equal_i(E_INVALID_ARGUMENT, security_lock_pin_hash("123", 3, SALT_A, out));
  cl_assert_equal_i(E_INVALID_ARGUMENT, security_lock_pin_hash("1234567", 7, SALT_A, out));
  cl_assert_equal_i(E_INVALID_ARGUMENT, security_lock_pin_hash("", 0, SALT_A, out));
  cl_assert_equal_i(E_INVALID_ARGUMENT, security_lock_pin_hash("1234567890", 255, SALT_A, out));
}

//! A rejected call must not have written a digest. Returning a status nobody
//! checked while leaving a plausible-looking hash behind is how a rejected PIN
//! ends up stored.
void test_security_lock_pin_hash__a_rejected_length_writes_no_digest(void) {
  uint8_t out[SECURITY_LOCK_HASH_LEN];
  memset(out, 0xa5, sizeof(out));
  cl_assert_equal_i(E_INVALID_ARGUMENT, security_lock_pin_hash("123", 3, SALT_A, out));
  for (int i = 0; i < SECURITY_LOCK_HASH_LEN; ++i) {
    cl_assert_equal_i(0xa5, out[i]);
  }
}

void test_security_lock_pin_hash__rejects_null_arguments(void) {
  uint8_t out[SECURITY_LOCK_HASH_LEN];
  cl_assert_equal_i(E_INVALID_ARGUMENT, security_lock_pin_hash(NULL, 4, SALT_A, out));
  cl_assert_equal_i(E_INVALID_ARGUMENT, security_lock_pin_hash("1234", 4, NULL, out));
  cl_assert_equal_i(E_INVALID_ARGUMENT, security_lock_pin_hash("1234", 4, SALT_A, NULL));
}

// Scrubbing the working buffer
////////////////////////////////////
//
// The derivation keeps salt || PIN in a 48-byte local and zeroes it before
// returning. Nothing zeroes a dead stack frame, so what it left behind is
// still readable at the same depth afterwards -- which is what the tests below
// read, by taking a snapshot from a frame of their own at that depth.
//
// One thing the scrub does not do, despite what its comment says: by the time
// it runs the PIN digits are long gone from the buffer, overwritten by the
// running digest on the loop's very first round. What it actually erases is
// salt || final digest. Asserting the digits are absent would therefore be a
// test that passes with the scrub deleted, so it is recorded here instead of
// written as one.

#define PROBE_BYTES 4096

static uint8_t s_stack_snapshot[PROBE_BYTES];

//! Copy back the stack a call at this depth just finished with. The
//! uninitialised read is the measurement, not an oversight.
static NOINLINE void prv_snapshot_stack(void) {
  uint8_t frame[PROBE_BYTES];
  memcpy(s_stack_snapshot, frame, sizeof(frame));
}

static bool prv_snapshot_holds(const uint8_t *needle, size_t len) {
  for (size_t i = 0; i + len <= sizeof(s_stack_snapshot); ++i) {
    if (memcmp(&s_stack_snapshot[i], needle, len) == 0) {
      return true;
    }
  }
  return false;
}

static const uint8_t MARKER[16] = {
    0xc0, 0xff, 0xee, 0x5e, 0xcb, 0xad, 0xf0, 0x0d,
    0x13, 0x37, 0xd0, 0x0d, 0xfa, 0xce, 0xb0, 0x0c,
};

static uint8_t s_marker_sink;

//! A frame the size of the derivation's, left dirty on purpose. The control
//! for the probe: if this cannot be found afterwards, the probe is not reading
//! the stack the derivation used and any "it was scrubbed" answer is worthless.
static NOINLINE void prv_leave_a_marker_on_the_stack(void) {
  uint8_t frame[SECURITY_LOCK_SALT_LEN + SECURITY_LOCK_HASH_LEN];
  memcpy(frame, MARKER, sizeof(MARKER));
  s_marker_sink = frame[0];
}

//! The scrub, and the control that keeps this from being a test that cannot
//! fail. A probe reading the wrong part of the stack would find no salt there
//! either, and would say so just as confidently.
void test_security_lock_pin_hash__the_working_buffer_is_scrubbed(void) {
  prv_leave_a_marker_on_the_stack();
  prv_snapshot_stack();
  cl_assert(prv_snapshot_holds(MARKER, sizeof(MARKER)));

  uint8_t out[SECURITY_LOCK_HASH_LEN];
  cl_assert_equal_i(S_SUCCESS, security_lock_pin_hash("134679", 6, SALT_A, out));
  prv_snapshot_stack();

  // The salt is the half of the buffer still in it when the loop ends, so it
  // is the half that says whether the scrub ran.
  cl_assert(!prv_snapshot_holds(SALT_A, SECURITY_LOCK_SALT_LEN));
}

// The comparator
////////////////////////////////////
//
// security_lock_hash_equal() is documented as constant-time, and the property
// that makes it so -- that it reads all HASH_LEN bytes whatever it finds --
// has no behavioural signature: `memcmp(a, b, HASH_LEN) == 0` returns the same
// answer for every input. No test written here can tell the two apart, and one
// claiming to would be measuring the compiler.
//
// What is testable is the half that does have a signature: a comparator that
// stops early, reads fewer bytes than the digest is long, or ignores a
// difference in some position accepts a wrong PIN. That is the regression
// worth a test, and every byte position gets one below.

void test_security_lock_pin_hash__equal_digests_compare_equal(void) {
  uint8_t a[SECURITY_LOCK_HASH_LEN];
  uint8_t b[SECURITY_LOCK_HASH_LEN];
  prv_hash("1234", SALT_A, a);
  prv_hash("1234", SALT_A, b);
  cl_assert(security_lock_hash_equal(a, b));
  cl_assert(security_lock_hash_equal(a, a));
}

//! A real pair, so this is not only about synthetic buffers.
void test_security_lock_pin_hash__different_pins_compare_unequal(void) {
  uint8_t a[SECURITY_LOCK_HASH_LEN];
  uint8_t b[SECURITY_LOCK_HASH_LEN];
  prv_hash("1234", SALT_A, a);
  prv_hash("9999", SALT_A, b);
  cl_assert(!security_lock_hash_equal(a, b));
}

//! Every byte position, both directions. A comparator that looked at a prefix
//! -- the shape a truncated memcmp takes -- would still pass a test that only
//! ever differed near the front.
void test_security_lock_pin_hash__a_difference_in_any_byte_is_caught(void) {
  uint8_t a[SECURITY_LOCK_HASH_LEN];
  prv_hash("1234", SALT_A, a);

  for (int i = 0; i < SECURITY_LOCK_HASH_LEN; ++i) {
    uint8_t b[SECURITY_LOCK_HASH_LEN];
    memcpy(b, a, sizeof(b));
    b[i] ^= 0xff;
    cl_assert(!security_lock_hash_equal(a, b));
    cl_assert(!security_lock_hash_equal(b, a));
  }
}

//! And every bit within a byte, so a comparator that masked or folded bits --
//! summing rather than OR-ing the differences, say -- is caught too.
void test_security_lock_pin_hash__a_single_flipped_bit_is_caught(void) {
  uint8_t a[SECURITY_LOCK_HASH_LEN];
  prv_hash("1234", SALT_A, a);

  for (int i = 0; i < SECURITY_LOCK_HASH_LEN; ++i) {
    for (int bit = 0; bit < 8; ++bit) {
      uint8_t b[SECURITY_LOCK_HASH_LEN];
      memcpy(b, a, sizeof(b));
      b[i] ^= (uint8_t)(1u << bit);
      cl_assert(!security_lock_hash_equal(a, b));
    }
  }
}

//! Two digests that differ everywhere, which is the ordinary wrong-PIN case
//! and the one an accumulator that overflowed would get wrong.
void test_security_lock_pin_hash__wholly_different_digests_compare_unequal(void) {
  uint8_t a[SECURITY_LOCK_HASH_LEN];
  uint8_t b[SECURITY_LOCK_HASH_LEN];
  memset(a, 0x00, sizeof(a));
  memset(b, 0xff, sizeof(b));
  cl_assert(!security_lock_hash_equal(a, b));

  memset(a, 0x55, sizeof(a));
  memset(b, 0xaa, sizeof(b));
  cl_assert(!security_lock_hash_equal(a, b));
}
