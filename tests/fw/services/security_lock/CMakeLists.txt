# SPDX-FileCopyrightText: 2026 Core Devices LLC
# SPDX-License-Identifier: Apache-2.0

# Every target here builds the feature's own sources, so the feature is on:
# security_lock.h declares security_lock_mark_dirty_since_shred() only under
# CONFIG_SERVICE_SECURITY_LOCK and supplies a static inline no-op otherwise,
# which collides with the fakes these tests define for it.

# pin_hash.c is deliberately not built here: the test substitutes a fake, so
# the record store is exercised without paying 10000 SHA-256 rounds per PIN
# operation. The real derivation is covered by test_security_lock_pin_hash.
pbl_clar_test(test_security_lock
  SOURCES
    src/fw/services/security_lock/service.c
    src/fw/services/settings/settings_file.c
    src/fw/services/settings/settings_raw_iter.c
    src/fw/services/filesystem/flash_translation.c
    src/fw/services/filesystem/pfs.c
    src/fw/flash_region/filesystem_regions.c
    src/fw/flash_region/flash_region.c
    src/fw/system/hexdump.c
    src/fw/util/crc8.c
    src/fw/util/dict.c
    src/fw/util/legacy_checksum.c
    src/fw/util/rand/rand.c
    tests/fakes/fake_rtc.c
    tests/fakes/fake_spi_flash.c
    third_party/tinymt/TinyMT/tinymt/tinymt32.c
  DEFINES CONFIG_SERVICE_SECURITY_LOCK=1
  OVERRIDES dummy_board
)

# The derivation the record store's fake stands in for, built for real. The
# subject is the digest itself: the iteration count, the salt feeding every
# round, and the comparator reading the whole digest.
pbl_clar_test(test_security_lock_pin_hash
  SOURCES
    src/fw/services/security_lock/pin_hash.c
    src/fw/services/security_lock/sha256.c
  DEFINES CONFIG_SERVICE_SECURITY_LOCK=1
  OVERRIDES dummy_board
)

pbl_clar_test(test_sha256
  SOURCES
    src/fw/services/security_lock/sha256.c
  DEFINES CONFIG_SERVICE_SECURITY_LOCK=1
  OVERRIDES dummy_board
)

# Everything the shred drives is faked in the test, so nothing but shred.c and
# the target list are built here: the subject is the shape of the sequence, not
# what each step does.
pbl_clar_test(test_security_lock_shred
  SOURCES
    src/fw/services/security_lock/shred.c
    src/fw/services/security_lock/shred_targets.c
  DEFINES CONFIG_SERVICE_SECURITY_LOCK=1
  OVERRIDES dummy_board
)

# The lock funnel, where the master switch is enforced for everything that
# locks. Everything it drives is faked: the subject is which of set_state, the
# UI lockout and the wipe run for a given state.
pbl_clar_test(test_security_lock_engage
  SOURCES
    src/fw/services/security_lock/lock.c
  DEFINES CONFIG_SERVICE_SECURITY_LOCK=1
  OVERRIDES dummy_board
)

# What the phone can ask for, and the countdowns the endpoint arms and retires.
# The service, the timer and the session are all faked: the subject is which
# deadlines get armed, which messages go out, and in what order.
pbl_clar_test(test_security_lock_endpoint
  SOURCES
    src/fw/services/security_lock/endpoint.c
  DEFINES CONFIG_SERVICE_SECURITY_LOCK=1
  OVERRIDES dummy_board
)
