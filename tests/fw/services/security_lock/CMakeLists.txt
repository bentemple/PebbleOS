# SPDX-FileCopyrightText: 2026 Core Devices LLC
# SPDX-License-Identifier: Apache-2.0

# pin_hash.c is deliberately not built here: the test substitutes a fake so
# the record store can be exercised without linking mbedtls.
# DUMA reports a false positive on this one, so it is disabled.
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
  DEFINES DUMA_DISABLED
  OVERRIDES dummy_board
)

pbl_clar_test(test_sha256
  SOURCES
    src/fw/services/security_lock/sha256.c
  OVERRIDES dummy_board
)

# Everything the shred drives is faked in the test, so nothing but shred.c is
# built here: the subject is the shape of the sequence, not what each step does.
pbl_clar_test(test_security_lock_shred
  SOURCES
    src/fw/services/security_lock/shred.c
  OVERRIDES dummy_board
)

# Same again for the disconnect countdown: the subject is which deadlines get
# armed and which do not, so the service, the timer and the session are faked.
pbl_clar_test(test_security_lock_endpoint
  SOURCES
    src/fw/services/security_lock/endpoint.c
  OVERRIDES dummy_board
)
