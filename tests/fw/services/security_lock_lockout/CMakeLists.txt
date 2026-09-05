# SPDX-FileCopyrightText: 2026 Core Devices LLC
# SPDX-License-Identifier: Apache-2.0

# The PIN lockout: what the service does with an attempt once the budget is
# spent. Its own target rather than more cases in test_security_lock, which
# covers the record store; the subject here is the refusal and the backoff, and
# both are measured against the clock, so the fake RTC is driven directly.
#
# pin_hash.c is deliberately not built: the test substitutes a fake, so a
# refusal can be told from a comparison by whether the hash ran at all.
pbl_clar_test(test_security_lock_lockout
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
