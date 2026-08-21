# SPDX-FileCopyrightText: 2026 Core Devices LLC
# SPDX-License-Identifier: Apache-2.0

# Only the module itself is built. Everything it draws with or pushes is faked
# in the test, which is what makes the row logic and the prompt state machine
# reachable without a MenuLayer, a window stack or a filesystem.
#
# The module compiles to nothing without the define, so it has to be forced
# here: the test build's autoconf does not carry the firmware's Kconfig choices.
pbl_clar_test(test_settings_security
  SOURCES
    src/fw/apps/system/settings/security.c
  DEFINES CONFIG_SERVICE_SECURITY_LOCK=1
  OVERRIDES dummy_board
)
