# SPDX-FileCopyrightText: 2026 Core Devices LLC
# SPDX-License-Identifier: Apache-2.0

# Only the app itself is built. It pushes one empty window and hands over to
# the kernel, so everything it touches is faked in the test.
#
# The app compiles to nothing without the define, and the test build's autoconf
# does not carry the firmware's Kconfig choices.
pbl_clar_test(test_lockdown
  SOURCES
    src/fw/apps/system/lockdown.c
  DEFINES CONFIG_SERVICE_SECURITY_LOCK=1
  OVERRIDES dummy_board
)
