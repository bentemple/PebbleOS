# SPDX-FileCopyrightText: 2026 Core Devices LLC
# SPDX-License-Identifier: Apache-2.0

# The lock screen itself is not covered here: it is a window stack push plus a
# call into the lock state store, and standing both up buys nothing a reading
# of the file does not already give you. The entry logic below is the part with
# real behaviour in it.
#
# gtypes.c is the real thing rather than a stub: grect_contains_point IS the
# hit test, and faking it would leave the layout assertions testing nothing.
pbl_clar_test(test_pin_entry_window
  SOURCES
    src/fw/popups/security/pin_entry_window.c
    src/fw/applib/graphics/gtypes.c
  OVERRIDES dummy_board
)
