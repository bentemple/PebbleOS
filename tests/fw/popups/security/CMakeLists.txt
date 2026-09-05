# SPDX-FileCopyrightText: 2026 Core Devices LLC
# SPDX-License-Identifier: Apache-2.0

# gtypes.c is the real thing rather than a stub: grect_contains_point IS the
# hit test, and faking it would leave the layout assertions testing nothing.
# perimeter.c likewise: it is what says which pixels a round display actually
# shows, so the layout can be checked against the circle rather than the
# bounding box.
#
# Built for both display shapes, because the round arm of the layout is picked
# by the preprocessor and so does not exist at all in a rect build.
pbl_clar_test(test_pin_entry_window
  SOURCES
    src/fw/popups/security/pin_entry_window.c
    src/fw/applib/graphics/gtypes.c
    src/fw/applib/graphics/perimeter.c
  OVERRIDES dummy_board
  PLATFORMS obelix gabbro
)

pbl_clar_test(test_lock_screen
  SOURCES
    src/fw/popups/security/lock_screen.c
    src/fw/popups/security/pin_entry_window.c
    src/fw/applib/graphics/gtypes.c
  OVERRIDES dummy_board
)
