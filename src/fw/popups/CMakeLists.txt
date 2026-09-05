# SPDX-FileCopyrightText: 2026 Core Devices LLC
# SPDX-License-Identifier: Apache-2.0

if(CONFIG_RECOVERY_FW)
  set(source bluetooth_pairing_ui.c)
else()
  set(excl)
  if(NOT CONFIG_HRM)
    list(APPEND excl ble_hrm/**)
  endif()
  if(NOT CONFIG_SERVICE_SECURITY_LOCK)
    list(APPEND excl security/**)
  endif()
  file(GLOB_RECURSE source CONFIGURE_DEPENDS *.c)
  pbl_filter_sources(source EXCLUDE ${excl})
endif()
pbl_library()
pbl_library_sources(${source})
