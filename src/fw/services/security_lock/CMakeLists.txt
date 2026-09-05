# SPDX-FileCopyrightText: 2026 Core Devices LLC
# SPDX-License-Identifier: Apache-2.0

pbl_library()
pbl_library_sources(
  service.c
  pin_hash.c
  sha256.c
  shred.c
  shred_targets.c
  lock.c
  endpoint.c
)
