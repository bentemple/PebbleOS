/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

//! Tests for pfs_shred() and pfs_gc_deleted_sectors().
//!
//! These assert on the raw contents of the emulated flash rather than on
//! filesystem-level behaviour. That is the whole point: the filesystem happily
//! reports a file as gone while its payload is still sitting there in the
//! clear, which is exactly the failure these functions exist to prevent.

#include <setjmp.h>
#include <string.h>

#include <pbl/drivers/flash.h>
#include "flash_region/flash_region.h"
#include "pbl/services/filesystem/pfs.h"
#include "pbl/util/math.h"
#include "pbl/util/size.h"

#include "clar.h"

#include "fake_spi_flash.h"
#include "fake_rtc.h"
#include "stubs_analytics.h"
#include "stubs_logging.h"
#include "stubs_mutex.h"
#include "stubs_passert.h"
#include "stubs_pbl_malloc.h"
#include "stubs_pebble_tasks.h"
#include "stubs_print.h"
#include "stubs_prompt.h"
#include "stubs_serial.h"
#include "stubs_sleep.h"
#include "stubs_task_watchdog.h"

// A pattern that will not occur naturally in filesystem metadata.
static const char SECRET[] = "TOPSECRET-CALENDAR-ENTRY-8b41d0f2";
#define SECRET_LEN (sizeof(SECRET) - 1)

static const char *SECRET_FILE = "secretf";
static const char *KEEPER_FILE = "keeperf";
static const char KEEPER[] = "KEEPME-HEALTH-DATA-must-survive-9c";
#define KEEPER_LEN (sizeof(KEEPER) - 1)

void test_pfs_shred__initialize(void) {
  fake_spi_flash_init(0, 0x1000000);
  pfs_init(false);
  pfs_format(true /* write_erase_headers */);
}

void test_pfs_shred__cleanup(void) {
  fake_spi_flash_cleanup();
}

// Helpers
////////////////////////////////////

static void prv_write_file(const char *name, const char *data, size_t len) {
  int fd = pfs_open(name, OP_FLAG_WRITE, FILE_TYPE_STATIC, len);
  cl_assert(fd >= 0);
  cl_assert(pfs_write(fd, data, len) == (int)len);
  cl_assert(pfs_close(fd) == S_SUCCESS);
}

static bool prv_read_file(const char *name, char *out, size_t len) {
  int fd = pfs_open(name, OP_FLAG_READ, FILE_TYPE_STATIC, 0);
  if (fd < 0) {
    return false;
  }
  bool ok = (pfs_read(fd, out, len) == (int)len);
  pfs_close(fd);
  return ok;
}

//! Scan the entire filesystem flash region for a byte pattern.
static bool prv_flash_contains(const char *pattern, size_t pattern_len) {
  enum { CHUNK = 4096 };
  // Overlap successive chunks so a pattern straddling a boundary is still seen.
  uint8_t buf[CHUNK + 64];
  cl_assert(pattern_len <= 64);

  for (uint32_t addr = FLASH_REGION_FILESYSTEM_BEGIN; addr < FLASH_REGION_FILESYSTEM_END;
       addr += CHUNK) {
    const uint32_t to_read = MIN(CHUNK + pattern_len, FLASH_REGION_FILESYSTEM_END - addr);
    flash_read_bytes(buf, addr, to_read);
    for (uint32_t i = 0; i + pattern_len <= to_read; ++i) {
      if (memcmp(&buf[i], pattern, pattern_len) == 0) {
        return true;
      }
    }
  }
  return false;
}

// pfs_remove leaves the payload behind -- the problem being solved
////////////////////////////////////

//! Establishes the baseline. If this ever starts failing, pfs_remove() has
//! gained erase semantics and pfs_shred() may no longer be necessary.
void test_pfs_shred__remove_leaves_payload_readable_on_flash(void) {
  prv_write_file(SECRET_FILE, SECRET, SECRET_LEN);
  cl_assert(prv_flash_contains(SECRET, SECRET_LEN));

  cl_assert_equal_i(S_SUCCESS, pfs_remove(SECRET_FILE));

  // Gone as far as the filesystem is concerned...
  char readback[SECRET_LEN];
  cl_assert(!prv_read_file(SECRET_FILE, readback, SECRET_LEN));
  // ...but still plainly there on the flash.
  cl_assert(prv_flash_contains(SECRET, SECRET_LEN));
}

// pfs_shred
////////////////////////////////////

void test_pfs_shred__destroys_payload(void) {
  prv_write_file(SECRET_FILE, SECRET, SECRET_LEN);
  cl_assert(prv_flash_contains(SECRET, SECRET_LEN));

  cl_assert_equal_i(S_SUCCESS, pfs_shred(SECRET_FILE));

  cl_assert(!prv_flash_contains(SECRET, SECRET_LEN));

  char readback[SECRET_LEN];
  cl_assert(!prv_read_file(SECRET_FILE, readback, SECRET_LEN));
}

void test_pfs_shred__spares_other_files(void) {
  prv_write_file(SECRET_FILE, SECRET, SECRET_LEN);
  prv_write_file(KEEPER_FILE, KEEPER, KEEPER_LEN);

  cl_assert_equal_i(S_SUCCESS, pfs_shred(SECRET_FILE));

  cl_assert(!prv_flash_contains(SECRET, SECRET_LEN));

  char readback[KEEPER_LEN];
  cl_assert(prv_read_file(KEEPER_FILE, readback, KEEPER_LEN));
  cl_assert_equal_i(0, memcmp(readback, KEEPER, KEEPER_LEN));
}

void test_pfs_shred__missing_file_is_success(void) {
  // Nothing to destroy is a successful shred; callers wipe a fixed list of
  // files and most of them will not exist on any given watch.
  cl_assert_equal_i(S_SUCCESS, pfs_shred("nosuchf"));
}

void test_pfs_shred__rejects_null(void) {
  cl_assert_equal_i(E_INVALID_ARGUMENT, pfs_shred(NULL));
}

void test_pfs_shred__multi_page_file(void) {
  // Larger than one 4K page, so the zeroing has to walk the page chain.
  enum { BIG_LEN = 9000 };
  char *big = malloc(BIG_LEN);
  cl_assert(big != NULL);
  for (int i = 0; i < BIG_LEN; ++i) {
    big[i] = (char)('A' + (i % 26));
  }
  memcpy(&big[BIG_LEN - SECRET_LEN], SECRET, SECRET_LEN);

  prv_write_file(SECRET_FILE, big, BIG_LEN);
  cl_assert(prv_flash_contains(SECRET, SECRET_LEN));

  cl_assert_equal_i(S_SUCCESS, pfs_shred(SECRET_FILE));
  cl_assert(!prv_flash_contains(SECRET, SECRET_LEN));

  free(big);
}

void test_pfs_shred__file_can_be_recreated_after_shred(void) {
  prv_write_file(SECRET_FILE, SECRET, SECRET_LEN);
  cl_assert_equal_i(S_SUCCESS, pfs_shred(SECRET_FILE));

  prv_write_file(SECRET_FILE, KEEPER, KEEPER_LEN);
  char readback[KEEPER_LEN];
  cl_assert(prv_read_file(SECRET_FILE, readback, KEEPER_LEN));
  cl_assert_equal_i(0, memcmp(readback, KEEPER, KEEPER_LEN));
}

// pfs_gc_deleted_sectors
////////////////////////////////////

//! The case pfs_shred() alone cannot cover: data unlinked by someone else, or
//! left behind by an earlier compaction, whose bytes are still on flash.
void test_pfs_shred__gc_erases_stale_payload_from_plain_remove(void) {
  prv_write_file(SECRET_FILE, SECRET, SECRET_LEN);
  pfs_remove(SECRET_FILE);
  cl_assert(prv_flash_contains(SECRET, SECRET_LEN));

  pfs_gc_deleted_sectors(0 /* no budget */);

  cl_assert(!prv_flash_contains(SECRET, SECRET_LEN));
}

//! Health/activity data lives in files we deliberately do not wipe, so the
//! sweep must not take them with it.
void test_pfs_shred__gc_preserves_live_files(void) {
  prv_write_file(SECRET_FILE, SECRET, SECRET_LEN);
  prv_write_file(KEEPER_FILE, KEEPER, KEEPER_LEN);
  pfs_remove(SECRET_FILE);

  pfs_gc_deleted_sectors(0 /* no budget */);

  cl_assert(!prv_flash_contains(SECRET, SECRET_LEN));

  char readback[KEEPER_LEN];
  cl_assert(prv_read_file(KEEPER_FILE, readback, KEEPER_LEN));
  cl_assert_equal_i(0, memcmp(readback, KEEPER, KEEPER_LEN));
}

void test_pfs_shred__gc_with_nothing_deleted_is_harmless(void) {
  prv_write_file(KEEPER_FILE, KEEPER, KEEPER_LEN);

  pfs_gc_deleted_sectors(0 /* no budget */);

  char readback[KEEPER_LEN];
  cl_assert(prv_read_file(KEEPER_FILE, readback, KEEPER_LEN));
  cl_assert_equal_i(0, memcmp(readback, KEEPER, KEEPER_LEN));
}

//! Shred then sweep is the sequence the shred engine actually uses.
void test_pfs_shred__shred_then_gc_leaves_nothing(void) {
  prv_write_file(SECRET_FILE, SECRET, SECRET_LEN);
  prv_write_file(KEEPER_FILE, KEEPER, KEEPER_LEN);

  cl_assert_equal_i(S_SUCCESS, pfs_shred(SECRET_FILE));
  pfs_gc_deleted_sectors(0 /* no budget */);

  cl_assert(!prv_flash_contains(SECRET, SECRET_LEN));

  char readback[KEEPER_LEN];
  cl_assert(prv_read_file(KEEPER_FILE, readback, KEEPER_LEN));
  cl_assert_equal_i(0, memcmp(readback, KEEPER, KEEPER_LEN));
}

//! Overwriting a file repeatedly leaves superseded copies scattered around;
//! the sweep is what reaches those.
void test_pfs_shred__gc_erases_superseded_copies(void) {
  // OP_FLAG_OVERWRITE shadows an existing file, so one has to exist first.
  prv_write_file(SECRET_FILE, SECRET, SECRET_LEN);
  for (int i = 0; i < 4; ++i) {
    int fd = pfs_open(SECRET_FILE, OP_FLAG_OVERWRITE, FILE_TYPE_STATIC, SECRET_LEN);
    cl_assert(fd >= 0);
    cl_assert(pfs_write(fd, SECRET, SECRET_LEN) == (int)SECRET_LEN);
    cl_assert(pfs_close(fd) == S_SUCCESS);
  }
  cl_assert(prv_flash_contains(SECRET, SECRET_LEN));

  cl_assert_equal_i(S_SUCCESS, pfs_shred(SECRET_FILE));
  pfs_gc_deleted_sectors(0 /* no budget */);

  cl_assert(!prv_flash_contains(SECRET, SECRET_LEN));
}

//! A budgeted sweep stops early and resumes where it left off, which is what
//! lets the shred run it in slices instead of blocking a task for minutes.
void test_pfs_shred__gc_budget_is_respected_and_resumable(void) {
  // One page each, so this has to span more erase sectors than a single pass
  // can collect: a budget that is never reached proves nothing about resuming.
  // Live files are interleaved with the deleted ones so collecting a sector
  // has to relocate pages, which is the feedback loop the resume loop below
  // has to terminate in spite of.
  enum { NUM_FILES = 40 };
  for (int i = 0; i < NUM_FILES; ++i) {
    char name[8];
    snprintf(name, sizeof(name), "f%d", i);
    char body[600];
    memset(body, 'a' + (i % 26), sizeof(body));
    memcpy(body, (i % 2) ? KEEPER : SECRET, (i % 2) ? KEEPER_LEN : SECRET_LEN);
    prv_write_file(name, body, sizeof(body));
    if ((i % 2) == 0) {
      pfs_remove(name);
    }
  }
  cl_assert(prv_flash_contains(SECRET, SECRET_LEN));

  // A budget of one collects exactly one sector and leaves the rest.
  const int first = pfs_gc_deleted_sectors(1);
  cl_assert_equal_i(1, first);

  // Must actually reach "nothing left to do". Collecting a sector relocates
  // the live pages in it, which leaves fresh deleted pages behind, so if that
  // feeds back the sweep never terminates -- and the shred driving it in
  // rescheduled passes would spin forever and starve its task. That is not
  // hypothetical: it wedged the watch until it was bounded.
  int passes = 0;
  const int limit = 2048;
  while (passes < limit) {
    if (pfs_gc_deleted_sectors(1) == 0) {
      break;
    }
    passes++;
  }
  cl_assert(passes < limit);
  // The first pass really did leave work behind, so the loop above measured
  // resuming rather than a filesystem that was already drained.
  cl_assert(passes >= 1);

  cl_assert(!prv_flash_contains(SECRET, SECRET_LEN));

  // The interleaved files were relocated, not collateral damage.
  char readback[KEEPER_LEN];
  cl_assert(prv_read_file("f1", readback, KEEPER_LEN));
  cl_assert_equal_i(0, memcmp(readback, KEEPER, KEEPER_LEN));
}

//! Deleted pages that cannot be collected must not read as a drained
//! filesystem: a caller scrubbing in slices stops at zero, and stopping over
//! payload that is still on flash is the failure the sweep exists to prevent.
void test_pfs_shred__gc_reports_no_progress_separately_from_drained(void) {
  prv_write_file(KEEPER_FILE, KEEPER, KEEPER_LEN);
  cl_assert_equal_i(0, pfs_gc_deleted_sectors(0));

  // No filesystem to walk says nothing about what is on the flash.
  fake_spi_flash_erase();
  cl_assert_equal_i(PFS_GC_NO_PROGRESS, pfs_gc_deleted_sectors(0));
}

//! pfs_shred() zeroes the payload and then unlinks, and power can be lost
//! between the two. The tail of the payload is then still in the clear with the
//! file still linked, so the shred has to be resumable: the next one has to
//! finish the job rather than trip over the half-zeroed file.
void test_pfs_shred__survives_power_loss_midway(void) {
  enum { BIG_LEN = 9000 };
  char *big = malloc(BIG_LEN);
  cl_assert(big != NULL);
  for (int i = 0; i < BIG_LEN; ++i) {
    big[i] = (char)('A' + (i % 26));
  }
  // At the very end, so any cut early in the zeroing leaves it readable.
  memcpy(&big[BIG_LEN - SECRET_LEN], SECRET, SECRET_LEN);

  // A spread of cut points: where in the write stream the power goes decides
  // which half-written state the next boot inherits.
  const int cut_points[] = {16, 128, 512, 2048};
  int interruptions = 0;

  for (size_t i = 0; i < ARRAY_LENGTH(cut_points); ++i) {
    fake_spi_flash_cleanup();
    fake_spi_flash_init(0, 0x1000000);
    pfs_init(false);
    pfs_format(true /* write_erase_headers */);
    prv_write_file(SECRET_FILE, big, BIG_LEN);

    jmp_buf power_cut;
    if (setjmp(power_cut) == 0) {
      fake_spi_flash_force_future_failure(cut_points[i], &power_cut);
      pfs_shred(SECRET_FILE);
      fake_spi_flash_force_future_failure(0, NULL);
    } else {
      // Power came back. Nothing else may fail from here on.
      fake_spi_flash_force_future_failure(0, NULL);
      interruptions++;

      // The state the reboot inherits: the file is still linked and the part of
      // the payload the zeroing never reached is still in the clear.
      cl_assert(prv_flash_contains(SECRET, SECRET_LEN));
      cl_assert_equal_i(S_SUCCESS, pfs_init(false));
      int fd = pfs_open(SECRET_FILE, OP_FLAG_READ, FILE_TYPE_STATIC, 0);
      cl_assert(fd >= 0);
      pfs_close(fd);
    }

    // Whatever state the cut left behind, shredding again finishes the job.
    cl_assert_equal_i(S_SUCCESS, pfs_shred(SECRET_FILE));
    cl_assert(!prv_flash_contains(SECRET, SECRET_LEN));
  }

  // The cuts have to have actually landed, or this measures nothing.
  cl_assert(interruptions > 0);

  free(big);
}
