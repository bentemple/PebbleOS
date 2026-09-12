/* SPDX-FileCopyrightText: 2024 Google LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include "kernel/events.h"

#ifdef CONFIG_SPEAKER
// Full volume = 0 dB DAC gain, the loudest undistorted level; the user's
// global speaker-volume preference scales it down from there.
#define ALARM_SPEAKER_VOLUME 100
#endif

void alarm_popup_push_window(PebbleAlarmClockEvent *e);

//! True while the ringing-alarm window is the one on top.
//!
//! For the locked watch, which routes buttons to this window rather than to the
//! lock screen: an alarm nobody can snooze or dismiss is worse than one that
//! never rang. False again as soon as either action is taken, so the
//! confirmation dialog that follows is not treated as the alarm.
//!
//! Compares the actual top window rather than reporting that the pop-up exists.
//! The caller is handing it button events on a locked watch, so "something is
//! showing" is not good enough: a future modal at ModalPriorityAlarm would
//! inherit that access on the strength of the alarm's own flag.
bool alarm_popup_owns_top_window(void);

//! Take a ringing alarm off the screen and stop its vibe, if one is up.
//!
//! For the wipe, which cannot reach it by priority: the alarm sits above the
//! lock screen, and the wipe spares the lock screen, so no range of priorities
//! takes the one and leaves the other. An erased watch holds nothing and talks
//! to nobody, and one still buzzing about it is the one place that rule
//! visibly did not hold.
//!
//! No-op when nothing is ringing. KernelMain only.
void alarm_popup_close(void);
