/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include "security.h"

#ifdef CONFIG_SERVICE_SECURITY_LOCK

#include "menu.h"
#include "option_menu.h"
#include "window.h"

#include "applib/ui/app_window_stack.h"
#include "applib/ui/dialogs/dialog.h"
#include "applib/ui/dialogs/expandable_dialog.h"
#include "applib/ui/ui.h"
#include "kernel/event_loop.h"
#include "kernel/pbl_malloc.h"
#include "popups/security/pin_entry_window.h"
#include "resource/resource_ids.auto.h"
#include "pbl/services/i18n/i18n.h"
#include "pbl/services/security_lock.h"
#include "pbl/services/security_lock_shred.h"
#include "pbl/services/security_lock_ui.h"
#include <pbl/logging/logging.h>
#include "shell/prefs.h"
#include "system/passert.h"
#include "pbl/util/math.h"
#include "pbl/util/size.h"

#include <stdio.h>
#include <string.h>

//! Wrong guesses tolerated at the Settings prompt before it gives up and drops
//! back to the menu. Deliberately NOT the lock screen's budget: see
//! prv_verify_current_pin().
#define SETTINGS_PIN_ATTEMPTS 3

#define SUBTITLE_BUF_SIZE 32

//! Wider than the others: these subtitles carry the value and what it is
//! counted from.
#define DELAY_SUBTITLE_BUF_SIZE 48

//! Erase After options, before the ones that would land before the lock are
//! filtered out. A macro so the filtered row buffer can be sized before the
//! table itself is declared.
#define NUM_SHRED_DELAY_OPTIONS 7

#define DELAY_SECONDS_PER_MINUTE 60
#define DELAY_SECONDS_PER_HOUR (60 * 60)

//! What the PIN prompt currently on screen is collecting.
typedef enum {
  //! Prove you know the existing PIN before being allowed to set another.
  PinStageAuthorizeSet,
  //! Same, before turning the whole feature off -- which discards that PIN.
  PinStageAuthorizeDisable,
  PinStageNewFirst,
  PinStageNewRepeat,
} PinStage;

//! Which PIN the new-PIN stages are collecting.
typedef enum {
  PinTargetMain,
  PinTargetDuress,
} PinTarget;

typedef struct SettingsSecurityData {
  SettingsCallbacks callbacks;

  //! Lives here rather than on its own so popping it frees nothing; the
  //! Security menu is always below it on the stack.
  SecurityPinEntryWindow pin_window;
  PinStage stage;
  PinTarget target;
  char first_entry[SECURITY_LOCK_PIN_MAX_LEN];
  uint8_t auth_attempts;

  //! Length the next PIN will be set to, from the picker that opens the
  //! set-PIN flow. Independent of the current PIN's length, which is what the
  //! authorize step prompts for.
  uint8_t new_pin_len;

  //! Cached so drawing a row does not read flash on every MenuLayer redraw.
  uint8_t current_pin_len;

  //! The master switch. Cached with the rest: every row's visibility depends
  //! on it, and prv_num_rows_cb() runs on every redraw.
  bool enabled;

  //! Both measured from the disconnect. Cached for the same reason, and so the
  //! two pickers can constrain each other without re-reading the store.
  uint32_t lock_delay_s;
  uint32_t shred_delay_s;

  char enabled_subtitle[SUBTITLE_BUF_SIZE];
  char pin_subtitle[SUBTITLE_BUF_SIZE];
  char lock_delay_subtitle[DELAY_SUBTITLE_BUF_SIZE];
  char shred_delay_subtitle[DELAY_SUBTITLE_BUF_SIZE];
  //! What Lockdown will actually do, which is the Erase After setting read from
  //! the moment it is pressed. The only place the concrete delay appears
  //! alongside the action it applies to.
  char lockdown_subtitle[DELAY_SUBTITLE_BUF_SIZE];

  //! Erase After rows, filtered down to those still legal for the current Lock
  //! After. Held here because the option menu keeps the array rather than
  //! copying it, and this menu is always below it on the stack.
  const char *shred_rows[NUM_SHRED_DELAY_OPTIONS];
  //! Index into the unfiltered option table for each of those rows.
  uint8_t shred_row_option[NUM_SHRED_DELAY_OPTIONS];
  uint8_t num_shred_rows;
} SettingsSecurityData;

//! The two lengths a PIN may be. Deliberately a list and not a range:
//! security_lock_set_pin() rejects anything between them, so offering a five
//! would be a row that cannot be used.
static const uint8_t s_pin_lengths[] = {4, 6};

static const char *s_pin_length_labels[] = {
    i18n_noop("4 digits"),
    i18n_noop("6 digits"),
};

_Static_assert(ARRAY_LENGTH(s_pin_lengths) == ARRAY_LENGTH(s_pin_length_labels),
               "Every offered PIN length needs a label");
_Static_assert(4 >= SECURITY_LOCK_PIN_MIN_LEN && 6 <= SECURITY_LOCK_PIN_MAX_LEN,
               "Offered PIN lengths must be ones the lock state store accepts");

//! Index into s_pin_lengths, falling back to the first entry for a stored PIN
//! whose length is no longer offered.
static uint8_t prv_length_index(uint8_t pin_len) {
  for (uint8_t i = 0; i < ARRAY_LENGTH(s_pin_lengths); ++i) {
    if (s_pin_lengths[i] == pin_len) {
      return i;
    }
  }
  return 0;
}

static bool prv_pin_is_set(SettingsSecurityData *data) {
  return data->current_pin_len >= SECURITY_LOCK_PIN_MIN_LEN;
}

//! Render a delay for a menu row.
//!
//! Says what it is counted from, because both delays are counted from the
//! disconnect and neither from the other: with the defaults the watch locks at
//! five minutes and erases at thirty, which is twenty-five minutes after the
//! lock rather than thirty. Read the other way round the user believes they
//! have longer than they do.
//!
//! Formatted from the stored value rather than looked up in the option tables,
//! so a delay the phone set that this picker does not offer is still reported
//! as what it actually is.
static void prv_format_delay(uint32_t seconds, char *buf, size_t buf_size) {
  char format[DELAY_SUBTITLE_BUF_SIZE];
  if ((seconds >= DELAY_SECONDS_PER_HOUR) && ((seconds % DELAY_SECONDS_PER_HOUR) == 0)) {
    /// Subtitle on the Lock After and Erase After rows, in hours. "%u hr after
    /// the phone disconnected", abbreviated to fit one line.
    i18n_get_with_buffer(i18n_noop("%u hr after disconnect"), format, sizeof(format));
    sniprintf(buf, buf_size, format, (unsigned)(seconds / DELAY_SECONDS_PER_HOUR));
  } else {
    /// Same, in minutes.
    i18n_get_with_buffer(i18n_noop("%u min after disconnect"), format, sizeof(format));
    sniprintf(buf, buf_size, format, (unsigned)(seconds / DELAY_SECONDS_PER_MINUTE));
  }
}

//! Render the Erase After delay as what Lockdown will do with it.
//!
//! Stated on the action rather than only on the setting, because the two rows
//! answer different questions: Erase After says what the number is and what it
//! is counted from, and this says what pressing the row above it will cost.
//! Without it, the only way to learn that Lockdown starts an erase at all is to
//! read a setting three rows up and join them yourself.
static void prv_format_lockdown(uint32_t seconds, char *buf, size_t buf_size) {
  char format[DELAY_SUBTITLE_BUF_SIZE];
  if ((seconds >= DELAY_SECONDS_PER_HOUR) && ((seconds % DELAY_SECONDS_PER_HOUR) == 0)) {
    /// Subtitle on the Lockdown row, in hours: the watch locks now and erases
    /// after this long unless the PIN is entered first.
    i18n_get_with_buffer(i18n_noop("Locks, erases in %u hr"), format, sizeof(format));
    sniprintf(buf, buf_size, format, (unsigned)(seconds / DELAY_SECONDS_PER_HOUR));
  } else {
    /// Same, in minutes.
    i18n_get_with_buffer(i18n_noop("Locks, erases in %u min"), format, sizeof(format));
    sniprintf(buf, buf_size, format, (unsigned)(seconds / DELAY_SECONDS_PER_MINUTE));
  }
}

//! Recompute the cached state the rows are drawn from. Reads flash, so it is
//! done here rather than in draw_row, which MenuLayer calls on every redraw.
static void prv_update_state(SettingsSecurityData *data) {
  // Deliberately does not touch new_pin_len. That belongs to the flow currently
  // in progress: this runs on every appear, and the picker sits between the
  // menu and the pad.
  data->current_pin_len = security_lock_get_pin_len();
  // A PIN and the switch are the same fact now, since turning it off discards
  // the PIN. Anded anyway, so a record where they disagree reads Off and offers
  // the one row that repairs it rather than a menu of controls with nothing
  // behind them.
  data->enabled = security_lock_is_enabled() && prv_pin_is_set(data);

  // i18n_get_with_buffer rather than i18n_get: these are rebuilt on every
  // refresh and there is no reason to keep an owned translation around for a
  // string that is immediately copied.
  if (data->enabled) {
    i18n_get_with_buffer(i18n_noop("On"), data->enabled_subtitle, sizeof(data->enabled_subtitle));
  } else {
    i18n_get_with_buffer(i18n_ctx_noop("SecurityLock", "Off"), data->enabled_subtitle,
                         sizeof(data->enabled_subtitle));
  }

  // Deliberately not On/Off: that is what the master switch above says, and a
  // second row saying it too reads as a separate control. This row is about the
  // credential, so it reports the credential. Only drawn while there is one.
  if (prv_pin_is_set(data)) {
    char format[SUBTITLE_BUF_SIZE];
    /// Subtitle on the Change PIN row: a PIN exists and is this many digits.
    i18n_get_with_buffer(i18n_noop("Set, %u digits"), format, sizeof(format));
    sniprintf(data->pin_subtitle, sizeof(data->pin_subtitle), format,
              (unsigned)data->current_pin_len);
  } else {
    data->pin_subtitle[0] = '\0';
  }

  data->lock_delay_s = security_lock_get_lock_delay_s();
  data->shred_delay_s = security_lock_get_shred_delay_s();
  prv_format_delay(data->lock_delay_s, data->lock_delay_subtitle,
                   sizeof(data->lock_delay_subtitle));
  if (data->shred_delay_s == SECURITY_LOCK_SHRED_DELAY_NEVER) {
    /// Erase After when the timed erase is off. Says the watch still locks,
    /// because turning the erase off is not turning the feature off.
    i18n_get_with_buffer(i18n_noop("Never, locks only"), data->shred_delay_subtitle,
                         sizeof(data->shred_delay_subtitle));
    /// Subtitle on the Lockdown row when Erase After is Never. Setting Never is
    /// how a user gets lock-without-erase, so the row has to stop promising one
    /// rather than show a bare zero.
    i18n_get_with_buffer(i18n_noop("Locks, no timed erase"), data->lockdown_subtitle,
                         sizeof(data->lockdown_subtitle));
  } else {
    prv_format_delay(data->shred_delay_s, data->shred_delay_subtitle,
                     sizeof(data->shred_delay_subtitle));
    prv_format_lockdown(data->shred_delay_s, data->lockdown_subtitle,
                        sizeof(data->lockdown_subtitle));
  }
}

//! Only safe once the settings window exists: settings_menu_reload_data() goes
//! through app-state user data, which settings_window_create() installs.
static void prv_refresh(SettingsSecurityData *data) {
  prv_update_state(data);
  settings_menu_reload_data(SettingsMenuItemSecurity);
  settings_menu_mark_dirty(SettingsMenuItemSecurity);
}

// PIN prompt
//////////////////////////////////////////////////////////////////////////////

static void prv_set_prompt_message(SettingsSecurityData *data, const char *text) {
  char message[SECURITY_PIN_MESSAGE_BUF_SIZE];
  i18n_get_with_buffer(text, message, sizeof(message));
  security_pin_entry_window_set_message(&data->pin_window, message);
}

static void prv_show_attempts_left(SettingsSecurityData *data, uint8_t left) {
  char format[SECURITY_PIN_MESSAGE_BUF_SIZE];
  char message[SECURITY_PIN_MESSAGE_BUF_SIZE];
  i18n_get_with_buffer((left == 1) ? i18n_noop("Wrong PIN, 1 try left")
                                   : i18n_noop("Wrong PIN, %u tries left"),
                       format, sizeof(format));
  sniprintf(message, sizeof(message), format, (unsigned)left);
  security_pin_entry_window_set_message(&data->pin_window, message);
}

//! Check a PIN the user typed to authorise a change here in Settings.
//!
//! security_lock_verify_pin() is the only thing that knows the salt and the
//! stored verifier, so it has to be what does the comparison. But its
//! failed-attempt counter is the lock screen's, and reaching three there is
//! what makes the lock screen shred. Leaving a Settings fumble on that counter
//! would mean the user's next typo on a real lock screen wipes the watch, which
//! is not a consequence anyone would expect from a menu they backed out of.
//!
//! Only a success puts the counter back. A wrong entry here costs an attempt
//! exactly as it does on the lock screen, so this menu cannot be used as a
//! free PIN oracle -- and cannot zero a counter the lock screen is relying on.
//!
//! A duress PIN authorises these prompts exactly as the real one does, and the
//! store queues the wipe that comes with it. Nothing here needs to know which
//! was typed -- except the switch-off prompt, which uses the variant below.
static bool prv_verify_current_pin(const char *digits, uint8_t len) {
  const bool matched = security_lock_verify_pin(digits, len, NULL);
  if (matched) {
    security_lock_reset_failed_attempts();
  }
  return matched;
}

//! Same, for the switch-off prompt, which is told which PIN matched.
//!
//! It has to be: a duress PIN there must wipe and then turn the feature off,
//! and security_lock_shred() refuses once the feature is off. Letting the store
//! queue the wipe as usual and carrying on to disable would leave the order to
//! the scheduler -- the wipe runs on the launcher task and this on the app
//! task -- so one outcome is a lock disarmed with nothing erased, on precisely
//! the compelled entry the duress PIN exists for. See prv_duress_disable_cb().
static SecurityPinVerdict prv_verify_disable_pin(const char *digits, uint8_t len) {
  const SecurityPinVerdict verdict = security_lock_verify_pin_verdict(digits, len);
  if (verdict != SecurityPinVerdictWrong) {
    security_lock_reset_failed_attempts();
  }
  return verdict;
}

static void prv_finish_prompt(SettingsSecurityData *data) {
  memset(data->first_entry, 0, sizeof(data->first_entry));
  security_pin_entry_window_reset(&data->pin_window);
  app_window_stack_remove(&data->pin_window.window, true /* animated */);
}

//! How long the PIN being collected must be.
//!
//! A duress PIN is pinned to the real PIN's length rather than offered a choice
//! of its own. security_lock_verify_pin() only tries the duress hash when the
//! entered length matches its stored length, and the lock screen only ever
//! prompts for the real PIN's length -- so a duress PIN of the other length
//! could never be typed in, and would look configured while doing nothing.
static uint8_t prv_new_pin_len(const SettingsSecurityData *data) {
  return (data->target == PinTargetDuress) ? data->current_pin_len : data->new_pin_len;
}

static void prv_begin_new_pin(SettingsSecurityData *data) {
  data->stage = PinStageNewFirst;
  security_pin_entry_window_set_pin_len(&data->pin_window, prv_new_pin_len(data));
  security_pin_entry_window_set_title(
      &data->pin_window, (data->target == PinTargetDuress) ? i18n_get("New duress PIN", data)
                                                           : i18n_get("New PIN", data));
  security_pin_entry_window_set_message(&data->pin_window, NULL);
}

//! Report a store refusal on the prompt rather than dropping the user back into
//! the menu with nothing changed and no reason given.
//!
//! Says nothing a duress PIN could be inferred from: "must differ" can only be
//! reached by someone who has just typed their own real PIN, so it tells them
//! nothing they did not already supply.
static void prv_report_store_failure(SettingsSecurityData *data, status_t rv) {
  if (rv == E_INVALID_ARGUMENT) {
    prv_set_prompt_message(data, i18n_noop("Must differ from your PIN"));
  } else {
    prv_set_prompt_message(data, i18n_noop("Could not save that PIN"));
  }
  data->stage = PinStageNewFirst;
  memset(data->first_entry, 0, sizeof(data->first_entry));
}

static void prv_handle_wrong_pin(SettingsSecurityData *data) {
  data->auth_attempts++;
  if (data->auth_attempts >= SETTINGS_PIN_ATTEMPTS) {
    PBL_LOG_DBG("Settings PIN prompt gave up after %u attempts", (unsigned)data->auth_attempts);
    prv_finish_prompt(data);
    return;
  }
  prv_show_attempts_left(data, SETTINGS_PIN_ATTEMPTS - data->auth_attempts);
}

//! Defined below with the rest of the picker.
static void prv_length_menu_push(SettingsSecurityData *data);

//! What a duress PIN at the switch-off prompt does: everything the real PIN
//! does, with a wipe in front of it.
//!
//! One callback rather than two, and on the launcher task rather than split
//! across two tasks. The order is not an implementation detail --
//! security_lock_shred() refuses once the feature is off, so a switch-off that
//! landed first would silently erase nothing -- and anything spread across two
//! tasks has the scheduler decide it.
//!
//! Runs on KernelMain, which security_lock_shred() requires: it tears down the
//! app and modal stacks and blocks for the length of the wipe. This app is one
//! of the things it closes, so nothing may follow that touches app state.
static void prv_duress_disable_cb(void *unused) {
  security_lock_shred(SecurityShredReasonDuressPin);

  // Not conditional on what the wipe destroyed: with nothing written since the
  // last one it legitimately erases nothing, and the switch still has to work.
  const status_t rv = security_lock_disable();
  if (rv != S_SUCCESS) {
    PBL_LOG_ERR("Refused to turn the security lock off after a duress wipe (%" PRId32 ")",
                (int32_t)rv);
  }
}

static void prv_pin_submit(const char *digits, uint8_t len, void *context) {
  SettingsSecurityData *data = context;

  switch (data->stage) {
    case PinStageAuthorizeSet:
      if (!prv_verify_current_pin(digits, len)) {
        prv_handle_wrong_pin(data);
        return;
      }
      if (data->target == PinTargetDuress) {
        // No length to pick: a duress PIN is pinned to the real PIN's length.
        prv_begin_new_pin(data);
        return;
      }
      // The length is chosen as part of setting the PIN rather than in a row of
      // its own, so the pad steps aside for the picker. Removed rather than left
      // underneath it: BACK out of the picker should reach the menu, not a
      // prompt whose authorisation has already been spent.
      prv_finish_prompt(data);
      prv_length_menu_push(data);
      return;

    case PinStageAuthorizeDisable: {
      const SecurityPinVerdict verdict = prv_verify_disable_pin(digits, len);
      if (verdict == SecurityPinVerdictWrong) {
        prv_handle_wrong_pin(data);
        return;
      }
      if (verdict == SecurityPinVerdictDuress) {
        // Accepted, and it looks accepted: the prompt goes away before anything
        // else happens, exactly as it does for the real PIN. The wipe takes the
        // app with it a moment later, which is the one thing that cannot be
        // made to match -- see docs/architecture/security_lock.md.
        //
        // Popped before the callback is queued, in the same order Lock Now
        // uses: the launcher may run it the instant it is queued.
        prv_finish_prompt(data);
        launcher_task_add_callback(prv_duress_disable_cb, NULL);
        return;
      }
      PBL_LOG_DBG("Turning the security lock off");
      const status_t rv = security_lock_disable();
      if (rv != S_SUCCESS) {
        // Only refused while Locked, where this menu is unreachable. Stay put
        // and say so: popping back to a menu that still reads "On" would look
        // like the switch had simply been ignored.
        PBL_LOG_ERR("Refused to turn the security lock off (%" PRId32 ")", (int32_t)rv);
        prv_set_prompt_message(data, i18n_noop("Could not turn it off"));
        return;
      }
      prv_finish_prompt(data);
      prv_refresh(data);
      return;
    }

    case PinStageNewFirst:
      memcpy(data->first_entry, digits, len);
      data->stage = PinStageNewRepeat;
      security_pin_entry_window_set_title(&data->pin_window, i18n_get("Repeat PIN", data));
      security_pin_entry_window_set_message(&data->pin_window, NULL);
      return;

    case PinStageNewRepeat: {
      if (memcmp(data->first_entry, digits, len) != 0) {
        memset(data->first_entry, 0, sizeof(data->first_entry));
        prv_begin_new_pin(data);
        prv_set_prompt_message(data, i18n_noop("PINs did not match"));
        return;
      }
      PBL_LOG_DBG("Setting a %u digit PIN", (unsigned)len);
      const status_t rv = (data->target == PinTargetDuress)
                              ? security_lock_set_duress_pin(digits, len)
                              : security_lock_set_pin(digits, len);
      if (rv != S_SUCCESS) {
        PBL_LOG_ERR("Failed to set the PIN (%" PRId32 ")", (int32_t)rv);
        prv_report_store_failure(data, rv);
        return;
      }
      prv_finish_prompt(data);
      prv_refresh(data);
      return;
    }

    default:
      WTF;
  }
}

static void prv_push_pin_prompt(SettingsSecurityData *data, PinStage stage, PinTarget target) {
  data->stage = stage;
  data->target = target;
  // Seeded from the persisted counter rather than zeroed, so backing out of the
  // row and coming back does not hand the budget out again.
  data->auth_attempts = MIN(security_lock_get_failed_attempts(), SETTINGS_PIN_ATTEMPTS);
  memset(data->first_entry, 0, sizeof(data->first_entry));

  const bool authorizing =
      (stage == PinStageAuthorizeSet) || (stage == PinStageAuthorizeDisable);
  const uint8_t len = authorizing ? data->current_pin_len : prv_new_pin_len(data);

  security_pin_entry_window_init(&data->pin_window, len, prv_pin_submit, data);
  // Unlike the lock screen, this one the user is allowed to walk away from.
  security_pin_entry_window_set_cancelable(&data->pin_window, true);
  security_pin_entry_window_set_title(
      &data->pin_window, authorizing ? i18n_get("Current PIN", data)
                                     : ((target == PinTargetDuress)
                                            ? i18n_get("New duress PIN", data)
                                            : i18n_get("New PIN", data)));
  if (stage == PinStageAuthorizeDisable) {
    /// Message on the PIN prompt that guards turning the feature off. Off is a
    /// clean slate rather than a pause, so say what it costs before it is typed.
    prv_set_prompt_message(data, i18n_noop("Turning off clears your PIN"));
  }

  app_window_stack_push(&data->pin_window.window, true /* animated */);
}


// PIN length
//////////////////////////////////////////////////////////////////////////////
//
// A step in the set-PIN flow rather than a row of its own. It has to be: with
// the menu down to the master switch while the feature is off, there is nowhere
// for a standalone row to live, and a first PIN would silently get whatever
// length happened to be stored. Folding it in also retires the old two-step
// dance -- pick a length, then go and change the PIN -- which was awkward
// enough to be listed as a known wart.

static void prv_length_menu_select(OptionMenu *option_menu, int selection, void *context) {
  SettingsSecurityData *data = settings_option_menu_get_context(context);
  data->new_pin_len = s_pin_lengths[selection];
  // Removed before the pad goes up, so the picker is not left underneath a
  // prompt it would reappear behind on the way back.
  app_window_stack_remove(&option_menu->window, true /* animated */);
  prv_push_pin_prompt(data, PinStageNewFirst, PinTargetMain);
}

//! Ask which length the PIN being set should be, then collect it.
static void prv_length_menu_push(SettingsSecurityData *data) {
  // Changing a PIN keeps its length unless the user says otherwise; a first one
  // starts at the shortest offered.
  const uint8_t opens_on = prv_pin_is_set(data) ? data->current_pin_len : s_pin_lengths[0];

  const OptionMenuCallbacks callbacks = {
    .select = prv_length_menu_select,
  };
  settings_option_menu_push(i18n_noop("PIN Length"), OptionMenuContentType_SingleLine,
                            prv_length_index(opens_on), &callbacks,
                            ARRAY_LENGTH(s_pin_length_labels), false /* icons_enabled */,
                            s_pin_length_labels, data);
}

// Lock After / Erase After
//////////////////////////////////////////////////////////////////////////////
//
// Both delays run from the moment the phone went away, so each constrains the
// other: an erase scheduled before the lock would destroy the data without the
// lock screen ever having offered a way to stop it, and
// security_lock_set_delays() refuses that pair outright. Nothing reachable by
// ordinary navigation may produce it.

//! Longest offered Lock After. Beyond an hour this is no longer riding out a
//! phone reboot or a walk out of range, it is just not locking.
#define LOCK_DELAY_MAX_S (60 * 60)

//! Longest offered Erase After. A phone that stays off overnight is exactly
//! what this has to be able to survive.
#define SHRED_DELAY_MAX_S (24 * 60 * 60)

static const uint32_t s_lock_delays_s[] = {60, 5 * 60, 15 * 60, 30 * 60, LOCK_DELAY_MAX_S};

static const char *s_lock_delay_labels[] = {
    i18n_noop("1 Minute"),   i18n_noop("5 Minutes"), i18n_noop("15 Minutes"),
    i18n_noop("30 Minutes"), i18n_noop("1 Hour"),
};

//! Never is last rather than first: it is the weakest choice on the list, not
//! the one to land on by accident.
static const uint32_t s_shred_delays_s[] = {
    30 * 60,
    60 * 60,
    2 * 60 * 60,
    4 * 60 * 60,
    8 * 60 * 60,
    SHRED_DELAY_MAX_S,
    SECURITY_LOCK_SHRED_DELAY_NEVER,
};

static const char *s_shred_delay_labels[] = {
    i18n_noop("30 Minutes"),
    i18n_noop("1 Hour"),
    i18n_noop("2 Hours"),
    i18n_noop("4 Hours"),
    i18n_noop("8 Hours"),
    i18n_noop("24 Hours"),
    /// Erase After option that arms no erase timer at all.
    i18n_ctx_noop("SecurityLock", "Never"),
};

_Static_assert(ARRAY_LENGTH(s_lock_delays_s) == ARRAY_LENGTH(s_lock_delay_labels),
               "Every offered lock delay needs a label");
_Static_assert(ARRAY_LENGTH(s_shred_delays_s) == ARRAY_LENGTH(s_shred_delay_labels),
               "Every offered erase delay needs a label");
_Static_assert(ARRAY_LENGTH(s_shred_delays_s) == NUM_SHRED_DELAY_OPTIONS,
               "The filtered row buffer has to hold every erase option");
//! Otherwise raising Lock After to its longest would leave Never as the only
//! legal Erase After, turning the timed erase off without being asked to.
_Static_assert(LOCK_DELAY_MAX_S <= SHRED_DELAY_MAX_S,
               "The longest lock delay needs a real erase option at or past it");

//! Never schedules no erase at all, so it is never "before the lock".
static bool prv_shred_delay_is_valid(uint32_t shred_delay_s, uint32_t lock_delay_s) {
  return (shred_delay_s == SECURITY_LOCK_SHRED_DELAY_NEVER) || (shred_delay_s >= lock_delay_s);
}

//! Index of the option holding `value`, or OPTION_MENU_CHOICE_NONE for a delay
//! the phone set that is not offered here. No row highlighted beats the wrong
//! row highlighted.
static int prv_option_index(uint32_t value, const uint32_t *values, size_t count) {
  for (size_t i = 0; i < count; ++i) {
    if (values[i] == value) {
      return (int)i;
    }
  }
  return OPTION_MENU_CHOICE_NONE;
}

//! Raise an erase delay the lock delay has overtaken to the shortest option
//! still at or past it, so moving Lock After up can never leave the pair in a
//! state the store refuses.
static uint32_t prv_clamp_shred_delay(uint32_t shred_delay_s, uint32_t lock_delay_s) {
  if (prv_shred_delay_is_valid(shred_delay_s, lock_delay_s)) {
    return shred_delay_s;
  }
  // Ascending with Never last, so this lands on a real erase rather than
  // turning the timed erase off behind the user's back.
  for (size_t i = 0; i < ARRAY_LENGTH(s_shred_delays_s); ++i) {
    if (prv_shred_delay_is_valid(s_shred_delays_s[i], lock_delay_s)) {
      return s_shred_delays_s[i];
    }
  }
  return SECURITY_LOCK_SHRED_DELAY_NEVER;
}

static void prv_apply_delays(SettingsSecurityData *data, uint32_t lock_delay_s,
                             uint32_t shred_delay_s) {
  const uint32_t erase_delay_s = prv_clamp_shred_delay(shred_delay_s, lock_delay_s);
  const status_t rv = security_lock_set_delays(lock_delay_s, erase_delay_s);
  if (rv != S_SUCCESS) {
    // Unreachable from the pickers, which only offer legal pairs. Logged rather
    // than swallowed: a refusal and a saved setting look identical on screen.
    PBL_LOG_ERR("Rejected delays lock=%" PRIu32 "s erase=%" PRIu32 "s (%" PRId32 ")", lock_delay_s,
                erase_delay_s, (int32_t)rv);
  }
  // Re-reads what the store actually kept, so a refusal shows the old value
  // rather than the one that never took.
  prv_refresh(data);
}

static void prv_lock_delay_menu_select(OptionMenu *option_menu, int selection, void *context) {
  SettingsSecurityData *data = settings_option_menu_get_context(context);
  if ((selection >= 0) && (selection < (int)ARRAY_LENGTH(s_lock_delays_s))) {
    prv_apply_delays(data, s_lock_delays_s[selection], data->shred_delay_s);
  }
  app_window_stack_remove(&option_menu->window, true /* animated */);
}

static void prv_lock_delay_menu_push(SettingsSecurityData *data) {
  const OptionMenuCallbacks callbacks = {
    .select = prv_lock_delay_menu_select,
  };
  settings_option_menu_push(
      i18n_noop("Lock After"), OptionMenuContentType_SingleLine,
      prv_option_index(data->lock_delay_s, s_lock_delays_s, ARRAY_LENGTH(s_lock_delays_s)),
      &callbacks, ARRAY_LENGTH(s_lock_delay_labels), false /* icons_enabled */, s_lock_delay_labels,
      data);
}

//! Collect the Erase After rows that are still legal for the current Lock
//! After. Filtered rather than shown-and-refused: a row that cannot be chosen
//! is a row that should not be on the list.
static void prv_build_shred_rows(SettingsSecurityData *data) {
  data->num_shred_rows = 0;
  for (size_t i = 0; i < ARRAY_LENGTH(s_shred_delays_s); ++i) {
    if (!prv_shred_delay_is_valid(s_shred_delays_s[i], data->lock_delay_s)) {
      continue;
    }
    data->shred_rows[data->num_shred_rows] = s_shred_delay_labels[i];
    data->shred_row_option[data->num_shred_rows] = (uint8_t)i;
    data->num_shred_rows++;
  }
}

static void prv_shred_delay_menu_select(OptionMenu *option_menu, int selection, void *context) {
  SettingsSecurityData *data = settings_option_menu_get_context(context);
  if ((selection >= 0) && (selection < (int)data->num_shred_rows)) {
    // Back through the same map the rows were built with; the picker's indices
    // are into the filtered list, not the table.
    prv_apply_delays(data, data->lock_delay_s, s_shred_delays_s[data->shred_row_option[selection]]);
  }
  app_window_stack_remove(&option_menu->window, true /* animated */);
}

static void prv_shred_delay_menu_push(SettingsSecurityData *data) {
  prv_build_shred_rows(data);

  int choice = OPTION_MENU_CHOICE_NONE;
  for (uint8_t i = 0; i < data->num_shred_rows; ++i) {
    if (s_shred_delays_s[data->shred_row_option[i]] == data->shred_delay_s) {
      choice = i;
      break;
    }
  }

  const OptionMenuCallbacks callbacks = {
    .select = prv_shred_delay_menu_select,
  };
  settings_option_menu_push(i18n_noop("Erase After"), OptionMenuContentType_SingleLine, choice,
                            &callbacks, data->num_shred_rows, false /* icons_enabled */,
                            data->shred_rows, data);
}

// Lockdown and Lockdown + Erase
//////////////////////////////////////////////////////////////////////////////
//
// Two actions, because they make different promises and one row would have to
// describe one of them inaccurately -- always the destructive one. Lockdown
// locks and starts the Erase After countdown, which the PIN calls off, exactly
// as a disconnect countdown behaves. Lockdown + Erase destroys the content
// there and then.
//
// There is deliberately no third "lock only" row: that is Erase After set to
// Never, which the countdown action honours by arming nothing. A separate row
// would be the same outcome reachable two ways, and the setting is the one the
// disconnect path already obeys.

//! Runs on KernelMain, which both funnels assert on: they kill the running app
//! (this one), and the erasing one blocks for the length of the wipe.
static void prv_countdown_callback(void *unused) {
  security_lock_engage_with_countdown(SecurityShredReasonManualPanic);
}

static void prv_erase_now_callback(void *unused) {
  security_lock_engage(SecurityShredReasonManualPanic);
}

static void prv_lockdown_confirm(ClickRecognizerRef recognizer, void *e_dialog) {
  expandable_dialog_pop(e_dialog);
  launcher_task_add_callback(prv_countdown_callback, NULL);
}

static void prv_lockdown_erase_confirm(ClickRecognizerRef recognizer, void *e_dialog) {
  expandable_dialog_pop(e_dialog);
  launcher_task_add_callback(prv_erase_now_callback, NULL);
}

//! Push a confirmation, and hand over only if the user takes it.
//!
//! Nothing happens when the dialog cannot be built, rather than locking or
//! erasing without having said what it costs.
//!
//! `name` goes through WINDOW_NAME() for the window, which compiles it out of a
//! release build, and is used raw for the log, where log strings cost no flash.
//! So the two rows stay distinguishable in a capture from a shipping watch.
static void prv_push_confirmation(const char *name, const char *header, const char *text,
                                  ClickHandler confirm) {
  ExpandableDialog *e_dialog = expandable_dialog_create_with_params(
      WINDOW_NAME(name), RESOURCE_ID_GENERIC_WARNING_LARGE, text, GColorBlack, GColorWhite, NULL,
      RESOURCE_ID_ACTION_BAR_ICON_CHECK, confirm);
  if (!e_dialog) {
    PBL_LOG_ERR("Could not create the %s confirmation", name);
    return;
  }
  expandable_dialog_set_header(e_dialog, header);
  app_expandable_dialog_push(e_dialog);
}

static void prv_lockdown_push(SettingsSecurityData *data) {
  /// Explanation shown before the watch locks and starts the erase countdown.
  /// The delay itself is on the row, so this says what stops it rather than
  /// repeating a number: the countdown is the part users have to know is
  /// escapable.
  const char *text = i18n_get(
      "Locks the watch behind your PIN straight away, then erases its copy of "
      "your notifications, calendar, reminders, contacts and weather when Erase "
      "After runs out.\n\n"
      "Entering your PIN before then cancels the erase. Rebooting does not.\n\n"
      "Step and sleep history is never erased, and your phone puts the rest "
      "back when you unlock and reconnect.\n\n"
      "Nothing on the watch is encrypted. This protects the screen, not the "
      "flash.",
      data);

  prv_push_confirmation("Lockdown", i18n_get("Lockdown", data), text,
                        prv_lockdown_confirm);
}

static void prv_lockdown_erase_push(SettingsSecurityData *data) {
  /// Explanation shown before the watch locks and erases its copy of the
  /// phone's content on the spot. Says what goes, what stays, and what this is
  /// not.
  const char *text = i18n_get(
      "Locks the watch behind your PIN and erases its copy of your "
      "notifications, calendar, reminders, contacts and weather immediately. "
      "There is no countdown and your PIN will not bring it back.\n\n"
      "Your phone puts them back when you unlock and reconnect.\n\n"
      "Step and sleep history is not erased.\n\n"
      "Nothing on the watch is encrypted. This protects the screen, not the "
      "flash.",
      data);

  prv_push_confirmation("Lockdown + Erase", i18n_get("Lockdown + Erase", data), text,
                        prv_lockdown_erase_confirm);
}

// Menu
//////////////////////////////////////////////////////////////////////////////

enum SettingsSecurityItem {
  //! First, and the only one that survives the feature being turned off.
  SettingsSecurityEnabled,
  SettingsSecurityPin,
  SettingsSecurityLockDelay,
  SettingsSecurityShredDelay,
  SettingsSecurityDuressPin,
  SettingsSecurityBlockNotifications,
  //! The recoverable one first: it is the row to land on by accident.
  SettingsSecurityLockdown,
  SettingsSecurityLockdownErase,
  SettingsSecurityLockdownInLauncher,
  NumSettingsSecurityItems
};

//! Off leaves exactly one row.
//!
//! Every other row configures or triggers something that does not exist while
//! the feature is off -- there is no PIN to change, nothing to time, nothing to
//! erase -- and a row that does nothing is worse than no row: it reads as a
//! control. There is no Clear PIN either: clearing the PIN is what turning it
//! off does, so the two would be the same button under different names.
//!
//! Nothing here may consult security_lock_has_duress_pin().
//!
//! Whether a duress PIN exists is the one thing this menu must not reveal --
//! someone who can make you unlock can also make you open Settings, and the
//! duress PIN only works if they cannot tell it is there. A "Clear duress PIN"
//! row that came and went would leak that bit exactly as loudly as a subtitle
//! would, so the row set is identical either way: one row that always offers to
//! set a new one, and clearing that happens only as a side effect of turning
//! the feature off.
static bool prv_item_is_visible(SettingsSecurityData *data, uint16_t item) {
  return (item == SettingsSecurityEnabled) || data->enabled;
}

static uint16_t prv_item_from_row(SettingsSecurityData *data, uint16_t row) {
  uint16_t visible_row = 0;
  for (uint16_t item = 0; item < NumSettingsSecurityItems; item++) {
    if (!prv_item_is_visible(data, item)) {
      continue;
    }
    if (visible_row == row) {
      return item;
    }
    visible_row++;
  }
  WTF;
}

static uint16_t prv_num_rows_cb(SettingsCallbacks *context) {
  SettingsSecurityData *data = (SettingsSecurityData *)context;
  uint16_t rows = 0;
  for (uint16_t item = 0; item < NumSettingsSecurityItems; item++) {
    if (prv_item_is_visible(data, item)) {
      rows++;
    }
  }
  return rows;
}

static void prv_draw_row_cb(SettingsCallbacks *context, GContext *ctx, const Layer *cell_layer,
                            uint16_t row, bool selected) {
  SettingsSecurityData *data = (SettingsSecurityData *)context;
  const char *title = NULL;
  //! Already localised by the time it gets here; the two cached subtitles are
  //! built by prv_update_state() and must not be fed back through i18n_get().
  const char *subtitle = NULL;

  switch (prv_item_from_row(data, row)) {
    case SettingsSecurityEnabled:
      /// The master switch for the whole feature. Off means the watch never
      /// locks itself and never erases anything, whatever asks it to.
      title = i18n_noop("Security Lock");
      subtitle = data->enabled_subtitle;
      break;
    case SettingsSecurityPin:
      // Only drawn while the feature is on, which means a PIN exists.
      title = i18n_noop("Change PIN");
      subtitle = data->pin_subtitle;
      break;
    case SettingsSecurityLockDelay:
      /// How long after the phone disconnects the watch locks itself.
      title = i18n_noop("Lock After");
      subtitle = data->lock_delay_subtitle;
      break;
    case SettingsSecurityShredDelay:
      /// How long after the phone disconnects the watch erases its copy of the
      /// phone's content. Measured from the disconnect, not from the lock.
      title = i18n_noop("Erase After");
      subtitle = data->shred_delay_subtitle;
      break;
    case SettingsSecurityDuressPin:
      title = i18n_noop("Duress PIN");
      // No subtitle, deliberately: any state shown here is the state that has
      // to stay hidden, and "Off" versus "On" is the whole secret.
      break;
    case SettingsSecurityLockdown:
      /// Lock now, erase at the configured Erase After unless the PIN is
      /// entered first. The same action the Lockdown app and the Quick Launch
      /// chord perform.
      title = i18n_noop("Lockdown");
      subtitle = data->lockdown_subtitle;
      break;
    case SettingsSecurityLockdownErase:
      /// Lock now and erase now. Named so the difference from the row above is
      /// the destructive word rather than a shade of wording.
      title = i18n_noop("Lockdown + Erase");
      /// Subtitle on the Lockdown + Erase row. "Now" is the whole difference
      /// from the row above, so it is said here and not only in the
      /// confirmation.
      subtitle = i18n_get(i18n_noop("Locks and erases now"), data);
      break;
    case SettingsSecurityBlockNotifications:
      /// Whether a notification arriving while the watch is locked is refused
      /// outright or kept, unshown, for whoever unlocks.
      title = i18n_noop("Block Notifications");
      if (shell_prefs_get_block_notifications_when_locked()) {
        /// Subtitle when notifications are refused while locked. Says what
        /// happens to them, since "On" alone does not.
        subtitle = i18n_get(i18n_noop("On, discarded while locked"), data);
      } else {
        /// Subtitle when they are kept. They are still never displayed on a
        /// locked watch, and saying so is the point of the row.
        subtitle = i18n_get(i18n_noop("Off, kept until unlocked"), data);
      }
      break;
    case SettingsSecurityLockdownInLauncher:
      /// Whether the Lockdown app is listed in the launcher. Off is decluttering
      /// only -- the app stays installed and stays bindable to a button.
      title = i18n_noop("Show in Launcher");
      if (shell_prefs_get_lockdown_app_in_launcher()) {
        subtitle = i18n_get(i18n_noop("On"), data);
      } else {
        /// Subtitle once Lockdown is off the launcher list. Says where it has
        /// gone rather than suggesting it is hidden from anyone: whoever takes
        /// the watch has no reason to erase the data they came for.
        subtitle = i18n_get(i18n_noop("Off, Quick Launch only"), data);
      }
      break;
    default:
      WTF;
  }

  menu_cell_basic_draw(ctx, cell_layer, i18n_get(title, data), subtitle, NULL);
}

static void prv_select_click_cb(SettingsCallbacks *context, uint16_t row) {
  SettingsSecurityData *data = (SettingsSecurityData *)context;

  switch (prv_item_from_row(data, row)) {
    case SettingsSecurityEnabled:
      if (!prv_pin_is_set(data)) {
        // Turning it on means having something to unlock with, so this is the
        // Set PIN flow -- and setting a PIN is itself what turns it on. Keyed
        // on the PIN rather than on the switch so a record where the two
        // disagree is repaired rather than made worse.
        prv_length_menu_push(data);
      } else {
        // Turning it off discards the PIN, so it has to be as protected as
        // unlocking is: otherwise anyone holding an unlocked watch could walk
        // in here and disarm the whole thing.
        prv_push_pin_prompt(data, PinStageAuthorizeDisable, PinTargetMain);
      }
      break;
    case SettingsSecurityPin:
      // Changing a PIN means proving you know the current one first.
      prv_push_pin_prompt(data, PinStageAuthorizeSet, PinTargetMain);
      break;
    case SettingsSecurityLockDelay:
      prv_lock_delay_menu_push(data);
      break;
    case SettingsSecurityShredDelay:
      prv_shred_delay_menu_push(data);
      break;
    case SettingsSecurityDuressPin:
      // Always straight to setting a new one. Asking "set or clear?" would
      // answer the question the menu exists to refuse to answer.
      prv_push_pin_prompt(data, PinStageAuthorizeSet, PinTargetDuress);
      break;
    case SettingsSecurityLockdown:
      prv_lockdown_push(data);
      break;
    case SettingsSecurityLockdownErase:
      prv_lockdown_erase_push(data);
      break;
    case SettingsSecurityBlockNotifications:
      shell_prefs_set_block_notifications_when_locked(
          !shell_prefs_get_block_notifications_when_locked());
      prv_refresh(data);
      break;
    case SettingsSecurityLockdownInLauncher:
      shell_prefs_set_lockdown_app_in_launcher(!shell_prefs_get_lockdown_app_in_launcher());
      prv_refresh(data);
      break;
    default:
      WTF;
  }
}

static void prv_appear_cb(SettingsCallbacks *context) {
  SettingsSecurityData *data = (SettingsSecurityData *)context;

  // Backing out of a prompt part way through leaves digits in both buffers with
  // nothing else to clear them, so this doubles as the cleanup for that. Done
  // by hand rather than through the window, which may never have been opened.
  memset(data->first_entry, 0, sizeof(data->first_entry));
  memset(data->pin_window.digits, 0, sizeof(data->pin_window.digits));

  // The rows depend on whether a PIN exists, which the prompts above change.
  prv_refresh(data);
}

static void prv_deinit_cb(SettingsCallbacks *context) {
  SettingsSecurityData *data = (SettingsSecurityData *)context;
  // Scrub the buffers directly rather than through the window: this runs even
  // when no prompt was ever opened, in which case the window was never
  // initialised and marking its layer dirty would be a walk through zeroes.
  memset(data->first_entry, 0, sizeof(data->first_entry));
  memset(data->pin_window.digits, 0, sizeof(data->pin_window.digits));
  i18n_free_all(data);
  app_free(data);
}

static Window *prv_init(void) {
  SettingsSecurityData *data = app_malloc_check(sizeof(*data));
  *data = (SettingsSecurityData){};

  data->callbacks = (SettingsCallbacks){
    .deinit = prv_deinit_cb,
    .draw_row = prv_draw_row_cb,
    .select_click = prv_select_click_cb,
    .num_rows = prv_num_rows_cb,
    .appear = prv_appear_cb,
  };

  // Always overwritten by the picker before a PIN is collected; seeded so it
  // can never hold a length the pad would clamp.
  data->new_pin_len = s_pin_lengths[0];
  prv_update_state(data);

  return settings_window_create(SettingsMenuItemSecurity, &data->callbacks);
}

const SettingsModuleMetadata *settings_security_get_info(void) {
  static const SettingsModuleMetadata s_module_info = {
    /// Title of the Security submenu in Settings, where the watch PIN is set.
    .name = i18n_noop("Security"),
    .init = prv_init,
  };

  return &s_module_info;
}

#endif // CONFIG_SERVICE_SECURITY_LOCK
