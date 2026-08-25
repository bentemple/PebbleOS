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
  //! Same, before being allowed to remove it.
  PinStageAuthorizeClear,
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

  //! Length the next PIN will be set to. Independent of the current PIN's
  //! length, which is what the authorize step prompts for.
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
  char length_subtitle[SUBTITLE_BUF_SIZE];
  char lock_delay_subtitle[DELAY_SUBTITLE_BUF_SIZE];
  char shred_delay_subtitle[DELAY_SUBTITLE_BUF_SIZE];

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

//! Recompute the cached state the rows are drawn from. Reads flash, so it is
//! done here rather than in draw_row, which MenuLayer calls on every redraw.
static void prv_update_state(SettingsSecurityData *data) {
  // Deliberately does not touch new_pin_len. That is seeded once in prv_init()
  // and otherwise belongs to the user: this runs on every appear, so seeding it
  // from the current PIN here would silently undo the PIN Length row every time
  // the menu came back into view.
  data->current_pin_len = security_lock_get_pin_len();
  data->enabled = security_lock_is_enabled();

  // i18n_get_with_buffer rather than i18n_get: these are rebuilt on every
  // refresh and there is no reason to keep an owned translation around for a
  // string that is immediately copied.
  if (data->enabled) {
    i18n_get_with_buffer(i18n_noop("On"), data->enabled_subtitle, sizeof(data->enabled_subtitle));
  } else if (prv_pin_is_set(data)) {
    /// Subtitle on the master switch when it is off but a PIN is stored. Says
    /// the PIN survives, so turning it back on does not mean setting one again.
    i18n_get_with_buffer(i18n_noop("Off, PIN kept"), data->enabled_subtitle,
                         sizeof(data->enabled_subtitle));
  } else {
    i18n_get_with_buffer(i18n_ctx_noop("SecurityLock", "Off"), data->enabled_subtitle,
                         sizeof(data->enabled_subtitle));
  }

  // Deliberately not On/Off: that is what the master switch above says now, and
  // "Change PIN -- On" beneath "Security Lock -- Off" reads as a contradiction.
  // This row is about the credential, so it reports the credential.
  if (prv_pin_is_set(data)) {
    char format[SUBTITLE_BUF_SIZE];
    /// Subtitle on the Change PIN row: a PIN exists and is this many digits.
    i18n_get_with_buffer(i18n_noop("Set, %u digits"), format, sizeof(format));
    sniprintf(data->pin_subtitle, sizeof(data->pin_subtitle), format,
              (unsigned)data->current_pin_len);
  } else {
    /// Subtitle on the Set PIN row when there is no PIN yet.
    i18n_get_with_buffer(i18n_noop("Not set"), data->pin_subtitle, sizeof(data->pin_subtitle));
  }

  i18n_get_with_buffer(s_pin_length_labels[prv_length_index(data->new_pin_len)],
                       data->length_subtitle, sizeof(data->length_subtitle));

  data->lock_delay_s = security_lock_get_lock_delay_s();
  data->shred_delay_s = security_lock_get_shred_delay_s();
  prv_format_delay(data->lock_delay_s, data->lock_delay_subtitle,
                   sizeof(data->lock_delay_subtitle));
  if (data->shred_delay_s == SECURITY_LOCK_SHRED_DELAY_NEVER) {
    /// Erase After when the timed erase is off. Says the watch still locks,
    /// because turning the erase off is not turning the feature off.
    i18n_get_with_buffer(i18n_noop("Never, locks only"), data->shred_delay_subtitle,
                         sizeof(data->shred_delay_subtitle));
  } else {
    prv_format_delay(data->shred_delay_s, data->shred_delay_subtitle,
                     sizeof(data->shred_delay_subtitle));
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
//! So the persistent counter is put back where it was and a local budget is
//! applied instead. That is not a weakening: the counter is only ever non-zero
//! while the watch is Locked (security_lock_set_state() zeroes it on any other
//! transition), and while Locked this menu is unreachable -- the lock screen
//! swallows every button and the app is dead. The only thing being undone here
//! is what this prompt itself just burned.
//!
//! The local budget is not rate limiting in any real sense either; someone
//! holding an unlocked watch has already won. It exists so that a menu cannot
//! be used as a frictionless PIN oracle.
static bool prv_verify_current_pin(const char *digits, uint8_t len) {
  const bool matched = security_lock_verify_pin(digits, len, NULL);
  security_lock_reset_failed_attempts();
  return matched;
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

static void prv_pin_submit(const char *digits, uint8_t len, void *context) {
  SettingsSecurityData *data = context;

  switch (data->stage) {
    case PinStageAuthorizeSet:
      if (!prv_verify_current_pin(digits, len)) {
        prv_handle_wrong_pin(data);
        return;
      }
      prv_begin_new_pin(data);
      return;

    case PinStageAuthorizeClear: {
      if (!prv_verify_current_pin(digits, len)) {
        prv_handle_wrong_pin(data);
        return;
      }
      PBL_LOG_DBG("Clearing PIN");
      const status_t rv = security_lock_clear_pin();
      if (rv != S_SUCCESS) {
        PBL_LOG_ERR("Failed to clear the PIN (%" PRId32 ")", (int32_t)rv);
        // Stay put and say why. Popping back to a menu that still reads "On"
        // would look like the clear had simply been ignored.
        prv_report_store_failure(data, rv);
        data->stage = PinStageAuthorizeClear;
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
  data->auth_attempts = 0;
  memset(data->first_entry, 0, sizeof(data->first_entry));

  const bool authorizing =
      (stage == PinStageAuthorizeSet) || (stage == PinStageAuthorizeClear);
  const uint8_t len = authorizing ? data->current_pin_len : prv_new_pin_len(data);

  security_pin_entry_window_init(&data->pin_window, len, prv_pin_submit, data);
  // Unlike the lock screen, this one the user is allowed to walk away from.
  security_pin_entry_window_set_cancelable(&data->pin_window, true);
  security_pin_entry_window_set_title(
      &data->pin_window, authorizing ? i18n_get("Current PIN", data)
                                     : ((target == PinTargetDuress)
                                            ? i18n_get("New duress PIN", data)
                                            : i18n_get("New PIN", data)));

  app_window_stack_push(&data->pin_window.window, true /* animated */);
}


// PIN length
//////////////////////////////////////////////////////////////////////////////

static void prv_length_menu_select(OptionMenu *option_menu, int selection, void *context) {
  SettingsSecurityData *data = settings_option_menu_get_context(context);
  data->new_pin_len = s_pin_lengths[selection];
  prv_refresh(data);
  app_window_stack_remove(&option_menu->window, true /* animated */);
}

static void prv_length_menu_push(SettingsSecurityData *data) {
  const OptionMenuCallbacks callbacks = {
    .select = prv_length_menu_select,
  };
  settings_option_menu_push(i18n_noop("PIN Length"), OptionMenuContentType_SingleLine,
                            prv_length_index(data->new_pin_len), &callbacks,
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

// Lock Now
//////////////////////////////////////////////////////////////////////////////

static void prv_engage_callback(void *unused) {
  // Runs on KernelMain, which security_lock_engage() asserts on: it kills the
  // running app (this one) and blocks for the length of the shred.
  security_lock_engage(SecurityShredReasonManualPanic);
}

static void prv_lock_now_confirm(ClickRecognizerRef recognizer, void *e_dialog) {
  expandable_dialog_pop(e_dialog);
  launcher_task_add_callback(prv_engage_callback, NULL);
}

static void prv_lock_now_push(SettingsSecurityData *data) {
  /// Explanation shown before the watch locks and erases its copy of the
  /// phone's content. Says what goes, what stays, and what this is not.
  const char *text = i18n_get(
      "Locks the watch behind your PIN and erases its copy of your "
      "notifications, calendar, reminders, contacts and weather. Your phone "
      "puts them back when you unlock and reconnect.\n\n"
      "Step and sleep history is not erased.\n\n"
      "Nothing on the watch is encrypted. This protects the screen, not the "
      "flash.", data);

  ExpandableDialog *e_dialog = expandable_dialog_create_with_params(
      WINDOW_NAME("Lock Now"), RESOURCE_ID_GENERIC_WARNING_LARGE, text, GColorBlack, GColorWhite,
      NULL, RESOURCE_ID_ACTION_BAR_ICON_CHECK, prv_lock_now_confirm);
  if (!e_dialog) {
    // Nothing happens rather than locking without having explained what it
    // destroys.
    PBL_LOG_ERR("Could not create the Lock Now confirmation");
    return;
  }
  expandable_dialog_set_header(e_dialog, i18n_get("Lock Now", data));
  app_expandable_dialog_push(e_dialog);
}

// Menu
//////////////////////////////////////////////////////////////////////////////

enum SettingsSecurityItem {
  //! First, because everything below it is inert while it is off.
  SettingsSecurityEnabled,
  SettingsSecurityPin,
  SettingsSecurityPinLength,
  SettingsSecurityLockDelay,
  SettingsSecurityShredDelay,
  SettingsSecurityDuressPin,
  SettingsSecurityClearPin,
  SettingsSecurityLockNow,
  SettingsSecurityLockdownInLauncher,
  NumSettingsSecurityItems
};

//! Nothing here may consult security_lock_has_duress_pin().
//!
//! Whether a duress PIN exists is the one thing this menu must not reveal --
//! someone who can make you unlock can also make you open Settings, and the
//! duress PIN only works if they cannot tell it is there. A "Clear duress PIN"
//! row that came and went would leak that bit exactly as loudly as a subtitle
//! would, so the row set is identical either way: one row that always offers to
//! set a new one, and clearing that happens only as a side effect of clearing
//! the real PIN.
//!
//! The master switch and the two PIN rows stay put whatever else is hidden.
//! Those three are how the feature is configured rather than things it does:
//! the length has to be pickable before a first PIN exists, and Clear PIN has
//! to stay reachable or a PIN kept across a switch-off could never be got rid
//! of without turning the feature back on first.
static bool prv_item_is_visible(SettingsSecurityData *data, uint16_t item) {
  //! Everything below the switch does nothing while it is off, and a row that
  //! does nothing is worse than no row: it reads as a control.
  const bool live = prv_pin_is_set(data) && data->enabled;

  switch (item) {
    case SettingsSecurityLockDelay:
    case SettingsSecurityShredDelay:
      // Without a PIN the watch neither locks nor erases when the phone goes
      // away, so a configured delay would be a countdown that never runs.
      return live;
    case SettingsSecurityDuressPin:
      // Follows the real PIN, which the row above already announces. Nothing
      // about the duress PIN itself is being disclosed.
      return live;
    case SettingsSecurityClearPin:
      return prv_pin_is_set(data);
    case SettingsSecurityLockNow:
      // Without a PIN there is nothing to unlock with, so this would erase
      // without locking. Offering it under this name would be a lie.
      return live;
    case SettingsSecurityLockdownInLauncher:
      // The app itself is hidden from the launcher and from Quick Launch
      // without a PIN, so this would offer to show something that is not there.
      // The stored preference is left alone and means what it meant again as
      // soon as a PIN is set.
      return live;
    default:
      return true;
  }
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
      title = prv_pin_is_set(data) ? i18n_noop("Change PIN") : i18n_noop("Set PIN");
      subtitle = data->pin_subtitle;
      break;
    case SettingsSecurityPinLength:
      title = i18n_noop("PIN Length");
      subtitle = data->length_subtitle;
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
    case SettingsSecurityClearPin:
      title = i18n_noop("Clear PIN");
      break;
    case SettingsSecurityLockNow:
      title = i18n_noop("Lock Now");
      /// Subtitle on the Lock Now row. The erase is the point, so say so here
      /// and not only in the confirmation.
      subtitle = i18n_get(i18n_noop("Lock and erase"), data);
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
    case SettingsSecurityEnabled: {
      if (!prv_pin_is_set(data)) {
        // Turning it on means having something to unlock with, so this is the
        // Set PIN flow -- and setting a PIN is itself what turns it on.
        prv_push_pin_prompt(data, PinStageNewFirst, PinTargetMain);
        break;
      }
      const status_t rv = security_lock_set_enabled(!data->enabled);
      if (rv != S_SUCCESS) {
        // Unreachable from here: the store only refuses this without a PIN,
        // handled above, or while Locked, where Settings cannot be reached.
        PBL_LOG_ERR("Refused to set the security lock enabled (%" PRId32 ")", (int32_t)rv);
      }
      prv_refresh(data);
      break;
    }
    case SettingsSecurityPin:
      if (!prv_pin_is_set(data)) {
        prv_push_pin_prompt(data, PinStageNewFirst, PinTargetMain);
      } else {
        // Changing a PIN means proving you know the current one first.
        prv_push_pin_prompt(data, PinStageAuthorizeSet, PinTargetMain);
      }
      break;
    case SettingsSecurityPinLength:
      prv_length_menu_push(data);
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
    case SettingsSecurityClearPin:
      prv_push_pin_prompt(data, PinStageAuthorizeClear, PinTargetMain);
      break;
    case SettingsSecurityLockNow:
      prv_lock_now_push(data);
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

  data->current_pin_len = security_lock_get_pin_len();
  // Changing a PIN keeps its length unless the user says otherwise; setting a
  // first one starts at the shortest offered. Routed through the table either
  // way so this can never hold a length the picker cannot show.
  data->new_pin_len =
      prv_pin_is_set(data) ? s_pin_lengths[prv_length_index(data->current_pin_len)]
                           : s_pin_lengths[0];
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
