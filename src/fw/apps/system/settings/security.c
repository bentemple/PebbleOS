/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include "security.h"

#ifdef CONFIG_SERVICE_SECURITY_LOCK

#include "menu.h"
#include "option_menu.h"
#include "window.h"

#include "applib/connection_service.h"
#include "applib/ui/app_window_stack.h"
#include "applib/ui/dialogs/dialog.h"
#include "applib/ui/dialogs/expandable_dialog.h"
#include "applib/ui/dialogs/simple_dialog.h"
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
#include "system/passert.h"
#include "pbl/util/size.h"

#include <stdio.h>
#include <string.h>

//! Wrong guesses tolerated at the Settings prompt before it gives up and drops
//! back to the menu. Deliberately NOT the lock screen's budget: see
//! prv_verify_current_pin().
#define SETTINGS_PIN_ATTEMPTS 3

#define SUBTITLE_BUF_SIZE 32

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

  char pin_subtitle[SUBTITLE_BUF_SIZE];
  char length_subtitle[SUBTITLE_BUF_SIZE];
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

//! Recompute the cached state the rows are drawn from. Reads flash, so it is
//! done here rather than in draw_row, which MenuLayer calls on every redraw.
static void prv_update_state(SettingsSecurityData *data) {
  // Deliberately does not touch new_pin_len. That is seeded once in prv_init()
  // and otherwise belongs to the user: this runs on every appear, so seeding it
  // from the current PIN here would silently undo the PIN Length row every time
  // the menu came back into view.
  data->current_pin_len = security_lock_get_pin_len();

  // i18n_get_with_buffer rather than i18n_get: these are rebuilt on every
  // refresh and there is no reason to keep an owned translation around for a
  // string that is immediately copied.
  if (prv_pin_is_set(data)) {
    char format[SUBTITLE_BUF_SIZE];
    i18n_get_with_buffer(i18n_noop("On, %u digits"), format, sizeof(format));
    sniprintf(data->pin_subtitle, sizeof(data->pin_subtitle), format,
              (unsigned)data->current_pin_len);
  } else {
    i18n_get_with_buffer(i18n_ctx_noop("SecurityLock", "Off"), data->pin_subtitle,
                         sizeof(data->pin_subtitle));
  }

  i18n_get_with_buffer(s_pin_length_labels[prv_length_index(data->new_pin_len)],
                       data->length_subtitle, sizeof(data->length_subtitle));
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
//! Deliberately says nothing a duress PIN could be inferred from: the phone
//! message depends only on the connection, and the "must differ" message can
//! only ever be reached by someone who just typed their own real PIN.
static void prv_report_store_failure(SettingsSecurityData *data, status_t rv) {
  if (rv == E_INVALID_OPERATION) {
    prv_set_prompt_message(data, i18n_noop("Connect your phone to change your PIN"));
  } else if (rv == E_INVALID_ARGUMENT) {
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

//! Say the phone is needed before asking for a PIN, rather than taking an entry
//! the store is going to refuse.
//!
//! Mirrors what the store actually enforces, which is narrower than "any
//! change": replacing or removing an existing secret needs the phone, because
//! that is what someone holding only the watch would want to do. Setting a
//! first PIN, or adding a duress PIN, protects something rather than
//! disarming it and is allowed offline -- otherwise the feature could not be
//! turned on at all by anyone whose watch is not currently paired.
static bool prv_require_phone(SettingsSecurityData *data) {
  if (connection_service_peek_pebble_app_connection()) {
    return true;
  }
  SimpleDialog *dialog = simple_dialog_create(WINDOW_NAME("No Phone"));
  if (!dialog) {
    return false;
  }
  Dialog *base = simple_dialog_get_dialog(dialog);
  dialog_set_text(base, i18n_get("Connect your phone to change your PIN", data));
  dialog_set_icon(base, RESOURCE_ID_GENERIC_WARNING_LARGE);
  dialog_set_timeout(base, DIALOG_TIMEOUT_INFINITE);
  app_simple_dialog_push(dialog);
  return false;
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
  SettingsSecurityPin,
  SettingsSecurityPinLength,
  SettingsSecurityDuressPin,
  SettingsSecurityClearPin,
  SettingsSecurityLockNow,
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
static bool prv_item_is_visible(SettingsSecurityData *data, uint16_t item) {
  switch (item) {
    case SettingsSecurityDuressPin:
      // Follows the real PIN, which the row above already announces. Nothing
      // about the duress PIN itself is being disclosed.
      return prv_pin_is_set(data);
    case SettingsSecurityClearPin:
      return prv_pin_is_set(data);
    case SettingsSecurityLockNow:
      // Without a PIN there is nothing to unlock with, so this would erase
      // without locking. Offering it under this name would be a lie.
      return prv_pin_is_set(data);
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
    case SettingsSecurityPin:
      title = prv_pin_is_set(data) ? i18n_noop("Change PIN") : i18n_noop("Set PIN");
      subtitle = data->pin_subtitle;
      break;
    case SettingsSecurityPinLength:
      title = i18n_noop("PIN Length");
      subtitle = data->length_subtitle;
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
    default:
      WTF;
  }

  menu_cell_basic_draw(ctx, cell_layer, i18n_get(title, data), subtitle, NULL);
}

static void prv_select_click_cb(SettingsCallbacks *context, uint16_t row) {
  SettingsSecurityData *data = (SettingsSecurityData *)context;

  switch (prv_item_from_row(data, row)) {
    case SettingsSecurityPin:
      if (!prv_pin_is_set(data)) {
        // The first one needs no phone: there is nothing yet to protect.
        prv_push_pin_prompt(data, PinStageNewFirst, PinTargetMain);
      } else if (prv_require_phone(data)) {
        prv_push_pin_prompt(data, PinStageAuthorizeSet, PinTargetMain);
      }
      break;
    case SettingsSecurityPinLength:
      prv_length_menu_push(data);
      break;
    case SettingsSecurityDuressPin:
      // Always straight to setting a new one. Asking "set or clear?" would
      // answer the question the menu exists to refuse to answer.
      //
      // No phone check: adding a duress PIN arms a defence rather than
      // disarming one, and the store allows it offline.
      prv_push_pin_prompt(data, PinStageAuthorizeSet, PinTargetDuress);
      break;
    case SettingsSecurityClearPin:
      if (prv_require_phone(data)) {
        prv_push_pin_prompt(data, PinStageAuthorizeClear, PinTargetMain);
      }
      break;
    case SettingsSecurityLockNow:
      prv_lock_now_push(data);
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
