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
  //! Prove you know the existing PIN before being allowed to replace it.
  PinStageAuthorizeChange,
  //! Same, before being allowed to remove it.
  PinStageAuthorizeClear,
  PinStageNewFirst,
  PinStageNewRepeat,
} PinStage;

typedef struct SettingsSecurityData {
  SettingsCallbacks callbacks;

  //! Lives here rather than on its own so popping it frees nothing; the
  //! Security menu is always below it on the stack.
  SecurityPinEntryWindow pin_window;
  PinStage stage;
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

static const char *s_pin_length_labels[] = {
    i18n_noop("4 digits"), i18n_noop("5 digits"), i18n_noop("6 digits"),
    i18n_noop("7 digits"), i18n_noop("8 digits"),
};

_Static_assert(ARRAY_LENGTH(s_pin_length_labels) ==
                   (SECURITY_LOCK_PIN_MAX_LEN - SECURITY_LOCK_PIN_MIN_LEN + 1),
               "PIN length labels must cover the whole allowed range");

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

  i18n_get_with_buffer(s_pin_length_labels[data->new_pin_len - SECURITY_LOCK_PIN_MIN_LEN],
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

static void prv_begin_new_pin(SettingsSecurityData *data) {
  data->stage = PinStageNewFirst;
  security_pin_entry_window_set_pin_len(&data->pin_window, data->new_pin_len);
  security_pin_entry_window_set_title(&data->pin_window, i18n_get("New PIN", data));
  security_pin_entry_window_set_message(&data->pin_window, NULL);
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
    case PinStageAuthorizeChange:
      if (!prv_verify_current_pin(digits, len)) {
        prv_handle_wrong_pin(data);
        return;
      }
      prv_begin_new_pin(data);
      return;

    case PinStageAuthorizeClear:
      if (!prv_verify_current_pin(digits, len)) {
        prv_handle_wrong_pin(data);
        return;
      }
      PBL_LOG_DBG("Clearing PIN");
      if (security_lock_clear_pin() != S_SUCCESS) {
        PBL_LOG_ERR("Failed to clear the PIN");
      }
      prv_finish_prompt(data);
      prv_refresh(data);
      return;

    case PinStageNewFirst:
      memcpy(data->first_entry, digits, len);
      data->stage = PinStageNewRepeat;
      security_pin_entry_window_set_title(&data->pin_window, i18n_get("Repeat PIN", data));
      security_pin_entry_window_set_message(&data->pin_window, NULL);
      return;

    case PinStageNewRepeat:
      if (memcmp(data->first_entry, digits, len) != 0) {
        memset(data->first_entry, 0, sizeof(data->first_entry));
        prv_begin_new_pin(data);
        prv_set_prompt_message(data, i18n_noop("PINs did not match"));
        return;
      }
      PBL_LOG_DBG("Setting a %u digit PIN", (unsigned)len);
      if (security_lock_set_pin(digits, len) != S_SUCCESS) {
        // The row subtitle re-reads the stored state below, so a failure shows
        // up as the PIN simply not being on rather than a false confirmation.
        PBL_LOG_ERR("Failed to set the PIN");
      }
      prv_finish_prompt(data);
      prv_refresh(data);
      return;

    default:
      WTF;
  }
}

static void prv_push_pin_prompt(SettingsSecurityData *data, PinStage stage) {
  const bool authorizing =
      (stage == PinStageAuthorizeChange) || (stage == PinStageAuthorizeClear);
  const uint8_t len = authorizing ? data->current_pin_len : data->new_pin_len;

  security_pin_entry_window_init(&data->pin_window, len, prv_pin_submit, data);
  // Unlike the lock screen, this one the user is allowed to walk away from.
  security_pin_entry_window_set_cancelable(&data->pin_window, true);
  security_pin_entry_window_set_title(
      &data->pin_window, authorizing ? i18n_get("Current PIN", data) : i18n_get("New PIN", data));

  data->stage = stage;
  data->auth_attempts = 0;
  memset(data->first_entry, 0, sizeof(data->first_entry));

  app_window_stack_push(&data->pin_window.window, true /* animated */);
}

// PIN length
//////////////////////////////////////////////////////////////////////////////

static void prv_length_menu_select(OptionMenu *option_menu, int selection, void *context) {
  SettingsSecurityData *data = settings_option_menu_get_context(context);
  data->new_pin_len = SECURITY_LOCK_PIN_MIN_LEN + selection;
  prv_refresh(data);
  app_window_stack_remove(&option_menu->window, true /* animated */);
}

static void prv_length_menu_push(SettingsSecurityData *data) {
  const OptionMenuCallbacks callbacks = {
    .select = prv_length_menu_select,
  };
  settings_option_menu_push(i18n_noop("PIN Length"), OptionMenuContentType_SingleLine,
                            data->new_pin_len - SECURITY_LOCK_PIN_MIN_LEN, &callbacks,
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
  SettingsSecurityClearPin,
  SettingsSecurityLockNow,
  NumSettingsSecurityItems
};

static bool prv_item_is_visible(SettingsSecurityData *data, uint16_t item) {
  switch (item) {
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
      prv_push_pin_prompt(data, prv_pin_is_set(data) ? PinStageAuthorizeChange : PinStageNewFirst);
      break;
    case SettingsSecurityPinLength:
      prv_length_menu_push(data);
      break;
    case SettingsSecurityClearPin:
      prv_push_pin_prompt(data, PinStageAuthorizeClear);
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
  // first one starts at the shortest allowed.
  data->new_pin_len = prv_pin_is_set(data) ? data->current_pin_len : SECURITY_LOCK_PIN_MIN_LEN;
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
