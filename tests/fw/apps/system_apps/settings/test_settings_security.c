/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include "clar.h"

#include <string.h>

#include "applib/ui/dialogs/expandable_dialog.h"
#include "applib/ui/dialogs/simple_dialog.h"
#include "apps/system/settings/menu.h"
#include "apps/system/settings/option_menu.h"
#include "apps/system/settings/security.h"
#include "popups/security/pin_entry_window.h"
#include "pbl/services/security_lock.h"
#include "pbl/services/security_lock_shred.h"
#include "pbl/util/size.h"

// Stubs
////////////////////////////////////
#include "stubs_logging.h"
#include "stubs_passert.h"
#include "stubs_pbl_malloc.h"
#include "stubs_pebble_tasks.h"
#include "stubs_print.h"
#include "stubs_serial.h"

// Fake lock state store
////////////////////////////////////
// Mirrors the real service closely enough for the properties under test, most
// importantly that verifying burns an attempt before it compares.

static char s_stored_pin[SECURITY_LOCK_PIN_MAX_LEN];
static uint8_t s_stored_pin_len;
static char s_stored_duress[SECURITY_LOCK_PIN_MAX_LEN];
static uint8_t s_stored_duress_len;
static uint8_t s_failed_attempts;
static int s_reset_attempts_calls;
static int s_engage_calls;
//! The real store refuses to change any PIN without a phone session.
static bool s_phone_connected = true;

uint8_t security_lock_get_pin_len(void) {
  return s_stored_pin_len;
}

status_t security_lock_set_pin(const char *digits, uint8_t len) {
  if (!s_phone_connected) {
    return E_INVALID_OPERATION;
  }
  if (len < SECURITY_LOCK_PIN_MIN_LEN || len > SECURITY_LOCK_PIN_MAX_LEN) {
    return E_INVALID_ARGUMENT;
  }
  memcpy(s_stored_pin, digits, len);
  s_stored_pin_len = len;
  s_failed_attempts = 0;
  return S_SUCCESS;
}

status_t security_lock_set_duress_pin(const char *digits, uint8_t len) {
  if (!s_phone_connected) {
    return E_INVALID_OPERATION;
  }
  if (s_stored_pin_len == 0) {
    return E_INVALID_OPERATION;
  }
  if ((len == s_stored_pin_len) && (memcmp(digits, s_stored_pin, len) == 0)) {
    return E_INVALID_ARGUMENT;
  }
  memcpy(s_stored_duress, digits, len);
  s_stored_duress_len = len;
  return S_SUCCESS;
}

//! A tripwire, not a fake: nothing in the menu may ask this. Any path that
//! does fails the test that walks it, which between them cover every row and
//! every branch of the visibility rule.
bool security_lock_has_duress_pin(void) {
  cl_fail("Settings must never ask whether a duress PIN exists");
  return false;
}

status_t security_lock_clear_pin(void) {
  if (!s_phone_connected) {
    return E_INVALID_OPERATION;
  }
  memset(s_stored_pin, 0, sizeof(s_stored_pin));
  s_stored_pin_len = 0;
  // Clearing the real PIN takes the duress PIN with it; that is the only way
  // to remove one, and the reason the menu needs no row for it.
  memset(s_stored_duress, 0, sizeof(s_stored_duress));
  s_stored_duress_len = 0;
  return S_SUCCESS;
}

bool security_lock_verify_pin(const char *digits, uint8_t len, uint8_t *attempts_remaining_out) {
  if (s_failed_attempts < UINT8_MAX) {
    s_failed_attempts++;
  }
  const bool matched = (len == s_stored_pin_len) && (memcmp(digits, s_stored_pin, len) == 0);
  if (matched) {
    s_failed_attempts = 0;
  }
  if (attempts_remaining_out) {
    *attempts_remaining_out = (s_failed_attempts >= SECURITY_LOCK_MAX_PIN_ATTEMPTS)
                                  ? 0
                                  : SECURITY_LOCK_MAX_PIN_ATTEMPTS - s_failed_attempts;
  }
  return matched;
}

uint8_t security_lock_get_failed_attempts(void) {
  return s_failed_attempts;
}

status_t security_lock_reset_failed_attempts(void) {
  s_reset_attempts_calls++;
  s_failed_attempts = 0;
  return S_SUCCESS;
}

bool security_lock_attempts_exhausted(void) {
  return s_failed_attempts >= SECURITY_LOCK_MAX_PIN_ATTEMPTS;
}

void security_lock_engage(SecurityShredReason reason) {
  s_engage_calls++;
}

// Fake UI surface
////////////////////////////////////
// Everything the module talks to is captured rather than drawn, which is what
// lets the row logic and the prompt state machine be driven directly.

static SettingsCallbacks *s_module;
static Window s_settings_window;

Window *settings_window_create(SettingsMenuItem category, SettingsCallbacks *callbacks) {
  s_module = callbacks;
  return &s_settings_window;
}

void settings_menu_reload_data(SettingsMenuItem category) {}
void settings_menu_mark_dirty(SettingsMenuItem category) {}

//! The PIN prompt currently pushed, or NULL.
static SecurityPinEntryWindow *s_prompt;
static SecurityPinEntrySubmitCb s_prompt_submit;
static void *s_prompt_context;
static uint8_t s_prompt_pin_len;
static bool s_prompt_cancelable;
static char s_prompt_message[SECURITY_PIN_MESSAGE_BUF_SIZE];

void security_pin_entry_window_init(SecurityPinEntryWindow *pin_window, uint8_t pin_len,
                                    SecurityPinEntrySubmitCb submit, void *context) {
  memset(pin_window, 0, sizeof(*pin_window));
  s_prompt_submit = submit;
  s_prompt_context = context;
  s_prompt_pin_len = pin_len;
  s_prompt_cancelable = false;
  s_prompt_message[0] = '\0';
}

void security_pin_entry_window_set_cancelable(SecurityPinEntryWindow *pin_window, bool cancelable) {
  s_prompt_cancelable = cancelable;
}

void security_pin_entry_window_set_pin_len(SecurityPinEntryWindow *pin_window, uint8_t pin_len) {
  s_prompt_pin_len = pin_len;
}

void security_pin_entry_window_set_title(SecurityPinEntryWindow *pin_window, const char *title) {}

void security_pin_entry_window_set_message(SecurityPinEntryWindow *pin_window,
                                           const char *message) {
  if (message) {
    strncpy(s_prompt_message, message, sizeof(s_prompt_message) - 1);
    s_prompt_message[sizeof(s_prompt_message) - 1] = '\0';
  } else {
    s_prompt_message[0] = '\0';
  }
}

void security_pin_entry_window_reset(SecurityPinEntryWindow *pin_window) {}

void app_window_stack_push(Window *window, bool animated) {
  s_prompt = (SecurityPinEntryWindow *)window;
}

bool app_window_stack_remove(Window *window, bool animated) {
  s_prompt = NULL;
  return true;
}

// The length picker.
static OptionMenuSelectCallback s_option_select;
static void *s_option_context;
static int s_option_choice;
static uint16_t s_option_num_rows;
static OptionMenu s_option_menu;

OptionMenu *settings_option_menu_push(const char *i18n_title_key,
                                      OptionMenuContentType content_type, int choice,
                                      const OptionMenuCallbacks *callbacks, uint16_t num_rows,
                                      bool icons_enabled, const char **rows, void *context) {
  s_option_select = callbacks->select;
  s_option_context = context;
  s_option_choice = choice;
  s_option_num_rows = num_rows;
  return &s_option_menu;
}

void *settings_option_menu_get_context(SettingsOptionMenuData *data) {
  return s_option_context;
}

// The "connect your phone" notice.
static int s_simple_dialog_pushes;
static char s_simple_dialog_text[128];
static SimpleDialog s_simple_dialog;
static Dialog s_dialog;

bool connection_service_peek_pebble_app_connection(void) {
  return s_phone_connected;
}

SimpleDialog *simple_dialog_create(const char *dialog_name) {
  return &s_simple_dialog;
}

Dialog *simple_dialog_get_dialog(SimpleDialog *simple_dialog) {
  return &s_dialog;
}

void dialog_set_text(Dialog *dialog, const char *text) {
  strncpy(s_simple_dialog_text, text, sizeof(s_simple_dialog_text) - 1);
  s_simple_dialog_text[sizeof(s_simple_dialog_text) - 1] = '\0';
}

void dialog_set_icon(Dialog *dialog, uint32_t icon) {}
void dialog_set_timeout(Dialog *dialog, uint32_t timeout) {}

void app_simple_dialog_push(SimpleDialog *simple_dialog) {
  s_simple_dialog_pushes++;
}

// Lock Now's confirmation.
static ClickHandler s_dialog_confirm;
static int s_dialog_pops;
static ExpandableDialog s_expandable_dialog;

ExpandableDialog *expandable_dialog_create_with_params(const char *dialog_name, ResourceId icon,
                                                       const char *text, GColor text_color,
                                                       GColor background_color,
                                                       DialogCallbacks *callbacks,
                                                       ResourceId select_icon,
                                                       ClickHandler select_click_handler) {
  s_dialog_confirm = select_click_handler;
  return &s_expandable_dialog;
}

void expandable_dialog_set_header(ExpandableDialog *e_dialog, const char *header) {}
void app_expandable_dialog_push(ExpandableDialog *e_dialog) {}

void expandable_dialog_pop(ExpandableDialog *e_dialog) {
  s_dialog_pops++;
}

// Lock Now must not call engage() inline: it asserts KernelMain and this runs
// on the app task.
static void (*s_deferred_callback)(void *);

void launcher_task_add_callback(void (*callback)(void *data), void *data) {
  s_deferred_callback = callback;
}

void menu_cell_basic_draw(GContext *ctx, const Layer *cell_layer, const char *title,
                          const char *subtitle, GBitmap *icon) {}

const char *i18n_get(const char *string, const void *owner) {
  return string;
}

void i18n_get_with_buffer(const char *string, char *buffer, size_t length) {
  strncpy(buffer, string, length);
  buffer[length - 1] = '\0';
}

void i18n_free_all(const void *owner) {}

// Helpers
////////////////////////////////////

//! Row order when no PIN is configured.
#define ROW_SET_PIN 0
#define ROW_PIN_LENGTH_UNSET 1
#define ROWS_WITHOUT_PIN 2
//! Row order once one is.
#define ROW_CHANGE_PIN 0
#define ROW_PIN_LENGTH_SET 1
#define ROW_DURESS_PIN 2
#define ROW_CLEAR_PIN 3
#define ROW_LOCK_NOW 4
#define ROWS_WITH_PIN 5

static void prv_open_settings(void) {
  settings_security_get_info()->init();
  cl_assert(s_module != NULL);
  s_module->appear(s_module);
}

static uint16_t prv_num_rows(void) {
  return s_module->num_rows(s_module);
}

static void prv_select(uint16_t row) {
  s_module->select_click(s_module, row);
}

static void prv_submit(const char *pin) {
  cl_assert(s_prompt != NULL);
  cl_assert_equal_i(strlen(pin), s_prompt_pin_len);
  s_prompt_submit(pin, strlen(pin), s_prompt_context);
}

static void prv_install_pin(const char *pin) {
  security_lock_set_pin(pin, strlen(pin));
  s_reset_attempts_calls = 0;
}

void test_settings_security__initialize(void) {
  memset(s_stored_pin, 0, sizeof(s_stored_pin));
  s_stored_pin_len = 0;
  memset(s_stored_duress, 0, sizeof(s_stored_duress));
  s_stored_duress_len = 0;
  s_phone_connected = true;
  s_simple_dialog_pushes = 0;
  s_simple_dialog_text[0] = '\0';
  s_failed_attempts = 0;
  s_reset_attempts_calls = 0;
  s_engage_calls = 0;
  s_module = NULL;
  s_prompt = NULL;
  s_prompt_submit = NULL;
  s_prompt_pin_len = 0;
  s_prompt_cancelable = false;
  s_prompt_message[0] = '\0';
  s_option_select = NULL;
  s_option_choice = -1;
  s_option_num_rows = 0;
  s_dialog_confirm = NULL;
  s_dialog_pops = 0;
  s_deferred_callback = NULL;
}

void test_settings_security__cleanup(void) {
  if (s_module) {
    s_module->deinit(s_module);
    s_module = NULL;
  }
}

// Rows
////////////////////////////////////

void test_settings_security__hides_pin_actions_until_there_is_a_pin(void) {
  prv_open_settings();
  cl_assert_equal_i(ROWS_WITHOUT_PIN, prv_num_rows());
}

void test_settings_security__shows_pin_actions_once_set(void) {
  prv_install_pin("1234");
  prv_open_settings();
  cl_assert_equal_i(ROWS_WITH_PIN, prv_num_rows());
}

// Rows appear and disappear underneath the selection, so the mapping from row
// index to action has to keep up. Getting it wrong here means selecting "Clear
// PIN" and erasing the watch instead.
void test_settings_security__rows_follow_the_pin_appearing(void) {
  prv_open_settings();
  cl_assert_equal_i(ROWS_WITHOUT_PIN, prv_num_rows());

  prv_select(ROW_SET_PIN);
  prv_submit("1234");
  prv_submit("1234");

  s_module->appear(s_module);
  cl_assert_equal_i(ROWS_WITH_PIN, prv_num_rows());

  // The last row must now be Lock Now, not something that fell through to a
  // default.
  prv_select(ROW_LOCK_NOW);
  cl_assert(s_dialog_confirm != NULL);
}

// Duress PIN
////////////////////////////////////

//! Defined with the rest of the length helpers further down.
static void prv_choose_length(uint8_t len);

//! Count and order of rows, which must not depend on the duress PIN.
static void prv_capture_row_titles(int *count) {
  *count = prv_num_rows();
}

// The menu must look identical whether or not a duress PIN is configured.
// Anything that varies -- a row appearing, a subtitle changing -- hands over
// the one bit the feature depends on keeping.
void test_settings_security__duress_state_is_not_visible(void) {
  prv_install_pin("1234");
  prv_open_settings();
  int without = 0;
  prv_capture_row_titles(&without);

  // Configure one, through the menu, exactly as a user would.
  prv_select(ROW_DURESS_PIN);
  prv_submit("1234");
  prv_submit("5678");
  prv_submit("5678");
  cl_assert_equal_i(4, s_stored_duress_len);

  s_module->appear(s_module);
  int with = 0;
  prv_capture_row_titles(&with);

  cl_assert_equal_i(without, with);
}

void test_settings_security__duress_pin_requires_the_current_pin(void) {
  prv_install_pin("1234");
  prv_open_settings();
  prv_select(ROW_DURESS_PIN);

  prv_submit("9999");
  cl_assert_equal_i(0, s_stored_duress_len);
  cl_assert(s_prompt != NULL);

  prv_submit("1234");
  prv_submit("5678");
  prv_submit("5678");
  cl_assert_equal_i(4, s_stored_duress_len);
}

// verify_pin only tries the duress hash when the entered length matches the one
// it was stored with, and the lock screen only ever prompts for the real PIN's
// length. A duress PIN of the other length would look set and never work.
void test_settings_security__duress_pin_matches_the_real_pin_length(void) {
  prv_install_pin("123456");
  prv_open_settings();

  // Even with the picker set to four, which is what the next real PIN would be.
  prv_select(ROW_PIN_LENGTH_SET);
  prv_choose_length(4);
  s_module->appear(s_module);

  prv_select(ROW_DURESS_PIN);
  cl_assert_equal_i(6, s_prompt_pin_len);
  prv_submit("123456");
  cl_assert_equal_i(6, s_prompt_pin_len);
}

void test_settings_security__duress_pin_must_differ_from_the_real_one(void) {
  prv_install_pin("1234");
  prv_open_settings();
  prv_select(ROW_DURESS_PIN);

  prv_submit("1234");
  prv_submit("1234");
  prv_submit("1234");

  cl_assert_equal_i(0, s_stored_duress_len);
  cl_assert(s_prompt != NULL);
  cl_assert_equal_s("Must differ from your PIN", s_prompt_message);
}

// Clearing the real PIN is the only way to remove a duress PIN, so it has to
// actually do it -- otherwise a forgotten one survives into the next PIN.
void test_settings_security__clearing_the_pin_takes_the_duress_pin_with_it(void) {
  prv_install_pin("1234");
  prv_open_settings();

  prv_select(ROW_DURESS_PIN);
  prv_submit("1234");
  prv_submit("5678");
  prv_submit("5678");
  cl_assert_equal_i(4, s_stored_duress_len);

  s_module->appear(s_module);
  prv_select(ROW_CLEAR_PIN);
  prv_submit("1234");

  cl_assert_equal_i(0, s_stored_pin_len);
  cl_assert_equal_i(0, s_stored_duress_len);
}

// Needing the phone
////////////////////////////////////

void test_settings_security__set_pin_asks_for_the_phone_first(void) {
  s_phone_connected = false;
  prv_open_settings();

  prv_select(ROW_SET_PIN);

  // No prompt at all: taking an entry the store is going to refuse would waste
  // the user's time and then fail for a reason they could not have guessed.
  cl_assert(s_prompt == NULL);
  cl_assert_equal_i(1, s_simple_dialog_pushes);
  cl_assert_equal_s("Connect your phone to change your PIN", s_simple_dialog_text);
}

void test_settings_security__every_pin_change_asks_for_the_phone(void) {
  prv_install_pin("1234");
  prv_open_settings();
  s_phone_connected = false;

  const uint16_t rows[] = {ROW_CHANGE_PIN, ROW_DURESS_PIN, ROW_CLEAR_PIN};
  for (int i = 0; i < (int)ARRAY_LENGTH(rows); ++i) {
    s_simple_dialog_pushes = 0;
    prv_select(rows[i]);
    cl_assert(s_prompt == NULL);
    cl_assert_equal_i(1, s_simple_dialog_pushes);
  }
}

// Verifying still works offline, so the phone check must not sit in front of
// the parts that only read.
void test_settings_security__lock_now_still_works_without_a_phone(void) {
  prv_install_pin("1234");
  prv_open_settings();
  s_phone_connected = false;

  prv_select(ROW_LOCK_NOW);
  cl_assert(s_dialog_confirm != NULL);
  cl_assert_equal_i(0, s_simple_dialog_pushes);
}

// The phone can go away between opening the prompt and submitting it.
void test_settings_security__a_refusal_mid_flow_says_why(void) {
  prv_open_settings();
  prv_select(ROW_SET_PIN);
  cl_assert(s_prompt != NULL);

  s_phone_connected = false;
  prv_submit("1234");
  prv_submit("1234");

  cl_assert_equal_i(0, security_lock_get_pin_len());
  // Still on the prompt, with the reason on screen rather than silently back in
  // the menu with nothing changed.
  cl_assert(s_prompt != NULL);
  cl_assert_equal_s("Connect your phone to change your PIN", s_prompt_message);
}

void test_settings_security__a_refused_clear_says_why(void) {
  prv_install_pin("1234");
  prv_open_settings();
  prv_select(ROW_CLEAR_PIN);

  s_phone_connected = false;
  prv_submit("1234");

  cl_assert_equal_i(4, security_lock_get_pin_len());
  cl_assert(s_prompt != NULL);
  cl_assert_equal_s("Connect your phone to change your PIN", s_prompt_message);
}

// Setting a PIN
////////////////////////////////////

void test_settings_security__set_pin_needs_two_matching_entries(void) {
  prv_open_settings();
  prv_select(ROW_SET_PIN);
  cl_assert(s_prompt != NULL);

  prv_submit("1234");
  // Still collecting; nothing stored yet.
  cl_assert_equal_i(0, security_lock_get_pin_len());
  cl_assert(s_prompt != NULL);

  prv_submit("1234");
  cl_assert_equal_i(4, security_lock_get_pin_len());
  cl_assert(s_prompt == NULL);
}

void test_settings_security__mismatched_entries_set_nothing(void) {
  prv_open_settings();
  prv_select(ROW_SET_PIN);

  prv_submit("1234");
  prv_submit("1235");

  cl_assert_equal_i(0, security_lock_get_pin_len());
  // Left on screen at the start of entry rather than dumping the user out.
  cl_assert(s_prompt != NULL);
  cl_assert_equal_s("PINs did not match", s_prompt_message);

  // And the flow still works from there.
  prv_submit("4321");
  prv_submit("4321");
  cl_assert_equal_i(4, security_lock_get_pin_len());
}

void test_settings_security__prompt_is_escapable_unlike_the_lock_screen(void) {
  prv_open_settings();
  prv_select(ROW_SET_PIN);
  cl_assert(s_prompt_cancelable);
}

// Changing and clearing require the current PIN
////////////////////////////////////

void test_settings_security__change_requires_the_current_pin(void) {
  prv_install_pin("1234");
  prv_open_settings();
  prv_select(ROW_CHANGE_PIN);

  prv_submit("9999");
  cl_assert(s_prompt != NULL);

  prv_submit("1234");
  prv_submit("5678");
  prv_submit("5678");

  cl_assert(s_prompt == NULL);
  cl_assert_equal_i(4, security_lock_get_pin_len());
  cl_assert(security_lock_verify_pin("5678", 4, NULL));
}

// Without this, requiring the current PIN to clear one would be theatre: an
// attacker would just set their own over the top.
void test_settings_security__change_cannot_be_used_to_bypass_the_old_pin(void) {
  prv_install_pin("1234");
  prv_open_settings();
  prv_select(ROW_CHANGE_PIN);

  // Wrong PIN, then straight into what would be the new-PIN entry.
  prv_submit("9999");
  prv_submit("5678");

  cl_assert(security_lock_verify_pin("1234", 4, NULL));
}

void test_settings_security__clear_requires_the_current_pin(void) {
  prv_install_pin("1234");
  prv_open_settings();
  prv_select(ROW_CLEAR_PIN);

  prv_submit("9999");
  cl_assert_equal_i(4, security_lock_get_pin_len());
  cl_assert(s_prompt != NULL);

  prv_submit("1234");
  cl_assert_equal_i(0, security_lock_get_pin_len());
  cl_assert(s_prompt == NULL);
}

// Attempt counter
////////////////////////////////////

void test_settings_security__gives_up_after_three_wrong_attempts(void) {
  prv_install_pin("1234");
  prv_open_settings();
  prv_select(ROW_CLEAR_PIN);

  prv_submit("9999");
  cl_assert(s_prompt != NULL);
  prv_submit("9998");
  cl_assert(s_prompt != NULL);
  prv_submit("9997");
  cl_assert(s_prompt == NULL);

  cl_assert_equal_i(4, security_lock_get_pin_len());
}

// The whole point of resetting the counter here: three fumbles in a menu must
// not leave the next typo on a real lock screen one attempt from a shred.
void test_settings_security__wrong_attempts_do_not_arm_the_lock_screen(void) {
  prv_install_pin("1234");
  prv_open_settings();
  prv_select(ROW_CLEAR_PIN);

  prv_submit("9999");
  prv_submit("9998");
  prv_submit("9997");

  cl_assert_equal_i(0, security_lock_get_failed_attempts());
  cl_assert(!security_lock_attempts_exhausted());
}

void test_settings_security__a_correct_pin_also_leaves_the_counter_clear(void) {
  prv_install_pin("1234");
  prv_open_settings();
  prv_select(ROW_CLEAR_PIN);

  prv_submit("1234");

  cl_assert_equal_i(0, security_lock_get_failed_attempts());
  cl_assert(s_reset_attempts_calls > 0);
}

// PIN length
////////////////////////////////////

//! The lengths the picker must offer, in order. Stated here rather than derived
//! from the module: "exactly four or six" is the requirement, so the test has
//! to fail if the module starts offering a five.
static const uint8_t s_expected_lengths[] = {4, 6};

static int prv_length_index(uint8_t len) {
  for (int i = 0; i < (int)ARRAY_LENGTH(s_expected_lengths); ++i) {
    if (s_expected_lengths[i] == len) {
      return i;
    }
  }
  cl_fail("that length is not offered");
  return 0;
}

static void prv_choose_length(uint8_t len) {
  cl_assert(s_option_select != NULL);
  s_option_select(&s_option_menu, prv_length_index(len), NULL);
}

void test_settings_security__offers_only_four_or_six_digits(void) {
  prv_open_settings();
  prv_select(ROW_PIN_LENGTH_UNSET);

  cl_assert_equal_i(ARRAY_LENGTH(s_expected_lengths), s_option_num_rows);

  // And each row really does produce the length it claims.
  for (int i = 0; i < (int)ARRAY_LENGTH(s_expected_lengths); ++i) {
    s_option_select(&s_option_menu, i, NULL);
    s_module->appear(s_module);
    prv_select(ROW_SET_PIN);
    cl_assert_equal_i(s_expected_lengths[i], s_prompt_pin_len);
    prv_select(ROW_PIN_LENGTH_UNSET);
  }
}

void test_settings_security__length_choice_survives_a_menu_refresh(void) {
  prv_install_pin("1234");
  prv_open_settings();

  prv_select(ROW_PIN_LENGTH_SET);
  prv_choose_length(6);

  // A refresh is what happens every time this menu comes back into view; the
  // choice must not be quietly reset to the current PIN's length.
  s_module->appear(s_module);

  prv_select(ROW_CHANGE_PIN);
  cl_assert_equal_i(4, s_prompt_pin_len);  // authorising against the old PIN
  prv_submit("1234");
  cl_assert_equal_i(6, s_prompt_pin_len);  // now collecting the new one

  prv_submit("135792");
  prv_submit("135792");
  cl_assert_equal_i(6, security_lock_get_pin_len());
}

void test_settings_security__length_applies_to_a_first_pin(void) {
  prv_open_settings();

  prv_select(ROW_PIN_LENGTH_UNSET);
  prv_choose_length(6);
  s_module->appear(s_module);

  prv_select(ROW_SET_PIN);
  cl_assert_equal_i(6, s_prompt_pin_len);

  prv_submit("135792");
  prv_submit("135792");
  cl_assert_equal_i(6, security_lock_get_pin_len());
}

void test_settings_security__length_menu_opens_on_the_current_choice(void) {
  prv_install_pin("123456");
  prv_open_settings();

  prv_select(ROW_PIN_LENGTH_SET);
  cl_assert_equal_i(prv_length_index(6), s_option_choice);
}

// Lock Now
////////////////////////////////////

void test_settings_security__lock_now_is_hidden_without_a_pin(void) {
  prv_open_settings();
  // Only Set PIN and PIN Length; nothing here can erase anything.
  cl_assert_equal_i(ROWS_WITHOUT_PIN, prv_num_rows());
}

void test_settings_security__lock_now_confirms_before_engaging(void) {
  prv_install_pin("1234");
  prv_open_settings();

  prv_select(ROW_LOCK_NOW);
  cl_assert(s_dialog_confirm != NULL);
  cl_assert_equal_i(0, s_engage_calls);
  cl_assert(s_deferred_callback == NULL);
}

// security_lock_engage() asserts it is on KernelMain and blocks for the length
// of the shred; this runs on the app task, so it has to be handed over.
void test_settings_security__lock_now_defers_engage_to_the_kernel(void) {
  prv_install_pin("1234");
  prv_open_settings();

  prv_select(ROW_LOCK_NOW);
  s_dialog_confirm(NULL, &s_expandable_dialog);

  cl_assert_equal_i(1, s_dialog_pops);
  cl_assert_equal_i(0, s_engage_calls);
  cl_assert(s_deferred_callback != NULL);

  s_deferred_callback(NULL);
  cl_assert_equal_i(1, s_engage_calls);
}
