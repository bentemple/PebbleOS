/* SPDX-FileCopyrightText: 2026 Core Devices LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include "clar.h"

#include <string.h>

#include "applib/ui/dialogs/expandable_dialog.h"
#include "apps/system/settings/menu.h"
#include "apps/system/settings/option_menu.h"
#include "apps/system/settings/security.h"
#include "popups/security/pin_entry_window.h"
#include "pbl/services/security_lock.h"
#include "pbl/services/security_lock_shred.h"
#include "pbl/util/size.h"
#include "shell/prefs.h"

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
static uint32_t s_lock_delay_s;
static uint32_t s_shred_delay_s;
static int s_rejected_delays;

uint8_t security_lock_get_pin_len(void) {
  return s_stored_pin_len;
}

status_t security_lock_set_pin(const char *digits, uint8_t len) {
  if (len < SECURITY_LOCK_PIN_MIN_LEN || len > SECURITY_LOCK_PIN_MAX_LEN) {
    return E_INVALID_ARGUMENT;
  }
  memcpy(s_stored_pin, digits, len);
  s_stored_pin_len = len;
  s_failed_attempts = 0;
  return S_SUCCESS;
}

status_t security_lock_set_duress_pin(const char *digits, uint8_t len) {
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

uint32_t security_lock_get_lock_delay_s(void) {
  return s_lock_delay_s;
}

uint32_t security_lock_get_shred_delay_s(void) {
  return s_shred_delay_s;
}

//! Mirrors the service's ordering rule, including its one exception: Never is
//! not an erase that happens sooner than the lock, it is no timed erase at all.
//! Rejections are counted rather than ignored -- the menu must never be able to
//! provoke one, and a silently swallowed E_INVALID_ARGUMENT looks exactly like
//! a setting that saved.
status_t security_lock_set_delays(uint32_t lock_delay_s, uint32_t shred_delay_s) {
  if ((shred_delay_s != SECURITY_LOCK_SHRED_DELAY_NEVER) && (shred_delay_s < lock_delay_s)) {
    s_rejected_delays++;
    return E_INVALID_ARGUMENT;
  }
  s_lock_delay_s = lock_delay_s;
  s_shred_delay_s = shred_delay_s;
  return S_SUCCESS;
}

// Fake launcher visibility pref
////////////////////////////////////
// Deliberately a shell pref rather than part of the lock record: what the
// launcher lists is a display preference, and hiding the app protects nothing.

static bool s_lockdown_in_launcher;

bool shell_prefs_get_lockdown_app_in_launcher(void) {
  return s_lockdown_in_launcher;
}

void shell_prefs_set_lockdown_app_in_launcher(bool enable) {
  s_lockdown_in_launcher = enable;
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

// What the last drawn row put on screen. The subtitles are the only place the
// "measured from the disconnect" framing is stated, so they are asserted on.
static char s_drawn_title[64];
static char s_drawn_subtitle[64];

static void prv_copy_drawn(char *dest, size_t size, const char *src) {
  strncpy(dest, src ? src : "", size - 1);
  dest[size - 1] = '\0';
}

void menu_cell_basic_draw(GContext *ctx, const Layer *cell_layer, const char *title,
                          const char *subtitle, GBitmap *icon) {
  prv_copy_drawn(s_drawn_title, sizeof(s_drawn_title), title);
  prv_copy_drawn(s_drawn_subtitle, sizeof(s_drawn_subtitle), subtitle);
}

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
#define ROW_SHOW_IN_LAUNCHER_UNSET 2
#define ROWS_WITHOUT_PIN 3
//! Row order once one is.
#define ROW_CHANGE_PIN 0
#define ROW_PIN_LENGTH_SET 1
#define ROW_LOCK_AFTER 2
#define ROW_ERASE_AFTER 3
#define ROW_DURESS_PIN 4
#define ROW_CLEAR_PIN 5
#define ROW_LOCK_NOW 6
#define ROW_SHOW_IN_LAUNCHER_SET 7
#define ROWS_WITH_PIN 8

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

static void prv_draw(uint16_t row) {
  s_module->draw_row(s_module, NULL, NULL, row, false /* selected */);
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
  s_failed_attempts = 0;
  s_reset_attempts_calls = 0;
  s_engage_calls = 0;
  s_lock_delay_s = SECURITY_LOCK_DEFAULT_LOCK_DELAY_S;
  s_shred_delay_s = SECURITY_LOCK_DEFAULT_SHRED_DELAY_S;
  s_rejected_delays = 0;
  s_drawn_title[0] = '\0';
  s_drawn_subtitle[0] = '\0';
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
  // The shipped default: the panic action is in the launcher unless asked
  // otherwise.
  s_lockdown_in_launcher = true;
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

// Working offline
////////////////////////////////////

// There is no connected-phone requirement any more: knowing the current PIN is
// the control. These pin the call sites down, because a select handler that
// falls through to nothing looks exactly like a working menu that ignores you.

void test_settings_security__changing_a_pin_reaches_the_prompt(void) {
  prv_install_pin("1234");
  prv_open_settings();
  prv_select(ROW_CHANGE_PIN);
  cl_assert(s_prompt != NULL);
}

void test_settings_security__clearing_a_pin_reaches_the_prompt(void) {
  prv_install_pin("1234");
  prv_open_settings();
  prv_select(ROW_CLEAR_PIN);
  cl_assert(s_prompt != NULL);
}

void test_settings_security__setting_a_first_pin_reaches_the_prompt(void) {
  prv_open_settings();
  prv_select(ROW_SET_PIN);
  cl_assert(s_prompt != NULL);
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
  // Only Set PIN, PIN Length and Show in Launcher; nothing here erases anything.
  cl_assert_equal_i(ROWS_WITHOUT_PIN, prv_num_rows());
  prv_draw(ROWS_WITHOUT_PIN - 1);
  cl_assert(strcmp("Lock Now", s_drawn_title) != 0);
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

// Show in Launcher
////////////////////////////////////

// Unlike Lock Now, this row is not gated on a PIN existing. It controls what
// the launcher lists, and the Lockdown app is listed whether or not a PIN is
// set -- a control that disappeared while the thing it controls stayed would
// be worse than no control.
void test_settings_security__show_in_launcher_is_offered_without_a_pin(void) {
  prv_open_settings();
  cl_assert_equal_i(ROWS_WITHOUT_PIN, prv_num_rows());
  prv_draw(ROW_SHOW_IN_LAUNCHER_UNSET);
  cl_assert_equal_s("Show in Launcher", s_drawn_title);
}

void test_settings_security__show_in_launcher_is_the_last_row_with_a_pin(void) {
  prv_install_pin("1234");
  prv_open_settings();
  cl_assert_equal_i(ROWS_WITH_PIN, prv_num_rows());
  prv_draw(ROW_SHOW_IN_LAUNCHER_SET);
  cl_assert_equal_s("Show in Launcher", s_drawn_title);
}

void test_settings_security__show_in_launcher_toggles(void) {
  prv_open_settings();

  prv_select(ROW_SHOW_IN_LAUNCHER_UNSET);
  cl_assert(!shell_prefs_get_lockdown_app_in_launcher());

  prv_select(ROW_SHOW_IN_LAUNCHER_UNSET);
  cl_assert(shell_prefs_get_lockdown_app_in_launcher());
}

// Turning it off is decluttering, not hiding: the app is still there and still
// bindable to a button. The row has to say so, and must not claim anything
// about security -- someone holding the watch has no reason to trigger a wipe
// of the data they came for.
void test_settings_security__show_in_launcher_says_quick_launch_still_works(void) {
  prv_open_settings();

  prv_draw(ROW_SHOW_IN_LAUNCHER_UNSET);
  cl_assert_equal_s("On", s_drawn_subtitle);

  prv_select(ROW_SHOW_IN_LAUNCHER_UNSET);
  prv_draw(ROW_SHOW_IN_LAUNCHER_UNSET);
  cl_assert(strstr(s_drawn_subtitle, "Off") != NULL);
  cl_assert(strstr(s_drawn_subtitle, "Quick Launch") != NULL);
}

// The row reads the pref rather than a copy taken when the menu opened, so a
// change made elsewhere is not shown as its old value.
void test_settings_security__show_in_launcher_reflects_the_stored_value(void) {
  shell_prefs_set_lockdown_app_in_launcher(false);
  prv_open_settings();

  prv_draw(ROW_SHOW_IN_LAUNCHER_UNSET);
  cl_assert(strstr(s_drawn_subtitle, "Off") != NULL);
}

// Lock After / Erase After
////////////////////////////////////

//! The options each picker must offer, in order. Stated here rather than read
//! back from the module, so that trimming the list or reordering it fails.
static const uint32_t s_expected_lock_delays[] = {60, 5 * 60, 15 * 60, 30 * 60, 60 * 60};
static const uint32_t s_expected_shred_delays[] = {
    30 * 60,      60 * 60,       2 * 60 * 60, 4 * 60 * 60,
    8 * 60 * 60,  24 * 60 * 60,  SECURITY_LOCK_SHRED_DELAY_NEVER,
};

//! The Erase After rows that must be offered for a given Lock After: nothing
//! shorter than the lock delay, and Never regardless. Re-derived here rather
//! than asked of the module, because that rule is the requirement.
static int prv_expected_shred_rows(uint32_t lock_delay_s, uint32_t *out) {
  int count = 0;
  for (size_t i = 0; i < ARRAY_LENGTH(s_expected_shred_delays); ++i) {
    const uint32_t value = s_expected_shred_delays[i];
    if ((value == SECURITY_LOCK_SHRED_DELAY_NEVER) || (value >= lock_delay_s)) {
      out[count++] = value;
    }
  }
  return count;
}

static void prv_choose_option(int index) {
  cl_assert(s_option_select != NULL);
  cl_assert(index < (int)s_option_num_rows);
  s_option_select(&s_option_menu, index, NULL);
  s_module->appear(s_module);
}

static void prv_choose_lock_delay(uint32_t seconds) {
  prv_select(ROW_LOCK_AFTER);
  for (size_t i = 0; i < ARRAY_LENGTH(s_expected_lock_delays); ++i) {
    if (s_expected_lock_delays[i] == seconds) {
      prv_choose_option(i);
      return;
    }
  }
  cl_fail("that lock delay is not offered");
}

static void prv_choose_shred_delay(uint32_t seconds) {
  uint32_t expected[ARRAY_LENGTH(s_expected_shred_delays)];
  const int count = prv_expected_shred_rows(s_lock_delay_s, expected);

  prv_select(ROW_ERASE_AFTER);
  for (int i = 0; i < count; ++i) {
    if (expected[i] == seconds) {
      prv_choose_option(i);
      return;
    }
  }
  cl_fail("that erase delay is not offered");
}

// The delays only do anything once a PIN exists: without one nothing locks and
// nothing is erased on a disconnect, so offering to time either would be the
// same lie Lock Now is hidden to avoid.
void test_settings_security__delay_rows_appear_with_the_pin(void) {
  prv_open_settings();
  cl_assert_equal_i(ROWS_WITHOUT_PIN, prv_num_rows());

  prv_select(ROW_SET_PIN);
  prv_submit("1234");
  prv_submit("1234");
  s_module->appear(s_module);

  cl_assert_equal_i(ROWS_WITH_PIN, prv_num_rows());
  prv_draw(ROW_LOCK_AFTER);
  cl_assert_equal_s("Lock After", s_drawn_title);
  prv_draw(ROW_ERASE_AFTER);
  cl_assert_equal_s("Erase After", s_drawn_title);
}

// Both delays run from the disconnect, not from each other. Read as "erase 30
// minutes after it locks" the defaults look like 35 minutes of grace instead of
// 30, so the row has to say what it is counting from.
void test_settings_security__subtitles_say_what_the_delay_is_measured_from(void) {
  prv_install_pin("1234");
  prv_open_settings();

  prv_draw(ROW_LOCK_AFTER);
  cl_assert(strstr(s_drawn_subtitle, "5 min") != NULL);
  cl_assert(strstr(s_drawn_subtitle, "disconnect") != NULL);

  prv_draw(ROW_ERASE_AFTER);
  cl_assert(strstr(s_drawn_subtitle, "30 min") != NULL);
  cl_assert(strstr(s_drawn_subtitle, "disconnect") != NULL);
}

void test_settings_security__lock_after_offers_minutes_not_days(void) {
  prv_install_pin("1234");
  prv_open_settings();

  prv_select(ROW_LOCK_AFTER);
  cl_assert_equal_i(ARRAY_LENGTH(s_expected_lock_delays), s_option_num_rows);

  for (size_t i = 0; i < ARRAY_LENGTH(s_expected_lock_delays); ++i) {
    prv_choose_option(i);
    cl_assert_equal_i(s_expected_lock_delays[i], s_lock_delay_s);
    prv_select(ROW_LOCK_AFTER);
  }
}

void test_settings_security__erase_after_offers_the_long_options(void) {
  prv_install_pin("1234");
  prv_open_settings();

  // At the default lock delay every option is legal, Never included.
  prv_select(ROW_ERASE_AFTER);
  cl_assert_equal_i(ARRAY_LENGTH(s_expected_shred_delays), s_option_num_rows);

  // An overnight disconnect is the case these exist for.
  prv_choose_shred_delay(8 * 60 * 60);
  cl_assert_equal_i(8 * 60 * 60, s_shred_delay_s);
  prv_choose_shred_delay(24 * 60 * 60);
  cl_assert_equal_i(24 * 60 * 60, s_shred_delay_s);
}

// Never means "lock on disconnect but never erase on a timer". The lock delay
// is untouched, so the watch still locks itself.
void test_settings_security__erase_after_can_be_never(void) {
  prv_install_pin("1234");
  prv_open_settings();

  prv_choose_shred_delay(SECURITY_LOCK_SHRED_DELAY_NEVER);

  cl_assert_equal_i(SECURITY_LOCK_SHRED_DELAY_NEVER, s_shred_delay_s);
  cl_assert_equal_i(SECURITY_LOCK_DEFAULT_LOCK_DELAY_S, s_lock_delay_s);
  cl_assert_equal_i(0, s_rejected_delays);

  // And the row says so rather than showing a bare zero.
  prv_draw(ROW_ERASE_AFTER);
  cl_assert(strstr(s_drawn_subtitle, "Never") != NULL);
  cl_assert(strstr(s_drawn_subtitle, "disconnect") == NULL);
}

// An erase that would land before the lock is not offered at all, so the user
// cannot pick one and be silently refused.
void test_settings_security__erase_after_hides_options_below_the_lock_delay(void) {
  prv_install_pin("1234");
  prv_open_settings();

  prv_choose_lock_delay(60 * 60);

  uint32_t expected[ARRAY_LENGTH(s_expected_shred_delays)];
  const int count = prv_expected_shred_rows(60 * 60, expected);

  prv_select(ROW_ERASE_AFTER);
  cl_assert_equal_i(count, s_option_num_rows);
  // 30 minutes has gone; 1 hour, the longer ones and Never remain.
  cl_assert_equal_i(ARRAY_LENGTH(s_expected_shred_delays) - 1, s_option_num_rows);

  for (int i = 0; i < count; ++i) {
    prv_choose_option(i);
    cl_assert_equal_i(expected[i], s_shred_delay_s);
    cl_assert_equal_i(0, s_rejected_delays);
    prv_select(ROW_ERASE_AFTER);
  }
}

// Raising the lock delay past the erase delay must push the erase delay up, not
// hand the store a pair it will refuse.
void test_settings_security__raising_the_lock_delay_pushes_the_erase_delay_up(void) {
  prv_install_pin("1234");
  prv_open_settings();

  prv_choose_shred_delay(30 * 60);
  prv_choose_lock_delay(60 * 60);

  cl_assert_equal_i(60 * 60, s_lock_delay_s);
  // The nearest option that is still at or past the lock delay, not Never.
  cl_assert_equal_i(60 * 60, s_shred_delay_s);
  cl_assert_equal_i(0, s_rejected_delays);
}

// Pushing the erase delay up must not quietly turn the timed erase off either.
void test_settings_security__never_survives_raising_the_lock_delay(void) {
  prv_install_pin("1234");
  prv_open_settings();

  prv_choose_shred_delay(SECURITY_LOCK_SHRED_DELAY_NEVER);
  prv_choose_lock_delay(60 * 60);

  cl_assert_equal_i(60 * 60, s_lock_delay_s);
  cl_assert_equal_i(SECURITY_LOCK_SHRED_DELAY_NEVER, s_shred_delay_s);
  cl_assert_equal_i(0, s_rejected_delays);
}

// The property that matters more than any single case: no sequence of ordinary
// navigation may leave the two delays in a state the store rejects.
void test_settings_security__no_navigation_produces_a_rejected_pair(void) {
  prv_install_pin("1234");
  prv_open_settings();

  for (size_t s = 0; s < ARRAY_LENGTH(s_expected_shred_delays); ++s) {
    for (size_t l = 0; l < ARRAY_LENGTH(s_expected_lock_delays); ++l) {
      // Back down to the shortest lock delay first so every erase option is
      // reachable, then set the pair under test.
      prv_choose_lock_delay(s_expected_lock_delays[0]);
      prv_choose_shred_delay(s_expected_shred_delays[s]);
      prv_choose_lock_delay(s_expected_lock_delays[l]);

      cl_assert_equal_i(s_expected_lock_delays[l], s_lock_delay_s);
      cl_assert((s_shred_delay_s == SECURITY_LOCK_SHRED_DELAY_NEVER) ||
                (s_shred_delay_s >= s_lock_delay_s));
      cl_assert_equal_i(0, s_rejected_delays);
    }
  }
}

// Whatever the phone last set is what the row has to report, even if it is not
// a value the picker offers. Rounding it to the nearest offered option in the
// subtitle would tell the user they have longer than they do.
void test_settings_security__row_reports_a_delay_the_picker_does_not_offer(void) {
  prv_install_pin("1234");
  s_lock_delay_s = 45 * 60;
  prv_open_settings();

  prv_draw(ROW_LOCK_AFTER);
  cl_assert(strstr(s_drawn_subtitle, "45 min") != NULL);
}

void test_settings_security__delay_pickers_open_on_the_current_choice(void) {
  prv_install_pin("1234");
  s_lock_delay_s = 15 * 60;
  s_shred_delay_s = 4 * 60 * 60;
  prv_open_settings();

  prv_select(ROW_LOCK_AFTER);
  cl_assert_equal_i(2, s_option_choice);  // 1, 5, 15 minutes

  prv_select(ROW_ERASE_AFTER);
  cl_assert_equal_i(3, s_option_choice);  // 30m, 1h, 2h, 4h
}
