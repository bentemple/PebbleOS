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
static SecurityLockState s_state;
static uint8_t s_failed_attempts;
static int s_reset_attempts_calls;
//! Both funnels together, whichever one was reached. Deliberately not named
//! s_engage_calls: test_lockdown.c has a counter by that name that means the
//! countdown funnel ONLY, and reading one file's assertions with the other's
//! meaning in mind is how "it locked" gets confused with "it erased".
//! s_countdown_calls and s_erase_now_calls below are the per-funnel counts.
static int s_engage_calls_any_funnel;
static int s_erase_now_calls;
static int s_countdown_calls;
static uint32_t s_lock_delay_s;
static uint32_t s_shred_delay_s;
static int s_rejected_delays;

//! Wipes asked for with the duress reason, and wipes refused because the
//! feature had already been turned off.
static int s_duress_shreds;
static int s_refused_shreds;
//! What a wipe reports destroying. Zero models the dirty-since-shred early-out,
//! where there was nothing new to erase.
static uint32_t s_shred_wiped;

//! When each half of a duress disable happened. A sequence rather than a pair
//! of counters: which came first is the whole property under test, and an
//! end-state check passes against an implementation that raced.
static int s_next_seq;
static int s_duress_shred_seq;
static int s_disable_seq;

uint8_t security_lock_get_pin_len(void) {
  return s_stored_pin_len;
}

SecurityLockState security_lock_get_state(void) {
  return s_state;
}

static status_t prv_clear_pin(void);

//! Forces the store to refuse a PIN with something other than the "must
//! differ" verdict. Nothing the pad can produce provokes that -- it only offers
//! lengths security_lock_set_pin() accepts -- so the branch that reports it
//! would otherwise be unreachable from here.
static bool s_set_pin_fails;

//! Mirrors the store's own rules: turning the feature off is clearing the PIN,
//! and it is refused while Locked.
//!
//! Copy of src/fw/services/security_lock/service.c security_lock_disable(),
//! including its Locked refusal and its S_NO_ACTION_REQUIRED early-out.
status_t security_lock_disable(void) {
  if (s_state == SecurityLockStateDisabled) {
    return S_NO_ACTION_REQUIRED;
  }
  if (s_state == SecurityLockStateLocked) {
    return E_INVALID_OPERATION;
  }
  return prv_clear_pin();
}

status_t security_lock_set_pin(const char *digits, uint8_t len) {
  if (s_set_pin_fails) {
    return E_INTERNAL;
  }
  if (!security_lock_pin_len_is_valid(len)) {
    return E_INVALID_ARGUMENT;
  }
  memcpy(s_stored_pin, digits, len);
  s_stored_pin_len = len;
  s_failed_attempts = 0;
  // Setting a PIN is what turns the feature on; there is nothing else to opt
  // in with.
  s_state = SecurityLockStateArmed;
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

static status_t prv_clear_pin(void) {
  memset(s_stored_pin, 0, sizeof(s_stored_pin));
  s_stored_pin_len = 0;
  // Clearing the real PIN takes the duress PIN with it; that is the only way
  // to remove one, and the reason the menu needs no row for it.
  memset(s_stored_duress, 0, sizeof(s_stored_duress));
  s_stored_duress_len = 0;
  s_state = SecurityLockStateDisabled;
  s_lock_delay_s = SECURITY_LOCK_DEFAULT_LOCK_DELAY_S;
  s_shred_delay_s = SECURITY_LOCK_DEFAULT_SHRED_DELAY_S;
  s_disable_seq = ++s_next_seq;
  return S_SUCCESS;
}

//! A tripwire, like the duress one below: the menu turns the feature off
//! through security_lock_disable(), which keeps the Locked refusal. Reaching
//! the store's recovery path directly would skip it.
status_t security_lock_clear_pin(void) {
  cl_fail("Settings must turn the feature off through security_lock_disable()");
  return E_INTERNAL;
}

//! Mirrors the master switch security_lock_shred() enforces: once the feature
//! is off there is nothing left to erase and the wipe is refused. That refusal
//! is what makes the ordering load-bearing rather than cosmetic.
//!
//! Copy of the !security_lock_is_enabled() early-out at the top of
//! src/fw/services/security_lock/shred.c security_lock_shred().
uint32_t security_lock_shred(SecurityShredReason reason) {
  if (s_state == SecurityLockStateDisabled) {
    s_refused_shreds++;
    return 0;
  }
  if (reason == SecurityShredReasonDuressPin) {
    s_duress_shreds++;
    s_duress_shred_seq = ++s_next_seq;
  }
  return s_shred_wiped;
}

//! Copy of src/fw/services/security_lock/service.c prv_verify_pin(): the
//! attempt is burned before the comparison, a duress match is a success rather
//! than a failure, and the remaining count is derived from
//! SECURITY_LOCK_MAX_PIN_ATTEMPTS.
static SecurityPinVerdict prv_verify(const char *digits, uint8_t len,
                                     uint8_t *attempts_remaining_out) {
  if (s_failed_attempts < UINT8_MAX) {
    s_failed_attempts++;
  }
  SecurityPinVerdict verdict = SecurityPinVerdictWrong;
  if ((len == s_stored_pin_len) && (memcmp(digits, s_stored_pin, len) == 0)) {
    verdict = SecurityPinVerdictReal;
  } else if ((s_stored_duress_len != 0) && (len == s_stored_duress_len) &&
             (memcmp(digits, s_stored_duress, len) == 0)) {
    verdict = SecurityPinVerdictDuress;
  }
  // A duress match is a success, not a failed attempt.
  if (verdict != SecurityPinVerdictWrong) {
    s_failed_attempts = 0;
  }
  if (attempts_remaining_out) {
    *attempts_remaining_out = (s_failed_attempts >= SECURITY_LOCK_MAX_PIN_ATTEMPTS)
                                  ? 0
                                  : SECURITY_LOCK_MAX_PIN_ATTEMPTS - s_failed_attempts;
  }
  return verdict;
}

bool security_lock_verify_pin(const char *digits, uint8_t len, uint8_t *attempts_remaining_out) {
  const SecurityPinVerdict verdict = prv_verify(digits, len, attempts_remaining_out);
  if (verdict == SecurityPinVerdictDuress) {
    // Reported as an ordinary success, exactly as the real one does, and the
    // wipe it takes with it is the thing that must not be lost.
    security_lock_shred(SecurityShredReasonDuressPin);
  }
  return verdict != SecurityPinVerdictWrong;
}

SecurityPinVerdict security_lock_verify_pin_verdict(const char *digits, uint8_t len) {
  // Deliberately schedules nothing: ordering the wipe against the switch-off is
  // the caller's job, which is the whole reason this variant exists.
  return prv_verify(digits, len, NULL);
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

//! The two funnels, counted separately. Settings offers both actions, so which
//! row reaches which one is the thing that must not drift: aiming at the
//! recoverable row and erasing the watch instead is the whole hazard.
void security_lock_engage(SecurityShredReason reason) {
  s_engage_calls_any_funnel++;
  s_erase_now_calls++;
}

void security_lock_engage_with_countdown(SecurityShredReason reason) {
  s_engage_calls_any_funnel++;
  s_countdown_calls++;
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
//!
//! Copy of the ordering check in src/fw/services/security_lock/service.c
//! security_lock_set_delays().
status_t security_lock_set_delays(uint32_t lock_delay_s, uint32_t shred_delay_s) {
  if ((shred_delay_s != SECURITY_LOCK_SHRED_DELAY_NEVER) && (shred_delay_s < lock_delay_s)) {
    s_rejected_delays++;
    return E_INVALID_ARGUMENT;
  }
  s_lock_delay_s = lock_delay_s;
  s_shred_delay_s = shred_delay_s;
  return S_SUCCESS;
}

static bool s_alarms_when_locked = true;

bool security_lock_get_alarms_when_locked(void) {
  return s_alarms_when_locked;
}

status_t security_lock_set_alarms_when_locked(bool allowed) {
  s_alarms_when_locked = allowed;
  return S_SUCCESS;
}

// Fake launcher visibility pref
////////////////////////////////////
// Deliberately a shell pref rather than part of the lock record: what the
// launcher lists is a display preference, and hiding the app protects nothing.

static bool s_lock_in_launcher;

bool shell_prefs_get_lock_app_in_launcher(void) {
  return s_lock_in_launcher;
}

//! Mirrors the production default: off.
static bool s_block_notifications_when_locked;

bool shell_prefs_get_block_notifications_when_locked(void) {
  return s_block_notifications_when_locked;
}

void shell_prefs_set_block_notifications_when_locked(bool enable) {
  s_block_notifications_when_locked = enable;
}

void shell_prefs_set_lock_app_in_launcher(bool enable) {
  s_lock_in_launcher = enable;
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

// The lockdown confirmations.
static ClickHandler s_dialog_confirm;
static int s_dialog_pops;
static int s_dialog_pushes;
static ExpandableDialog s_expandable_dialog;

//! Out of memory. The rows must do nothing at all rather than lock or erase
//! without having said what it costs.
static bool s_dialog_create_fails;

ExpandableDialog *expandable_dialog_create_with_params(const char *dialog_name, ResourceId icon,
                                                       const char *text, GColor text_color,
                                                       GColor background_color,
                                                       DialogCallbacks *callbacks,
                                                       ResourceId select_icon,
                                                       ClickHandler select_click_handler) {
  if (s_dialog_create_fails) {
    return NULL;
  }
  s_dialog_confirm = select_click_handler;
  return &s_expandable_dialog;
}

void expandable_dialog_set_header(ExpandableDialog *e_dialog, const char *header) {}

void app_expandable_dialog_push(ExpandableDialog *e_dialog) {
  s_dialog_pushes++;
}

void expandable_dialog_pop(ExpandableDialog *e_dialog) {
  s_dialog_pops++;
}

// Lock Now must not call engage() inline: it asserts KernelMain and this runs
// on the app task. Neither may a duress disable, which is why the wipe and the
// switch-off can be ordered against each other at all.
static void (*s_deferred_callback)(void *);

void launcher_task_add_callback(void (*callback)(void *data), void *data) {
  s_deferred_callback = callback;
}

//! Stand in for the launcher task draining its queue.
static void prv_run_deferred(void) {
  cl_assert(s_deferred_callback != NULL);
  void (*callback)(void *) = s_deferred_callback;
  s_deferred_callback = NULL;
  callback(NULL);
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

// Reaching into the module's own allocation
////////////////////////////////////
//
// SettingsSecurityData is private to security.c, so the PIN buffers it keeps
// have no name here. They are reachable anyway: settings_window_create() is
// handed &data->callbacks, which is the first member, so s_module is the block
// the module allocated. Only the front of it is ever read -- the callbacks and
// the pin entry window, both of which this test can size, plus the handful of
// small fields declared straight after them, which is where the half-entered
// PIN lives.

#define MODULE_SCAN_BYTES (sizeof(SettingsCallbacks) + sizeof(SecurityPinEntryWindow) + 64)

//! Offset of `needle` in that window, or -1. Finding it is how the buffer is
//! located at all, so every caller asserts on the result rather than trusting
//! the layout.
static int prv_find_in_module(const char *needle, size_t len) {
  const char *base = (const char *)s_module;
  for (size_t i = 0; i + len <= MODULE_SCAN_BYTES; ++i) {
    if (memcmp(base + i, needle, len) == 0) {
      return (int)i;
    }
  }
  return -1;
}

//! What the module's allocation held the last time prv_deinit_cb() ran, taken
//! before it was handed back. See i18n_free_all() below.
static uint8_t s_block_at_deinit[MODULE_SCAN_BYTES];
static bool s_capture_block_at_deinit;

static void prv_assert_zeroed_at_deinit(size_t offset, size_t len) {
  cl_assert(offset + len <= sizeof(s_block_at_deinit));
  for (size_t i = 0; i < len; ++i) {
    cl_assert_equal_i(0, s_block_at_deinit[offset + i]);
  }
}

//! prv_deinit_cb() scrubs its buffers, calls this, and only then frees the
//! block -- so this is the last moment its contents can be read without
//! reading freed memory.
void i18n_free_all(const void *owner) {
  if (s_capture_block_at_deinit) {
    memcpy(s_block_at_deinit, owner, sizeof(s_block_at_deinit));
    s_capture_block_at_deinit = false;
  }
}

// Helpers
////////////////////////////////////

//! The master switch is first on both row sets, and while the feature is off it
//! is the only row: everything else configures or triggers something that does
//! not exist until there is a PIN.
#define ROW_ENABLED 0
#define ROWS_WHEN_OFF 1

//! Row order once the feature is on. There is no Clear PIN and no PIN Length:
//! clearing the PIN is what turning it off does, and the length is picked as
//! part of setting a PIN.
//!
//! Two lockdown rows rather than one: the recoverable action and the immediate
//! one are different enough that a single row would have to lie about one of
//! them. Lockdown is first, because it is the one to land on by accident.
#define ROW_CHANGE_PIN 1
#define ROW_LOCK_AFTER 2
#define ROW_ERASE_AFTER 3
#define ROW_DURESS_PIN 4
#define ROW_BLOCK_NOTIFICATIONS 5
#define ROW_ALARMS_WHEN_LOCKED 6
#define ROW_LOCK 7
#define ROW_LOCKDOWN_ERASE 8
#define ROW_SHOW_IN_LAUNCHER 9
#define ROWS_WHEN_ON 10

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

//! Choose a length on the picker that now opens every set-PIN flow. Defined
//! with the rest of the length helpers further down.
static void prv_choose_length(uint8_t len);

//! Pick an Erase After, through the picker rather than by writing the store.
//! Defined with the rest of the delay helpers further down.
static void prv_choose_shred_delay(uint32_t seconds);

//! Turn the feature on from the menu, the way a user would: the switch, the
//! length picker, then the PIN twice.
static void prv_enable_with_pin(const char *pin) {
  prv_select(ROW_ENABLED);
  prv_choose_length(strlen(pin));
  prv_submit(pin);
  prv_submit(pin);
  s_module->appear(s_module);
}

//! And off again, which costs the current PIN.
static void prv_disable_with_pin(const char *pin) {
  prv_select(ROW_ENABLED);
  prv_submit(pin);
  s_module->appear(s_module);
}

void test_settings_security__initialize(void) {
  memset(s_stored_pin, 0, sizeof(s_stored_pin));
  s_stored_pin_len = 0;
  memset(s_stored_duress, 0, sizeof(s_stored_duress));
  s_stored_duress_len = 0;
  s_state = SecurityLockStateDisabled;
  s_failed_attempts = 0;
  s_reset_attempts_calls = 0;
  s_duress_shreds = 0;
  s_refused_shreds = 0;
  // Something to destroy, unless a test says otherwise.
  s_shred_wiped = 0x1;
  s_next_seq = 0;
  s_duress_shred_seq = 0;
  s_disable_seq = 0;
  s_engage_calls_any_funnel = 0;
  s_erase_now_calls = 0;
  s_countdown_calls = 0;
  s_set_pin_fails = false;
  s_lock_delay_s = SECURITY_LOCK_DEFAULT_LOCK_DELAY_S;
  // Not the shipped default, which is Never. Most of this file is about rows
  // and prompts rather than about the erase being off, and a Never default
  // would make every subtitle assertion below read the disarmed wording.
  s_shred_delay_s = 30 * 60;
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
  s_dialog_pushes = 0;
  s_dialog_create_fails = false;
  s_deferred_callback = NULL;
  memset(s_block_at_deinit, 0xAA, sizeof(s_block_at_deinit));
  s_capture_block_at_deinit = false;
  // The shipped default: the panic action is in the launcher unless asked
  // otherwise.
  s_lock_in_launcher = true;
  // The shipped default too: a locked watch still wakes its owner.
  s_alarms_when_locked = true;
  // And the shipped default here: nothing the phone has already handed over is
  // thrown away, it is only held back until the watch is open again.
  s_block_notifications_when_locked = false;
}

void test_settings_security__cleanup(void) {
  if (s_module) {
    s_module->deinit(s_module);
    s_module = NULL;
  }
}

// The master switch
////////////////////////////////////
//
// First row on every row set, because everything below it does nothing while it
// is off -- and a row that does nothing is worse than no row: it reads as a
// control.

void test_settings_security__the_switch_is_the_first_row(void) {
  prv_open_settings();

  prv_draw(ROW_ENABLED);
  cl_assert_equal_s("Security Lock", s_drawn_title);
}

void test_settings_security__the_switch_is_the_first_row_with_a_pin_too(void) {
  prv_install_pin("1234");
  prv_open_settings();

  prv_draw(ROW_ENABLED);
  cl_assert_equal_s("Security Lock", s_drawn_title);
}

void test_settings_security__the_switch_reads_off_out_of_the_box(void) {
  prv_open_settings();

  prv_draw(ROW_ENABLED);
  // The context prefix the fake i18n leaves in place -- the plain "Off" is
  // shared with unrelated rows and needs disambiguating for translators.
  cl_assert(strstr(s_drawn_subtitle, "Off") != NULL);
  cl_assert(strstr(s_drawn_subtitle, "PIN") == NULL);
}

//! Setting a PIN is what turns it on; there is nothing else to opt in with.
void test_settings_security__setting_a_pin_turns_the_switch_on(void) {
  prv_install_pin("1234");
  prv_open_settings();

  prv_draw(ROW_ENABLED);
  cl_assert_equal_s("On", s_drawn_subtitle);
}

//! On and Off belong to the master switch alone. A PIN row that also said "On"
//! would read as a second control over the same thing.
void test_settings_security__the_pin_row_does_not_say_on_or_off(void) {
  prv_install_pin("1234");
  prv_open_settings();

  prv_draw(ROW_CHANGE_PIN);
  cl_assert(strstr(s_drawn_subtitle, "4") != NULL);
  cl_assert(strstr(s_drawn_subtitle, "On") == NULL);
}

//! With no PIN there is nothing to unlock with, so turning it on is the Set PIN
//! flow rather than a refusal the user has to decode -- starting with the
//! length, which is otherwise unreachable now the row for it is gone.
void test_settings_security__turning_it_on_asks_for_a_length_then_a_pin(void) {
  prv_open_settings();

  prv_select(ROW_ENABLED);

  // The picker first, and no pad until it has been answered.
  cl_assert(s_option_select != NULL);
  cl_assert(s_prompt == NULL);

  prv_choose_length(6);
  cl_assert(s_prompt != NULL);
  cl_assert_equal_i(6, s_prompt_pin_len);

  prv_submit("135792");
  prv_submit("135792");
  cl_assert_equal_i(6, s_stored_pin_len);

  s_module->appear(s_module);
  prv_draw(ROW_ENABLED);
  cl_assert_equal_s("On", s_drawn_subtitle);
}

//! The security point of the whole change: anyone holding an unlocked watch
//! could otherwise walk in here and switch the protection off. Turning it off
//! has to be as protected as unlocking is.
void test_settings_security__turning_it_off_requires_the_current_pin(void) {
  prv_install_pin("1234");
  prv_open_settings();

  prv_select(ROW_ENABLED);

  cl_assert(s_prompt != NULL);
  cl_assert_equal_i(4, s_prompt_pin_len);
  // Nothing has happened yet.
  cl_assert_equal_i(SecurityLockStateArmed, s_state);

  prv_submit("9999");
  cl_assert_equal_i(SecurityLockStateArmed, s_state);
  cl_assert_equal_i(4, s_stored_pin_len);
  cl_assert(s_prompt != NULL);

  prv_submit("1234");
  cl_assert_equal_i(SecurityLockStateDisabled, s_state);
  cl_assert(s_prompt == NULL);
}

//! Off is a clean slate rather than a pause: the PIN goes with it, so "turn it
//! back on" is setting a PIN again.
void test_settings_security__turning_it_off_clears_the_pin(void) {
  prv_install_pin("1234");
  prv_open_settings();

  prv_disable_with_pin("1234");

  cl_assert_equal_i(0, s_stored_pin_len);
  cl_assert_equal_i(SecurityLockStateDisabled, s_state);
}

// The duress PIN goes with it too. Asserted once, further down, next to the
// rest of the duress behaviour:
// test_settings_security__disabling_takes_the_duress_pin_with_it.

//! The prompt has to say what it costs. Nothing else on screen distinguishes
//! this from the Change PIN prompt, and the two have very different outcomes.
void test_settings_security__the_disable_prompt_says_the_pin_goes(void) {
  prv_install_pin("1234");
  prv_open_settings();

  prv_select(ROW_ENABLED);

  cl_assert_equal_s("Turning off clears your PIN", s_prompt_message);
}

//! The store refuses to turn the feature off while the watch is Locked -- that
//! would be an unlock without the PIN. Settings is unreachable from a locked
//! watch, so nothing reaches this today; the prompt still has to cope, because
//! popping back to a menu that still reads "On" looks exactly like a switch
//! that was ignored.
void test_settings_security__a_refused_switch_off_says_so_on_the_prompt(void) {
  prv_install_pin("1234");
  s_state = SecurityLockStateLocked;
  prv_open_settings();

  prv_select(ROW_ENABLED);
  prv_submit("1234");  // the right PIN; it is the store that says no

  // Still on the prompt, with a reason, rather than back on a menu that would
  // report the feature as still on and give no clue why.
  cl_assert(s_prompt != NULL);
  cl_assert_equal_s("Could not turn it off", s_prompt_message);

  // And nothing was half-done.
  cl_assert_equal_i(SecurityLockStateLocked, s_state);
  cl_assert_equal_i(4, s_stored_pin_len);
}

//! Backing out of the prompt leaves the feature exactly as it was.
void test_settings_security__walking_away_from_the_disable_prompt_changes_nothing(void) {
  prv_install_pin("1234");
  prv_open_settings();

  prv_select(ROW_ENABLED);
  cl_assert(s_prompt_cancelable);
  s_module->appear(s_module);  // what backing out of the prompt looks like

  cl_assert_equal_i(SecurityLockStateArmed, s_state);
  cl_assert_equal_i(4, s_stored_pin_len);
  cl_assert_equal_i(ROWS_WHEN_ON, prv_num_rows());
}

//! Off leaves one row. Everything else configures or triggers something that
//! does not exist, and a row that does nothing reads as a control.
void test_settings_security__off_leaves_only_the_switch(void) {
  prv_install_pin("1234");
  prv_open_settings();
  cl_assert_equal_i(ROWS_WHEN_ON, prv_num_rows());

  prv_disable_with_pin("1234");

  cl_assert_equal_i(ROWS_WHEN_OFF, prv_num_rows());
  prv_draw(ROW_ENABLED);
  cl_assert_equal_s("Security Lock", s_drawn_title);
  cl_assert(strstr(s_drawn_subtitle, "Off") != NULL);
  cl_assert(strstr(s_drawn_subtitle, "PIN") == NULL);
}

void test_settings_security__the_rows_come_back_when_it_is_turned_on(void) {
  prv_install_pin("1234");
  prv_open_settings();

  prv_disable_with_pin("1234");
  prv_enable_with_pin("4321");

  cl_assert_equal_i(ROWS_WHEN_ON, prv_num_rows());
}

//! Named individually because each was its own decision, and a row set that
//! quietly regrew one of them would still have the right count.
void test_settings_security__nothing_else_is_reachable_while_it_is_off(void) {
  prv_install_pin("1234");
  prv_open_settings();
  prv_disable_with_pin("1234");

  for (uint16_t row = 0; row < prv_num_rows(); row++) {
    prv_draw(row);
    cl_assert(strcmp(s_drawn_title, "Lock") != 0);
    cl_assert(strcmp(s_drawn_title, "Lockdown + Erase") != 0);
    cl_assert(strcmp(s_drawn_title, "Lock Now") != 0);
    cl_assert(strcmp(s_drawn_title, "Lock After") != 0);
    cl_assert(strcmp(s_drawn_title, "Erase After") != 0);
    cl_assert(strcmp(s_drawn_title, "Duress PIN") != 0);
    cl_assert(strcmp(s_drawn_title, "Change PIN") != 0);
    cl_assert(strcmp(s_drawn_title, "PIN Length") != 0);
    cl_assert(strcmp(s_drawn_title, "Clear PIN") != 0);
    cl_assert(strcmp(s_drawn_title, "Show in Launcher") != 0);
  }
}

//! Clear PIN is gone for good: clearing the PIN is what turning the feature off
//! does, so a row for it would be the same button under a second name.
void test_settings_security__there_is_no_clear_pin_row(void) {
  prv_install_pin("1234");
  prv_open_settings();

  for (uint16_t row = 0; row < prv_num_rows(); row++) {
    prv_draw(row);
    cl_assert(strcmp(s_drawn_title, "Clear PIN") != 0);
  }
}

// Rows
////////////////////////////////////

void test_settings_security__hides_pin_actions_until_there_is_a_pin(void) {
  prv_open_settings();
  cl_assert_equal_i(ROWS_WHEN_OFF, prv_num_rows());
}

void test_settings_security__shows_pin_actions_once_set(void) {
  prv_install_pin("1234");
  prv_open_settings();
  cl_assert_equal_i(ROWS_WHEN_ON, prv_num_rows());
}

//! An inconsistent record -- on with no PIN -- is not a state any control
//! produces, but it must read as off and offer the one row that repairs it
//! rather than a menu of controls with nothing behind them.
void test_settings_security__on_without_a_pin_reads_as_off(void) {
  s_state = SecurityLockStateArmed;
  prv_open_settings();

  cl_assert_equal_i(ROWS_WHEN_OFF, prv_num_rows());
  prv_draw(ROW_ENABLED);
  cl_assert(strstr(s_drawn_subtitle, "Off") != NULL);

  // And selecting it sets a PIN rather than trying to turn off what is not on.
  prv_select(ROW_ENABLED);
  prv_choose_length(4);
  prv_submit("1234");
  prv_submit("1234");
  cl_assert_equal_i(4, s_stored_pin_len);
}

// Rows appear and disappear underneath the selection, so the mapping from row
// index to action has to keep up. Getting it wrong here means aiming at one row
// and erasing the watch instead.
void test_settings_security__rows_follow_the_pin_appearing(void) {
  prv_open_settings();
  cl_assert_equal_i(ROWS_WHEN_OFF, prv_num_rows());

  prv_enable_with_pin("1234");
  cl_assert_equal_i(ROWS_WHEN_ON, prv_num_rows());

  prv_draw(ROW_CHANGE_PIN);
  cl_assert_equal_s("Change PIN", s_drawn_title);

  // And the lockdown rows really are where the indices say, not something that
  // fell through to a default.
  prv_draw(ROW_LOCK);
  cl_assert_equal_s("Lock", s_drawn_title);
  prv_draw(ROW_LOCKDOWN_ERASE);
  cl_assert_equal_s("Lockdown + Erase", s_drawn_title);
}

// Duress PIN
////////////////////////////////////

//! Every string the menu puts on screen, row by row.
//!
//! Strings and not a row count: a count sees a row appearing or disappearing
//! and nothing else, and the cheapest way to leak the duress bit is a word in a
//! title or a subtitle on a row that was always there.
#define MAX_CAPTURED_ROWS 16
typedef struct {
  int count;
  char titles[MAX_CAPTURED_ROWS][sizeof(s_drawn_title)];
  char subtitles[MAX_CAPTURED_ROWS][sizeof(s_drawn_subtitle)];
} CapturedRows;

static void prv_capture_rows(CapturedRows *out) {
  out->count = prv_num_rows();
  cl_assert(out->count <= MAX_CAPTURED_ROWS);
  for (int row = 0; row < out->count; row++) {
    prv_draw(row);
    strcpy(out->titles[row], s_drawn_title);
    strcpy(out->subtitles[row], s_drawn_subtitle);
  }
}

// The menu must look identical whether or not a duress PIN is configured.
// Anything that varies -- a row appearing, a subtitle changing, a word in a
// title -- hands over the one bit the feature depends on keeping.
void test_settings_security__duress_state_is_not_visible(void) {
  CapturedRows without;
  CapturedRows with;

  prv_install_pin("1234");
  prv_open_settings();
  prv_capture_rows(&without);

  // Configure one, through the menu, exactly as a user would.
  prv_select(ROW_DURESS_PIN);
  prv_submit("1234");
  prv_submit("5678");
  prv_submit("5678");
  cl_assert_equal_i(4, s_stored_duress_len);

  s_module->appear(s_module);
  prv_capture_rows(&with);

  cl_assert_equal_i(without.count, with.count);
  for (int row = 0; row < with.count; row++) {
    cl_assert_equal_s(without.titles[row], with.titles[row]);
    cl_assert_equal_s(without.subtitles[row], with.subtitles[row]);
  }
}

//! And the Duress PIN row in particular carries no subtitle at all: "Set"
//! against "Not set" is the whole secret, and so is anything that only ever
//! appears on one of the two.
void test_settings_security__the_duress_row_has_no_subtitle(void) {
  prv_install_pin("1234");
  prv_open_settings();

  prv_draw(ROW_DURESS_PIN);
  cl_assert_equal_s("Duress PIN", s_drawn_title);
  cl_assert_equal_s("", s_drawn_subtitle);

  prv_select(ROW_DURESS_PIN);
  prv_submit("1234");
  prv_submit("5678");
  prv_submit("5678");
  s_module->appear(s_module);

  prv_draw(ROW_DURESS_PIN);
  cl_assert_equal_s("Duress PIN", s_drawn_title);
  cl_assert_equal_s("", s_drawn_subtitle);
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
//
// So this flow gets no length picker: the choice would be one that cannot be
// honoured.
void test_settings_security__duress_pin_matches_the_real_pin_length(void) {
  prv_install_pin("123456");
  prv_open_settings();

  prv_select(ROW_DURESS_PIN);
  cl_assert_equal_i(6, s_prompt_pin_len);
  s_option_select = NULL;

  prv_submit("123456");
  cl_assert(s_option_select == NULL);
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

//! A refusal puts the flow back at the FIRST of the two new-PIN entries, and
//! takes the refused digits with it. Left sitting at the repeat stage, the next
//! entry would be compared against a buffer that has just been scrubbed, so a
//! user retyping a perfectly good PIN would be told it did not match.
void test_settings_security__a_refused_pin_restarts_the_pair(void) {
  prv_install_pin("1234");
  prv_open_settings();
  prv_select(ROW_DURESS_PIN);

  prv_submit("1234");
  prv_submit("1234");  // same as the real PIN
  prv_submit("1234");
  cl_assert_equal_s("Must differ from your PIN", s_prompt_message);
  // The refused digits are not left in the module's buffer to be compared
  // against, or to be read out of a heap block later.
  cl_assert_equal_i(-1, prv_find_in_module("1234", 4));

  // A fresh pair takes from here, with no "did not match" in between.
  prv_submit("5678");
  cl_assert_equal_s("", s_prompt_message);
  prv_submit("5678");
  cl_assert_equal_i(4, s_stored_duress_len);
}

//! Any other refusal from the store says so too, rather than dropping the user
//! back into the menu with nothing changed and no reason given. Unreachable by
//! ordinary use -- the pad only produces lengths the store accepts -- which is
//! exactly why it needs driving from here.
void test_settings_security__a_pin_the_store_will_not_save_says_so(void) {
  prv_open_settings();
  prv_select(ROW_ENABLED);
  prv_choose_length(4);

  s_set_pin_fails = true;
  prv_submit("1234");
  prv_submit("1234");

  cl_assert(s_prompt != NULL);
  cl_assert_equal_s("Could not save that PIN", s_prompt_message);
  cl_assert_equal_i(0, s_stored_pin_len);

  // And the flow still works once the store is willing.
  s_set_pin_fails = false;
  prv_submit("4321");
  prv_submit("4321");
  cl_assert_equal_i(4, s_stored_pin_len);
}

// The duress PIN at the disable prompt
////////////////////////////////////
//
// It acts like the real PIN, but wipes first. Being made to switch the
// protection off is close to the case the duress PIN exists for, so refusing it
// there would cost the user the behaviour they expected at exactly the wrong
// moment.
//
// The order is the whole of it: security_lock_shred() refuses once the feature
// is off, so a switch-off that landed first would disarm the lock and erase
// nothing. Both halves therefore run in one callback on the launcher task,
// rather than the wipe being queued there while this task carries on to
// disable -- which is a race the scheduler decides.

//! Set a duress PIN through the menu, the way a user would, and clear the
//! bookkeeping the setup itself produced.
static void prv_install_duress_pin(const char *current, const char *duress) {
  prv_select(ROW_DURESS_PIN);
  prv_submit(current);
  prv_submit(duress);
  prv_submit(duress);
  cl_assert_equal_i(strlen(duress), s_stored_duress_len);
  s_module->appear(s_module);
  s_duress_shreds = 0;
  s_next_seq = 0;
  s_duress_shred_seq = 0;
  s_disable_seq = 0;
}

void test_settings_security__a_duress_pin_wipes_then_turns_the_feature_off(void) {
  prv_install_pin("1234");
  prv_open_settings();
  prv_install_duress_pin("1234", "5678");

  prv_select(ROW_ENABLED);
  prv_submit("5678");

  // Accepted: the prompt closes exactly as it does for the real PIN, and it is
  // not treated as a wrong entry.
  cl_assert(s_prompt == NULL);
  cl_assert(strstr(s_prompt_message, "Wrong") == NULL);

  // Nothing has happened on this task. Both halves belong to the launcher.
  cl_assert_equal_i(0, s_duress_shreds);
  cl_assert_equal_i(SecurityLockStateArmed, s_state);

  prv_run_deferred();

  // Wiped, and then off -- with the PIN and the duress PIN gone with it, which
  // is what a real disable does.
  cl_assert_equal_i(1, s_duress_shreds);
  cl_assert_equal_i(SecurityLockStateDisabled, s_state);
  cl_assert_equal_i(0, s_stored_pin_len);
  cl_assert_equal_i(0, s_stored_duress_len);

  // The load-bearing assertion. Both outcomes hold whichever way round they
  // ran; only the order distinguishes this from the version that raced.
  cl_assert(s_duress_shred_seq != 0);
  cl_assert(s_disable_seq != 0);
  cl_assert(s_duress_shred_seq < s_disable_seq);
  // And the wipe was never handed a switched-off feature to refuse.
  cl_assert_equal_i(0, s_refused_shreds);
}

//! The wipe may legitimately destroy nothing: the dirty-since-shred early-out
//! skips the file zeroing when nothing has been written since the last one.
//! The switch-off must not be conditional on the wipe having done work.
void test_settings_security__a_duress_pin_disables_even_when_the_wipe_erased_nothing(void) {
  prv_install_pin("1234");
  prv_open_settings();
  prv_install_duress_pin("1234", "5678");
  s_shred_wiped = 0;

  prv_select(ROW_ENABLED);
  prv_submit("5678");
  prv_run_deferred();

  cl_assert_equal_i(1, s_duress_shreds);
  cl_assert_equal_i(SecurityLockStateDisabled, s_state);
  cl_assert_equal_i(0, s_stored_pin_len);
  cl_assert(s_duress_shred_seq < s_disable_seq);
}

//! A duress match is a success, not a failed attempt -- so the prompt does not
//! spend one of its three tries on it.
void test_settings_security__a_duress_pin_at_the_disable_prompt_is_not_a_wrong_entry(void) {
  prv_install_pin("1234");
  prv_open_settings();
  prv_install_duress_pin("1234", "5678");

  prv_select(ROW_ENABLED);
  prv_submit("5678");

  cl_assert_equal_i(0, s_failed_attempts);
  cl_assert(strstr(s_prompt_message, "Wrong") == NULL);
}

//! The real PIN is untouched by any of this: it still turns the feature off
//! then and there, with no wipe and nothing deferred.
void test_settings_security__the_real_pin_turns_it_off_without_a_wipe(void) {
  prv_install_pin("1234");
  prv_open_settings();
  prv_install_duress_pin("1234", "5678");

  prv_select(ROW_ENABLED);
  prv_submit("1234");

  cl_assert_equal_i(SecurityLockStateDisabled, s_state);
  cl_assert_equal_i(0, s_duress_shreds);
  cl_assert(s_deferred_callback == NULL);
  cl_assert(s_prompt == NULL);
}

//! And a wrong PIN is still a wrong PIN: nothing wiped, nothing disabled.
void test_settings_security__a_wrong_pin_at_the_disable_prompt_wipes_nothing(void) {
  prv_install_pin("1234");
  prv_open_settings();
  prv_install_duress_pin("1234", "5678");

  prv_select(ROW_ENABLED);
  prv_submit("9999");

  cl_assert_equal_i(SecurityLockStateArmed, s_state);
  cl_assert_equal_i(0, s_duress_shreds);
  cl_assert(s_deferred_callback == NULL);
  cl_assert(s_prompt != NULL);
}

// The other prompts keep the ordinary duress semantics: the wipe is queued by
// the store as the entry is accepted, and nothing in those flows turns the
// feature off underneath it. Only the disable prompt has to order the two by
// hand, and only it is told which PIN matched.
void test_settings_security__a_duress_pin_still_authorises_a_pin_change(void) {
  prv_install_pin("1234");
  prv_open_settings();
  prv_install_duress_pin("1234", "5678");

  prv_select(ROW_CHANGE_PIN);
  prv_submit("5678");

  cl_assert_equal_i(1, s_duress_shreds);
  cl_assert(s_option_select != NULL);  // through to the length picker
}

// Turning the feature off is the only way to remove a duress PIN, so it has to
// actually do it -- otherwise a forgotten one survives into the next PIN. Off
// is a clean slate rather than a pause, and this is the whole of it: both PINs
// gone.
void test_settings_security__disabling_takes_the_duress_pin_with_it(void) {
  prv_install_pin("1234");
  prv_open_settings();
  prv_install_duress_pin("1234", "5678");

  prv_disable_with_pin("1234");

  cl_assert_equal_i(0, s_stored_pin_len);
  cl_assert_equal_i(0, s_stored_duress_len);
  cl_assert_equal_i(SecurityLockStateDisabled, s_state);
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

void test_settings_security__turning_it_off_reaches_the_prompt(void) {
  prv_install_pin("1234");
  prv_open_settings();
  prv_select(ROW_ENABLED);
  cl_assert(s_prompt != NULL);
}

void test_settings_security__setting_a_first_pin_reaches_the_picker(void) {
  prv_open_settings();
  prv_select(ROW_ENABLED);
  cl_assert(s_option_select != NULL);
  prv_choose_length(4);
  cl_assert(s_prompt != NULL);
}

// Setting a PIN
////////////////////////////////////

void test_settings_security__set_pin_needs_two_matching_entries(void) {
  prv_open_settings();
  prv_select(ROW_ENABLED);
  prv_choose_length(4);
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
  prv_select(ROW_ENABLED);
  prv_choose_length(4);

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
  prv_select(ROW_ENABLED);
  prv_choose_length(4);
  cl_assert(s_prompt_cancelable);
}

// Scrubbing the half-entered PIN
////////////////////////////////////
//
// Collecting a PIN twice means keeping the first entry somewhere until the
// second one arrives, and walking away leaves it there: the prompt is
// cancelable, so BACK pops the window without telling anyone. The window
// scrubs its own pad (see test_pin_entry_window.c), but this buffer belongs to
// Settings and nothing else clears it.

//! Get as far as the first of the two new-PIN entries and find where the module
//! parked it. Asserting it is findable is what makes the checks below able to
//! fail: a buffer the search cannot see would pass every "it is zero" test.
static size_t prv_park_a_first_entry(const char *pin) {
  prv_select(ROW_ENABLED);
  prv_choose_length(strlen(pin));
  prv_submit(pin);
  const int at = prv_find_in_module(pin, strlen(pin));
  cl_assert(at >= 0);
  return (size_t)at;
}

void test_settings_security__backing_out_scrubs_the_half_entered_pin(void) {
  prv_open_settings();
  const size_t at = prv_park_a_first_entry("135792");
  // Digits still on the pad when the user walked away.
  memcpy(s_prompt->digits, "1357", 4);

  s_module->appear(s_module);  // what backing out of the prompt looks like

  for (size_t i = 0; i < strlen("135792"); ++i) {
    cl_assert_equal_i(0, ((const uint8_t *)s_module)[at + i]);
  }
  for (size_t i = 0; i < sizeof(s_prompt->digits); ++i) {
    cl_assert_equal_i(0, s_prompt->digits[i]);
  }
}

//! And closing the menu outright, which is the ordinary way out: the block goes
//! back to the heap, so whatever is in it at that moment is what anyone reading
//! freed memory gets.
void test_settings_security__closing_the_menu_scrubs_the_half_entered_pin(void) {
  prv_open_settings();
  const size_t at = prv_park_a_first_entry("135792");
  memcpy(s_prompt->digits, "1357", 4);
  const size_t pad_at = (const uint8_t *)s_prompt->digits - (const uint8_t *)s_module;

  s_capture_block_at_deinit = true;
  s_module->deinit(s_module);
  s_module = NULL;  // already torn down; cleanup must not do it again
  cl_assert(!s_capture_block_at_deinit);  // the snapshot really was taken

  prv_assert_zeroed_at_deinit(at, strlen("135792"));
  prv_assert_zeroed_at_deinit(pad_at, sizeof(s_prompt->digits));
}

// Changing the PIN requires the current one
////////////////////////////////////

void test_settings_security__change_requires_the_current_pin(void) {
  prv_install_pin("1234");
  prv_open_settings();
  prv_select(ROW_CHANGE_PIN);

  prv_submit("9999");
  cl_assert(s_prompt != NULL);

  prv_submit("1234");
  prv_choose_length(4);
  prv_submit("5678");
  prv_submit("5678");

  cl_assert(s_prompt == NULL);
  cl_assert_equal_i(4, security_lock_get_pin_len());
  cl_assert(security_lock_verify_pin("5678", 4, NULL));
}

// Without this, requiring the current PIN to turn the feature off would be
// theatre: an attacker would just set their own over the top.
void test_settings_security__change_cannot_be_used_to_bypass_the_old_pin(void) {
  prv_install_pin("1234");
  prv_open_settings();
  prv_select(ROW_CHANGE_PIN);

  // Wrong PIN, then the full pair that would set a new one if the prompt had
  // let it through. One entry short of that and the flow could not have
  // completed anyway, so it would prove nothing.
  prv_submit("9999");
  prv_submit("5678");
  prv_submit("5678");

  cl_assert_equal_i(4, s_stored_pin_len);
  cl_assert(security_lock_verify_pin("1234", 4, NULL));
  cl_assert(!security_lock_verify_pin("5678", 4, NULL));
}

// Attempt counter
////////////////////////////////////

void test_settings_security__gives_up_after_three_wrong_attempts(void) {
  prv_install_pin("1234");
  prv_open_settings();
  prv_select(ROW_ENABLED);

  prv_submit("9999");
  cl_assert(s_prompt != NULL);
  prv_submit("9998");
  cl_assert(s_prompt != NULL);
  prv_submit("9997");
  cl_assert(s_prompt == NULL);

  cl_assert_equal_i(4, security_lock_get_pin_len());
}

// A wrong entry here costs an attempt exactly as it does on the lock screen.
// Putting the counter back on a failure made this menu a free PIN oracle, and
// zeroed a counter the lock screen's own bound is built on.
void test_settings_security__wrong_attempts_are_not_given_back(void) {
  prv_install_pin("1234");
  prv_open_settings();
  prv_select(ROW_ENABLED);

  prv_submit("9999");
  prv_submit("9998");
  prv_submit("9997");

  cl_assert_equal_i(SECURITY_LOCK_MAX_PIN_ATTEMPTS, security_lock_get_failed_attempts());
  cl_assert(security_lock_attempts_exhausted());
}

// And coming back to the row does not hand the budget out again: the prompt's
// own allowance is seeded from the persisted counter.
void test_settings_security__reopening_the_row_does_not_restore_the_budget(void) {
  prv_install_pin("1234");
  prv_open_settings();
  prv_select(ROW_ENABLED);

  prv_submit("9999");
  prv_submit("9998");
  cl_assert(s_prompt != NULL);

  prv_select(ROW_ENABLED);
  prv_submit("9997");

  // Spent, not restarted: the prompt gives up rather than offering three more.
  cl_assert(s_prompt == NULL);
  cl_assert_equal_i(SECURITY_LOCK_MAX_PIN_ATTEMPTS, security_lock_get_failed_attempts());
}

void test_settings_security__a_correct_pin_also_leaves_the_counter_clear(void) {
  prv_install_pin("1234");
  prv_open_settings();
  prv_select(ROW_ENABLED);

  prv_submit("1234");

  cl_assert_equal_i(0, security_lock_get_failed_attempts());
  cl_assert(s_reset_attempts_calls > 0);
}

// PIN length
////////////////////////////////////
//
// A step in the set-PIN flow rather than a row of its own. With the menu down
// to the master switch while the feature is off there is nowhere for a row to
// live, and a first PIN would otherwise get whatever length happened to be
// stored rather than one the user chose.

//! The lengths the picker must offer, in order. Stated here rather than derived
//! from the module: "every even width from four to ten" is the requirement, so
//! the test has to fail if the module starts offering a five.
static const uint8_t s_expected_lengths[] = {4, 6, 8, 10};

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

void test_settings_security__offers_only_the_even_lengths_from_four_to_ten(void) {
  prv_open_settings();
  prv_select(ROW_ENABLED);

  cl_assert_equal_i(ARRAY_LENGTH(s_expected_lengths), s_option_num_rows);

  // And each row really does produce the length it claims.
  for (int i = 0; i < (int)ARRAY_LENGTH(s_expected_lengths); ++i) {
    s_option_select(&s_option_menu, i, NULL);
    cl_assert_equal_i(s_expected_lengths[i], s_prompt_pin_len);
    s_module->appear(s_module);
    prv_select(ROW_ENABLED);
  }
}

//! The whole flow at the longest offered length, not just the picker: the
//! length reaches the pad, the pad collects ten digits, the repeat compares all
//! ten, and the store keeps them. Every buffer on that path is sized to
//! SECURITY_LOCK_PIN_MAX_LEN, so this is where a stale one shows up.
void test_settings_security__a_ten_digit_pin_round_trips(void) {
  prv_open_settings();

  prv_enable_with_pin("1357924681");

  cl_assert_equal_i(10, s_stored_pin_len);
  cl_assert_equal_i(0, memcmp(s_stored_pin, "1357924681", 10));
  prv_draw(ROW_ENABLED);
  cl_assert_equal_s("On", s_drawn_subtitle);
}

//! And the mismatch check still compares the whole thing. Two ten-digit PINs
//! differing only in the last digit must not be taken as a match -- a compare
//! bounded by the shorter old maximum would accept them.
void test_settings_security__a_ten_digit_repeat_must_match_every_digit(void) {
  prv_open_settings();

  prv_select(ROW_ENABLED);
  prv_choose_length(10);
  prv_submit("1357924681");
  prv_submit("1357924682");

  cl_assert_equal_i(0, s_stored_pin_len);
}

//! The length picked has to reach the pad that collects the new PIN, or a
//! six-digit choice quietly produces a four-digit PIN.
void test_settings_security__length_applies_to_a_changed_pin(void) {
  prv_install_pin("1234");
  prv_open_settings();

  prv_select(ROW_CHANGE_PIN);
  cl_assert_equal_i(4, s_prompt_pin_len);  // authorising against the old PIN
  prv_submit("1234");

  prv_choose_length(6);
  cl_assert_equal_i(6, s_prompt_pin_len);  // now collecting the new one

  prv_submit("135792");
  prv_submit("135792");
  cl_assert_equal_i(6, security_lock_get_pin_len());
}

void test_settings_security__length_applies_to_a_first_pin(void) {
  prv_open_settings();

  prv_select(ROW_ENABLED);
  prv_choose_length(6);
  cl_assert_equal_i(6, s_prompt_pin_len);

  prv_submit("135792");
  prv_submit("135792");
  cl_assert_equal_i(6, security_lock_get_pin_len());
}

//! Changing a PIN keeps its length unless the user says otherwise, so the
//! picker opens on it and the extra step costs one press.
void test_settings_security__length_menu_opens_on_the_current_length(void) {
  prv_install_pin("123456");
  prv_open_settings();

  prv_select(ROW_CHANGE_PIN);
  prv_submit("123456");

  cl_assert_equal_i(prv_length_index(6), s_option_choice);
}

//! And on the shortest offered when there is no PIN to keep the length of.
void test_settings_security__length_menu_opens_on_the_shortest_for_a_first_pin(void) {
  prv_open_settings();

  prv_select(ROW_ENABLED);

  cl_assert_equal_i(prv_length_index(4), s_option_choice);
}

//! Backing out of the picker leaves the authorisation spent rather than sitting
//! on a prompt that has already been satisfied.
void test_settings_security__backing_out_of_the_picker_drops_the_prompt(void) {
  prv_install_pin("1234");
  prv_open_settings();

  prv_select(ROW_CHANGE_PIN);
  prv_submit("1234");

  cl_assert(s_prompt == NULL);
  cl_assert(s_option_select != NULL);
}

// Lockdown and Lockdown + Erase
////////////////////////////////////
//
// Two actions, because they are not the same promise. Lockdown locks and starts
// the Erase After countdown, which the PIN calls off; Lockdown + Erase destroys
// the content there and then. A single row would have to describe one of them
// inaccurately, and the inaccurate one is always the destructive one.

void test_settings_security__the_lockdown_rows_are_hidden_while_it_is_off(void) {
  prv_open_settings();
  // Only the master switch; nothing here locks or erases anything.
  cl_assert_equal_i(ROWS_WHEN_OFF, prv_num_rows());
  prv_draw(ROW_ENABLED);
  cl_assert(strcmp("Lock", s_drawn_title) != 0);
  cl_assert(strcmp("Lockdown + Erase", s_drawn_title) != 0);
}

void test_settings_security__lockdown_confirms_before_engaging(void) {
  prv_install_pin("1234");
  prv_open_settings();

  prv_select(ROW_LOCK);
  cl_assert(s_dialog_confirm != NULL);
  cl_assert_equal_i(0, s_engage_calls_any_funnel);
  cl_assert(s_deferred_callback == NULL);
}

void test_settings_security__lockdown_erase_confirms_before_engaging(void) {
  prv_install_pin("1234");
  prv_open_settings();

  prv_select(ROW_LOCKDOWN_ERASE);
  cl_assert(s_dialog_confirm != NULL);
  cl_assert_equal_i(0, s_engage_calls_any_funnel);
  cl_assert(s_deferred_callback == NULL);
}

//! Out of memory is not a reason to lock or erase. With no confirmation to put
//! on screen the rows do nothing at all, rather than going ahead without ever
//! having said what it costs.
void test_settings_security__does_nothing_when_the_confirmation_cannot_be_shown(void) {
  prv_install_pin("1234");
  prv_open_settings();
  s_dialog_create_fails = true;

  prv_select(ROW_LOCK);
  cl_assert_equal_i(0, s_dialog_pushes);
  cl_assert(s_dialog_confirm == NULL);
  cl_assert(s_deferred_callback == NULL);
  cl_assert_equal_i(0, s_engage_calls_any_funnel);

  prv_select(ROW_LOCKDOWN_ERASE);
  cl_assert_equal_i(0, s_dialog_pushes);
  cl_assert(s_dialog_confirm == NULL);
  cl_assert(s_deferred_callback == NULL);
  cl_assert_equal_i(0, s_engage_calls_any_funnel);

  // And nothing about the refusal breaks the ordinary path.
  s_dialog_create_fails = false;
  prv_select(ROW_LOCK);
  cl_assert_equal_i(1, s_dialog_pushes);
  cl_assert(s_dialog_confirm != NULL);
}

//! The row that must not erase. Reaching the erase-now funnel from here would
//! destroy the content of a user who chose the recoverable action, and nothing
//! on screen would have said so.
void test_settings_security__lockdown_starts_a_countdown_rather_than_erasing(void) {
  prv_install_pin("1234");
  prv_open_settings();

  prv_select(ROW_LOCK);
  s_dialog_confirm(NULL, &s_expandable_dialog);
  prv_run_deferred();

  cl_assert_equal_i(1, s_countdown_calls);
  cl_assert_equal_i(0, s_erase_now_calls);
}

//! And the row that must. This is the only control in the whole feature that
//! erases on the spot without the user having been locked out first.
void test_settings_security__lockdown_erase_erases_on_the_spot(void) {
  prv_install_pin("1234");
  prv_open_settings();

  prv_select(ROW_LOCKDOWN_ERASE);
  s_dialog_confirm(NULL, &s_expandable_dialog);
  prv_run_deferred();

  cl_assert_equal_i(1, s_erase_now_calls);
  cl_assert_equal_i(0, s_countdown_calls);
}

// Both funnels assert they are on KernelMain and the erasing one blocks for the
// length of the wipe; this runs on the app task, so it has to be handed over.
void test_settings_security__the_lockdown_rows_defer_to_the_kernel(void) {
  prv_install_pin("1234");
  prv_open_settings();

  prv_select(ROW_LOCK);
  s_dialog_confirm(NULL, &s_expandable_dialog);

  cl_assert_equal_i(1, s_dialog_pops);
  cl_assert_equal_i(0, s_engage_calls_any_funnel);
  cl_assert(s_deferred_callback != NULL);

  s_deferred_callback(NULL);
  cl_assert_equal_i(1, s_engage_calls_any_funnel);
}

//! The subtitle is the only place the concrete delay appears, so it is what a
//! user reads to learn how long they have to change their mind.
void test_settings_security__the_lockdown_row_says_how_long_the_erase_is(void) {
  prv_install_pin("1234");
  s_shred_delay_s = 30 * 60;
  prv_open_settings();

  prv_draw(ROW_LOCK);
  cl_assert_equal_s("Lock", s_drawn_title);
  cl_assert(strstr(s_drawn_subtitle, "30 min") != NULL);
}

void test_settings_security__the_lockdown_row_reports_hours_as_hours(void) {
  prv_install_pin("1234");
  s_shred_delay_s = 4 * 60 * 60;
  prv_open_settings();

  prv_draw(ROW_LOCK);
  cl_assert(strstr(s_drawn_subtitle, "4 hr") != NULL);
}

//! Erase After set to Never is how a user gets lock-without-erase -- there is
//! deliberately no separate lock-only action -- so the row has to stop
//! promising an erase rather than show a bare zero.
void test_settings_security__the_lockdown_row_says_when_nothing_will_be_erased(void) {
  prv_install_pin("1234");
  s_shred_delay_s = SECURITY_LOCK_SHRED_DELAY_NEVER;
  prv_open_settings();

  prv_draw(ROW_LOCK);
  cl_assert_equal_s("Lock", s_drawn_title);
  cl_assert(strstr(s_drawn_subtitle, "no timed erase") != NULL);
  cl_assert(strstr(s_drawn_subtitle, "min") == NULL);
}

//! It follows the setting rather than being read once at open. The two rows sit
//! below Erase After in the same menu, so changing one and looking down at the
//! other is the ordinary way to use them.
void test_settings_security__the_lockdown_row_follows_the_erase_after_setting(void) {
  prv_install_pin("1234");
  prv_open_settings();

  prv_choose_shred_delay(SECURITY_LOCK_SHRED_DELAY_NEVER);
  prv_draw(ROW_LOCK);
  cl_assert(strstr(s_drawn_subtitle, "no timed erase") != NULL);

  prv_choose_shred_delay(60 * 60);
  prv_draw(ROW_LOCK);
  cl_assert(strstr(s_drawn_subtitle, "1 hr") != NULL);
}

//! Never changes nothing about the immediate action: it is the setting for the
//! timed erase, and this row does not use a timer.
void test_settings_security__lockdown_erase_still_erases_with_never_set(void) {
  prv_install_pin("1234");
  s_shred_delay_s = SECURITY_LOCK_SHRED_DELAY_NEVER;
  prv_open_settings();

  prv_draw(ROW_LOCKDOWN_ERASE);
  cl_assert_equal_s("Lockdown + Erase", s_drawn_title);
  cl_assert(strstr(s_drawn_subtitle, "now") != NULL);

  prv_select(ROW_LOCKDOWN_ERASE);
  s_dialog_confirm(NULL, &s_expandable_dialog);
  prv_run_deferred();
  cl_assert_equal_i(1, s_erase_now_calls);
}

//! "Lock Now" described neither action once there were two of them, so it is
//! gone rather than reused for one of them.
void test_settings_security__there_is_no_lock_now_row(void) {
  prv_install_pin("1234");
  prv_open_settings();

  for (uint16_t row = 0; row < prv_num_rows(); row++) {
    prv_draw(row);
    cl_assert(strcmp(s_drawn_title, "Lock Now") != 0);
  }
}

// Show in Launcher
////////////////////////////////////

// Alarms while locked
////////////////////////////////////

//! A locked watch still wakes its owner; an erased one does not, and that half
//! is not this row's to change. The subtitle has to say where the permission
//! ends, or "On" reads as a promise the erase breaks.
void test_settings_security__alarms_when_locked_toggles(void) {
  prv_open_settings();
  prv_enable_with_pin("1234");

  prv_draw(ROW_ALARMS_WHEN_LOCKED);
  cl_assert_equal_s("Alarms When Locked", s_drawn_title);
  cl_assert_equal_s("Ring until erased", s_drawn_subtitle);

  prv_select(ROW_ALARMS_WHEN_LOCKED);
  cl_assert(!s_alarms_when_locked);
  prv_draw(ROW_ALARMS_WHEN_LOCKED);
  cl_assert_equal_s("Silent while locked", s_drawn_subtitle);

  prv_select(ROW_ALARMS_WHEN_LOCKED);
  cl_assert(s_alarms_when_locked);
}

//! Nothing to configure about a lock that is off, so the row goes with the rest.
void test_settings_security__alarms_row_hidden_while_off(void) {
  prv_open_settings();
  cl_assert_equal_i(ROWS_WHEN_OFF, prv_num_rows());
  prv_enable_with_pin("1234");
  cl_assert_equal_i(ROWS_WHEN_ON, prv_num_rows());
}

// Gated on the switch like the rows above it. While it is off the Lockdown app
// is hidden from the launcher and from Quick Launch, so a row offering to show
// it in the launcher would control something that is not there.
void test_settings_security__show_in_launcher_is_hidden_while_it_is_off(void) {
  prv_open_settings();
  cl_assert_equal_i(ROWS_WHEN_OFF, prv_num_rows());
  for (uint16_t row = 0; row < ROWS_WHEN_OFF; row++) {
    prv_draw(row);
    cl_assert(strcmp("Show in Launcher", s_drawn_title) != 0);
  }
}

// And the pref is left exactly as the user last set it, so it still means what
// it meant once the feature comes back.
void test_settings_security__hiding_the_row_does_not_rewrite_the_pref(void) {
  prv_install_pin("1234");
  prv_open_settings();
  prv_select(ROW_SHOW_IN_LAUNCHER);
  cl_assert(!shell_prefs_get_lock_app_in_launcher());

  prv_disable_with_pin("1234");
  cl_assert_equal_i(ROWS_WHEN_OFF, prv_num_rows());
  cl_assert(!shell_prefs_get_lock_app_in_launcher());

  prv_enable_with_pin("4321");
  cl_assert_equal_i(ROWS_WHEN_ON, prv_num_rows());
  prv_draw(ROW_SHOW_IN_LAUNCHER);
  cl_assert_equal_s("Show in Launcher", s_drawn_title);
  cl_assert(strstr(s_drawn_subtitle, "Off") != NULL);
}

void test_settings_security__show_in_launcher_is_the_last_row(void) {
  prv_install_pin("1234");
  prv_open_settings();
  cl_assert_equal_i(ROWS_WHEN_ON, prv_num_rows());
  prv_draw(ROW_SHOW_IN_LAUNCHER);
  cl_assert_equal_s("Show in Launcher", s_drawn_title);
}

void test_settings_security__show_in_launcher_toggles(void) {
  prv_install_pin("1234");
  prv_open_settings();

  prv_select(ROW_SHOW_IN_LAUNCHER);
  cl_assert(!shell_prefs_get_lock_app_in_launcher());

  prv_select(ROW_SHOW_IN_LAUNCHER);
  cl_assert(shell_prefs_get_lock_app_in_launcher());
}

// Turning it off is decluttering, not hiding: the app is still there and still
// bindable to a button. The row has to say so, and must not claim anything
// about security -- someone holding the watch has no reason to trigger a wipe
// of the data they came for.
void test_settings_security__show_in_launcher_says_quick_launch_still_works(void) {
  prv_install_pin("1234");
  prv_open_settings();

  prv_draw(ROW_SHOW_IN_LAUNCHER);
  cl_assert_equal_s("On", s_drawn_subtitle);

  prv_select(ROW_SHOW_IN_LAUNCHER);
  prv_draw(ROW_SHOW_IN_LAUNCHER);
  cl_assert(strstr(s_drawn_subtitle, "Off") != NULL);
  cl_assert(strstr(s_drawn_subtitle, "Quick Launch") != NULL);
}

// The row reads the pref rather than a copy taken when the menu opened, so a
// change made elsewhere is not shown as its old value.
void test_settings_security__show_in_launcher_reflects_the_stored_value(void) {
  prv_install_pin("1234");
  shell_prefs_set_lock_app_in_launcher(false);
  prv_open_settings();

  prv_draw(ROW_SHOW_IN_LAUNCHER);
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

// The delays only do anything once the feature is on: while it is off nothing
// locks and nothing is erased on a disconnect, so offering to time either would
// be the same lie Lock Now is hidden to avoid.
void test_settings_security__delay_rows_appear_with_the_pin(void) {
  prv_open_settings();
  cl_assert_equal_i(ROWS_WHEN_OFF, prv_num_rows());

  prv_enable_with_pin("1234");

  cl_assert_equal_i(ROWS_WHEN_ON, prv_num_rows());
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

// Block Notifications
////////////////////////////////////

//! Off by default, and the subtitle says what "off" does to a message rather
//! than just that it is off: kept, not shown.
void test_settings_security__block_notifications_defaults_to_off(void) {
  prv_install_pin("1234");
  prv_open_settings();

  prv_draw(ROW_BLOCK_NOTIFICATIONS);

  cl_assert(!shell_prefs_get_block_notifications_when_locked());
  cl_assert_equal_s("Block Notifications", s_drawn_title);
  cl_assert_equal_s("Off, kept until unlocked", s_drawn_subtitle);
}

//! Selecting it toggles, and the subtitle states the consequence of on --
//! discarded, which is the distinction the row exists to make.
void test_settings_security__block_notifications_toggles(void) {
  prv_install_pin("1234");
  prv_open_settings();

  prv_select(ROW_BLOCK_NOTIFICATIONS);

  cl_assert(shell_prefs_get_block_notifications_when_locked());
  prv_draw(ROW_BLOCK_NOTIFICATIONS);
  cl_assert_equal_s("On, discarded while locked", s_drawn_subtitle);

  prv_select(ROW_BLOCK_NOTIFICATIONS);
  cl_assert(!shell_prefs_get_block_notifications_when_locked());
}

//! And it is gone with the rest when the feature is off: there is no lock for a
//! notification to arrive behind.
void test_settings_security__block_notifications_is_hidden_when_off(void) {
  prv_install_pin("1234");
  prv_open_settings();
  cl_assert_equal_i(ROWS_WHEN_ON, prv_num_rows());

  prv_disable_with_pin("1234");

  cl_assert_equal_i(ROWS_WHEN_OFF, prv_num_rows());
}
