/* SPDX-FileCopyrightText: 2024 Google LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include "menu.h"

#include "shell/normal/quick_launch.h"

//! Every binding the Quick Launch settings menu can configure, in row order.
//! Combos are pairs of held buttons and have no ButtonId of their own, so this
//! enum, rather than a ButtonId, identifies a binding.
typedef enum QuickLaunchBinding {
  QuickLaunchBindingTapUp = 0,
  QuickLaunchBindingTapDown,
  QuickLaunchBindingHoldUp,
  QuickLaunchBindingHoldSelect,
  QuickLaunchBindingHoldDown,
  QuickLaunchBindingHoldBack,
  QuickLaunchBindingComboBackUp,
  QuickLaunchBindingComboUpDown,

  QuickLaunchBindingCount,
} QuickLaunchBinding;

AppInstallId quick_launch_binding_get_app(QuickLaunchBinding binding);
void quick_launch_binding_set_app(QuickLaunchBinding binding, AppInstallId app_id);
void quick_launch_binding_disable(QuickLaunchBinding binding);

const SettingsModuleMetadata *settings_quick_launch_get_info(void);
