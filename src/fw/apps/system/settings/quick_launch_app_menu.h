/* SPDX-FileCopyrightText: 2024 Google LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include "apps/system/settings/quick_launch.h"

#include "applib/ui/window.h"

typedef enum QuickLaunchMenuCategory {
  //! Entries that are only visible in Quick Launch, e.g. the system toggles.
  QuickLaunchMenuCategoryActions,
  //! Regular launcher apps.
  QuickLaunchMenuCategoryApps,
} QuickLaunchMenuCategory;

//! @param binding The binding being edited.
//! @param category Which kind of target the menu lists.
//! @param parent The category menu to unwind along with this one on selection.
void quick_launch_app_menu_window_push(QuickLaunchBinding binding, QuickLaunchMenuCategory category,
                                       Window *parent);
