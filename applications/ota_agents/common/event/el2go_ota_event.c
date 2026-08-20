/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/* Event abstraction weak default. No-op registration; callers fall back to
 * polling. See the zephyr/ backend for the real behavior. */

#include "el2go_app_compiler.h"
#include "el2go_ota_event.h"

/**
 * @copydoc el2go_ota_event_register_net_up
 *
 * Weak default. No-op registration that reports success; callers fall back to
 * polling. A backend overrides it to deliver the real notification.
 */
__weak int el2go_ota_event_register_net_up(el2go_app_net_up_cb_t cb, void *user_data)
{
    (void)cb;
    (void)user_data;
    return 0;
}
