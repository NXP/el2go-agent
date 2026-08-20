/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/* System services weak defaults. No-op fallbacks used when no concrete
 * backend is linked; see the zephyr/ backend for the real behavior. */

#include "el2go_app_compiler.h"
#include "el2go_app_sys.h"

/**
 * @copydoc el2go_app_sys_activate_update
 *
 * Weak default. No-op; a backend overrides it to reset the device.
 */
__weak int el2go_app_sys_activate_update(void)
{
    return 0;
}

/**
 * @copydoc el2go_app_sys_sleep_ms
 *
 * Weak default. No-op; a backend overrides it to sleep the calling context.
 */
__weak void el2go_app_sys_sleep_ms(uint32_t ms)
{
    (void)ms;
}

/**
 * @copydoc el2go_app_sys_uptime_ms
 *
 * Weak default. Returns 0; a backend overrides it with the real uptime.
 */
__weak int64_t el2go_app_sys_uptime_ms(void)
{
    return 0;
}

/**
 * @copydoc el2go_app_sys_wait
 *
 * Weak default. No-op; a backend overrides it to block until timeout or
 * signal.
 */
__weak void el2go_app_sys_wait(uint32_t timeout_ms)
{
    (void)timeout_ms;
}

/**
 * @copydoc el2go_app_sys_signal
 *
 * Weak default. No-op; a backend overrides it to wake a waiting worker.
 */
__weak void el2go_app_sys_signal(void)
{
}
