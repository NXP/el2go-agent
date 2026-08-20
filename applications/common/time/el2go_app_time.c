/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/* Time weak default: sync is a no-op and the hour is reported unknown. See the
 * zephyr/ backend for the real behavior. */

#include "el2go_app_compiler.h"
#include "el2go_app_time.h"

/**
 * @copydoc el2go_app_time_sync
 *
 * Weak default. No-op; a backend overrides it to synchronize the time source
 * (for example SNTP or an on-chip RTC).
 */
__weak void el2go_app_time_sync(void)
{
    /* stub */
}

/**
 * @copydoc el2go_app_time_get_hour_of_day
 *
 * Weak default. Reports the time as unknown (-1); a backend overrides it to
 * return the current UTC hour of day.
 */
__weak int el2go_app_time_get_hour_of_day(void)
{
    return -1;
}
