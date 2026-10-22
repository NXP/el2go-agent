/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <zephyr/kernel.h>
#include "osal.h"

void osal_sleep_ms(uint32_t ms)
{
    k_msleep((int32_t)ms);
}

int64_t osal_uptime_ms(void)
{
    return (int64_t)k_uptime_get();
}

const char *osal_getenv(const char *name)
{
    (void)name;

    /* Not implemented */
    return NULL;
}

void osal_setenv(const char *name, const char *value)
{
    (void)name;
    (void)value;

    /* Not implemented */
}

char *osal_find_library(const char *name)
{
    (void)name;

    /* Not implemented */
    return NULL;
}

void osal_lib_init(void)
{
    /* No-op on Zephyr: logging level is controlled via Kconfig
     * (CONFIG_LOG_DEFAULT_LEVEL) and there is no runtime environment
     * to read from.
     */
}

int osal_start_task(int (*fn)(int argc, const char *argv[]), int argc, const char *argv[])
{
    /* On Zephyr, main() already runs as a thread; call fn directly. */
    return fn(argc, argv);
}
