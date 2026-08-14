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
