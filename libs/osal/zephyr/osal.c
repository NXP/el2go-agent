/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "osal.h"

void osal_lib_init(void)
{
    /* No-op on Zephyr: logging level is controlled via Kconfig
     * (CONFIG_LOG_DEFAULT_LEVEL) and there is no runtime environment
     * to read from.
     */
}
