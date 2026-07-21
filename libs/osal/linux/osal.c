/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <time.h>
#include "osal.h"
#include "local.h"

void osal_sleep_ms(uint32_t ms)
{
    struct timespec ts;

    ts.tv_sec = (time_t)(ms / 1000U);
    ts.tv_nsec = (long)((ms % 1000U) * 1000000UL);
    (void)nanosleep(&ts, NULL);
}

void osal_lib_init(void)
{
    set_log_file();
    set_log_level();
}
