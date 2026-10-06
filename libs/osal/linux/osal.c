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

int64_t osal_uptime_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + (int64_t)ts.tv_nsec / 1000000;
}

void osal_lib_init(void)
{
    set_log_file();
    set_log_level();
}

int osal_start_task(int (*fn)(int argc, const char *argv[]), int argc, const char *argv[])
{
    /* On Linux/POSIX, main() runs in a normal process context; call fn directly. */
    return fn(argc, argv);
}
