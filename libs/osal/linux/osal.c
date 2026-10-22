/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <time.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <dirent.h>

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

const char *osal_getenv(const char *name)
{
    return getenv(name);
}

void osal_setenv(const char *name, const char *value)
{
    /* Always overwrite any existing value */
    setenv(name, value, 1);
}

char *osal_find_library(const char *name)
{
    char *lib_path = NULL;
    DIR *dir = NULL;
    struct dirent *entry = NULL;
    size_t name_len = 0;

    dir = opendir("/usr/lib");
    if (!dir)
        goto exit;

    name_len = strlen(name);

    while ((entry = readdir(dir)) != NULL) {
        if (!strncmp(entry->d_name, name, name_len)) {
            lib_path = strdup(entry->d_name);
            break;
        }
    }

exit:
    (void)closedir(dir);

    return lib_path;
}

void osal_lib_init(void)
{
    set_log_file();
    set_log_level();
}

int osal_start_task(int (*fn)(void *ctx), void *ctx)
{
    /* On Linux/POSIX, main() runs in a normal process context - call fn directly. */
    return fn(ctx);
}
