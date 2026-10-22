/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <zephyr/kernel.h>
#include "osal.h"

/* Stack size for the OSAL task thread.
 * Controlled via CONFIG_OSAL_TASK_STACK_SIZE (Kconfig); 
 */
#define OSAL_TASK_STACK_SIZE CONFIG_OSAL_TASK_STACK_SIZE

K_THREAD_STACK_DEFINE(osal_task_stack, OSAL_TASK_STACK_SIZE);
static struct k_thread osal_task_data;

typedef struct {
    int (*fn)(void *ctx);
    void *ctx;
} osal_task_args_t;

static osal_task_args_t osal_task_args;

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
     * (CONFIG_LOG_DEFAULT_LEVEL); there is no runtime environment
     * to read from.
     */
}

static void osal_task_entry(void *p1, void *p2, void *p3)
{
    osal_task_args_t *args = (osal_task_args_t *)p1;
    (void)p2;
    (void)p3;

    (void)args->fn(args->ctx);
}

int osal_start_task(int (*fn)(void *ctx), void *ctx)
{
    osal_task_args.fn = fn;
    osal_task_args.ctx = ctx;

    k_tid_t tid = k_thread_create(&osal_task_data, osal_task_stack,
                                  K_THREAD_STACK_SIZEOF(osal_task_stack), osal_task_entry,
                                  (void *)&osal_task_args, NULL, NULL, 0, 0, K_FOREVER);

    if (tid == NULL) {
        return -1;
    }

    k_thread_name_set(tid, "osal_task");
    k_thread_start(tid);

    return 0;
}
