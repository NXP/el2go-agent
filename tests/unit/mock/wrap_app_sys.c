/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "wrap_app_sys.h"

#include "el2go_app_sys.h"
#include "el2go_app_time.h"

typedef struct {
    int64_t uptime_ms;

    uint32_t last_wait_ms;
    size_t wait_call_count;

    uint32_t last_sleep_ms;
    size_t sleep_call_count;

    size_t signal_call_count;
    size_t activate_call_count;

    int hour_of_day;
} wrap_app_sys_state_t;

static wrap_app_sys_state_t s_state = { .hour_of_day = -1 };

void wrap_app_sys_reset(void)
{
    s_state.uptime_ms = 0;
    s_state.last_wait_ms = 0U;
    s_state.wait_call_count = 0U;
    s_state.last_sleep_ms = 0U;
    s_state.sleep_call_count = 0U;
    s_state.signal_call_count = 0U;
    s_state.activate_call_count = 0U;
    s_state.hour_of_day = -1;
}

void wrap_app_sys_set_uptime_ms(int64_t ms)
{
    s_state.uptime_ms = ms;
}

void wrap_app_sys_advance_ms(int64_t delta_ms)
{
    s_state.uptime_ms += delta_ms;
}

uint32_t wrap_app_sys_last_wait_ms(void)
{
    return s_state.last_wait_ms;
}

size_t wrap_app_sys_wait_call_count(void)
{
    return s_state.wait_call_count;
}

size_t wrap_app_sys_sleep_call_count(void)
{
    return s_state.sleep_call_count;
}

uint32_t wrap_app_sys_last_sleep_ms(void)
{
    return s_state.last_sleep_ms;
}

size_t wrap_app_sys_signal_call_count(void)
{
    return s_state.signal_call_count;
}

size_t wrap_app_sys_activate_call_count(void)
{
    return s_state.activate_call_count;
}

void wrap_app_sys_set_hour_of_day(int hour)
{
    s_state.hour_of_day = hour;
}

/* wraps */

int __wrap_el2go_app_sys_activate_update(void)
{
    s_state.activate_call_count++;
    return 0;
}

void __wrap_el2go_app_sys_sleep_ms(uint32_t ms)
{
    s_state.sleep_call_count++;
    s_state.last_sleep_ms = ms;
    s_state.uptime_ms += (int64_t)ms;
}

int64_t __wrap_el2go_app_sys_uptime_ms(void)
{
    return s_state.uptime_ms;
}

void __wrap_el2go_app_sys_wait(uint32_t timeout_ms)
{
    s_state.wait_call_count++;
    s_state.last_wait_ms = timeout_ms;
    s_state.uptime_ms += (int64_t)timeout_ms;
}

void __wrap_el2go_app_sys_signal(void)
{
    s_state.signal_call_count++;
}

int __wrap_el2go_app_time_get_hour_of_day(void)
{
    return s_state.hour_of_day;
}

void __wrap_el2go_app_time_sync(void)
{
    /* no-op */
}
