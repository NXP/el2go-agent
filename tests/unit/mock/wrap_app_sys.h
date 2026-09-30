/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/**
 * @file wrap_app_sys.h
 * @brief Test-only fake clock/sleep/wait for el2go_app_sys.h / el2go_app_time.h.
 */

#ifndef WRAP_APP_SYS_H
#define WRAP_APP_SYS_H

#include <stddef.h>
#include <stdint.h>

/** @brief Reset all fake-clock state to defaults (uptime 0, all counters 0,
 * hour-of-day unknown). */
void wrap_app_sys_reset(void);

/** @brief Directly set the fake uptime, in milliseconds. */
void wrap_app_sys_set_uptime_ms(int64_t ms);

/** @brief Advance the fake uptime by the given number of milliseconds. */
void wrap_app_sys_advance_ms(int64_t delta_ms);

/** @brief The timeout_ms argument passed to the most recent el2go_app_sys_wait() call. */
uint32_t wrap_app_sys_last_wait_ms(void);

/** @brief Number of times el2go_app_sys_wait() has been called. */
size_t wrap_app_sys_wait_call_count(void);

/** @brief Number of times el2go_app_sys_sleep_ms() has been called. */
size_t wrap_app_sys_sleep_call_count(void);

/** @brief The ms argument passed to the most recent el2go_app_sys_sleep_ms() call. */
uint32_t wrap_app_sys_last_sleep_ms(void);

/** @brief Number of times el2go_app_sys_signal() has been called. */
size_t wrap_app_sys_signal_call_count(void);

/** @brief Number of times el2go_app_sys_activate_update() has been called. */
size_t wrap_app_sys_activate_call_count(void);

/** @brief Set the value returned by el2go_app_time_get_hour_of_day(). Pass -1
 * for "unknown" (the default after reset). */
void wrap_app_sys_set_hour_of_day(int hour);

#endif /* WRAP_APP_SYS_H */
