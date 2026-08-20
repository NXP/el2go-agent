/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/* Zephyr backend for the system services: activate update, sleep, uptime, and
 * wait/signal.
 *
 * Single-threaded model: the agent runs entirely on the main thread. The k_sem
 * is a binary semaphore used purely for interruptible sleep, a wait with a
 * timeout that signal() can wake early, unlike k_msleep() which always runs to
 * full duration. It is not used for mutual exclusion. The libraries above this
 * layer are NOT thread safe and depend on all agent logic running on a single
 * thread. signal() may still be called from another context (for example a
 * net_mgmt event callback) to wake the main thread early.
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/reboot.h>

#include "el2go_app_sys.h"

static K_SEM_DEFINE(ota_signal_sem, 0, 1);

/**
 * @brief Activates the update by performing a cold reset of the device.
 *
 * Zephyr backend variant of el2go_app_sys_activate_update(). Does not return.
 */
int el2go_app_sys_activate_update(void)
{
    sys_reboot(SYS_REBOOT_COLD);
    return 0; /* unreachable, satisfies compiler */
}

/**
 * @brief Sleeps the calling thread for the given duration
 *
 * Zephyr backend variant of el2go_app_sys_sleep_ms().
 *
 * @param[in] ms Number of milliseconds to sleep
 */
void el2go_app_sys_sleep_ms(uint32_t ms)
{
    k_msleep(ms);
}

/**
 * @brief Returns milliseconds elapsed since boot
 *
 * Zephyr backend variant of el2go_app_sys_uptime_ms().
 *
 * @return Milliseconds since boot as reported by k_uptime_get()
 */
int64_t el2go_app_sys_uptime_ms(void)
{
    return k_uptime_get();
}

/**
 * @brief Blocks the caller until signalled or the timeout expires
 *
 * Zephyr backend variant of el2go_app_sys_wait(). Takes the signal semaphore
 * with the given timeout; a pending el2go_app_sys_signal() wakes it early.
 *
 * @param[in] timeout_ms Maximum time to block in milliseconds
 */
void el2go_app_sys_wait(uint32_t timeout_ms)
{
    (void)k_sem_take(&ota_signal_sem, K_MSEC(timeout_ms));
}

/**
 * @brief Wakes a caller blocked in el2go_app_sys_wait()
 *
 * Zephyr backend variant of el2go_app_sys_signal(). Gives the signal
 * semaphore. Safe to call when nothing is waiting; the signal is coalesced
 * by the binary semaphore.
 */
void el2go_app_sys_signal(void)
{
    k_sem_give(&ota_signal_sem);
}
