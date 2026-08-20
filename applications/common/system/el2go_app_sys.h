/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/**
 * @file el2go_app_sys.h
 * @brief System services abstraction: activate update, sleep, uptime, wait/signal.
 *
 * Declares the system-service interface used by the OTA agent: device reboot,
 * sleeping, uptime, and interruptible wait/signal. This
 * header defines the generic contract that every backend must honor; the
 * symbols carry weak defaults so a build links without a concrete backend. A
 * concrete backend (see the zephyr/ implementation) overrides the weak
 * definitions with the real behavior.
 *
 * @defgroup el2go_app_sys System Services Abstraction
 * @brief Device system-services contract.
 * @{
 */

#ifndef __EL2GO_APP_SYS_H__
#define __EL2GO_APP_SYS_H__

#include <stdint.h>

/**
 * @brief Activate a successfully handed-off firmware update.
 *
 * Performs whatever OS-specific action is required to activate the update
 * that was just handed to FWUAL. On Zephyr this triggers a cold reboot and
 * does not return. On other platforms the backend performs the appropriate
 * activation action and returns 0 on success, non-zero on failure.
 *
 * @return 0 on success (or does not return on platforms that reboot).
 * @return Non-zero if activation failed.
 */
int el2go_app_sys_activate_update(void);

/**
 * @brief Sleep the calling context for the given number of milliseconds.
 *
 * @param[in] ms  Duration to sleep, in milliseconds.
 */
void el2go_app_sys_sleep_ms(uint32_t ms);

/**
 * @brief Get milliseconds elapsed since boot.
 *
 * @return Monotonic uptime in milliseconds.
 */
int64_t el2go_app_sys_uptime_ms(void);

/**
 * @brief Block until the timeout expires or a signal arrives.
 *
 * Blocks the caller until timeout_ms elapses or el2go_app_sys_signal() is
 * called, whichever happens first. Used to implement an interruptible sleep in
 * the agent's poll loop.
 *
 * @param[in] timeout_ms  Maximum time to wait, in milliseconds.
 */
void el2go_app_sys_wait(uint32_t timeout_ms);

/**
 * @brief Wake a caller blocked in el2go_app_sys_wait().
 *
 * Safe to call from another context (for example a network-event callback) to
 * interrupt the wait early.
 */
void el2go_app_sys_signal(void);

#endif /* __EL2GO_APP_SYS_H__ */

/** @} */ /* end of el2go_app_sys */
