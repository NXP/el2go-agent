/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/*
 * Scheduler for the advanced agent.
 *
 * Drives the update-check cadence: it sleeps until the next scheduled check,
 * applies exponential backoff on failure, and can be woken early by an
 * explicit trigger or by a network-up event.
 */

#ifndef __OTA_SCHEDULER_H__
#define __OTA_SCHEDULER_H__

#include <stdint.h>

/**
 * @brief Callback invoked by the scheduler when a check is due.
 *
 * @param[in] user_data  Opaque pointer supplied to scheduler_init().
 */
typedef void (*scheduler_check_fn_t)(void *user_data);

/**
 * @brief Initialize the scheduler and arm the first check.
 *
 * Registers the check callback, subscribes to network-up events, and schedules
 * the initial update check.
 *
 * @param[in] check_fn   Callback invoked when a check is due.
 * @param[in] user_data  Opaque pointer passed back to @p check_fn.
 */
void scheduler_init(scheduler_check_fn_t check_fn, void *user_data);

/**
 * @brief Wake the scheduler to run a check immediately.
 */
void scheduler_trigger_now(void);

/**
 * @brief Reset the backoff delay to the base poll interval.
 *
 * Called after a successful cycle to return to the normal polling cadence.
 */
void scheduler_reset(void);

/**
 * @brief Apply exponential backoff.
 *
 * Doubles the current delay, capped at the configured maximum.
 */
void scheduler_backoff(void);

/**
 * @brief Rearm the next check with an explicit delay.
 *
 * @param[in] delay_ms  Delay in milliseconds until the next check.
 */
void scheduler_rearm_ms(uint32_t delay_ms);

/**
 * @brief Current scheduling delay.
 *
 * @return The delay in milliseconds currently used between checks.
 */
uint32_t scheduler_current_delay_ms(void);

#endif /* __OTA_SCHEDULER_H__ */
