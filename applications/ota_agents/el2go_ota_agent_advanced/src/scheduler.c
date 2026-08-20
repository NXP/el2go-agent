/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/*
 * Scheduler implementation for the advanced agent.
 *
 * The scheduler runs on the main thread: it sleeps until the next scheduled
 * check, then invokes the registered check callback. The wait is computed from
 * an absolute target time so that repeated cycles do not accumulate drift. The
 * wait can be interrupted early by an explicit trigger or by a network up event
 * (delivered from the net_mgmt thread via a binary semaphore).
 */

#include <stddef.h>

#include "scheduler.h"
#include "el2go_ota_diag.h"
#include "el2go_ota_event.h"
#include "el2go_app_sys.h"

static scheduler_check_fn_t s_check_fn = NULL;
static void *s_user_data = NULL;
static uint32_t current_delay_ms = (uint32_t)CONFIG_EL2GO_OTA_ADV_POLL_INTERVAL_S * 1000U;

/* Absolute uptime (ms) at which the next check is due; used for drift correction. */
static int64_t s_next_target_ms;

/**
 * @brief Scheduler loop running on the main thread.
 *
 * Runs forever and does not return: waits until the absolute target time (or
 * until woken early), invokes the registered check callback, then schedules the
 * next target based on the current delay.
 */
static void run_schedule_loop(void)
{
    for (;;) {
        /* Derive the wait from the absolute target so cycles do not drift. */
        int64_t wait_ms = s_next_target_ms - el2go_app_sys_uptime_ms();

        if (wait_ms < 0) {
            wait_ms = 0;
        }

        el2go_app_sys_wait((uint32_t)wait_ms);

        if (s_check_fn != NULL) {
            s_check_fn(s_user_data);
        }

        s_next_target_ms = el2go_app_sys_uptime_ms() + (int64_t)current_delay_ms;

        /* Intentional infinite loop */
    }
}

/**
 * @brief Network-up event handler.
 *
 * Wakes the scheduler to run a check as soon as connectivity is available.
 *
 * @param[in] user_data  Unused callback context.
 */
static void net_up_handler(void *user_data)
{
    (void)user_data;

    OTA_DIAG_INFO("network up - triggering OTA check");
    scheduler_trigger_now();
}

void scheduler_init(scheduler_check_fn_t check_fn, void *user_data)
{
    s_check_fn = check_fn;
    s_user_data = user_data;

    if (el2go_ota_event_register_net_up(net_up_handler, NULL) != 0) {
        OTA_DIAG_WARN("el2go_ota_event_register_net_up() failed - relying on poll interval");
    }

    /* Target the first check for now so the loop runs one immediately. */
    s_next_target_ms = el2go_app_sys_uptime_ms();

    /* Runs the scheduler loop on the main thread; does not return. */
    run_schedule_loop();
}

void scheduler_trigger_now(void)
{
    el2go_app_sys_signal();
}

void scheduler_reset(void)
{
    current_delay_ms = (uint32_t)CONFIG_EL2GO_OTA_ADV_POLL_INTERVAL_S * 1000U;
}

void scheduler_backoff(void)
{
    uint32_t max_ms = (uint32_t)CONFIG_EL2GO_OTA_ADV_RETRY_MAX_BACKOFF_S * 1000U;

    if (current_delay_ms == 0U) {
        current_delay_ms = (uint32_t)CONFIG_EL2GO_OTA_ADV_RETRY_INITIAL_BACKOFF_S * 1000U;
    } else {
        current_delay_ms = current_delay_ms * 2U;
    }

    if (current_delay_ms > max_ms) {
        current_delay_ms = max_ms;
    }

    OTA_DIAG_INFO("scheduler backoff: next check in %u s", current_delay_ms / 1000U);
}

void scheduler_rearm_ms(uint32_t delay_ms)
{
    /* Applied to the wait that follows the current check. */
    current_delay_ms = delay_ms;
}

uint32_t scheduler_current_delay_ms(void)
{
    return current_delay_ms;
}
