/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/*
 * Local policy implementation for the advanced agent.
 *
 * Applies two independent gates to an available update: a blackout window
 * (a range of hours during which updates are suppressed) and a defer window
 * (a minimum interval between attempts).
 */

#include "policy.h"
#include "el2go_app_time.h"
#include "el2go_app_sys.h"
#include "el2go_ota_diag.h"

/* System uptime in milliseconds at the last attempt; 0 means never attempted. */
static int64_t last_attempt_uptime_ms = 0;

/**
 * @brief Test whether a blackout window is configured.
 *
 * The blackout window is disabled when its start and end hours are equal.
 *
 * @return true if a blackout window is configured, false otherwise.
 */
static bool blackout_enabled(void)
{
    return CONFIG_EL2GO_OTA_ADV_BLACKOUT_START_HOUR != CONFIG_EL2GO_OTA_ADV_BLACKOUT_END_HOUR;
}

/**
 * @brief Test whether the current UTC hour falls inside the blackout window.
 *
 * Supports windows that wrap past midnight (start hour greater than end hour).
 * If the wall-clock time is unknown, the window is treated as inactive.
 *
 * @return true if currently inside the blackout window, false otherwise.
 */
static bool in_blackout_window(void)
{
    if (!blackout_enabled()) {
        return false;
    }

    int hour = el2go_app_time_get_hour_of_day();
    if (hour < 0) {
        /* Wall clock time is unknown; not treated as blackout. */
        return false;
    }

    int start = CONFIG_EL2GO_OTA_ADV_BLACKOUT_START_HOUR;
    int end = CONFIG_EL2GO_OTA_ADV_BLACKOUT_END_HOUR;

    if (start < end) {
        return (hour >= start && hour < end);
    } else {
        /* Wraps past midnight */
        return (hour >= start || hour < end);
    }
}

/**
 * @brief Test whether the defer window has elapsed since the last attempt.
 *
 * @return true if the update may be attempted (deferral disabled, no prior
 *         attempt, or the window has elapsed), false while still deferring.
 */
static bool defer_window_elapsed(void)
{
    if (CONFIG_EL2GO_OTA_ADV_DEFER_WINDOW_S == 0) { /* deferral disabled */
        return true;
    }
    if (last_attempt_uptime_ms == 0) { /* never attempted */
        return true;
    }

    int64_t elapsed_ms = el2go_app_sys_uptime_ms() - last_attempt_uptime_ms;
    int64_t window_ms = (int64_t)CONFIG_EL2GO_OTA_ADV_DEFER_WINDOW_S * 1000;
    return elapsed_ms >= window_ms;
}

policy_result_t policy_evaluate(const el2go_ota_check_update_resp_t *resp)
{
    if (resp == NULL || !resp->update_available || resp->update_count == 0U) {
        return POLICY_CANCEL;
    }

    if (in_blackout_window()) {
        OTA_DIAG_INFO("OTA policy: BLACKOUT (hour=%d, window=%d-%d)",
                      el2go_app_time_get_hour_of_day(), CONFIG_EL2GO_OTA_ADV_BLACKOUT_START_HOUR,
                      CONFIG_EL2GO_OTA_ADV_BLACKOUT_END_HOUR);
        return POLICY_BLACKOUT;
    }

    if (!defer_window_elapsed()) {
        OTA_DIAG_INFO("OTA policy: DEFER (%u s remaining)",
                      (unsigned)(policy_defer_remaining_ms() / 1000U));
        return POLICY_DEFER;
    }

    return POLICY_PROCEED;
}

void policy_record_attempt(void)
{
    last_attempt_uptime_ms = el2go_app_sys_uptime_ms();
}

uint32_t policy_defer_remaining_ms(void)
{
    if (CONFIG_EL2GO_OTA_ADV_DEFER_WINDOW_S == 0) {
        return 0U;
    }

    if (last_attempt_uptime_ms == 0) {
        return 0U;
    }

    int64_t elapsed_ms = el2go_app_sys_uptime_ms() - last_attempt_uptime_ms;
    int64_t window_ms = (int64_t)CONFIG_EL2GO_OTA_ADV_DEFER_WINDOW_S * 1000;
    int64_t remaining = window_ms - elapsed_ms;

    return (remaining > 0) ? (uint32_t)remaining : 0U;
}
