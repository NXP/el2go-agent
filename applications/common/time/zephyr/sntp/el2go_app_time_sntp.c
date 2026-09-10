/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/* Time backend: SNTP. A sync performs one SNTP query and caches the epoch
 * alongside the uptime at that moment; the hour of day is then derived from
 * the cached epoch plus elapsed uptime. Call the sync after
 * el2go_app_net_init() has brought the network up. */

#include "el2go_app_time.h"

#include <zephyr/kernel.h>
#include <zephyr/net/sntp.h>
#include <zephyr/logging/log.h>
#include <time.h>

LOG_MODULE_REGISTER(time, CONFIG_LOG_DEFAULT_LEVEL);

static uint64_t epoch_s = 0U;
static int64_t uptime_at_sync_ms = 0;

/**
 * @brief Queries an SNTP server and caches the current time
 *
 * SNTP backend variant of el2go_app_time_sync(). Performs a single blocking
 * SNTP request to the configured server bounded by the configured timeout. On
 * success the returned epoch and the current uptime are cached so the hour of
 * day can be derived later. On failure the cached time is left unchanged, which
 * keeps the time reported as unknown and disables the blackout policy.
 */

#define SNTP_SYNC_MAX_ATTEMPTS 15
#define SNTP_SYNC_RETRY_DELAY_MS 1000

void el2go_app_time_sync(void)
{
    struct sntp_time t = { 0 };
    int rc = -1;
    int attempt = -1;

    for (attempt = 1; attempt <= SNTP_SYNC_MAX_ATTEMPTS; attempt++) {
        rc = sntp_simple(CONFIG_EL2GO_TIME_SNTP_SERVER, CONFIG_EL2GO_TIME_SNTP_TIMEOUT_MS, &t);
        if (rc == 0) {
            struct timespec ts = { .tv_sec = (time_t)t.seconds, .tv_nsec = 0 };
            (void)clock_settime(CLOCK_REALTIME, &ts);
            epoch_s = t.seconds;
            uptime_at_sync_ms = k_uptime_get();
            LOG_INF("SNTP sync ok (epoch=%llu, attempt=%d)", (unsigned long long)epoch_s, attempt);
            return;
        }

        LOG_WRN("SNTP sync attempt %d/%d failed (%d)", attempt, SNTP_SYNC_MAX_ATTEMPTS, rc);
        k_sleep(K_MSEC(SNTP_SYNC_RETRY_DELAY_MS));
    }

    LOG_WRN("SNTP sync failed after %d attempts - blackout policy disabled",
            SNTP_SYNC_MAX_ATTEMPTS);
}

/**
 * @brief Returns the current UTC hour of day
 *
 * SNTP backend variant of el2go_app_time_get_hour_of_day(). Computes the
 * current time from the cached epoch plus the uptime elapsed since the last
 * successful sync, then reduces it to the hour within the UTC day.
 *
 * @retval Hour of day in the range 0-23
 * @retval -1 if no successful sync has occurred yet
 */
int el2go_app_time_get_hour_of_day(void)
{
    int64_t elapsed_ms = 0;
    uint64_t now_s = 0U;
    uint32_t seconds_day = 0U;

    if (epoch_s == 0U) {
        return -1;
    }

    elapsed_ms = k_uptime_get() - uptime_at_sync_ms;
    now_s = epoch_s + (uint64_t)(elapsed_ms / 1000);
    seconds_day = (uint32_t)(now_s % 86400U);

    return (int)(seconds_day / 3600U);
}
