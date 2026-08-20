/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/*
 * Policy engine for the advanced agent.
 *
 * Decides whether an available update should be applied now, deferred to a
 * later time, or cancelled, based on the server response and local blackout /
 * defer windows.
 */

#ifndef __OTA_POLICY_H__
#define __OTA_POLICY_H__

#include "ota/el2go_ota_lib.h"
#include <stdint.h>

/** @brief Outcome of evaluating an update against the local policy. */
typedef enum {
    POLICY_PROCEED = 0,
    POLICY_DEFER = 1,
    POLICY_BLACKOUT = 2,
    POLICY_CANCEL = 3,
} policy_result_t;

/**
 * @brief Evaluate an available update against the local policy.
 *
 * Combines the server response with the configured blackout window and the
 * defer window tracked since the last attempt to decide how the agent should
 * proceed.
 *
 * @param[in] resp  Check-update response describing the available update.
 *
 * @return POLICY_PROCEED to apply the update now
 * @return POLICY_DEFER to retry after the defer window elapses
 * @return POLICY_BLACKOUT if currently inside a blackout window
 * @return POLICY_CANCEL if the update must not be applied
 */
policy_result_t policy_evaluate(const el2go_ota_check_update_resp_t *resp);

/**
 * @brief Record the current time as the most recent update attempt.
 *
 * Establishes the reference point used to compute the defer window.
 */
void policy_record_attempt(void);

/**
 * @brief Time remaining in the current defer window.
 *
 * @return Milliseconds until the defer window expires, or 0 if the window has
 *         already passed or deferral is disabled.
 */
uint32_t policy_defer_remaining_ms(void);

#endif /* __OTA_POLICY_H__ */
