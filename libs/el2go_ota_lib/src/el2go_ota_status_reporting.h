/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __EL2GO_OTA_STATUS_REPORTING_H__
#define __EL2GO_OTA_STATUS_REPORTING_H__

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "ota/el2go_ota_lib.h"
#include "transport/el2go_ota_transport.h"

/* NVS key for the pending status entry. */
#define EL2GO_OTA_STATUS_NVS_KEY 1U

/* Magic byte stored in el2go_ota_pending_status_t.valid to mark a live entry. */
#define EL2GO_OTA_STATUS_VALID_MAGIC 0xA5U

/**
 * @brief NVS-persisted pending status record.
 *
 * Written to NVS before attempting delivery. Cleared on successful ACK from
 * the backend. A valid field value of EL2GO_OTA_STATUS_VALID_MAGIC indicates
 * a live entry that requires delivery. Any other value means no entry.
 */
typedef struct {
    uint8_t outcome;     /**< el2go_ota_update_outcome_t cast to uint8_t */
    char update_id[64];  /**< null-terminated update identifier */
    char package_id[64]; /**< null-terminated package identifier */
    uint8_t valid;       /**< EL2GO_OTA_STATUS_VALID_MAGIC = valid pending entry */
} el2go_ota_pending_status_t;

/**
 * @brief Internal implementation of el2go_ota_report_status().
 *
 * Called by el2go_ota_lib.c after parameter validation. Persists the entry
 * to NVS first, then attempts delivery via transport. Clears NVS on success;
 * retains entry on failure for retry via el2go_ota_status_reporting_retry_pending().
 *
 * @param[in] transport   Initialised transport instance. Guaranteed non-NULL.
 * @param[in] update_id   Update identifier. Guaranteed non-NULL.
 * @param[in] package_id  Package identifier. Guaranteed non-NULL.
 * @param[in] outcome     Update outcome. Guaranteed valid by caller.
 * @return EL2GO_OTA_SUCCESS on success (backend acknowledged).
 * @return EL2GO_OTA_ERROR_NETWORK on delivery failure (NVS entry retained).
 * @return EL2GO_OTA_ERROR_SERVER on server error response.
 * @return EL2GO_OTA_ERROR_INTERNAL on NVS, encoding, or decoding failure.
 */
el2go_ota_status_t el2go_ota_status_reporting_report(el2go_ota_transport_t *transport,
                                                     const char *update_id, const char *package_id,
                                                     el2go_ota_update_outcome_t outcome);

/**
 * @brief Internal implementation of el2go_ota_report_pending_status().
 *
 * Called by el2go_ota_lib.c after parameter validation. Reads any persisted
 * pending entry from NVS and attempts delivery. Returns EL2GO_OTA_SUCCESS
 * immediately if no valid entry exists.
 *
 * @param[in] transport  Initialised transport instance. Guaranteed non-NULL.
 * @return EL2GO_OTA_SUCCESS if no pending entry exists or delivery succeeded.
 * @return EL2GO_OTA_ERROR_NETWORK if delivery failed (entry retained).
 * @return EL2GO_OTA_ERROR_SERVER on server error response.
 * @return EL2GO_OTA_ERROR_INTERNAL on NVS, encoding, or decoding failure.
 */
el2go_ota_status_t el2go_ota_status_reporting_retry_pending(el2go_ota_transport_t *transport);

#endif /* __EL2GO_OTA_STATUS_REPORTING_H__ */
