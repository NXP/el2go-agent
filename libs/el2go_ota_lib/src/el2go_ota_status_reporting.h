/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __EL2GO_OTA_STATUS_REPORTING_H__
#define __EL2GO_OTA_STATUS_REPORTING_H__

#include "ota/el2go_ota_lib.h"
#include "el2go_ota_transport.h"
#include "compiler.h"

/* NVS key for the pending status entry. */
#define EL2GO_OTA_STATUS_NVS_KEY 1U

/*
 * el2go_ota_pending_status_t and EL2GO_OTA_STATUS_VALID_MAGIC are defined in
 * the public header include/ota/el2go_ota_lib.h, which is already included
 * above via "ota/el2go_ota_lib.h".
 */

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
__export el2go_ota_status_t el2go_ota_status_reporting_report(el2go_ota_transport_t *transport,
                                                              const char *update_id,
                                                              const char *package_id,
                                                              el2go_ota_update_outcome_t outcome);

/**
 * @brief Internal implementation of el2go_ota_schedule_status_report().
 *
 * Persists the pending status entry to NVS without attempting delivery.
 * Does not require an active network connection.  Called by el2go_ota_lib.c
 * after parameter validation.
 *
 * @param[in] update_id   Update identifier. Guaranteed non-NULL.
 * @param[in] package_id  Package identifier. Guaranteed non-NULL.
 * @param[in] outcome     Update outcome. Guaranteed valid by caller.
 * @return EL2GO_OTA_SUCCESS on success.
 * @return EL2GO_OTA_ERROR_INTERNAL on KVS init or write failure.
 */
__export el2go_ota_status_t el2go_ota_status_reporting_schedule(const char *update_id,
                                                                const char *package_id,
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
__export el2go_ota_status_t
el2go_ota_status_reporting_retry_pending(el2go_ota_transport_t *transport);

/**
 * @brief Internal implementation of el2go_ota_get_pending_status().
 *
 * Reads the NVS entry into out without attempting delivery or clearing it.
 * If no entry exists, returns EL2GO_OTA_SUCCESS with out->valid == 0.
 *
 * @param[out] out  Receives the pending entry. Guaranteed non-NULL by caller.
 * @return EL2GO_OTA_SUCCESS on success.
 * @return EL2GO_OTA_ERROR_INTERNAL on KVS init or read failure.
 */
__export el2go_ota_status_t el2go_ota_status_reporting_read_pending(el2go_ota_pending_status_t *out);

#endif /* __EL2GO_OTA_STATUS_REPORTING_H__ */
