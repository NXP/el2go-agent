/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <string.h>

#include "debug.h"
#include "el2go_ota_kvs.h"
#include "el2go_ota_status_reporting.h"
#include "el2go_ota_request_builder.h"
#include "el2go_ota_response_handler.h"

/* gRPC method path for ReportUpdateStatus */
#define STATUS_REPORTING_GRPC_METHOD \
    "/com.nxp.iot.ota.update.poc.proto.OtaUpdateDeliveryService/ReportUpdateStatus"

/* Wire buffer size -- enough for UpdateStatusNotification + gRPC framing */
#define STATUS_WIRE_BUF_SIZE 320U

static el2go_ota_update_status_t outcome_to_wire_status(el2go_ota_update_outcome_t outcome)
{
    switch (outcome) {
    case EL2GO_OTA_OUTCOME_SUCCESS:
        return EL2GO_OTA_UPDATE_STATUS_SUCCESS;
    case EL2GO_OTA_OUTCOME_ROLLBACK:
        return EL2GO_OTA_UPDATE_STATUS_ROLLED_BACK;
    case EL2GO_OTA_OUTCOME_FAILURE:
    default:
        return EL2GO_OTA_UPDATE_STATUS_ERROR;
    }
}

static const char *outcome_to_message(el2go_ota_update_outcome_t outcome)
{
    switch (outcome) {
    case EL2GO_OTA_OUTCOME_SUCCESS:
        return "UPDATE_SUCCESS";
    case EL2GO_OTA_OUTCOME_ROLLBACK:
        return "ROLLBACK";
    case EL2GO_OTA_OUTCOME_FAILURE:
    default:
        return "UPDATE_FAILED";
    }
}

static el2go_ota_status_t status_reporting_deliver(el2go_ota_transport_t *transport,
                                                   const char *update_id,
                                                   el2go_ota_update_outcome_t outcome)
{
    el2go_ota_status_t result = EL2GO_OTA_ERROR_INTERNAL;
    el2go_ota_report_status_req_t req = { 0 };
    uint8_t wire_buf[STATUS_WIRE_BUF_SIZE] = { 0 };
    size_t encoded_len = 0U;
    size_t recv_len = 0U;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (transport->send == NULL || transport->recv == NULL) {
        EL2GO_DBG_PRINTF(ERROR, "transport vtable not fully initialised\n");
        result = EL2GO_OTA_ERROR_INVALID_PARAM;
        goto exit;
    }

    req.update_id = update_id;
    req.status = outcome_to_wire_status(outcome);
    req.status_message = outcome_to_message(outcome);

    result = el2go_ota_encode_report_status(&req, wire_buf, sizeof(wire_buf), &encoded_len);
    if (result != EL2GO_OTA_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to encode ReportPackageStatus request: %d\n", (int)result);
        goto exit;
    }

    result = transport->send(transport, STATUS_REPORTING_GRPC_METHOD, wire_buf, encoded_len);
    if (result != EL2GO_OTA_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "transport send failed: %d\n", (int)result);
        goto exit;
    }

    result = transport->recv(transport, wire_buf, sizeof(wire_buf), &recv_len);
    if (result != EL2GO_OTA_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "transport recv failed: %d\n", (int)result);
        goto exit;
    }

    result = el2go_ota_parse_report_status_response(wire_buf, recv_len);
    if (result != EL2GO_OTA_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "ReportPackageStatus response error: %d\n", (int)result);
        goto exit;
    }

    EL2GO_DBG_PRINTF(INFO, "ReportPackageStatus delivered (update_id=%s)\n", update_id);
    result = EL2GO_OTA_SUCCESS;

exit:
    return result;
}

el2go_ota_status_t el2go_ota_status_reporting_report(el2go_ota_transport_t *transport,
                                                     const char *update_id, const char *package_id,
                                                     el2go_ota_update_outcome_t outcome)
{
    el2go_ota_status_t result = EL2GO_OTA_ERROR_INTERNAL;
    el2go_ota_pending_status_t entry = { 0 };

    EL2GO_DBG_TRACE_API_CALL;

    if (transport == NULL || update_id == NULL || package_id == NULL) {
        EL2GO_DBG_PRINTF(ERROR, "status_reporting_report: NULL argument\n");
        return EL2GO_OTA_ERROR_INVALID_PARAM;
    }

    result = el2go_ota_kvs_init();
    if (result != EL2GO_OTA_SUCCESS) {
        /* KVS not available -- skip persistence and attempt delivery directly */
        EL2GO_DBG_PRINTF(ERROR, "KVS init failed; attempting delivery without persistence\n");
        return status_reporting_deliver(transport, update_id, outcome);
    }

    /* Persist before any network I/O */
    entry.outcome = (uint8_t)outcome;
    (void)strncpy(entry.update_id, update_id, sizeof(entry.update_id) - 1U);
    (void)strncpy(entry.package_id, package_id, sizeof(entry.package_id) - 1U);
    entry.valid = EL2GO_OTA_STATUS_VALID_MAGIC;

    result = el2go_ota_kvs_write(EL2GO_OTA_STATUS_NVS_KEY, &entry, sizeof(entry));
    if (result != EL2GO_OTA_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to persist pending status to KVS\n");
        return result;
    }

    /* Attempt delivery */
    result = status_reporting_deliver(transport, update_id, outcome);

    if (result == EL2GO_OTA_SUCCESS) {
        /* Backend acknowledged -- safe to clear the pending entry */
        (void)el2go_ota_kvs_delete(EL2GO_OTA_STATUS_NVS_KEY);
    } else {
        EL2GO_DBG_PRINTF(INFO, "Delivery failed; pending status retained in KVS for retry\n");
    }

    return result;
}

el2go_ota_status_t el2go_ota_status_reporting_schedule(const char *update_id,
                                                       const char *package_id,
                                                       el2go_ota_update_outcome_t outcome)
{
    el2go_ota_status_t result = EL2GO_OTA_ERROR_INTERNAL;
    el2go_ota_pending_status_t entry = { 0 };

    EL2GO_DBG_TRACE_API_CALL;

    if (update_id == NULL || package_id == NULL) {
        EL2GO_DBG_PRINTF(ERROR, "status_reporting_schedule: NULL argument\n");
        return EL2GO_OTA_ERROR_INVALID_PARAM;
    }

    result = el2go_ota_kvs_init();
    if (result != EL2GO_OTA_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "KVS init failed; cannot schedule status report\n");
        return result;
    }

    entry.outcome = (uint8_t)outcome;
    (void)strncpy(entry.update_id, update_id, sizeof(entry.update_id) - 1U);
    (void)strncpy(entry.package_id, package_id, sizeof(entry.package_id) - 1U);
    entry.valid = EL2GO_OTA_STATUS_VALID_MAGIC;

    result = el2go_ota_kvs_write(EL2GO_OTA_STATUS_NVS_KEY, &entry, sizeof(entry));
    if (result != EL2GO_OTA_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to persist scheduled status to KVS\n");
        return result;
    }

    EL2GO_DBG_PRINTF(INFO, "Status report scheduled (update_id=%s, outcome=%d)\n", update_id,
                     (int)outcome);

    return EL2GO_OTA_SUCCESS;
}

el2go_ota_status_t el2go_ota_status_reporting_read_pending(el2go_ota_pending_status_t *out)
{
    el2go_ota_status_t result = EL2GO_OTA_ERROR_INTERNAL;
    bool found = false;

    EL2GO_DBG_TRACE_API_CALL;

    if (out == NULL) {
        EL2GO_DBG_PRINTF(ERROR, "status_reporting_read_pending: out is NULL\n");
        return EL2GO_OTA_ERROR_INVALID_PARAM;
    }

    result = el2go_ota_kvs_init();
    if (result != EL2GO_OTA_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "KVS init failed; cannot read pending status\n");
        return result;
    }

    result = el2go_ota_kvs_read(EL2GO_OTA_STATUS_NVS_KEY, out, sizeof(*out), &found);
    if (result != EL2GO_OTA_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "KVS read failed: %d\n", (int)result);
        return result;
    }

    if (!found) {
        /* No entry present -- return a zeroed struct with valid == 0 */
        out->valid = 0U;
    } else {
        /* Ensure null-termination of strings read from KVS */
        out->update_id[sizeof(out->update_id) - 1U] = '\0';
        out->package_id[sizeof(out->package_id) - 1U] = '\0';
    }

    return EL2GO_OTA_SUCCESS;
}

el2go_ota_status_t el2go_ota_status_reporting_retry_pending(el2go_ota_transport_t *transport)
{
    el2go_ota_status_t result = EL2GO_OTA_ERROR_INTERNAL;
    el2go_ota_pending_status_t entry = { 0 };
    el2go_ota_update_outcome_t outcome = EL2GO_OTA_OUTCOME_FAILURE;
    bool found = false;

    EL2GO_DBG_TRACE_API_CALL;

    if (transport == NULL) {
        EL2GO_DBG_PRINTF(ERROR, "status_reporting_retry_pending: transport is NULL\n");
        return EL2GO_OTA_ERROR_INVALID_PARAM;
    }

    result = el2go_ota_kvs_init();
    if (result != EL2GO_OTA_SUCCESS) {
        goto exit;
    }

    result = el2go_ota_kvs_read(EL2GO_OTA_STATUS_NVS_KEY, &entry, sizeof(entry), &found);
    if (result != EL2GO_OTA_SUCCESS) {
        goto exit;
    }

    if (!found || entry.valid != EL2GO_OTA_STATUS_VALID_MAGIC) {
        /* No pending entry -- nothing to do */
        EL2GO_DBG_PRINTF(INFO, "No pending status entry found in KVS\n");
        result = EL2GO_OTA_SUCCESS;
        goto exit;
    }

    /* Ensure null-termination of strings read from KVS */
    entry.update_id[sizeof(entry.update_id) - 1U] = '\0';
    entry.package_id[sizeof(entry.package_id) - 1U] = '\0';

    outcome = (el2go_ota_update_outcome_t)entry.outcome;

    EL2GO_DBG_PRINTF(INFO, "Retrying pending status delivery (update_id=%s)\n", entry.update_id);

    result = status_reporting_deliver(transport, entry.update_id, outcome);
    if (result == EL2GO_OTA_SUCCESS) {
        (void)el2go_ota_kvs_delete(EL2GO_OTA_STATUS_NVS_KEY);
    } else {
        EL2GO_DBG_PRINTF(INFO, "Pending status retry failed; entry retained for next attempt\n");
    }

exit:
    return result;
}
