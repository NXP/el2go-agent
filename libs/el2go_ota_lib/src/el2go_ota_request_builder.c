/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <string.h>

#include <pb_encode.h>

#include "debug.h"
#include "el2go_ota_request_builder.h"
#include "ota_delivery.pb.h"

/*  Internal encode callbacks */

/**
 * @brief Encode callback context for deviceAttributes map entries.
 */
typedef struct {
    const el2go_ota_attr_t *attrs;
    size_t attr_count;
} encode_attrs_ctx_t;

/**
 * @brief nanopb encode callback for a map<string,string> field.
 *
 * Each map entry is encoded as a length-delimited sub-message with:
 *   field 1 (STRING) = key
 *   field 2 (STRING) = value
 */
static bool encode_string_map_cb(pb_ostream_t *stream, const pb_field_t *field, void *const *arg)
{
    const encode_attrs_ctx_t *ctx = (const encode_attrs_ctx_t *)(*arg);
    pb_ostream_t sizing = PB_OSTREAM_SIZING;
    const char *key = NULL;
    const char *value = NULL;
    size_t i = 0U;
    bool status = false;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    for (i = 0U; i < ctx->attr_count; i++) {
        /* Two-pass: size the sub-message first using a counting-only stream. */
        memset(&sizing, 0, sizeof(sizing));

        key = ctx->attrs[i].key;
        value = ctx->attrs[i].value;

        if (!key || !value) {
            continue;
        }

        if (!pb_encode_tag_for_field(stream, field)) {
            goto exit;
        }

        if (!pb_encode_tag(&sizing, PB_WT_STRING, 1U)) {
            goto exit;
        }
        if (!pb_encode_string(&sizing, (const pb_byte_t *)key, strlen(key))) {
            goto exit;
        }
        if (!pb_encode_tag(&sizing, PB_WT_STRING, 2U)) {
            goto exit;
        }
        if (!pb_encode_string(&sizing, (const pb_byte_t *)value, strlen(value))) {
            goto exit;
        }

        if (!pb_encode_varint(stream, (uint64_t)sizing.bytes_written)) {
            goto exit;
        }

        if (!pb_encode_tag(stream, PB_WT_STRING, 1U)) {
            goto exit;
        }
        if (!pb_encode_string(stream, (const pb_byte_t *)key, strlen(key))) {
            goto exit;
        }

        if (!pb_encode_tag(stream, PB_WT_STRING, 2U)) {
            goto exit;
        }
        if (!pb_encode_string(stream, (const pb_byte_t *)value, strlen(value))) {
            goto exit;
        }
    }

    status = true;

exit:
    return status;
}

/* Public API */

el2go_ota_status_t el2go_ota_encode_check_update(const el2go_ota_check_update_req_t *req,
                                                 uint8_t *buf, size_t buf_len, size_t *out_len)
{
    com_nxp_iot_ota_AvailableUpdatesRequest msg = com_nxp_iot_ota_AvailableUpdatesRequest_init_zero;
    encode_attrs_ctx_t attrs_ctx = { NULL, 0U };
    pb_ostream_t stream = { 0 };
    el2go_ota_status_t status = EL2GO_OTA_ERROR_ENCODE;

    EL2GO_DBG_TRACE_API_CALL;

    if (req == NULL || buf == NULL || out_len == NULL || buf_len == 0U) {
        EL2GO_DBG_PRINTF(ERROR, "encode_check_update: NULL argument\n");
        status = EL2GO_OTA_ERROR_INVALID_PARAM;
        goto exit;
    }

    *out_len = 0U;

    attrs_ctx.attrs = req->attrs;
    attrs_ctx.attr_count = req->attr_count;

    if (req->attr_count > 0U && req->attrs != NULL) {
        msg.deviceAttributes.funcs.encode = encode_string_map_cb;
        msg.deviceAttributes.arg = &attrs_ctx;
    }

    stream = pb_ostream_from_buffer(buf, buf_len);

    if (!pb_encode(&stream, com_nxp_iot_ota_AvailableUpdatesRequest_fields, &msg)) {
        EL2GO_DBG_PRINTF(ERROR, "encode_check_update: pb_encode failed: %s\n",
                         PB_GET_ERROR(&stream));
        goto exit;
    }

    *out_len = stream.bytes_written;
    status = EL2GO_OTA_SUCCESS;

exit:
    return status;
}

el2go_ota_status_t el2go_ota_encode_fetch_package(const el2go_ota_fetch_pkg_req_t *req,
                                                  uint8_t *buf, size_t buf_len, size_t *out_len)
{
    com_nxp_iot_ota_FileRequest msg = com_nxp_iot_ota_FileRequest_init_zero;
    pb_ostream_t stream = { 0 };
    el2go_ota_status_t status = EL2GO_OTA_ERROR_ENCODE;

    EL2GO_DBG_TRACE_API_CALL;

    if (req == NULL || buf == NULL || out_len == NULL || buf_len == 0U) {
        EL2GO_DBG_PRINTF(ERROR, "encode_fetch_package: NULL argument\n");
        status = EL2GO_OTA_ERROR_INVALID_PARAM;
        goto exit;
    }

    if (req->update_id == NULL || req->package_id == NULL) {
        EL2GO_DBG_PRINTF(ERROR, "encode_fetch_package: update_id or package_id is NULL\n");
        status = EL2GO_OTA_ERROR_INVALID_PARAM;
        goto exit;
    }

    *out_len = 0U;

    (void)strncpy(msg.updateId, req->update_id, sizeof(msg.updateId) - 1U);
    (void)strncpy(msg.packageId, req->package_id, sizeof(msg.packageId) - 1U);
    msg.updateId[sizeof(msg.updateId) - 1U] = '\0';
    msg.packageId[sizeof(msg.packageId) - 1U] = '\0';

    if (req->artifact_id != NULL) {
        (void)strncpy(msg.artifactId, req->artifact_id, sizeof(msg.artifactId) - 1U);
        msg.artifactId[sizeof(msg.artifactId) - 1U] = '\0';
    }

    if (req->has_range_start) {
        msg.has_rangeStart = true;
        msg.rangeStart = req->range_start;
    }
    if (req->has_range_end) {
        msg.has_rangeEnd = true;
        msg.rangeEnd = req->range_end;
    }

    stream = pb_ostream_from_buffer(buf, buf_len);

    if (!pb_encode(&stream, com_nxp_iot_ota_FileRequest_fields, &msg)) {
        EL2GO_DBG_PRINTF(ERROR, "encode_fetch_package: pb_encode failed: %s\n",
                         PB_GET_ERROR(&stream));
        goto exit;
    }

    *out_len = stream.bytes_written;
    status = EL2GO_OTA_SUCCESS;

exit:
    return status;
}

el2go_ota_status_t el2go_ota_encode_report_status(const el2go_ota_report_status_req_t *req,
                                                  uint8_t *buf, size_t buf_len, size_t *out_len)
{
    com_nxp_iot_ota_UpdateStatusNotification msg =
        com_nxp_iot_ota_UpdateStatusNotification_init_zero;
    pb_ostream_t stream = { 0 };
    el2go_ota_status_t status = EL2GO_OTA_ERROR_ENCODE;

    EL2GO_DBG_TRACE_API_CALL;

    if (req == NULL || buf == NULL || out_len == NULL || buf_len == 0U) {
        EL2GO_DBG_PRINTF(ERROR, "encode_report_status: NULL argument\n");
        status = EL2GO_OTA_ERROR_INVALID_PARAM;
        goto exit;
    }

    if (req->update_id == NULL) {
        EL2GO_DBG_PRINTF(ERROR, "encode_report_status: update_id is NULL\n");
        status = EL2GO_OTA_ERROR_INVALID_PARAM;
        goto exit;
    }

    *out_len = 0U;

    (void)strncpy(msg.updateId, req->update_id, sizeof(msg.updateId) - 1U);
    msg.updateId[sizeof(msg.updateId) - 1U] = '\0';

    msg.updateStatus = (com_nxp_iot_ota_Status)req->status;

    if (req->status_message != NULL) {
        msg.has_statusMessage = true;
        (void)strncpy(msg.statusMessage, req->status_message, sizeof(msg.statusMessage) - 1U);
        msg.statusMessage[sizeof(msg.statusMessage) - 1U] = '\0';
    }

    stream = pb_ostream_from_buffer(buf, buf_len);

    if (!pb_encode(&stream, com_nxp_iot_ota_UpdateStatusNotification_fields, &msg)) {
        EL2GO_DBG_PRINTF(ERROR, "encode_report_status: pb_encode failed: %s\n",
                         PB_GET_ERROR(&stream));
        goto exit;
    }

    *out_len = stream.bytes_written;
    status = EL2GO_OTA_SUCCESS;

exit:
    return status;
}
