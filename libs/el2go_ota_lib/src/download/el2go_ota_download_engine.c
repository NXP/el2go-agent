/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "osal.h"
#include "debug.h"
#include "download/el2go_ota_download_engine.h"
#include "el2go_ota_request_builder.h"
#include "el2go_ota_response_handler.h"
#include "ota/el2go_ota_lib.h"
#include "ota/el2go_ota_config.h"

/* Wire buffer size: chunk data plus gRPC/protobuf framing overhead. */
#define WIRE_BUF_SIZE (EL2GO_OTA_CHUNK_SIZE + EL2GO_OTA_WIRE_OVERHEAD)

/* gRPC method paths for the OTA delivery service. */
#define GRPC_METHOD_GET_AVAILABLE_UPDATES \
    "/com.nxp.iot.ota.update.poc.proto.OtaUpdateDeliveryService/GetAvailableUpdates"
#define GRPC_METHOD_FETCH_FILE \
    "/com.nxp.iot.ota.update.poc.proto.OtaUpdateDeliveryService/FetchFile"

el2go_ota_status_t
el2go_ota_download_engine_check_for_updates(el2go_ota_transport_t *transport,
                                            const el2go_ota_attr_t *attrs, size_t attr_count,
                                            el2go_ota_check_update_resp_t *out_resp)
{
    uint8_t wire_buf[WIRE_BUF_SIZE] = { 0U };
    el2go_ota_check_update_req_t req = { 0 };
    size_t encoded_len = 0U;
    size_t recv_len = 0U;
    el2go_ota_status_t status = EL2GO_OTA_ERROR_NETWORK;

    req.attrs = attrs;
    req.attr_count = attr_count;

    status = el2go_ota_encode_check_update(&req, wire_buf, sizeof(wire_buf), &encoded_len);
    if (status != EL2GO_OTA_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "check_for_updates: encode failed: %d\n", status);
        goto exit;
    }

    status = transport->send(transport, GRPC_METHOD_GET_AVAILABLE_UPDATES, wire_buf, encoded_len);
    if (status != EL2GO_OTA_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "check_for_updates: send failed: %d\n", status);
        status = EL2GO_OTA_ERROR_NETWORK;
        goto exit;
    }

    status = transport->recv(transport, wire_buf, sizeof(wire_buf), &recv_len);
    if (status != EL2GO_OTA_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "check_for_updates: recv failed: %d\n", status);
        goto exit;
    }

    status = el2go_ota_parse_check_update_response(wire_buf, recv_len, out_resp);
    if (status != EL2GO_OTA_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "check_for_updates: parse failed: %d\n", status);
        goto exit;
    }

    if (out_resp->update_available) {
        EL2GO_DBG_PRINTF(INFO, "Update available: %zu update(s)\n", out_resp->update_count);
        {
            for (size_t i = 0U; i < out_resp->update_count; i++) {
                EL2GO_DBG_PRINTF(INFO, "  update_id=%s (packages: %zu)\n",
                                 out_resp->updates[i].update_id,
                                 out_resp->updates[i].package_count);
            }
        }
    } else {
        EL2GO_DBG_PRINTF(INFO, "No update available.\n");
    }

    status = EL2GO_OTA_SUCCESS;
exit:
    return status;
}

el2go_ota_status_t el2go_ota_download_engine_fetch_package(
    el2go_ota_transport_t *transport, const char *update_id, const char *package_id,
    size_t resume_offset,
    el2go_ota_status_t (*chunk_cb)(const uint8_t *data, size_t len, size_t offset, void *ctx),
    void *cb_ctx)
{
    uint8_t wire_buf[WIRE_BUF_SIZE] = { 0U };
    el2go_ota_fetch_pkg_req_t req = { 0 };
    el2go_ota_fetch_pkg_resp_t resp = { 0 };
    size_t encoded_len = 0U;
    size_t recv_len = 0U;
    size_t byte_offset = 0U;
    uint32_t attempt = 0U;
    bool done = false;
    el2go_ota_status_t status = EL2GO_OTA_ERROR_NETWORK;
    el2go_ota_status_t cb_status = EL2GO_OTA_ERROR_NETWORK;

    byte_offset = resume_offset;

    EL2GO_DBG_PRINTF(INFO, "Downloading package: update_id=%s package_id=%s offset=%zu\n",
                     update_id, package_id, resume_offset);

    while (!done) {
        req.update_id = update_id;
        req.package_id = package_id;
        req.artifact_id = NULL;
        req.has_range_start = true;
        req.range_start = (int64_t)byte_offset;
        req.has_range_end = true;
        req.range_end = (int64_t)(byte_offset + EL2GO_OTA_CHUNK_SIZE - 1U);

        /* Encoding failure is not retried. */
        status = el2go_ota_encode_fetch_package(&req, wire_buf, sizeof(wire_buf), &encoded_len);
        if (status != EL2GO_OTA_SUCCESS) {
            EL2GO_DBG_PRINTF(ERROR, "fetch_package: encode failed: %d\n", status);
            goto exit;
        }

        /* Send + receive with exponential backoff retry on network errors. */
        attempt = 0U;
        while (attempt <= EL2GO_OTA_DOWNLOAD_MAX_RETRIES) {
            status = transport->send(transport, GRPC_METHOD_FETCH_FILE, wire_buf, encoded_len);
            if (status != EL2GO_OTA_SUCCESS) {
                goto handle_network_error;
            }

            status = transport->recv(transport, wire_buf, sizeof(wire_buf), &recv_len);
            if (status != EL2GO_OTA_SUCCESS) {
                goto handle_network_error;
            }

            /* Network succeeded -- break the retry loop. */
            break;

handle_network_error:
            if (attempt < EL2GO_OTA_DOWNLOAD_MAX_RETRIES) {
                uint32_t delay_ms = EL2GO_OTA_DOWNLOAD_RETRY_BASE_MS << attempt;
                EL2GO_DBG_PRINTF(ERROR,
                                 "fetch_package: network failure on attempt %u, "
                                 "retrying in %u ms\n",
                                 attempt + 1U, delay_ms);
                osal_sleep_ms(delay_ms);
                attempt++;
                continue;
            }
            EL2GO_DBG_PRINTF(ERROR, "fetch_package: download failed after %u retries\n",
                             EL2GO_OTA_DOWNLOAD_MAX_RETRIES);
            status = EL2GO_OTA_ERROR_NETWORK;
            goto exit;
        }

        /* Parse failure is not retried. */
        status = el2go_ota_parse_fetch_package_response(wire_buf, recv_len, &resp);
        if (status != EL2GO_OTA_SUCCESS) {
            EL2GO_DBG_PRINTF(ERROR, "fetch_package: parse failed: %d\n", status);
            goto exit;
        }

        /* Empty data payload signals end of file. */
        if (resp.data_len == 0U) {
            EL2GO_DBG_PRINTF(INFO, "fetch_package: server signalled end of file\n");
            done = true;
            break;
        }

        /*
         * Resume support: if this chunk ends at or before resume_offset,
         * it was already delivered in a previous attempt -- skip it.
         */
        if ((byte_offset + resp.data_len) <= resume_offset) {
            EL2GO_DBG_PRINTF(VERBOSE,
                             "fetch_package: skipping already-delivered chunk "
                             "offset=%zu len=%zu\n",
                             byte_offset, resp.data_len);
            byte_offset += resp.data_len;
            continue;
        }

        cb_status = chunk_cb(resp.data_ptr, resp.data_len, byte_offset, cb_ctx);
        if (cb_status != EL2GO_OTA_SUCCESS) {
            EL2GO_DBG_PRINTF(ERROR, "fetch_package: chunk_cb returned error %d at offset %zu\n",
                             cb_status, byte_offset);
            status = cb_status;
            goto exit;
        }

        byte_offset += resp.data_len;

        /* Short read signals end of file. */
        if (resp.data_len < EL2GO_OTA_CHUNK_SIZE) {
            EL2GO_DBG_PRINTF(INFO, "fetch_package: last chunk received (short read)\n");
            done = true;
        }
    }

    EL2GO_DBG_PRINTF(INFO, "Download complete: %zu bytes delivered\n", byte_offset - resume_offset);

    status = EL2GO_OTA_SUCCESS;
exit:
    return status;
}
