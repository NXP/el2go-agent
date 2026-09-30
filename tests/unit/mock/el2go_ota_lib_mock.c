/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "el2go_ota_lib_mock.h"

#include <string.h>

#ifndef EL2GO_OTA_LIB_MOCK_MAX_QUEUE
#define EL2GO_OTA_LIB_MOCK_MAX_QUEUE 4U
#endif

#ifndef EL2GO_OTA_LIB_MOCK_PAYLOAD_MAX
#define EL2GO_OTA_LIB_MOCK_PAYLOAD_MAX 8192U
#endif

typedef struct {
    el2go_ota_check_update_resp_t resp;
    el2go_ota_status_t status;
} queued_check_t;

typedef struct {
    /* init/connect state */
    bool connected;
    bool connect_fail;
    size_t connect_call_count;

    /* check_for_updates() */
    queued_check_t queue[EL2GO_OTA_LIB_MOCK_MAX_QUEUE];
    size_t queue_count;
    size_t queue_pos;
    size_t check_call_count;

    /* download_package() */
    uint8_t payload[EL2GO_OTA_LIB_MOCK_PAYLOAD_MAX];
    size_t payload_len;
    uint32_t download_fail_count;
    bool download_hard_fail;
    size_t download_call_count;
    size_t last_resume_offset;

    /* report_status() */
    uint32_t report_reject_count;
    size_t report_call_count;
    el2go_ota_update_outcome_t last_reported_outcome;
    char last_reported_update_id[EL2GO_OTA_MAX_UPDATE_ID_LEN];
    char last_reported_package_id[EL2GO_OTA_MAX_PACKAGE_ID_LEN];

    /* pending status */
    el2go_ota_pending_status_t pending_status;

    /* schedule_status_report() */
    size_t schedule_call_count;
    el2go_ota_update_outcome_t last_scheduled_outcome;
    char last_scheduled_update_id[EL2GO_OTA_MAX_UPDATE_ID_LEN];
    char last_scheduled_package_id[EL2GO_OTA_MAX_PACKAGE_ID_LEN];

    /* report_pending_status() */
    uint32_t pending_reject_count;
    size_t pending_delivered_count;
    size_t report_pending_call_count;

    /* single static mock ctx instance, returned by el2go_ota_init() */
    int ctx_marker;
} el2go_ota_lib_mock_state_t;

static el2go_ota_lib_mock_state_t s_mock;

void el2go_ota_lib_mock_reset(void)
{
    memset(&s_mock, 0, sizeof(s_mock));
}

void el2go_ota_lib_mock_queue_check_response(const el2go_ota_check_update_resp_t *resp,
                                             el2go_ota_status_t status)
{
    if (resp == NULL || s_mock.queue_count >= EL2GO_OTA_LIB_MOCK_MAX_QUEUE) {
        return;
    }
    s_mock.queue[s_mock.queue_count].resp = *resp;
    s_mock.queue[s_mock.queue_count].status = status;
    s_mock.queue_count++;
}

size_t el2go_ota_lib_mock_check_count(void)
{
    return s_mock.check_call_count;
}

void el2go_ota_lib_mock_set_payload(const uint8_t *data, size_t len)
{
    if (len > EL2GO_OTA_LIB_MOCK_PAYLOAD_MAX) {
        len = EL2GO_OTA_LIB_MOCK_PAYLOAD_MAX;
    }
    if (data != NULL && len > 0U) {
        memcpy(s_mock.payload, data, len);
    }
    s_mock.payload_len = len;
}

void el2go_ota_lib_mock_set_download_fail_count(uint32_t fail_count)
{
    s_mock.download_fail_count = fail_count;
}

void el2go_ota_lib_mock_set_download_hard_fail(bool always_fail)
{
    s_mock.download_hard_fail = always_fail;
}

size_t el2go_ota_lib_mock_download_call_count(void)
{
    return s_mock.download_call_count;
}

size_t el2go_ota_lib_mock_last_resume_offset(void)
{
    return s_mock.last_resume_offset;
}

void el2go_ota_lib_mock_set_report_reject_count(uint32_t reject_count)
{
    s_mock.report_reject_count = reject_count;
}

el2go_ota_update_outcome_t el2go_ota_lib_mock_last_reported_outcome(void)
{
    return s_mock.last_reported_outcome;
}

const char *el2go_ota_lib_mock_last_reported_update_id(void)
{
    return s_mock.last_reported_update_id;
}

const char *el2go_ota_lib_mock_last_reported_package_id(void)
{
    return s_mock.last_reported_package_id;
}

size_t el2go_ota_lib_mock_report_call_count(void)
{
    return s_mock.report_call_count;
}

void el2go_ota_lib_mock_set_pending_status(const el2go_ota_pending_status_t *status)
{
    if (status == NULL) {
        memset(&s_mock.pending_status, 0, sizeof(s_mock.pending_status));
        return;
    }
    s_mock.pending_status = *status;
}

void el2go_ota_lib_mock_set_connect_fail(bool fail)
{
    s_mock.connect_fail = fail;
}

size_t el2go_ota_lib_mock_connect_call_count(void)
{
    return s_mock.connect_call_count;
}

void el2go_ota_lib_mock_force_disconnected(void)
{
    s_mock.connected = false;
}

el2go_ota_update_outcome_t el2go_ota_lib_mock_last_scheduled_outcome(void)
{
    return s_mock.last_scheduled_outcome;
}

const char *el2go_ota_lib_mock_last_scheduled_update_id(void)
{
    return s_mock.last_scheduled_update_id;
}

const char *el2go_ota_lib_mock_last_scheduled_package_id(void)
{
    return s_mock.last_scheduled_package_id;
}

size_t el2go_ota_lib_mock_schedule_call_count(void)
{
    return s_mock.schedule_call_count;
}

void el2go_ota_lib_mock_set_pending_reject_count(uint32_t reject_count)
{
    s_mock.pending_reject_count = reject_count;
}

size_t el2go_ota_lib_mock_pending_delivered_count(void)
{
    return s_mock.pending_delivered_count;
}

size_t el2go_ota_lib_mock_report_pending_call_count(void)
{
    return s_mock.report_pending_call_count;
}

el2go_ota_status_t __wrap_el2go_ota_init(el2go_ota_ctx_t **ctx,
                                         const el2go_ota_mtls_config_t *config)
{
    if (ctx == NULL || config == NULL || config->hostname == NULL ||
        config->server_ca_chain == NULL || config->server_ca_chain_size == 0U) {
        if (ctx != NULL) {
            *ctx = NULL;
        }
        return EL2GO_OTA_ERROR_INVALID_PARAM;
    }

    *ctx = (el2go_ota_ctx_t *)&s_mock.ctx_marker;
    return EL2GO_OTA_SUCCESS;
}

el2go_ota_status_t __wrap_el2go_ota_connect(el2go_ota_ctx_t *ctx)
{
    (void)ctx;

    s_mock.connect_call_count++;

    if (s_mock.connect_fail) {
        return EL2GO_OTA_ERROR_NETWORK;
    }

    s_mock.connected = true;
    return EL2GO_OTA_SUCCESS;
}

el2go_ota_status_t __wrap_el2go_ota_disconnect(el2go_ota_ctx_t *ctx)
{
    (void)ctx;

    s_mock.connected = false;
    return EL2GO_OTA_SUCCESS;
}

void __wrap_el2go_ota_cleanup(el2go_ota_ctx_t **ctx)
{
    s_mock.connected = false;
    if (ctx != NULL) {
        *ctx = NULL;
    }
}

bool __wrap_el2go_ota_is_connected(const el2go_ota_ctx_t *ctx)
{
    if (ctx == NULL) {
        return false;
    }
    return s_mock.connected;
}

const char *__wrap_el2go_ota_get_error_string(el2go_ota_status_t status)
{
    (void)status;
    return "mock-error";
}

el2go_ota_status_t __wrap_el2go_ota_check_for_updates(el2go_ota_ctx_t *ctx,
                                                      const el2go_ota_attr_t *attrs,
                                                      size_t attr_count,
                                                      el2go_ota_check_update_resp_t *out_resp)
{
    (void)ctx;
    (void)attrs;
    (void)attr_count;

    if (out_resp == NULL) {
        return EL2GO_OTA_ERROR_INVALID_PARAM;
    }

    s_mock.check_call_count++;

    if (s_mock.queue_count == 0U) {
        memset(out_resp, 0, sizeof(*out_resp));
        out_resp->update_available = false;
        return EL2GO_OTA_SUCCESS;
    }

    size_t idx = s_mock.queue_pos;
    if (idx >= s_mock.queue_count) {
        idx = s_mock.queue_count - 1U; /* repeat last entry once exhausted */
    } else {
        s_mock.queue_pos++;
    }

    *out_resp = s_mock.queue[idx].resp;
    return s_mock.queue[idx].status;
}

el2go_ota_status_t __wrap_el2go_ota_download_package(
    el2go_ota_ctx_t *ctx, const char *update_id, const char *package_id, const char *file_id,
    size_t resume_offset,
    el2go_ota_status_t (*chunk_cb)(const uint8_t *data, size_t len, size_t offset, void *cb_ctx),
    void *cb_ctx)
{
    (void)ctx;
    (void)update_id;
    (void)package_id;
    (void)file_id;

    s_mock.download_call_count++;
    s_mock.last_resume_offset = resume_offset;

    if (s_mock.download_hard_fail) {
        return EL2GO_OTA_ERROR_NETWORK;
    }
    if (s_mock.download_call_count <= (size_t)s_mock.download_fail_count) {
        return EL2GO_OTA_ERROR_NETWORK;
    }

    if (chunk_cb == NULL) {
        return EL2GO_OTA_ERROR_INVALID_PARAM;
    }

    size_t offset = resume_offset;
    el2go_ota_status_t status = EL2GO_OTA_SUCCESS;

    while (offset < s_mock.payload_len) {
        size_t remaining = s_mock.payload_len - offset;
        size_t chunk_len = remaining < EL2GO_OTA_CHUNK_SIZE ? remaining : EL2GO_OTA_CHUNK_SIZE;

        status = chunk_cb(&s_mock.payload[offset], chunk_len, offset, cb_ctx);
        if (status != EL2GO_OTA_SUCCESS) {
            return status;
        }
        offset += chunk_len;
    }

    return status;
}

el2go_ota_status_t __wrap_el2go_ota_report_status(el2go_ota_ctx_t *ctx, const char *update_id,
                                                  const char *package_id,
                                                  el2go_ota_update_outcome_t outcome)
{
    (void)ctx;

    s_mock.report_call_count++;

    if (s_mock.report_call_count <= (size_t)s_mock.report_reject_count) {
        return EL2GO_OTA_ERROR_NETWORK;
    }

    s_mock.last_reported_outcome = outcome;
    if (update_id != NULL) {
        (void)strncpy(s_mock.last_reported_update_id, update_id,
                      sizeof(s_mock.last_reported_update_id) - 1U);
        s_mock.last_reported_update_id[sizeof(s_mock.last_reported_update_id) - 1U] = '\0';
    }
    if (package_id != NULL) {
        (void)strncpy(s_mock.last_reported_package_id, package_id,
                      sizeof(s_mock.last_reported_package_id) - 1U);
        s_mock.last_reported_package_id[sizeof(s_mock.last_reported_package_id) - 1U] = '\0';
    }

    return EL2GO_OTA_SUCCESS;
}

el2go_ota_status_t __wrap_el2go_ota_schedule_status_report(const char *update_id,
                                                           const char *package_id,
                                                           el2go_ota_update_outcome_t outcome)
{
    s_mock.schedule_call_count++;
    s_mock.last_scheduled_outcome = outcome;

    if (update_id != NULL) {
        (void)strncpy(s_mock.last_scheduled_update_id, update_id,
                      sizeof(s_mock.last_scheduled_update_id) - 1U);
        s_mock.last_scheduled_update_id[sizeof(s_mock.last_scheduled_update_id) - 1U] = '\0';
    }
    if (package_id != NULL) {
        (void)strncpy(s_mock.last_scheduled_package_id, package_id,
                      sizeof(s_mock.last_scheduled_package_id) - 1U);
        s_mock.last_scheduled_package_id[sizeof(s_mock.last_scheduled_package_id) - 1U] = '\0';
    }

    s_mock.pending_status.outcome = (uint8_t)outcome;

    (void)memcpy(s_mock.pending_status.update_id, s_mock.last_scheduled_update_id,
                 sizeof(s_mock.pending_status.update_id));

    (void)memcpy(s_mock.pending_status.package_id, s_mock.last_scheduled_package_id,
                 sizeof(s_mock.pending_status.package_id));

    s_mock.pending_status.valid = EL2GO_OTA_STATUS_VALID_MAGIC;

    return EL2GO_OTA_SUCCESS;
}

el2go_ota_status_t __wrap_el2go_ota_get_pending_status(el2go_ota_pending_status_t *out)
{
    if (out == NULL) {
        return EL2GO_OTA_ERROR_INVALID_PARAM;
    }
    *out = s_mock.pending_status;
    return EL2GO_OTA_SUCCESS;
}

el2go_ota_status_t __wrap_el2go_ota_report_pending_status(el2go_ota_ctx_t *ctx)
{
    (void)ctx;

    if (s_mock.pending_status.valid != EL2GO_OTA_STATUS_VALID_MAGIC) {
        return EL2GO_OTA_SUCCESS; /* nothing pending -- matches real contract */
    }

    s_mock.report_pending_call_count++;

    if (s_mock.report_pending_call_count <= (size_t)s_mock.pending_reject_count) {
        return EL2GO_OTA_ERROR_NETWORK; /* entry retained, matching real retry contract */
    }

    s_mock.pending_delivered_count++;
    memset(&s_mock.pending_status, 0, sizeof(s_mock.pending_status)); /* delivered -> cleared */
    return EL2GO_OTA_SUCCESS;
}
