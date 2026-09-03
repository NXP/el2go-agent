/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <string.h>

#include "el2go_ota_transport.h"
#include "mock_transport.h"

#define MOCK_MAX_RESPONSES 16
#define MOCK_MAX_RESP_LEN 4096
#define MOCK_MAX_REQ_LEN 4096

struct mock_response {
    uint8_t data[MOCK_MAX_RESP_LEN];
    size_t len;
    int is_error;
};

static struct mock_response s_responses[MOCK_MAX_RESPONSES];
static size_t s_resp_head;
static size_t s_resp_tail;
static size_t s_resp_count;

static uint8_t s_last_request[MOCK_MAX_REQ_LEN];
static size_t s_last_request_len;
static int s_have_request;
static size_t s_send_count;

void mock_transport_reset(void)
{
    s_resp_head = 0;
    s_resp_tail = 0;
    s_resp_count = 0;
    s_last_request_len = 0;
    s_have_request = 0;
    s_send_count = 0;
    (void)memset(s_responses, 0, sizeof(s_responses));
    (void)memset(s_last_request, 0, sizeof(s_last_request));
}

int mock_transport_queue_response(const uint8_t *data, size_t len)
{
    struct mock_response *slot;

    if (s_resp_count >= MOCK_MAX_RESPONSES) {
        return -1;
    }
    if (len > MOCK_MAX_RESP_LEN) {
        return -1;
    }
    if ((data == NULL) && (len != 0U)) {
        return -1;
    }

    slot = &s_responses[s_resp_tail];
    slot->is_error = 0;
    slot->len = len;
    if (len != 0U) {
        (void)memcpy(slot->data, data, len);
    }

    s_resp_tail = (s_resp_tail + 1U) % MOCK_MAX_RESPONSES;
    s_resp_count++;
    return 0;
}

int mock_transport_queue_network_error(void)
{
    struct mock_response *slot;

    if (s_resp_count >= MOCK_MAX_RESPONSES) {
        return -1;
    }

    slot = &s_responses[s_resp_tail];
    slot->is_error = 1;
    slot->len = 0;

    s_resp_tail = (s_resp_tail + 1U) % MOCK_MAX_RESPONSES;
    s_resp_count++;
    return 0;
}

int mock_transport_get_last_request(uint8_t *buf, size_t buf_size, size_t *out_len)
{
    if ((buf == NULL) || (out_len == NULL)) {
        return -1;
    }
    if (s_have_request == 0) {
        return -1;
    }
    if (buf_size < s_last_request_len) {
        return -1;
    }

    (void)memcpy(buf, s_last_request, s_last_request_len);
    *out_len = s_last_request_len;
    return 0;
}

size_t mock_transport_send_count(void)
{
    return s_send_count;
}

static el2go_ota_status_t mock_send(el2go_ota_transport_t *t, const char *method_path,
                                    const uint8_t *msg, size_t msg_len)
{
    (void)t;
    (void)method_path;

    if (msg == NULL) {
        return EL2GO_OTA_ERROR_INVALID_PARAM;
    }
    if (msg_len > MOCK_MAX_REQ_LEN) {
        s_last_request_len = 0U;
        s_have_request = 0;
        return EL2GO_OTA_ERROR_INTERNAL;
    }

    (void)memcpy(s_last_request, msg, msg_len);
    s_last_request_len = msg_len;
    s_have_request = 1;
    s_send_count++;

    return EL2GO_OTA_SUCCESS;
}

static el2go_ota_status_t mock_recv(el2go_ota_transport_t *t, uint8_t *buf, size_t buf_len,
                                    size_t *out_len)
{
    struct mock_response *slot;

    (void)t;

    if ((buf == NULL) || (out_len == NULL)) {
        return EL2GO_OTA_ERROR_INVALID_PARAM;
    }

    if (s_resp_count == 0U) {
        /* simulate a closed connection. */
        return EL2GO_OTA_ERROR_NETWORK;
    }

    slot = &s_responses[s_resp_head];
    s_resp_head = (s_resp_head + 1U) % MOCK_MAX_RESPONSES;
    s_resp_count--;

    if (slot->is_error != 0) {
        return EL2GO_OTA_ERROR_NETWORK;
    }

    if (slot->len > buf_len) {
        return EL2GO_OTA_ERROR_INTERNAL;
    }

    if (slot->len != 0U) {
        (void)memcpy(buf, slot->data, slot->len);
    }
    *out_len = slot->len;
    return EL2GO_OTA_SUCCESS;
}

static void mock_deinit(el2go_ota_transport_t *t)
{
    if (t != NULL) {
        t->impl_ctx = NULL;
    }
}

el2go_ota_status_t mock_transport_init(el2go_ota_transport_t *t)
{
    if (t == NULL) {
        return EL2GO_OTA_ERROR_INVALID_PARAM;
    }

    t->send = mock_send;
    t->recv = mock_recv;
    t->deinit = mock_deinit;
    t->impl_ctx = NULL;

    return EL2GO_OTA_SUCCESS;
}
