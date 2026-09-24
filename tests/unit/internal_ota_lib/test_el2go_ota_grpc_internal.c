/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "test_framework.h"
#include "test_suites.h"

#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include "common/el2go_status.h"
#include "ota/el2go_ota_lib.h"

#include "wrap_net_crypto.h"
#include "el2go_ota_tls.h"

#define el2go_ota_transport_init test_shadow_el2go_ota_transport_init
#include "transport/grpc/el2go_ota_grpc.c"
#undef el2go_ota_transport_init

/**
 * @brief Verify grpc parse trailers status ok.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_grpc_parse_trailers_status_ok(void *params)
{
    /* HPACK literal: len=0x0B "grpc-status", value len=1 "0" */
    static const uint8_t block[] = { 0x0BU, 'g', 'r', 'p', 'c', '-',   's',
                                     't',   'a', 't', 'u', 's', 0x01U, '0' };
    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, grpc_parse_trailers(block, sizeof(block)));
    return true;
}

/**
 * @brief Verify grpc parse trailers status nonzero.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_grpc_parse_trailers_status_nonzero(void *params)
{
    /* grpc-status value "5" (NOT_FOUND) -> ERROR_SERVER */
    static const uint8_t block[] = { 0x0BU, 'g', 'r', 'p', 'c', '-',   's',
                                     't',   'a', 't', 'u', 's', 0x01U, '5' };
    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_SERVER, grpc_parse_trailers(block, sizeof(block)));
    return true;
}

/**
 * @brief Verify grpc parse trailers not found.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_grpc_parse_trailers_not_found(void *params)
{
    /* No "grpc-status" name pattern anywhere in the block -> treated as OK */
    static const uint8_t block[] = { 0x04U, 't', 'e', 's', 't', 0x01U, 'x' };
    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, grpc_parse_trailers(block, sizeof(block)));
    return true;
}

/**
 * @brief Verify grpc parse trailers null block.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_grpc_parse_trailers_null_block(void *params)
{
    (void)params;
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, grpc_parse_trailers(NULL, 0U));
    return true;
}

/**
 * @brief Verify grpc parse trailers too short.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_grpc_parse_trailers_too_short(void *params)
{
    static const uint8_t block[] = { 0x01U, 'x' };
    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, grpc_parse_trailers(block, sizeof(block)));
    return true;
}

/**
 * @brief Verify grpc status.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_grpc_status(void *params)
{
    (void)params;

    TEST_ASSERT_STRING_EQUAL("OK", grpc_status_name(0U));
    TEST_ASSERT_STRING_EQUAL("CANCELLED", grpc_status_name(1U));
    TEST_ASSERT_STRING_EQUAL("UNKNOWN", grpc_status_name(2U));
    TEST_ASSERT_STRING_EQUAL("INVALID_ARGUMENT", grpc_status_name(3U));
    TEST_ASSERT_STRING_EQUAL("DEADLINE_EXCEEDED", grpc_status_name(4U));
    TEST_ASSERT_STRING_EQUAL("NOT_FOUND", grpc_status_name(5U));
    TEST_ASSERT_STRING_EQUAL("ALREADY_EXISTS", grpc_status_name(6U));
    TEST_ASSERT_STRING_EQUAL("PERMISSION_DENIED", grpc_status_name(7U));
    TEST_ASSERT_STRING_EQUAL("RESOURCE_EXHAUSTED", grpc_status_name(8U));
    TEST_ASSERT_STRING_EQUAL("FAILED_PRECONDITION", grpc_status_name(9U));
    TEST_ASSERT_STRING_EQUAL("ABORTED", grpc_status_name(10U));
    TEST_ASSERT_STRING_EQUAL("OUT_OF_RANGE", grpc_status_name(11U));
    TEST_ASSERT_STRING_EQUAL("UNIMPLEMENTED", grpc_status_name(12U));
    TEST_ASSERT_STRING_EQUAL("INTERNAL", grpc_status_name(13U));
    TEST_ASSERT_STRING_EQUAL("UNAVAILABLE", grpc_status_name(14U));
    TEST_ASSERT_STRING_EQUAL("DATA_LOSS", grpc_status_name(15U));
    TEST_ASSERT_STRING_EQUAL("UNAUTHENTICATED", grpc_status_name(16U));

    TEST_ASSERT_STRING_EQUAL("UNKNOWN_CODE", grpc_status_name(9999U));
    return true;
}

/**
 * @brief Verify h2 build frame hdr layout.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_h2_build_frame_hdr_layout(void *params)
{
    uint8_t hdr[H2_FRAME_HDR_LEN] = { 0U };
    (void)params;

    h2_build_frame_hdr(hdr, 0x00ABCDU, H2_TYPE_DATA, H2_FLAG_END_STREAM, 0x00000003U);

    /* payload length: 24-bit big-endian */
    TEST_ASSERT_EQUAL(0x00U, hdr[0]);
    TEST_ASSERT_EQUAL(0xABU, hdr[1]);
    TEST_ASSERT_EQUAL(0xCDU, hdr[2]);
    /* type / flags */
    TEST_ASSERT_EQUAL(H2_TYPE_DATA, hdr[3]);
    TEST_ASSERT_EQUAL(H2_FLAG_END_STREAM, hdr[4]);
    /* stream id: reserved MSB = 0, then 31-bit id */
    TEST_ASSERT_EQUAL(0x00U, hdr[5]);
    TEST_ASSERT_EQUAL(0x00U, hdr[6]);
    TEST_ASSERT_EQUAL(0x00U, hdr[7]);
    TEST_ASSERT_EQUAL(0x03U, hdr[8]);
    return true;
}

/**
 * @brief Verify hpack put string buffer too small.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_hpack_put_string_buffer_too_small(void *params)
{
    uint8_t buf[2] = { 0U };
    size_t pos = 0U;
    (void)params;

    /* "content-type" needs 1 (len byte) + 12 bytes = 13; buf only has 2. */
    TEST_ASSERT_EQUAL(false, hpack_put_string(buf, sizeof(buf), &pos, "content-type", 12U));
    return true;
}

/**
 * @brief Verify hpack put string len too large.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_hpack_put_string_len_too_large(void *params)
{
    uint8_t buf[256] = { 0U };
    size_t pos = 0U;
    (void)params;

    /* len >= 128 is rejected outright (single-byte HPACK length only). */
    TEST_ASSERT_EQUAL(false, hpack_put_string(buf, sizeof(buf), &pos, "x", 128U));
    return true;
}

/**
 * @brief Verify grpc parse trailers status all codes.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_grpc_parse_trailers_status_all_codes(void *params)
{
    /* Two-digit codes 10..16 must all be parsed and classified correctly. */
    static const uint8_t block_10[] = { 0x0BU, 'g', 'r', 'p', 'c',   '-', 's', 't',
                                        'a',   't', 'u', 's', 0x02U, '1', '0' };
    static const uint8_t block_16[] = { 0x0BU, 'g', 'r', 'p', 'c',   '-', 's', 't',
                                        'a',   't', 'u', 's', 0x02U, '1', '6' };
    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_SERVER, grpc_parse_trailers(block_10, sizeof(block_10)));
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_SERVER, grpc_parse_trailers(block_16, sizeof(block_16)));
    return true;
}

/**
 * @brief Verify grpc parse trailers truncated value.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_grpc_parse_trailers_truncated_value(void *params)
{
    /* val_len says 5 bytes follow, but only 1 byte remains in the block. */
    static const uint8_t block[] = { 0x0BU, 'g', 'r', 'p', 'c', '-',   's',
                                     't',   'a', 't', 'u', 's', 0x05U, '0' };
    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, grpc_parse_trailers(block, sizeof(block)));
    return true;
}

/**
 * @brief Verify grpc parse trailers non digit value.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_grpc_parse_trailers_non_digit_value(void *params)
{
    /* Value starts with a non-digit -- digit loop stops immediately, code
     * stays 0, so this is treated as OK. */
    static const uint8_t block[] = { 0x0BU, 'g', 'r', 'p', 'c', '-',   's',
                                     't',   'a', 't', 'u', 's', 0x01U, 'x' };
    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, grpc_parse_trailers(block, sizeof(block)));
    return true;
}

/**
 * @brief Verify grpc parse trailers overflow guard.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_grpc_parse_trailers_overflow_guard(void *params)
{
    /* A value long enough to overflow uint32_t during decimal accumulation
     * must not wrap around to a false "0" (OK) result; the multiply/add
     * overflow guard should stop the parse and the code accumulated so far
     * (non-zero) is reported as ERROR_SERVER. */
    static const uint8_t block[] = { 0x0BU, 'g', 'r', 'p', 'c', '-', 's', 't', 'a', 't', 'u', 's',
                                     0x0BU, '9', '9', '9', '9', '9', '9', '9', '9', '9', '9', '9' };
    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_SERVER, grpc_parse_trailers(block, sizeof(block)));
    return true;
}

/**
 * @brief Verify grpc parse trailers val start beyond block.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_grpc_parse_trailers_val_start_beyond_block(void *params)
{
    /* The name prefix ends exactly at block_len, so val_start would read
     * past the buffer -- must be treated as truncated. */
    static const uint8_t block[] = { 0x0BU, 'g', 'r', 'p', 'c', '-', 's', 't', 'a', 't', 'u', 's' };
    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, grpc_parse_trailers(block, sizeof(block)));
    return true;
}

/**
 * @brief Verify hpack encode grpc request success.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_hpack_encode_grpc_request_success(void *params)
{
    uint8_t buf[HPACK_BUF_SIZE] = { 0U };
    size_t len = 0U;
    (void)params;

    len = hpack_encode_grpc_request(buf, sizeof(buf), "/pkg.Svc/Method", "example.com");

    TEST_ASSERT(len > 0U);
    /* First two bytes are the fully-indexed :method POST and :scheme https. */
    TEST_ASSERT_EQUAL(0x80U | 3U, buf[0]);
    TEST_ASSERT_EQUAL(0x80U | 7U, buf[1]);
    return true;
}

/**
 * @brief Verify hpack encode grpc request buffer too small.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_hpack_encode_grpc_request_buffer_too_small(void *params)
{
    uint8_t buf[2] = { 0U };
    (void)params;

    /* Buffer too small even for the first two indexed headers + path literal. */
    TEST_ASSERT_EQUAL(0U, hpack_encode_grpc_request(buf, sizeof(buf), "/pkg.Svc/Method",
                                                    "example.com"));
    return true;
}

/**
 * @brief Verify grpc send null params.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_grpc_send_null_params(void *params)
{
    el2go_ota_transport_t t;
    static const uint8_t msg[1] = { 0x01U };
    (void)params;
    memset(&t, 0, sizeof(t));

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      grpc_send(NULL, "/pkg.Svc/Method", msg, sizeof(msg)));
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, grpc_send(&t, NULL, msg, sizeof(msg)));
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      grpc_send(&t, "/pkg.Svc/Method", NULL, sizeof(msg)));
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, grpc_send(&t, "/pkg.Svc/Method", msg, 0U));

    /* impl_ctx == NULL guard (t itself non-NULL but not yet initialised). */
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      grpc_send(&t, "/pkg.Svc/Method", msg, sizeof(msg)));
    return true;
}

/**
 * @brief Verify grpc recv null params.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_grpc_recv_null_params(void *params)
{
    el2go_ota_transport_t t;
    uint8_t buf[4] = { 0U };
    size_t out_len = 0U;
    (void)params;
    memset(&t, 0, sizeof(t));

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, grpc_recv(NULL, buf, sizeof(buf), &out_len));
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, grpc_recv(&t, NULL, sizeof(buf), &out_len));
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, grpc_recv(&t, buf, sizeof(buf), NULL));

    /* impl_ctx == NULL guard. */
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, grpc_recv(&t, buf, sizeof(buf), &out_len));
    return true;
}

/* Reset every wrap control variable relevant to the TLS init/connect path. */
extern int g_wrap_net_crypto_new_rc;
extern int g_wrap_net_crypto_configure_rc;
extern int g_wrap_net_crypto_set_server_cert_rc;
extern int g_wrap_net_crypto_connect_rc;
extern int g_wrap_net_crypto_write_rc;
extern int g_wrap_net_crypto_read_rc;

static void grpc_reset_wraps(void)
{
    g_wrap_net_crypto_new_rc = 0;
    g_wrap_net_crypto_configure_rc = 0;
    g_wrap_net_crypto_set_server_cert_rc = 0;
    g_wrap_net_crypto_connect_rc = 0;
    g_wrap_net_crypto_write_rc = 1;
    g_wrap_net_crypto_read_rc = 1;
    mock_net_rx_reset();
    mock_net_tx_reset();
}

static const uint8_t k_ca_chain[4] = { 0x30, 0x82, 0x01, 0x00 };

static el2go_ota_mtls_config_t grpc_make_cfg(void)
{
    el2go_ota_mtls_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.hostname = "example.com";
    cfg.port = 443U;
    cfg.server_ca_chain = k_ca_chain;
    cfg.server_ca_chain_size = sizeof(k_ca_chain);
    cfg.client_auth = EL2GO_OTA_CLIENT_AUTH_NONE;
    return cfg;
}

static el2go_platform_ctx_t *grpc_get_pctx(void)
{
    static el2go_platform_ctx_t *s_ctx = NULL;

    if (s_ctx == NULL) {
        (void)el2go_platform_init(&s_ctx);
    }
    return s_ctx;
}

/* Append one HTTP/2 frame (header + payload) to the RX queue. */
static void queue_frame(uint32_t payload_len, uint8_t type, uint8_t flags, uint32_t stream_id,
                        const uint8_t *payload)
{
    uint8_t hdr[H2_FRAME_HDR_LEN] = { 0U };

    h2_build_frame_hdr(hdr, payload_len, type, flags, stream_id);
    (void)mock_net_rx_push(hdr, sizeof(hdr));
    if (payload_len > 0U && payload != NULL) {
        (void)mock_net_rx_push(payload, payload_len);
    }
}

/**
 * @brief Verify grpc roundtrip send recv success.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_grpc_roundtrip_send_recv_success(void *params)
{
    el2go_ota_tls_ctx_t *tls = NULL;
    el2go_ota_mtls_config_t cfg = grpc_make_cfg();
    el2go_ota_transport_t t;
    static const uint8_t msg[3] = { 0xAAU, 0xBBU, 0xCCU };
    uint8_t recv_buf[16] = { 0U };
    size_t out_len = 0U;
    static const uint8_t grpc_payload[5 + 3] = { 0x00U, 0x00U, 0x00U, 0x00U,
                                                 0x03U, 0xAAU, 0xBBU, 0xCCU };

    (void)params;
    memset(&t, 0, sizeof(t));
    grpc_reset_wraps();

    TEST_ASSERT_EQUAL(EL2GO_STATUS_SUCCESS, el2go_ota_tls_init(&tls, grpc_get_pctx(), &cfg));
    TEST_ASSERT_NOT_NULL(tls);

    /* Server side of the h2 handshake performed inside grpc_send(). */
    queue_frame(0U, H2_TYPE_SETTINGS, 0x00U, 0U, NULL); /* server SETTINGS */

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      test_shadow_el2go_ota_transport_init(&t, tls, cfg.hostname));
    TEST_ASSERT_NOT_NULL(t.send);
    TEST_ASSERT_NOT_NULL(t.recv);

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, t.send(&t, "/pkg.Svc/Method", msg, sizeof(msg)));

    /* Queue the response DATA frame for recv(). */
    queue_frame((uint32_t)sizeof(grpc_payload), H2_TYPE_DATA, H2_FLAG_END_STREAM, 1U, grpc_payload);

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, t.recv(&t, recv_buf, sizeof(recv_buf), &out_len));
    TEST_ASSERT_EQUAL(3U, out_len);
    TEST_ASSERT_MEMORY_EQUAL(msg, recv_buf, sizeof(msg));

    if (t.deinit != NULL) {
        t.deinit(&t);
    }
    el2go_ota_tls_deinit(tls);
    return true;
}

/**
 * @brief Verify grpc send preface write fail.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_grpc_send_preface_write_fail(void *params)
{
    el2go_ota_tls_ctx_t *tls = NULL;
    el2go_ota_mtls_config_t cfg = grpc_make_cfg();
    el2go_ota_transport_t t;
    static const uint8_t msg[1] = { 0x01U };

    (void)params;
    memset(&t, 0, sizeof(t));
    grpc_reset_wraps();

    TEST_ASSERT_EQUAL(EL2GO_STATUS_SUCCESS, el2go_ota_tls_init(&tls, grpc_get_pctx(), &cfg));
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      test_shadow_el2go_ota_transport_init(&t, tls, cfg.hostname));

    g_wrap_net_crypto_write_fail_on_call = 1U; /* the connection preface write */

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_NETWORK, t.send(&t, "/pkg.Svc/Method", msg, sizeof(msg)));

    if (t.deinit != NULL) {
        t.deinit(&t);
    }
    el2go_ota_tls_deinit(tls);
    return true;
}

static bool grpc_setup_ready_transport(el2go_ota_tls_ctx_t **tls, el2go_ota_transport_t *t)
{
    el2go_ota_mtls_config_t cfg = grpc_make_cfg();
    static const uint8_t msg[1] = { 0x01U };

    memset(t, 0, sizeof(*t));
    grpc_reset_wraps();

    if (el2go_ota_tls_init(tls, grpc_get_pctx(), &cfg) != EL2GO_STATUS_SUCCESS) {
        return false;
    }
    queue_frame(0U, H2_TYPE_SETTINGS, 0x00U, 0U, NULL); /* server SETTINGS for handshake */
    if (test_shadow_el2go_ota_transport_init(t, *tls, cfg.hostname) != EL2GO_OTA_SUCCESS) {
        return false;
    }
    /* First send() performs the h2 handshake and the actual message send. */
    return t->send(t, "/pkg.Svc/Method", msg, sizeof(msg)) == EL2GO_OTA_SUCCESS;
}

/**
 * @brief Verify grpc recv ping then data.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_grpc_recv_ping_then_data(void *params)
{
    el2go_ota_tls_ctx_t *tls = NULL;
    el2go_ota_transport_t t;
    uint8_t recv_buf[16] = { 0U };
    size_t out_len = 0U;
    static const uint8_t ping_payload[H2_PING_PAYLOAD_LEN] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    static const uint8_t grpc_payload[5 + 2] = { 0x00U, 0x00U, 0x00U, 0x00U, 0x02U, 0xAAU, 0xBBU };

    (void)params;
    TEST_ASSERT(grpc_setup_ready_transport(&tls, &t));

    queue_frame(H2_PING_PAYLOAD_LEN, H2_TYPE_PING, 0x00U, 0U, ping_payload);
    queue_frame((uint32_t)sizeof(grpc_payload), H2_TYPE_DATA, H2_FLAG_END_STREAM, 1U, grpc_payload);

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, t.recv(&t, recv_buf, sizeof(recv_buf), &out_len));
    TEST_ASSERT_EQUAL(2U, out_len);

    if (t.deinit != NULL) {
        t.deinit(&t);
    }
    el2go_ota_tls_deinit(tls);
    return true;
}

/**
 * @brief Verify grpc recv window update then data.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_grpc_recv_window_update_then_data(void *params)
{
    el2go_ota_tls_ctx_t *tls = NULL;
    el2go_ota_transport_t t;
    uint8_t recv_buf[16] = { 0U };
    size_t out_len = 0U;
    static const uint8_t window_payload[4] = { 0x00U, 0x00U, 0xFFU, 0xFFU };
    static const uint8_t grpc_payload[5 + 1] = { 0x00U, 0x00U, 0x00U, 0x00U, 0x01U, 0xCCU };

    (void)params;
    TEST_ASSERT(grpc_setup_ready_transport(&tls, &t));

    queue_frame(4U, H2_TYPE_WINDOW_UPDATE, 0x00U, 0U, window_payload);
    queue_frame((uint32_t)sizeof(grpc_payload), H2_TYPE_DATA, H2_FLAG_END_STREAM, 1U, grpc_payload);

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, t.recv(&t, recv_buf, sizeof(recv_buf), &out_len));
    TEST_ASSERT_EQUAL(1U, out_len);

    if (t.deinit != NULL) {
        t.deinit(&t);
    }
    el2go_ota_tls_deinit(tls);
    return true;
}

/**
 * @brief Verify grpc recv rst stream.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_grpc_recv_rst_stream(void *params)
{
    el2go_ota_tls_ctx_t *tls = NULL;
    el2go_ota_transport_t t;
    uint8_t recv_buf[16] = { 0U };
    size_t out_len = 0U;
    static const uint8_t rst_payload[4] = { 0x00U, 0x00U, 0x00U, 0x08U }; /* CANCEL */

    (void)params;
    TEST_ASSERT(grpc_setup_ready_transport(&tls, &t));

    queue_frame(4U, H2_TYPE_RST_STREAM, 0x00U, 1U, rst_payload);

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_NETWORK, t.recv(&t, recv_buf, sizeof(recv_buf), &out_len));

    if (t.deinit != NULL) {
        t.deinit(&t);
    }
    el2go_ota_tls_deinit(tls);
    return true;
}

/**
 * @brief Verify grpc recv goaway.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_grpc_recv_goaway(void *params)
{
    el2go_ota_tls_ctx_t *tls = NULL;
    el2go_ota_transport_t t;
    uint8_t recv_buf[16] = { 0U };
    size_t out_len = 0U;
    static const uint8_t goaway_payload[8] = { 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U };

    (void)params;
    TEST_ASSERT(grpc_setup_ready_transport(&tls, &t));

    queue_frame(8U, H2_TYPE_GOAWAY, 0x00U, 0U, goaway_payload);

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_NETWORK, t.recv(&t, recv_buf, sizeof(recv_buf), &out_len));

    if (t.deinit != NULL) {
        t.deinit(&t);
    }
    el2go_ota_tls_deinit(tls);
    return true;
}

/**
 * @brief Verify grpc recv data with padding.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_grpc_recv_data_with_padding(void *params)
{
    el2go_ota_tls_ctx_t *tls = NULL;
    el2go_ota_transport_t t;
    uint8_t recv_buf[16] = { 0U };
    size_t out_len = 0U;
    /* 5-byte gRPC header + 2-byte message + 3 padding bytes = pay_len 10. */
    static const uint8_t padded_payload[5 + 2 + 3] = {
        0x00U, 0x00U, 0x00U, 0x00U, 0x02U, /* gRPC header: uncompressed, len=2 */
        0xDEU, 0xADU,                      /* message body */
        0x00U, 0x00U, 0x00U                /* padding */
    };

    (void)params;
    TEST_ASSERT(grpc_setup_ready_transport(&tls, &t));

    queue_frame((uint32_t)sizeof(padded_payload), H2_TYPE_DATA, H2_FLAG_END_STREAM, 1U,
                padded_payload);

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, t.recv(&t, recv_buf, sizeof(recv_buf), &out_len));
    TEST_ASSERT_EQUAL(2U, out_len);
    TEST_ASSERT_EQUAL(0xDEU, recv_buf[0]);
    TEST_ASSERT_EQUAL(0xADU, recv_buf[1]);

    if (t.deinit != NULL) {
        t.deinit(&t);
    }
    el2go_ota_tls_deinit(tls);
    return true;
}

/**
 * @brief Verify grpc recv headers before data.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_grpc_recv_headers_before_data(void *params)
{
    el2go_ota_tls_ctx_t *tls = NULL;
    el2go_ota_transport_t t;
    uint8_t recv_buf[16] = { 0U };
    size_t out_len = 0U;
    static const uint8_t headers_payload[3] = { 0x88U, 0x00U, 0x00U }; /* dummy HPACK bytes */
    static const uint8_t grpc_payload[5 + 1] = { 0x00U, 0x00U, 0x00U, 0x00U, 0x01U, 0x42U };

    (void)params;
    TEST_ASSERT(grpc_setup_ready_transport(&tls, &t));

    /* Response HEADERS without END_STREAM -- must be drained, not parsed as trailers. */
    queue_frame(3U, H2_TYPE_HEADERS, 0x00U, 1U, headers_payload);
    queue_frame((uint32_t)sizeof(grpc_payload), H2_TYPE_DATA, H2_FLAG_END_STREAM, 1U, grpc_payload);

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, t.recv(&t, recv_buf, sizeof(recv_buf), &out_len));
    TEST_ASSERT_EQUAL(1U, out_len);

    if (t.deinit != NULL) {
        t.deinit(&t);
    }
    el2go_ota_tls_deinit(tls);
    return true;
}

/**
 * @brief Verify grpc recv trailer nonzero status.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_grpc_recv_trailer_nonzero_status(void *params)
{
    el2go_ota_tls_ctx_t *tls = NULL;
    el2go_ota_transport_t t;
    uint8_t recv_buf[16] = { 0U };
    size_t out_len = 0U;
    /* DATA without END_STREAM (trailers follow separately). */
    static const uint8_t grpc_payload[5 + 1] = { 0x00U, 0x00U, 0x00U, 0x00U, 0x01U, 0x7FU };
    /* HPACK trailer block: "grpc-status" literal, value "5" (NOT_FOUND). */
    static const uint8_t trailer_block[] = { 0x0BU, 'g', 'r', 'p', 'c', '-',   's',
                                             't',   'a', 't', 'u', 's', 0x01U, '5' };

    (void)params;
    TEST_ASSERT(grpc_setup_ready_transport(&tls, &t));

    queue_frame((uint32_t)sizeof(grpc_payload), H2_TYPE_DATA, 0x00U, 1U, grpc_payload);
    queue_frame((uint32_t)sizeof(trailer_block), H2_TYPE_HEADERS, H2_FLAG_END_STREAM, 1U,
                trailer_block);

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_SERVER, t.recv(&t, recv_buf, sizeof(recv_buf), &out_len));
    /* The DATA payload before the trailers should still have been captured. */
    TEST_ASSERT_EQUAL(1U, out_len);

    if (t.deinit != NULL) {
        t.deinit(&t);
    }
    el2go_ota_tls_deinit(tls);
    return true;
}

/**
 * @brief Verify grpc recv frame limit exceeded.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_grpc_recv_frame_limit_exceeded(void *params)
{
    el2go_ota_tls_ctx_t *tls = NULL;
    el2go_ota_transport_t t;
    uint8_t recv_buf[16] = { 0U };
    size_t out_len = 0U;
    static const uint8_t window_payload[4] = { 0x00U, 0x00U, 0x00U, 0x01U };
    unsigned int i = 0U;

    (void)params;
    TEST_ASSERT(grpc_setup_ready_transport(&tls, &t));

    /* GRPC_RECV_MAX_FRAMES is 64; queue more than that many harmless
     * WINDOW_UPDATE frames so the loop exhausts its iteration budget. */
    for (i = 0U; i < 70U; i++) {
        queue_frame(4U, H2_TYPE_WINDOW_UPDATE, 0x00U, 1U, window_payload);
    }

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_NETWORK, t.recv(&t, recv_buf, sizeof(recv_buf), &out_len));

    if (t.deinit != NULL) {
        t.deinit(&t);
    }
    el2go_ota_tls_deinit(tls);
    return true;
}

/**
 * @brief Verify grpc send handshake with ping.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_grpc_send_handshake_with_ping(void *params)
{
    el2go_ota_tls_ctx_t *tls = NULL;
    el2go_ota_mtls_config_t cfg = grpc_make_cfg();
    el2go_ota_transport_t t;
    static const uint8_t msg[1] = { 0x01U };
    static const uint8_t ping_payload[H2_PING_PAYLOAD_LEN] = { 9, 8, 7, 6, 5, 4, 3, 2 };

    (void)params;
    memset(&t, 0, sizeof(t));
    grpc_reset_wraps();

    TEST_ASSERT_EQUAL(EL2GO_STATUS_SUCCESS, el2go_ota_tls_init(&tls, grpc_get_pctx(), &cfg));
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      test_shadow_el2go_ota_transport_init(&t, tls, cfg.hostname));

    /* Server sends a PING before its SETTINGS during the handshake. */
    queue_frame(H2_PING_PAYLOAD_LEN, H2_TYPE_PING, 0x00U, 0U, ping_payload);
    queue_frame(0U, H2_TYPE_SETTINGS, 0x00U, 0U, NULL);

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, t.send(&t, "/pkg.Svc/Method", msg, sizeof(msg)));

    if (t.deinit != NULL) {
        t.deinit(&t);
    }
    el2go_ota_tls_deinit(tls);
    return true;
}

/* ---- suite registration ------------------------------------------------ */

void register_ota_lib_grpc_tests(void)
{
    TEST_REGISTER_ID_WITH_PARAMS("-", test_ota_grpc_parse_trailers_status_ok, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("-", test_ota_grpc_parse_trailers_status_nonzero, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("-", test_ota_grpc_parse_trailers_not_found, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("-", test_ota_grpc_parse_trailers_null_block, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("-", test_ota_grpc_parse_trailers_too_short, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("-", test_ota_grpc_status, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("-", test_ota_h2_build_frame_hdr_layout, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("-", test_ota_hpack_put_string_buffer_too_small, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("-", test_ota_hpack_put_string_len_too_large, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("-", test_ota_grpc_parse_trailers_status_all_codes, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("-", test_ota_grpc_parse_trailers_truncated_value, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("-", test_ota_grpc_parse_trailers_non_digit_value, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("-", test_ota_grpc_parse_trailers_overflow_guard, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("-", test_ota_grpc_parse_trailers_val_start_beyond_block, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("-", test_ota_hpack_encode_grpc_request_success, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("-", test_ota_hpack_encode_grpc_request_buffer_too_small, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("-", test_ota_grpc_send_null_params, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("-", test_ota_grpc_recv_null_params, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("-", test_ota_grpc_roundtrip_send_recv_success, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("-", test_ota_grpc_send_preface_write_fail, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("-", test_ota_grpc_recv_ping_then_data, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("-", test_ota_grpc_recv_window_update_then_data, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("-", test_ota_grpc_recv_rst_stream, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("-", test_ota_grpc_recv_goaway, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("-", test_ota_grpc_recv_data_with_padding, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("-", test_ota_grpc_recv_headers_before_data, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("-", test_ota_grpc_recv_trailer_nonzero_status, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("-", test_ota_grpc_recv_frame_limit_exceeded, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("-", test_ota_grpc_send_handshake_with_ping, NULL);
}
