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

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, grpc_parse_trailers(block, sizeof(block), NULL));
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

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_SERVER, grpc_parse_trailers(block, sizeof(block), NULL));
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

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, grpc_parse_trailers(block, sizeof(block), NULL));
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
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, grpc_parse_trailers(NULL, 0U, NULL));
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

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, grpc_parse_trailers(block, sizeof(block), NULL));
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

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_SERVER,
                      grpc_parse_trailers(block_10, sizeof(block_10), NULL));
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_SERVER,
                      grpc_parse_trailers(block_16, sizeof(block_16), NULL));
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

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, grpc_parse_trailers(block, sizeof(block), NULL));
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

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, grpc_parse_trailers(block, sizeof(block), NULL));
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

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_SERVER, grpc_parse_trailers(block, sizeof(block), NULL));
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

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, grpc_parse_trailers(block, sizeof(block), NULL));
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
    /* mTLS is mandatory: client credentials must be present in the keystore. */
    g_wrap_psa_its_get_info_rc = PSA_SUCCESS;
    g_wrap_psa_its_get_rc = PSA_SUCCESS;
    g_wrap_psa_its_cert_size = 16U;
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

/* RFC 7540 S6.10 CONTINUATION frame type. Defined locally (rather than
 * depending on the eventual production H2_TYPE_CONTINUATION macro) so
 * these test-only byte-stream scenarios build and fail meaningfully even
 * before the source change that adds real CONTINUATION support lands. */
#define TEST_H2_TYPE_CONTINUATION 0x09U

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

    /* Response HEADERS without END_STREAM -- must be drained, not parsed as
     * trailers. END_HEADERS is set because this is a single, complete,
     * non-split header block (this test is about the Response-Headers vs.
     * Trailers distinction, not about CONTINUATION reassembly -- that is
     * covered separately by the dedicated split-block tests 14.38-14.42). */
    queue_frame(3U, H2_TYPE_HEADERS, H2_FLAG_END_HEADERS, 1U, headers_payload);
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
    /* END_HEADERS is set because this trailer block is a single, complete,
     * non-split header block (this test is about nonzero grpc-status
     * classification, not about CONTINUATION reassembly -- that is covered
     * separately by the dedicated split-block tests 14.38-14.42). */
    queue_frame((uint32_t)sizeof(trailer_block), H2_TYPE_HEADERS,
                H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM, 1U, trailer_block);

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

/*
 * Perform one send()/recv() round trip on an already-initialised,
 * already-handshaken transport, queuing a Trailers-Only response (no DATA
 * frame) whose HPACK block is exactly @p trailer_block / @p trailer_block_len.
 * Returns the status from recv().
 */
static el2go_ota_status_t grpc_do_trailers_only_round(el2go_ota_transport_t *t, uint32_t stream_id,
                                                      const uint8_t *trailer_block,
                                                      size_t trailer_block_len)
{
    static const uint8_t msg[1] = { 0x01U };
    uint8_t recv_buf[16] = { 0U };
    size_t out_len = 0U;
    el2go_ota_status_t status;

    status = t->send(t, "/pkg.Svc/Method", msg, sizeof(msg));
    if (status != EL2GO_OTA_SUCCESS) {
        return status;
    }
    queue_frame((uint32_t)trailer_block_len, H2_TYPE_HEADERS,
                H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM, stream_id, trailer_block);
    return t->recv(t, recv_buf, sizeof(recv_buf), &out_len);
}

/**
 * @brief Verify that a dynamic-table indexed back-reference to grpc-status
 * is correctly resolved on a reused connection, even when grpc-message was
 * also inserted into the dynamic table immediately after grpc-status in
 * the same Trailers block (the exact scenario from the live device log
 * that originally caused this to be silently misreported as SUCCESS).
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_grpc_recv_trailer_dyn_table_reuse_detects_error(void *params)
{
    el2go_ota_tls_ctx_t *tls = NULL;
    el2go_ota_transport_t t;
    /*
     * Round 1: grpc-status: 7 and grpc-message: "Invalid device!", both
     * literal-with-incremental-indexing (0x40 prefix), name+value
     * Huffman-encoded -- matches the real EL2GO OTA server / Envoy wire
     * format confirmed from live device log captures. Insertion order:
     * grpc-status first (dynamic idx 62 at insertion time), then
     * grpc-message (pushes grpc-status to idx 63, grpc-message is idx 62).
     * Generated and cross-checked with Python hpack==4.2.0
     * HuffmanEncoder(REQUEST_CODES, REQUEST_CODES_LENGTH).
     */
    static const uint8_t trailer_round1[] = {
        0x40U, 0x88U, 0x9AU, 0xCAU, 0xC8U, 0xB2U, 0x12U, 0x34U, 0xDAU, 0x8FU, 0x81U, 0x77U,
        0x40U, 0x89U, 0x9AU, 0xCAU, 0xC8U, 0xB5U, 0x25U, 0x42U, 0x07U, 0x31U, 0x7FU, 0x8CU,
        0xC9U, 0x57U, 0x71U, 0xD0U, 0x69U, 0x14U, 0x90U, 0xBDU, 0xCCU, 0x42U, 0xFFU, 0x1FU
    };
    /*
     * Round 2 (same connection, new stream): pure indexed back-references,
     * zero literal bytes -- 0xBF = 0x80|63 (grpc-status), 0xBE = 0x80|62
     * (grpc-message). This is the exact wire pattern from the live device
     * log ("88 c3 c2 c1 ..." style trailer) that was previously silently
     * misreported as EL2GO_OTA_SUCCESS due to the insertion-count desync
     * bug (grpc-message's insertion was never counted because
     * hpack_find_grpc_status_fallback() returned immediately after
     * resolving grpc-status, before reaching grpc-message in the same
     * round-1 block).
     */
    static const uint8_t trailer_round2[] = { 0xBFU, 0xBEU };

    (void)params;
    TEST_ASSERT(grpc_setup_ready_transport(&tls, &t));

    /* Round 1: literal grpc-status: 7 -- establishes the dynamic-table
     * mirror and must itself be correctly classified as an error. */
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_SERVER,
                      grpc_do_trailers_only_round(&t, 3U, trailer_round1, sizeof(trailer_round1)));

    /* Round 2: pure indexed back-references to the same grpc-status: 7 /
     * grpc-message. Must still resolve to ERROR_SERVER, not silently
     * fall through to SUCCESS. */
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_SERVER,
                      grpc_do_trailers_only_round(&t, 5U, trailer_round2, sizeof(trailer_round2)));

    if (t.deinit != NULL) {
        t.deinit(&t);
    }
    el2go_ota_tls_deinit(tls);
    return true;
}

/**
 * @brief False-positive check: a dynamic-table indexed back-reference to a
 * genuinely successful grpc-status: 0 must still resolve to SUCCESS on a
 * reused connection -- the insertion-tracking fix must not turn a correct
 * "OK" indexed reference into an incorrectly reported error.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_grpc_recv_trailer_dyn_table_reuse_no_false_positive(void *params)
{
    el2go_ota_tls_ctx_t *tls = NULL;
    el2go_ota_transport_t t;
    /* Round 1: grpc-status: 0, literal with incremental indexing, Huffman
     * name+value. Single insertion (dynamic idx 62). */
    static const uint8_t trailer_round1[] = { 0x40U, 0x88U, 0x9AU, 0xCAU, 0xC8U, 0xB2U,
                                              0x12U, 0x34U, 0xDAU, 0x8FU, 0x81U, 0x07U };
    /* Round 2: pure indexed back-reference to grpc-status: 0 (0xBE = 0x80|62). */
    static const uint8_t trailer_round2[] = { 0xBEU };

    (void)params;
    TEST_ASSERT(grpc_setup_ready_transport(&tls, &t));

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      grpc_do_trailers_only_round(&t, 3U, trailer_round1, sizeof(trailer_round1)));
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      grpc_do_trailers_only_round(&t, 5U, trailer_round2, sizeof(trailer_round2)));

    if (t.deinit != NULL) {
        t.deinit(&t);
    }
    el2go_ota_tls_deinit(tls);
    return true;
}

/**
 * @brief Verify the dynamic-table mirror stays correctly synchronized
 * across more than one subsequent call on the same connection (not just a
 * one-shot fix that only happens to work for the second call).
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_grpc_recv_trailer_dyn_table_reuse_three_rounds(void *params)
{
    el2go_ota_tls_ctx_t *tls = NULL;
    el2go_ota_transport_t t;
    static const uint8_t trailer_round1[] = {
        0x40U, 0x88U, 0x9AU, 0xCAU, 0xC8U, 0xB2U, 0x12U, 0x34U, 0xDAU, 0x8FU, 0x81U, 0x77U,
        0x40U, 0x89U, 0x9AU, 0xCAU, 0xC8U, 0xB5U, 0x25U, 0x42U, 0x07U, 0x31U, 0x7FU, 0x8CU,
        0xC9U, 0x57U, 0x71U, 0xD0U, 0x69U, 0x14U, 0x90U, 0xBDU, 0xCCU, 0x42U, 0xFFU, 0x1FU
    };
    static const uint8_t trailer_indexed[] = { 0xBFU, 0xBEU };

    (void)params;
    TEST_ASSERT(grpc_setup_ready_transport(&tls, &t));

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_SERVER,
                      grpc_do_trailers_only_round(&t, 3U, trailer_round1, sizeof(trailer_round1)));
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_SERVER, grpc_do_trailers_only_round(&t, 5U, trailer_indexed,
                                                                          sizeof(trailer_indexed)));
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_SERVER, grpc_do_trailers_only_round(&t, 7U, trailer_indexed,
                                                                          sizeof(trailer_indexed)));

    if (t.deinit != NULL) {
        t.deinit(&t);
    }
    el2go_ota_tls_deinit(tls);
    return true;
}

/**
 * @brief Verify a server SETTINGS frame carrying MAX_FRAME_SIZE above the
 * protocol default is parsed correctly during the initial handshake, and
 * the handshake still completes normally (diagnostic-only: no behavior
 * change to send()).
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_grpc_handshake_settings_max_frame_size_parsed(void *params)
{
    el2go_ota_tls_ctx_t *tls = NULL;
    el2go_ota_mtls_config_t cfg = grpc_make_cfg();
    el2go_ota_transport_t t;
    static const uint8_t msg[1] = { 0x01U };
    /* One SETTINGS parameter: MAX_FRAME_SIZE (0x0005) = 32768 (0x00008000). */
    static const uint8_t settings_payload[6] = { 0x00U, 0x05U, 0x00U, 0x00U, 0x80U, 0x00U };

    (void)params;
    memset(&t, 0, sizeof(t));
    grpc_reset_wraps();

    TEST_ASSERT_EQUAL(EL2GO_STATUS_SUCCESS, el2go_ota_tls_init(&tls, grpc_get_pctx(), &cfg));
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      test_shadow_el2go_ota_transport_init(&t, tls, cfg.hostname));

    queue_frame((uint32_t)sizeof(settings_payload), H2_TYPE_SETTINGS, 0x00U, 0U, settings_payload);

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, t.send(&t, "/pkg.Svc/Method", msg, sizeof(msg)));
    TEST_ASSERT_EQUAL(32768U, ((grpc_ctx_t *)t.impl_ctx)->server_max_frame_size);

    if (t.deinit != NULL) {
        t.deinit(&t);
    }
    el2go_ota_tls_deinit(tls);
    return true;
}

/**
 * @brief Verify a SETTINGS frame with multiple parameters (not just
 * MAX_FRAME_SIZE) is still parsed correctly and the right parameter is
 * picked out -- confirms the 6-byte-per-parameter walk does not desync on
 * a multi-parameter frame.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_grpc_handshake_settings_multi_param(void *params)
{
    el2go_ota_tls_ctx_t *tls = NULL;
    el2go_ota_mtls_config_t cfg = grpc_make_cfg();
    el2go_ota_transport_t t;
    static const uint8_t msg[1] = { 0x01U };
    /*
     * Three parameters, 18 bytes total:
     *   HEADER_TABLE_SIZE (0x0001) = 4096  (0x00001000) -- ignored by this helper
     *   MAX_FRAME_SIZE    (0x0005) = 20000 (0x00004E20)
     *   MAX_CONCURRENT_STREAMS (0x0003) = 100 (0x00000064) -- ignored by this helper
     */
    static const uint8_t settings_payload[18] = { 0x00U, 0x01U, 0x00U, 0x00U, 0x10U, 0x00U,
                                                  0x00U, 0x05U, 0x00U, 0x00U, 0x4EU, 0x20U,
                                                  0x00U, 0x03U, 0x00U, 0x00U, 0x00U, 0x64U };

    (void)params;
    memset(&t, 0, sizeof(t));
    grpc_reset_wraps();

    TEST_ASSERT_EQUAL(EL2GO_STATUS_SUCCESS, el2go_ota_tls_init(&tls, grpc_get_pctx(), &cfg));
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      test_shadow_el2go_ota_transport_init(&t, tls, cfg.hostname));

    queue_frame((uint32_t)sizeof(settings_payload), H2_TYPE_SETTINGS, 0x00U, 0U, settings_payload);

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, t.send(&t, "/pkg.Svc/Method", msg, sizeof(msg)));
    TEST_ASSERT_EQUAL(20000U, ((grpc_ctx_t *)t.impl_ctx)->server_max_frame_size);

    if (t.deinit != NULL) {
        t.deinit(&t);
    }
    el2go_ota_tls_deinit(tls);
    return true;
}

/**
 * @brief Verify a malformed SETTINGS frame whose payload length is not a
 * multiple of 6 (RFC 7540 S6.5 requires it to be) does not desync the
 * connection -- the trailing partial bytes must still be drained, and a
 * subsequent frame on the connection must still be read correctly.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_grpc_handshake_settings_malformed_length_no_desync(void *params)
{
    el2go_ota_tls_ctx_t *tls = NULL;
    el2go_ota_mtls_config_t cfg = grpc_make_cfg();
    el2go_ota_transport_t t;
    static const uint8_t msg[3] = { 0xAAU, 0xBBU, 0xCCU };
    /* 8 bytes: one full 6-byte parameter (MAX_FRAME_SIZE=20000) plus 2
     * trailing bytes that do not form a complete parameter. */
    static const uint8_t settings_payload[8] = { 0x00U, 0x05U, 0x00U, 0x00U,
                                                 0x4EU, 0x20U, 0xFFU, 0xFFU };
    uint8_t recv_buf[16] = { 0U };
    size_t out_len = 0U;
    static const uint8_t grpc_payload[5 + 3] = { 0x00U, 0x00U, 0x00U, 0x00U,
                                                 0x03U, 0xAAU, 0xBBU, 0xCCU };

    (void)params;
    memset(&t, 0, sizeof(t));
    grpc_reset_wraps();

    TEST_ASSERT_EQUAL(EL2GO_STATUS_SUCCESS, el2go_ota_tls_init(&tls, grpc_get_pctx(), &cfg));
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      test_shadow_el2go_ota_transport_init(&t, tls, cfg.hostname));

    queue_frame((uint32_t)sizeof(settings_payload), H2_TYPE_SETTINGS, 0x00U, 0U, settings_payload);

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, t.send(&t, "/pkg.Svc/Method", msg, sizeof(msg)));
    TEST_ASSERT_EQUAL(20000U, ((grpc_ctx_t *)t.impl_ctx)->server_max_frame_size);

    /* Connection must still be correctly aligned -- queue and successfully
     * receive a normal response DATA frame after the malformed SETTINGS. */
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
 * @brief Verify a non-compliant server advertising MAX_FRAME_SIZE below
 * the RFC 7540 S6.5.2 floor (16384) is logged but does not cause any
 * error or behavior change -- diagnostic only.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_grpc_handshake_settings_max_frame_size_below_floor(void *params)
{
    el2go_ota_tls_ctx_t *tls = NULL;
    el2go_ota_mtls_config_t cfg = grpc_make_cfg();
    el2go_ota_transport_t t;
    static const uint8_t msg[1] = { 0x01U };
    /* MAX_FRAME_SIZE = 1000 (0x000003E8) -- non-compliant (below 16384). */
    static const uint8_t settings_payload[6] = { 0x00U, 0x05U, 0x00U, 0x00U, 0x03U, 0xE8U };

    (void)params;
    memset(&t, 0, sizeof(t));
    grpc_reset_wraps();

    TEST_ASSERT_EQUAL(EL2GO_STATUS_SUCCESS, el2go_ota_tls_init(&tls, grpc_get_pctx(), &cfg));
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      test_shadow_el2go_ota_transport_init(&t, tls, cfg.hostname));

    queue_frame((uint32_t)sizeof(settings_payload), H2_TYPE_SETTINGS, 0x00U, 0U, settings_payload);

    /* Must still succeed -- this is diagnostic-only, never a hard failure. */
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, t.send(&t, "/pkg.Svc/Method", msg, sizeof(msg)));
    TEST_ASSERT_EQUAL(1000U, ((grpc_ctx_t *)t.impl_ctx)->server_max_frame_size);

    if (t.deinit != NULL) {
        t.deinit(&t);
    }
    el2go_ota_tls_deinit(tls);
    return true;
}

/**
 * @brief Verify a server-initiated SETTINGS frame received during
 * steady-state grpc_recv() (not just the initial handshake) is also
 * parsed via the shared helper and does not disrupt an in-progress
 * response.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_grpc_recv_settings_max_frame_size_steady_state(void *params)
{
    el2go_ota_tls_ctx_t *tls = NULL;
    el2go_ota_transport_t t;
    uint8_t recv_buf[16] = { 0U };
    size_t out_len = 0U;
    static const uint8_t settings_payload[6] = { 0x00U, 0x05U, 0x00U, 0x00U, 0x4EU, 0x20U };
    static const uint8_t grpc_payload[5 + 2] = { 0x00U, 0x00U, 0x00U, 0x00U, 0x02U, 0xAAU, 0xBBU };

    (void)params;
    TEST_ASSERT(grpc_setup_ready_transport(&tls, &t));

    /* Server re-sends SETTINGS mid-connection (RFC 7540 S6.5 permits this
     * at any time), then the actual response DATA frame. */
    queue_frame((uint32_t)sizeof(settings_payload), H2_TYPE_SETTINGS, 0x00U, 0U, settings_payload);
    queue_frame((uint32_t)sizeof(grpc_payload), H2_TYPE_DATA, H2_FLAG_END_STREAM, 1U, grpc_payload);

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, t.recv(&t, recv_buf, sizeof(recv_buf), &out_len));
    TEST_ASSERT_EQUAL(2U, out_len);
    TEST_ASSERT_EQUAL(20000U, ((grpc_ctx_t *)t.impl_ctx)->server_max_frame_size);

    if (t.deinit != NULL) {
        t.deinit(&t);
    }
    el2go_ota_tls_deinit(tls);
    return true;
}

/**
 * @brief Baseline CONTINUATION scenario: a Trailers-Only block containing
 * ONLY the grpc-status field (Huffman-encoded "grpc-status": 7
 * PERMISSION_DENIED, the same wire bytes verified elsewhere in this file
 * for the dynamic-table reuse tests) is split into a HEADERS frame
 * (END_STREAM set, END_HEADERS NOT set) carrying only the first 4 of its
 * 12 bytes, and a CONTINUATION frame (END_HEADERS set) carrying the
 * remaining 8 bytes. The split lands inside the Huffman-coded
 * "grpc-status" NAME bytes themselves (which span bytes 2-9), well before
 * the field is fully decodable.
 *
 * Hand-verified pre-fix behavior: current code ignores END_HEADERS and
 * parses only the first HEADERS frame's 4 bytes as if that were the
 * complete block. hpack_decode_string_bounded() fails when it discovers
 * the Huffman name string (declared length 8) does not fit in the
 * remaining 2 bytes of this 4-byte fragment -- returns false (truncated).
 * Since nothing was found yet (found == false), hpack_find_grpc_status_
 * fallback() returns false ("not found"), so grpc_parse_trailers()
 * reports EL2GO_OTA_SUCCESS. Pre-fix result: EL2GO_OTA_SUCCESS (0) --
 * silently wrong, the real data is grpc-status: 7, an error. This test
 * asserts EL2GO_OTA_ERROR_SERVER, so it FAILS pre-fix with a clean
 * "Expected 10, got 0".
 *
 * Expected POST-FIX (Step 2): full reassembly correctly decodes
 * grpc-status: 7 -> EL2GO_OTA_ERROR_SERVER.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_grpc_recv_trailers_split_continuation_basic(void *params)
{
    el2go_ota_tls_ctx_t *tls = NULL;
    el2go_ota_transport_t t;
    uint8_t recv_buf[16] = { 0U };
    size_t out_len = 0U;
    el2go_ota_status_t result = EL2GO_OTA_ERROR_INTERNAL;
    /* Standalone grpc-status: 7 (PERMISSION_DENIED) field, Huffman name +
     * Huffman value, literal with incremental indexing -- 12 bytes total.
     * Same byte pattern verified elsewhere in this file (first 12 bytes of
     * the dynamic-table reuse tests' trailer_round1). Split after byte 3
     * (4-byte first fragment), landing inside the 8-byte Huffman name
     * (bytes 2-9) -- well before the name, let alone the value, can be
     * decoded. */
    static const uint8_t full_field[12] = { 0x40U, 0x88U, 0x9AU, 0xCAU, 0xC8U, 0xB2U,
                                            0x12U, 0x34U, 0xDAU, 0x8FU, 0x81U, 0x77U };

    (void)params;
    TEST_ASSERT(grpc_setup_ready_transport(&tls, &t));

    /* HEADERS: END_STREAM set (Trailers-Only, no prior DATA), END_HEADERS
     * NOT set -- only the first 4 of 12 bytes. */
    queue_frame(4U, H2_TYPE_HEADERS, H2_FLAG_END_STREAM, 1U, full_field);
    /* CONTINUATION: the remaining 8 bytes, completing the block. */
    queue_frame(8U, TEST_H2_TYPE_CONTINUATION, H2_FLAG_END_HEADERS, 1U, &full_field[4]);

    result = t.recv(&t, recv_buf, sizeof(recv_buf), &out_len);
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_SERVER, result);

    if (t.deinit != NULL) {
        t.deinit(&t);
    }
    el2go_ota_tls_deinit(tls);
    return true;
}

/**
 * @brief Response-Headers (no END_STREAM) split across HEADERS +
 * CONTINUATION, where the split lands inside the VALUE bytes of a literal
 * ":status" header carrying a non-200 code ("500", plain ASCII digits,
 * non-Huffman). Confirms the Response-Headers path
 * (hpack_validate_response_headers()) must also reassemble split blocks --
 * and demonstrates a concrete, security-relevant consequence of not doing
 * so: an HTTP-level 500 (e.g. from a misbehaving proxy) gets silently
 * treated as a successful response instead of being rejected.
 *
 * Field layout (13 bytes): byte0=0x40 (literal+incr-idx, literal name),
 * byte1=0x07 (name length=7, non-Huffman), bytes2-8=":status" (7 bytes),
 * byte9=0x03 (value length=3, non-Huffman), bytes10-12="500".
 *
 * Hand-verified pre-fix behavior: first fragment = bytes 0-10 (11 bytes,
 * through the first value digit '5'). hpack_validate_response_headers()
 * decodes the name ":status" fully (fits in 11 bytes), then calls
 * hpack_decode_string_bounded() for the value: it reads the length byte
 * (3) at pos 9, advancing pos to 10, then checks "str_len(3) >
 * block_len(11) - pos(10) = 1" -- true, so it returns false (truncated).
 * The validator's is_status branch treats this as "continue" (cannot
 * determine, keep scanning) WITHOUT re-advancing pos past the integer it
 * already consumed. The next loop iteration reads block[10] = '5' (0x35)
 * as if it were a fresh header's first byte, decodes it as an indexed
 * name reference (prefix_bits=4, name_idx=5, non-zero so NOT literal),
 * finds neither :status nor content-type, and calls hpack_skip_string()
 * at pos=11 which immediately fails (pos >= block_len) -- the overall
 * function then returns true (fail-open, "no explicit non-200 :status
 * found"). Pre-fix, grpc_recv() therefore treats this truncated,
 * ambiguous block as a valid 200 response, continues its frame loop,
 * drains the CONTINUATION frame (default: case, by declared length,
 * frame-header alignment preserved), and successfully reads the
 * subsequent DATA+END_STREAM frame -- returning EL2GO_OTA_SUCCESS with
 * out_len=1 and recv_buf[0]=0x42, as if the call had fully succeeded.
 * This test asserts EL2GO_OTA_ERROR_NETWORK, so it FAILS pre-fix with
 * "Expected 4, got 0" -- and the real pre-fix danger is not a crash or a
 * wrong error code, but a silently fabricated success.
 *
 * Expected POST-FIX (Step 2): the full 13-byte block is reassembled
 * before validation; code=500 is correctly decoded and is non-200, so
 * hpack_validate_response_headers() returns false and grpc_recv() returns
 * EL2GO_OTA_ERROR_NETWORK immediately, never reaching the DATA frame.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_grpc_recv_response_headers_split_continuation(void *params)
{
    el2go_ota_tls_ctx_t *tls = NULL;
    el2go_ota_transport_t t;
    uint8_t recv_buf[16] = { 0U };
    size_t out_len = 0U;
    el2go_ota_status_t result = EL2GO_OTA_ERROR_INTERNAL;
    static const uint8_t full_field[13] = { 0x40U, 0x07U, ':',   's', 't', 'a', 't',
                                            'u',   's',   0x03U, '5', '0', '0' };
    static const uint8_t grpc_payload[5 + 1] = { 0x00U, 0x00U, 0x00U, 0x00U, 0x01U, 0x42U };

    (void)params;
    TEST_ASSERT(grpc_setup_ready_transport(&tls, &t));

    /* Response-Headers: no END_STREAM, no END_HEADERS -- first 11 of 13 bytes. */
    queue_frame(11U, H2_TYPE_HEADERS, 0x00U, 1U, full_field);
    /* CONTINUATION: remaining 2 bytes. */
    queue_frame(2U, TEST_H2_TYPE_CONTINUATION, H2_FLAG_END_HEADERS, 1U, &full_field[11]);
    queue_frame((uint32_t)sizeof(grpc_payload), H2_TYPE_DATA, H2_FLAG_END_STREAM, 1U, grpc_payload);

    result = t.recv(&t, recv_buf, sizeof(recv_buf), &out_len);
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_NETWORK, result);

    if (t.deinit != NULL) {
        t.deinit(&t);
    }
    el2go_ota_tls_deinit(tls);
    return true;
}

/**
 * @brief Worst-case split on the real two-field (grpc-status + grpc-
 * message) live-device-log wire bytes: the break point lands inside the
 * grpc-status NAME's Huffman bytes (same field span as the basic test,
 * different offset, and this time on the full multi-field block instead
 * of a standalone single-field one) to confirm multi-field reassembly,
 * not just single-field.
 *
 * Hand-verified pre-fix behavior: first fragment = bytes 0-6 (7 bytes).
 * Same failure mode as the basic test -- hpack_decode_string_bounded()
 * fails decoding the 8-byte Huffman name (only 5 bytes available after
 * the length byte), found stays false, fallback returns false, trailers
 * report EL2GO_OTA_SUCCESS. This test asserts EL2GO_OTA_ERROR_SERVER, so
 * it FAILS pre-fix with "Expected 10, got 0".
 *
 * Expected POST-FIX (Step 2): full reassembly of all 36 bytes correctly
 * decodes grpc-status: 7 (PERMISSION_DENIED) via the HPACK fallback.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_grpc_recv_trailers_split_mid_huffman_name(void *params)
{
    el2go_ota_tls_ctx_t *tls = NULL;
    el2go_ota_transport_t t;
    uint8_t recv_buf[16] = { 0U };
    size_t out_len = 0U;
    el2go_ota_status_t result = EL2GO_OTA_ERROR_INTERNAL;
    /* Same 36-byte wire bytes as the live-device-log grpc-status: 7 +
     * grpc-message: "Invalid device!" Trailers block used elsewhere in
     * this file. Split at offset 7 -- inside the grpc-status Huffman name
     * bytes (span 2-9), before the name (let alone the value) can be
     * decoded. */
    static const uint8_t full_block[36] = { 0x40U, 0x88U, 0x9AU, 0xCAU, 0xC8U, 0xB2U, 0x12U, 0x34U,
                                            0xDAU, 0x8FU, 0x81U, 0x77U, 0x40U, 0x89U, 0x9AU, 0xCAU,
                                            0xC8U, 0xB5U, 0x25U, 0x42U, 0x07U, 0x31U, 0x7FU, 0x8CU,
                                            0xC9U, 0x57U, 0x71U, 0xD0U, 0x69U, 0x14U, 0x90U, 0xBDU,
                                            0xCCU, 0x42U, 0xFFU, 0x1FU };

    (void)params;
    TEST_ASSERT(grpc_setup_ready_transport(&tls, &t));

    queue_frame(7U, H2_TYPE_HEADERS, H2_FLAG_END_STREAM, 1U, full_block);
    queue_frame(29U, TEST_H2_TYPE_CONTINUATION, H2_FLAG_END_HEADERS, 1U, &full_block[7]);

    result = t.recv(&t, recv_buf, sizeof(recv_buf), &out_len);
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_SERVER, result);

    if (t.deinit != NULL) {
        t.deinit(&t);
    }
    el2go_ota_tls_deinit(tls);
    return true;
}

/**
 * @brief Trailers split across THREE frames (HEADERS + CONTINUATION +
 * CONTINUATION) on the same 36-byte real two-field block -- confirms the
 * eventual accumulation loop is not hardcoded for exactly one
 * CONTINUATION. The first fragment (4 bytes) is deliberately far short of
 * the 12 bytes needed to fully decode grpc-status alone, so -- as with
 * the other split tests -- the pre-fix result cannot depend on how many
 * more fragments exist after the first one, since pre-fix code never
 * looks past the first HEADERS frame for an END_STREAM-flagged block.
 *
 * Hand-verified pre-fix behavior: identical failure mode to the basic
 * split test's 4-byte first fragment -- found stays false, fallback
 * returns false, EL2GO_OTA_SUCCESS. This test asserts
 * EL2GO_OTA_ERROR_SERVER, so it FAILS pre-fix with "Expected 10, got 0".
 *
 * Expected POST-FIX (Step 2): all three frames (4 + 16 + 16 = 36 bytes)
 * are accumulated before decoding, correctly finding grpc-status: 7.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_grpc_recv_trailers_split_three_frames(void *params)
{
    el2go_ota_tls_ctx_t *tls = NULL;
    el2go_ota_transport_t t;
    uint8_t recv_buf[16] = { 0U };
    size_t out_len = 0U;
    el2go_ota_status_t result = EL2GO_OTA_ERROR_INTERNAL;
    static const uint8_t full_block[36] = { 0x40U, 0x88U, 0x9AU, 0xCAU, 0xC8U, 0xB2U, 0x12U, 0x34U,
                                            0xDAU, 0x8FU, 0x81U, 0x77U, 0x40U, 0x89U, 0x9AU, 0xCAU,
                                            0xC8U, 0xB5U, 0x25U, 0x42U, 0x07U, 0x31U, 0x7FU, 0x8CU,
                                            0xC9U, 0x57U, 0x71U, 0xD0U, 0x69U, 0x14U, 0x90U, 0xBDU,
                                            0xCCU, 0x42U, 0xFFU, 0x1FU };

    (void)params;
    TEST_ASSERT(grpc_setup_ready_transport(&tls, &t));

    queue_frame(4U, H2_TYPE_HEADERS, H2_FLAG_END_STREAM, 1U, full_block);
    queue_frame(16U, TEST_H2_TYPE_CONTINUATION, 0x00U, 1U, &full_block[4]);
    queue_frame(16U, TEST_H2_TYPE_CONTINUATION, H2_FLAG_END_HEADERS, 1U, &full_block[20]);

    result = t.recv(&t, recv_buf, sizeof(recv_buf), &out_len);
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_SERVER, result);

    if (t.deinit != NULL) {
        t.deinit(&t);
    }
    el2go_ota_tls_deinit(tls);
    return true;
}

/**
 * @brief NEGATIVE test: a stray PING frame arrives between a HEADERS
 * frame (END_HEADERS NOT set) and its CONTINUATION. Per RFC 7540 S6.10,
 * once a HEADERS frame without END_HEADERS has been received, receiving
 * ANY other frame type before END_HEADERS is a connection-level
 * PROTOCOL_ERROR -- it must be explicitly rejected, not drained-and-
 * ignored (the fallback behavior used for every other out-of-order frame
 * in this file's recv() loop) and not silently skipped over while still
 * reassembling the header block around it.
 *
 * Hand-verified pre-fix behavior: current code has no concept of "waiting
 * for END_HEADERS" at all. Upon seeing this HEADERS frame (END_STREAM
 * set), it immediately parses only its first-4-of-12 bytes as the
 * complete Trailers block (same truncation failure mode as the basic
 * split test: found stays false -> EL2GO_OTA_SUCCESS) and returns
 * immediately via "return grpc_status;" -- it never even reads the queued
 * PING or CONTINUATION frames that follow. Pre-fix result:
 * EL2GO_OTA_SUCCESS (0). This test asserts EL2GO_OTA_ERROR_NETWORK, so it
 * FAILS pre-fix with "Expected 4, got 0".
 *
 * Expected POST-FIX (Step 2): the implementation waits for END_HEADERS,
 * sees the PING arrive first, and explicitly rejects it as
 * PROTOCOL_ERROR -> EL2GO_OTA_ERROR_NETWORK. This specific assertion
 * (ERROR_NETWORK, not ERROR_SERVER and not a crash) also guards against a
 * *naively* -correct-looking implementation that reassembles through the
 * PING as if it were just another frame to skip -- that would be its own
 * new bug (RFC 7540 S6.10 explicitly forbids this), and would likely
 * still resolve to ERROR_SERVER if it happened to find grpc-status: 7
 * anyway. Only an implementation that explicitly checks for and rejects
 * the interleaved PING satisfies this assertion.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_grpc_recv_continuation_interleaved_ping_rejected(void *params)
{
    el2go_ota_tls_ctx_t *tls = NULL;
    el2go_ota_transport_t t;
    uint8_t recv_buf[16] = { 0U };
    size_t out_len = 0U;
    el2go_ota_status_t result = EL2GO_OTA_ERROR_INTERNAL;
    static const uint8_t full_field[12] = { 0x40U, 0x88U, 0x9AU, 0xCAU, 0xC8U, 0xB2U,
                                            0x12U, 0x34U, 0xDAU, 0x8FU, 0x81U, 0x77U };
    static const uint8_t ping_payload[H2_PING_PAYLOAD_LEN] = { 1, 2, 3, 4, 5, 6, 7, 8 };

    (void)params;
    TEST_ASSERT(grpc_setup_ready_transport(&tls, &t));

    /* HEADERS without END_HEADERS -- block is not yet complete (4 of 12 bytes). */
    queue_frame(4U, H2_TYPE_HEADERS, H2_FLAG_END_STREAM, 1U, full_field);
    /* Stray PING arrives before the CONTINUATION that would complete the
     * header block -- must be rejected, not drained-and-ignored and not
     * silently skipped over. */
    queue_frame(H2_PING_PAYLOAD_LEN, H2_TYPE_PING, 0x00U, 0U, ping_payload);
    /* This CONTINUATION should never be consumed if the PING is correctly
     * rejected first; queued anyway so the mock stream has well-defined
     * contents regardless of how far the implementation gets. */
    queue_frame(8U, TEST_H2_TYPE_CONTINUATION, H2_FLAG_END_HEADERS, 1U, &full_field[4]);

    result = t.recv(&t, recv_buf, sizeof(recv_buf), &out_len);
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_NETWORK, result);

    if (t.deinit != NULL) {
        t.deinit(&t);
    }
    el2go_ota_tls_deinit(tls);
    return true;
}

/* ---- DATA-frame (Length-Prefixed-Message) reassembly tests --------------- */

/*
 * Per the gRPC-over-HTTP2 spec, DATA frame boundaries have no relation to
 * Length-Prefixed-Message boundaries: a server, or a proxy such as Envoy that
 * re-frames the upstream response, may split the 5-byte message prefix and/or
 * the body across any number of DATA frames. The tests below pin the
 * reassembly behaviour of grpc_recv().
 */

/** Largest message used by the reassembly tests (keeps the mock RX queue small). */
#define GRPC_SPLIT_MAX_MSG 80U

/**
 * @brief Build a gRPC Length-Prefixed-Message (5-byte prefix + body) for the
 * reassembly tests. The body is a deterministic pattern: body[i] = i*7+3.
 *
 * @param[out] wire     Output buffer, at least 5 + body_len bytes.
 * @param[in]  body_len Body length (<= GRPC_SPLIT_MAX_MSG).
 * @return Total wire length (5 + body_len).
 */
static size_t grpc_split_build_wire(uint8_t *wire, size_t body_len)
{
    size_t i = 0U;

    wire[0] = 0x00U; /* uncompressed */
    wire[1] = (uint8_t)((body_len >> 24U) & 0xFFU);
    wire[2] = (uint8_t)((body_len >> 16U) & 0xFFU);
    wire[3] = (uint8_t)((body_len >> 8U) & 0xFFU);
    wire[4] = (uint8_t)(body_len & 0xFFU);
    for (i = 0U; i < body_len; i++) {
        wire[GRPC_MSG_HDR_LEN + i] = (uint8_t)(i * 7U + 3U);
    }
    return GRPC_MSG_HDR_LEN + body_len;
}

/**
 * @brief Queue @p wire as DATA frames on @p stream_id, cut after each offset in
 * @p cuts (strictly increasing, each < wire_len). The last frame carries
 * @p last_flags.
 */
static void grpc_split_queue_data(const uint8_t *wire, size_t wire_len, const size_t *cuts,
                                  size_t n_cuts, uint8_t last_flags, uint32_t stream_id)
{
    size_t start = 0U;
    size_t i = 0U;

    for (i = 0U; i <= n_cuts; i++) {
        size_t end = (i < n_cuts) ? cuts[i] : wire_len;

        queue_frame((uint32_t)(end - start), H2_TYPE_DATA, (i == n_cuts) ? last_flags : 0x00U,
                    stream_id, &wire[start]);
        start = end;
    }
}

/** Standalone Trailers-Only block: grpc-status literal, value "0" (OK). */
static const uint8_t k_split_trailer_ok[] = { 0x0BU, 'g', 'r', 'p', 'c', '-',   's',
                                              't',   'a', 't', 'u', 's', 0x01U, '0' };
/** Trailer block: grpc-status literal, value "5" (NOT_FOUND). */
static const uint8_t k_split_trailer_not_found[] = { 0x0BU, 'g', 'r', 'p', 'c', '-',   's',
                                                     't',   'a', 't', 'u', 's', 0x01U, '5' };

/**
 * @brief Run one split-message scenario that is expected to succeed.
 *
 * Sets up a ready transport, queues the message cut at @p cuts, then (unless
 * the last DATA frame carries END_STREAM) the OK trailers, and checks that
 * recv() returns the exact original body.
 */
static bool grpc_split_run_ok(size_t body_len, const size_t *cuts, size_t n_cuts,
                              uint8_t last_flags)
{
    el2go_ota_tls_ctx_t *tls = NULL;
    el2go_ota_transport_t t;
    uint8_t wire[GRPC_MSG_HDR_LEN + GRPC_SPLIT_MAX_MSG] = { 0U };
    uint8_t recv_buf[GRPC_SPLIT_MAX_MSG + 8U] = { 0U };
    size_t out_len = 0U;
    size_t wire_len = grpc_split_build_wire(wire, body_len);

    TEST_ASSERT(grpc_setup_ready_transport(&tls, &t));

    grpc_split_queue_data(wire, wire_len, cuts, n_cuts, last_flags, 1U);
    if ((last_flags & H2_FLAG_END_STREAM) == 0U) {
        queue_frame((uint32_t)sizeof(k_split_trailer_ok), H2_TYPE_HEADERS,
                    H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM, 1U, k_split_trailer_ok);
    }

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, t.recv(&t, recv_buf, sizeof(recv_buf), &out_len));
    TEST_ASSERT_EQUAL((int)body_len, (int)out_len);
    TEST_ASSERT_MEMORY_EQUAL(&wire[GRPC_MSG_HDR_LEN], recv_buf, body_len);

    if (t.deinit != NULL) {
        t.deinit(&t);
    }
    el2go_ota_tls_deinit(tls);
    return true;
}

/** @brief Prefix split 1+4: the first DATA frame carries only the compressed-flag byte. */
static bool test_ota_grpc_recv_data_prefix_split_1_4(void *params)
{
    static const size_t cuts[] = { 1U };

    (void)params;
    return grpc_split_run_ok(40U, cuts, 1U, 0x00U);
}

/** @brief Prefix split 3+2: the cut lands inside the 4-byte length field. */
static bool test_ota_grpc_recv_data_prefix_split_3_2(void *params)
{
    static const size_t cuts[] = { 3U };

    (void)params;
    return grpc_split_run_ok(40U, cuts, 1U, 0x00U);
}

/** @brief Prefix alone in the first DATA frame, whole body in the second. */
static bool test_ota_grpc_recv_data_prefix_and_body_separate_frames(void *params)
{
    static const size_t cuts[] = { GRPC_MSG_HDR_LEN };

    (void)params;
    return grpc_split_run_ok(40U, cuts, 1U, 0x00U);
}

/** @brief Body split across two DATA frames (prefix + first part, then the rest). */
static bool test_ota_grpc_recv_data_body_split_two_frames(void *params)
{
    static const size_t cuts[] = { GRPC_MSG_HDR_LEN + 15U };

    (void)params;
    return grpc_split_run_ok(40U, cuts, 1U, 0x00U);
}

/** @brief Several fragments with cuts inside both the prefix and the body. */
static bool test_ota_grpc_recv_data_split_many_fragments(void *params)
{
    static const size_t cuts[] = { 2U, 7U, GRPC_MSG_HDR_LEN + 20U };

    (void)params;
    return grpc_split_run_ok(40U, cuts, 3U, 0x00U);
}

/**
 * @brief One byte per DATA frame, with more frames than GRPC_RECV_MAX_FRAMES.
 *
 * Guards the progress-based reset of the frame-iteration budget: a valid
 * message must not be rejected merely because it arrives in many fragments.
 */
static bool test_ota_grpc_recv_data_one_byte_frames_exceed_frame_cap(void *params)
{
    size_t cuts[GRPC_MSG_HDR_LEN + GRPC_SPLIT_MAX_MSG] = { 0U };
    size_t body_len = 70U;
    size_t total = GRPC_MSG_HDR_LEN + body_len;
    size_t i = 0U;

    (void)params;
    TEST_ASSERT(total > GRPC_RECV_MAX_FRAMES);
    for (i = 0U; i + 1U < total; i++) {
        cuts[i] = i + 1U;
    }
    return grpc_split_run_ok(body_len, cuts, total - 1U, 0x00U);
}

/** @brief Split message whose last DATA frame carries END_STREAM (no separate trailers). */
static bool test_ota_grpc_recv_data_split_end_stream_on_last_data(void *params)
{
    static const size_t cuts[] = { GRPC_MSG_HDR_LEN + 15U };

    (void)params;
    return grpc_split_run_ok(40U, cuts, 1U, H2_FLAG_END_STREAM);
}

/** @brief PING and WINDOW_UPDATE frames interleaved between the DATA fragments. */
static bool test_ota_grpc_recv_data_split_with_interleaved_control_frames(void *params)
{
    el2go_ota_tls_ctx_t *tls = NULL;
    el2go_ota_transport_t t;
    uint8_t wire[GRPC_MSG_HDR_LEN + GRPC_SPLIT_MAX_MSG] = { 0U };
    uint8_t recv_buf[GRPC_SPLIT_MAX_MSG + 8U] = { 0U };
    size_t out_len = 0U;
    static const uint8_t ping_payload[H2_PING_PAYLOAD_LEN] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    static const uint8_t window_payload[4] = { 0x00U, 0x00U, 0xFFU, 0xFFU };
    size_t wire_len = grpc_split_build_wire(wire, 40U);
    size_t cut_a = 3U;
    size_t cut_b = GRPC_MSG_HDR_LEN + 15U;

    (void)params;
    TEST_ASSERT(grpc_setup_ready_transport(&tls, &t));

    queue_frame((uint32_t)cut_a, H2_TYPE_DATA, 0x00U, 1U, &wire[0]);
    queue_frame(H2_PING_PAYLOAD_LEN, H2_TYPE_PING, 0x00U, 0U, ping_payload);
    queue_frame((uint32_t)(cut_b - cut_a), H2_TYPE_DATA, 0x00U, 1U, &wire[cut_a]);
    queue_frame(4U, H2_TYPE_WINDOW_UPDATE, 0x00U, 0U, window_payload);
    queue_frame((uint32_t)(wire_len - cut_b), H2_TYPE_DATA, 0x00U, 1U, &wire[cut_b]);
    queue_frame((uint32_t)sizeof(k_split_trailer_ok), H2_TYPE_HEADERS,
                H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM, 1U, k_split_trailer_ok);

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, t.recv(&t, recv_buf, sizeof(recv_buf), &out_len));
    TEST_ASSERT_EQUAL(40, (int)out_len);
    TEST_ASSERT_MEMORY_EQUAL(&wire[GRPC_MSG_HDR_LEN], recv_buf, 40U);

    if (t.deinit != NULL) {
        t.deinit(&t);
    }
    el2go_ota_tls_deinit(tls);
    return true;
}

/** @brief A legal empty DATA frame (no END_STREAM) before the message must be ignored. */
static bool test_ota_grpc_recv_data_leading_empty_frame(void *params)
{
    el2go_ota_tls_ctx_t *tls = NULL;
    el2go_ota_transport_t t;
    uint8_t wire[GRPC_MSG_HDR_LEN + GRPC_SPLIT_MAX_MSG] = { 0U };
    uint8_t recv_buf[GRPC_SPLIT_MAX_MSG + 8U] = { 0U };
    size_t out_len = 0U;
    size_t wire_len = grpc_split_build_wire(wire, 12U);

    (void)params;
    TEST_ASSERT(grpc_setup_ready_transport(&tls, &t));

    queue_frame(0U, H2_TYPE_DATA, 0x00U, 1U, NULL);
    queue_frame((uint32_t)wire_len, H2_TYPE_DATA, 0x00U, 1U, wire);
    queue_frame((uint32_t)sizeof(k_split_trailer_ok), H2_TYPE_HEADERS,
                H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM, 1U, k_split_trailer_ok);

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, t.recv(&t, recv_buf, sizeof(recv_buf), &out_len));
    TEST_ASSERT_EQUAL(12, (int)out_len);
    TEST_ASSERT_MEMORY_EQUAL(&wire[GRPC_MSG_HDR_LEN], recv_buf, 12U);

    if (t.deinit != NULL) {
        t.deinit(&t);
    }
    el2go_ota_tls_deinit(tls);
    return true;
}

/** @brief Zero-length message whose 5-byte prefix is split across two frames. */
static bool test_ota_grpc_recv_data_zero_length_message_prefix_split(void *params)
{
    static const size_t cuts[] = { 2U };

    (void)params;
    return grpc_split_run_ok(0U, cuts, 1U, 0x00U);
}

/**
 * @brief The stream ends (END_STREAM on DATA) before the announced message
 * length was delivered. Must fail with NETWORK, never report a short message
 * as success.
 */
static bool test_ota_grpc_recv_data_truncated_message_end_stream(void *params)
{
    el2go_ota_tls_ctx_t *tls = NULL;
    el2go_ota_transport_t t;
    uint8_t wire[GRPC_MSG_HDR_LEN + GRPC_SPLIT_MAX_MSG] = { 0U };
    uint8_t recv_buf[GRPC_SPLIT_MAX_MSG + 8U] = { 0U };
    size_t out_len = 0U;

    (void)params;
    (void)grpc_split_build_wire(wire, 40U); /* announces 40 bytes... */
    TEST_ASSERT(grpc_setup_ready_transport(&tls, &t));

    /* ...but only 10 body bytes arrive before END_STREAM. */
    queue_frame(GRPC_MSG_HDR_LEN + 10U, H2_TYPE_DATA, H2_FLAG_END_STREAM, 1U, wire);

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_NETWORK, t.recv(&t, recv_buf, sizeof(recv_buf), &out_len));
    TEST_ASSERT_EQUAL(0, (int)out_len);

    if (t.deinit != NULL) {
        t.deinit(&t);
    }
    el2go_ota_tls_deinit(tls);
    return true;
}

/**
 * @brief Trailers with grpc-status 0 arrive while the message is still
 * incomplete. Must fail with NETWORK, not report success with a partial body.
 */
static bool test_ota_grpc_recv_data_trailers_before_message_complete(void *params)
{
    el2go_ota_tls_ctx_t *tls = NULL;
    el2go_ota_transport_t t;
    uint8_t wire[GRPC_MSG_HDR_LEN + GRPC_SPLIT_MAX_MSG] = { 0U };
    uint8_t recv_buf[GRPC_SPLIT_MAX_MSG + 8U] = { 0U };
    size_t out_len = 0U;

    (void)params;
    (void)grpc_split_build_wire(wire, 40U);
    TEST_ASSERT(grpc_setup_ready_transport(&tls, &t));

    queue_frame(GRPC_MSG_HDR_LEN + 10U, H2_TYPE_DATA, 0x00U, 1U, wire);
    queue_frame((uint32_t)sizeof(k_split_trailer_ok), H2_TYPE_HEADERS,
                H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM, 1U, k_split_trailer_ok);

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_NETWORK, t.recv(&t, recv_buf, sizeof(recv_buf), &out_len));
    TEST_ASSERT_EQUAL(0, (int)out_len);

    if (t.deinit != NULL) {
        t.deinit(&t);
    }
    el2go_ota_tls_deinit(tls);
    return true;
}

/**
 * @brief A non-zero grpc-status in the trailers still wins over the
 * incomplete-message check: the server's error code must be reported.
 */
static bool test_ota_grpc_recv_data_nonzero_status_before_message_complete(void *params)
{
    el2go_ota_tls_ctx_t *tls = NULL;
    el2go_ota_transport_t t;
    uint8_t wire[GRPC_MSG_HDR_LEN + GRPC_SPLIT_MAX_MSG] = { 0U };
    uint8_t recv_buf[GRPC_SPLIT_MAX_MSG + 8U] = { 0U };
    size_t out_len = 0U;

    (void)params;
    (void)grpc_split_build_wire(wire, 40U);
    TEST_ASSERT(grpc_setup_ready_transport(&tls, &t));

    queue_frame(GRPC_MSG_HDR_LEN + 10U, H2_TYPE_DATA, 0x00U, 1U, wire);
    queue_frame((uint32_t)sizeof(k_split_trailer_not_found), H2_TYPE_HEADERS,
                H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM, 1U, k_split_trailer_not_found);

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_SERVER, t.recv(&t, recv_buf, sizeof(recv_buf), &out_len));

    if (t.deinit != NULL) {
        t.deinit(&t);
    }
    el2go_ota_tls_deinit(tls);
    return true;
}

/**
 * @brief The announced length exceeds the caller's buffer, with the prefix
 * split across frames. Must fail with INTERNAL and must not write past buf.
 */
static bool test_ota_grpc_recv_data_split_prefix_oversize_length_rejected(void *params)
{
    el2go_ota_tls_ctx_t *tls = NULL;
    el2go_ota_transport_t t;
    uint8_t wire[GRPC_MSG_HDR_LEN + GRPC_SPLIT_MAX_MSG] = { 0U };
    uint8_t recv_buf[8] = { 0U };
    size_t out_len = 0U;
    size_t wire_len = grpc_split_build_wire(wire, 40U); /* 40 > sizeof(recv_buf) */

    (void)params;
    TEST_ASSERT(grpc_setup_ready_transport(&tls, &t));

    queue_frame(3U, H2_TYPE_DATA, 0x00U, 1U, wire);
    queue_frame((uint32_t)(wire_len - 3U), H2_TYPE_DATA, 0x00U, 1U, &wire[3]);

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INTERNAL, t.recv(&t, recv_buf, sizeof(recv_buf), &out_len));
    TEST_ASSERT_EQUAL(0, (int)out_len);

    if (t.deinit != NULL) {
        t.deinit(&t);
    }
    el2go_ota_tls_deinit(tls);
    return true;
}

/** @brief The compressed flag (first prefix byte) is still rejected when the prefix is split. */
static bool test_ota_grpc_recv_data_split_compressed_flag_rejected(void *params)
{
    el2go_ota_tls_ctx_t *tls = NULL;
    el2go_ota_transport_t t;
    uint8_t wire[GRPC_MSG_HDR_LEN + GRPC_SPLIT_MAX_MSG] = { 0U };
    uint8_t recv_buf[GRPC_SPLIT_MAX_MSG + 8U] = { 0U };
    size_t out_len = 0U;
    size_t wire_len = grpc_split_build_wire(wire, 40U);

    (void)params;
    wire[0] = 0x01U; /* compressed */
    TEST_ASSERT(grpc_setup_ready_transport(&tls, &t));

    queue_frame(2U, H2_TYPE_DATA, 0x00U, 1U, wire);
    queue_frame((uint32_t)(wire_len - 2U), H2_TYPE_DATA, 0x00U, 1U, &wire[2]);

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_NETWORK, t.recv(&t, recv_buf, sizeof(recv_buf), &out_len));

    if (t.deinit != NULL) {
        t.deinit(&t);
    }
    el2go_ota_tls_deinit(tls);
    return true;
}

/**
 * @brief Two consecutive calls on the SAME connection: the first response is
 * split, the second is whole. Confirms the reassembly leaves the TLS stream
 * frame-aligned (no leftover bytes) so the second call, on stream 3, decodes
 * correctly.
 */
static bool test_ota_grpc_recv_data_split_then_whole_on_same_connection(void *params)
{
    el2go_ota_tls_ctx_t *tls = NULL;
    el2go_ota_transport_t t;
    static const uint8_t msg[1] = { 0x01U };
    uint8_t wire1[GRPC_MSG_HDR_LEN + GRPC_SPLIT_MAX_MSG] = { 0U };
    uint8_t wire2[GRPC_MSG_HDR_LEN + GRPC_SPLIT_MAX_MSG] = { 0U };
    uint8_t recv_buf[GRPC_SPLIT_MAX_MSG + 8U] = { 0U };
    size_t out_len = 0U;
    size_t len1 = grpc_split_build_wire(wire1, 40U);
    size_t len2 = grpc_split_build_wire(wire2, 25U);
    size_t cuts[] = { 2U, GRPC_MSG_HDR_LEN + 10U };

    (void)params;
    TEST_ASSERT(grpc_setup_ready_transport(&tls, &t));

    /* Round 1 (stream 1): split message + OK trailers. */
    grpc_split_queue_data(wire1, len1, cuts, 2U, 0x00U, 1U);
    queue_frame((uint32_t)sizeof(k_split_trailer_ok), H2_TYPE_HEADERS,
                H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM, 1U, k_split_trailer_ok);
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, t.recv(&t, recv_buf, sizeof(recv_buf), &out_len));
    TEST_ASSERT_EQUAL(40, (int)out_len);
    TEST_ASSERT_MEMORY_EQUAL(&wire1[GRPC_MSG_HDR_LEN], recv_buf, 40U);

    /* Round 2 (stream 3): whole message + OK trailers. */
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, t.send(&t, "/pkg.Svc/Method", msg, sizeof(msg)));
    queue_frame((uint32_t)len2, H2_TYPE_DATA, 0x00U, 3U, wire2);
    queue_frame((uint32_t)sizeof(k_split_trailer_ok), H2_TYPE_HEADERS,
                H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM, 3U, k_split_trailer_ok);
    (void)memset(recv_buf, 0, sizeof(recv_buf));
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, t.recv(&t, recv_buf, sizeof(recv_buf), &out_len));
    TEST_ASSERT_EQUAL(25, (int)out_len);
    TEST_ASSERT_MEMORY_EQUAL(&wire2[GRPC_MSG_HDR_LEN], recv_buf, 25U);

    if (t.deinit != NULL) {
        t.deinit(&t);
    }
    el2go_ota_tls_deinit(tls);
    return true;
}

/**
 * @brief Behaviour-preservation: two complete messages in two separate DATA
 * frames (not valid for a unary call, but previously tolerated). The LAST
 * message is returned, exactly as before the reassembly change.
 */
static bool test_ota_grpc_recv_data_two_messages_last_wins(void *params)
{
    el2go_ota_tls_ctx_t *tls = NULL;
    el2go_ota_transport_t t;
    uint8_t wire1[GRPC_MSG_HDR_LEN + GRPC_SPLIT_MAX_MSG] = { 0U };
    uint8_t wire2[GRPC_MSG_HDR_LEN + GRPC_SPLIT_MAX_MSG] = { 0U };
    uint8_t recv_buf[GRPC_SPLIT_MAX_MSG + 8U] = { 0U };
    size_t out_len = 0U;
    size_t len1 = grpc_split_build_wire(wire1, 10U);
    size_t len2 = grpc_split_build_wire(wire2, 7U);

    (void)params;
    wire2[GRPC_MSG_HDR_LEN] ^= 0x5AU; /* make the second body distinguishable */
    TEST_ASSERT(grpc_setup_ready_transport(&tls, &t));

    queue_frame((uint32_t)len1, H2_TYPE_DATA, 0x00U, 1U, wire1);
    queue_frame((uint32_t)len2, H2_TYPE_DATA, H2_FLAG_END_STREAM, 1U, wire2);

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, t.recv(&t, recv_buf, sizeof(recv_buf), &out_len));
    TEST_ASSERT_EQUAL(7, (int)out_len);
    TEST_ASSERT_MEMORY_EQUAL(&wire2[GRPC_MSG_HDR_LEN], recv_buf, 7U);

    if (t.deinit != NULL) {
        t.deinit(&t);
    }
    el2go_ota_tls_deinit(tls);
    return true;
}

/**
 * @brief A DATA frame shorter than the 5-byte prefix that ends the stream
 * fails with NETWORK, and its bytes are fully drained so the reused
 * connection stays frame-aligned: a following call on stream 3 succeeds.
 */
static bool test_ota_grpc_recv_data_short_frame_drained_no_desync(void *params)
{
    el2go_ota_tls_ctx_t *tls = NULL;
    el2go_ota_transport_t t;
    static const uint8_t msg[1] = { 0x01U };
    uint8_t wire[GRPC_MSG_HDR_LEN + GRPC_SPLIT_MAX_MSG] = { 0U };
    uint8_t recv_buf[GRPC_SPLIT_MAX_MSG + 8U] = { 0U };
    size_t out_len = 0U;
    size_t wire_len = grpc_split_build_wire(wire, 12U);

    (void)params;
    TEST_ASSERT(grpc_setup_ready_transport(&tls, &t));

    /* Round 1 (stream 1): a 3-byte DATA frame with END_STREAM -> error. */
    queue_frame(3U, H2_TYPE_DATA, H2_FLAG_END_STREAM, 1U, wire);
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_NETWORK, t.recv(&t, recv_buf, sizeof(recv_buf), &out_len));

    /* Round 2 (stream 3): must decode cleanly, proving no leftover bytes. */
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, t.send(&t, "/pkg.Svc/Method", msg, sizeof(msg)));
    queue_frame((uint32_t)wire_len, H2_TYPE_DATA, 0x00U, 3U, wire);
    queue_frame((uint32_t)sizeof(k_split_trailer_ok), H2_TYPE_HEADERS,
                H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM, 3U, k_split_trailer_ok);
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, t.recv(&t, recv_buf, sizeof(recv_buf), &out_len));
    TEST_ASSERT_EQUAL(12, (int)out_len);
    TEST_ASSERT_MEMORY_EQUAL(&wire[GRPC_MSG_HDR_LEN], recv_buf, 12U);

    if (t.deinit != NULL) {
        t.deinit(&t);
    }
    el2go_ota_tls_deinit(tls);
    return true;
}

/**
 * @brief A complete message followed by an empty DATA frame carrying
 * END_STREAM (some HTTP/2 stacks end a stream this way instead of using
 * trailers on the last data frame). The message must be kept.
 */
static bool test_ota_grpc_recv_data_message_then_empty_end_stream(void *params)
{
    el2go_ota_tls_ctx_t *tls = NULL;
    el2go_ota_transport_t t;
    uint8_t wire[GRPC_MSG_HDR_LEN + GRPC_SPLIT_MAX_MSG] = { 0U };
    uint8_t recv_buf[GRPC_SPLIT_MAX_MSG + 8U] = { 0U };
    size_t out_len = 0U;
    size_t wire_len = grpc_split_build_wire(wire, 20U);

    (void)params;
    TEST_ASSERT(grpc_setup_ready_transport(&tls, &t));

    queue_frame((uint32_t)wire_len, H2_TYPE_DATA, 0x00U, 1U, wire);
    queue_frame(0U, H2_TYPE_DATA, H2_FLAG_END_STREAM, 1U, NULL);

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, t.recv(&t, recv_buf, sizeof(recv_buf), &out_len));
    TEST_ASSERT_EQUAL(20, (int)out_len);
    TEST_ASSERT_MEMORY_EQUAL(&wire[GRPC_MSG_HDR_LEN], recv_buf, 20U);

    if (t.deinit != NULL) {
        t.deinit(&t);
    }
    el2go_ota_tls_deinit(tls);
    return true;
}

/**
 * @brief Queue @p count single-byte-body gRPC messages, one per DATA frame, on stream 1.
 *
 * Message i carries the body byte (uint8_t)i. Only the last frame carries END_STREAM, so
 * the stream stays open for the earlier ones.
 */
static void grpc_queue_tiny_messages(size_t count)
{
    uint8_t wire[GRPC_MSG_HDR_LEN + 1U] = { 0x00U, 0x00U, 0x00U, 0x00U, 0x01U, 0x00U };
    size_t i = 0U;

    for (i = 0U; i < count; i++) {
        wire[GRPC_MSG_HDR_LEN] = (uint8_t)i;
        queue_frame((uint32_t)sizeof(wire), H2_TYPE_DATA,
                    (i + 1U == count) ? H2_FLAG_END_STREAM : 0x00U, 1U, wire);
    }
}

/**
 * @brief More complete messages than the budget allows on one unary call are rejected.
 *
 * Later messages overwrite earlier ones (see the "last wins" test), but a peer must not be
 * able to keep grpc_recv() looping by sending small complete messages: progress resets the
 * idle-frame budget, so the number of messages is bounded separately. The stream ends
 * cleanly with END_STREAM, so only the message bound can reject it.
 */
static bool test_ota_grpc_recv_data_too_many_messages_rejected(void *params)
{
    el2go_ota_tls_ctx_t *tls = NULL;
    el2go_ota_transport_t t;
    uint8_t recv_buf[GRPC_SPLIT_MAX_MSG] = { 0U };
    size_t out_len = 0U;

    (void)params;
    TEST_ASSERT(grpc_setup_ready_transport(&tls, &t));

    /* One message more than the first plus GRPC_RECV_MAX_FRAMES restarts allows. */
    grpc_queue_tiny_messages((size_t)GRPC_RECV_MAX_FRAMES + 2U);

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_NETWORK, t.recv(&t, recv_buf, sizeof(recv_buf), &out_len));

    if (t.deinit != NULL) {
        t.deinit(&t);
    }
    el2go_ota_tls_deinit(tls);
    return true;
}

/**
 * @brief The largest accepted number of messages still succeeds, and the last one wins.
 *
 * Pins the boundary of the message bound: the first message plus GRPC_RECV_MAX_FRAMES
 * restarts is tolerated, exactly as before the bound existed.
 */
static bool test_ota_grpc_recv_data_max_messages_last_wins(void *params)
{
    el2go_ota_tls_ctx_t *tls = NULL;
    el2go_ota_transport_t t;
    uint8_t recv_buf[GRPC_SPLIT_MAX_MSG] = { 0U };
    size_t out_len = 0U;
    size_t count = (size_t)GRPC_RECV_MAX_FRAMES + 1U;

    (void)params;
    TEST_ASSERT(grpc_setup_ready_transport(&tls, &t));

    grpc_queue_tiny_messages(count);

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, t.recv(&t, recv_buf, sizeof(recv_buf), &out_len));
    TEST_ASSERT_EQUAL(1, (int)out_len);
    TEST_ASSERT_EQUAL((int)(uint8_t)(count - 1U), (int)recv_buf[0]);

    if (t.deinit != NULL) {
        t.deinit(&t);
    }
    el2go_ota_tls_deinit(tls);
    return true;
}

/* ---- suite registration ------------------------------------------------ */

void register_ota_lib_grpc_tests(void)
{
    TEST_REGISTER_ID_WITH_PARAMS("14.1", test_ota_grpc_parse_trailers_status_ok, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.2", test_ota_grpc_parse_trailers_status_nonzero, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.3", test_ota_grpc_parse_trailers_not_found, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.4", test_ota_grpc_parse_trailers_null_block, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.5", test_ota_grpc_parse_trailers_too_short, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.6", test_ota_grpc_status, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.7", test_ota_h2_build_frame_hdr_layout, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.8", test_ota_hpack_put_string_buffer_too_small, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.9", test_ota_hpack_put_string_len_too_large, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.10", test_ota_grpc_parse_trailers_status_all_codes, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.11", test_ota_grpc_parse_trailers_truncated_value, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.12", test_ota_grpc_parse_trailers_non_digit_value, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.13", test_ota_grpc_parse_trailers_overflow_guard, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.14", test_ota_grpc_parse_trailers_val_start_beyond_block,
                                 NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.15", test_ota_hpack_encode_grpc_request_success, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.16", test_ota_hpack_encode_grpc_request_buffer_too_small,
                                 NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.17", test_ota_grpc_send_null_params, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.18", test_ota_grpc_recv_null_params, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.19", test_ota_grpc_roundtrip_send_recv_success, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.20", test_ota_grpc_send_preface_write_fail, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.21", test_ota_grpc_recv_ping_then_data, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.22", test_ota_grpc_recv_window_update_then_data, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.23", test_ota_grpc_recv_rst_stream, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.24", test_ota_grpc_recv_goaway, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.25", test_ota_grpc_recv_data_with_padding, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.26", test_ota_grpc_recv_headers_before_data, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.27", test_ota_grpc_recv_trailer_nonzero_status, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.28", test_ota_grpc_recv_frame_limit_exceeded, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.29", test_ota_grpc_send_handshake_with_ping, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.30", test_ota_grpc_recv_trailer_dyn_table_reuse_detects_error,
                                 NULL);
    TEST_REGISTER_ID_WITH_PARAMS(
        "14.31", test_ota_grpc_recv_trailer_dyn_table_reuse_no_false_positive, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.32", test_ota_grpc_recv_trailer_dyn_table_reuse_three_rounds,
                                 NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.33", test_ota_grpc_handshake_settings_max_frame_size_parsed,
                                 NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.34", test_ota_grpc_handshake_settings_multi_param, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.35",
                                 test_ota_grpc_handshake_settings_malformed_length_no_desync, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.36",
                                 test_ota_grpc_handshake_settings_max_frame_size_below_floor, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.37", test_ota_grpc_recv_settings_max_frame_size_steady_state,
                                 NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.38", test_ota_grpc_recv_trailers_split_continuation_basic,
                                 NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.39", test_ota_grpc_recv_response_headers_split_continuation,
                                 NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.40", test_ota_grpc_recv_trailers_split_mid_huffman_name, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.41", test_ota_grpc_recv_trailers_split_three_frames, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.42", test_ota_grpc_recv_continuation_interleaved_ping_rejected,
                                 NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.43", test_ota_grpc_recv_data_prefix_split_1_4, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.44", test_ota_grpc_recv_data_prefix_split_3_2, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.45", test_ota_grpc_recv_data_prefix_and_body_separate_frames,
                                 NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.46", test_ota_grpc_recv_data_body_split_two_frames, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.47", test_ota_grpc_recv_data_split_many_fragments, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.48", test_ota_grpc_recv_data_one_byte_frames_exceed_frame_cap,
                                 NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.49", test_ota_grpc_recv_data_split_end_stream_on_last_data,
                                 NULL);
    TEST_REGISTER_ID_WITH_PARAMS(
        "14.50", test_ota_grpc_recv_data_split_with_interleaved_control_frames, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.51", test_ota_grpc_recv_data_leading_empty_frame, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.52", test_ota_grpc_recv_data_zero_length_message_prefix_split,
                                 NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.53", test_ota_grpc_recv_data_truncated_message_end_stream,
                                 NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.54", test_ota_grpc_recv_data_trailers_before_message_complete,
                                 NULL);
    TEST_REGISTER_ID_WITH_PARAMS(
        "14.55", test_ota_grpc_recv_data_nonzero_status_before_message_complete, NULL);
    TEST_REGISTER_ID_WITH_PARAMS(
        "14.56", test_ota_grpc_recv_data_split_prefix_oversize_length_rejected, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.57", test_ota_grpc_recv_data_split_compressed_flag_rejected,
                                 NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.58",
                                 test_ota_grpc_recv_data_split_then_whole_on_same_connection, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.59", test_ota_grpc_recv_data_two_messages_last_wins, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.60", test_ota_grpc_recv_data_short_frame_drained_no_desync,
                                 NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.61", test_ota_grpc_recv_data_message_then_empty_end_stream,
                                 NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.62", test_ota_grpc_recv_data_too_many_messages_rejected, NULL);
    TEST_REGISTER_ID_WITH_PARAMS("14.63", test_ota_grpc_recv_data_max_messages_last_wins, NULL);
}
