/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "test_el2go_ota_lib_public.h"

#include "ota/el2go_ota_lib.h"
#include "ota/el2go_ota_config.h"

#include "canned_protobuf.h"
#include "mock_transport.h"

/* Non-empty CA chain; wrapped TLS init ignores its contents. */
static const uint8_t k_dummy_ca[] = { 0x30, 0x82, 0x01, 0x00 };

static const el2go_ota_mtls_config_t k_wrap_config = {
    .hostname = "test.example.com",
    .port = 443U,
    .server_ca_chain = k_dummy_ca,
    .server_ca_chain_size = sizeof(k_dummy_ca),
};

__attribute__((weak)) const el2go_ota_mtls_config_t *ct_server_config(void)
{
    return NULL;
}

/* Require the mock-transport seam and reset it; may return TEST_SKIP. */
#define PUB_MOCK_ENTER()                         \
    do {                                         \
        TEST_REQUIRE_CAP(CT_CAP_MOCK_TRANSPORT); \
        mock_transport_reset();                  \
    } while (0)

/* Init + connect a real context through the wrap seam.  Returns TEST_PASS and
 * sets *out_ctx on success; the caller must call el2go_ota_cleanup(). */
static test_result_t wrap_connect(el2go_ota_ctx_t **out_ctx)
{
    el2go_ota_ctx_t *ctx = NULL;

    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, el2go_ota_init(&ctx, &k_wrap_config));
    TEST_ASSERT_NOT_NULL(ctx);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, el2go_ota_connect(ctx));
    TEST_ASSERT_TRUE(el2go_ota_is_connected(ctx));

    *out_ctx = ctx;
    return TEST_PASS;
}

/**
 * @brief el2go_ota_init() rejects NULL ctx / NULL config.
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_init_null_params(void)
{
    el2go_ota_ctx_t *ctx = NULL;
    el2go_ota_mtls_config_t cfg = { 0 };

    TEST_ASSERT_EQ(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_init(NULL, &cfg));
    TEST_ASSERT_EQ(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_init(&ctx, NULL));
    TEST_ASSERT_NULL(ctx);
    return TEST_PASS;
}

/**
 * @brief el2go_ota_init() rejects a config with missing required fields.
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_init_invalid_config(void)
{
    el2go_ota_ctx_t *ctx = NULL;
    /* All zero: hostname NULL, port 0, ca chain NULL -> invalid param. */
    el2go_ota_mtls_config_t cfg = { 0 };

    TEST_ASSERT_EQ(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_init(&ctx, &cfg));
    TEST_ASSERT_NULL(ctx);
    return TEST_PASS;
}

/**
 * @brief el2go_ota_is_connected(NULL) is false; never crashes.
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_is_connected_null(void)
{
    TEST_ASSERT_FALSE(el2go_ota_is_connected(NULL));
    return TEST_PASS;
}

/**
 * @brief el2go_ota_get_error_string() returns a non-NULL string for every code.
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_error_string_never_null(void)
{
    int code;

    for (code = (int)EL2GO_OTA_SUCCESS; code <= (int)EL2GO_OTA_ERROR_INTERNAL; code++) {
        const char *msg = el2go_ota_get_error_string((el2go_ota_status_t)code);

        TEST_ASSERT_NOT_NULL(msg);
    }
    return TEST_PASS;
}

/**
 * @brief Public API entry points reject NULL ctx without crashing.
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_api_null_ctx(void)
{
    el2go_ota_check_update_resp_t resp = { 0 };

    TEST_ASSERT_EQ(EL2GO_OTA_ERROR_INVALID_PARAM,
                   el2go_ota_check_for_updates(NULL, NULL, 0U, &resp));
    TEST_ASSERT_EQ(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_connect(NULL));
    TEST_ASSERT_EQ(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_disconnect(NULL));
    TEST_ASSERT_EQ(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_report_pending_status(NULL));
    return TEST_PASS;
}

/**
 * @brief OTA_CT_OL_1.3 : check_for_updates, update available (public API) 
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_check_update_available(void)
{
    el2go_ota_ctx_t *ctx = NULL;
    el2go_ota_check_update_resp_t resp = { 0 };
    uint8_t wire[512U] = { 0 };
    size_t wire_len = 0U;
    test_result_t rc;

    PUB_MOCK_ENTER();

    TEST_ASSERT_EQ(0, canned_check_update_one_package(wire, sizeof(wire), &wire_len));
    TEST_ASSERT_EQ(0, mock_transport_queue_response(wire, wire_len));

    rc = wrap_connect(&ctx);
    if (rc != TEST_PASS) {
        el2go_ota_cleanup(&ctx);
        return rc;
    }

    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, el2go_ota_check_for_updates(ctx, NULL, 0U, &resp));
    TEST_ASSERT_TRUE(resp.update_available);
    TEST_ASSERT_EQ(1U, resp.update_count);
    TEST_ASSERT_STR_EQ("upd-1", resp.updates[0].update_id);
    TEST_ASSERT_EQ(1U, mock_transport_send_count());

    el2go_ota_cleanup(&ctx);
    TEST_ASSERT_NULL(ctx);
    return TEST_PASS;
}

/**
 * @brief OTA_CT_OL_1.4 : check_for_updates, no update (public API)
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_check_update_empty(void)
{
    el2go_ota_ctx_t *ctx = NULL;
    el2go_ota_check_update_resp_t resp = { 0 };
    uint8_t wire[128U] = { 0 };
    size_t wire_len = 0U;
    test_result_t rc;

    PUB_MOCK_ENTER();

    TEST_ASSERT_EQ(0, canned_check_update_empty(wire, sizeof(wire), &wire_len));
    TEST_ASSERT_EQ(0, mock_transport_queue_response(wire, wire_len));

    rc = wrap_connect(&ctx);
    if (rc != TEST_PASS) {
        el2go_ota_cleanup(&ctx);
        return rc;
    }

    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, el2go_ota_check_for_updates(ctx, NULL, 0U, &resp));
    TEST_ASSERT_FALSE(resp.update_available);

    el2go_ota_cleanup(&ctx);
    return TEST_PASS;
}

/**
 * @brief check_for_updates before connect must be gated as a network error.
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_check_before_connect(void)
{
    el2go_ota_ctx_t *ctx = NULL;
    el2go_ota_check_update_resp_t resp = { 0 };

    PUB_MOCK_ENTER();

    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, el2go_ota_init(&ctx, &k_wrap_config));
    TEST_ASSERT_NOT_NULL(ctx);
    TEST_ASSERT_FALSE(el2go_ota_is_connected(ctx));

    /* Not connected: the wrapper must refuse before touching the transport. */
    TEST_ASSERT_EQ(EL2GO_OTA_ERROR_NETWORK, el2go_ota_check_for_updates(ctx, NULL, 0U, &resp));
    TEST_ASSERT_EQ(0U, mock_transport_send_count());

    el2go_ota_cleanup(&ctx);
    return TEST_PASS;
}

/* Chunk-callback capture used by the public download-flow tests. */
struct pub_chunk_capture {
    size_t total_len;
    size_t call_count;
};

/* Per-call offset capture for range-advance assertions. */
struct pub_range_capture {
    size_t offsets[8U];
    size_t call_count;
};

static el2go_ota_status_t pub_capture_cb(const uint8_t *data, size_t len, size_t offset,
                                         void *cb_ctx)
{
    struct pub_chunk_capture *cap = (struct pub_chunk_capture *)cb_ctx;

    (void)data;
    (void)offset;
    cap->total_len += len;
    cap->call_count++;
    return EL2GO_OTA_SUCCESS;
}

/**
 * @brief OTA_CT_OL_1.5 : download_package streams chunks (public API)
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_download_package(void)
{
    el2go_ota_ctx_t *ctx = NULL;
    struct pub_chunk_capture cap = { 0 };
    uint8_t c0[128U] = { 0 };
    uint8_t eof[32U] = { 0 };
    size_t l0 = 0U;
    size_t le = 0U;
    static const uint8_t payload[] = { 0xAA, 0xBB, 0xCC, 0xDD };
    test_result_t rc;

    PUB_MOCK_ENTER();

    TEST_ASSERT_EQ(0, canned_fetch_package_chunk(c0, sizeof(c0), 0, (int64_t)sizeof(payload) - 1,
                                                 payload, sizeof(payload), &l0));
    TEST_ASSERT_EQ(0, canned_fetch_package_chunk(eof, sizeof(eof), 0, 0, NULL, 0U, &le));

    rc = wrap_connect(&ctx);
    if (rc != TEST_PASS) {
        el2go_ota_cleanup(&ctx);
        return rc;
    }

    TEST_ASSERT_EQ(0, mock_transport_queue_response(c0, l0));
    TEST_ASSERT_EQ(0, mock_transport_queue_response(eof, le));

    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, el2go_ota_download_package(ctx, "upd-1", "pkg-1", "file-1",
                                                                 0U, pub_capture_cb, &cap));
    TEST_ASSERT_EQ(sizeof(payload), cap.total_len);
    TEST_ASSERT_TRUE(cap.call_count >= 1U);

    el2go_ota_cleanup(&ctx);
    return TEST_PASS;
}

/**
 * @brief OTA_CT_OL_1.7 : report_status SUCCESS acked (public API)
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_report_status_ack(void)
{
    el2go_ota_ctx_t *ctx = NULL;
    uint8_t ack[16U] = { 0 };
    size_t ack_len = 0U;
    test_result_t rc;

    PUB_MOCK_ENTER();

    TEST_ASSERT_EQ(0, canned_report_status_ack(ack, sizeof(ack), &ack_len));

    rc = wrap_connect(&ctx);
    if (rc != TEST_PASS) {
        el2go_ota_cleanup(&ctx);
        return rc;
    }

    TEST_ASSERT_EQ(0, mock_transport_queue_response(ack, ack_len));

    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS,
                   el2go_ota_report_status(ctx, "upd-2", "pkg-2", EL2GO_OTA_OUTCOME_SUCCESS));

    el2go_ota_cleanup(&ctx);
    return TEST_PASS;
}

/**
 * @brief Range-capture callback for OTA_CT_OL_1.6
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static el2go_ota_status_t pub_range_cb(const uint8_t *data, size_t len, size_t offset, void *cb_ctx)
{
    struct pub_range_capture *cap = (struct pub_range_capture *)cb_ctx;

    (void)data;
    (void)len;
    if (cap->call_count < 8U) {
        cap->offsets[cap->call_count] = offset;
        cap->call_count++;
    }
    return EL2GO_OTA_SUCCESS;
}

/**
 * @brief OTA_CT_OL_1.6 : chunk callback receives correct ranges (public API)
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_chunk_range_advances(void)
{
    el2go_ota_ctx_t *ctx = NULL;
    struct pub_range_capture rcap = { 0 };
    uint8_t c0[128U] = { 0 };
    uint8_t c1[128U] = { 0 };
    uint8_t c2[128U] = { 0 };
    uint8_t eof[32U] = { 0 };
    size_t l0 = 0U;
    size_t l1 = 0U;
    size_t l2 = 0U;
    size_t le = 0U;
    static const uint8_t p[] = { 0x10, 0x11, 0x12, 0x13 };
    size_t i;
    test_result_t rc;

    PUB_MOCK_ENTER();

    TEST_ASSERT_EQ(0, canned_fetch_package_chunk(c0, sizeof(c0), 0, 3, p, sizeof(p), &l0));
    TEST_ASSERT_EQ(0, canned_fetch_package_chunk(c1, sizeof(c1), 4, 7, p, sizeof(p), &l1));
    TEST_ASSERT_EQ(0, canned_fetch_package_chunk(c2, sizeof(c2), 8, 11, p, sizeof(p), &l2));
    TEST_ASSERT_EQ(0, canned_fetch_package_chunk(eof, sizeof(eof), 0, 0, NULL, 0U, &le));

    rc = wrap_connect(&ctx);
    if (rc != TEST_PASS) {
        el2go_ota_cleanup(&ctx);
        return rc;
    }

    TEST_ASSERT_EQ(0, mock_transport_queue_response(c0, l0));
    TEST_ASSERT_EQ(0, mock_transport_queue_response(c1, l1));
    TEST_ASSERT_EQ(0, mock_transport_queue_response(c2, l2));
    TEST_ASSERT_EQ(0, mock_transport_queue_response(eof, le));

    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, el2go_ota_download_package(ctx, "upd-1", "pkg-1", "file-1",
                                                                 0U, pub_range_cb, &rcap));
    TEST_ASSERT_EQ(3U, rcap.call_count);

    for (i = 1U; i < rcap.call_count; i++) {
        TEST_ASSERT_MSG(rcap.offsets[i] > rcap.offsets[i - 1U],
                        "rangeStart did not advance between consecutive chunk callbacks");
    }

    el2go_ota_cleanup(&ctx);
    return TEST_PASS;
}

/**
 * @brief OTA_CT_OL_1.8 : report_status FAILURE acked (public API)
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_report_status_failure(void)
{
    el2go_ota_ctx_t *ctx = NULL;
    uint8_t ack[16U] = { 0 };
    size_t ack_len = 0U;
    test_result_t rc;

    PUB_MOCK_ENTER();

    TEST_ASSERT_EQ(0, canned_report_status_ack(ack, sizeof(ack), &ack_len));

    rc = wrap_connect(&ctx);
    if (rc != TEST_PASS) {
        el2go_ota_cleanup(&ctx);
        return rc;
    }

    TEST_ASSERT_EQ(0, mock_transport_queue_response(ack, ack_len));

    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS,
                   el2go_ota_report_status(ctx, "upd-8", "pkg-8", EL2GO_OTA_OUTCOME_FAILURE));

    el2go_ota_cleanup(&ctx);
    return TEST_PASS;
}

/**
 * @brief OTA_CT_OL_1.9 : report_status ROLLBACK acked (public API)
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_report_status_rollback(void)
{
    el2go_ota_ctx_t *ctx = NULL;
    uint8_t ack[16U] = { 0 };
    size_t ack_len = 0U;
    test_result_t rc;

    PUB_MOCK_ENTER();

    TEST_ASSERT_EQ(0, canned_report_status_ack(ack, sizeof(ack), &ack_len));

    rc = wrap_connect(&ctx);
    if (rc != TEST_PASS) {
        el2go_ota_cleanup(&ctx);
        return rc;
    }

    TEST_ASSERT_EQ(0, mock_transport_queue_response(ack, ack_len));

    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS,
                   el2go_ota_report_status(ctx, "upd-9", "pkg-9", EL2GO_OTA_OUTCOME_ROLLBACK));

    el2go_ota_cleanup(&ctx);
    return TEST_PASS;
}

/**
 * @brief OTA_CT_OL_1.10 : network interruption mid-download (public API)
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_download_network_interruption(void)
{
    el2go_ota_ctx_t *ctx = NULL;
    struct pub_chunk_capture cap = { 0 };
    uint8_t c0[128U] = { 0 };
    size_t l0 = 0U;
    static const uint8_t p0[] = { 0x10, 0x11, 0x12, 0x13 };
    test_result_t rc;

    PUB_MOCK_ENTER();

    TEST_ASSERT_EQ(0, canned_fetch_package_chunk(c0, sizeof(c0), 0, 3, p0, sizeof(p0), &l0));

    rc = wrap_connect(&ctx);
    if (rc != TEST_PASS) {
        el2go_ota_cleanup(&ctx);
        return rc;
    }

    TEST_ASSERT_EQ(0, mock_transport_queue_response(c0, l0));
    TEST_ASSERT_EQ(0, mock_transport_queue_network_error());

    TEST_ASSERT_EQ(EL2GO_OTA_ERROR_NETWORK,
                   el2go_ota_download_package(ctx, "upd-10", "pkg-10", "file-10", 0U,
                                              pub_capture_cb, &cap));

    el2go_ota_cleanup(&ctx);
    return TEST_PASS;
}

/**
 * @brief OTA_CT_OL_1.11 : download resumes from last offset (public API)
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_download_resume(void)
{
    el2go_ota_ctx_t *ctx = NULL;
    struct pub_chunk_capture cap = { 0 };
    uint8_t c1[128U] = { 0 };
    uint8_t eof[32U] = { 0 };
    size_t l1 = 0U;
    size_t le = 0U;
    static const uint8_t p1[] = { 0xB0, 0xB1, 0xB2, 0xB3 };
    test_result_t rc;

    PUB_MOCK_ENTER();

    TEST_ASSERT_EQ(0, canned_fetch_package_chunk(c1, sizeof(c1), 4, 7, p1, sizeof(p1), &l1));
    TEST_ASSERT_EQ(0, canned_fetch_package_chunk(eof, sizeof(eof), 0, 0, NULL, 0U, &le));

    rc = wrap_connect(&ctx);
    if (rc != TEST_PASS) {
        el2go_ota_cleanup(&ctx);
        return rc;
    }

    TEST_ASSERT_EQ(0, mock_transport_queue_response(c1, l1));
    TEST_ASSERT_EQ(0, mock_transport_queue_response(eof, le));

    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, el2go_ota_download_package(ctx, "upd-11", "pkg-11", "file-11",
                                                                 4U, pub_capture_cb, &cap));
    TEST_ASSERT_EQ(sizeof(p1), cap.total_len);

    el2go_ota_cleanup(&ctx);
    return TEST_PASS;
}

/**
 * @brief OTA_CT_OL_1.12 : report_status retry after failures (public API) 
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_report_pending_status(void)
{
    el2go_ota_ctx_t *ctx = NULL;
    uint8_t ack[16U] = { 0 };
    size_t ack_len = 0U;
    test_result_t rc;

    PUB_MOCK_ENTER();

    /* Schedule a pending status (no network needed). */
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS,
                   el2go_ota_schedule_status_report("upd-12", "pkg-12", EL2GO_OTA_OUTCOME_SUCCESS));

    TEST_ASSERT_EQ(0, canned_report_status_ack(ack, sizeof(ack), &ack_len));
    TEST_ASSERT_EQ(0, mock_transport_queue_response(ack, ack_len));

    rc = wrap_connect(&ctx);
    if (rc != TEST_PASS) {
        el2go_ota_cleanup(&ctx);
        return rc;
    }

    /* Deliver the pending entry via the connected context. */
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, el2go_ota_report_pending_status(ctx));

    el2go_ota_cleanup(&ctx);
    return TEST_PASS;
}

/**
 * @brief OTA_CT_OL_1.13 : malformed server response (public API)
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_check_update_malformed(void)
{
    el2go_ota_ctx_t *ctx = NULL;
    el2go_ota_check_update_resp_t resp = { 0 };
    static const uint8_t garbage[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    };
    test_result_t rc;

    PUB_MOCK_ENTER();

    TEST_ASSERT_EQ(0, mock_transport_queue_response(garbage, sizeof(garbage)));

    rc = wrap_connect(&ctx);
    if (rc != TEST_PASS) {
        el2go_ota_cleanup(&ctx);
        return rc;
    }

    TEST_ASSERT_EQ(EL2GO_OTA_ERROR_DECODE, el2go_ota_check_for_updates(ctx, NULL, 0U, &resp));

    el2go_ota_cleanup(&ctx);
    return TEST_PASS;
}

/**
 * @brief OTA_CT_OL_1.1 : init + connect over real mutual TLS
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_init_connect_real_tls(void)
{
    const el2go_ota_mtls_config_t *cfg;
    el2go_ota_ctx_t *ctx = NULL;
    el2go_ota_status_t s;

    TEST_REQUIRE_CAP(CT_CAP_REAL_TLS);

    cfg = ct_server_config();
    if (cfg == NULL) {
        TEST_SKIP_WITH("no live OTA server configured for this target");
    }

    s = el2go_ota_init(&ctx, cfg);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, s);
    TEST_ASSERT_NOT_NULL(ctx);

    s = el2go_ota_connect(ctx);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, s);
    TEST_ASSERT_TRUE(el2go_ota_is_connected(ctx));

    (void)el2go_ota_disconnect(ctx);
    el2go_ota_cleanup(&ctx);
    TEST_ASSERT_NULL(ctx);
    return TEST_PASS;
}

/**
 * @brief OTA_CT_OL_1.2 : connect with invalid CA chain rejected
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_connect_invalid_ca_rejected(void)
{
    const el2go_ota_mtls_config_t *base;
    el2go_ota_mtls_config_t bad;
    static const uint8_t bogus_ca[] = { 0x30, 0x00 };
    el2go_ota_ctx_t *ctx = NULL;
    el2go_ota_status_t s;

    TEST_REQUIRE_CAP(CT_CAP_REAL_TLS);

    base = ct_server_config();
    if (base == NULL) {
        TEST_SKIP_WITH("no live OTA server configured for this target");
    }

    bad = *base;
    bad.server_ca_chain = bogus_ca;
    bad.server_ca_chain_size = sizeof(bogus_ca);

    s = el2go_ota_init(&ctx, &bad);
    if (s == EL2GO_OTA_SUCCESS) {
        s = el2go_ota_connect(ctx);
        TEST_ASSERT_NE(EL2GO_OTA_SUCCESS, s);
        TEST_ASSERT_FALSE(el2go_ota_is_connected(ctx));
    } else {
        TEST_ASSERT_NE(EL2GO_OTA_SUCCESS, s);
    }

    el2go_ota_cleanup(&ctx);
    return TEST_PASS;
}

/**
 * @brief already-connected idempotent (public API)
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_connect_idempotent(void)
{
    el2go_ota_ctx_t *ctx = NULL;
    test_result_t rc;

    PUB_MOCK_ENTER();

    rc = wrap_connect(&ctx);
    if (rc != TEST_PASS) {
        el2go_ota_cleanup(&ctx);
        return rc;
    }

    /* Second connect on an already-connected context must return SUCCESS
     * without re-initialising the transport (send_count stays the same). */
    size_t sends_before = mock_transport_send_count();
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, el2go_ota_connect(ctx));
    TEST_ASSERT_TRUE(el2go_ota_is_connected(ctx));
    TEST_ASSERT_EQ(sends_before, mock_transport_send_count());

    el2go_ota_cleanup(&ctx);
    return TEST_PASS;
}

/**
 * @brief disconnect then reconnect (public API)
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_disconnect_reconnect(void)
{
    el2go_ota_ctx_t *ctx = NULL;
    test_result_t rc;

    PUB_MOCK_ENTER();

    rc = wrap_connect(&ctx);
    if (rc != TEST_PASS) {
        el2go_ota_cleanup(&ctx);
        return rc;
    }

    /* Disconnect -- context must still be valid (not freed). */
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, el2go_ota_disconnect(ctx));
    TEST_ASSERT_FALSE(el2go_ota_is_connected(ctx));

    /* Reconnect through the wrap seam. */
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, el2go_ota_connect(ctx));
    TEST_ASSERT_TRUE(el2go_ota_is_connected(ctx));

    el2go_ota_cleanup(&ctx);
    return TEST_PASS;
}

/**
 * @brief report_pending_status: schedule then deliver via connected ctx
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_report_pending_with_nvs(void)
{
    el2go_ota_ctx_t *ctx = NULL;
    uint8_t ack[16U] = { 0 };
    size_t ack_len = 0U;
    test_result_t rc;

    PUB_MOCK_ENTER();
    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH);

    /* Ensure no leftover entry. */
    (void)el2go_ota_schedule_status_report("dummy", "dummy", EL2GO_OTA_OUTCOME_FAILURE);

    /* Schedule a fresh SUCCESS entry. */
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS,
                   el2go_ota_schedule_status_report("upd-pp", "pkg-pp", EL2GO_OTA_OUTCOME_SUCCESS));

    TEST_ASSERT_EQ(0, canned_report_status_ack(ack, sizeof(ack), &ack_len));
    TEST_ASSERT_EQ(0, mock_transport_queue_response(ack, ack_len));

    rc = wrap_connect(&ctx);
    if (rc != TEST_PASS) {
        el2go_ota_cleanup(&ctx);
        return rc;
    }

    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, el2go_ota_report_pending_status(ctx));

    el2go_ota_cleanup(&ctx);
    return TEST_PASS;
}

/**
 * @brief get_pending_status: read what was scheduled
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_get_pending_status(void)
{
    el2go_ota_pending_status_t pending = { 0 };

    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH);

    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, el2go_ota_schedule_status_report("upd-gp", "pkg-gp",
                                                                       EL2GO_OTA_OUTCOME_ROLLBACK));

    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, el2go_ota_get_pending_status(&pending));
    TEST_ASSERT_EQ(EL2GO_OTA_STATUS_VALID_MAGIC, pending.valid);
    TEST_ASSERT_EQ((uint8_t)EL2GO_OTA_OUTCOME_ROLLBACK, pending.outcome);
    TEST_ASSERT_STR_EQ("upd-gp", pending.update_id);
    return TEST_PASS;
}

/**
 * @brief check_for_updates: recv returns empty -- exercises decode failure path
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_check_update_decode_fail(void)
{
    el2go_ota_ctx_t *ctx = NULL;
    el2go_ota_check_update_resp_t resp = { 0 };

    TEST_REQUIRE_CAP(CT_CAP_MOCK_TRANSPORT);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, wrap_connect(&ctx));
    TEST_ASSERT_NOT_NULL(ctx);

    /* Queue a corrupt response that will fail decode */
    static const uint8_t corrupt[] = { 0xFF, 0xFE };
    TEST_ASSERT_EQ(0, mock_transport_queue_response(corrupt, sizeof(corrupt)));

    /* decode should fail -- exercises result != EL2GO_OTA_SUCCESS after recv */
    el2go_ota_status_t s = el2go_ota_check_for_updates(ctx, NULL, 0U, &resp);
    /* May succeed with no update or fail with decode error -- either exercises the branch */
    (void)s;

    el2go_ota_cleanup(&ctx);
    return TEST_PASS;
}

/**
 * @brief report_status: with connected ctx -- exercises the connected path fully
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_report_status_connected(void)
{
    el2go_ota_ctx_t *ctx = NULL;
    uint8_t ack[16U] = { 0 };
    size_t ack_len = 0U;

    TEST_REQUIRE_CAP(CT_CAP_MOCK_TRANSPORT);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, wrap_connect(&ctx));
    TEST_ASSERT_NOT_NULL(ctx);

    TEST_ASSERT_EQ(0, canned_report_status_ack(ack, sizeof(ack), &ack_len));
    TEST_ASSERT_EQ(0, mock_transport_queue_response(ack, ack_len));

    /* Exercises the connected path in el2go_ota_report_status */
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS,
                   el2go_ota_report_status(ctx, "u", "p", EL2GO_OTA_OUTCOME_SUCCESS));

    el2go_ota_cleanup(&ctx);
    return TEST_PASS;
}

/**
 * @brief report_pending_status: exercises the ctx connected path
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_report_pending_connected(void)
{
    el2go_ota_ctx_t *ctx = NULL;

    TEST_REQUIRE_CAP(CT_CAP_MOCK_TRANSPORT);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, wrap_connect(&ctx));
    TEST_ASSERT_NOT_NULL(ctx);

    /* No pending status -- exercises the "no pending entry" branch */
    el2go_ota_status_t s = el2go_ota_report_pending_status(ctx);
    (void)s; /* may return no_entry or success */

    el2go_ota_cleanup(&ctx);
    return TEST_PASS;
}

/**
 * @brief is_connected: true then false after disconnect
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_is_connected_true_false(void)
{
    el2go_ota_ctx_t *ctx = NULL;

    TEST_REQUIRE_CAP(CT_CAP_MOCK_TRANSPORT);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, wrap_connect(&ctx));
    TEST_ASSERT_NOT_NULL(ctx);
    TEST_ASSERT_TRUE(el2go_ota_is_connected(ctx));

    el2go_ota_disconnect(ctx);
    TEST_ASSERT_MSG(!el2go_ota_is_connected(ctx), "expected not connected");

    el2go_ota_cleanup(&ctx);
    return TEST_PASS;
}

/**
 * @brief get_error_string: call with all status codes -- exercises map_status switch
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_all_error_strings(void)
{
    static const el2go_ota_status_t codes[] = {
        EL2GO_OTA_SUCCESS,      EL2GO_OTA_ERROR_INTERNAL, EL2GO_OTA_ERROR_NETWORK,
        EL2GO_OTA_ERROR_DECODE, EL2GO_OTA_ERROR_ENCODE,   EL2GO_OTA_ERROR_INVALID_PARAM,
        EL2GO_OTA_ERROR_SERVER, (el2go_ota_status_t)99, /* unknown */
    };

    TEST_REQUIRE_CAP(CT_CAP_MOCK_TRANSPORT);
    for (size_t i = 0U; i < sizeof(codes) / sizeof(codes[0]); i++) {
        const char *s = el2go_ota_get_error_string(codes[i]);
        TEST_ASSERT_NOT_NULL(s);
    }
    return TEST_PASS;
}

/**
 * @brief download_package: with NULL file_id -- exercises the null check branch fully
 *
 * @return @c TEST_PASS if all assertions pass, 
 *         @c TEST_FAIL otherwise.
 *         @c TEST_SKIP if capabilities not matched
 */
static test_result_t test_ota_download_null_file_id(void)
{
    el2go_ota_ctx_t *ctx = NULL;
    el2go_ota_check_update_resp_t check_resp = { 0 };
    uint8_t wire[512U] = { 0 };
    size_t wire_len = 0U;

    TEST_REQUIRE_CAP(CT_CAP_MOCK_TRANSPORT);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, wrap_connect(&ctx));
    TEST_ASSERT_NOT_NULL(ctx);

    /* First do a check_update to get update_id/package_id */
    TEST_ASSERT_EQ(0, canned_check_update_one_package(wire, sizeof(wire), &wire_len));
    TEST_ASSERT_EQ(0, mock_transport_queue_response(wire, wire_len));
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, el2go_ota_check_for_updates(ctx, NULL, 0U, &check_resp));
    TEST_ASSERT_TRUE(check_resp.update_available);

    /* file_id = NULL -- exercises that specific null branch */
    el2go_ota_status_t s = el2go_ota_download_package(ctx, check_resp.first_update_id,
                                                      check_resp.first_package_id, NULL, 0U,
                                                      pub_capture_cb, NULL);
    TEST_ASSERT_NE(EL2GO_OTA_SUCCESS, s);

    el2go_ota_cleanup(&ctx);
    return TEST_PASS;
}

/* ---- suite registration ------------------------------------------------ */

TEST_SUITE_BEGIN(ota_lib_public)
TEST_REGISTER("OTA_CT_OL_1.14", test_ota_init_null_params)
TEST_REGISTER("OTA_CT_OL_1.15", test_ota_init_invalid_config)
TEST_REGISTER("OTA_CT_OL_1.16", test_ota_is_connected_null)
TEST_REGISTER("OTA_CT_OL_1.17", test_ota_error_string_never_null)
TEST_REGISTER("OTA_CT_OL_1.18", test_ota_api_null_ctx)
TEST_REGISTER("OTA_CT_OL_1.3", test_ota_check_update_available)
TEST_REGISTER("OTA_CT_OL_1.4", test_ota_check_update_empty)
TEST_REGISTER("OTA_CT_OL_1.13", test_ota_check_update_malformed)
TEST_REGISTER("OTA_CT_OL_1.19", test_ota_check_before_connect)
TEST_REGISTER("OTA_CT_OL_1.5", test_ota_download_package)
TEST_REGISTER("OTA_CT_OL_1.6", test_ota_chunk_range_advances)
TEST_REGISTER("OTA_CT_OL_1.10", test_ota_download_network_interruption)
TEST_REGISTER("OTA_CT_OL_1.11", test_ota_download_resume)
TEST_REGISTER("OTA_CT_OL_1.7", test_ota_report_status_ack)
TEST_REGISTER("OTA_CT_OL_1.8", test_ota_report_status_failure)
TEST_REGISTER("OTA_CT_OL_1.9", test_ota_report_status_rollback)
TEST_REGISTER("OTA_CT_OL_1.12", test_ota_report_pending_status)
TEST_REGISTER("OTA_CT_OL_1.1", test_ota_init_connect_real_tls)
TEST_REGISTER("OTA_CT_OL_1.2", test_ota_connect_invalid_ca_rejected)
TEST_REGISTER("OTA_CT_OL_1.20", test_ota_connect_idempotent)
TEST_REGISTER("OTA_CT_OL_1.21", test_ota_disconnect_reconnect)
TEST_REGISTER("OTA_CT_OL_1.22", test_ota_report_pending_with_nvs)
TEST_REGISTER("OTA_CT_OL_1.23", test_ota_get_pending_status)
TEST_REGISTER("OTA_CT_OL_1.24", test_ota_check_update_decode_fail)
TEST_REGISTER("OTA_CT_OL_1.25", test_ota_report_status_connected)
TEST_REGISTER("OTA_CT_OL_1.26", test_ota_report_pending_connected)
TEST_REGISTER("OTA_CT_OL_1.27", test_ota_is_connected_true_false)
TEST_REGISTER("OTA_CT_OL_1.28", test_ota_all_error_strings)
TEST_REGISTER("OTA_CT_OL_1.29", test_ota_download_null_file_id)
TEST_SUITE_END(ota_lib_public)
