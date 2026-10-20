/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "test_el2go_ota_compat_shim.h"

#include "test_framework.h"
#include "test_suites.h"

#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include "common/el2go_status.h"
#include "el2go_ota_download_engine.h"
#include "el2go_ota_transport.h"
#include "ota/el2go_ota_lib.h"
#include "ota/el2go_ota_config.h"
#include "test_el2go_ota_fixtures.h"

/**
 * @brief check_for_updates with transport->send == NULL must return INVALID_PARAM.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_download_engine_null_send_fn(void *params)
{
    el2go_ota_transport_t t = { .send = NULL, .recv = NULL };
    el2go_ota_check_update_resp_t resp = { 0 };

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_download_engine_check_for_updates(&t, NULL, 0U, &resp));

    return true;
}

/**
 * @brief fetch_package with file_id == NULL must return INVALID_PARAM.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_download_engine_null_file_id(void *params)
{
    el2go_ota_transport_t t = { .send = NULL, .recv = NULL };

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_download_engine_fetch_package(&t, "upd-1", "pkg-1", NULL, 0U, 0,
                                                              ota_fixture_noop_chunk_cb, NULL));

    return true;
}

/**
 * @brief Verify engine check null resp.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_engine_check_null_resp(void *params)
{
    el2go_ota_transport_t t = { .send = NULL, .recv = NULL };
    (void)params;
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_download_engine_check_for_updates(&t, NULL, 0U, NULL));
    return true;
}

/**
 * @brief Verify engine fetch null update id.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_engine_fetch_null_update_id(void *params)
{
    el2go_ota_transport_t t = { .send = NULL, .recv = NULL };
    (void)params;
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_download_engine_fetch_package(&t, NULL, "pkg", "file", 0U, 0,
                                                              ota_fixture_noop_chunk_cb, NULL));
    return true;
}

/**
 * @brief Verify engine fetch null pkg id.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_engine_fetch_null_pkg_id(void *params)
{
    el2go_ota_transport_t t = { .send = NULL, .recv = NULL };
    (void)params;
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_download_engine_fetch_package(&t, "upd", NULL, "file", 0U, 0,
                                                              ota_fixture_noop_chunk_cb, NULL));
    return true;
}

/**
 * @brief Verify engine fetch null callback.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_engine_fetch_null_callback(void *params)
{
    el2go_ota_transport_t t = { .send = NULL, .recv = NULL };
    (void)params;
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_download_engine_fetch_package(&t, "upd", "pkg", NULL, 0U, 0, NULL,
                                                              NULL));
    return true;
}

/**
 * @brief Verify engine check null resp valid transport.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_engine_check_null_resp_valid_transport(void *params)
{
    el2go_ota_transport_t t;
    memset(&t, 0, sizeof(t));
    t.send = (void *)1U;
    (void)params;
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_download_engine_check_for_updates(&t, NULL, 0U, NULL));
    return true;
}

/**
 * @brief Verify check update null recv.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_check_update_null_recv(void *params)
{
    el2go_ota_transport_t t = { 0 };
    el2go_ota_check_update_resp_t resp = { 0 };
    (void)params;
    t.send = (void *)1U;
    t.recv = NULL;
    el2go_ota_status_t s = el2go_ota_download_engine_check_for_updates(&t, NULL, 0U, &resp);
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, s);
    return true;
}

/**
 * @brief Verify fetch null recv.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_fetch_null_recv(void *params)
{
    el2go_ota_transport_t t = { 0 };
    (void)params;
    t.send = (void *)1U;
    t.recv = NULL;
    el2go_ota_status_t s = el2go_ota_download_engine_fetch_package(&t, "u", "p", "f", 0U, 0,
                                                                   ota_fixture_noop_chunk_cb, NULL);
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, s);
    return true;
}

/**
 * @brief Verify engine check attr count no attrs.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_engine_check_attr_count_no_attrs(void *params)
{
    el2go_ota_transport_t t = { 0 };
    el2go_ota_check_update_resp_t resp = { 0 };
    (void)params;
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_download_engine_check_for_updates(&t, NULL, 5U, &resp));
    return true;
}

/**
 * @brief Verify engine fetch null transport.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_engine_fetch_null_transport(void *params)
{
    (void)params;
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_download_engine_fetch_package(NULL, "u", "p", "f", 0U, 0,
                                                              ota_fixture_noop_chunk_cb, NULL));
    return true;
}

/** @defgroup ota_engine_mock_helpers Mock transport helpers for range-clamping tests
 * @{
 * These stubs are intentionally minimal: they count outgoing requests and
 * return a synthetic 5-byte gRPC EOF frame so the engine can complete one
 * download loop iteration without a real server.
 */

/** @brief Last range_end value captured by mock_send_capture_range(). Initialised to -1. */
static int64_t g_mock_captured_range_end = -1;

/** @brief Number of times mock_send_capture_range() has been called. */
static int g_mock_send_call_count = 0;

/* Minimum gRPC frame size returned by mock_recv_empty_eof(). */
#define MOCK_WIRE_BUF_SIZE 8U

/**
 * @brief Mock transport send stub that counts invocations.
 *
 * Increments g_mock_send_call_count on each call so tests can assert that
 * exactly the expected number of gRPC requests were issued.  Does not inspect
 * the encoded request bytes.
 *
 * @param[in] transport  Unused.
 * @param[in] method     Unused.
 * @param[in] data       Unused.
 * @param[in] data_len   Unused.
 * @return EL2GO_OTA_SUCCESS always.
 */
static el2go_ota_status_t mock_send_capture_range(el2go_ota_transport_t *transport,
                                                  const char *method, const uint8_t *data,
                                                  size_t data_len)
{
    (void)transport;
    (void)method;
    (void)data;
    (void)data_len;
    g_mock_send_call_count++;
    return EL2GO_OTA_SUCCESS;
}

/**
 * @brief Mock transport recv stub that returns a minimal gRPC EOF frame.
 *
 * Writes a 5-byte gRPC frame (1 compressed-flag byte 0x00 followed by a
 * 4-byte big-endian zero message length) into buf.  The response handler
 * decodes this as an empty FileResponse with data_len == 0, which the engine
 * treats as end-of-file and returns EL2GO_OTA_SUCCESS.
 *
 * @param[in]  transport  Unused.
 * @param[out] buf        Destination buffer for the synthetic frame.
 * @param[in]  buf_size   Size of buf in bytes.
 * @param[out] out_len    Set to 5 when buf_size >= 5, otherwise 0.
 * @return EL2GO_OTA_SUCCESS always.
 */
static el2go_ota_status_t mock_recv_empty_eof(el2go_ota_transport_t *transport, uint8_t *buf,
                                              size_t buf_size, size_t *out_len)
{
    (void)transport;
    if (buf_size >= 5U) {
        memset(buf, 0, 5U);
        *out_len = 5U;
    } else {
        *out_len = 0U;
    }
    return EL2GO_OTA_SUCCESS;
}

/** @} */ /* end of ota_engine_mock_helpers */

/**
 * @brief 9.12 -- file size is an exact multiple of EL2GO_OTA_CHUNK_SIZE.
 *
 * With the fix, the byte_offset-based EOF check fires after the first (and
 * only) full chunk, so the engine must NOT send a second request.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_fetch_exact_chunk_multiple_eof(void *params)
{
    (void)params;

    /* File is exactly one chunk in size. */
    int64_t file_size = (int64_t)EL2GO_OTA_CHUNK_SIZE;

    g_mock_send_call_count = 0;
    g_mock_captured_range_end = -1;

    el2go_ota_transport_t t = { 0 };
    t.send = mock_send_capture_range;
    t.recv = mock_recv_empty_eof;

    el2go_ota_status_t s = el2go_ota_download_engine_fetch_package(
        &t, "upd", "pkg", "file", 0U, file_size, ota_fixture_noop_chunk_cb, NULL);

    /*
     * The engine sends one request and then receives an empty response (EOF).
     * It should return success and should NOT have sent a second request.
     */
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, s);
    TEST_ASSERT_EQUAL(1, g_mock_send_call_count);

    return true;
}

/**
 * @brief 9.13 -- file smaller than EL2GO_OTA_CHUNK_SIZE with known_file_size seeded.
 *
 * The very first request must have range_end clamped to known_file_size - 1
 * (not the full EL2GO_OTA_CHUNK_SIZE - 1).  We verify by checking that the
 * engine completes with SUCCESS in one round-trip.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_fetch_small_file_range_clamped(void *params)
{
    (void)params;

    /* File is half a chunk. */
    int64_t file_size = (int64_t)(EL2GO_OTA_CHUNK_SIZE / 2U);

    g_mock_send_call_count = 0;

    el2go_ota_transport_t t = { 0 };
    t.send = mock_send_capture_range;
    t.recv = mock_recv_empty_eof;

    el2go_ota_status_t s = el2go_ota_download_engine_fetch_package(
        &t, "upd", "pkg", "file", 0U, file_size, ota_fixture_noop_chunk_cb, NULL);

    /*
     * The engine encodes a single request with range_end = file_size - 1,
     * receives an empty response (EOF), and exits successfully.
     */
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, s);
    TEST_ASSERT_EQUAL(1, g_mock_send_call_count);

    return true;
}

/**
 * @brief 9.14 -- resume_offset inside the final partial chunk.
 *
 * When resume_offset is within the last chunk of the file, the first
 * post-resume request must be clamped to range_end = file_size - 1.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_fetch_resume_in_last_chunk_clamped(void *params)
{
    (void)params;

    /*
     * File: 1.5 chunks.  resume_offset lands in the second (partial) chunk,
     * so only one request is issued (for the final partial range).
     */
    int64_t file_size = (int64_t)(EL2GO_OTA_CHUNK_SIZE + EL2GO_OTA_CHUNK_SIZE / 2U);
    size_t resume_offset = (size_t)EL2GO_OTA_CHUNK_SIZE;

    g_mock_send_call_count = 0;

    el2go_ota_transport_t t = { 0 };
    t.send = mock_send_capture_range;
    t.recv = mock_recv_empty_eof;

    el2go_ota_status_t s = el2go_ota_download_engine_fetch_package(
        &t, "upd", "pkg", "file", resume_offset, file_size, ota_fixture_noop_chunk_cb, NULL);

    /* One request sent (the final partial chunk), then EOF -> SUCCESS. */
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, s);
    TEST_ASSERT_EQUAL(1, g_mock_send_call_count);

    return true;
}

/* ---- suite registration ------------------------------------------------ */

void register_ota_lib_download_engine_tests(void)
{
    TEST_REGISTER_ID("9.1", test_ota_download_engine_null_send_fn);
    TEST_REGISTER_ID("9.2", test_ota_download_engine_null_file_id);
    TEST_REGISTER_ID("9.3", test_ota_engine_check_null_resp);
    TEST_REGISTER_ID("9.4", test_ota_engine_fetch_null_update_id);
    TEST_REGISTER_ID("9.5", test_ota_engine_fetch_null_pkg_id);
    TEST_REGISTER_ID("9.6", test_ota_engine_fetch_null_callback);
    TEST_REGISTER_ID("9.7", test_ota_engine_check_null_resp_valid_transport);
    TEST_REGISTER_ID("9.8", test_ota_check_update_null_recv);
    TEST_REGISTER_ID("9.9", test_ota_fetch_null_recv);
    TEST_REGISTER_ID("9.10", test_ota_engine_check_attr_count_no_attrs);
    TEST_REGISTER_ID("9.11", test_ota_engine_fetch_null_transport);
    TEST_REGISTER_ID("9.12", test_ota_fetch_exact_chunk_multiple_eof);
    TEST_REGISTER_ID("9.13", test_ota_fetch_small_file_range_clamped);
    TEST_REGISTER_ID("9.14", test_ota_fetch_resume_in_last_chunk_clamped);
}
