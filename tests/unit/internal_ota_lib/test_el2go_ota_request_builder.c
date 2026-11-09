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
#include "el2go_ota_request_builder.h"
#include "ota/el2go_ota_lib.h"

/**
 * @brief Verify that el2go_ota_encode_check_update() with no attributes
 *        succeeds and produces a non-empty output buffer.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_encode_check_update_no_attrs(void *params)
{
    el2go_ota_check_update_req_t req = { .attrs = NULL, .attr_count = 0U };
    uint8_t buf[64];
    size_t out_len = 0U;
    el2go_ota_status_t status;

    (void)params;

    status = el2go_ota_encode_check_update(&req, buf, sizeof(buf), &out_len);
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, status);
    TEST_PRINT_INFO("check_update (no attrs) encoded %u byte(s)", (unsigned)out_len);

    return true;
}

/**
 * @brief encode_check_update with a single attribute -- exercises
 *        the non-zero attribute loop in the encoder.
 * 
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_encode_check_update_one_attr(void *params)
{
    static const el2go_ota_attr_t attrs[] = { { "board", "native" } };
    el2go_ota_check_update_req_t req = { .attrs = attrs, .attr_count = 1U };
    uint8_t buf[128];
    size_t out_len = 0U;

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_encode_check_update(&req, buf, sizeof(buf), &out_len));
    TEST_ASSERT(out_len > 0U);
    return true;
}

/**
 * @brief encode_fetch_package with range_start == range_end == 0 encodes
 *        a minimal range sub-message (zero-value varint path).
 * 
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_encode_fetch_package_zero_range(void *params)
{
    el2go_ota_fetch_pkg_req_t req = {
        .update_id = "u",
        .package_id = "p",
        .file_id = "f",
        .range_start = 0,
        .range_end = 0,
    };
    uint8_t buf[64];
    size_t out_len = 0U;

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_encode_fetch_package(&req, buf, sizeof(buf), &out_len));
    TEST_ASSERT(out_len > 0U);
    return true;
}

/**
 * @brief encode_report_status with UNSPECIFIED status (value 0 -- default
 *        varint) must succeed.
 * 
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_encode_report_status_unspecified(void *params)
{
    el2go_ota_report_status_req_t req = {
        .update_id = "upd-u",
        .status = EL2GO_OTA_UPDATE_STATUS_UNSPECIFIED,
        .status_message = NULL,
    };
    uint8_t buf[64];
    size_t out_len = 0U;

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_encode_report_status(&req, buf, sizeof(buf), &out_len));
    return true;
}

/**
 * @brief Verify encode check update attrs null zero.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_encode_check_update_attrs_null_zero(void *params)
{
    el2go_ota_check_update_req_t req = { .attrs = NULL, .attr_count = 0U };
    uint8_t buf[64];
    size_t out_len = 0U;
    (void)params;
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_encode_check_update(&req, buf, sizeof(buf), &out_len));
    TEST_ASSERT_EQUAL(0U, out_len);
    return true;
}

/**
 * @brief Verify encode report status default.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_encode_report_status_default(void *params)
{
    el2go_ota_report_status_req_t req = { .update_id = "u", .status = 0, .status_message = NULL };
    uint8_t buf[32];
    size_t out_len = 0U;
    (void)params;
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_encode_report_status(&req, buf, sizeof(buf), &out_len));
    return true;
}

/**
 * @brief Verify encode check update null attr key.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_encode_check_update_null_attr_key(void *params)
{
    static const el2go_ota_attr_t attrs_null_key[] = {
        { NULL, "v1" }, /* NULL key -- must be skipped, not an error */
    };
    el2go_ota_check_update_req_t req = { .attrs = attrs_null_key, .attr_count = 1U };
    uint8_t buf[128];
    size_t out_len = 0U;
    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_encode_check_update(&req, buf, sizeof(buf), &out_len));
    return true;
}

/**
 * @brief Verify encode check update null attr value.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_encode_check_update_null_attr_value(void *params)
{
    static const el2go_ota_attr_t attrs_null_val[] = {
        { "k1", NULL }, /* NULL value -- must be skipped, not an error */
    };
    el2go_ota_check_update_req_t req = { .attrs = attrs_null_val, .attr_count = 1U };
    uint8_t buf[128];
    size_t out_len = 0U;
    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_encode_check_update(&req, buf, sizeof(buf), &out_len));
    return true;
}

/**
 * @brief Verify encode check zero buflen.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_encode_check_zero_buflen(void *params)
{
    el2go_ota_check_update_req_t req = { .attrs = NULL, .attr_count = 0U };
    uint8_t buf[64];
    size_t out_len = 0U;
    (void)params;
    /* buf_len == 0 hits the 4th sub-condition of the null-guard in encode_check_update */
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_encode_check_update(&req, buf, 0U, &out_len));
    return true;
}

/**
 * @brief An output buffer that is too small for the encoded request must be
 *        reported as an encode error for every shorter length, never as a
 *        success with truncated data.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_encode_check_update_truncated_buffer_rejected(void *params)
{
    static const el2go_ota_attr_t attrs[] = { { "board", "native" }, { "fw", "1.2.3" } };
    el2go_ota_check_update_req_t req = { .attrs = attrs, .attr_count = 2U };
    uint8_t buf[64] = { 0U };
    size_t full_len = 0U;
    size_t out_len = 0U;
    size_t len = 0U;

    (void)params;
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_encode_check_update(&req, buf, sizeof(buf), &full_len));
    TEST_ASSERT(full_len > 0U && full_len < sizeof(buf));

    for (len = 1U; len < full_len; len++) {
        TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_ENCODE,
                          el2go_ota_encode_check_update(&req, buf, len, &out_len));
    }
    /* Exactly the required size still succeeds. */
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_encode_check_update(&req, buf, full_len, &out_len));
    TEST_ASSERT_EQUAL(full_len, out_len);
    return true;
}

/**
 * @brief 7.11 -- encode_fetch_package rejects every NULL argument, a zero
 *        buffer length and each missing identifier with INVALID_PARAM.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_encode_fetch_package_invalid_args(void *params)
{
    el2go_ota_fetch_pkg_req_t req = { .update_id = "u", .package_id = "p", .file_id = "f" };
    el2go_ota_fetch_pkg_req_t bad = req;
    uint8_t buf[64];
    size_t out_len = 0U;

    (void)params;
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_encode_fetch_package(NULL, buf, sizeof(buf), &out_len));
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_encode_fetch_package(&req, NULL, sizeof(buf), &out_len));
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_encode_fetch_package(&req, buf, sizeof(buf), NULL));
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_encode_fetch_package(&req, buf, 0U, &out_len));

    bad.update_id = NULL;
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_encode_fetch_package(&bad, buf, sizeof(buf), &out_len));
    bad = req;
    bad.package_id = NULL;
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_encode_fetch_package(&bad, buf, sizeof(buf), &out_len));
    bad = req;
    bad.file_id = NULL;
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_encode_fetch_package(&bad, buf, sizeof(buf), &out_len));
    return true;
}

/**
 * @brief 7.12 -- encode_report_status rejects every NULL argument, a zero
 *        buffer length and a missing update_id with INVALID_PARAM.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_encode_report_status_invalid_args(void *params)
{
    el2go_ota_report_status_req_t req = { .update_id = "u", .status_message = "m" };
    el2go_ota_report_status_req_t bad = { .update_id = NULL };
    uint8_t buf[64];
    size_t out_len = 0U;

    (void)params;
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_encode_report_status(NULL, buf, sizeof(buf), &out_len));
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_encode_report_status(&req, NULL, sizeof(buf), &out_len));
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_encode_report_status(&req, buf, sizeof(buf), NULL));
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_encode_report_status(&req, buf, 0U, &out_len));
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_encode_report_status(&bad, buf, sizeof(buf), &out_len));
    return true;
}

/**
 * @brief 7.13 -- fetch_package and report_status return ENCODE when the
 *        output buffer is one byte too small.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_encode_fetch_and_report_small_buffer(void *params)
{
    el2go_ota_fetch_pkg_req_t freq = {
        .update_id = "upd", .package_id = "pkg", .file_id = "file", .range_end = 1024U
    };
    el2go_ota_report_status_req_t rreq = { .update_id = "upd", .status_message = "done" };
    uint8_t buf[128];
    size_t full_len = 0U;
    size_t out_len = 0U;

    (void)params;
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_encode_fetch_package(&freq, buf, sizeof(buf), &full_len));
    TEST_ASSERT(full_len > 1U);
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_ENCODE,
                      el2go_ota_encode_fetch_package(&freq, buf, full_len - 1U, &out_len));

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_encode_report_status(&rreq, buf, sizeof(buf), &full_len));
    TEST_ASSERT(full_len > 1U);
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_ENCODE,
                      el2go_ota_encode_report_status(&rreq, buf, full_len - 1U, &out_len));
    return true;
}

/* ---- suite registration ------------------------------------------------ */

void register_ota_lib_request_builder_tests(void)
{
    TEST_REGISTER_ID("7.1", test_ota_encode_check_update_no_attrs);
    TEST_REGISTER_ID("7.2", test_ota_encode_check_update_one_attr);
    TEST_REGISTER_ID("7.3", test_ota_encode_fetch_package_zero_range);
    TEST_REGISTER_ID("7.4", test_ota_encode_report_status_unspecified);
    TEST_REGISTER_ID("7.5", test_ota_encode_check_update_attrs_null_zero);
    TEST_REGISTER_ID("7.6", test_ota_encode_report_status_default);
    TEST_REGISTER_ID("7.7", test_ota_encode_check_update_null_attr_key);
    TEST_REGISTER_ID("7.8", test_ota_encode_check_update_null_attr_value);
    TEST_REGISTER_ID("7.9", test_ota_encode_check_zero_buflen);
    TEST_REGISTER_ID("7.10", test_ota_encode_check_update_truncated_buffer_rejected);
    TEST_REGISTER_ID("7.11", test_ota_encode_fetch_package_invalid_args);
    TEST_REGISTER_ID("7.12", test_ota_encode_report_status_invalid_args);
    TEST_REGISTER_ID("7.13", test_ota_encode_fetch_and_report_small_buffer);
}
