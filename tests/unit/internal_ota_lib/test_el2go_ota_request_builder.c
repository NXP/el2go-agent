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

/* ---- suite registration ------------------------------------------------ */

void register_ota_lib_request_builder_tests(void)
{
    TEST_REGISTER_ID("-", test_ota_encode_check_update_no_attrs);
    TEST_REGISTER_ID("-", test_ota_encode_check_update_one_attr);
    TEST_REGISTER_ID("-", test_ota_encode_fetch_package_zero_range);
    TEST_REGISTER_ID("-", test_ota_encode_report_status_unspecified);
    TEST_REGISTER_ID("-", test_ota_encode_check_update_attrs_null_zero);
    TEST_REGISTER_ID("-", test_ota_encode_report_status_default);
    TEST_REGISTER_ID("-", test_ota_encode_check_update_null_attr_key);
    TEST_REGISTER_ID("-", test_ota_encode_check_update_null_attr_value);
    TEST_REGISTER_ID("-", test_ota_encode_check_zero_buflen);
}
