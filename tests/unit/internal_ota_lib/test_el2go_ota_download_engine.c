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
                      el2go_ota_download_engine_fetch_package(&t, "upd-1", "pkg-1", NULL, 0U,
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
                      el2go_ota_download_engine_fetch_package(&t, NULL, "pkg", "file", 0U,
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
                      el2go_ota_download_engine_fetch_package(&t, "upd", NULL, "file", 0U,
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
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_download_engine_fetch_package(
                                                         &t, "upd", "pkg", NULL, 0U, NULL, NULL));
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
    el2go_ota_status_t s = el2go_ota_download_engine_fetch_package(&t, "u", "p", "f", 0U,
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
                      el2go_ota_download_engine_fetch_package(NULL, "u", "p", "f", 0U,
                                                              ota_fixture_noop_chunk_cb, NULL));
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
}
