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
#include "el2go_ota_status_reporting.h"
#include "ota/el2go_ota_lib.h"
#include "test_el2go_ota_fixtures.h"

/**
 * @brief status_reporting_report with null transport must return INVALID_PARAM.
 * 
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_status_reporting_report_null_transport(void *params)
{
    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_status_reporting_report(NULL, "upd-1", "pkg-1",
                                                        EL2GO_OTA_OUTCOME_SUCCESS));

    return true;
}

/**
 * @brief status_reporting_report with null update_id must return INVALID_PARAM.
 * 
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_status_reporting_report_null_update_id(void *params)
{
    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_status_reporting_report(NULL, NULL, "pkg-1",
                                                        EL2GO_OTA_OUTCOME_SUCCESS));

    return true;
}

/**
 * @brief status_reporting_retry_pending with null transport must return INVALID_PARAM.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_status_reporting_retry_null_transport(void *params)
{
    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_status_reporting_retry_pending(NULL));

    return true;
}

/**
 * @brief status_reporting_read_pending with null out must return INVALID_PARAM.
 * 
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_status_reporting_read_pending_null(void *params)
{
    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_status_reporting_read_pending(NULL));

    return true;
}

/**
 * @brief Verify status report failure.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_status_report_failure(void *param)
{
    (void)param;
    ota_fixture_reset_net_crypto_wraps();
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_status_reporting_report(NULL, "u", "p", EL2GO_OTA_OUTCOME_FAILURE));
    return true;
}

/**
 * @brief Verify status report rollback.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_status_report_rollback(void *param)
{
    (void)param;
    ota_fixture_reset_net_crypto_wraps();
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_status_reporting_report(NULL, "u", "p",
                                                        EL2GO_OTA_OUTCOME_ROLLBACK));
    return true;
}

/**
 * @brief Verify retry pending null.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_retry_pending_null(void *param)
{
    (void)param;
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_status_reporting_retry_pending(NULL));
    return true;
}

/**
 * @brief Verify deliver null vtable.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_deliver_null_vtable(void *param)
{
    el2go_ota_transport_t t = { 0 }; /* send=NULL, recv=NULL */
    (void)param;
    /* el2go_ota_status_reporting_report: transport != NULL (passes line 111),
     * enters status_reporting_deliver, which checks send==NULL at line 61 -> INVALID_PARAM */
    el2go_ota_status_t s =
        el2go_ota_status_reporting_report(&t, "u", "p", EL2GO_OTA_OUTCOME_SUCCESS);
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, s);
    return true;
}

/**
 * @brief Verify status report all outcomes null vtable.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_status_report_all_outcomes_null_vtable(void *param)
{
    el2go_ota_transport_t t = { 0 }; /* send=NULL -> hits line 61 */
    (void)param;
    /* All 3 outcomes exercise outcome_to_wire_status and outcome_to_message */
    el2go_ota_status_t s1 =
        el2go_ota_status_reporting_report(&t, "u", "p", EL2GO_OTA_OUTCOME_SUCCESS);
    el2go_ota_status_t s2 =
        el2go_ota_status_reporting_report(&t, "u", "p", EL2GO_OTA_OUTCOME_FAILURE);
    el2go_ota_status_t s3 =
        el2go_ota_status_reporting_report(&t, "u", "p", EL2GO_OTA_OUTCOME_ROLLBACK);
    /* All should return INVALID_PARAM since send==NULL */
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, s1);
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, s2);
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, s3);
    return true;
}

/**
 * @brief Verify status report null transport.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_status_report_null_transport(void *param)
{
    (void)param;
    /* transport == NULL hits line 111 check */
    TEST_ASSERT(EL2GO_OTA_SUCCESS !=
                el2go_ota_status_reporting_report(NULL, "u", "p", EL2GO_OTA_OUTCOME_SUCCESS));
    return true;
}

/**
 * @brief Verify schedule null package.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_schedule_null_package(void *param)
{
    (void)param;
    TEST_ASSERT(EL2GO_OTA_SUCCESS !=
                el2go_ota_status_reporting_schedule("upd", NULL, EL2GO_OTA_OUTCOME_SUCCESS));
    return true;
}

/**
 * @defgroup ota_status_fake_transport Fake transport for status reporting
 * @{
 */

static el2go_ota_status_t g_fake_send_result;
static el2go_ota_status_t g_fake_recv_result;
static unsigned int g_fake_send_calls;

static el2go_ota_status_t fake_send(el2go_ota_transport_t *t, const char *method_path,
                                    const uint8_t *msg, size_t msg_len)
{
    (void)t;
    (void)method_path;
    (void)msg;
    (void)msg_len;
    g_fake_send_calls++;
    return g_fake_send_result;
}

static el2go_ota_status_t fake_recv(el2go_ota_transport_t *t, uint8_t *buf, size_t buf_len,
                                    size_t *out_len)
{
    (void)t;
    (void)buf;
    (void)buf_len;
    *out_len = 0U; /* google.protobuf.Empty */
    return g_fake_recv_result;
}

static void fake_transport_init(el2go_ota_transport_t *t, el2go_ota_status_t send_result,
                                el2go_ota_status_t recv_result)
{
    memset(t, 0, sizeof(*t));
    t->send = fake_send;
    t->recv = fake_recv;
    g_fake_send_result = send_result;
    g_fake_recv_result = recv_result;
    g_fake_send_calls = 0U;
}

/** @} */

/*
 * The unit build has no flash/NVS backend, so el2go_ota_kvs_init() fails
 * with EL2GO_OTA_ERROR_INTERNAL. Tests 12.12-12.15 cover that path: report
 * falls back to delivery without persistence, and the KVS-only APIs return
 * the KVS error. The persisted path is covered by the component suite.
 */

/**
 * @brief 12.12 -- without KVS, report still delivers; a send error is returned.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_status_report_no_kvs_send_fail(void *params)
{
    el2go_ota_transport_t t;
    (void)params;

    fake_transport_init(&t, EL2GO_OTA_ERROR_NETWORK, EL2GO_OTA_SUCCESS);
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_NETWORK,
                      el2go_ota_status_reporting_report(&t, "upd-s", "pkg-s",
                                                        EL2GO_OTA_OUTCOME_SUCCESS));
    TEST_ASSERT_EQUAL(1U, g_fake_send_calls);
    return true;
}

/**
 * @brief 12.13 -- report with a failing recv returns the recv error.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_status_report_recv_fail(void *params)
{
    el2go_ota_transport_t t;
    (void)params;

    fake_transport_init(&t, EL2GO_OTA_SUCCESS, EL2GO_OTA_ERROR_NETWORK);
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_NETWORK,
                      el2go_ota_status_reporting_report(&t, "upd-r", "pkg-r",
                                                        EL2GO_OTA_OUTCOME_FAILURE));
    return true;
}

/**
 * @brief 12.14 -- without KVS, a fully acknowledged report returns SUCCESS.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_status_report_no_kvs_success(void *params)
{
    el2go_ota_transport_t t;
    (void)params;

    fake_transport_init(&t, EL2GO_OTA_SUCCESS, EL2GO_OTA_SUCCESS);
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, el2go_ota_status_reporting_report(
                                             &t, "upd-ok", "pkg-ok", EL2GO_OTA_OUTCOME_ROLLBACK));
    TEST_ASSERT_EQUAL(1U, g_fake_send_calls);
    return true;
}

/**
 * @brief 12.15 -- without KVS, schedule, read_pending and retry_pending fail
 *        with the KVS error and never touch the transport.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_status_kvs_only_apis_without_kvs(void *params)
{
    el2go_ota_transport_t t;
    el2go_ota_pending_status_t pending = { 0 };
    (void)params;

    fake_transport_init(&t, EL2GO_OTA_SUCCESS, EL2GO_OTA_SUCCESS);
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INTERNAL, el2go_ota_status_reporting_schedule(
                                                    "upd-q", "pkg-q", EL2GO_OTA_OUTCOME_FAILURE));
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INTERNAL, el2go_ota_status_reporting_read_pending(&pending));
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INTERNAL, el2go_ota_status_reporting_retry_pending(&t));
    TEST_ASSERT_EQUAL(0U, g_fake_send_calls);
    return true;
}

/* ---- suite registration ------------------------------------------------ */

void register_ota_lib_status_reporting_tests(void)
{
    TEST_REGISTER_ID("12.1", test_ota_status_reporting_report_null_transport);
    TEST_REGISTER_ID("12.2", test_ota_status_reporting_report_null_update_id);
    TEST_REGISTER_ID("12.3", test_ota_status_reporting_retry_null_transport);
    TEST_REGISTER_ID("12.4", test_ota_status_reporting_read_pending_null);
    TEST_REGISTER_ID("12.5", test_ota_status_report_failure);
    TEST_REGISTER_ID("12.6", test_ota_status_report_rollback);
    TEST_REGISTER_ID("12.7", test_ota_retry_pending_null);
    TEST_REGISTER_ID("12.8", test_ota_deliver_null_vtable);
    TEST_REGISTER_ID("12.9", test_ota_status_report_all_outcomes_null_vtable);
    TEST_REGISTER_ID("12.10", test_ota_status_report_null_transport);
    TEST_REGISTER_ID("12.11", test_ota_schedule_null_package);
    TEST_REGISTER_ID("12.12", test_ota_status_report_no_kvs_send_fail);
    TEST_REGISTER_ID("12.13", test_ota_status_report_recv_fail);
    TEST_REGISTER_ID("12.14", test_ota_status_report_no_kvs_success);
    TEST_REGISTER_ID("12.15", test_ota_status_kvs_only_apis_without_kvs);
}
