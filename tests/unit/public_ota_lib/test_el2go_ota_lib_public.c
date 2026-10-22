/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "common/el2go_version.h"
#include "ota/el2go_ota_lib.h"
#include "test_framework.h"
#include "test_suites.h"

/**
 * @defgroup test_el2go_ota_lib_public Public EL2GO OTA Library Tests
 * @brief Unit tests for the public el2go_ota_lib API.
 *
 * Covers parameter validation and state management paths that are
 * exercisable without hardware (no live PSA keystore required).
 *
 * @{
 */

/* ========================================================================== */
/* Helpers                                                                    */
/* ========================================================================== */

/** Minimal valid CA cert placeholder -- content not verified in param tests. */
static const uint8_t s_dummy_ca[] = { 0x30, 0x01, 0x00 };

/* Parameter Validation Tests -- el2go_ota_init() */

/**
 * @brief el2go_ota_init(NULL, valid_config) must return
 *        EL2GO_OTA_ERROR_INVALID_PARAM and leave *ctx untouched.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_init_null_ctx(void *params)
{
    el2go_ota_mtls_config_t cfg = {
        .hostname = "ota.example.com",
        .port = 443U,
        .server_ca_chain = s_dummy_ca,
        .server_ca_chain_size = sizeof(s_dummy_ca),
    };

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_init(NULL, &cfg));

    return true;
}

/**
 * @brief el2go_ota_init(&ctx, NULL) must return EL2GO_OTA_ERROR_INVALID_PARAM
 *        and set *ctx to NULL.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_init_null_config(void *params)
{
    el2go_ota_ctx_t *ctx = (el2go_ota_ctx_t *)0xDEADBEEF; /* sentinel */
    el2go_ota_status_t status = EL2GO_OTA_SUCCESS;

    (void)params;

    status = el2go_ota_init(&ctx, NULL);
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, status);
    TEST_ASSERT_NULL(ctx);

    return true;
}

/**
 * @brief el2go_ota_init() with config->hostname == NULL must return
 *        EL2GO_OTA_ERROR_INVALID_PARAM.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_init_null_hostname(void *params)
{
    el2go_ota_ctx_t *ctx = NULL;
    el2go_ota_mtls_config_t cfg = {
        .hostname = NULL,
        .port = 443U,
        .server_ca_chain = s_dummy_ca,
        .server_ca_chain_size = sizeof(s_dummy_ca),
    };

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_init(&ctx, &cfg));
    TEST_ASSERT_NULL(ctx);

    return true;
}

/**
 * @brief el2go_ota_init() with server_ca_chain == NULL must return
 *        EL2GO_OTA_ERROR_INVALID_PARAM.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_init_null_ca_chain(void *params)
{
    el2go_ota_ctx_t *ctx = NULL;
    el2go_ota_mtls_config_t cfg = {
        .hostname = "ota.example.com",
        .port = 443U,
        .server_ca_chain = NULL,
        .server_ca_chain_size = 0U,
    };

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_init(&ctx, &cfg));
    TEST_ASSERT_NULL(ctx);

    return true;
}

/**
 * @brief el2go_ota_init() with server_ca_chain_size == 0 (non-NULL pointer)
 *        must return EL2GO_OTA_ERROR_INVALID_PARAM.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_init_zero_ca_chain_size(void *params)
{
    el2go_ota_ctx_t *ctx = NULL;
    el2go_ota_mtls_config_t cfg = {
        .hostname = "ota.example.com",
        .port = 443U,
        .server_ca_chain = s_dummy_ca,
        .server_ca_chain_size = 0U,
    };

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_init(&ctx, &cfg));
    TEST_ASSERT_NULL(ctx);

    return true;
}

/* Parameter Validation Tests -- el2go_ota_connect() / disconnect() */

/**
 * @brief el2go_ota_connect(NULL) must return EL2GO_OTA_ERROR_INVALID_PARAM.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_connect_null_ctx(void *params)
{
    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_connect(NULL));

    return true;
}

/**
 * @brief el2go_ota_disconnect(NULL) must return EL2GO_OTA_ERROR_INVALID_PARAM.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_disconnect_null_ctx(void *params)
{
    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_disconnect(NULL));

    return true;
}

/* Diagnostics Tests */

/**
 * @brief el2go_ota_is_connected(NULL) must return false.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_is_connected_null_ctx(void *params)
{
    (void)params;

    TEST_ASSERT_EQUAL(false, el2go_ota_is_connected(NULL));

    return true;
}

/**
 * @brief el2go_ota_get_error_string() must return a non-NULL string for every
 *        defined status code, including the success case.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_get_error_string(void *params)
{
    (void)params;

    TEST_ASSERT_NOT_NULL(el2go_ota_get_error_string(EL2GO_OTA_SUCCESS));
    TEST_ASSERT_NOT_NULL(el2go_ota_get_error_string(EL2GO_OTA_ERROR_INVALID_PARAM));
    TEST_ASSERT_NOT_NULL(el2go_ota_get_error_string(EL2GO_OTA_ERROR_MEMORY));
    TEST_ASSERT_NOT_NULL(el2go_ota_get_error_string(EL2GO_OTA_ERROR_AUTH));
    TEST_ASSERT_NOT_NULL(el2go_ota_get_error_string(EL2GO_OTA_ERROR_NETWORK));
    TEST_ASSERT_NOT_NULL(el2go_ota_get_error_string(EL2GO_OTA_ERROR_TLS_HANDSHAKE));
    TEST_ASSERT_NOT_NULL(el2go_ota_get_error_string(EL2GO_OTA_ERROR_CERT_VERIFY));
    TEST_ASSERT_NOT_NULL(el2go_ota_get_error_string(EL2GO_OTA_ERROR_PLATFORM_INIT));
    TEST_ASSERT_NOT_NULL(el2go_ota_get_error_string(EL2GO_OTA_ERROR_ENCODE));
    TEST_ASSERT_NOT_NULL(el2go_ota_get_error_string(EL2GO_OTA_ERROR_DECODE));
    TEST_ASSERT_NOT_NULL(el2go_ota_get_error_string(EL2GO_OTA_ERROR_INTERNAL));
    /* Unknown value must also return a non-NULL fallback. */
    TEST_ASSERT_NOT_NULL(el2go_ota_get_error_string((el2go_ota_status_t)0xFF));

    return true;
}

/**
 * @brief el2go_ota_cleanup(NULL) and el2go_ota_cleanup(&NULL) must not crash.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_cleanup_null_safe(void *params)
{
    el2go_ota_ctx_t *ctx = NULL;

    (void)params;

    el2go_ota_cleanup(NULL); /* must not crash */
    el2go_ota_cleanup(&ctx); /* *ctx already NULL -- must not crash */

    TEST_PRINT_INFO("el2go_ota_cleanup() with NULL is safe");

    return true;
}

/**
 * @brief el2go_ota_init() with valid parameters must succeed and return a
 *        non-NULL context that can be cleaned up without crashing.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_init_cleanup(void *params)
{
    el2go_ota_ctx_t *ctx = NULL;
    el2go_ota_status_t status = EL2GO_OTA_SUCCESS;
    el2go_ota_mtls_config_t cfg = {
        .hostname = "ota.example.com",
        .port = 443U,
        .server_ca_chain = s_dummy_ca,
        .server_ca_chain_size = sizeof(s_dummy_ca),
    };

    (void)params;

    status = el2go_ota_init(&ctx, &cfg);
    /* PSA and net_crypto calls are mocked, so init succeeds in the test environment. */
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, status);
    TEST_ASSERT_NOT_NULL(ctx);
    el2go_ota_cleanup(&ctx);
    TEST_ASSERT_NULL(ctx);

    return true;
}

/**
 * @brief A failed el2go_ota_init() must leave ctx NULL, which must report
 *        not connected.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_is_connected_after_init(void *params)
{
    el2go_ota_ctx_t *ctx = NULL;
    el2go_ota_mtls_config_t cfg = {
        .hostname = "ota.example.com",
        .port = 443U,
        .server_ca_chain = s_dummy_ca,
        .server_ca_chain_size = sizeof(s_dummy_ca),
    };

    (void)params;

    /* Init succeeds with mocked PSA/net_crypto. After cleanup ctx must be NULL. */
    (void)el2go_ota_init(&ctx, &cfg);
    el2go_ota_cleanup(&ctx);
    TEST_ASSERT_NULL(ctx);

    /* NULL ctx must always report not connected. */
    TEST_ASSERT_EQUAL(false, el2go_ota_is_connected(ctx));
    return true;
}

/**
 * @brief el2go_ota_get_error_string() on the status returned by a failed
 *        el2go_ota_init() must return a non-NULL, non-empty string.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_get_error_string_after_failed_init(void *params)
{
    el2go_ota_ctx_t *ctx = NULL;
    el2go_ota_status_t status = EL2GO_OTA_SUCCESS;
    el2go_ota_mtls_config_t cfg = {
        .hostname = "ota.example.com",
        .port = 443U,
        .server_ca_chain = s_dummy_ca,
        .server_ca_chain_size = sizeof(s_dummy_ca),
    };
    const char *err = NULL;

    (void)params;

    status = el2go_ota_init(&ctx, &cfg);
    /* The returned status must translate to a non-NULL, non-empty string. */
    err = el2go_ota_get_error_string(status);
    TEST_ASSERT_NOT_NULL(err);
    TEST_ASSERT_NOT_EQUAL('\0', err[0]);

    el2go_ota_cleanup(&ctx);
    return true;
}

/* Version Tests */

/**
 * @brief Test el2go_ota_get_version() with NULL parameters.
 *
 * Verifies that passing @c NULL for any output pointer returns
 * @c EL2GO_OTA_ERROR_INVALID_PARAM.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_get_version_null_params(void *params)
{
    unsigned int major = 0, minor = 0, patch = 0;
    el2go_ota_status_t status = EL2GO_OTA_SUCCESS;

    (void)params;

    status = el2go_ota_get_version(NULL, &minor, &patch);
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, status);

    status = el2go_ota_get_version(&major, NULL, &patch);
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, status);

    status = el2go_ota_get_version(&major, &minor, NULL);
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, status);

    status = el2go_ota_get_version(NULL, NULL, NULL);
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, status);

    return true;
}

/**
 * @brief Test el2go_ota_get_version() returns the expected version.
 *
 * Verifies that the returned major, minor, and patch numbers match the
 * compile-time constants defined in el2go_version.h.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_get_version_success(void *params)
{
    unsigned int major = 0, minor = 0, patch = 0;
    el2go_ota_status_t status = EL2GO_OTA_SUCCESS;

    (void)params;

    status = el2go_ota_get_version(&major, &minor, &patch);
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, status);
    TEST_ASSERT_EQUAL(EL2GO_LIB_VERSION_MAJOR, major);
    TEST_ASSERT_EQUAL(EL2GO_LIB_VERSION_MINOR, minor);
    TEST_ASSERT_EQUAL(EL2GO_LIB_VERSION_PATCH, patch);

    return true;
}

/* Additional public API branch coverage */

/**
 * @brief Verify init port zero.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_init_port_zero(void *params)
{
    el2go_ota_ctx_t *ctx = NULL;
    el2go_ota_mtls_config_t cfg = {
        .hostname = "ota.example.com",
        .port = 0U, /* zero port must be rejected */
        .server_ca_chain = s_dummy_ca,
        .server_ca_chain_size = sizeof(s_dummy_ca),
    };

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_init(&ctx, &cfg));
    TEST_ASSERT_NULL(ctx);

    return true;
}

/**
 * @brief Verify schedule status report null params.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_schedule_status_report_null_params(void *params)
{
    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_schedule_status_report(NULL, "pkg-1", EL2GO_OTA_OUTCOME_SUCCESS));
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_schedule_status_report("upd-1", NULL, EL2GO_OTA_OUTCOME_SUCCESS));

    return true;
}

/**
 * @brief Verify schedule status report invalid outcome.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_schedule_status_report_invalid_outcome(void *params)
{
    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_schedule_status_report("upd-1", "pkg-1",
                                                       (el2go_ota_update_outcome_t)99));

    return true;
}

/**
 * @brief Verify get pending status null.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_get_pending_status_null(void *params)
{
    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_get_pending_status(NULL));

    return true;
}

/* Test Registration */

/**
 * @brief Register all public EL2GO OTA Library tests with the test framework.
 */
void register_ota_lib_tests(void)
{
    TEST_REGISTER_ID("OTA_UT_OL_1.1", test_ota_init_null_ctx);
    TEST_REGISTER_ID("OTA_UT_OL_1.2", test_ota_init_null_config);
    TEST_REGISTER_ID("OTA_UT_OL_1.3", test_ota_init_null_hostname);
    TEST_REGISTER_ID("OTA_UT_OL_1.4", test_ota_init_null_ca_chain);
    TEST_REGISTER_ID("OTA_UT_OL_1.5", test_ota_init_zero_ca_chain_size);
    TEST_REGISTER_ID("OTA_UT_OL_1.6", test_ota_connect_null_ctx);
    TEST_REGISTER_ID("OTA_UT_OL_1.7", test_ota_disconnect_null_ctx);
    TEST_REGISTER_ID("OTA_UT_OL_1.8", test_ota_is_connected_null_ctx);
    TEST_REGISTER_ID("OTA_UT_OL_1.9", test_ota_get_error_string);
    TEST_REGISTER_ID("OTA_UT_OL_1.10", test_ota_cleanup_null_safe);
    TEST_REGISTER_ID("OTA_UT_OL_1.11", test_ota_init_cleanup);
    TEST_REGISTER_ID("OTA_UT_OL_1.12", test_ota_is_connected_after_init);
    TEST_REGISTER_ID("OTA_UT_OL_1.13", test_ota_get_error_string_after_failed_init);
    TEST_REGISTER_ID("OTA_UT_OL_1.16", test_ota_get_version_null_params);
    TEST_REGISTER_ID("OTA_UT_OL_1.17", test_ota_get_version_success);
    TEST_REGISTER_ID("OTA_UT_OL_1.18", test_ota_init_port_zero);
    TEST_REGISTER_ID("OTA_UT_OL_1.19", test_ota_schedule_status_report_null_params);
    TEST_REGISTER_ID("OTA_UT_OL_1.20", test_ota_schedule_status_report_invalid_outcome);
    TEST_REGISTER_ID("OTA_UT_OL_1.21", test_ota_get_pending_status_null);
}
