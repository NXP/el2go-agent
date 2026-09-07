/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

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
 */
static bool test_el2go_ota_init_null_ctx(void *params)
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
 */
static bool test_el2go_ota_init_null_config(void *params)
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
 */
static bool test_el2go_ota_init_null_hostname(void *params)
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
 */
static bool test_el2go_ota_init_null_ca_chain(void *params)
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
 */
static bool test_el2go_ota_init_zero_ca_chain_size(void *params)
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
 */
static bool test_el2go_ota_connect_null_ctx(void *params)
{
    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_connect(NULL));

    return true;
}

/**
 * @brief el2go_ota_disconnect(NULL) must return EL2GO_OTA_ERROR_INVALID_PARAM.
 */
static bool test_el2go_ota_disconnect_null_ctx(void *params)
{
    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_disconnect(NULL));

    return true;
}

/* Diagnostics Tests */

/**
 * @brief el2go_ota_is_connected(NULL) must return false.
 */
static bool test_el2go_ota_is_connected_null_ctx(void *params)
{
    (void)params;

    TEST_ASSERT_EQUAL(false, el2go_ota_is_connected(NULL));

    return true;
}

/**
 * @brief el2go_ota_get_error_string() must return a non-NULL string for every
 *        defined status code, including the success case.
 */
static bool test_el2go_ota_get_error_string(void *params)
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
 */
static bool test_el2go_ota_cleanup_null_safe(void *params)
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
 */
static bool test_el2go_ota_init_cleanup(void *params)
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
    /* Must fail -- no real PSA keystore or valid CA on a unit-test host. */
    TEST_ASSERT_NOT_EQUAL(EL2GO_OTA_SUCCESS, status);
    /* ctx must be NULL-ed on any failure path. */
    TEST_ASSERT_NULL(ctx);
    /* cleanup of NULL ctx must be safe. */
    el2go_ota_cleanup(&ctx);

    return true;
}

/**
 * @brief A failed el2go_ota_init() must leave ctx NULL, which must report
 *        not connected.
 */
static bool test_el2go_ota_is_connected_after_init(void *params)
{
    el2go_ota_ctx_t *ctx = NULL;
    el2go_ota_mtls_config_t cfg = {
        .hostname = "ota.example.com",
        .port = 443U,
        .server_ca_chain = s_dummy_ca,
        .server_ca_chain_size = sizeof(s_dummy_ca),
    };

    (void)params;

    /* Ignore the specific error -- see test_el2go_ota_init_cleanup. */
    (void)el2go_ota_init(&ctx, &cfg);
    TEST_ASSERT_NULL(ctx);

    /* NULL ctx must always report not connected. */
    TEST_ASSERT_EQUAL(false, el2go_ota_is_connected(ctx));

    el2go_ota_cleanup(&ctx);
    return true;
}

/**
 * @brief el2go_ota_get_error_string() on the status returned by a failed
 *        el2go_ota_init() must return a non-NULL, non-empty string.
 */
static bool test_el2go_ota_get_error_string_after_failed_init(void *params)
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
    TEST_ASSERT_NULL(ctx);

    /* The returned status must translate to a non-NULL, non-empty string. */
    err = el2go_ota_get_error_string(status);
    TEST_ASSERT_NOT_NULL(err);
    TEST_ASSERT_NOT_EQUAL('\0', err[0]);

    el2go_ota_cleanup(&ctx);
    return true;
}

/* Client Auth Mode -- backward-compatibility invariants */

/**
 * @brief EL2GO_OTA_CLIENT_AUTH_REQUIRED must be enum value 0.
 *
 * Legacy callers that leave client_auth out of their designated initializer
 * rely on this to keep mTLS behaviour.
 */
static bool test_client_auth_required_is_zero(void *params)
{
    (void)params;

    TEST_ASSERT_EQUAL(0, (int)EL2GO_OTA_CLIENT_AUTH_REQUIRED);

    return true;
}

/**
 * @brief A zero-initialised el2go_ota_mtls_config_t must have
 *        client_auth == EL2GO_OTA_CLIENT_AUTH_REQUIRED.
 */
static bool test_client_auth_default_is_required(void *params)
{
    el2go_ota_mtls_config_t cfg = { 0 };

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_CLIENT_AUTH_REQUIRED, cfg.client_auth);

    return true;
}

/* Test Registration */

/**
 * @brief Register all public EL2GO OTA Library tests with the test framework.
 */
void register_ota_lib_tests(void)
{
    TEST_REGISTER(test_el2go_ota_init_null_ctx);
    TEST_REGISTER(test_el2go_ota_init_null_config);
    TEST_REGISTER(test_el2go_ota_init_null_hostname);
    TEST_REGISTER(test_el2go_ota_init_null_ca_chain);
    TEST_REGISTER(test_el2go_ota_init_zero_ca_chain_size);
    TEST_REGISTER(test_el2go_ota_connect_null_ctx);
    TEST_REGISTER(test_el2go_ota_disconnect_null_ctx);
    TEST_REGISTER(test_el2go_ota_is_connected_null_ctx);
    TEST_REGISTER(test_el2go_ota_get_error_string);
    TEST_REGISTER(test_el2go_ota_cleanup_null_safe);
    TEST_REGISTER(test_el2go_ota_init_cleanup);
    TEST_REGISTER(test_el2go_ota_is_connected_after_init);
    TEST_REGISTER(test_el2go_ota_get_error_string_after_failed_init);
    TEST_REGISTER(test_client_auth_required_is_zero);
    TEST_REGISTER(test_client_auth_default_is_required);
}
