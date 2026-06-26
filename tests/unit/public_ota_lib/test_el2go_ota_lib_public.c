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

/** Minimal valid CA cert placeholder — content not verified in param tests. */
static const uint8_t s_dummy_ca[] = { 0x30, 0x01, 0x00 };

/* ========================================================================== */
/* Parameter Validation Tests — el2go_ota_init()                              */
/* ========================================================================== */

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
    TEST_ASSERT_EQUAL(NULL, ctx);

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
    TEST_ASSERT_EQUAL(NULL, ctx);

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
    TEST_ASSERT_EQUAL(NULL, ctx);

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
    TEST_ASSERT_EQUAL(NULL, ctx);

    return true;
}

/* ========================================================================== */
/* Parameter Validation Tests — el2go_ota_connect() / disconnect()            */
/* ========================================================================== */

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

/* ========================================================================== */
/* Diagnostics Tests                                                          */
/* ========================================================================== */

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
 * @brief el2go_ota_get_last_error(NULL) must return a non-NULL string.
 */
static bool test_el2go_ota_get_last_error_null_ctx(void *params)
{
    const char *err = NULL;

    (void)params;

    err = el2go_ota_get_last_error(NULL);
    TEST_ASSERT_NOT_EQUAL(NULL, err);

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
    el2go_ota_cleanup(&ctx); /* *ctx already NULL — must not crash */

    TEST_PRINT_INFO("el2go_ota_cleanup() with NULL is safe");

    return true;
}

/* ========================================================================== */
/* Test Registration                                                          */
/* ========================================================================== */

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
    TEST_REGISTER(test_el2go_ota_get_last_error_null_ctx);
    TEST_REGISTER(test_el2go_ota_cleanup_null_safe);
}