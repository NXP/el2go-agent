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
#include "el2go_ota_tls.h"
#include "el2go_ota_cred.h"
#include "common/el2go_platform.h"
#include "test_el2go_ota_fixtures.h"
#include "wrap_net_crypto.h"

/**
 * @brief Verify tls init null out ctx.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_tls_init_null_out_ctx(void *params)
{
    el2go_ota_mtls_config_t c = ota_fixture_make_cfg();
    (void)params;
    ota_fixture_reset_net_crypto_wraps();
    TEST_ASSERT_EQUAL(EL2GO_STATUS_INVALID_PARAMETER,
                      el2go_ota_tls_init(NULL, ota_fixture_get_pctx(), &c));
    return true;
}

/**
 * @brief Verify tls init null config.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_tls_init_null_config(void *params)
{
    el2go_ota_tls_ctx_t *ctx = NULL;
    (void)params;
    ota_fixture_reset_net_crypto_wraps();
    TEST_ASSERT_EQUAL(EL2GO_STATUS_INVALID_PARAMETER,
                      el2go_ota_tls_init(&ctx, ota_fixture_get_pctx(), NULL));
    TEST_ASSERT_NULL(ctx);
    return true;
}

/**
 * @brief Verify tls init success.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_tls_init_success(void *params)
{
    el2go_ota_tls_ctx_t *ctx = NULL;
    el2go_ota_mtls_config_t c = ota_fixture_make_cfg();
    (void)params;
    ota_fixture_reset_net_crypto_wraps();
    TEST_ASSERT_EQUAL(EL2GO_STATUS_SUCCESS, el2go_ota_tls_init(&ctx, ota_fixture_get_pctx(), &c));
    TEST_ASSERT_NOT_NULL(ctx);
    el2go_ota_tls_deinit(ctx);
    return true;
}

/**
 * @brief Verify tls init new fail.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_tls_init_new_fail(void *params)
{
    el2go_ota_tls_ctx_t *ctx = NULL;
    el2go_ota_mtls_config_t c = ota_fixture_make_cfg();
    (void)params;
    ota_fixture_reset_net_crypto_wraps();
    g_wrap_net_crypto_new_rc = 1;
    TEST_ASSERT(EL2GO_STATUS_SUCCESS != el2go_ota_tls_init(&ctx, ota_fixture_get_pctx(), &c));
    TEST_ASSERT_NULL(ctx);
    return true;
}

/**
 * @brief Verify tls init configure fail.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_tls_init_configure_fail(void *params)
{
    el2go_ota_tls_ctx_t *ctx = NULL;
    el2go_ota_mtls_config_t c = ota_fixture_make_cfg();
    (void)params;
    ota_fixture_reset_net_crypto_wraps();
    g_wrap_net_crypto_configure_rc = 1;
    TEST_ASSERT(EL2GO_STATUS_SUCCESS != el2go_ota_tls_init(&ctx, ota_fixture_get_pctx(), &c));
    TEST_ASSERT_NULL(ctx);
    return true;
}

/**
 * @brief Verify tls init cert fail.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_tls_init_cert_fail(void *params)
{
    el2go_ota_tls_ctx_t *ctx = NULL;
    el2go_ota_mtls_config_t c = ota_fixture_make_cfg();
    (void)params;
    ota_fixture_reset_net_crypto_wraps();
    g_wrap_net_crypto_set_server_cert_rc = 1;
    TEST_ASSERT(EL2GO_STATUS_SUCCESS != el2go_ota_tls_init(&ctx, ota_fixture_get_pctx(), &c));
    TEST_ASSERT_NULL(ctx);
    return true;
}

/**
 * @brief Verify tls connect null.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_tls_connect_null(void *params)
{
    (void)params;
    TEST_ASSERT_EQUAL(EL2GO_STATUS_INVALID_PARAMETER, el2go_ota_tls_connect(NULL));
    return true;
}

/**
 * @brief Verify tls connect fail.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_tls_connect_fail(void *params)
{
    el2go_ota_tls_ctx_t *ctx = NULL;
    el2go_ota_mtls_config_t c = ota_fixture_make_cfg();
    (void)params;
    ota_fixture_reset_net_crypto_wraps();
    TEST_ASSERT_EQUAL(EL2GO_STATUS_SUCCESS, el2go_ota_tls_init(&ctx, ota_fixture_get_pctx(), &c));
    g_wrap_net_crypto_connect_rc = 1;
    TEST_ASSERT(EL2GO_STATUS_SUCCESS != el2go_ota_tls_connect(ctx));
    el2go_ota_tls_deinit(ctx);
    return true;
}

/**
 * @brief Verify tls connect success.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_tls_connect_success(void *params)
{
    el2go_ota_tls_ctx_t *ctx = NULL;
    el2go_ota_mtls_config_t c = ota_fixture_make_cfg();
    (void)params;
    ota_fixture_reset_net_crypto_wraps();
    TEST_ASSERT_EQUAL(EL2GO_STATUS_SUCCESS, el2go_ota_tls_init(&ctx, ota_fixture_get_pctx(), &c));
    TEST_ASSERT_EQUAL(EL2GO_STATUS_SUCCESS, el2go_ota_tls_connect(ctx));
    el2go_ota_tls_disconnect(ctx);
    el2go_ota_tls_deinit(ctx);
    return true;
}

/**
 * @brief Verify tls disconnect null.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_tls_disconnect_null(void *params)
{
    (void)params;
    el2go_ota_tls_disconnect(NULL);
    return true;
}

/**
 * @brief Verify tls deinit null.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_tls_deinit_null(void *params)
{
    (void)params;
    el2go_ota_tls_deinit(NULL);
    return true;
}

/**
 * @brief Verify tls write null ctx.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_tls_write_null_ctx(void *params)
{
    static const uint8_t buf[4] = { 0 };
    (void)params;
    TEST_ASSERT_EQUAL(EL2GO_STATUS_INVALID_PARAMETER, el2go_ota_tls_write(NULL, buf, sizeof(buf)));
    return true;
}

/**
 * @brief Verify tls write null buf.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_tls_write_null_buf(void *params)
{
    el2go_ota_tls_ctx_t *ctx = NULL;
    el2go_ota_mtls_config_t c = ota_fixture_make_cfg();
    (void)params;
    ota_fixture_reset_net_crypto_wraps();
    TEST_ASSERT_EQUAL(EL2GO_STATUS_SUCCESS, el2go_ota_tls_init(&ctx, ota_fixture_get_pctx(), &c));
    TEST_ASSERT_EQUAL(EL2GO_STATUS_INVALID_PARAMETER, el2go_ota_tls_write(ctx, NULL, 4U));
    el2go_ota_tls_deinit(ctx);
    return true;
}

/**
 * @brief Verify tls write zero len.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_tls_write_zero_len(void *params)
{
    el2go_ota_tls_ctx_t *ctx = NULL;
    el2go_ota_mtls_config_t c = ota_fixture_make_cfg();
    static const uint8_t buf[4] = { 0 };
    (void)params;
    ota_fixture_reset_net_crypto_wraps();
    TEST_ASSERT_EQUAL(EL2GO_STATUS_SUCCESS, el2go_ota_tls_init(&ctx, ota_fixture_get_pctx(), &c));
    TEST_ASSERT_EQUAL(EL2GO_STATUS_INVALID_PARAMETER, el2go_ota_tls_write(ctx, buf, 0U));
    el2go_ota_tls_deinit(ctx);
    return true;
}

/**
 * @brief Verify tls write success.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_tls_write_success(void *params)
{
    el2go_ota_tls_ctx_t *ctx = NULL;
    el2go_ota_mtls_config_t c = ota_fixture_make_cfg();
    static const uint8_t buf[4] = { 1, 2, 3, 4 };
    (void)params;
    ota_fixture_reset_net_crypto_wraps();
    g_wrap_net_crypto_write_rc = (int)sizeof(buf);
    TEST_ASSERT_EQUAL(EL2GO_STATUS_SUCCESS, el2go_ota_tls_init(&ctx, ota_fixture_get_pctx(), &c));
    TEST_ASSERT_EQUAL(EL2GO_STATUS_SUCCESS, el2go_ota_tls_write(ctx, buf, sizeof(buf)));
    el2go_ota_tls_deinit(ctx);
    return true;
}

/**
 * @brief Verify tls write fail.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_tls_write_fail(void *params)
{
    el2go_ota_tls_ctx_t *ctx = NULL;
    el2go_ota_mtls_config_t c = ota_fixture_make_cfg();
    static const uint8_t buf[4] = { 0 };
    (void)params;
    ota_fixture_reset_net_crypto_wraps();
    TEST_ASSERT_EQUAL(EL2GO_STATUS_SUCCESS, el2go_ota_tls_init(&ctx, ota_fixture_get_pctx(), &c));
    g_wrap_net_crypto_write_rc = -1;
    TEST_ASSERT(EL2GO_STATUS_SUCCESS != el2go_ota_tls_write(ctx, buf, sizeof(buf)));
    el2go_ota_tls_deinit(ctx);
    return true;
}

/**
 * @brief Verify tls read null ctx.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_tls_read_null_ctx(void *params)
{
    uint8_t buf[4] = { 0 };
    size_t n = 0U;
    (void)params;
    TEST_ASSERT_EQUAL(EL2GO_STATUS_INVALID_PARAMETER,
                      el2go_ota_tls_read(NULL, buf, sizeof(buf), &n));
    return true;
}

/**
 * @brief Verify tls read null buf.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_tls_read_null_buf(void *params)
{
    el2go_ota_tls_ctx_t *ctx = NULL;
    el2go_ota_mtls_config_t c = ota_fixture_make_cfg();
    size_t n = 0U;
    (void)params;
    ota_fixture_reset_net_crypto_wraps();
    TEST_ASSERT_EQUAL(EL2GO_STATUS_SUCCESS, el2go_ota_tls_init(&ctx, ota_fixture_get_pctx(), &c));
    TEST_ASSERT_EQUAL(EL2GO_STATUS_INVALID_PARAMETER, el2go_ota_tls_read(ctx, NULL, 4U, &n));
    el2go_ota_tls_deinit(ctx);
    return true;
}

/**
 * @brief Verify tls read null out len.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_tls_read_null_out_len(void *params)
{
    el2go_ota_tls_ctx_t *ctx = NULL;
    el2go_ota_mtls_config_t c = ota_fixture_make_cfg();
    uint8_t buf[4] = { 0 };
    (void)params;
    ota_fixture_reset_net_crypto_wraps();
    TEST_ASSERT_EQUAL(EL2GO_STATUS_SUCCESS, el2go_ota_tls_init(&ctx, ota_fixture_get_pctx(), &c));
    TEST_ASSERT_EQUAL(EL2GO_STATUS_INVALID_PARAMETER,
                      el2go_ota_tls_read(ctx, buf, sizeof(buf), NULL));
    el2go_ota_tls_deinit(ctx);
    return true;
}

/**
 * @brief Verify tls read conn closed.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_tls_read_conn_closed(void *params)
{
    el2go_ota_tls_ctx_t *ctx = NULL;
    el2go_ota_mtls_config_t c = ota_fixture_make_cfg();
    uint8_t buf[4] = { 0 };
    size_t n = 0U;
    (void)params;
    ota_fixture_reset_net_crypto_wraps();
    TEST_ASSERT_EQUAL(EL2GO_STATUS_SUCCESS, el2go_ota_tls_init(&ctx, ota_fixture_get_pctx(), &c));
    g_wrap_net_crypto_read_rc = 0;
    TEST_ASSERT(EL2GO_STATUS_SUCCESS != el2go_ota_tls_read(ctx, buf, sizeof(buf), &n));
    el2go_ota_tls_deinit(ctx);
    return true;
}

/**
 * @brief Verify tls init cipher fail.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_tls_init_cipher_fail(void *params)
{
    el2go_ota_tls_ctx_t *ctx = NULL;
    el2go_ota_mtls_config_t c = ota_fixture_make_cfg();
    (void)params;
    ota_fixture_reset_net_crypto_and_psa_wraps();
    g_wrap_net_crypto_set_cipher_suites_rc = 1;
    TEST_ASSERT(EL2GO_STATUS_SUCCESS != el2go_ota_tls_init(&ctx, ota_fixture_get_pctx(), &c));
    TEST_ASSERT_NULL(ctx);
    return true;
}

/**
 * @brief Verify tls init curves fail.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_tls_init_curves_fail(void *params)
{
    el2go_ota_tls_ctx_t *ctx = NULL;
    el2go_ota_mtls_config_t c = ota_fixture_make_cfg();
    (void)params;
    ota_fixture_reset_net_crypto_and_psa_wraps();
    g_wrap_net_crypto_set_curves_rc = 1;
    TEST_ASSERT(EL2GO_STATUS_SUCCESS != el2go_ota_tls_init(&ctx, ota_fixture_get_pctx(), &c));
    TEST_ASSERT_NULL(ctx);
    return true;
}

/**
 * @brief Verify tls init alpn fail.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_tls_init_alpn_fail(void *params)
{
    el2go_ota_tls_ctx_t *ctx = NULL;
    el2go_ota_mtls_config_t c = ota_fixture_make_cfg();
    (void)params;
    ota_fixture_reset_net_crypto_and_psa_wraps();
    g_wrap_net_crypto_set_alpn_rc = 1;
    TEST_ASSERT(EL2GO_STATUS_SUCCESS != el2go_ota_tls_init(&ctx, ota_fixture_get_pctx(), &c));
    TEST_ASSERT_NULL(ctx);
    return true;
}

/**
 * @brief Verify tls init client auth success.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_tls_init_client_auth_success(void *params)
{
    el2go_ota_tls_ctx_t *ctx = NULL;
    el2go_ota_mtls_config_t c = ota_fixture_make_cfg();
    c.client_auth = EL2GO_OTA_CLIENT_AUTH_REQUIRED;
    c.client_cert_object_id = 0x01U;
    c.client_key_object_id = 0x02U;
    (void)params;
    ota_fixture_reset_net_crypto_and_psa_wraps();

    TEST_ASSERT_EQUAL(EL2GO_STATUS_SUCCESS, el2go_ota_tls_init(&ctx, ota_fixture_get_pctx(), &c));
    TEST_ASSERT_NOT_NULL(ctx);
    el2go_ota_tls_deinit(ctx);
    return true;
}

/**
 * @brief Verify tls init client auth cli cert fail.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_tls_init_client_auth_cli_cert_fail(void *params)
{
    el2go_ota_tls_ctx_t *ctx = NULL;
    el2go_ota_mtls_config_t c = ota_fixture_make_cfg();
    c.client_auth = EL2GO_OTA_CLIENT_AUTH_REQUIRED;
    (void)params;
    ota_fixture_reset_net_crypto_and_psa_wraps();
    g_wrap_net_crypto_set_cli_cert_rc = 1;
    TEST_ASSERT(EL2GO_STATUS_SUCCESS != el2go_ota_tls_init(&ctx, ota_fixture_get_pctx(), &c));
    TEST_ASSERT_NULL(ctx);
    return true;
}

/**
 * @brief Verify tls init client auth assoc key fail.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_tls_init_client_auth_assoc_key_fail(void *params)
{
    el2go_ota_tls_ctx_t *ctx = NULL;
    el2go_ota_mtls_config_t c = ota_fixture_make_cfg();
    c.client_auth = EL2GO_OTA_CLIENT_AUTH_REQUIRED;
    (void)params;
    ota_fixture_reset_net_crypto_and_psa_wraps();
    g_wrap_net_crypto_associate_key_rc = 1;
    TEST_ASSERT(EL2GO_STATUS_SUCCESS != el2go_ota_tls_init(&ctx, ota_fixture_get_pctx(), &c));
    TEST_ASSERT_NULL(ctx);
    return true;
}

/**
 * @brief Verify tls write partial.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_tls_write_partial(void *params)
{
    el2go_ota_tls_ctx_t *ctx = NULL;
    el2go_ota_mtls_config_t c = ota_fixture_make_cfg();
    static const uint8_t buf[4] = { 1, 2, 3, 4 };
    (void)params;
    ota_fixture_reset_net_crypto_and_psa_wraps();
    g_wrap_net_crypto_write_rc = 1; /* only 1 byte per call -- triggers retry loop */
    TEST_ASSERT_EQUAL(EL2GO_STATUS_SUCCESS, el2go_ota_tls_init(&ctx, ota_fixture_get_pctx(), &c));
    TEST_ASSERT_EQUAL(EL2GO_STATUS_SUCCESS, el2go_ota_tls_write(ctx, buf, sizeof(buf)));
    el2go_ota_tls_deinit(ctx);
    return true;
}

/**
 * @brief Verify tls read negative.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_tls_read_negative(void *params)
{
    el2go_ota_tls_ctx_t *ctx = NULL;
    el2go_ota_mtls_config_t c = ota_fixture_make_cfg();
    uint8_t buf[4] = { 0 };
    size_t n = 0U;
    (void)params;
    ota_fixture_reset_net_crypto_and_psa_wraps();
    TEST_ASSERT_EQUAL(EL2GO_STATUS_SUCCESS, el2go_ota_tls_init(&ctx, ota_fixture_get_pctx(), &c));
    g_wrap_net_crypto_read_rc = -1; /* negative return -- distinct from 0 (closed) */
    TEST_ASSERT(EL2GO_STATUS_SUCCESS != el2go_ota_tls_read(ctx, buf, sizeof(buf), &n));
    el2go_ota_tls_deinit(ctx);
    return true;
}

/**
 * @brief Verify tls init null platform.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_tls_init_null_platform(void *params)
{
    el2go_ota_tls_ctx_t *ctx = NULL;
    el2go_ota_mtls_config_t c = ota_fixture_make_cfg();
    (void)params;
    ota_fixture_reset_net_crypto_wraps();

    TEST_ASSERT_EQUAL(EL2GO_STATUS_INVALID_PARAMETER, el2go_ota_tls_init(&ctx, NULL, &c));
    TEST_ASSERT_NULL(ctx);
    return true;
}

/**
 * @brief Verify tls connect disconnect.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_tls_connect_disconnect(void *params)
{
    el2go_ota_tls_ctx_t *ctx = NULL;
    el2go_ota_mtls_config_t c = ota_fixture_make_cfg();
    (void)params;
    ota_fixture_reset_net_crypto_wraps();
    TEST_ASSERT_EQUAL(EL2GO_STATUS_SUCCESS, el2go_ota_tls_init(&ctx, ota_fixture_get_pctx(), &c));
    TEST_ASSERT_NOT_NULL(ctx);
    TEST_ASSERT_EQUAL(EL2GO_STATUS_SUCCESS, el2go_ota_tls_connect(ctx));
    el2go_ota_tls_disconnect(ctx);
    /* disconnect again -- exercises the "already disconnected" path */
    el2go_ota_tls_disconnect(ctx);
    el2go_ota_tls_deinit(ctx);
    return true;
}

/* ---- suite registration ------------------------------------------------ */

void register_ota_lib_tls_tests(void)
{
    TEST_REGISTER_ID("13.1", test_ota_tls_init_null_out_ctx);
    TEST_REGISTER_ID("13.2", test_ota_tls_init_null_config);
    TEST_REGISTER_ID("13.3", test_ota_tls_init_success);
    TEST_REGISTER_ID("13.4", test_ota_tls_init_new_fail);
    TEST_REGISTER_ID("13.5", test_ota_tls_init_configure_fail);
    TEST_REGISTER_ID("13.6", test_ota_tls_init_cert_fail);
    TEST_REGISTER_ID("13.7", test_ota_tls_connect_null);
    TEST_REGISTER_ID("13.8", test_ota_tls_connect_fail);
    TEST_REGISTER_ID("13.9", test_ota_tls_connect_success);
    TEST_REGISTER_ID("13.10", test_ota_tls_disconnect_null);
    TEST_REGISTER_ID("13.11", test_ota_tls_deinit_null);
    TEST_REGISTER_ID("13.12", test_ota_tls_write_null_ctx);
    TEST_REGISTER_ID("13.13", test_ota_tls_write_null_buf);
    TEST_REGISTER_ID("13.14", test_ota_tls_write_zero_len);
    TEST_REGISTER_ID("13.15", test_ota_tls_write_success);
    TEST_REGISTER_ID("13.16", test_ota_tls_write_fail);
    TEST_REGISTER_ID("13.17", test_ota_tls_read_null_ctx);
    TEST_REGISTER_ID("13.18", test_ota_tls_read_null_buf);
    TEST_REGISTER_ID("13.19", test_ota_tls_read_null_out_len);
    TEST_REGISTER_ID("13.20", test_ota_tls_read_conn_closed);
    TEST_REGISTER_ID("13.21", test_ota_tls_init_cipher_fail);
    TEST_REGISTER_ID("13.22", test_ota_tls_init_curves_fail);
    TEST_REGISTER_ID("13.23", test_ota_tls_init_alpn_fail);
    TEST_REGISTER_ID("13.24", test_ota_tls_init_client_auth_success);
    TEST_REGISTER_ID("13.25", test_ota_tls_init_client_auth_cli_cert_fail);
    TEST_REGISTER_ID("13.26", test_ota_tls_init_client_auth_assoc_key_fail);
    TEST_REGISTER_ID("13.27", test_ota_tls_write_partial);
    TEST_REGISTER_ID("13.28", test_ota_tls_read_negative);
    TEST_REGISTER_ID("13.29", test_ota_tls_init_null_platform);
    TEST_REGISTER_ID("13.30", test_ota_tls_connect_disconnect);
}
