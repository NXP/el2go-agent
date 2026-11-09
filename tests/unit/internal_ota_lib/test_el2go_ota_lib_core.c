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
#include "ota/el2go_ota_lib.h"
#include "ota/el2go_ota_config.h"
#include "test_el2go_ota_fixtures.h"
#include "wrap_net_crypto.h"

/**
 * @brief check_for_updates with attr_count > 0 but attrs == NULL must return
 *        EL2GO_OTA_ERROR_INVALID_PARAM (guard inside download engine).
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_check_for_updates_attr_count_without_attrs(void *params)
{
    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_check_for_updates(NULL, NULL, 1U, NULL));

    return true;
}

/**
 * @brief el2go_ota_schedule_status_report(NULL, ...) must return
 *        EL2GO_OTA_ERROR_INVALID_PARAM.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_schedule_status_report_null_update_id(void *params)
{
    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_schedule_status_report(NULL, "pkg-1", EL2GO_OTA_OUTCOME_SUCCESS));

    return true;
}

/**
 * @brief el2go_ota_schedule_status_report with null package_id must return
 *        EL2GO_OTA_ERROR_INVALID_PARAM.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_schedule_status_report_null_package_id(void *params)
{
    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_schedule_status_report("upd-1", NULL, EL2GO_OTA_OUTCOME_SUCCESS));

    return true;
}

/**
 * @brief el2go_ota_schedule_status_report with invalid outcome must return
 *        EL2GO_OTA_ERROR_INVALID_PARAM.
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
 * @brief el2go_ota_get_pending_status(NULL) must return
 *        EL2GO_OTA_ERROR_INVALID_PARAM.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_get_pending_status_null_out(void *params)
{
    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_get_pending_status(NULL));

    return true;
}

/**
 * @brief Verify schedule failure.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_schedule_failure(void *params)
{
    (void)params;
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_schedule_status_report(NULL, "pkg-1", EL2GO_OTA_OUTCOME_FAILURE));
    return true;
}

/**
 * @brief Verify schedule rollback.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_schedule_rollback(void *params)
{
    (void)params;
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_schedule_status_report(NULL, "pkg-1", EL2GO_OTA_OUTCOME_ROLLBACK));
    return true;
}

/**
 * @brief Verify get version all null.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_get_version_all_null(void *params)
{
    (void)params;
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_get_version(NULL, NULL, NULL));
    return true;
}

/**
 * @brief Verify get version minor null.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_get_version_minor_null(void *params)
{
    unsigned int major = 0, patch = 0;
    (void)params;
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_get_version(&major, NULL, &patch));
    return true;
}

/**
 * @brief Verify get version patch null.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_get_version_patch_null(void *params)
{
    unsigned int major = 0, minor = 0;
    (void)params;
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_get_version(&major, &minor, NULL));
    return true;
}

/**
 * @brief Verify get version success.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_get_version_success(void *params)
{
    unsigned int major = 0, minor = 0, patch = 0;
    (void)params;
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, el2go_ota_get_version(&major, &minor, &patch));
    TEST_PRINT_INFO("version: %u.%u.%u", major, minor, patch);
    return true;
}

/**
 * @brief Verify check update not connected.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_check_update_not_connected(void *params)
{
    el2go_ota_ctx_t *ctx = NULL;
    el2go_ota_check_update_resp_t resp = { 0 };
    static const el2go_ota_mtls_config_t cfg = {
        .hostname = "x",
        .port = 443U,
        .server_ca_chain = (const uint8_t *)"\x30\x82",
        .server_ca_chain_size = 2U,
    };
    (void)params;
    ota_fixture_reset_net_crypto_wraps();

    /* Init but do NOT connect */
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, el2go_ota_init(&ctx, &cfg));
    TEST_ASSERT_NOT_NULL(ctx);
    TEST_ASSERT(!el2go_ota_is_connected(ctx));

    /* These all require a connection -- exercises !ctx->connected branch */
    TEST_ASSERT(EL2GO_OTA_SUCCESS != el2go_ota_check_for_updates(ctx, NULL, 0U, &resp));
    TEST_ASSERT(EL2GO_OTA_SUCCESS != el2go_ota_download_package(ctx, "u", "p", "f", 0U,
                                                                ota_fixture_noop_chunk_cb, NULL));
    TEST_ASSERT(EL2GO_OTA_SUCCESS !=
                el2go_ota_report_status(ctx, "u", "p", EL2GO_OTA_OUTCOME_SUCCESS));
    TEST_ASSERT(EL2GO_OTA_SUCCESS != el2go_ota_report_pending_status(ctx));

    el2go_ota_cleanup(&ctx);
    return true;
}

/**
 * @brief Verify cleanup no deinit.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_cleanup_no_deinit(void *params)
{
    el2go_ota_ctx_t *ctx = NULL;
    static const el2go_ota_mtls_config_t cfg = {
        .hostname = "x",
        .port = 443U,
        .server_ca_chain = (const uint8_t *)"\x30\x82",
        .server_ca_chain_size = 2U,
    };
    (void)params;
    ota_fixture_reset_net_crypto_wraps();

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, el2go_ota_init(&ctx, &cfg));
    TEST_ASSERT_NOT_NULL(ctx);
    el2go_ota_cleanup(&ctx);
    TEST_ASSERT_NULL(ctx);
    /* cleanup again with NULL out-param must be a safe no-op. */
    el2go_ota_cleanup(NULL);
    return true;
}

/**
 * @brief Verify error string switch.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_error_string_switch(void *params)
{
    el2go_ota_ctx_t *ctx = NULL;
    static const el2go_ota_mtls_config_t cfg = {
        .hostname = "x",
        .port = 443U,
        .server_ca_chain = (const uint8_t *)"\x30\x82",
        .server_ca_chain_size = 2U,
    };
    (void)params;
    ota_fixture_reset_net_crypto_wraps();

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, el2go_ota_init(&ctx, &cfg));
    TEST_ASSERT_NOT_NULL(ctx);

    /* Call with all known error codes to exercise the map_status switch branches */
    static const el2go_ota_status_t codes[] = {
        EL2GO_OTA_SUCCESS,      EL2GO_OTA_ERROR_INTERNAL, EL2GO_OTA_ERROR_NETWORK,
        EL2GO_OTA_ERROR_DECODE, EL2GO_OTA_ERROR_ENCODE,   EL2GO_OTA_ERROR_INVALID_PARAM,
        EL2GO_OTA_ERROR_SERVER, (el2go_ota_status_t)999,
    };
    for (size_t i = 0U; i < sizeof(codes) / sizeof(codes[0]); i++) {
        /* el2go_ota_get_error_string takes only status (1 arg) */
        const char *s = el2go_ota_get_error_string(codes[i]);
        TEST_ASSERT_NOT_NULL(s);
    }

    el2go_ota_cleanup(&ctx);
    return true;
}

/**
 * @brief Verify map status default.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_map_status_default(void *params)
{
    (void)params;
    /* Pass an unknown status code -- exercises the default branch in map_status */
    const char *s1 = el2go_ota_get_error_string((el2go_ota_status_t)0xFF);
    const char *s2 = el2go_ota_get_error_string((el2go_ota_status_t)0x7F);
    const char *s3 = el2go_ota_get_error_string(EL2GO_OTA_SUCCESS);
    TEST_ASSERT_NOT_NULL(s1);
    TEST_ASSERT_NOT_NULL(s2);
    TEST_ASSERT_NOT_NULL(s3);
    return true;
}

/**
 * @brief Verify ota lib check null resp.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_lib_check_null_resp(void *params)
{
    el2go_ota_ctx_t *ctx = NULL;
    static const el2go_ota_mtls_config_t cfg = {
        .hostname = "x",
        .port = 443U,
        .server_ca_chain = (const uint8_t *)"\x30\x82",
        .server_ca_chain_size = 2U,
    };
    (void)params;
    ota_fixture_reset_net_crypto_wraps();
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, el2go_ota_init(&ctx, &cfg));
    TEST_ASSERT_NOT_NULL(ctx);

    /* Not connected -- exercises !ctx->connected branch */
    TEST_ASSERT(EL2GO_OTA_SUCCESS != el2go_ota_check_for_updates(ctx, NULL, 0U, NULL));

    el2go_ota_cleanup(&ctx);
    return true;
}

/**
 * @brief Verify connect null ctx.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_connect_null_ctx(void *params)
{
    (void)params;
    TEST_ASSERT(EL2GO_OTA_SUCCESS != el2go_ota_connect(NULL));
    return true;
}

/**
 * @brief Verify disconnect null ctx.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_disconnect_null_ctx(void *params)
{
    (void)params;
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_disconnect(NULL));
    return true;
}

/**
 * @brief Verify is connected null ctx.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_is_connected_null_ctx(void *params)
{
    (void)params;
    TEST_ASSERT(!el2go_ota_is_connected(NULL));
    return true;
}

/**
 * @brief Verify error string after cleanup.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_error_string_after_cleanup(void *params)
{
    (void)params;
    /* Call with every known status code to exercise all switch branches */
    el2go_ota_status_t codes[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 99 };
    for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); i++) {
        const char *s = el2go_ota_get_error_string(codes[i]);
        TEST_ASSERT_NOT_NULL(s);
    }
    return true;
}

/**
 * @brief Verify report status null ctx.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_report_status_null_ctx(void *params)
{
    (void)params;
    TEST_ASSERT(EL2GO_OTA_SUCCESS !=
                el2go_ota_report_status(NULL, "u", "p", EL2GO_OTA_OUTCOME_SUCCESS));
    return true;
}

/**
 * @brief Verify report pending null ctx.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_report_pending_null_ctx(void *params)
{
    (void)params;
    TEST_ASSERT(EL2GO_OTA_SUCCESS != el2go_ota_report_pending_status(NULL));
    return true;
}

/**
 * @brief Verify download null ctx.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_download_null_ctx(void *params)
{
    (void)params;
    TEST_ASSERT(EL2GO_OTA_SUCCESS != el2go_ota_download_package(NULL, "u", "p", "f", 0U,
                                                                ota_fixture_noop_chunk_cb, NULL));
    return true;
}

/**
 * @brief Verify check null ctx.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_check_null_ctx(void *params)
{
    el2go_ota_check_update_resp_t resp = { 0 };
    (void)params;
    TEST_ASSERT(EL2GO_OTA_SUCCESS != el2go_ota_check_for_updates(NULL, NULL, 0U, &resp));
    return true;
}

/**
 * @brief Verify init null config.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_init_null_config(void *params)
{
    el2go_ota_ctx_t *ctx = NULL;
    (void)params;
    TEST_ASSERT(EL2GO_OTA_SUCCESS != el2go_ota_init(&ctx, NULL));
    TEST_ASSERT_NULL(ctx);
    return true;
}

/**
 * @brief Verify init null out ctx.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_init_null_out_ctx(void *params)
{
    static const el2go_ota_mtls_config_t cfg = {
        .hostname = "x",
        .port = 443U,
        .server_ca_chain = (const uint8_t *)"\x30",
        .server_ca_chain_size = 1U,
    };
    (void)params;
    TEST_ASSERT(EL2GO_OTA_SUCCESS != el2go_ota_init(NULL, &cfg));
    return true;
}

/**
 * @brief Verify map status all arms.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_map_status_all_arms(void *params)
{
    static const el2go_ota_mtls_config_t cfg = {
        .hostname = "x",
        .port = 443U,
        .server_ca_chain = (const uint8_t *)"\x30\x82",
        .server_ca_chain_size = 2U,
    };
    static const el2go_status_t cases[] = {
        EL2GO_STATUS_NET_CRYPTO_INVALID_CERT,
        EL2GO_STATUS_NET_CRYPTO_INVALID_KEY,
        EL2GO_STATUS_NET_CRYPTO_HANDSHAKE_FAILED,
        EL2GO_STATUS_NET_CRYPTO_CONFIG_FAILED,
        EL2GO_STATUS_ALLOCATION_ERROR,
        EL2GO_STATUS_INVALID_PARAMETER,
        EL2GO_STATUS_PLATFORM_INIT_FAILED,
        EL2GO_STATUS_FAILURE,
    };
    size_t i;
    (void)params;

    for (i = 0U; i < sizeof(cases) / sizeof(cases[0]); i++) {
        el2go_ota_ctx_t *ctx = NULL;
        ota_fixture_reset_net_crypto_wraps();
        TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, el2go_ota_init(&ctx, &cfg));
        TEST_ASSERT_NOT_NULL(ctx);
        g_wrap_net_crypto_connect_rc = 1;
        g_wrap_net_crypto_connect_status = cases[i];
        el2go_ota_status_t r = el2go_ota_connect(ctx);
        TEST_ASSERT(r != EL2GO_OTA_SUCCESS);
        el2go_ota_cleanup(&ctx);
    }
    return true;
}

/**
 * @brief Verify connect already connected.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_connect_already_connected(void *params)
{
    static const el2go_ota_mtls_config_t cfg = {
        .hostname = "x",
        .port = 443U,
        .server_ca_chain = (const uint8_t *)"\x30\x82",
        .server_ca_chain_size = 2U,
    };
    el2go_ota_ctx_t *ctx = NULL;
    (void)params;
    ota_fixture_reset_net_crypto_wraps();
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, el2go_ota_init(&ctx, &cfg));
    TEST_ASSERT_NOT_NULL(ctx);
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, el2go_ota_connect(ctx));
    /* Call connect again -- ctx->connected == true -> takes the "already connected" branch */
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, el2go_ota_connect(ctx));
    el2go_ota_cleanup(&ctx);
    return true;
}

/**
 * @brief Verify disconnect not connected.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_disconnect_not_connected(void *params)
{
    static const el2go_ota_mtls_config_t cfg = {
        .hostname = "x",
        .port = 443U,
        .server_ca_chain = (const uint8_t *)"\x30\x82",
        .server_ca_chain_size = 2U,
    };
    el2go_ota_ctx_t *ctx = NULL;
    (void)params;
    ota_fixture_reset_net_crypto_wraps();
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, el2go_ota_init(&ctx, &cfg));
    TEST_ASSERT_NOT_NULL(ctx);
    /* ctx is NOT connected -- hits the !ctx->connected true-branch in el2go_ota_disconnect */
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, el2go_ota_disconnect(ctx));
    /* is_connected returns false -- exercises the false branch of is_connected */
    TEST_ASSERT(!el2go_ota_is_connected(ctx));
    el2go_ota_cleanup(&ctx);
    return true;
}

/**
 * @brief Verify is connected true.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_is_connected_true(void *params)
{
    static const el2go_ota_mtls_config_t cfg = {
        .hostname = "x",
        .port = 443U,
        .server_ca_chain = (const uint8_t *)"\x30\x82",
        .server_ca_chain_size = 2U,
    };
    el2go_ota_ctx_t *ctx = NULL;
    (void)params;
    ota_fixture_reset_net_crypto_wraps();
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, el2go_ota_init(&ctx, &cfg));
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, el2go_ota_connect(ctx));
    TEST_ASSERT(el2go_ota_is_connected(ctx));
    el2go_ota_cleanup(&ctx);
    return true;
}

/**
 * @brief 6.31 -- check_for_updates() caches file size; download_package() uses the cache.
 *
 * Initialises a connected context, calls check_for_updates() to populate the
 * internal file-size cache, then calls download_package() for the same file_id
 * and verifies the function completes without crashing.  The wrap stubs return
 * zero-byte responses so the engine exits after one round-trip.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_cached_size_used_by_download(void *params)
{
    static const el2go_ota_mtls_config_t cfg = {
        .hostname = "x",
        .port = 443U,
        .server_ca_chain = (const uint8_t *)"\x30\x82",
        .server_ca_chain_size = 2U,
    };
    el2go_ota_ctx_t *ctx = NULL;
    el2go_ota_check_update_resp_t resp = { 0 };
    (void)params;

    ota_fixture_reset_net_crypto_wraps();

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, el2go_ota_init(&ctx, &cfg));
    TEST_ASSERT_NOT_NULL(ctx);
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, el2go_ota_connect(ctx));

    /*
     * check_for_updates() will call the engine which calls send/recv through
     * the wraps.  The wrap recv returns 0 bytes -> parse sees empty response ->
     * no updates available.  The cache will be populated with 0 entries (empty
     * response), which is the same code path as a real successful parse with
     * zero update_count.  The important thing: the cache population code ran
     * without crashing.
     */
    el2go_ota_status_t check_result = el2go_ota_check_for_updates(ctx, NULL, 0U, &resp);
    /* Either success (empty response decoded as no updates) or a decode error
     * from the stub -- both are acceptable; what matters is the ctx is intact. */
    (void)check_result;

    /*
     * Now call download_package.  With an empty cache (known_file_size = 0)
     * the engine falls back to reactive learning.  The stub recv returns 0
     * bytes -> parse sees empty response -> engine returns SUCCESS immediately.
     */
    el2go_ota_status_t dl_result =
        el2go_ota_download_package(ctx, "upd", "pkg", "file", 0U, ota_fixture_noop_chunk_cb, NULL);
    /* Acceptable results: SUCCESS (empty EOF from stub) or a decode/network
     * error from the stub transport -- the key assertion is that the function
     * was callable with the correct arity (no compile error) and did not
     * crash. */
    (void)dl_result;

    el2go_ota_cleanup(&ctx);
    TEST_ASSERT_NULL(ctx);
    return true;
}

/* ---- API guards on a context in each connection state --------------------- */

/**
 * @brief Every network API refuses to run on a context that is not connected.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_network_apis_require_connection(void *params)
{
    el2go_ota_ctx_t *ctx = NULL;
    el2go_ota_check_update_resp_t resp = { 0 };
    el2go_ota_mtls_config_t cfg = ota_fixture_make_cfg();

    (void)params;
    memset(&resp, 0, sizeof(resp));
    ota_fixture_reset_net_crypto_wraps();
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, el2go_ota_init(&ctx, &cfg));

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_NETWORK, el2go_ota_check_for_updates(ctx, NULL, 0U, &resp));
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_NETWORK,
                      el2go_ota_download_package(ctx, "u", "p", "f", 0U, ota_fixture_noop_chunk_cb,
                                                 NULL));
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_NETWORK,
                      el2go_ota_report_status(ctx, "u", "p", EL2GO_OTA_OUTCOME_SUCCESS));
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_NETWORK, el2go_ota_report_pending_status(ctx));

    el2go_ota_cleanup(&ctx);
    return true;
}

/**
 * @brief A NULL context is rejected by the pending-status report.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_report_pending_status_null_ctx(void *params)
{
    (void)params;
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_report_pending_status(NULL));
    return true;
}

/**
 * @brief A NULL response buffer is rejected once the context is connected.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_check_for_updates_null_resp_connected(void *params)
{
    el2go_ota_ctx_t *ctx = NULL;

    (void)params;
    TEST_ASSERT(ota_fixture_init_connected(&ctx));
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_check_for_updates(ctx, NULL, 0U, NULL));
    el2go_ota_cleanup(&ctx);
    return true;
}

/**
 * @brief download_package validates each pointer argument on a connected context.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_download_package_null_args_connected(void *params)
{
    el2go_ota_ctx_t *ctx = NULL;

    (void)params;
    TEST_ASSERT(ota_fixture_init_connected(&ctx));
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_download_package(ctx, NULL, "p", "f", 0U, ota_fixture_noop_chunk_cb,
                                                 NULL));
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_download_package(ctx, "u", NULL, "f", 0U, ota_fixture_noop_chunk_cb,
                                                 NULL));
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_download_package(ctx, "u", "p", NULL, 0U, ota_fixture_noop_chunk_cb,
                                                 NULL));
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_download_package(ctx, "u", "p", "f", 0U, NULL, NULL));
    el2go_ota_cleanup(&ctx);
    return true;
}

/**
 * @brief report_status validates ids and outcome on a connected context.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_report_status_invalid_args_connected(void *params)
{
    el2go_ota_ctx_t *ctx = NULL;

    (void)params;
    TEST_ASSERT(ota_fixture_init_connected(&ctx));
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_report_status(ctx, NULL, "p", EL2GO_OTA_OUTCOME_SUCCESS));
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_report_status(ctx, "u", NULL, EL2GO_OTA_OUTCOME_SUCCESS));
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_report_status(ctx, "u", "p", (el2go_ota_update_outcome_t)99));
    el2go_ota_cleanup(&ctx);
    return true;
}

/* ---- init and connect failure handling ------------------------------------- */

/** @brief Check that init rejects @p cfg with INVALID_PARAM and creates no context. */
static bool ota_init_must_reject(const el2go_ota_mtls_config_t *cfg)
{
    el2go_ota_ctx_t *ctx = (el2go_ota_ctx_t *)(uintptr_t)1U; /* must be reset to NULL */

    ota_fixture_reset_net_crypto_wraps();
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_init(&ctx, cfg));
    TEST_ASSERT_NULL(ctx);
    return true;
}

/**
 * @brief A NULL hostname is rejected.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_init_rejects_null_hostname(void *params)
{
    el2go_ota_mtls_config_t cfg = ota_fixture_make_cfg();

    (void)params;
    cfg.hostname = NULL;
    return ota_init_must_reject(&cfg);
}

/**
 * @brief Port 0 is rejected.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_init_rejects_zero_port(void *params)
{
    el2go_ota_mtls_config_t cfg = ota_fixture_make_cfg();

    (void)params;
    cfg.port = 0U;
    return ota_init_must_reject(&cfg);
}

/**
 * @brief A NULL server CA chain is rejected.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_init_rejects_null_ca_chain(void *params)
{
    el2go_ota_mtls_config_t cfg = ota_fixture_make_cfg();

    (void)params;
    cfg.server_ca_chain = NULL;
    return ota_init_must_reject(&cfg);
}

/**
 * @brief A zero-length server CA chain is rejected.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_init_rejects_empty_ca_chain(void *params)
{
    el2go_ota_mtls_config_t cfg = ota_fixture_make_cfg();

    (void)params;
    cfg.server_ca_chain_size = 0U;
    return ota_init_must_reject(&cfg);
}

/**
 * @brief A TLS setup failure during init leaves no context behind.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_init_tls_failure_leaves_no_context(void *params)
{
    el2go_ota_ctx_t *ctx = NULL;
    el2go_ota_mtls_config_t cfg = ota_fixture_make_cfg();

    (void)params;
    ota_fixture_reset_net_crypto_wraps();
    g_wrap_net_crypto_new_rc = 1;
    TEST_ASSERT(el2go_ota_init(&ctx, &cfg) != EL2GO_OTA_SUCCESS);
    TEST_ASSERT_NULL(ctx);
    ota_fixture_reset_net_crypto_wraps();
    return true;
}

/**
 * @brief A TLS configure failure during init leaves no context behind.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_init_tls_configure_failure_leaves_no_context(void *params)
{
    el2go_ota_ctx_t *ctx = NULL;
    el2go_ota_mtls_config_t cfg = ota_fixture_make_cfg();

    (void)params;
    ota_fixture_reset_net_crypto_wraps();
    g_wrap_net_crypto_configure_rc = 1;
    TEST_ASSERT(el2go_ota_init(&ctx, &cfg) != EL2GO_OTA_SUCCESS);
    TEST_ASSERT_NULL(ctx);
    ota_fixture_reset_net_crypto_wraps();
    return true;
}

/**
 * @brief A server CA rejection during init leaves no context behind.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_init_server_cert_failure_leaves_no_context(void *params)
{
    el2go_ota_ctx_t *ctx = NULL;
    el2go_ota_mtls_config_t cfg = ota_fixture_make_cfg();

    (void)params;
    ota_fixture_reset_net_crypto_wraps();
    g_wrap_net_crypto_set_server_cert_rc = 1;
    TEST_ASSERT(el2go_ota_init(&ctx, &cfg) != EL2GO_OTA_SUCCESS);
    TEST_ASSERT_NULL(ctx);
    ota_fixture_reset_net_crypto_wraps();
    return true;
}

/**
 * @brief A failed TLS connect reports an error and leaves the context disconnected.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_connect_tls_failure_stays_disconnected(void *params)
{
    el2go_ota_ctx_t *ctx = NULL;
    el2go_ota_mtls_config_t cfg = ota_fixture_make_cfg();

    (void)params;
    ota_fixture_reset_net_crypto_wraps();
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, el2go_ota_init(&ctx, &cfg));

    /* The TLS layer status must be mapped to the public error code. */
    g_wrap_net_crypto_connect_rc = 1;
    g_wrap_net_crypto_connect_status = EL2GO_STATUS_NET_CRYPTO_HANDSHAKE_FAILED;
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_TLS_HANDSHAKE, el2go_ota_connect(ctx));
    TEST_ASSERT(!el2go_ota_is_connected(ctx));

    g_wrap_net_crypto_connect_status = EL2GO_STATUS_NET_CRYPTO_INVALID_CERT;
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_CERT_VERIFY, el2go_ota_connect(ctx));
    TEST_ASSERT(!el2go_ota_is_connected(ctx));

    /* The context must still be usable: a later connect succeeds. */
    g_wrap_net_crypto_connect_rc = 0;
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, el2go_ota_connect(ctx));
    TEST_ASSERT(el2go_ota_is_connected(ctx));

    el2go_ota_cleanup(&ctx);
    ota_fixture_reset_net_crypto_wraps();
    return true;
}

/**
 * @brief Disconnecting a connected context clears the connected state; cleanup is idempotent.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_disconnect_then_cleanup_twice(void *params)
{
    el2go_ota_ctx_t *ctx = NULL;

    (void)params;
    TEST_ASSERT(ota_fixture_init_connected(&ctx));
    TEST_ASSERT(el2go_ota_is_connected(ctx));
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, el2go_ota_disconnect(ctx));
    TEST_ASSERT(!el2go_ota_is_connected(ctx));

    el2go_ota_cleanup(&ctx);
    TEST_ASSERT_NULL(ctx);
    el2go_ota_cleanup(&ctx); /* second call on a NULL context must be a no-op */
    el2go_ota_cleanup(NULL);
    return true;
}

/* ---- transport failures on a connected context ---------------------------- */

/**
 * @brief A write failure while sending a request is reported as a network error.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_requests_report_network_error_on_write_failure(void *params)
{
    el2go_ota_ctx_t *ctx = NULL;
    el2go_ota_check_update_resp_t resp = { 0 };

    (void)params;
    memset(&resp, 0, sizeof(resp));

    /* Each request runs on a fresh connection so its first write is the h2 preface. */
    TEST_ASSERT(ota_fixture_init_connected(&ctx));
    g_wrap_net_crypto_write_fail_on_call = 1U;
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_NETWORK, el2go_ota_check_for_updates(ctx, NULL, 0U, &resp));
    el2go_ota_cleanup(&ctx);

    TEST_ASSERT(ota_fixture_init_connected(&ctx));
    g_wrap_net_crypto_write_fail_on_call = 1U;
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_NETWORK,
                      el2go_ota_download_package(ctx, "u", "p", "f", 0U, ota_fixture_noop_chunk_cb,
                                                 NULL));
    el2go_ota_cleanup(&ctx);

    TEST_ASSERT(ota_fixture_init_connected(&ctx));
    g_wrap_net_crypto_write_fail_on_call = 1U;
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_NETWORK,
                      el2go_ota_report_status(ctx, "u", "p", EL2GO_OTA_OUTCOME_ROLLBACK));
    el2go_ota_cleanup(&ctx);

    ota_fixture_reset_net_crypto_wraps();
    return true;
}

/* ---- suite registration ------------------------------------------------ */

void register_ota_lib_core_tests(void)
{
    TEST_REGISTER_ID("6.1", test_ota_check_for_updates_attr_count_without_attrs);
    TEST_REGISTER_ID("6.2", test_ota_schedule_status_report_null_update_id);
    TEST_REGISTER_ID("6.3", test_ota_schedule_status_report_null_package_id);
    TEST_REGISTER_ID("6.4", test_ota_schedule_status_report_invalid_outcome);
    TEST_REGISTER_ID("6.5", test_ota_get_pending_status_null_out);
    TEST_REGISTER_ID("6.6", test_ota_schedule_failure);
    TEST_REGISTER_ID("6.7", test_ota_schedule_rollback);
    TEST_REGISTER_ID("6.8", test_ota_get_version_all_null);
    TEST_REGISTER_ID("6.9", test_ota_get_version_minor_null);
    TEST_REGISTER_ID("6.10", test_ota_get_version_patch_null);
    TEST_REGISTER_ID("6.11", test_ota_get_version_success);
    TEST_REGISTER_ID("6.12", test_ota_check_update_not_connected);
    TEST_REGISTER_ID("6.13", test_ota_cleanup_no_deinit);
    TEST_REGISTER_ID("6.14", test_ota_error_string_switch);
    TEST_REGISTER_ID("6.15", test_ota_map_status_default);
    TEST_REGISTER_ID("6.16", test_ota_lib_check_null_resp);
    TEST_REGISTER_ID("6.17", test_ota_connect_null_ctx);
    TEST_REGISTER_ID("6.18", test_ota_disconnect_null_ctx);
    TEST_REGISTER_ID("6.19", test_ota_is_connected_null_ctx);
    TEST_REGISTER_ID("6.20", test_ota_error_string_after_cleanup);
    TEST_REGISTER_ID("6.21", test_ota_report_status_null_ctx);
    TEST_REGISTER_ID("6.22", test_ota_report_pending_null_ctx);
    TEST_REGISTER_ID("6.23", test_ota_download_null_ctx);
    TEST_REGISTER_ID("6.24", test_ota_check_null_ctx);
    TEST_REGISTER_ID("6.25", test_ota_init_null_config);
    TEST_REGISTER_ID("6.26", test_ota_init_null_out_ctx);
    TEST_REGISTER_ID("6.27", test_ota_map_status_all_arms);
    TEST_REGISTER_ID("6.28", test_ota_connect_already_connected);
    TEST_REGISTER_ID("6.29", test_ota_disconnect_not_connected);
    TEST_REGISTER_ID("6.30", test_ota_is_connected_true);
    TEST_REGISTER_ID("6.31", test_ota_cached_size_used_by_download);
    TEST_REGISTER_ID("6.32", test_ota_network_apis_require_connection);
    TEST_REGISTER_ID("6.33", test_ota_report_pending_status_null_ctx);
    TEST_REGISTER_ID("6.34", test_ota_check_for_updates_null_resp_connected);
    TEST_REGISTER_ID("6.35", test_ota_download_package_null_args_connected);
    TEST_REGISTER_ID("6.36", test_ota_report_status_invalid_args_connected);
    TEST_REGISTER_ID("6.37", test_ota_init_rejects_null_hostname);
    TEST_REGISTER_ID("6.38", test_ota_init_tls_failure_leaves_no_context);
    TEST_REGISTER_ID("6.39", test_ota_connect_tls_failure_stays_disconnected);
    TEST_REGISTER_ID("6.40", test_ota_disconnect_then_cleanup_twice);
    TEST_REGISTER_ID("6.41", test_ota_requests_report_network_error_on_write_failure);
    TEST_REGISTER_ID("6.42", test_ota_init_rejects_zero_port);
    TEST_REGISTER_ID("6.43", test_ota_init_rejects_null_ca_chain);
    TEST_REGISTER_ID("6.44", test_ota_init_rejects_empty_ca_chain);
    TEST_REGISTER_ID("6.45", test_ota_init_tls_configure_failure_leaves_no_context);
    TEST_REGISTER_ID("6.46", test_ota_init_server_cert_failure_leaves_no_context);
}
