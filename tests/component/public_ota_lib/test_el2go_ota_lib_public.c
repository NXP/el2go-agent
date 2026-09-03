/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "test_el2go_ota_lib_public.h"

#include "ota/el2go_ota_lib.h"
#include "ota/el2go_ota_config.h"

/* Optional live-server config hook; weak default returns NULL (bodies skip). */
__attribute__((weak)) const el2go_ota_mtls_config_t *ct_server_config(void)
{
    return NULL;
}

/* ---- portable-everywhere: parameter validation ------------------------ */

/* el2go_ota_init() rejects NULL ctx / NULL config. */
static test_result_t test_ol_init_null_params(void)
{
    el2go_ota_ctx_t *ctx = NULL;
    el2go_ota_mtls_config_t cfg = { 0 };

    TEST_ASSERT_EQ(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_init(NULL, &cfg));
    TEST_ASSERT_EQ(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_init(&ctx, NULL));
    TEST_ASSERT_NULL(ctx);
    return TEST_PASS;
}

/* el2go_ota_init() rejects a config with missing required fields. */
static test_result_t test_ol_init_invalid_config(void)
{
    el2go_ota_ctx_t *ctx = NULL;
    /* All zero: hostname NULL, port 0, ca chain NULL -> invalid param. */
    el2go_ota_mtls_config_t cfg = { 0 };

    TEST_ASSERT_EQ(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_init(&ctx, &cfg));
    TEST_ASSERT_NULL(ctx);
    return TEST_PASS;
}

/* el2go_ota_is_connected(NULL) is false; never crashes. */
static test_result_t test_ol_is_connected_null(void)
{
    TEST_ASSERT_FALSE(el2go_ota_is_connected(NULL));
    return TEST_PASS;
}

/* el2go_ota_get_error_string() returns a non-NULL string for every code. */
static test_result_t test_ol_error_string_never_null(void)
{
    int code;

    for (code = (int)EL2GO_OTA_SUCCESS; code <= (int)EL2GO_OTA_ERROR_INTERNAL; code++) {
        const char *msg = el2go_ota_get_error_string((el2go_ota_status_t)code);

        TEST_ASSERT_NOT_NULL(msg);
    }
    return TEST_PASS;
}

/* Public API entry points reject NULL ctx without crashing. */
static test_result_t test_ol_public_api_null_ctx(void)
{
    el2go_ota_check_update_resp_t resp = { 0 };

    TEST_ASSERT_EQ(EL2GO_OTA_ERROR_INVALID_PARAM,
                   el2go_ota_check_for_updates(NULL, NULL, 0U, &resp));
    TEST_ASSERT_EQ(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_connect(NULL));
    TEST_ASSERT_EQ(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_disconnect(NULL));
    TEST_ASSERT_EQ(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_report_pending_status(NULL));
    return TEST_PASS;
}

/* ---- promoted-live: init + connect over real mutual TLS ---------------- */

/* OTA_CT_OL_1.1: init + connect against a real OTA server over mutual TLS. */
static test_result_t test_ol_init_connect_real_tls(void)
{
    const el2go_ota_mtls_config_t *cfg;
    el2go_ota_ctx_t *ctx = NULL;
    el2go_ota_status_t s;

    TEST_REQUIRE_CAP(CT_CAP_REAL_TLS);

    cfg = ct_server_config();
    if (cfg == NULL) {
        TEST_SKIP_WITH("no live OTA server configured for this target");
    }

    s = el2go_ota_init(&ctx, cfg);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, s);
    TEST_ASSERT_NOT_NULL(ctx);

    s = el2go_ota_connect(ctx);
    TEST_ASSERT_EQ(EL2GO_OTA_SUCCESS, s);
    TEST_ASSERT_TRUE(el2go_ota_is_connected(ctx));

    (void)el2go_ota_disconnect(ctx);
    el2go_ota_cleanup(&ctx);
    TEST_ASSERT_NULL(ctx);
    return TEST_PASS;
}

/* OTA_CT_OL_1.2: connect must fail when the server cert does not chain to the CA. */
static test_result_t test_ol_connect_invalid_ca_rejected(void)
{
    const el2go_ota_mtls_config_t *base;
    el2go_ota_mtls_config_t bad;
    static const uint8_t bogus_ca[] = { 0x30, 0x00 };
    el2go_ota_ctx_t *ctx = NULL;
    el2go_ota_status_t s;

    TEST_REQUIRE_CAP(CT_CAP_REAL_TLS);

    base = ct_server_config();
    if (base == NULL) {
        TEST_SKIP_WITH("no live OTA server configured for this target");
    }

    bad = *base;
    bad.server_ca_chain = bogus_ca;
    bad.server_ca_chain_size = sizeof(bogus_ca);

    s = el2go_ota_init(&ctx, &bad);
    if (s == EL2GO_OTA_SUCCESS) {
        s = el2go_ota_connect(ctx);
        TEST_ASSERT_NE(EL2GO_OTA_SUCCESS, s);
        TEST_ASSERT_FALSE(el2go_ota_is_connected(ctx));
    } else {
        TEST_ASSERT_NE(EL2GO_OTA_SUCCESS, s);
    }

    el2go_ota_cleanup(&ctx);
    return TEST_PASS;
}

/* ---- suite table ------------------------------------------------------- */

TEST_SUITE_BEGIN(ota_lib_public)
TEST_REGISTER("-", test_ol_init_null_params)
TEST_REGISTER("-", test_ol_init_invalid_config)
TEST_REGISTER("-", test_ol_is_connected_null)
TEST_REGISTER("-", test_ol_error_string_never_null)
TEST_REGISTER("-", test_ol_public_api_null_ctx)
TEST_REGISTER("OTA_CT_OL_1.1", test_ol_init_connect_real_tls)
TEST_REGISTER("OTA_CT_OL_1.2", test_ol_connect_invalid_ca_rejected)
TEST_SUITE_END(ota_lib_public)
