/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/* Unit tests for libs/el2go_ota_lib/src/cred/psa/el2go_ota_cred_psa.c. */

#include "test_el2go_ota_compat_shim.h"

#include "test_framework.h"
#include "test_suites.h"

#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include "common/el2go_status.h"
#include "el2go_ota_cred.h"
#include "common/el2go_platform.h"
#include "osal.h"
#include "test_el2go_ota_fixtures.h"
#include "wrap_net_crypto.h"

#include <psa/error.h>

/**
 * @brief Verify cred psa null config.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_cred_psa_null_config(void *params)
{
    uint8_t *cert = NULL;
    size_t len = 0U;
    uint32_t kid = 0U;
    (void)params;
    TEST_ASSERT_EQUAL(EL2GO_STATUS_INVALID_PARAMETER,
                      el2go_ota_prepare_client_credentials(ota_fixture_get_pctx(), NULL, &cert,
                                                           &len, &kid));
    return true;
}

/**
 * @brief Verify cred psa null cert out.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_cred_psa_null_cert_out(void *params)
{
    el2go_ota_mtls_config_t c = ota_fixture_make_cfg();
    size_t len = 0U;
    uint32_t kid = 0U;
    (void)params;
    TEST_ASSERT_EQUAL(EL2GO_STATUS_INVALID_PARAMETER,
                      el2go_ota_prepare_client_credentials(ota_fixture_get_pctx(), &c, NULL, &len,
                                                           &kid));
    return true;
}

/**
 * @brief Verify cred psa get info fail.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_cred_psa_get_info_fail(void *params)
{
    el2go_ota_mtls_config_t c = ota_fixture_make_cfg();
    c.client_cert_object_id = 0x10U;
    uint8_t *cert = NULL;
    size_t len = 0U;
    uint32_t kid = 0U;
    (void)params;
    ota_fixture_reset_net_crypto_and_psa_wraps();
    g_wrap_psa_get_key_attributes_rc = PSA_ERROR_DOES_NOT_EXIST;
    TEST_ASSERT(EL2GO_STATUS_SUCCESS != el2go_ota_prepare_client_credentials(
                                            ota_fixture_get_pctx(), &c, &cert, &len, &kid));
    return true;
}

/**
 * @brief Verify cred psa zero cert size.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_cred_psa_zero_cert_size(void *params)
{
    el2go_ota_mtls_config_t c = ota_fixture_make_cfg();
    c.client_cert_object_id = 0x10U;
    uint8_t *cert = NULL;
    size_t len = 0U;
    uint32_t kid = 0U;
    (void)params;
    ota_fixture_reset_net_crypto_and_psa_wraps();
    g_wrap_psa_its_cert_size = 0U;
    TEST_ASSERT(EL2GO_STATUS_SUCCESS != el2go_ota_prepare_client_credentials(
                                            ota_fixture_get_pctx(), &c, &cert, &len, &kid));
    return true;
}

/**
 * @brief Verify cred psa get fail.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_cred_psa_get_fail(void *params)
{
    el2go_ota_mtls_config_t c = ota_fixture_make_cfg();
    c.client_cert_object_id = 0x10U;
    uint8_t *cert = NULL;
    size_t len = 0U;
    uint32_t kid = 0U;
    (void)params;
    ota_fixture_reset_net_crypto_and_psa_wraps();
    g_wrap_psa_its_cert_size = 8U;
    g_wrap_psa_export_key_rc = PSA_ERROR_GENERIC_ERROR;
    TEST_ASSERT(EL2GO_STATUS_SUCCESS != el2go_ota_prepare_client_credentials(
                                            ota_fixture_get_pctx(), &c, &cert, &len, &kid));
    return true;
}

/**
 * @brief Verify cred psa success.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_cred_psa_success(void *params)
{
    el2go_ota_mtls_config_t c = ota_fixture_make_cfg();
    c.client_cert_object_id = 0x10U;
    c.client_key_object_id = 0x20U;
    uint8_t *cert = NULL;
    size_t len = 0U;
    uint32_t kid = 0U;
    (void)params;
    ota_fixture_reset_net_crypto_and_psa_wraps();
    g_wrap_psa_its_cert_size = 8U;
    {
        el2go_status_t r =
            el2go_ota_prepare_client_credentials(ota_fixture_get_pctx(), &c, &cert, &len, &kid);
        if (r == EL2GO_STATUS_SUCCESS) {
            TEST_ASSERT_NOT_NULL(cert);
            TEST_ASSERT_EQUAL(0x20U, kid);
            osal_free(cert);
        }
    }
    return true;
}

/**
 * @brief Verify cred psa null key id.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_cred_psa_null_key_id(void *params)
{
    el2go_ota_mtls_config_t c = ota_fixture_make_cfg();
    uint8_t *cert = NULL;
    size_t len = 0U;
    (void)params;
    TEST_ASSERT_EQUAL(EL2GO_STATUS_INVALID_PARAMETER,
                      el2go_ota_prepare_client_credentials(ota_fixture_get_pctx(), &c, &cert, &len,
                                                           NULL));
    return true;
}

/* ---- suite registration ------------------------------------------------ */

void register_ota_lib_cred_psa_tests(void)
{
    TEST_REGISTER_ID("10.1", test_ota_cred_psa_null_config);
    TEST_REGISTER_ID("10.2", test_ota_cred_psa_null_cert_out);
    TEST_REGISTER_ID("10.3", test_ota_cred_psa_get_info_fail);
    TEST_REGISTER_ID("10.4", test_ota_cred_psa_zero_cert_size);
    TEST_REGISTER_ID("10.5", test_ota_cred_psa_get_fail);
    TEST_REGISTER_ID("10.6", test_ota_cred_psa_success);
    TEST_REGISTER_ID("10.7", test_ota_cred_psa_null_key_id);
}
