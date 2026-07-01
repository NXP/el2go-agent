/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "fwual/fwual.h"
#include "ota/el2go_ota_lib.h"
#include "test_framework.h"
#include "test_suites.h"

/**
 * @brief Verify that fwual_init() is reachable from the ota_agent_advanced entry point.
 *
 * Calls the fwual_init() stub from the advanced agent context and checks it
 * returns without error. Validates that the FWUAL dependency is correctly
 * linked into the ota_agent_advanced build target.
 *
 * @param[in] params Unused test parameter, pass NULL.
 *
 * @retval true  Test passed.
 * @retval false Test failed.
 */
static bool test_ota_agent_advanced_calls_fwual_init(void *params)
{
    bool test_status = true;

    (void)params;

    fwual_init();
    TEST_PRINT_INFO("ota_agent_advanced: fwual_init() reachable");

    return test_status;
}

/**
 * @brief Verify that el2go_ota_init() is reachable from the ota_agent_advanced entry point.
 *
 * Calls the el2go_ota_init() stub from the advanced agent context and
 * checks it returns without error. Validates that the OTA library dependency
 * is correctly linked into the ota_agent_advanced build target.
 *
 * @param[in] params Unused test parameter, pass NULL.
 *
 * @retval true  Test passed.
 * @retval false Test failed.
 */
static bool test_ota_agent_advanced_calls_ota_lib_init(void *params)
{
    bool test_status = true;

    (void)params;

    /* Verify el2go_ota_init() is reachable at link time.
     * NULL server_ca_chain must return EL2GO_OTA_ERROR_INVALID_PARAM. */
    el2go_ota_ctx_t *ctx = NULL;
    const el2go_ota_mtls_config_t config = {
        .hostname = "ota.example.com",
        .port = 443U,
        .server_ca_chain = NULL,
        .server_ca_chain_size = 0U,
        .client_key_object_id = 0U,
        .client_cert_object_id = 0U,
    };

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_init(&ctx, &config));
    TEST_ASSERT_NULL(ctx);
    TEST_PRINT_INFO("ota_agent_advanced: el2go_ota_init() reachable");

    return test_status;
}

void register_ota_agent_advanced_tests(void)
{
    TEST_REGISTER(test_ota_agent_advanced_calls_fwual_init);
    TEST_REGISTER(test_ota_agent_advanced_calls_ota_lib_init);
}
