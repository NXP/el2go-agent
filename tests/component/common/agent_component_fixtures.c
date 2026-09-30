/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "agent_component_fixtures.h"

#include "fwual/fwual.h"
#include "ota/el2go_ota_lib.h"

test_result_t agent_ct_public_api_reachable(void)
{
    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH);

    TEST_ASSERT_EQ(FWUAL_OK, fwual_init());

    el2go_ota_ctx_t *ctx = NULL;
    const el2go_ota_mtls_config_t config = {
        .hostname = "ota.example.com",
        .port = 443U,
        .server_ca_chain = NULL,
        .server_ca_chain_size = 0U,
        .client_key_object_id = 0U,
        .client_cert_object_id = 0U,
    };

    TEST_ASSERT_EQ(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_init(&ctx, &config));
    TEST_ASSERT_NULL(ctx);
    return TEST_PASS;
}
