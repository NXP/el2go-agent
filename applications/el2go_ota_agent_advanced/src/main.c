/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "fwual/fwual.h"
#include "ota/el2go_ota_lib.h"

int main(void)
{
    if (fwual_init() != FWUAL_OK)
        return 1;

    el2go_ota_ctx_t *ctx = NULL;
    const el2go_ota_mtls_config_t config = {
        .hostname = "ota.example.com",
        .port = 443U,
        .server_ca_chain = NULL,
        .server_ca_chain_size = 0U,
        .client_key_object_id = 0U,
        .client_cert_object_id = 0U,
    };

    if (el2go_ota_init(&ctx, &config) != EL2GO_OTA_SUCCESS)
        return 1;

    el2go_ota_cleanup(&ctx);
    return 0;
}
