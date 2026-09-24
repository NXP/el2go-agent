/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "test_el2go_ota_compat_shim.h"
#include "test_el2go_ota_fixtures.h"
#include "el2go_ota_tls.h"
#include "wrap_net_crypto.h"

static const uint8_t s_ota_fixture_ca[4] = { 0x30, 0x82, 0x01, 0x00 };

el2go_ota_mtls_config_t ota_fixture_make_cfg(void)
{
    el2go_ota_mtls_config_t c = { 0 };

    c.hostname = "example.com";
    c.port = 443U;
    c.server_ca_chain = s_ota_fixture_ca;
    c.server_ca_chain_size = sizeof(s_ota_fixture_ca);
    c.client_auth = EL2GO_OTA_CLIENT_AUTH_NONE;
    return c;
}

el2go_platform_ctx_t *ota_fixture_get_pctx(void)
{
    static el2go_platform_ctx_t *s_ctx = NULL;

    if (s_ctx == NULL) {
        (void)el2go_platform_init(&s_ctx);
    }
    return s_ctx;
}

void ota_fixture_reset_net_crypto_wraps(void)
{
    g_wrap_net_crypto_new_rc = 0;
    g_wrap_net_crypto_configure_rc = 0;
    g_wrap_net_crypto_set_server_cert_rc = 0;
    g_wrap_net_crypto_connect_rc = 0;
    g_wrap_net_crypto_write_rc = 1;
    g_wrap_net_crypto_read_rc = 1;
}

void ota_fixture_reset_net_crypto_and_psa_wraps(void)
{
    ota_fixture_reset_net_crypto_wraps();
    g_wrap_net_crypto_set_cipher_suites_rc = 0;
    g_wrap_net_crypto_set_curves_rc = 0;
    g_wrap_net_crypto_set_alpn_rc = 0;
    g_wrap_net_crypto_associate_key_rc = 0;
    g_wrap_net_crypto_set_cli_cert_rc = 0;
    g_wrap_psa_its_get_info_rc = PSA_SUCCESS;
    g_wrap_psa_its_get_rc = PSA_SUCCESS;
    g_wrap_psa_its_cert_size = 16U;
}

el2go_ota_status_t ota_fixture_noop_chunk_cb(const uint8_t *data, size_t len, size_t offset,
                                             void *ctx)
{
    (void)data;
    (void)len;
    (void)offset;
    (void)ctx;
    return EL2GO_OTA_SUCCESS;
}
