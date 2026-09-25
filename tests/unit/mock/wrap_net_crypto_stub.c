/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "wrap_net_crypto.h"

#include <string.h>

int g_wrap_net_crypto_new_rc;
int g_wrap_net_crypto_configure_rc;
int g_wrap_net_crypto_set_server_cert_rc;
int g_wrap_net_crypto_set_cli_cert_rc;
int g_wrap_net_crypto_set_cipher_suites_rc;
int g_wrap_net_crypto_set_curves_rc;
int g_wrap_net_crypto_set_alpn_rc;
int g_wrap_net_crypto_associate_key_rc;
int g_wrap_net_crypto_connect_rc;
el2go_status_t g_wrap_net_crypto_connect_status;
int g_wrap_net_crypto_disconnect_rc;
int g_wrap_net_crypto_write_rc;
int g_wrap_net_crypto_read_rc;

psa_status_t g_wrap_psa_its_get_info_rc;
psa_status_t g_wrap_psa_its_get_rc;
size_t g_wrap_psa_its_cert_size;

unsigned int g_wrap_net_crypto_read_fail_on_call;
unsigned int g_wrap_net_crypto_write_fail_on_call;

void mock_net_rx_reset(void)
{
    /* No fake RX queue to reset. */
}

int mock_net_rx_push(const uint8_t *bytes, size_t len)
{
    (void)bytes;
    (void)len;
    return -1;
}

void mock_net_tx_reset(void)
{
    /* No fake TX buffer to reset. */
}

int mock_net_tx_data(const uint8_t **out, size_t *out_len)
{
    if (out != NULL) {
        *out = NULL;
    }
    if (out_len != NULL) {
        *out_len = 0U;
    }
    return -1;
}

void wrap_net_crypto_reset_all(void)
{
    g_wrap_net_crypto_new_rc = 0;
    g_wrap_net_crypto_configure_rc = 0;
    g_wrap_net_crypto_set_server_cert_rc = 0;
    g_wrap_net_crypto_set_cli_cert_rc = 0;
    g_wrap_net_crypto_set_cipher_suites_rc = 0;
    g_wrap_net_crypto_set_curves_rc = 0;
    g_wrap_net_crypto_set_alpn_rc = 0;
    g_wrap_net_crypto_associate_key_rc = 0;
    g_wrap_net_crypto_connect_rc = 0;
    g_wrap_net_crypto_disconnect_rc = 0;
    g_wrap_net_crypto_write_rc = 0;
    g_wrap_net_crypto_read_rc = 0;
    g_wrap_psa_its_get_info_rc = 0;
    g_wrap_psa_its_get_rc = 0;
    g_wrap_psa_its_cert_size = 0U;
    g_wrap_net_crypto_read_fail_on_call = 0U;
    g_wrap_net_crypto_write_fail_on_call = 0U;
}
