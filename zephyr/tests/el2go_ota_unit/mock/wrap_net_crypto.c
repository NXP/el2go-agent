/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include "common/el2go_status.h"
#include "net_crypto.h"

#include <psa/error.h>
#include <psa/crypto.h>

#include <psa/storage_common.h>
#include <zephyr/secure_storage/its/common.h>

/* Control variables -- set these from tests to inject failures. */
psa_status_t g_wrap_psa_get_key_attributes_rc = PSA_SUCCESS;
psa_status_t g_wrap_psa_export_key_rc = PSA_SUCCESS;

int g_wrap_net_crypto_new_rc = 0; /* 0 = success */
int g_wrap_net_crypto_configure_rc = 0;
int g_wrap_net_crypto_set_server_cert_rc = 0;
int g_wrap_net_crypto_set_cli_cert_rc = 0;
int g_wrap_net_crypto_set_cipher_suites_rc = 0;
int g_wrap_net_crypto_set_curves_rc = 0;
int g_wrap_net_crypto_set_alpn_rc = 0;
int g_wrap_net_crypto_associate_key_rc = 0;
int g_wrap_net_crypto_connect_rc = 0;
int g_wrap_net_crypto_disconnect_rc = 0;

el2go_status_t g_wrap_net_crypto_connect_status = EL2GO_STATUS_FAILURE;

int g_wrap_net_crypto_write_rc = 1; /* bytes written (>0 = success) */
int g_wrap_net_crypto_read_rc = 1;  /* bytes read (>0 = success) */
psa_status_t g_wrap_psa_its_get_info_rc = PSA_ERROR_DOES_NOT_EXIST;
psa_status_t g_wrap_psa_its_get_rc = PSA_ERROR_DOES_NOT_EXIST;

size_t g_wrap_psa_its_cert_size = 16U;

/* Programmable RX byte queue / TX capture buffer / fault injection. */

#define MOCK_NET_RX_BUF_SIZE 4096U
#define MOCK_NET_TX_BUF_SIZE 4096U

static uint8_t s_rx_buf[MOCK_NET_RX_BUF_SIZE];
static size_t s_rx_len; /* valid bytes in s_rx_buf */
static size_t s_rx_pos; /* consumed so far */

static uint8_t s_tx_buf[MOCK_NET_TX_BUF_SIZE];
static size_t s_tx_len;

/* Fail-on-call-N counters. 0 = never fail. Reset alongside the buffers. */
static unsigned int s_read_call_count;
static unsigned int s_write_call_count;
unsigned int g_wrap_net_crypto_read_fail_on_call = 0U;
unsigned int g_wrap_net_crypto_write_fail_on_call = 0U;

void mock_net_rx_reset(void)
{
    s_rx_len = 0U;
    s_rx_pos = 0U;
    s_read_call_count = 0U;
    g_wrap_net_crypto_read_fail_on_call = 0U;
    memset(s_rx_buf, 0, sizeof(s_rx_buf));
}

int mock_net_rx_push(const uint8_t *bytes, size_t len)
{
    if (bytes == NULL && len != 0U) {
        return -1;
    }
    if (len > (sizeof(s_rx_buf) - s_rx_len)) {
        return -1; /* would overflow the queue */
    }
    if (len != 0U) {
        memcpy(s_rx_buf + s_rx_len, bytes, len);
    }
    s_rx_len += len;
    return 0;
}

void mock_net_tx_reset(void)
{
    s_tx_len = 0U;
    s_write_call_count = 0U;
    g_wrap_net_crypto_write_fail_on_call = 0U;
    memset(s_tx_buf, 0, sizeof(s_tx_buf));
}

int mock_net_tx_data(const uint8_t **out, size_t *out_len)
{
    if (out == NULL || out_len == NULL) {
        return -1;
    }
    *out = s_tx_buf;
    *out_len = s_tx_len;
    return 0;
}

/* Opaque context for net_crypto -- a small heap block so callers can free it. */
struct net_crypto_ctx {
    uint32_t dummy;
};

el2go_status_t __wrap_net_crypto_new(net_crypto_ctx_t **ctx)
{
    if (ctx == NULL) {
        return EL2GO_STATUS_FAILURE;
    }
    if (g_wrap_net_crypto_new_rc != 0) {
        *ctx = NULL;
        return EL2GO_STATUS_FAILURE;
    }
    *ctx = (net_crypto_ctx_t *)calloc(1U, sizeof(net_crypto_ctx_t));
    return (*ctx != NULL) ? EL2GO_STATUS_SUCCESS : EL2GO_STATUS_ALLOCATION_ERROR;
}

el2go_status_t __wrap_net_crypto_configure(net_crypto_ctx_t *ctx, const net_crypto_config_t *config)
{
    (void)ctx;
    (void)config;
    return (g_wrap_net_crypto_configure_rc == 0) ? EL2GO_STATUS_SUCCESS : EL2GO_STATUS_FAILURE;
}

el2go_status_t __wrap_net_crypto_set_server_cert(net_crypto_ctx_t *ctx, const uint8_t *ca_cert_pem,
                                                 size_t ca_cert_len)
{
    (void)ctx;
    (void)ca_cert_pem;
    (void)ca_cert_len;
    return (g_wrap_net_crypto_set_server_cert_rc == 0) ? EL2GO_STATUS_SUCCESS :
                                                         EL2GO_STATUS_FAILURE;
}

el2go_status_t __wrap_net_crypto_set_cli_cert(net_crypto_ctx_t *ctx, const uint8_t *cert_pem,
                                              size_t cert_len)
{
    (void)ctx;
    (void)cert_pem;
    (void)cert_len;
    return (g_wrap_net_crypto_set_cli_cert_rc == 0) ? EL2GO_STATUS_SUCCESS : EL2GO_STATUS_FAILURE;
}

el2go_status_t __wrap_net_crypto_set_cipher_suites(net_crypto_ctx_t *ctx,
                                                   const el2go_cipher_list_t *cipher_suites)
{
    (void)ctx;
    (void)cipher_suites;
    return (g_wrap_net_crypto_set_cipher_suites_rc == 0) ? EL2GO_STATUS_SUCCESS :
                                                           EL2GO_STATUS_FAILURE;
}

el2go_status_t __wrap_net_crypto_set_curves(net_crypto_ctx_t *ctx,
                                            const el2go_curve_list_t *curve_list)
{
    (void)ctx;
    (void)curve_list;
    return (g_wrap_net_crypto_set_curves_rc == 0) ? EL2GO_STATUS_SUCCESS : EL2GO_STATUS_FAILURE;
}

el2go_status_t __wrap_net_crypto_set_alpn(net_crypto_ctx_t *ctx, const char **alpn_protos)
{
    (void)ctx;
    (void)alpn_protos;
    return (g_wrap_net_crypto_set_alpn_rc == 0) ? EL2GO_STATUS_SUCCESS : EL2GO_STATUS_FAILURE;
}

el2go_status_t __wrap_net_crypto_associate_key(net_crypto_ctx_t *ctx, uint32_t object_id)
{
    (void)ctx;
    (void)object_id;
    return (g_wrap_net_crypto_associate_key_rc == 0) ? EL2GO_STATUS_SUCCESS : EL2GO_STATUS_FAILURE;
}

el2go_status_t __wrap_net_crypto_connect(net_crypto_ctx_t *ctx)
{
    (void)ctx;
    return (g_wrap_net_crypto_connect_rc == 0) ? EL2GO_STATUS_SUCCESS :
                                                 g_wrap_net_crypto_connect_status;
}

el2go_status_t __wrap_net_crypto_disconnect(net_crypto_ctx_t *ctx)
{
    (void)ctx;
    return (g_wrap_net_crypto_disconnect_rc == 0) ? EL2GO_STATUS_SUCCESS : EL2GO_STATUS_FAILURE;
}

int __wrap_net_crypto_write(net_crypto_ctx_t *ctx, const uint8_t *buffer, size_t len)
{
    (void)ctx;

    s_write_call_count++;

    if (g_wrap_net_crypto_write_fail_on_call != 0U &&
        s_write_call_count == g_wrap_net_crypto_write_fail_on_call) {
        return -1;
    }

    /* Capture outbound bytes for wire-format assertions, best-effort. */
    if (buffer != NULL && len > 0U && (s_tx_len + len) <= sizeof(s_tx_buf)) {
        memcpy(s_tx_buf + s_tx_len, buffer, len);
        s_tx_len += len;
    }

    return g_wrap_net_crypto_write_rc;
}

int __wrap_net_crypto_read(net_crypto_ctx_t *ctx, uint8_t *buffer, size_t len)
{
    (void)ctx;

    s_read_call_count++;

    if (g_wrap_net_crypto_read_fail_on_call != 0U &&
        s_read_call_count == g_wrap_net_crypto_read_fail_on_call) {
        return -1;
    }

    /* Serve queued bytes if any are available (grpc round-trip tests). */
    if (s_rx_pos < s_rx_len) {
        size_t available = s_rx_len - s_rx_pos;
        size_t to_copy = (len < available) ? len : available;

        if (buffer != NULL && to_copy > 0U) {
            memcpy(buffer, s_rx_buf + s_rx_pos, to_copy);
        }
        s_rx_pos += to_copy;
        return (int)to_copy;
    }

    /* Legacy fallback: no queue loaded -- preserve existing TLS test behaviour. */
    if (g_wrap_net_crypto_read_rc <= 0) {
        return g_wrap_net_crypto_read_rc;
    }
    /* Zero-fill the output buffer to keep valgrind happy. */
    if (buffer != NULL && len > 0U) {
        memset(buffer, 0, len);
    }
    return g_wrap_net_crypto_read_rc;
}

void __wrap_net_crypto_free(net_crypto_ctx_t **ctx)
{
    if (ctx != NULL && *ctx != NULL) {
        free(*ctx);
        *ctx = NULL;
    }
}

/*
 * PSA Crypto API wraps -- used by el2go_ota_cred_psa.c.
 *
 * psa_get_key_attributes() and psa_export_key() are the PSA Crypto API
 * functions called by the credential provider to read the DER certificate.
 * The mock synthesises attributes with PSA_KEY_TYPE_RAW_DATA so that
 * PSA_EXPORT_KEY_OUTPUT_SIZE() returns g_wrap_psa_its_cert_size, then
 * psa_export_key() zero-fills the output buffer to simulate a cert blob.
 */

psa_status_t __wrap_psa_get_key_attributes(mbedtls_svc_key_id_t key,
                                           psa_key_attributes_t *attributes)
{
    (void)key;
    if (g_wrap_psa_get_key_attributes_rc != PSA_SUCCESS) {
        return g_wrap_psa_get_key_attributes_rc;
    }
    if (attributes != NULL) {
        memset(attributes, 0, sizeof(*attributes));
        psa_set_key_type(attributes, PSA_KEY_TYPE_RAW_DATA);
        psa_set_key_bits(attributes, (psa_key_bits_t)(g_wrap_psa_its_cert_size * 8U));
    }
    return PSA_SUCCESS;
}

psa_status_t __wrap_psa_export_key(mbedtls_svc_key_id_t key, uint8_t *data, size_t data_size,
                                   size_t *data_length)
{
    (void)key;
    if (g_wrap_psa_export_key_rc != PSA_SUCCESS) {
        if (data_length != NULL) {
            *data_length = 0U;
        }
        return g_wrap_psa_export_key_rc;
    }
    if (data != NULL && data_size > 0U) {
        memset(data, 0, data_size);
    }
    if (data_length != NULL) {
        *data_length = data_size;
    }
    return PSA_SUCCESS;
}

/*
 * PSA ITS wraps -- used by el2go_ota_cred_psa.c.
 *
 * psa_its_get_info()/psa_its_get() have no out-of-line call for
 * --wrap to intercept, so these wrap the symbols 
 * secure_storage_its_get_info() and secure_storage_its_get()
 * they forward to.
 */

psa_status_t __wrap_secure_storage_its_get_info(secure_storage_its_caller_id_t caller_id,
                                                psa_storage_uid_t uid,
                                                struct psa_storage_info_t *p_info)
{
    (void)caller_id;
    (void)uid;
    if (g_wrap_psa_its_get_info_rc != PSA_SUCCESS) {
        return g_wrap_psa_its_get_info_rc;
    }
    if (p_info != NULL) {
        memset(p_info, 0, sizeof(*p_info));
        p_info->size = g_wrap_psa_its_cert_size;
        p_info->capacity = g_wrap_psa_its_cert_size;
    }
    return PSA_SUCCESS;
}

psa_status_t __wrap_secure_storage_its_get(secure_storage_its_caller_id_t caller_id,
                                           psa_storage_uid_t uid, size_t data_offset,
                                           size_t data_size, void *p_data, size_t *p_data_length)
{
    (void)caller_id;
    (void)uid;
    (void)data_offset;
    if (g_wrap_psa_its_get_rc != PSA_SUCCESS) {
        return g_wrap_psa_its_get_rc;
    }
    /* Fill output with zeros to simulate a DER cert blob. */
    if (p_data != NULL && data_size > 0U) {
        memset(p_data, 0, data_size);
    }
    if (p_data_length != NULL) {
        *p_data_length = data_size;
    }
    return PSA_SUCCESS;
}

/*
 * Reset every g_wrap_* control variable and RX/TX byte queue back to its
 * default. Wired as the ZTEST_SUITE "before" hook in ztest_unit_main.c so
 * mock state set by one test cannot leak into the next.
 */
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
    g_wrap_net_crypto_connect_status = EL2GO_STATUS_FAILURE;
    g_wrap_net_crypto_disconnect_rc = 0;
    g_wrap_net_crypto_write_rc = 1;
    g_wrap_net_crypto_read_rc = 1;
    g_wrap_psa_get_key_attributes_rc = PSA_SUCCESS;
    g_wrap_psa_export_key_rc = PSA_SUCCESS;
    g_wrap_psa_its_get_info_rc = PSA_ERROR_DOES_NOT_EXIST;
    g_wrap_psa_its_get_rc = PSA_ERROR_DOES_NOT_EXIST;
    g_wrap_psa_its_cert_size = 16U;

    mock_net_rx_reset();
    mock_net_tx_reset();
}
