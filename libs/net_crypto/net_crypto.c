/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "net_crypto.h"
#include "compiler.h"

/* Weak implementations - can be overridden by specific transport implementations */

__weak el2go_status_t net_crypto_init(void)
{
    /* only some implementations may need initialization */
    return EL2GO_STATUS_SUCCESS;
}

__weak el2go_status_t net_crypto_set_server_cert(net_crypto_ctx_t *ctx, const uint8_t *ca_cert_pem,
                                                 size_t ca_cert_len)
{
    (void)ctx;
    (void)ca_cert_pem;
    (void)ca_cert_len;

    return EL2GO_STATUS_NOT_IMPLEMENTED;
}

__weak el2go_status_t net_crypto_set_cli_cert(net_crypto_ctx_t *ctx, const uint8_t *cert_pem,
                                              size_t cert_len)
{
    (void)ctx;
    (void)cert_pem;
    (void)cert_len;

    return EL2GO_STATUS_NOT_IMPLEMENTED;
}

__weak el2go_status_t net_crypto_set_cipher_suites(net_crypto_ctx_t *ctx,
                                                   const el2go_cipher_list_t *cipher_suites)
{
    (void)ctx;
    (void)cipher_suites;

    return EL2GO_STATUS_NOT_IMPLEMENTED;
}

__weak el2go_status_t net_crypto_set_curves(net_crypto_ctx_t *ctx,
                                            const el2go_curve_list_t *curve_list)
{
    (void)ctx;
    (void)curve_list;

    return EL2GO_STATUS_NOT_IMPLEMENTED;
}

__weak el2go_status_t net_crypto_associate_key(net_crypto_ctx_t *ctx, uint32_t object_id)
{
    (void)ctx;
    (void)object_id;

    return EL2GO_STATUS_NOT_IMPLEMENTED;
}

__weak el2go_status_t net_crypto_self_signed_cert(const char *subject, uint32_t key_id,
                                                  const uint8_t *device_uuid,
                                                  size_t device_uuid_len, uint8_t *cert_out,
                                                  size_t *cert_out_len)
{
    (void)subject;
    (void)key_id;
    (void)device_uuid;
    (void)device_uuid_len;
    (void)cert_out;
    (void)cert_out_len;

    return EL2GO_STATUS_NOT_IMPLEMENTED;
}

__weak el2go_status_t net_crypto_new(net_crypto_ctx_t **ctx)
{
    (void)ctx;

    return EL2GO_STATUS_NOT_IMPLEMENTED;
}

__weak el2go_status_t net_crypto_configure(net_crypto_ctx_t *ctx, const net_crypto_config_t *config)
{
    (void)ctx;
    (void)config;

    return EL2GO_STATUS_NOT_IMPLEMENTED;
}

__weak el2go_status_t net_crypto_connect(net_crypto_ctx_t *ctx)
{
    (void)ctx;

    return EL2GO_STATUS_NOT_IMPLEMENTED;
}

__weak el2go_status_t net_crypto_verify_cert(net_crypto_ctx_t *ctx, const uint8_t *crl_pem,
                                             size_t crl_len)
{
    (void)ctx;
    (void)crl_pem;
    (void)crl_len;

    return EL2GO_STATUS_NOT_IMPLEMENTED;
}

__weak int net_crypto_read(net_crypto_ctx_t *ctx, uint8_t *buffer, size_t len)
{
    (void)ctx;
    (void)buffer;
    (void)len;

    return -1;
}

__weak int net_crypto_write(net_crypto_ctx_t *ctx, const uint8_t *buffer, size_t len)
{
    (void)ctx;
    (void)buffer;
    (void)len;

    return -1;
}

__weak void net_crypto_free(net_crypto_ctx_t **ctx)
{
    (void)ctx;
}

__weak void net_crypto_cleanup(void)
{
}

__weak el2go_status_t net_crypto_disconnect(net_crypto_ctx_t *ctx)
{
    (void)ctx;

    return EL2GO_STATUS_NOT_IMPLEMENTED;
}

__weak el2go_status_t net_crypto_generate_csr(uint32_t key_id, const char *subject_name,
                                              net_crypto_md_alg_t md_alg, uint8_t encoding,
                                              uint8_t *csr_out, size_t csr_out_size,
                                              size_t *csr_out_len)
{
    (void)key_id;
    (void)subject_name;
    (void)md_alg;
    (void)encoding;
    (void)csr_out;
    (void)csr_out_size;
    (void)csr_out_len;

    return EL2GO_STATUS_NOT_IMPLEMENTED;
}

__weak el2go_status_t net_crypto_cert_get_pubkey(const uint8_t *cert_der, size_t cert_der_len,
                                                 uint8_t *pubkey_out, size_t pubkey_out_size,
                                                 size_t *pubkey_len)
{
    (void)cert_der;
    (void)cert_der_len;
    (void)pubkey_out;
    (void)pubkey_out_size;
    (void)pubkey_len;

    return EL2GO_STATUS_NOT_IMPLEMENTED;
}

__weak el2go_status_t net_crypto_cert_get_dn(const uint8_t *cert_der, size_t cert_der_len,
                                             bool is_subject, char *dn_out, size_t dn_out_size)
{
    (void)cert_der;
    (void)cert_der_len;
    (void)is_subject;
    (void)dn_out;
    (void)dn_out_size;

    return EL2GO_STATUS_NOT_IMPLEMENTED;
}

__weak el2go_status_t net_crypto_sha256(const uint8_t *data, size_t data_len, uint8_t *hash_out)
{
    (void)data;
    (void)data_len;
    (void)hash_out;

    return EL2GO_STATUS_NOT_IMPLEMENTED;
}

__weak el2go_status_t net_crypto_sha256_stream(net_crypto_fetch_callback_t fetch_callback,
                                               void *context, uint8_t *hash_out)
{
    (void)fetch_callback;
    (void)context;
    (void)hash_out;

    return EL2GO_STATUS_NOT_IMPLEMENTED;
}

__weak int net_crypto_ct_memcmp(const void *a, const void *b, size_t len)
{
    (void)a;
    (void)b;
    (void)len;

    return EL2GO_STATUS_NOT_IMPLEMENTED;
}

__weak el2go_status_t net_crypto_get_cert_cn(const uint8_t *cert_der, size_t cert_der_len,
                                             char *cn_out, size_t cn_out_len)
{
    (void)cert_der;
    (void)cert_der_len;
    (void)cn_out;
    (void)cn_out_len;
    return EL2GO_STATUS_NOT_IMPLEMENTED;
}
