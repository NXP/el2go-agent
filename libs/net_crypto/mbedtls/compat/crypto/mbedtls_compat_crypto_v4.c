
/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <string.h>
#include <psa/crypto.h>
#include <mbedtls/pk.h>
#include <mbedtls/asn1.h>
#include <mbedtls/x509_crt.h>

#include "mbedtls_compat_crypto.h"

/* ========================================================================== */
/* SHA-256 functions (v4: via PSA crypto)                                     */
/* ========================================================================== */

void mbedtls_compat_sha256_init(mbedtls_compat_sha256_context *ctx)
{
    ctx->ctx = psa_hash_operation_init();
}

void mbedtls_compat_sha256_free(mbedtls_compat_sha256_context *ctx)
{
    (void)psa_hash_abort(&ctx->ctx);
}

int mbedtls_compat_sha256_starts(mbedtls_compat_sha256_context *ctx)
{
    psa_status_t status = psa_hash_setup(&ctx->ctx, PSA_ALG_SHA_256);

    return (status == PSA_SUCCESS) ? 0 : -1;
}

int mbedtls_compat_sha256_update(mbedtls_compat_sha256_context *ctx, const unsigned char *input,
                                 size_t ilen)
{
    psa_status_t status = psa_hash_update(&ctx->ctx, input, ilen);

    return (status == PSA_SUCCESS) ? 0 : -1;
}

int mbedtls_compat_sha256_finish(mbedtls_compat_sha256_context *ctx, unsigned char output[32])
{
    size_t hash_len = 0;
    psa_status_t status =
        psa_hash_finish(&ctx->ctx, output, PSA_HASH_LENGTH(PSA_ALG_SHA_256), &hash_len);

    return (status == PSA_SUCCESS) ? 0 : -1;
}

int mbedtls_compat_sha256(const unsigned char *input, size_t ilen, unsigned char output[32])
{
    size_t hash_len = 0;
    psa_status_t status = psa_hash_compute(PSA_ALG_SHA_256, input, ilen, output,
                                           PSA_HASH_LENGTH(PSA_ALG_SHA_256), &hash_len);

    return (status == PSA_SUCCESS) ? 0 : -1;
}

/* ========================================================================== */
/* EC public key extraction (v4: via DER write + ASN.1 parse)                */
/* ========================================================================== */

/*
 * Extract the raw uncompressed EC public key (0x04 || X || Y) from a PK context.
 *
 * mbedtls_pk_write_pubkey_der writes a SubjectPublicKeyInfo DER blob to the END
 * of the supplied buffer. The BIT STRING payload inside that DER blob is:
 *   0x00 (unused-bits byte) || 0x04 || X || Y
 * so we skip the leading 0x00 to return 0x04 || X || Y.
 */
int mbedtls_compat_pk_get_ec_pubkey_raw(const mbedtls_pk_context *pk, uint8_t *buf, size_t buf_size,
                                        size_t *out_len)
{
    /* 200 bytes is enough for P-521 SubjectPublicKeyInfo */
    unsigned char der_buf[200];
    int der_len;
    const unsigned char *p;
    const unsigned char *end;
    size_t len;
    int ret;

    if (pk == NULL || buf == NULL || out_len == NULL)
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;

    /* Write SubjectPublicKeyInfo DER to the END of der_buf */
    der_len = mbedtls_pk_write_pubkey_der((mbedtls_pk_context *)pk, der_buf, sizeof(der_buf));
    if (der_len < 0)
        return der_len;

    if ((size_t)der_len > sizeof(der_buf))
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;

    p = der_buf + sizeof(der_buf) - (size_t)der_len;
    end = der_buf + sizeof(der_buf);

    /* Skip outer SEQUENCE tag + length */
    ret = mbedtls_asn1_get_tag((unsigned char **)&p, end, &len,
                               MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0)
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;

    /* Skip AlgorithmIdentifier SEQUENCE */
    ret = mbedtls_asn1_get_tag((unsigned char **)&p, end, &len,
                               MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0)
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    p += len;

    /* Parse BIT STRING */
    ret = mbedtls_asn1_get_tag((unsigned char **)&p, end, &len, MBEDTLS_ASN1_BIT_STRING);
    if (ret != 0)
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;

    /* First byte of BIT STRING is unused-bits count (must be 0 for EC keys) */
    if (len < 1 || *p != 0x00)
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    p++;
    len--;

    /* Remaining bytes are the raw EC point: 0x04 || X || Y */
    if (len > buf_size)
        return MBEDTLS_COMPAT_ERR_PK_BUFFER_TOO_SMALL;

    memcpy(buf, p, len);
    *out_len = len;
    return 0;
}

/* ========================================================================== */
/* PK functions (v4-specific)                                                  */
/* ========================================================================== */

int mbedtls_compat_pk_setup_key(mbedtls_pk_context *pk, uint32_t key_id)
{
    mbedtls_svc_key_id_t svc_key_id;

    if (pk == NULL)
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;

    svc_key_id = mbedtls_svc_key_id_make(0, key_id);

    return mbedtls_pk_wrap_psa(pk, svc_key_id);
}

int mbedtls_compat_pk_has_key(const mbedtls_pk_context *pk)
{
    return mbedtls_pk_get_key_type(pk) != PSA_KEY_TYPE_NONE;
}

/* ========================================================================== */
/* X.509 certificate write (v4)                                               */
/* ========================================================================== */

int mbedtls_compat_x509write_crt_set_serial(mbedtls_x509write_cert *ctx,
                                            const unsigned char *serial, size_t serial_len)
{
    return mbedtls_x509write_crt_set_serial_raw(ctx, serial, serial_len);
}

int mbedtls_compat_x509write_crt_der(mbedtls_x509write_cert *ctx, unsigned char *buf, size_t size,
                                     mbedtls_compat_rng_context *rng_ctx)
{
    (void)rng_ctx;
    /* mbedTLS 4.x does not require RNG parameter */
    return mbedtls_x509write_crt_der(ctx, buf, size);
}
