/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <string.h>
#include <psa/crypto.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>

#include "builtin_macros.h"
#include "osal.h"

#include "mbedtls_compat.h"

/**
 * @addtogroup mbedtls_compat_v4
 * @{
 */

/* ========================================================================== */
/* RNG Context Structure                                                       */
/* ========================================================================== */

/**
 * @brief RNG context for mbedTLS 4.x.
 *
 * In mbedTLS 4.x PSA crypto handles RNG internally, so no explicit
 * RNG context is needed. This struct exists only to satisfy the C
 * requirement that structs cannot be empty.
 */
struct mbedtls_compat_rng_context {
    int dummy; /**< Unused - PSA crypto handles RNG internally. */
};

/* ========================================================================== */
/* Cipher Suite Mapping                                                        */
/* ========================================================================== */

/**
 * @brief Mapping from el2go_cipher_suite_t to mbedTLS 4.x cipher suite IDs.
 *
 * Index corresponds to @ref el2go_cipher_suite_t value.
 * 0 means not supported in mbedTLS 4.x.
 *
 * @note Must stay in sync with @ref el2go_cipher_suite_t in plat_crypto_params.h.
 */
static const int cipher_suite_map[] = {
    /* EL2GO_CIPHER_ECDHE_ECDSA_AES128_CBC_SHA256 */
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    /* EL2GO_CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256 */
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    /* EL2GO_CIPHER_ECDHE_ECDSA_AES256_CBC_SHA384 */
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
    /* EL2GO_CIPHER_ECDHE_ECDSA_AES256_GCM_SHA384 */
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    /* EL2GO_CIPHER_ECDH_ECDSA_AES128_CBC_SHA256  */
    0, /* not supported in mbedTLS 4.x */
    /* EL2GO_CIPHER_ECDH_ECDSA_AES128_GCM_SHA256  */
    0, /* not supported in mbedTLS 4.x */
    /* EL2GO_CIPHER_ECDH_ECDSA_AES256_CBC_SHA384  */
    0, /* not supported in mbedTLS 4.x */
    /* EL2GO_CIPHER_ECDH_ECDSA_AES256_GCM_SHA384  */
    0, /* not supported in mbedTLS 4.x */
    /* EL2GO_CIPHER_ECDHE_RSA_AES128_CBC_SHA256   */
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    /* EL2GO_CIPHER_ECDHE_RSA_AES128_GCM_SHA256   */
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    /* EL2GO_CIPHER_ECDHE_RSA_AES256_CBC_SHA384   */
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
    /* EL2GO_CIPHER_ECDHE_RSA_AES256_GCM_SHA384   */
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    /* EL2GO_CIPHER_ECDH_RSA_AES128_CBC_SHA256    */
    0, /* not supported in mbedTLS 4.x */
    /* EL2GO_CIPHER_ECDH_RSA_AES128_GCM_SHA256    */
    0, /* not supported in mbedTLS 4.x */
    /* EL2GO_CIPHER_ECDH_RSA_AES256_CBC_SHA384    */
    0, /* not supported in mbedTLS 4.x */
    /* EL2GO_CIPHER_ECDH_RSA_AES256_GCM_SHA384    */
    0, /* not supported in mbedTLS 4.x */
};

/* ========================================================================== */
/* Curve Mapping                                                               */
/* ========================================================================== */

/**
 * @brief Curve mapping table from platform-agnostic curve IDs to mbedTLS 4.x format.
 *
 * Uses IANA TLS group IDs (uint16_t).
 *
 * @note SECP224R1 is not supported in mbedTLS 4.x.
 * @note Order must match @ref el2go_curve_id_t enum in plat_crypto_params.h.
 * @note Size must match @ref EL2GO_CURVE_MAX.
 */
static const mbedtls_compat_group_id_t curve_map[] = {
    0,                                    /* EL2GO_CURVE_SECP224R1 - not supported in v4 */
    MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1, /* EL2GO_CURVE_SECP256R1 */
    MBEDTLS_SSL_IANA_TLS_GROUP_SECP384R1, /* EL2GO_CURVE_SECP384R1 */
    MBEDTLS_SSL_IANA_TLS_GROUP_SECP521R1, /* EL2GO_CURVE_SECP521R1 */
};

/* Functions are documented in mbedtls_compat.h */

int mbedtls_compat_cipher_suite_to_id(el2go_cipher_suite_t suite)
{
    if (suite >= ARRAY_SIZE(cipher_suite_map))
        return 0;

    return cipher_suite_map[suite];
}

size_t mbedtls_compat_cipher_suite_map_size(void)
{
    return ARRAY_SIZE(cipher_suite_map);
}

size_t mbedtls_compat_curve_map_size(void)
{
    return ARRAY_SIZE(curve_map);
}

mbedtls_compat_group_id_t mbedtls_compat_curve_to_id(el2go_curve_id_t curve)
{
    if (curve >= ARRAY_SIZE(curve_map))
        return MBEDTLS_COMPAT_CURVE_SENTINEL;

    return curve_map[curve];
}

/* ========================================================================== */
/* RNG Functions (v4-specific)                                                */
/* ========================================================================== */

int mbedtls_compat_rng_init(mbedtls_compat_rng_context **ctx, const unsigned char *pers,
                            size_t pers_len)
{
    (void)pers;
    (void)pers_len;

    if (ctx == NULL)
        return -1;

    /* mbedTLS 4.x uses PSA crypto - no RNG context needed */
    *ctx = NULL;
    return 0;
}

void mbedtls_compat_rng_free(mbedtls_compat_rng_context *ctx)
{
    /* Nothing to free - context is NULL */
    (void)ctx;
}

int mbedtls_compat_ssl_conf_rng(mbedtls_ssl_config *conf, mbedtls_compat_rng_context *rng_ctx)
{
    (void)conf;
    (void)rng_ctx;
    /* mbedTLS 4.x configures RNG automatically via PSA */
    return 0;
}

/* ========================================================================== */
/* PK Functions (v4-specific)                                                 */
/* ========================================================================== */

int mbedtls_compat_pk_setup_key(mbedtls_pk_context *pk, uint32_t key_id)
{
    mbedtls_svc_key_id_t svc_key_id;

    if (pk == NULL)
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;

    /* Convert uint32_t to mbedtls_svc_key_id_t */
    svc_key_id = mbedtls_svc_key_id_make(0, key_id);

    return mbedtls_pk_wrap_psa(pk, svc_key_id);
}

int mbedtls_compat_pk_has_key(const mbedtls_pk_context *pk)
{
    return mbedtls_pk_get_key_type(pk) != PSA_KEY_TYPE_NONE;
}

/* ========================================================================== */
/* X.509 Certificate Functions (v4-specific)                                  */
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
    /* mbedTLS 4.x doesn't require RNG parameter */
    return mbedtls_x509write_crt_der(ctx, buf, size);
}

/* ========================================================================== */
/* SSL Configuration Functions                                                 */
/* ========================================================================== */

void mbedtls_compat_ssl_conf_groups(mbedtls_ssl_config *conf,
                                    const mbedtls_compat_group_id_t *groups)
{
    mbedtls_ssl_conf_groups(conf, groups);
}

/* ========================================================================== */
/* SHA-256 Functions - mbedTLS v4.x (via PSA crypto)                         */
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
/* EC Public Key Extraction (v4-specific)                                     */
/* ========================================================================== */

/*
 * Extract the raw uncompressed EC public key (0x04 || X || Y) from a PK context.
 *
 * mbedtls_pk_write_pubkey_der writes a SubjectPublicKeyInfo DER blob to the END
 * of the supplied buffer and returns the number of bytes written (positive) or a
 * negative error code.  The BIT STRING payload inside that DER blob is:
 *   0x00 (unused-bits byte) || 0x04 || X || Y
 * so we skip the leading 0x00 to return 0x04 || X || Y.
 */
int mbedtls_compat_pk_get_ec_pubkey_raw(const mbedtls_pk_context *pk, uint8_t *buf, size_t buf_size,
                                        size_t *out_len)
{
    /* Temporary DER work buffer - 200 bytes is enough for P-521 SubjectPublicKeyInfo */
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

    /* mbedtls_pk_write_pubkey_der places data at the end of the buffer */
    p = der_buf + sizeof(der_buf) - der_len;
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
        return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;

    memcpy(buf, p, len);
    *out_len = len;
    return 0;
}

/** @} */ /* end of mbedtls_compat_v4 */
