/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "builtin_macros.h"
#include "mbedtls_compat_tls.h"

int mbedtls_compat_ssl_conf_rng(mbedtls_ssl_config *conf, mbedtls_compat_rng_context *rng_ctx)
{
    (void)conf;
    (void)rng_ctx;
    /* mbedTLS 4.x configures RNG automatically via PSA */
    return 0;
}

/* ========================================================================== */
/* Cipher suite mapping (v4-specific)                                          */
/* ========================================================================== */

/**
 * Cipher suite mapping for mbedTLS 4.x.
 * Some TLS 1.2 ECDH_* static suites are removed in v4.
 * Order must match el2go_cipher_suite_t in plat_crypto_params.h.
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

/* ========================================================================== */
/* Curve mapping (v4-specific: uses IANA TLS group IDs, SECP224R1 removed)   */
/* ========================================================================== */

/**
 * Curve mapping table for mbedTLS 4.x.
 * SECP224R1 is not supported in v4.
 * Order must match el2go_curve_id_t in plat_crypto_params.h.
 */
static const mbedtls_compat_group_id_t curve_map[] = {
    0,                                    /* EL2GO_CURVE_SECP224R1 - not supported in v4 */
    MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1, /* EL2GO_CURVE_SECP256R1 */
    MBEDTLS_SSL_IANA_TLS_GROUP_SECP384R1, /* EL2GO_CURVE_SECP384R1 */
    MBEDTLS_SSL_IANA_TLS_GROUP_SECP521R1, /* EL2GO_CURVE_SECP521R1 */
};

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
/* SSL configuration (v4-specific)                                             */
/* ========================================================================== */

void mbedtls_compat_ssl_conf_groups(mbedtls_ssl_config *conf,
                                    const mbedtls_compat_group_id_t *groups)
{
    mbedtls_ssl_conf_groups(conf, groups);
}
