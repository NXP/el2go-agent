/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "builtin_macros.h"

#include "mbedtls_compat_tls.h"

/* ========================================================================== */
/* Cipher suite mapping (shared between v2 and v3)                            */
/* ========================================================================== */

/**
 * Mapping from el2go_cipher_suite_t to mbedTLS 2.x/3.x cipher suite IDs.
 * Index corresponds to el2go_cipher_suite_t value. 0 means not supported.
 * Must stay in sync with el2go_cipher_suite_t in plat_crypto_params.h.
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
    MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
    /* EL2GO_CIPHER_ECDH_ECDSA_AES128_GCM_SHA256  */
    MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
    /* EL2GO_CIPHER_ECDH_ECDSA_AES256_CBC_SHA384  */
    MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
    /* EL2GO_CIPHER_ECDH_ECDSA_AES256_GCM_SHA384  */
    MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
    /* EL2GO_CIPHER_ECDHE_RSA_AES128_CBC_SHA256   */
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    /* EL2GO_CIPHER_ECDHE_RSA_AES128_GCM_SHA256   */
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    /* EL2GO_CIPHER_ECDHE_RSA_AES256_CBC_SHA384   */
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
    /* EL2GO_CIPHER_ECDHE_RSA_AES256_GCM_SHA384   */
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    /* EL2GO_CIPHER_ECDH_RSA_AES128_CBC_SHA256    */
    MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
    /* EL2GO_CIPHER_ECDH_RSA_AES128_GCM_SHA256    */
    MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
    /* EL2GO_CIPHER_ECDH_RSA_AES256_CBC_SHA384    */
    MBEDTLS_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
    /* EL2GO_CIPHER_ECDH_RSA_AES256_GCM_SHA384    */
    MBEDTLS_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
    /* EL2GO_CIPHER_TLS1_3_AES_128_GCM_SHA256       */
    MBEDTLS_TLS1_3_AES_128_GCM_SHA256,
    /* EL2GO_CIPHER_TLS1_3_AES_256_GCM_SHA384       */
    MBEDTLS_TLS1_3_AES_256_GCM_SHA384,
    /* EL2GO_CIPHER_TLS1_3_CHACHA20_POLY1305_SHA256 */
    MBEDTLS_TLS1_3_CHACHA20_POLY1305_SHA256,
    /* EL2GO_CIPHER_TLS1_3_AES_128_CCM_SHA256       */
    MBEDTLS_TLS1_3_AES_128_CCM_SHA256,
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

int mbedtls_compat_ssl_conf_rng(mbedtls_ssl_config *conf, mbedtls_compat_rng_context *rng_ctx)
{
    if (conf == NULL || rng_ctx == NULL)
        return -1;

    mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, &rng_ctx->ctr_drbg);
    return 0;
}
