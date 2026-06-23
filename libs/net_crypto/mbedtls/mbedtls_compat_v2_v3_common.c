/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <mbedtls/version.h>

/* Only compile common code for versions that share implementation (2.x and 3.x) */
#if MBEDTLS_VERSION_MAJOR < 4

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/bignum.h>
#include <mbedtls/x509_crt.h>

#include "builtin_macros.h"
#include "osal.h"

#include "mbedtls_compat.h"

/**
 * @defgroup mbedtls_compat_v2_v3 mbedTLS 2.x and 3.x Common Implementation
 * @ingroup mbedtls_compat
 * @brief Shared implementation for mbedTLS 2.x and 3.x compatibility layer.
 * @{
 */

/* ========================================================================== */
/* RNG Context Structure (shared between v2 and v3)                           */
/* ========================================================================== */

/**
 * @brief RNG context for mbedTLS 2.x and 3.x.
 *
 * Contains entropy and CTR_DRBG contexts required for random number
 * generation in mbedTLS versions prior to 4.x. In mbedTLS 4.x this
 * structure is empty as PSA crypto handles RNG internally.
 */
struct mbedtls_compat_rng_context {
    mbedtls_entropy_context entropy;   /**< Entropy context for seeding. */
    mbedtls_ctr_drbg_context ctr_drbg; /**< CTR_DRBG context for RNG. */
};

/* ========================================================================== */
/* Cipher Suite Mapping                                                        */
/* ========================================================================== */

/**
 * @brief Mapping from el2go_cipher_suite_t to mbedTLS cipher suite IDs.
 *
 * Index corresponds to @ref el2go_cipher_suite_t value.
 * 0 means not supported.
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

/* ========================================================================== */
/* RNG Functions (shared between v2 and v3)                                   */
/* ========================================================================== */

int mbedtls_compat_rng_init(mbedtls_compat_rng_context **ctx, const unsigned char *pers,
                            size_t pers_len)
{
    int ret = 0;
    mbedtls_compat_rng_context *rng_ctx;

    if (!ctx)
        return -1;

    rng_ctx = osal_calloc(1, sizeof(mbedtls_compat_rng_context));
    if (!rng_ctx)
        return -1;

    mbedtls_ctr_drbg_init(&rng_ctx->ctr_drbg);
    mbedtls_entropy_init(&rng_ctx->entropy);

    ret = mbedtls_ctr_drbg_seed(&rng_ctx->ctr_drbg, mbedtls_entropy_func, &rng_ctx->entropy, pers,
                                pers_len);
    if (ret != 0) {
        mbedtls_ctr_drbg_free(&rng_ctx->ctr_drbg);
        mbedtls_entropy_free(&rng_ctx->entropy);
        osal_free(rng_ctx);
        return ret;
    }

    *ctx = rng_ctx;
    return 0;
}

void mbedtls_compat_rng_free(mbedtls_compat_rng_context *ctx)
{
    if (!ctx)
        return;

    mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
    mbedtls_entropy_free(&ctx->entropy);
    osal_free(ctx);
}

int mbedtls_compat_ssl_conf_rng(mbedtls_ssl_config *conf, mbedtls_compat_rng_context *rng_ctx)
{
    if (!conf || !rng_ctx)
        return -1;

    mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, &rng_ctx->ctr_drbg);
    return 0;
}

/* ========================================================================== */
/* PK Functions (shared between v2 and v3)                                    */
/* ========================================================================== */

int mbedtls_compat_pk_has_key(const mbedtls_pk_context *pk)
{
    return mbedtls_pk_get_type(pk) != MBEDTLS_PK_NONE;
}

/* ========================================================================== */
/* X.509 Certificate Functions (shared between v2 and v3)                     */
/* ========================================================================== */

int mbedtls_compat_x509write_crt_set_serial(mbedtls_x509write_cert *ctx,
                                            const unsigned char *serial, size_t serial_len)
{
    int ret;
    mbedtls_mpi mpi_serial;

    mbedtls_mpi_init(&mpi_serial);
    ret = mbedtls_mpi_read_binary(&mpi_serial, serial, serial_len);
    if (ret == 0)
        ret = mbedtls_x509write_crt_set_serial(ctx, &mpi_serial);
    mbedtls_mpi_free(&mpi_serial);

    return ret;
}

int mbedtls_compat_x509write_crt_der(mbedtls_x509write_cert *ctx, unsigned char *buf, size_t size,
                                     mbedtls_compat_rng_context *rng_ctx)
{
    if (!rng_ctx)
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;

    return mbedtls_x509write_crt_der(ctx, buf, size, mbedtls_ctr_drbg_random, &rng_ctx->ctr_drbg);
}

/** @} */ /* end of mbedtls_compat */

#endif /* MBEDTLS_VERSION_MAJOR < 4 */