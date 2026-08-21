/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __MBEDTLS_COMPAT_RNG_H__
#define __MBEDTLS_COMPAT_RNG_H__

#include <mbedtls/version.h>
#include <stddef.h>

/**
 * @defgroup mbedtls_compat_rng mbedTLS RNG Compatibility
 * @brief Shared RNG abstraction used by both TLS and CSR compat layers.
 * @{
 */

#if MBEDTLS_VERSION_MAJOR < 4

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

/**
 * @brief RNG context for mbedTLS 2.x and 3.x.
 *
 * Wraps entropy and CTR_DRBG contexts. Defined here so that all compat
 * layers (TLS, crypto, CSR) can access struct fields without cross-directory
 * includes.
 */
struct mbedtls_compat_rng_context {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
};

#endif /* MBEDTLS_VERSION_MAJOR < 4 */

/**
 * @brief Opaque RNG context typedef.
 *
 * - v2/v3: struct body defined above; fields accessible to all compat layers.
 * - v4:    empty stub; PSA crypto handles RNG internally (struct defined in
 *          compat/tls/mbedtls_compat_tls_v4.c).
 */
typedef struct mbedtls_compat_rng_context mbedtls_compat_rng_context;

/**
 * @brief Initialize RNG context.
 *
 * @param[out] ctx       Pointer to RNG context pointer (allocated by this function).
 * @param[in]  pers      Personalization string for RNG seeding.
 * @param[in]  pers_len  Length of personalization string.
 *
 * @return 0 on success, negative error code on failure.
 */
int mbedtls_compat_rng_init(mbedtls_compat_rng_context **ctx, const unsigned char *pers,
                            size_t pers_len);

/**
 * @brief Free RNG context.
 *
 * @param[in] ctx  RNG context to free (may be NULL).
 */
void mbedtls_compat_rng_free(mbedtls_compat_rng_context *ctx);

/** @} */

#endif /* __MBEDTLS_COMPAT_RNG_H__ */
