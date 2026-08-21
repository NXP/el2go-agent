/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __MBEDTLS_COMPAT_TLS_H__
#define __MBEDTLS_COMPAT_TLS_H__

#include <mbedtls/ssl.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>
#include <stdint.h>

#include "plat_crypto_params.h"
#include "compat/mbedtls_compat_rng.h"

/*
 * Pull in the version-specific type definitions and macros.
 * Each header defines mbedtls_compat_group_id_t, MBEDTLS_COMPAT_CURVE_SENTINEL,
 * and MBEDTLS_COMPAT_GET_PEER_CERT for the corresponding mbedTLS major version.
 */
#if MBEDTLS_VERSION_MAJOR == 2
#include "mbedtls_compat_macros_v2.h"
#elif MBEDTLS_VERSION_MAJOR == 3
#include "mbedtls_compat_macros_v3.h"
#elif MBEDTLS_VERSION_MAJOR == 4
#include "mbedtls_compat_macros_v4.h"
#endif

/**
 * @defgroup mbedtls_compat_tls mbedTLS TLS Compatibility
 * @brief Version-specific TLS types, macros, and function wrappers.
 * @{
 */

/* ========================================================================== */
/* Fragment length constants                                                   */
/* ========================================================================== */

/** 2048-byte fragment length in bytes (used with MBEDTLS_SSL_MAX_FRAG_LEN_2048). */
#define MBEDTLS_COMPAT_FRAG_LEN_2048 2048U

/** 4096-byte fragment length in bytes (used with MBEDTLS_SSL_MAX_FRAG_LEN_4096). */
#define MBEDTLS_COMPAT_FRAG_LEN_4096 4096U

/* ========================================================================== */
/* RNG / SSL configuration                                                     */
/* ========================================================================== */

/**
 * @brief Configure SSL context with RNG.
 *
 * @param[in] conf     SSL configuration context.
 * @param[in] rng_ctx  RNG context.
 *
 * @return 0 on success, negative error code on failure.
 */
int mbedtls_compat_ssl_conf_rng(mbedtls_ssl_config *conf, mbedtls_compat_rng_context *rng_ctx);

/**
 * @brief Configure supported elliptic curves/groups on an SSL config.
 *
 * - v2.x: calls mbedtls_ssl_conf_curves.
 * - v3.x/v4.x: calls mbedtls_ssl_conf_groups.
 *
 * @param[in] conf    SSL configuration context.
 * @param[in] groups  NULL-terminated array of group IDs.
 */
void mbedtls_compat_ssl_conf_groups(mbedtls_ssl_config *conf,
                                    const mbedtls_compat_group_id_t *groups);

/* ========================================================================== */
/* Cipher suite and curve mapping                                              */
/* ========================================================================== */

/**
 * @brief Get the number of entries in the cipher suite mapping table.
 *
 * @return Number of entries.
 */
size_t mbedtls_compat_cipher_suite_map_size(void);

/**
 * @brief Convert a platform cipher suite identifier to a mbedTLS cipher suite ID.
 *
 * @param[in] suite  Platform cipher suite.
 *
 * @return mbedTLS cipher suite ID, or 0 if not supported in this version.
 */
int mbedtls_compat_cipher_suite_to_id(el2go_cipher_suite_t suite);

/**
 * @brief Get the number of entries in the curve mapping table.
 *
 * @return Number of entries.
 */
size_t mbedtls_compat_curve_map_size(void);

/**
 * @brief Convert a platform curve ID to a mbedTLS group ID.
 *
 * @param[in] curve  Platform curve identifier.
 *
 * @return mbedTLS group ID, or MBEDTLS_COMPAT_CURVE_SENTINEL if not supported.
 */
mbedtls_compat_group_id_t mbedtls_compat_curve_to_id(el2go_curve_id_t curve);

/** @} */

#endif /* __MBEDTLS_COMPAT_TLS_H__ */
