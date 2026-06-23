/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __PLAT_CRYPTO_PARAMS_H__
#define __PLAT_CRYPTO_PARAMS_H__

#include <stddef.h>
#include <stdint.h>

/**
 * @addtogroup el2go_platform_int
 * @{
 */

/* ========================================================================== */
/* Cipher suites                                                               */
/* ========================================================================== */

/**
 * @brief Platform-agnostic cipher suite identifiers.
 *
 * These represent cipher suites independent of any TLS library.
 * Each platform defines which cipher suites it supports.
 *
 * @note Order must match cipher_suite_map in mbedtls_mapping.c
 */
typedef enum {
    /* TLS 1.2 - ECDHE-ECDSA cipher suites */
    EL2GO_CIPHER_ECDHE_ECDSA_AES128_CBC_SHA256 = 0, /**< TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 */
    EL2GO_CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256,     /**< TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 */
    EL2GO_CIPHER_ECDHE_ECDSA_AES256_CBC_SHA384,     /**< TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 */
    EL2GO_CIPHER_ECDHE_ECDSA_AES256_GCM_SHA384,     /**< TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 */

    /* TLS 1.2 - ECDH-ECDSA cipher suites */
    EL2GO_CIPHER_ECDH_ECDSA_AES128_CBC_SHA256, /**< TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 */
    EL2GO_CIPHER_ECDH_ECDSA_AES128_GCM_SHA256, /**< TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 */
    EL2GO_CIPHER_ECDH_ECDSA_AES256_CBC_SHA384, /**< TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 */
    EL2GO_CIPHER_ECDH_ECDSA_AES256_GCM_SHA384, /**< TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 */

    /* TLS 1.2 - ECDHE-RSA cipher suites */
    EL2GO_CIPHER_ECDHE_RSA_AES128_CBC_SHA256, /**< TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 */
    EL2GO_CIPHER_ECDHE_RSA_AES128_GCM_SHA256, /**< TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 */
    EL2GO_CIPHER_ECDHE_RSA_AES256_CBC_SHA384, /**< TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 */
    EL2GO_CIPHER_ECDHE_RSA_AES256_GCM_SHA384, /**< TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 */

    /* TLS 1.2 - ECDH-RSA cipher suites */
    EL2GO_CIPHER_ECDH_RSA_AES128_CBC_SHA256, /**< TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 */
    EL2GO_CIPHER_ECDH_RSA_AES128_GCM_SHA256, /**< TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 */
    EL2GO_CIPHER_ECDH_RSA_AES256_CBC_SHA384, /**< TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 */
    EL2GO_CIPHER_ECDH_RSA_AES256_GCM_SHA384, /**< TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 */

    /* TODO: Add TLS 1.3 cipher suites */

    EL2GO_CIPHER_MAX /**< Sentinel value, must be last */
} el2go_cipher_suite_t;

/**
 * @brief Platform cipher suite list.
 *
 * Holds a pointer to an array of cipher suites and their count,
 * as returned by the platform-specific implementation.
 */
typedef struct {
    const el2go_cipher_suite_t *suites; /**< Pointer to array of supported cipher suites */
    size_t count;                       /**< Number of cipher suites in the array */
} el2go_cipher_list_t;

/**
 * @brief Get platform-specific cipher suite list.
 *
 * Returns the list of cipher suites supported by this platform.
 * Override this function in the platform-specific implementation.
 *
 * @return @ref el2go_cipher_list_t value, containing the supported cipher suites and their count.
 */
el2go_cipher_list_t el2go_platform_get_cipher_suites(void);

/* ========================================================================== */
/* Curves                                                                      */
/* ========================================================================== */

/**
 * @brief Elliptic curve group identifier.
 *
 * Platform-agnostic enumeration for elliptic curve groups.
 * Maps to the underlying crypto library's curve identifiers.
 */
typedef enum {
    EL2GO_CURVE_SECP224R1 = 0, /**< NIST P-224 curve */
    EL2GO_CURVE_SECP256R1,     /**< NIST P-256 curve */
    EL2GO_CURVE_SECP384R1,     /**< NIST P-384 curve */
    EL2GO_CURVE_SECP521R1,     /**< NIST P-521 curve */
    /* TODO: Add more curves as needed */
    EL2GO_CURVE_MAX /**< Sentinel value, must be last */
} el2go_curve_id_t;

/**
 * @brief Platform curve list.
 *
 * Holds a pointer to an array of elliptic curve identifiers and their count,
 * as returned by the platform-specific implementation.
 */
typedef struct {
    const el2go_curve_id_t *curves; /**< Pointer to array of supported elliptic curves */
    size_t count;                   /**< Number of curves in the array */
} el2go_curve_list_t;

/**
 * @brief Get platform-specific curve list.
 *
 * Returns the list of elliptic curves supported by this platform.
 * When no platform-specific curves are provided, the caller
 * will use mbedTLS default curves.
 *
 * Override this function in the platform-specific implementation.
 *
 * @return @ref el2go_curve_list_t value, containing the supported curves and their count.
 */
el2go_curve_list_t el2go_platform_get_curves(void);

/** @} */ /* end of el2go_platform_int */

#endif /* __PLAT_CRYPTO_PARAMS_H__ */
