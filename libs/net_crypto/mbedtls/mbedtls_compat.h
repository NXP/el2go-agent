/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef MBEDTLS_COMPAT_H
#define MBEDTLS_COMPAT_H

#include <mbedtls/version.h>
#include <mbedtls/ssl.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>

#include "plat_crypto_params.h"

/**
 * @defgroup mbedtls_compat mbedTLS Compatibility
 * @brief mbedTLS version compatibility layer for EdgeLock 2GO.
 * @{
 */

/* ========================================================================== */
/* Version Detection Macros                                                    */
/* ========================================================================== */

/* Ensure MBEDTLS_VERSION_MAJOR is defined */
#if !defined(MBEDTLS_VERSION_MAJOR)
#error "MBEDTLS_VERSION_MAJOR is not defined - incompatible or missing mbedTLS version.h"
#endif

/* Validate supported version range */
#if MBEDTLS_VERSION_MAJOR < 2 || MBEDTLS_VERSION_MAJOR > 4
#error "Unsupported MbedTLS version - only versions 2, 3, and 4 are supported"
#endif

/* ========================================================================== */
/* Include version-specific macro definitions                                  */
/* ========================================================================== */

#if MBEDTLS_VERSION_MAJOR == 2
#include "mbedtls_compat_macros_v2.h"
#elif MBEDTLS_VERSION_MAJOR == 3
#include "mbedtls_compat_macros_v3.h"
#elif MBEDTLS_VERSION_MAJOR == 4
#include "mbedtls_compat_macros_v4.h"
#endif

/* ========================================================================== */
/* SSL Max Fragment Length Thresholds                                          */
/* ========================================================================== */

/**
 * @brief Threshold for selecting 2048 max fragment length.
 *
 * If MBEDTLS_SSL_MAX_CONTENT_LEN is below this value, use MBEDTLS_SSL_MAX_FRAG_LEN_2048.
 */
#define MBEDTLS_COMPAT_FRAG_LEN_2048 4096

/**
 * @brief Threshold for selecting 4096 max fragment length.
 *
 * If MBEDTLS_SSL_MAX_CONTENT_LEN is below this value, use MBEDTLS_SSL_MAX_FRAG_LEN_4096.
 */
#define MBEDTLS_COMPAT_FRAG_LEN_4096 (16 * 1024)

/* ========================================================================== */
/* RNG Context Type (opaque)                                                   */
/* ========================================================================== */

/**
 * @brief Opaque RNG context structure.
 *
 * Implementation differs by mbedTLS version:
 *  - v2.x and v3.x: Contains entropy + CTR_DRBG contexts.
 *  - v4.x: Empty (PSA crypto handles RNG internally).
 */
typedef struct mbedtls_compat_rng_context mbedtls_compat_rng_context;

/* ========================================================================== */
/* RNG Functions                                                               */
/* ========================================================================== */

/**
 * @brief Initialize RNG context.
 *
 * @param[out] ctx       Pointer to RNG context pointer (allocated by this function).
 * @param[in]  pers      Personalization string for RNG seeding.
 * @param[in]  pers_len  Length of personalization string.
 *
 * @return 0 on success, negative error code on failure.
 */
int mbedtls_compat_rng_init(mbedtls_compat_rng_context **ctx,
			    const unsigned char *pers, size_t pers_len);

/**
 * @brief Free RNG context.
 *
 * @param[in] ctx  RNG context to free.
 */
void mbedtls_compat_rng_free(mbedtls_compat_rng_context *ctx);

/**
 * @brief Configure SSL context with RNG.
 *
 * @param[in] conf     SSL configuration context.
 * @param[in] rng_ctx  RNG context.
 *
 * @return 0 on success, negative error code on failure.
 */
int mbedtls_compat_ssl_conf_rng(mbedtls_ssl_config *conf,
				mbedtls_compat_rng_context *rng_ctx);

/* ========================================================================== */
/* PK (Public Key) Functions                                                   */
/* ========================================================================== */

/**
 * @brief Setup PK context with PSA opaque key.
 *
 * @note For mbedTLS 2.x, this returns MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE.
 *
 * @param[in] pk      PK context to setup.
 * @param[in] key_id  PSA key ID (uint32_t, converted internally to mbedtls_svc_key_id_t).
 *
 * @return 0 on success, negative error code on failure.
 */
int mbedtls_compat_pk_setup_key(mbedtls_pk_context *pk, uint32_t key_id);

/**
 * @brief Check if PK context has a key configured.
 *
 * @param[in] pk  PK context to check.
 *
 * @return 1 if key is present, 0 otherwise.
 */
int mbedtls_compat_pk_has_key(const mbedtls_pk_context *pk);

/* ========================================================================== */
/* X.509 Certificate Functions                                                 */
/* ========================================================================== */

/**
 * @brief Set certificate serial number from raw bytes.
 *
 * Handles API differences between mbedTLS versions:
 *  - v2.x/v3.x: Converts to MPI then calls mbedtls_x509write_crt_set_serial.
 *  - v4.x: Calls mbedtls_x509write_crt_set_serial_raw directly.
 *
 * @param[in] ctx        Certificate write context.
 * @param[in] serial     Serial number as byte array.
 * @param[in] serial_len Length of serial number.
 *
 * @return 0 on success, negative error code on failure.
 */
int mbedtls_compat_x509write_crt_set_serial(mbedtls_x509write_cert *ctx,
					    const unsigned char *serial,
					    size_t serial_len);

/**
 * @brief Write certificate in DER format.
 *
 * Handles API differences between mbedTLS versions:
 *  - v2.x/v3.x: Requires RNG callback parameters.
 *  - v4.x: No RNG parameters needed (uses PSA internally).
 *
 * @param[in] ctx      Certificate write context.
 * @param[in] buf      Output buffer.
 * @param[in] size     Buffer size.
 * @param[in] rng_ctx  RNG context (may be NULL for v4.x).
 *
 * @return Number of bytes written on success, negative error code on failure.
 */
int mbedtls_compat_x509write_crt_der(mbedtls_x509write_cert *ctx,
				     unsigned char *buf, size_t size,
				     mbedtls_compat_rng_context *rng_ctx);

/* ========================================================================== */
/* SSL Configuration - Curves/Groups                                           */
/* ========================================================================== */

/**
 * @brief Configure supported elliptic curves/groups.
 *
 * Handles API differences between mbedTLS versions:
 *  - v2.x/v3.x: Calls mbedtls_ssl_conf_curves.
 *  - v4.x: Calls mbedtls_ssl_conf_groups.
 *
 * @param[in] conf    SSL configuration context.
 * @param[in] groups  NULL-terminated array of group IDs.
 */
void mbedtls_compat_ssl_conf_groups(mbedtls_ssl_config *conf,
				    const mbedtls_compat_group_id_t *groups);

/* ========================================================================== */
/* Cipher Suite Mapping                                                        */
/* ========================================================================== */

/**
 * @brief Get the size of the cipher suite mapping table.
 *
 * @return Number of entries in the cipher suite mapping table.
 */
size_t mbedtls_compat_cipher_suite_map_size(void);

/**
 * @brief Convert platform cipher suite to mbedTLS ID.
 *
 * @param[in] suite  Platform-agnostic cipher suite identifier.
 *
 * @return mbedTLS cipher suite ID, or 0 if not supported in this version.
 */
int mbedtls_compat_cipher_suite_to_id(el2go_cipher_suite_t suite);

/**
 * @brief Get the size of the curve mapping table.
 *
 * @return Number of entries in the curve mapping table.
 */
size_t mbedtls_compat_curve_map_size(void);

/**
 * @brief Convert platform curve ID to mbedTLS group ID.
 *
 * @param[in] curve  Platform-agnostic curve identifier.
 *
 * @return mbedTLS group ID, or MBEDTLS_COMPAT_CURVE_SENTINEL if not supported
 *         by this mbedTLS version.
 */
mbedtls_compat_group_id_t mbedtls_compat_curve_to_id(el2go_curve_id_t curve);

/** @} */ /* end of mbedtls_compat */

#endif /* MBEDTLS_COMPAT_H */