/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef MBEDTLS_COMPAT_MACROS_V3_H
#define MBEDTLS_COMPAT_MACROS_V3_H

#include <mbedtls/version.h>
#include <mbedtls/ssl.h>

/**
 * @defgroup mbedtls_compat_v3 mbedTLS 3.x Compatibility
 * @ingroup mbedtls_compat
 * @brief mbedTLS 3.x specific compatibility macros and types.
 * @{
 */

/**
 * @brief Group/Curve ID type for mbedTLS 3.x.
 */
typedef uint16_t mbedtls_compat_group_id_t;

/**
 * @brief Sentinel value for unsupported curves in mbedTLS 3.x.
 */
#define MBEDTLS_COMPAT_CURVE_SENTINEL 0

/**
 * @brief Get peer certificate from SSL session in mbedTLS 3.x.
 *
 * Version dependent on minor version:
 *  - v3.0.x: Direct struct access.
 *  - v3.1.0+: Function call via mbedtls_ssl_get_peer_cert().
 */
#if MBEDTLS_VERSION_NUMBER < 0x03010000
#define MBEDTLS_COMPAT_GET_PEER_CERT(ssl) ((ssl)->session->peer_cert)
#else
#define MBEDTLS_COMPAT_GET_PEER_CERT(ssl) mbedtls_ssl_get_peer_cert(ssl)
#endif

/**
 * @brief Maximum SSL content length for mbedTLS 3.x.
 *
 * In mbedTLS 3.x the content length is split into IN/OUT directions.
 * This macro resolves to the minimum of the two.
 */
#if !defined(MBEDTLS_SSL_MAX_CONTENT_LEN)
#define MBEDTLS_SSL_MAX_CONTENT_LEN                                                          \
    (MBEDTLS_SSL_IN_CONTENT_LEN < MBEDTLS_SSL_OUT_CONTENT_LEN ? MBEDTLS_SSL_IN_CONTENT_LEN : \
                                                                MBEDTLS_SSL_OUT_CONTENT_LEN)
#endif

/** @} */ /* end of mbedtls_compat_v3 */

#endif /* MBEDTLS_COMPAT_MACROS_V3_H */