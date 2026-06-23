/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef MBEDTLS_COMPAT_MACROS_V4_H
#define MBEDTLS_COMPAT_MACROS_V4_H

#include <mbedtls/version.h>
#include <mbedtls/ssl.h>
#include <stdint.h>

/**
 * @defgroup mbedtls_compat_v4 mbedTLS 4.x Compatibility
 * @ingroup mbedtls_compat
 * @brief mbedTLS 4.x specific compatibility macros and types.
 * @{
 */

/**
 * @brief Group/Curve ID type for mbedTLS 4.x.
 */
typedef uint16_t mbedtls_compat_group_id_t;

/**
 * @brief Sentinel value for unsupported curves in mbedTLS 4.x.
 */
#define MBEDTLS_COMPAT_CURVE_SENTINEL 0

/**
 * @brief Get peer certificate from SSL session in mbedTLS 4.x.
 *
 * In mbedTLS 4.x peer certificate access is always done via
 * mbedtls_ssl_get_peer_cert() function call.
 */
#define MBEDTLS_COMPAT_GET_PEER_CERT(ssl) mbedtls_ssl_get_peer_cert(ssl)

/**
 * @brief Maximum SSL content length for mbedTLS 4.x.
 *
 * In mbedTLS 4.x the content length is split into IN/OUT directions.
 * This macro resolves to the minimum of the two.
 */
#if !defined(MBEDTLS_SSL_MAX_CONTENT_LEN)
#define MBEDTLS_SSL_MAX_CONTENT_LEN                                                          \
    (MBEDTLS_SSL_IN_CONTENT_LEN < MBEDTLS_SSL_OUT_CONTENT_LEN ? MBEDTLS_SSL_IN_CONTENT_LEN : \
                                                                MBEDTLS_SSL_OUT_CONTENT_LEN)
#endif

/** @} */ /* end of mbedtls_compat_v4 */

#endif /* MBEDTLS_COMPAT_MACROS_V4_H */