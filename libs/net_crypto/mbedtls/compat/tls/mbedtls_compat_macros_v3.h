/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __MBEDTLS_COMPAT_MACROS_V3_H__
#define __MBEDTLS_COMPAT_MACROS_V3_H__

/** @defgroup mbedtls_compat_v3 mbedTLS 3.x Compatibility Macros
 * @brief Portability shims for mbedTLS 3.x API differences.
 * @{
 */

#include <mbedtls/version.h>

/** Group/curve ID type for mbedTLS 3.x (IANA TLS group ID, uint16_t). */
typedef uint16_t mbedtls_compat_group_id_t;

/** Sentinel value for unsupported curves in mbedTLS 3.x. */
#define MBEDTLS_COMPAT_CURVE_SENTINEL 0

/*
 * Get peer certificate in mbedTLS 3.x.
 * v3.0.x uses direct struct access; v3.1.0+ uses a function call.
 */
#if MBEDTLS_VERSION_NUMBER < 0x03010000
#define MBEDTLS_COMPAT_GET_PEER_CERT(ssl) ((ssl)->session->peer_cert)
#else
#define MBEDTLS_COMPAT_GET_PEER_CERT(ssl) mbedtls_ssl_get_peer_cert(ssl)
#endif

/*
 * Resolve MAX_CONTENT_LEN as the minimum of IN/OUT lengths in mbedTLS 3.x.
 */
#if !defined(MBEDTLS_SSL_MAX_CONTENT_LEN)
#define MBEDTLS_SSL_MAX_CONTENT_LEN                                                          \
    (MBEDTLS_SSL_IN_CONTENT_LEN < MBEDTLS_SSL_OUT_CONTENT_LEN ? MBEDTLS_SSL_IN_CONTENT_LEN : \
                                                                MBEDTLS_SSL_OUT_CONTENT_LEN)
#endif

/** @} */ /* end of mbedtls_compat_v3 */

#endif /* __MBEDTLS_COMPAT_MACROS_V3_H__ */
