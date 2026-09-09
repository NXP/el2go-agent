/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __MBEDTLS_COMPAT_MACROS_V4_H__
#define __MBEDTLS_COMPAT_MACROS_V4_H__

/** @defgroup mbedtls_compat_v4 mbedTLS 4.x Compatibility Macros
 * @brief Portability shims for mbedTLS 4.x API differences.
 * @{
 */

#include <psa/crypto.h>

/** Group/curve ID type for mbedTLS 4.x (IANA TLS group ID, uint16_t). */
typedef uint16_t mbedtls_compat_group_id_t;

/** Sentinel value for unsupported curves in mbedTLS 4.x. */
#define MBEDTLS_COMPAT_CURVE_SENTINEL 0

/** Get peer certificate in mbedTLS 4.x via function call. */
#define MBEDTLS_COMPAT_GET_PEER_CERT(ssl) mbedtls_ssl_get_peer_cert(ssl)

/*
 * Resolve MAX_CONTENT_LEN as the minimum of IN/OUT lengths in mbedTLS 4.x.
 */
#if !defined(MBEDTLS_SSL_MAX_CONTENT_LEN)
#define MBEDTLS_SSL_MAX_CONTENT_LEN                                                          \
    (MBEDTLS_SSL_IN_CONTENT_LEN < MBEDTLS_SSL_OUT_CONTENT_LEN ? MBEDTLS_SSL_IN_CONTENT_LEN : \
                                                                MBEDTLS_SSL_OUT_CONTENT_LEN)
#endif

/** @} */ /* end of mbedtls_compat_v4 */

#endif /* __MBEDTLS_COMPAT_MACROS_V4_H__ */
