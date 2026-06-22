/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef MBEDTLS_COMPAT_MACROS_V2_H
#define MBEDTLS_COMPAT_MACROS_V2_H

#include <mbedtls/version.h>
#include <mbedtls/ssl.h>

/**
 * @defgroup mbedtls_compat_v2 mbedTLS 2.x Compatibility
 * @ingroup mbedtls_compat
 * @brief mbedTLS 2.x specific compatibility macros and types.
 * @{
 */

/**
 * @brief Group/Curve ID type for mbedTLS 2.x.
 */
typedef mbedtls_ecp_group_id mbedtls_compat_group_id_t;

/**
 * @brief Sentinel value for unsupported curves in mbedTLS 2.x.
 */
#define MBEDTLS_COMPAT_CURVE_SENTINEL MBEDTLS_ECP_DP_NONE

/**
 * @brief Get peer certificate from SSL session in mbedTLS 2.x.
 */
#define MBEDTLS_COMPAT_GET_PEER_CERT(ssl) ((ssl)->session->peer_cert)

/** @} */ /* end of mbedtls_compat_v2 */

#endif /* MBEDTLS_COMPAT_MACROS_V2_H */