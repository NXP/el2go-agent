/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __MBEDTLS_COMPAT_MACROS_V2_H__
#define __MBEDTLS_COMPAT_MACROS_V2_H__

#include <mbedtls/ecp.h>

/** Group/curve ID type for mbedTLS 2.x (mbedtls_ecp_group_id). */
typedef mbedtls_ecp_group_id mbedtls_compat_group_id_t;

/** Sentinel value for unsupported curves in mbedTLS 2.x. */
#define MBEDTLS_COMPAT_CURVE_SENTINEL MBEDTLS_ECP_DP_NONE

/** Get peer certificate in mbedTLS 2.x via direct struct access. */
#define MBEDTLS_COMPAT_GET_PEER_CERT(ssl) ((ssl)->session->peer_cert)

#endif /* __MBEDTLS_COMPAT_MACROS_V2_H__ */
