/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <mbedtls/error.h>

#include "builtin_macros.h"

#include "mbedtls_compat_tls.h"

/* ========================================================================== */
/* Curve mapping (v2-specific: uses mbedtls_ecp_group_id)                     */
/* ========================================================================== */

/**
 * Curve mapping table for mbedTLS 2.x.
 * Uses mbedtls_ecp_group_id values.
 * Order must match el2go_curve_id_t in plat_crypto_params.h.
 */
static const mbedtls_compat_group_id_t curve_map[] = {
    MBEDTLS_ECP_DP_SECP224R1, /* EL2GO_CURVE_SECP224R1 */
    MBEDTLS_ECP_DP_SECP256R1, /* EL2GO_CURVE_SECP256R1 */
    MBEDTLS_ECP_DP_SECP384R1, /* EL2GO_CURVE_SECP384R1 */
    MBEDTLS_ECP_DP_SECP521R1, /* EL2GO_CURVE_SECP521R1 */
};

size_t mbedtls_compat_curve_map_size(void)
{
    return ARRAY_SIZE(curve_map);
}

mbedtls_compat_group_id_t mbedtls_compat_curve_to_id(el2go_curve_id_t curve)
{
    if (curve >= ARRAY_SIZE(curve_map))
        return MBEDTLS_COMPAT_CURVE_SENTINEL;

    return curve_map[curve];
}

/* ========================================================================== */
/* SSL configuration (v2-specific)                                             */
/* ========================================================================== */

void mbedtls_compat_ssl_conf_groups(mbedtls_ssl_config *conf,
                                    const mbedtls_compat_group_id_t *groups)
{
    /* mbedTLS 2.x uses mbedtls_ssl_conf_curves with mbedtls_ecp_group_id array */
    mbedtls_ssl_conf_curves(conf, groups);
}
