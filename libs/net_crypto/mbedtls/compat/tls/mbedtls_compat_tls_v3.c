/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "builtin_macros.h"

#include "mbedtls_compat_tls.h"

/* ========================================================================== */
/* Curve mapping (v3-specific: uses IANA TLS group IDs)                       */
/* ========================================================================== */

/**
 * Curve mapping table for mbedTLS 3.x.
 * Uses IANA TLS group IDs (uint16_t).
 * Order must match el2go_curve_id_t in plat_crypto_params.h.
 */
static const mbedtls_compat_group_id_t curve_map[] = {
    MBEDTLS_SSL_IANA_TLS_GROUP_SECP224R1, /* EL2GO_CURVE_SECP224R1 */
    MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1, /* EL2GO_CURVE_SECP256R1 */
    MBEDTLS_SSL_IANA_TLS_GROUP_SECP384R1, /* EL2GO_CURVE_SECP384R1 */
    MBEDTLS_SSL_IANA_TLS_GROUP_SECP521R1, /* EL2GO_CURVE_SECP521R1 */
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
/* SSL configuration (v3-specific)                                             */
/* ========================================================================== */

void mbedtls_compat_ssl_conf_groups(mbedtls_ssl_config *conf,
                                    const mbedtls_compat_group_id_t *groups)
{
    mbedtls_ssl_conf_groups(conf, groups);
}
