/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <mbedtls/error.h>

#include "builtin_macros.h"
#include "debug.h"

#include "mbedtls_compat.h"

/**
 * @addtogroup mbedtls_compat_v2
 * @{
 */

/**
 * @brief Curve mapping table from platform-agnostic curve IDs to mbedTLS 2.x format.
 *
 * Uses mbedtls_ecp_group_id values.
 *
 * @note Order must match @ref el2go_curve_id_t enum in plat_crypto_params.h.
 * @note Size must match @ref EL2GO_CURVE_MAX.
 */
static const mbedtls_compat_group_id_t curve_map[] = {
    MBEDTLS_ECP_DP_SECP224R1, /* EL2GO_CURVE_SECP224R1 */
    MBEDTLS_ECP_DP_SECP256R1, /* EL2GO_CURVE_SECP256R1 */
    MBEDTLS_ECP_DP_SECP384R1, /* EL2GO_CURVE_SECP384R1 */
    MBEDTLS_ECP_DP_SECP521R1, /* EL2GO_CURVE_SECP521R1 */
};

/* Functions are documented in mbedtls_compat.h */

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
/* PK Functions (v2-specific)                                                 */
/* ========================================================================== */

int mbedtls_compat_pk_setup_key(mbedtls_pk_context *pk, uint32_t key_id)
{
    (void)pk;
    (void)key_id;

    /*
	 * mbedTLS 2.x doesn't have PSA crypto support or mbedtls_pk_setup_opaque.
	 * Hardware-backed keys would require custom PK implementation.
	 * For now, return feature unavailable.
	 */
    EL2GO_DBG_PRINTF(ERROR, "PSA opaque key support not available in mbedTLS 2.x\n");
    EL2GO_DBG_PRINTF(ERROR, "Please use mbedTLS 3.x or later for hardware key support\n");

    return EL2GO_STATUS_NOT_IMPLEMENTED;
}

/* ========================================================================== */
/* SSL Configuration Functions (v2-specific)                                  */
/* ========================================================================== */

void mbedtls_compat_ssl_conf_groups(mbedtls_ssl_config *conf,
                                    const mbedtls_compat_group_id_t *groups)
{
    /* mbedTLS 2.x uses mbedtls_ssl_conf_curves */
    mbedtls_ssl_conf_curves(conf, groups);
}

/* ========================================================================== */
/* SHA-256 Functions - mbedTLS v2.x                                           */
/* ========================================================================== */

void mbedtls_compat_sha256_init(mbedtls_compat_sha256_context *ctx)
{
    mbedtls_sha256_init(&ctx->ctx);
}

void mbedtls_compat_sha256_free(mbedtls_compat_sha256_context *ctx)
{
    mbedtls_sha256_free(&ctx->ctx);
}

int mbedtls_compat_sha256_starts(mbedtls_compat_sha256_context *ctx)
{
    return mbedtls_sha256_starts_ret(&ctx->ctx, 0);
}

int mbedtls_compat_sha256_update(mbedtls_compat_sha256_context *ctx, const unsigned char *input,
                                 size_t ilen)
{
    return mbedtls_sha256_update_ret(&ctx->ctx, input, ilen);
}

int mbedtls_compat_sha256_finish(mbedtls_compat_sha256_context *ctx, unsigned char output[32])
{
    return mbedtls_sha256_finish_ret(&ctx->ctx, output);
}

int mbedtls_compat_sha256(const unsigned char *input, size_t ilen, unsigned char output[32])
{
    return mbedtls_sha256_ret(input, ilen, output, 0);
}

/** @} */ /* end of mbedtls_compat_v2 */
