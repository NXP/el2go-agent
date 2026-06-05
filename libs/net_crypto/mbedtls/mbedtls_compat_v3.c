/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <mbedtls/version.h>
#include <mbedtls/sha256.h>
#include <psa/crypto.h>

#include "builtin_macros.h"

#include "mbedtls_compat.h"

/**
 * @addtogroup mbedtls_compat_v3
 * @{
 */

/**
 * @brief Curve mapping table from platform-agnostic curve IDs to mbedTLS 3.x format.
 *
 * Uses IANA TLS group IDs (uint16_t).
 *
 * @note Order must match @ref el2go_curve_id_t enum in plat_crypto_params.h.
 * @note Size must match @ref EL2GO_CURVE_MAX.
 */
static const mbedtls_compat_group_id_t curve_map[] = {
    MBEDTLS_SSL_IANA_TLS_GROUP_SECP224R1, /* EL2GO_CURVE_SECP224R1 */
    MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1, /* EL2GO_CURVE_SECP256R1 */
    MBEDTLS_SSL_IANA_TLS_GROUP_SECP384R1, /* EL2GO_CURVE_SECP384R1 */
    MBEDTLS_SSL_IANA_TLS_GROUP_SECP521R1, /* EL2GO_CURVE_SECP521R1 */
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
/* PK Functions (v3-specific)                                                 */
/* ========================================================================== */

int mbedtls_compat_pk_setup_key(mbedtls_pk_context *pk, uint32_t key_id)
{
    mbedtls_svc_key_id_t svc_key_id;

    if (!pk)
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;

    /* Convert uint32_t to mbedtls_svc_key_id_t */
    svc_key_id = mbedtls_svc_key_id_make(0, key_id);

    return mbedtls_pk_setup_opaque(pk, svc_key_id);
}

/* ========================================================================== */
/* SSL Configuration Functions (v3-specific)                                  */
/* ========================================================================== */

void mbedtls_compat_ssl_conf_groups(mbedtls_ssl_config *conf,
                                    const mbedtls_compat_group_id_t *groups)
{
    mbedtls_ssl_conf_groups(conf, groups);
}

/* ========================================================================== */
/* SHA-256 Functions - mbedTLS v3.x                                           */
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
    return mbedtls_sha256_starts(&ctx->ctx, 0);
}

int mbedtls_compat_sha256_update(mbedtls_compat_sha256_context *ctx, const unsigned char *input,
                                 size_t ilen)
{
    return mbedtls_sha256_update(&ctx->ctx, input, ilen);
}

int mbedtls_compat_sha256_finish(mbedtls_compat_sha256_context *ctx, unsigned char output[32])
{
    return mbedtls_sha256_finish(&ctx->ctx, output);
}

int mbedtls_compat_sha256(const unsigned char *input, size_t ilen, unsigned char output[32])
{
    return mbedtls_sha256(input, ilen, output, 0);
}

/** @} */ /* end of mbedtls_compat_v3 */
