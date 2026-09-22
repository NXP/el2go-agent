/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/*
 * mbedTLS 3.x crypto compatibility implementation.
 *
 * Contains SHA-256 streaming/one-shot functions (modern API, no _ret suffix)
 * and EC public key extraction (private_ prefix struct fields).
 */

#include <mbedtls/sha256.h>
#include <mbedtls/ecp.h>

#include "mbedtls_compat_crypto.h"

/* ========================================================================== */
/* SHA-256 streaming/one-shot (v3: modern API without _ret suffix)            */
/* ========================================================================== */

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

/* ========================================================================== */
/* EC public key extraction (v3: private_ prefix struct fields)               */
/* ========================================================================== */

int mbedtls_compat_pk_get_ec_pubkey_raw(const mbedtls_pk_context *pk, uint8_t *buf, size_t buf_size,
                                        size_t *out_len)
{
    mbedtls_ecp_keypair *ecp;

    if (pk == NULL || buf == NULL || out_len == NULL)
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;

    ecp = mbedtls_pk_ec(*pk);
    if (ecp == NULL)
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;

    int ret = mbedtls_ecp_point_write_binary(&ecp->private_grp, &ecp->private_Q,
                                             MBEDTLS_ECP_PF_UNCOMPRESSED, out_len, buf, buf_size);
    if (ret == MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL)
        return MBEDTLS_COMPAT_ERR_PK_BUFFER_TOO_SMALL;
    return ret;
}

/* ========================================================================== */
/* PK functions (v3-specific)                                                  */
/* ========================================================================== */

int mbedtls_compat_pk_setup_key(mbedtls_pk_context *pk, uint32_t key_id)
{
    mbedtls_svc_key_id_t svc_key_id;

    if (!pk)
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;

    svc_key_id = mbedtls_svc_key_id_make(0, key_id);

    return mbedtls_pk_setup_opaque(pk, svc_key_id);
}
