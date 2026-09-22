/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/*
 * mbedTLS 2.x crypto compatibility implementation.
 *
 * Contains SHA-256 streaming/one-shot functions (using _ret suffix API)
 * and EC public key extraction (direct struct field access).
 */

#include <mbedtls/sha256.h>
#include <mbedtls/ecp.h>

#include "builtin_macros.h"
#include "debug.h"

#include "mbedtls_compat_crypto.h"

/* ========================================================================== */
/* SHA-256 streaming/one-shot (v2: _ret suffix API)                           */
/* ========================================================================== */

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

/* ========================================================================== */
/* EC public key extraction (v2: direct grp/Q field access)                  */
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

    int ret = mbedtls_ecp_point_write_binary(&ecp->grp, &ecp->Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                             out_len, buf, buf_size);
    if (ret == MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL)
        return MBEDTLS_COMPAT_ERR_PK_BUFFER_TOO_SMALL;
    return ret;
}

/* ========================================================================== */
/* PK functions (v2-specific)                                                  */
/* ========================================================================== */

int mbedtls_compat_pk_setup_key(mbedtls_pk_context *pk, uint32_t key_id)
{
    (void)pk;
    (void)key_id;

    /* mbedTLS 2.x does not support PSA opaque keys. */
    EL2GO_DBG_PRINTF(ERROR, "PSA opaque key support not available in mbedTLS 2.x\n");
    EL2GO_DBG_PRINTF(ERROR, "Please use mbedTLS 3.x or later for hardware key support\n");

    return EL2GO_STATUS_NOT_IMPLEMENTED;
}
