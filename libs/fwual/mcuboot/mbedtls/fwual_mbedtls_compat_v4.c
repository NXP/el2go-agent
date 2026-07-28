/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/*
 * fwual mbedTLS compatibility layer - mbedTLS 4.x implementation.
 *
 * SHA-256 is handled via the PSA crypto API (psa_hash_*).
 * Constant-time compare uses a manual bitwise-OR loop since
 * <mbedtls/constant_time.h> is not available in mbedTLS 4.x.
 */

#include <mbedtls/version.h>

#if MBEDTLS_VERSION_MAJOR >= 4

#include <psa/crypto.h>

#include "fwual_mbedtls_compat.h"

void fwual_sha256_init(fwual_sha256_context *ctx)
{
    ctx->ctx = psa_hash_operation_init();
}

void fwual_sha256_free(fwual_sha256_context *ctx)
{
    (void)psa_hash_abort(&ctx->ctx);
}

int fwual_sha256_starts(fwual_sha256_context *ctx)
{
    psa_status_t status = psa_hash_setup(&ctx->ctx, PSA_ALG_SHA_256);

    return (status == PSA_SUCCESS) ? 0 : -1;
}

int fwual_sha256_update(fwual_sha256_context *ctx, const unsigned char *input, size_t ilen)
{
    psa_status_t status = psa_hash_update(&ctx->ctx, input, ilen);

    return (status == PSA_SUCCESS) ? 0 : -1;
}

int fwual_sha256_finish(fwual_sha256_context *ctx, unsigned char output[32])
{
    size_t hash_len = 0;
    psa_status_t status =
        psa_hash_finish(&ctx->ctx, output, PSA_HASH_LENGTH(PSA_ALG_SHA_256), &hash_len);

    return (status == PSA_SUCCESS) ? 0 : -1;
}

int fwual_ct_memcmp(const void *a, const void *b, size_t len)
{
    const unsigned char *pa = (const unsigned char *)a;
    const unsigned char *pb = (const unsigned char *)b;
    unsigned char diff = 0;
    size_t i;

    for (i = 0; i < len; i++) {
        diff |= pa[i] ^ pb[i];
    }

    return (int)diff;
}

#endif /* MBEDTLS_VERSION_MAJOR >= 4 */
