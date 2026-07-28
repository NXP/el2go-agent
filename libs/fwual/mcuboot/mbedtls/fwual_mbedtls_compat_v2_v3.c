/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/*
 * fwual mbedTLS compatibility layer - mbedTLS 2.x and 3.x implementation.
 *
 * SHA-256 is handled via the mbedtls_sha256_* API.
 * Constant-time compare uses mbedtls_ct_memcmp from <mbedtls/constant_time.h>.
 */

#include <mbedtls/version.h>

#if MBEDTLS_VERSION_MAJOR < 4

#include <mbedtls/sha256.h>
#include <mbedtls/constant_time.h>

#include "fwual_mbedtls_compat.h"

void fwual_sha256_init(fwual_sha256_context *ctx)
{
    mbedtls_sha256_init(&ctx->ctx);
}

void fwual_sha256_free(fwual_sha256_context *ctx)
{
    mbedtls_sha256_free(&ctx->ctx);
}

int fwual_sha256_starts(fwual_sha256_context *ctx)
{
    return mbedtls_sha256_starts_ret(&ctx->ctx, 0 /* 0 = SHA-256, not SHA-224 */);
}

int fwual_sha256_update(fwual_sha256_context *ctx, const unsigned char *input, size_t ilen)
{
    return mbedtls_sha256_update_ret(&ctx->ctx, input, ilen);
}

int fwual_sha256_finish(fwual_sha256_context *ctx, unsigned char output[32])
{
    return mbedtls_sha256_finish_ret(&ctx->ctx, output);
}

int fwual_ct_memcmp(const void *a, const void *b, size_t len)
{
    return mbedtls_ct_memcmp(a, b, len);
}

#endif /* MBEDTLS_VERSION_MAJOR < 4 */
