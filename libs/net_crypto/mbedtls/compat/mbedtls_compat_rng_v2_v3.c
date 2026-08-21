/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/*
 * RNG compatibility implementation for mbedTLS 2.x and 3.x.
 *
 * Uses CTR-DRBG seeded from an entropy source. The struct body is defined
 * in mbedtls_compat_rng.h so that all compat layers can access fields
 * without cross-directory includes.
 */

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#include "osal.h"

#include "mbedtls_compat_rng.h"

int mbedtls_compat_rng_init(mbedtls_compat_rng_context **ctx, const unsigned char *pers,
                            size_t pers_len)
{
    int ret = 0;
    mbedtls_compat_rng_context *rng_ctx;

    if (ctx == NULL)
        return -1;

    rng_ctx = osal_calloc(1, sizeof(mbedtls_compat_rng_context));
    if (rng_ctx == NULL)
        return -1;

    mbedtls_ctr_drbg_init(&rng_ctx->ctr_drbg);
    mbedtls_entropy_init(&rng_ctx->entropy);

    ret = mbedtls_ctr_drbg_seed(&rng_ctx->ctr_drbg, mbedtls_entropy_func, &rng_ctx->entropy, pers,
                                pers_len);
    if (ret != 0) {
        mbedtls_ctr_drbg_free(&rng_ctx->ctr_drbg);
        mbedtls_entropy_free(&rng_ctx->entropy);
        osal_free(rng_ctx);
        return ret;
    }

    *ctx = rng_ctx;
    return 0;
}

void mbedtls_compat_rng_free(mbedtls_compat_rng_context *ctx)
{
    if (ctx == NULL)
        return;

    mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
    mbedtls_entropy_free(&ctx->entropy);
    osal_free(ctx);
}
