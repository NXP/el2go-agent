/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/*
 * RNG compatibility implementation for mbedTLS 4.x.
 *
 * PSA crypto handles RNG internally, so the context is a stub. The struct
 * is defined here (not in the header) because v4 has no fields to expose.
 */

#include "mbedtls_compat_rng.h"

/*
 * RNG context for mbedTLS 4.x.
 * PSA crypto handles RNG internally. The struct exists only to satisfy
 * the C requirement that structs cannot be empty.
 */
struct mbedtls_compat_rng_context {
    int dummy; /* unused - PSA crypto handles RNG internally */
};

int mbedtls_compat_rng_init(mbedtls_compat_rng_context **ctx, const unsigned char *pers,
                            size_t pers_len)
{
    (void)pers;
    (void)pers_len;

    if (ctx == NULL)
        return -1;

    /* mbedTLS 4.x uses PSA crypto - no RNG context needed */
    *ctx = NULL;
    return 0;
}

void mbedtls_compat_rng_free(mbedtls_compat_rng_context *ctx)
{
    /* Nothing to free - context is NULL for v4 */
    (void)ctx;
}
