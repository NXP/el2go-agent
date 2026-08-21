/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <string.h>
#include <mbedtls/x509_csr.h>

#include "mbedtls_compat_csr.h"

void mbedtls_compat_x509write_csr_set_md_alg(mbedtls_x509write_csr *ctx, mbedtls_md_type_t md_alg)
{
    mbedtls_x509write_csr_set_md_alg(ctx, md_alg);
}

int mbedtls_compat_x509write_csr_pem(mbedtls_x509write_csr *ctx, unsigned char *buf, size_t size,
                                     mbedtls_compat_rng_context *rng_ctx)
{
    if (rng_ctx == NULL)
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;

    return mbedtls_x509write_csr_pem(ctx, buf, size, mbedtls_ctr_drbg_random, &rng_ctx->ctr_drbg);
}

int mbedtls_compat_x509write_csr_der(mbedtls_x509write_csr *ctx, unsigned char *buf, size_t size,
                                     size_t *der_len, mbedtls_compat_rng_context *rng_ctx)
{
    int ret = 0;

    if (rng_ctx == NULL || der_len == NULL)
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;

    ret = mbedtls_x509write_csr_der(ctx, buf, size, mbedtls_ctr_drbg_random, &rng_ctx->ctr_drbg);
    if (ret < 0)
        return ret;

    /* mbedtls_x509write_csr_der writes at the end of buf; move to front */
    *der_len = (size_t)ret;
    memmove(buf, buf + size - *der_len, *der_len);
    return 0;
}
