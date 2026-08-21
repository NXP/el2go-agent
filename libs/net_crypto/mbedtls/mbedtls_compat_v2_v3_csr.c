/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <mbedtls/version.h>

/* Only compile common code for versions that share implementation (2.x and 3.x) */
#if MBEDTLS_VERSION_MAJOR < 4

#include <mbedtls/x509_csr.h>

#include "mbedtls_compat.h"
#include "mbedtls_compat_v2_v3_internal.h"

/**
 * @addtogroup mbedtls_compat_v2_v3
 * @{
 */

/* ========================================================================== */
/* CSR Functions (shared between v2 and v3)                                   */
/* ========================================================================== */

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

/** @} */ /* end of mbedtls_compat_v2_v3 */

#endif /* MBEDTLS_VERSION_MAJOR < 4 */
