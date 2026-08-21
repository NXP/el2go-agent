/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <mbedtls/x509_csr.h>
#include <mbedtls/md.h>

#include "mbedtls_compat.h"

/**
 * @addtogroup mbedtls_compat_v4
 * @{
 */

/* ========================================================================== */
/* CSR Functions (v4-specific)                                                */
/* ========================================================================== */

void mbedtls_compat_x509write_csr_set_md_alg(mbedtls_x509write_csr *ctx, mbedtls_md_type_t md_alg)
{
    /* mbedTLS v4 normalizes opaque ECDSA keys to PSA_ALG_ECDSA_ANY internally,
     * stripping the hash. The hash must be set explicitly on the CSR writer. */
    mbedtls_x509write_csr_set_md_alg(ctx, md_alg);
}

int mbedtls_compat_x509write_csr_pem(mbedtls_x509write_csr *ctx, unsigned char *buf, size_t size,
                                     mbedtls_compat_rng_context *rng_ctx)
{
    (void)rng_ctx;
    /* mbedTLS 4.x uses PSA crypto internally - no RNG parameter needed */
    return mbedtls_x509write_csr_pem(ctx, buf, size);
}

/** @} */ /* end of mbedtls_compat_v4 */
