/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/*
 * Shared mbedTLS 2.x / 3.x crypto compatibility implementation.
 *
 * Contains functions that are identical between v2 and v3:
 *   - SHA-256 context init/free (same API in both versions)
 *   - x509write_crt_set_serial (MPI-based, same in both versions)
 *   - x509write_crt_der (same signature in both versions)
 *
 * Version-specific SHA-256 streaming/one-shot functions and EC public key
 * extraction live in mbedtls_compat_crypto_v2.c and mbedtls_compat_crypto_v3.c.
 */

#include <mbedtls/bignum.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509_crt.h>

#include "mbedtls_compat_crypto.h"

/* ========================================================================== */
/* SHA-256 context (shared v2/v3 - identical API)                             */
/* ========================================================================== */

void mbedtls_compat_sha256_init(mbedtls_compat_sha256_context *ctx)
{
    mbedtls_sha256_init(&ctx->ctx);
}

void mbedtls_compat_sha256_free(mbedtls_compat_sha256_context *ctx)
{
    mbedtls_sha256_free(&ctx->ctx);
}

/* ========================================================================== */
/* X.509 certificate write (shared v2/v3 - MPI-based serial)                 */
/* ========================================================================== */

int mbedtls_compat_x509write_crt_set_serial(mbedtls_x509write_cert *ctx,
                                            const unsigned char *serial, size_t serial_len)
{
    int ret;
    mbedtls_mpi mpi_serial;

    mbedtls_mpi_init(&mpi_serial);
    ret = mbedtls_mpi_read_binary(&mpi_serial, serial, serial_len);
    if (ret == 0)
        ret = mbedtls_x509write_crt_set_serial(ctx, &mpi_serial);
    mbedtls_mpi_free(&mpi_serial);

    return ret;
}

int mbedtls_compat_x509write_crt_der(mbedtls_x509write_cert *ctx, unsigned char *buf, size_t size,
                                     mbedtls_compat_rng_context *rng_ctx)
{
    if (rng_ctx == NULL)
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;

    return mbedtls_x509write_crt_der(ctx, buf, size, mbedtls_ctr_drbg_random, &rng_ctx->ctr_drbg);
}

/* ========================================================================== */
/* PK functions (shared v2/v3)                                                 */
/* ========================================================================== */

int mbedtls_compat_pk_has_key(const mbedtls_pk_context *pk)
{
    return mbedtls_pk_get_type(pk) != MBEDTLS_PK_NONE;
}
