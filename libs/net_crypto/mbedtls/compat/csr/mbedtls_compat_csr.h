/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __MBEDTLS_COMPAT_CSR_H__
#define __MBEDTLS_COMPAT_CSR_H__

#include <mbedtls/x509_csr.h>
#include <mbedtls/md.h>
#include <stddef.h>

#include "compat/mbedtls_compat_rng.h"

/**
 * @defgroup mbedtls_compat_csr mbedTLS CSR/Certificate Write Compatibility
 * @brief Version-specific wrappers for X.509 CSR and certificate write operations.
 * @{
 */

/**
 * @brief Set the hash algorithm for a CSR signature.
 *
 * In mbedTLS 4.x the hash algorithm is derived from the PSA key attributes,
 * so this call forwards to mbedtls_x509write_csr_set_md_alg. In v2/v3 it
 * does the same; the function exists for a uniform call site.
 *
 * @param[in] ctx     CSR write context.
 * @param[in] md_alg  Hash algorithm.
 */
void mbedtls_compat_x509write_csr_set_md_alg(mbedtls_x509write_csr *ctx, mbedtls_md_type_t md_alg);

/**
 * @brief Write a CSR in PEM format.
 *
 * - v2/v3: requires rng_ctx for ECDSA signing.
 * - v4:    rng_ctx is ignored (PSA handles RNG internally).
 *
 * @param[in] ctx      CSR write context.
 * @param[in] buf      Output buffer.
 * @param[in] size     Buffer size.
 * @param[in] rng_ctx  RNG context (may be NULL for v4).
 *
 * @return 0 on success, negative error code on failure.
 */
int mbedtls_compat_x509write_csr_pem(mbedtls_x509write_csr *ctx, unsigned char *buf, size_t size,
                                     mbedtls_compat_rng_context *rng_ctx);

/**
 * @brief Write a CSR in DER format.
 *
 * On success the DER bytes are moved to the start of buf and *der_len is set.
 *
 * - v2/v3: requires rng_ctx for ECDSA signing.
 * - v4:    rng_ctx is ignored (PSA handles RNG internally).
 *
 * @param[in]  ctx      CSR write context.
 * @param[in]  buf      Output buffer.
 * @param[in]  size     Buffer size.
 * @param[out] der_len  Number of DER bytes written on success.
 * @param[in]  rng_ctx  RNG context (may be NULL for v4).
 *
 * @return 0 on success, negative error code on failure.
 */
int mbedtls_compat_x509write_csr_der(mbedtls_x509write_csr *ctx, unsigned char *buf, size_t size,
                                     size_t *der_len, mbedtls_compat_rng_context *rng_ctx);

/** @} */

#endif /* __MBEDTLS_COMPAT_CSR_H__ */
