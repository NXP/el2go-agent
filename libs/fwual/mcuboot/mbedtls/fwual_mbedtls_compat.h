/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __FWUAL_MBEDTLS_COMPAT_H__
#define __FWUAL_MBEDTLS_COMPAT_H__

/*
 * Minimal mbedTLS version compatibility layer for fwual/mcuboot.
 *
 * Provides version-agnostic wrappers for:
 *   - SHA-256 streaming hash
 *   - Constant-time memory compare
 *
 * mbedTLS 2.x / 3.x: uses mbedtls_sha256_* and mbedtls_ct_memcmp directly.
 * mbedTLS 4.x:        uses PSA crypto API (psa_hash_*) and a manual CT loop.
 */

#include <mbedtls/version.h>
#include <stddef.h>
#include <stdint.h>

#if !defined(MBEDTLS_VERSION_MAJOR)
#error "MBEDTLS_VERSION_MAJOR is not defined - check mbedTLS version.h"
#endif

#if MBEDTLS_VERSION_MAJOR < 4

#include <mbedtls/sha256.h>

typedef struct fwual_sha256_context {
    mbedtls_sha256_context ctx;
} fwual_sha256_context;

#else /* MBEDTLS_VERSION_MAJOR >= 4 */

#include <psa/crypto.h>

typedef struct fwual_sha256_context {
    psa_hash_operation_t ctx;
} fwual_sha256_context;

#endif /* MBEDTLS_VERSION_MAJOR */

/**
 * @brief Initialize a SHA-256 context.
 *
 * @param[in] ctx  SHA-256 context to initialize.
 */
void fwual_sha256_init(fwual_sha256_context *ctx);

/**
 * @brief Free a SHA-256 context.
 *
 * @param[in] ctx  SHA-256 context to free.
 */
void fwual_sha256_free(fwual_sha256_context *ctx);

/**
 * @brief Start a SHA-256 hash operation.
 *
 * @param[in] ctx  SHA-256 context.
 *
 * @return 0 on success, negative error code on failure.
 */
int fwual_sha256_starts(fwual_sha256_context *ctx);

/**
 * @brief Feed data into a SHA-256 hash operation.
 *
 * @param[in] ctx    SHA-256 context.
 * @param[in] input  Input data buffer.
 * @param[in] ilen   Length of input data in bytes.
 *
 * @return 0 on success, negative error code on failure.
 */
int fwual_sha256_update(fwual_sha256_context *ctx, const unsigned char *input, size_t ilen);

/**
 * @brief Finish a SHA-256 hash operation.
 *
 * @param[in]  ctx     SHA-256 context.
 * @param[out] output  Output buffer for the hash (32 bytes).
 *
 * @return 0 on success, negative error code on failure.
 */
int fwual_sha256_finish(fwual_sha256_context *ctx, unsigned char output[32]);

/**
 * @brief Constant-time memory comparison.
 *
 * Compares two buffers in constant time to prevent timing side-channels.
 *
 * @param[in] a    First buffer.
 * @param[in] b    Second buffer.
 * @param[in] len  Number of bytes to compare.
 *
 * @return 0 if buffers are equal, non-zero otherwise.
 */
int fwual_ct_memcmp(const void *a, const void *b, size_t len);

#endif /* __FWUAL_MBEDTLS_COMPAT_H__ */
