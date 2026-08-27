/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __MBEDTLS_COMPAT_CRYPTO_H__
#define __MBEDTLS_COMPAT_CRYPTO_H__

#include <mbedtls/version.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>
#include <stdint.h>
#include <stddef.h>

#include "compat/mbedtls_compat_rng.h"

/**
 * @defgroup mbedtls_compat_crypto mbedTLS Crypto Compatibility
 * @brief Version-specific SHA-256 and EC public key extraction wrappers.
 * @{
 */

/* ========================================================================== */
/* SHA-256 context type (version-specific)                                    */
/* ========================================================================== */

#if MBEDTLS_VERSION_MAJOR == 4

#include <psa/crypto.h>

/**
 * @brief SHA-256 context for mbedTLS 4.x.
 * Wraps psa_hash_operation_t.
 */
typedef struct mbedtls_compat_sha256_context {
    psa_hash_operation_t ctx;
} mbedtls_compat_sha256_context;

#else /* mbedTLS 2.x and 3.x */

#include <mbedtls/sha256.h>

/**
 * @brief SHA-256 context for mbedTLS 2.x and 3.x.
 * Wraps mbedtls_sha256_context.
 */
typedef struct mbedtls_compat_sha256_context {
    mbedtls_sha256_context ctx;
} mbedtls_compat_sha256_context;

#endif /* MBEDTLS_VERSION_MAJOR */

/* ========================================================================== */
/* SHA-256 functions                                                           */
/* ========================================================================== */

/**
 * @brief Initialize a SHA-256 context.
 *
 * @param[in] ctx  SHA-256 context to initialize.
 */
void mbedtls_compat_sha256_init(mbedtls_compat_sha256_context *ctx);

/**
 * @brief Free a SHA-256 context.
 *
 * @param[in] ctx  SHA-256 context to free.
 */
void mbedtls_compat_sha256_free(mbedtls_compat_sha256_context *ctx);

/**
 * @brief Start a SHA-256 hash operation.
 *
 * @param[in] ctx  SHA-256 context.
 *
 * @return 0 on success, negative error code on failure.
 */
int mbedtls_compat_sha256_starts(mbedtls_compat_sha256_context *ctx);

/**
 * @brief Feed data into a SHA-256 hash operation.
 *
 * @param[in] ctx    SHA-256 context.
 * @param[in] input  Input data buffer.
 * @param[in] ilen   Length of input data.
 *
 * @return 0 on success, negative error code on failure.
 */
int mbedtls_compat_sha256_update(mbedtls_compat_sha256_context *ctx, const unsigned char *input,
                                 size_t ilen);

/**
 * @brief Finish a SHA-256 hash operation.
 *
 * @param[in]  ctx     SHA-256 context.
 * @param[out] output  Output buffer for the hash (32 bytes).
 *
 * @return 0 on success, negative error code on failure.
 */
int mbedtls_compat_sha256_finish(mbedtls_compat_sha256_context *ctx, unsigned char output[32]);

/**
 * @brief Calculate SHA-256 hash of a buffer in one shot.
 *
 * @param[in]  input   Input data buffer.
 * @param[in]  ilen    Length of input data.
 * @param[out] output  Output buffer for the hash (32 bytes).
 *
 * @return 0 on success, negative error code on failure.
 */
int mbedtls_compat_sha256(const unsigned char *input, size_t ilen, unsigned char output[32]);

/* ========================================================================== */
/* PK key setup                                                                */
/* ========================================================================== */

/**
 * @brief Setup PK context with a PSA opaque key.
 *
 * Not supported in mbedTLS 2.x (returns error).
 *
 * @param[in] pk      PK context to setup.
 * @param[in] key_id  PSA key ID (converted to mbedtls_svc_key_id_t internally).
 *
 * @return 0 on success, negative error code on failure.
 */
int mbedtls_compat_pk_setup_key(mbedtls_pk_context *pk, uint32_t key_id);

/**
 * @brief Check whether a PK context has a key configured.
 *
 * @param[in] pk  PK context to check.
 *
 * @return 1 if a key is present, 0 otherwise.
 */
int mbedtls_compat_pk_has_key(const mbedtls_pk_context *pk);

/* ========================================================================== */
/* EC public key extraction                                                    */
/* ========================================================================== */

/**
 * @brief Extract the raw uncompressed EC public key bytes from a PK context.
 *
 * Returns the key in uncompressed point format: 0x04 || X || Y.
 *
 * @param[in]  pk        PK context containing an EC public key.
 * @param[out] buf       Output buffer.
 * @param[in]  buf_size  Size of output buffer.
 * @param[out] out_len   Number of bytes written.
 *
 * @return 0 on success, negative error code on failure.
 */
int mbedtls_compat_pk_get_ec_pubkey_raw(const mbedtls_pk_context *pk, uint8_t *buf, size_t buf_size,
                                        size_t *out_len);

/* ========================================================================== */
/* X.509 certificate write                                                     */
/* ========================================================================== */

/**
 * @brief Set certificate serial number from raw bytes.
 *
 * - v2/v3: converts to MPI then calls mbedtls_x509write_crt_set_serial.
 * - v4:    calls mbedtls_x509write_crt_set_serial_raw directly.
 *
 * @param[in] ctx        Certificate write context.
 * @param[in] serial     Serial number as byte array.
 * @param[in] serial_len Length of serial number.
 *
 * @return 0 on success, negative error code on failure.
 */
int mbedtls_compat_x509write_crt_set_serial(mbedtls_x509write_cert *ctx,
                                            const unsigned char *serial, size_t serial_len);

/**
 * @brief Write certificate in DER format.
 *
 * - v2/v3: requires rng_ctx for signing.
 * - v4:    rng_ctx is ignored (PSA handles RNG internally).
 *
 * @param[in] ctx      Certificate write context.
 * @param[in] buf      Output buffer.
 * @param[in] size     Buffer size.
 * @param[in] rng_ctx  RNG context (may be NULL for v4).
 *
 * @return Number of bytes written on success, negative error code on failure.
 */
int mbedtls_compat_x509write_crt_der(mbedtls_x509write_cert *ctx, unsigned char *buf, size_t size,
                                     mbedtls_compat_rng_context *rng_ctx);

/* ========================================================================== */
/* X.509 certificate parse                                                     */
/* ========================================================================== */

/**
 * @brief Extract the Common Name (CN) from a DER-encoded certificate.
 *
 * Parses the subject DN of the certificate and copies the CN value into
 * cn_out as a null-terminated string.
 *
 * @param[in]  cert_der      DER-encoded certificate buffer.
 * @param[in]  cert_der_len  Length of the DER buffer.
 * @param[out] cn_out        Output buffer for the CN string (null-terminated).
 * @param[in]  cn_out_len    Size of the output buffer.
 *
 * @return 0 on success, negative error code on failure.
 */
int mbedtls_compat_get_cert_cn(const uint8_t *cert_der, size_t cert_der_len, char *cn_out,
                               size_t cn_out_len);

/** @} */

#endif /* __MBEDTLS_COMPAT_CRYPTO_H__ */