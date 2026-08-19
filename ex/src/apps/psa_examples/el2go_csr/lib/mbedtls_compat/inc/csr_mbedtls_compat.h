/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef CSR_MBEDTLS_COMPAT_H
#define CSR_MBEDTLS_COMPAT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "psa/crypto.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/x509_crt.h"

/*! @brief Bind a PK context to an existing PSA opaque key.
 *
 * Wraps mbedtls_pk_setup_opaque() (Mbed TLS 3.x) or mbedtls_pk_wrap_psa()
 * (Mbed TLS 4.x), which was renamed in 4.0.
 *
 * @param[in,out]  pk      Pointer to an initialised PK context to be bound.
 * @param[in]      key_id  PSA key identifier of the opaque key to bind.
 *
 * @retval 0 on success, non-zero Mbed TLS or PSA error code otherwise.
 */
int csr_compat_pk_bind_psa(mbedtls_pk_context *pk, psa_key_id_t key_id);

/*! @brief Write a CSR as a NUL-terminated PEM string.
 *
 * Wraps mbedtls_x509write_csr_pem(). On Mbed TLS 3.x an RNG callback is
 * required and is backed internally by psa_generate_random(). On Mbed TLS 4.x
 * the RNG arguments were removed from the API; the library uses the global
 * PSA RNG directly.
 *
 * @param[in]  csr   Pointer to the populated CSR write context.
 * @param[out] buf   Buffer that receives the NUL-terminated PEM output.
 * @param[in]  size  Size of buf in bytes.
 *
 * @retval 0 on success, non-zero Mbed TLS error code otherwise.
 */
int csr_compat_x509write_csr_pem(mbedtls_x509write_csr *csr,
                                 unsigned char *buf, size_t size);

/*! @brief Import the public key of a parsed X.509 certificate into the PSA key store.
 *
 * Provides a version-agnostic way to obtain a volatile PSA key suitable for
 * PSA_KEY_USAGE_VERIFY_HASH from a certificate's embedded public key.
 *
 * On Mbed TLS 3.x the raw EC point bytes are extracted via mbedtls_pk_ec() and
 * mbedtls_ecp_point_write_binary(), then imported with psa_import_key().
 * On Mbed TLS 4.x the ECP struct accessors are removed; the implementation
 * uses mbedtls_pk_get_psa_attributes() and mbedtls_pk_import_into_psa()
 * instead, which is also curve-agnostic.
 *
 * @param[in]  cert        Pointer to the parsed certificate whose public key
 *                         is to be imported.
 * @param[in]  sig_alg     PSA algorithm that will be used with the key
 *                         (e.g. PSA_ALG_ECDSA(PSA_ALG_SHA_256)). The key is
 *                         created with usage PSA_KEY_USAGE_VERIFY_HASH and
 *                         this algorithm.
 * @param[in]  key_type    PSA key type of the public key
 *                         (e.g. PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1)).
 *                         Obtained from the board PAL configuration. Only used
 *                         on Mbed TLS 3.x; on 4.x the type is derived from the
 *                         certificate by mbedtls_pk_get_psa_attributes().
 * @param[out] out_key_id  On success, receives the identifier of the newly
 *                         created volatile PSA key. The caller is responsible
 *                         for destroying it with psa_destroy_key() when it is
 *                         no longer needed.
 *
 * @retval PSA_SUCCESS on success, non-zero PSA or Mbed TLS error code otherwise.
 */
int csr_compat_cert_pubkey_to_psa(const mbedtls_x509_crt *cert,
                                  psa_algorithm_t sig_alg,
                                  psa_key_type_t key_type,
                                  psa_key_id_t *out_key_id);

#ifdef __cplusplus
}
#endif

#endif /* CSR_MBEDTLS_COMPAT_H */
