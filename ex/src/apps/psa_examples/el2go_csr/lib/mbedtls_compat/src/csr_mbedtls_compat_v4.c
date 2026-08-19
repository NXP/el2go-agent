/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "csr_mbedtls_compat.h"

int csr_compat_pk_bind_psa(mbedtls_pk_context *pk, psa_key_id_t key_id)
{
    /* mbedtls_pk_setup_opaque() was renamed to mbedtls_pk_wrap_psa() in 4.0. */
    return mbedtls_pk_wrap_psa(pk, key_id);
}

int csr_compat_x509write_csr_pem(mbedtls_x509write_csr *csr,
                                 unsigned char *buf, size_t size)
{
    /* RNG arguments were removed in 4.0; the library uses the global PSA RNG. */
    return mbedtls_x509write_csr_pem(csr, buf, size);
}

int csr_compat_cert_pubkey_to_psa(const mbedtls_x509_crt *cert,
                                  psa_algorithm_t sig_alg,
                                  psa_key_type_t key_type,
                                  psa_key_id_t *out_key_id)
{
    /* 4.0 removed the ECP struct accessors. Use the PK-to-PSA helpers instead.
     * key_type is not used here because mbedtls_pk_get_psa_attributes() derives
     * the type directly from the certificate's public key. */
    (void)key_type;

    mbedtls_x509_crt *c = (mbedtls_x509_crt *)cert;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;

    psa_status_t s = mbedtls_pk_get_psa_attributes(&c->pk,
                                                   PSA_KEY_USAGE_VERIFY_HASH,
                                                   &attr);
    if (s != PSA_SUCCESS)
    {
        psa_reset_key_attributes(&attr);
        return (int)s;
    }

    /* Enforce the caller's algorithm (get_psa_attributes may set a default). */
    psa_set_key_algorithm(&attr, sig_alg);

    s = mbedtls_pk_import_into_psa(&c->pk, &attr, out_key_id);
    psa_reset_key_attributes(&attr);
    return (int)s;
}
