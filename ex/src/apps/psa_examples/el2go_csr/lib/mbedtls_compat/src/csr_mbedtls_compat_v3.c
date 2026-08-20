/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "csr_mbedtls_compat.h"
#include "mbedtls/ecp.h"

/* 3.x CSR writer requires an (f_rng, p_rng) callback. Keys are PSA-opaque and
 * psa_crypto_init() is already called in main(), so back the callback with the
 * PSA RNG to match 4.0 behavior (which uses the PSA RNG internally). */
static int csr_psa_rng(void *ctx, unsigned char *out, size_t len)
{
    (void)ctx;
    return (psa_generate_random(out, len) == PSA_SUCCESS) ? 0 : -1;
}

int csr_compat_pk_bind_psa(mbedtls_pk_context *pk, psa_key_id_t key_id)
{
    return mbedtls_pk_setup_opaque(pk, key_id);
}

int csr_compat_x509write_csr_pem(mbedtls_x509write_csr *csr,
                                 unsigned char *buf, size_t size)
{
    return mbedtls_x509write_csr_pem(csr, buf, size, csr_psa_rng, NULL);
}

int csr_compat_x509write_csr_der(mbedtls_x509write_csr *csr,
                                  unsigned char *buf, size_t size,
                                  size_t *der_len)
{
    int ret = mbedtls_x509write_csr_der(csr, buf, size, csr_psa_rng, NULL);
    if (ret < 0)
    {
        return ret;
    }
    /* DER is written at the END of buf; move it to the start. */
    *der_len = (size_t)ret;
    memmove(buf, buf + size - *der_len, *der_len);
    return 0;
}

int csr_compat_cert_pubkey_to_psa(const mbedtls_x509_crt *cert,
                                  psa_algorithm_t sig_alg,
                                  psa_key_type_t key_type,
                                  psa_key_id_t *out_key_id)
{
    mbedtls_ecp_keypair *ecp = mbedtls_pk_ec(cert->pk);
    if (ecp == NULL)
    {
        return MBEDTLS_ERR_PK_TYPE_MISMATCH;
    }

    uint8_t pub[MBEDTLS_ECP_MAX_PT_LEN];
    size_t pub_len = 0;
    int ret = mbedtls_ecp_point_write_binary(&ecp->private_grp, &ecp->private_Q,
                                             MBEDTLS_ECP_PF_UNCOMPRESSED,
                                             &pub_len, pub, sizeof(pub));
    if (ret != 0)
    {
        return ret;
    }

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attr, sig_alg);
    psa_set_key_type(&attr, key_type);

    psa_status_t s = psa_import_key(&attr, pub, pub_len, out_key_id);
    psa_reset_key_attributes(&attr);
    return (int)s;
}
