/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "csr_util.h"

psa_status_t generate_csr(psa_key_id_t key_id, uint8_t *csr_output_buf, size_t csr_output_buf_size, size_t *csr_output_len)
{
    psa_status_t status = PSA_SUCCESS;
    mbedtls_x509write_csr csr = {0};
    mbedtls_pk_context pk = {0};

    if (!csr_output_buf || !csr_output_len || !csr_output_buf_size)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    mbedtls_pk_init(&pk);
    if (mbedtls_pk_setup_opaque(&pk, key_id))
    {
            status = PSA_ERROR_GENERIC_ERROR;
            goto exit;
    }
    
    mbedtls_x509write_csr_init(&csr);
    mbedtls_x509write_csr_set_key(&csr, &pk);
    mbedtls_x509write_csr_set_md_alg(&csr, MBEDTLS_MD_SHA256);

    if (mbedtls_x509write_csr_set_subject_name(&csr, CSR_SUBJECT_NAME))
    {
        status = PSA_ERROR_GENERIC_ERROR;
        goto exit;
    }

    if (mbedtls_x509write_csr_pem(&csr, csr_output_buf, csr_output_buf_size, NULL, NULL))
    {
        status = PSA_ERROR_GENERIC_ERROR;
        goto exit;
    }

    // PEM is null-terminated
    *csr_output_len = 0U;
    while (csr_output_buf[*csr_output_len] != '\0')
    {
        (*csr_output_len)++;
    }

exit:
    mbedtls_x509write_csr_free(&csr);
    mbedtls_pk_free(&pk);

    return status;
}

psa_status_t verify_certificate(psa_key_id_t key_id, const uint8_t *cert_buf, size_t cert_buf_size)
{
    mbedtls_x509_crt cert = {0};
    mbedtls_pk_context pk_from_cert = {0};
    psa_status_t status = PSA_SUCCESS;
    uint8_t hash[MAX_HASH_SIZE]= {0};
    size_t hash_len = 0U;
    uint8_t signature[MAX_SIG_RAW_SIZE]= {0};
    size_t signature_len = 0U;
    uint8_t challenge[CHALLENGE_SIZE]= {0};
    
    if (!cert_buf || !cert_buf_size)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    mbedtls_x509_crt_init(&cert);
    mbedtls_pk_init(&pk_from_cert);
    
    status = psa_generate_random(challenge, sizeof(challenge));
    if (status != PSA_SUCCESS)
    {
        goto exit;
    }
    
    status = psa_hash_compute(PSA_HASH_ALG, challenge, sizeof(challenge), hash,
                            sizeof(hash), &hash_len);
    if (status != PSA_SUCCESS)
    {
        goto exit;
    }

    status = psa_sign_hash(key_id, PSA_SIG_ALG, hash, hash_len, signature,
                        sizeof(signature), &signature_len);
    if (status != PSA_SUCCESS)
    {
        goto exit;
    }
       
    if (mbedtls_x509_crt_parse(&cert, cert_buf, cert_buf_size))
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    if (mbedtls_pk_verify(&cert.pk, MBEDTLS_HASH_ALG, hash, hash_len, signature, signature_len))
    {
        status = PSA_ERROR_INVALID_SIGNATURE;
        goto exit;
    }

exit:
    mbedtls_x509_crt_free(&cert);
    mbedtls_pk_free(&pk_from_cert);

    return status;
}