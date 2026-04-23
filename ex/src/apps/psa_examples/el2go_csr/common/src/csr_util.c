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
    psa_status_t status = PSA_SUCCESS;
    uint8_t hash[MAX_HASH_SIZE]= {0};
    size_t hash_len = 0U;
    uint8_t signature[MAX_SIG_RAW_SIZE]= {0};
    size_t signature_len = 0U;
    uint8_t challenge[CHALLENGE_SIZE]= {0};
    uint8_t public_key_raw[65] = {0};  // 0x04 + 32 bytes X + 32 bytes Y for P256
    size_t public_key_len = 0U;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t temp_key_id = 0;
    mbedtls_ecp_keypair *ecp;
    
    if (!cert_buf || !cert_buf_size)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    mbedtls_x509_crt_init(&cert);
    
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

    // Extract raw public key from certificate (uncompressed format: 0x04 || X || Y)
    ecp = mbedtls_pk_ec(cert.pk);
    if (ecp == NULL)
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }
    
    if (mbedtls_ecp_point_write_binary(&ecp->private_grp, &ecp->private_Q,
                                        MBEDTLS_ECP_PF_UNCOMPRESSED,
                                        &public_key_len, public_key_raw,
                                        sizeof(public_key_raw)) != 0)
    {
        status = PSA_ERROR_GENERIC_ERROR;
        goto exit;
    }
    
    // Import public key into PSA (raw format is directly supported)
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attributes, PSA_SIG_ALG);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    
    status = psa_import_key(&attributes, public_key_raw, public_key_len, &temp_key_id);
    if (status != PSA_SUCCESS)
    {
        goto exit;
    }

    // Verify signature using PSA (both signature and key are in PSA format now)
    status = psa_verify_hash(temp_key_id, PSA_SIG_ALG, hash, hash_len, signature, signature_len);
    
    psa_destroy_key(temp_key_id);

exit:
    psa_reset_key_attributes(&attributes);
    mbedtls_x509_crt_free(&cert);

    return status;
}