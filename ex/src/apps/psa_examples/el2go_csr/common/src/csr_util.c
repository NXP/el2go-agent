/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "csr_util.h"
#include "csr_mbedtls_compat.h"

psa_status_t generate_csr(psa_key_id_t key_id, uint8_t *csr_output_buf, size_t csr_output_buf_size, size_t *csr_output_len)
{
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    mbedtls_md_type_t md_type = MBEDTLS_MD_NONE;
    mbedtls_x509write_csr csr = {0};
    mbedtls_pk_context pk = {0}; 

    if (!csr_output_buf || !csr_output_len || !csr_output_buf_size)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    mbedtls_pk_init(&pk);
    if (csr_compat_pk_bind_psa(&pk, key_id))
    {
            status = PSA_ERROR_GENERIC_ERROR;
            goto exit;
    }

    mbedtls_x509write_csr_init(&csr);
    mbedtls_x509write_csr_set_key(&csr, &pk);

    md_type = get_msg_digest_algo();
    mbedtls_x509write_csr_set_md_alg(&csr, md_type);

    if (mbedtls_x509write_csr_set_subject_name(&csr, CSR_SUBJECT_NAME))
    {
        status = PSA_ERROR_GENERIC_ERROR;
        goto exit;
    }

    if (csr_compat_x509write_csr_pem(&csr, csr_output_buf, csr_output_buf_size))
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
    status = PSA_SUCCESS;
exit:
    mbedtls_x509write_csr_free(&csr);
    mbedtls_pk_free(&pk);
    
    return status;
}

psa_status_t verify_certificate(psa_key_id_t key_id, const uint8_t *cert_buf, size_t cert_buf_size)
{
    mbedtls_x509_crt cert = {0U};
    size_t hash_len = 0U;
    size_t signature_len = 0U;
    psa_key_id_t temp_key_id = 0U;
    uint8_t* challenge = NULL;
    uint8_t* hash = NULL;
    uint8_t* signature = NULL;
    const challenge_response_config_t *config = NULL;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    
    // Get the challenge response configs from the PAL layer
    config = get_challenge_response_config(); 

    if (!cert_buf || !cert_buf_size || !config)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    mbedtls_x509_crt_init(&cert);
    
    challenge = (uint8_t *)malloc(config->challenge_size);
    if (challenge == NULL)
    {
        status = PSA_ERROR_INSUFFICIENT_MEMORY;
        goto exit;
    }

    hash = (uint8_t *)malloc(config->max_hash_size);
    if (hash == NULL)
    {
        status = PSA_ERROR_INSUFFICIENT_MEMORY;
        goto exit;
    }
    
    signature = (uint8_t *)malloc(config->max_sig_raw_size);
    if (signature == NULL)
    {
        status = PSA_ERROR_INSUFFICIENT_MEMORY;
        goto exit;
    }
    
    status = psa_generate_random(challenge, config->challenge_size);
    if (status != PSA_SUCCESS)
    {
        goto exit;
    }
    
    status = psa_hash_compute(config->hash_alg, challenge, config->challenge_size, hash,
                            config->max_hash_size, &hash_len);
    if (status != PSA_SUCCESS)
    {
        goto exit;
    }

    status = psa_sign_hash(key_id, config->sig_alg, hash, hash_len, signature,
                        config->max_sig_raw_size, &signature_len);
    if (status != PSA_SUCCESS)
    {
        goto exit;
    }

    if (mbedtls_x509_crt_parse(&cert, cert_buf, cert_buf_size))
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    status = csr_compat_cert_pubkey_to_psa(&cert, config->sig_alg, config->key_type, &temp_key_id);
    if (status != PSA_SUCCESS)
    {
        goto exit;
    }

    status = psa_verify_hash(temp_key_id, config->sig_alg, hash, hash_len, signature, signature_len);

    psa_destroy_key(temp_key_id);

exit:
    if (challenge)
    {
        memset(challenge, 0, config->challenge_size);
        free(challenge);
    }
    if (hash)
    {
        memset(hash, 0, config->max_hash_size);
        free(hash);
    }
    if (signature)
    {
        memset(signature, 0, config->max_sig_raw_size);
        free(signature);
    }

    mbedtls_x509_crt_free(&cert);

    return status;
}

psa_status_t generate_key(psa_key_attributes_t *attr, psa_key_id_t* key_id, bool regeneration_flag)
{
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    psa_key_id_t output_key_id = 0U;

    if (!attr || !key_id || 
        !((*key_id >= PSA_KEY_ID_USER_MIN && *key_id <= PSA_KEY_ID_USER_MAX) || 
          (*key_id >= PSA_KEY_ID_VENDOR_MIN && *key_id <= PSA_KEY_ID_VENDOR_MAX)))
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }   

    fill_key_attributes(attr, key_id); 
    
    status = psa_generate_key(attr, &output_key_id);
    
    if (regeneration_flag)
    {
        if (status == PSA_ERROR_ALREADY_EXISTS)
        {
            LOG(LOG_TRACE, "Regeneration flag is active! Destroying key and generating a new one...\r\n");

            status = psa_destroy_key(*key_id);
            if (status != PSA_SUCCESS)
            {
                LOG(LOG_ERROR, "PSA key destruction failed!\r\n");
                goto exit;
            }
            
            status = psa_generate_key(attr, &output_key_id);
        }
    }
    else 
    {
        if (status == PSA_ERROR_ALREADY_EXISTS)
        {
            LOG(LOG_TRACE, "PSA key already exists, using existing key.\r\n");
            goto exit;
        }
    }
    
    if (status != PSA_SUCCESS)
    {
        LOG(LOG_ERROR, "Error occured in PSA key generation!\r\n");
        goto exit;
    }
    
    LOG(LOG_TRACE, "PSA key generated successfully!\r\n");
exit:
    return status;
}
