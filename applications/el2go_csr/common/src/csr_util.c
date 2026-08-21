/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <stdlib.h>
#include <string.h>

#include "csr_util.h"

psa_status_t generate_csr(psa_key_id_t key_id, uint8_t *csr_output_buf, size_t csr_output_buf_size,
                          size_t *csr_output_len)
{
    el2go_status_t status = EL2GO_STATUS_FAILURE;

    if (csr_output_buf == NULL || csr_output_len == NULL || csr_output_buf_size == 0U) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = net_crypto_generate_csr((uint32_t)key_id, CSR_SUBJECT_NAME, get_msg_digest_algo(),
                                     csr_output_buf, csr_output_buf_size, csr_output_len);

    if (status == EL2GO_STATUS_BUFFER_TOO_SMALL) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    } else if (status != EL2GO_STATUS_SUCCESS) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    return PSA_SUCCESS;
}

psa_status_t verify_certificate(psa_key_id_t key_id, const uint8_t *cert_buf, size_t cert_buf_size)
{
    size_t hash_len = 0U;
    size_t signature_len = 0U;
    size_t public_key_len = 0U;
    psa_key_id_t temp_key_id = 0U;
    uint8_t *challenge = NULL;
    uint8_t *public_key_raw = NULL;
    uint8_t *hash = NULL;
    uint8_t *signature = NULL;
    const challenge_response_config_t *config = NULL;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    el2go_status_t nc_status = EL2GO_STATUS_FAILURE;

    /* Get the challenge response configs from the PAL layer */
    config = get_challenge_response_config();

    if (cert_buf == NULL || cert_buf_size == 0U || config == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    challenge = (uint8_t *)malloc(config->challenge_size);
    if (challenge == NULL) {
        status = PSA_ERROR_INSUFFICIENT_MEMORY;
        goto exit;
    }

    public_key_raw = (uint8_t *)malloc(config->max_pub_key_size);
    if (public_key_raw == NULL) {
        status = PSA_ERROR_INSUFFICIENT_MEMORY;
        goto exit;
    }

    hash = (uint8_t *)malloc(config->max_hash_size);
    if (hash == NULL) {
        status = PSA_ERROR_INSUFFICIENT_MEMORY;
        goto exit;
    }

    signature = (uint8_t *)malloc(config->max_sig_raw_size);
    if (signature == NULL) {
        status = PSA_ERROR_INSUFFICIENT_MEMORY;
        goto exit;
    }

    status = psa_generate_random(challenge, config->challenge_size);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    status = psa_hash_compute(config->hash_alg, challenge, config->challenge_size, hash,
                              config->max_hash_size, &hash_len);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    status = psa_sign_hash(key_id, config->sig_alg, hash, hash_len, signature,
                           config->max_sig_raw_size, &signature_len);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    /* Extract the public key from the DER certificate via net_crypto */
    nc_status = net_crypto_cert_get_pubkey(cert_buf, cert_buf_size, public_key_raw,
                                           config->max_pub_key_size, &public_key_len);
    if (nc_status != EL2GO_STATUS_SUCCESS) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attributes, config->sig_alg);
    psa_set_key_type(&attributes, config->key_type);

    status = psa_import_key(&attributes, public_key_raw, public_key_len, &temp_key_id);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    status =
        psa_verify_hash(temp_key_id, config->sig_alg, hash, hash_len, signature, signature_len);

    psa_destroy_key(temp_key_id);

exit:
    if (challenge != NULL) {
        memset(challenge, 0, config->challenge_size);
        free(challenge);
    }
    if (public_key_raw != NULL) {
        memset(public_key_raw, 0, config->max_pub_key_size);
        free(public_key_raw);
    }
    if (hash != NULL) {
        memset(hash, 0, config->max_hash_size);
        free(hash);
    }
    if (signature != NULL) {
        memset(signature, 0, config->max_sig_raw_size);
        free(signature);
    }

    psa_reset_key_attributes(&attributes);

    return status;
}

psa_status_t generate_key(psa_key_attributes_t *attr, psa_key_id_t *key_id, bool regeneration_flag)
{
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    psa_key_id_t output_key_id = 0U;

    if (attr == NULL || key_id == NULL ||
        !((*key_id >= PSA_KEY_ID_USER_MIN && *key_id <= PSA_KEY_ID_USER_MAX) ||
          (*key_id >= PSA_KEY_ID_VENDOR_MIN && *key_id <= PSA_KEY_ID_VENDOR_MAX))) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    fill_key_attributes(attr, key_id);

    status = psa_generate_key(attr, &output_key_id);

    if (regeneration_flag) {
        if (status == PSA_ERROR_ALREADY_EXISTS) {
            LOG(LOG_TRACE,
                "Regeneration flag is active! Destroying key and generating a new one...\r\n");

            status = psa_destroy_key(*key_id);
            if (status != PSA_SUCCESS) {
                LOG(LOG_ERROR, "PSA key destruction failed!\r\n");
                goto exit;
            }

            status = psa_generate_key(attr, &output_key_id);
        }
    } else {
        if (status == PSA_ERROR_ALREADY_EXISTS) {
            LOG(LOG_TRACE, "PSA key already exists, using existing key.\r\n");
            goto exit;
        }
    }

    if (status != PSA_SUCCESS) {
        LOG(LOG_ERROR, "Error occured in PSA key generation!\r\n");
        goto exit;
    }

    LOG(LOG_TRACE, "PSA key generated successfully!\r\n");
exit:
    return status;
}
