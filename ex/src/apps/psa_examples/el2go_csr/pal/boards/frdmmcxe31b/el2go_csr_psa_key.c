/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
*/

#include "el2go_csr_psa_key.h"
#include "el2go_csr_console.h"

psa_status_t generate_key(psa_key_attributes_t *attr, psa_key_id_t* key_id, bool regeneration_flag)
{
    psa_status_t status = PSA_SUCCESS;

    if (!attr || !key_id || 
        !((*key_id >= PSA_KEY_ID_USER_MIN && *key_id <= PSA_KEY_ID_USER_MAX) || 
          (*key_id >= PSA_KEY_ID_VENDOR_MIN && *key_id <= PSA_KEY_ID_VENDOR_MAX)))
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }   

    psa_set_key_id(attr, *key_id);
    psa_set_key_lifetime(attr, PSA_KEY_LIFETIME_VOLATILE); 
    psa_set_key_usage_flags(attr, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(attr, 256);

    status = psa_generate_key(attr, key_id);
    
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
            
            status = psa_generate_key(attr, key_id);
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
