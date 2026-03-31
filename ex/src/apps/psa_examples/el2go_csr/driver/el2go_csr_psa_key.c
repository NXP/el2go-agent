/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
*/

#include "el2go_csr_psa_key.h"

psa_status_t fill_key_attributes(psa_key_attributes_t *attr, psa_key_id_t* key_id)
{
    psa_status_t status = PSA_SUCCESS;

    if (!attr || !key_id)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }   
    
    psa_reset_key_attributes(attr); 

    // OEM defines PSA key ID
    if (*key_id >= PSA_KEY_ID_USER_MIN && *key_id <= PSA_KEY_ID_USER_MAX || 
        *key_id >= PSA_KEY_ID_VENDOR_MIN && *key_id <= PSA_KEY_ID_VENDOR_MAX)
    {
        psa_set_key_id(attr, *key_id);
        // Note: use PSA_KEY_LIFETIME_PERSISTENT  if you want to use a specific 
        //       key identifier. Will be ignored for PSA_KEY_PERSISTENCE_VOLATILE 
        //       lifetime.
    }


    psa_set_key_lifetime(attr, PSA_KEY_PERSISTENCE_VOLATILE);
    psa_set_key_usage_flags(attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(attr, 256);

    status = psa_generate_key(attr, key_id);

    return status;
}
