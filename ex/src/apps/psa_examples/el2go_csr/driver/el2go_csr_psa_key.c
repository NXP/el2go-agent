/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
*/

#include "el2go_csr_psa_key.h"

psa_status_t fill_key_attributes(psa_key_attributes_t *attr, psa_key_id_t key_identifier)
{
    if (!attr || key_identifier == PSA_KEY_ID_NULL || 
        key_identifier < PSA_KEY_ID_VENDOR_MIN || key_identifier > PSA_KEY_ID_VENDOR_MAX)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_reset_key_attributes(attr); 
    
    psa_set_key_id(attr, key_identifier);
    psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_PERSISTENT);
    psa_set_key_usage_flags(attr, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(attr, 256);

    return PSA_SUCCESS;
}
