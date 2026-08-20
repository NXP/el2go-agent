/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
*/

#include "el2go_csr_psa_key.h"
#include "mcux_psa_defines.h"

void fill_key_attributes(psa_key_attributes_t *attr, psa_key_id_t* key_id)
{
    psa_set_key_id(attr, *key_id);
    psa_set_key_lifetime(attr, PSA_KEY_LIFETIME_PERSISTENT); 
    psa_set_key_usage_flags(attr, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(attr, 256);
}
 