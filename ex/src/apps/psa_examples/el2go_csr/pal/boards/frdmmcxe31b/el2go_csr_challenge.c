/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "el2go_csr_challenge.h"

/* Default challenge-response configuration */
static const challenge_response_config_t g_challenge_response_config = {
    .challenge_size = 32U,                          
    .hash_alg = PSA_ALG_SHA_256,                     
    .sig_alg = PSA_ALG_ECDSA(PSA_ALG_SHA_256),  
    .key_type = PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1),        
    .max_hash_size = PSA_HASH_MAX_SIZE,                
    .max_sig_raw_size = PSA_SIGNATURE_MAX_SIZE,        
    .max_pub_key_size = 65U,                          
};

const challenge_response_config_t* get_challenge_response_config(void)
{
    return &g_challenge_response_config;
}
