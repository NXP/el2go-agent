/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "el2go_csr.h"

int main(void)
{
    psa_key_id_t key_id = PSA_KEY_ID_NULL; 
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;

    platform_init();

    if(psa_crypto_init() != PSA_SUCCESS)
    {
        LOG(LOG_ERROR, "Initialization of crypto HW failed!\r\n");
        goto exit; 
    }

    LOG(LOG_INFO, "\r\nHello from EL2GO CSR example.\r\n");
    
    while (true);

    exit:
        // mbedtls_psa_crypto_free(); // <-- need this?
        psa_destroy_key(key_id);
        LOG(LOG_ERROR, "EL2GO CSR application failed!\r\n");
        while(true);
}
