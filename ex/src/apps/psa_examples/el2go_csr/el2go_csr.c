/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "el2go_csr.h"

int main(void)
{
    psa_key_id_t key_id; 
    psa_key_attributes_t key_attr;

#ifndef __ZEPHYR__
    BOARD_InitHardware();
#endif

    if(psa_crypto_init() != PSA_SUCCESS)
    {
        printc(LOG_ERROR, "Initialization of crypto HW failed!\r\n");
        goto exit; 
    }

    printc(LOG_INFO, "\r\nHello from EL2GO CSR example.\r\n");
    
    while (true);

    exit:
        // mbedtls_psa_crypto_free(); // <-- need this?
        psa_destroy_key(key_id);
        printc(LOG_ERROR, "EL2GO CSR application failed!\r\n");
        while(true);
}
