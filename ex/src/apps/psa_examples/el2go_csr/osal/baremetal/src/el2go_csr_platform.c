/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
*/

#include "el2go_csr_platform.h"
#include "el2go_csr_console.h"
#include "secure_storage.h"

void platform_init(void)
{
    BOARD_InitHardware();
    psa_status_t psa_status = secure_storage_its_initialize();
    if ( psa_status != PSA_SUCCESS)
    {
        LOG(LOG_ERROR, "secure_storage_its_initialize failed! \r\n");
    }
}