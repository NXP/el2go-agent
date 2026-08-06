/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
*/

#include "el2go_csr_platform.h"
#include "el2go_csr_console.h"
#include "el2go_csr_bsp.h"
#include "secure_storage.h"

platform_status_t platform_init(void)
{
    BOARD_InitHardware();
    psa_status_t psa_status = secure_storage_its_initialize();
    if ( psa_status != PSA_SUCCESS)
    {
        LOG(LOG_ERROR, "secure_storage_its_initialize failed! \r\n");
        return (uint32_t)psa_status;
    }

    LOG(LOG_TRACE, "Platform (FRDMMCXA266) has been initialized successfully. \r\n");
    return kStatus_PLATFORM_INIT_SUCCESS;
}