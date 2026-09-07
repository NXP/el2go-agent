/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
*/

#include "el2go_csr_platform.h"
#include "el2go_csr_console.h"
#include "el2go_csr_bsp.h"
#include "el2go_csr_memory.h"
#include "secure_storage.h"
#include "hse_host.h"

#ifndef PLATFORM_SYNC_HSEB_NVM_FLAG
  #define PLATFORM_SYNC_HSEB_NVM_FLAG 0 
#endif

static platform_status_t platform_sync_hseb_nvm(void)
{   
    /* Erase the littleFS flash region sector by sector. */
    csr_mem_status_t mem_status = mem_erase_sector((uint32_t)(LITTLEFS_START_ADDR+CONFIG_FLASH_BASE_ADDRESS), 
                                                   (uint32_t)LITTLEFS_BLOCK_COUNT);
    
    if (mem_status != kStatus_CSR_MEM_SUCCESS)
    {
        LOG(LOG_ERROR, "littleFS flash region erase FAILED! \r\n");
        return kStatus_PLATFORM_INIT_FAILED;
    }
    LOG(LOG_TRACE, "littleFS flash region erased successfully! \r\n");

    uint8_t muIf    = 0U;
    uint8_t muChannelIdx    = 1U;
    hseSrvDescriptor_t* pHseSrvDesc = &gHseSrvDesc[muIf][muChannelIdx];
    pHseSrvDesc->srvId  = HSE_SRV_ID_ERASE_HSE_NVM_DATA;
    hseSrvResponse_t response   = HSE_Send(muIf, muChannelIdx, gSyncTxOption, pHseSrvDesc);

    if (response == HSE_SRV_RSP_OK) 
    {
        LOG(LOG_TRACE, "HSEB NVM has been wiped successfully! \r\n");
        return kStatus_PLATFORM_INIT_SUCCESS;
    }
       
    LOG(LOG_ERROR, "HSEB NVM wipe command FAILED! \r\n");
    return kStatus_PLATFORM_INIT_FAILED;
        
}

platform_status_t platform_init(void)
{
    BOARD_InitHardware();

#if defined(PLATFORM_SYNC_HSEB_NVM_FLAG) && (PLATFORM_SYNC_HSEB_NVM_FLAG == 1)
    if (platform_sync_hseb_nvm() != kStatus_PLATFORM_INIT_SUCCESS)
    {
        return kStatus_PLATFORM_INIT_FAILED;
    }
#endif 

    psa_status_t psa_status = secure_storage_its_initialize();
    if ( psa_status != PSA_SUCCESS)
    {
        LOG(LOG_ERROR, "secure_storage_its_initialize failed! \r\n");
        return (uint32_t)psa_status;
    }

    LOG(LOG_TRACE, "Platform (FRDMMCXE31B) has been initialized successfully. \r\n");
    return kStatus_PLATFORM_INIT_SUCCESS;
}