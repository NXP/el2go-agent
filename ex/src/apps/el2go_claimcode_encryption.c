/*
 * Copyright 2023-2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <iot_agent_claimcode_encrypt.h>

#include <fsl_device_registers.h>
#include <fsl_romapi_iap.h>
#include <fsl_cache.h>
#include "flash_config.h"

#include <nxp_iot_agent_status.h>
#include <nxp_iot_agent_config.h>
#include <iot_agent_demo_config.h>

#ifdef __ZEPHYR__
#include <stdio.h>
#define LOG printf
#else
#include "fsl_debug_console.h"
#include <board.h>
#include <app.h>
#define LOG PRINTF
#endif

/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define SYSTEM_IS_XIP_FLEXSPI()                                                                               \
    ((((uint32_t)SystemCoreClockUpdate >= 0x08000000U) && ((uint32_t)SystemCoreClockUpdate < 0x10000000U)) || \
     (((uint32_t)SystemCoreClockUpdate >= 0x18000000U) && ((uint32_t)SystemCoreClockUpdate < 0x20000000U)))

#define FLASH_ADDRESS           (0x08000000U)
#define FCB_ADDRESS             (FLASH_ADDRESS + 0x00000400U)
#define CLAIM_CODE_INFO_ADDRESS (FLASH_ADDRESS + 0x004a0000U)
#define FLEXSPI_INSTANCE        (0U)
#define FLASH_OPTION_QSPI_SDR   (0xc0000004U)

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Code
 ******************************************************************************/

static const char *plain_claimcode = IOT_AGENT_CLAIMCODE_STRING;

__attribute__ ((aligned(4))) static const uint8_t iot_agent_claimcode_ecdh_pub_key[64] = {
    NXP_IOT_AGENT_CLAIMCODE_KEY_AGREEMENT_PUBLIC_KEY
};

// An indicator to be able to make a fast and easy decision whether there is
// a claimcode blob at a particular address in Flash
static const uint8_t claimcode_blob_indicator[4] = {'E', '2', 'G', 'C'};

const flexspi_nor_config_t flexspi_config_claim_code = {
    .memConfig =
        {
            .tag                 = FC_BLOCK_TAG,
            .version             = FC_BLOCK_VERSION,
            .readSampleClkSrc    = 1,
            .csHoldTime          = 3,
            .csSetupTime         = 3,
            .deviceModeCfgEnable = 1,
            .deviceModeSeq       = {.seqNum = 1, .seqId = 2},
            .deviceModeArg       = 0xC740,
            .configCmdEnable     = 0,
            .deviceType          = 0x1,
            .sflashPadType       = kSerialFlash_4Pads,
            .serialClkFreq       = 7,
            .sflashA1Size        = 0x4000000U,
            .sflashA2Size        = 0,
            .sflashB1Size        = 0,
            .sflashB2Size        = 0,
            .lookupTable =
                {
                    /* Read */
                    [0] = FC_FLEXSPI_LUT_SEQ(FC_CMD_SDR, FC_FLEXSPI_1PAD, 0xEC, FC_RADDR_SDR, FC_FLEXSPI_4PAD, 0x20),
                    [1] = FC_FLEXSPI_LUT_SEQ(FC_DUMMY_SDR, FC_FLEXSPI_4PAD, 0x0A, FC_READ_SDR, FC_FLEXSPI_4PAD, 0x04),

                    /* Read Status */
                    [4 * 1 + 0] =
                        FC_FLEXSPI_LUT_SEQ(FC_CMD_SDR, FC_FLEXSPI_1PAD, 0x05, FC_READ_SDR, FC_FLEXSPI_1PAD, 0x04),

                    /* Write Status */
                    [4 * 2 + 0] =
                        FC_FLEXSPI_LUT_SEQ(FC_CMD_SDR, FC_FLEXSPI_1PAD, 0x01, FC_WRITE_SDR, FC_FLEXSPI_1PAD, 0x02),

                    /* Write Enable */
                    [4 * 3 + 0] =
                        FC_FLEXSPI_LUT_SEQ(FC_CMD_SDR, FC_FLEXSPI_1PAD, 0x06, FC_STOP_EXE, FC_FLEXSPI_1PAD, 0x00),

                    /* Sector erase */
                    [4 * 5 + 0] =
                        FC_FLEXSPI_LUT_SEQ(FC_CMD_SDR, FC_FLEXSPI_1PAD, 0x21, FC_RADDR_SDR, FC_FLEXSPI_1PAD, 0x20),

                    /* Block erase */
                    [4 * 8 + 0] =
                        FC_FLEXSPI_LUT_SEQ(FC_CMD_SDR, FC_FLEXSPI_1PAD, 0x5C, FC_RADDR_SDR, FC_FLEXSPI_1PAD, 0x20),

                    /* Page program */
                    [4 * 9 + 0] =
                        FC_FLEXSPI_LUT_SEQ(FC_CMD_SDR, FC_FLEXSPI_1PAD, 0x12, FC_RADDR_SDR, FC_FLEXSPI_1PAD, 0x20),
                    [4 * 9 + 1] =
                        FC_FLEXSPI_LUT_SEQ(FC_WRITE_SDR, FC_FLEXSPI_1PAD, 0x00, FC_STOP_EXE, FC_FLEXSPI_1PAD, 0x00),

                    /* chip erase */
                    [4 * 11 + 0] =
                        FC_FLEXSPI_LUT_SEQ(FC_CMD_SDR, FC_FLEXSPI_1PAD, 0x60, FC_STOP_EXE, FC_FLEXSPI_1PAD, 0x00),
                },
        },
    .pageSize           = 0x100,
    .sectorSize         = 0x1000,
    .ipcmdSerialClkFreq = 0,
    .blockSize          = 0x8000,
    .flashStateCtx      = 0xFFFFFFFF,
};

typedef struct _flexspi_cache_status
{
    volatile bool CacheEnableFlag;
} flexspi_cache_status_t;

static void disable_cache(flexspi_cache_status_t *cacheStatus)
{
    /* Disable cache */
    CACHE64_DisableCache(CACHE64_CTRL0);
    cacheStatus->CacheEnableFlag = true;
}

static void enable_cache(flexspi_cache_status_t cacheStatus)
{
    if (cacheStatus.CacheEnableFlag)
    {
        /* Enable cache. */
        CACHE64_EnableCache(CACHE64_CTRL0);
    }
}

static status_t program_memory(api_core_context_t *context, uint32_t address, uint32_t length, const void *data)
{
    __disable_irq(); 

    flexspi_cache_status_t cacheStatus;
    disable_cache(&cacheStatus);

    status_t status = iap_mem_write(context, address, length, data, kMemoryID_FlexspiNor);

    enable_cache(cacheStatus);
    __enable_irq();
    return status;
}

static status_t erase_memory(api_core_context_t *context, uint32_t address, uint32_t sector_size)
{
    __disable_irq();
    flexspi_cache_status_t cacheStatus;
    disable_cache(&cacheStatus); 

    status_t status = iap_mem_erase(context, address, sector_size, kMemoryID_FlexspiNor); 

    enable_cache(cacheStatus);
    __enable_irq();

    return status;
}

static status_t flush_memory(api_core_context_t *context)
{
    __disable_irq();
    flexspi_cache_status_t cacheStatus;
    disable_cache(&cacheStatus); 

    status_t status = iap_mem_flush(context); 

    enable_cache(cacheStatus);
    __enable_irq();

    return status;
}

static iot_agent_status_t write_claimcode_blob_to_flash(uint32_t address,
                                                        uint8_t *claimcode_blob,
                                                        size_t claimcode_blob_length)
{
    api_core_context_t context = {0};

    // Note, 4096 is not enough for sbloader API, but sufficient for Flash driver API.
    uint8_t iap_api_arena[4096] = {0};

    kp_api_init_param_t params = {0};
    params.allocStart          = (uint32_t)&iap_api_arena;
    params.allocSize           = sizeof(iap_api_arena);

    status_t status = iap_api_init(&context, &params);
    if (kStatus_Success != status)
    {
        return IOT_AGENT_FAILURE;
    }

    flexspi_nor_config_t flashConfig = {0};

    if (!SYSTEM_IS_XIP_FLEXSPI())
    {
        // In case of RAM execution we found out a limitation in case the Flash configuration
        // is loaded throught the flexspi_nor_get_config; in case of SW reset, only the RW61x chip
        // reset (but not the Flash), causing the function giving back the default Flash setting
        // used by the boot ROM for initial FCB read. For this reason the Flash config is stored in the
        // application variable flexspi_config_claim_code

        /**********************************************************************************************************************
         * API: flexspi_nor_set_clock_source
         *********************************************************************************************************************/
        uint32_t flexspi_clock_source = 0x0;
        status = flexspi_nor_set_clock_source(flexspi_clock_source);
        if (kStatus_Success != status)
        {
            LOG("flexspi_nor_set_clock_source returned with code [%d]\r\n", status);
        }

        /**********************************************************************************************************************
         * API: flexspi_clock_config
         *********************************************************************************************************************/
        uint32_t flexspi_freqOption    = 0x1;
        uint32_t flexspi_sampleClkMode = 0x0;
        flexspi_clock_config(FLEXSPI_INSTANCE, flexspi_freqOption, flexspi_sampleClkMode);	  

        flashConfig = *((flexspi_nor_config_t *)&flexspi_config_claim_code);
    }
    else
    {
        flashConfig = *((flexspi_nor_config_t *)FCB_ADDRESS);
    }

    status = iap_mem_config(&context, (uint32_t *)&flashConfig, kMemoryID_FlexspiNor);
    if (kStatus_Success != status)
    {
        LOG("iap_mem_config returned with code [%d]\r\n", status);
        return IOT_AGENT_FAILURE;
    }

    status = erase_memory(&context, address, flashConfig.sectorSize);
    if (kStatus_Success != status)
    {
        LOG("iap_mem_erase returned with code [%d]\r\n", status);
        return IOT_AGENT_FAILURE;
    }

    status = program_memory(&context, address, sizeof(claimcode_blob_indicator), claimcode_blob_indicator);
    if (kStatus_Success != status)
    {
        LOG("iap_mem_write returned with code [%d]\r\n", status);
        return IOT_AGENT_FAILURE;
    }

    status = program_memory(&context, address + sizeof(claimcode_blob_indicator), sizeof(uint32_t), (uint8_t*) &claimcode_blob_length);
    if (kStatus_Success != status)
    {
        LOG("iap_mem_write returned with code [%d]\r\n", status);
        return IOT_AGENT_FAILURE;
    }

    status = program_memory(&context, address + sizeof(claimcode_blob_indicator) + sizeof(uint32_t), claimcode_blob_length, claimcode_blob);
    if (kStatus_Success != status)
    {
        LOG("iap_mem_write returned with code [%d]\r\n", status);
        return IOT_AGENT_FAILURE;
    }

    status = flush_memory(&context);
    if (kStatus_Success != status)
    {
        LOG("iap_mem_flush returned with code [%d]\r\n", status);
        return IOT_AGENT_FAILURE;
    }

    return IOT_AGENT_SUCCESS;
}

/*!
 * @brief Main function
 */
int main(void)
{
    /* Init board hardware. */
#ifndef __ZEPHYR__
    BOARD_InitHardware();
#endif

    uint8_t claimcode_blob[512];
    size_t claimcode_blob_length = sizeof(claimcode_blob);

    iot_agent_status_t agent_status = iot_agent_claimcode_encrypt(plain_claimcode, iot_agent_claimcode_ecdh_pub_key,
                                                                  sizeof(iot_agent_claimcode_ecdh_pub_key),
                                                                  &claimcode_blob[0], &claimcode_blob_length);

    if (IOT_AGENT_SUCCESS != agent_status)
    {
        LOG("iot_agent_claimcode_encrypt failed: 0x%08x", agent_status);
        while (1)
            ;
    }

    agent_status = write_claimcode_blob_to_flash(CLAIM_CODE_INFO_ADDRESS, &claimcode_blob[0], claimcode_blob_length);
    if (IOT_AGENT_SUCCESS != agent_status)
    {
        LOG("write_claimcode_blob_to_flash failed: 0x%08x", agent_status);
        while (1)
            ;
    }

    if(memcmp((uint8_t *)CLAIM_CODE_INFO_ADDRESS, claimcode_blob_indicator, sizeof(claimcode_blob_indicator)) != 0)
    {
        LOG("claimcode indicator was not found in flash");
        while (1)
            ;
    }

    LOG("claimcode information written to flash at address 0x%08x", CLAIM_CODE_INFO_ADDRESS);

    while (1)
    {
    }
}
