/*
 * Copyright 2023-2026 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "el2go_claimcode_encrypt.h"

#include <fsl_device_registers.h>
#include <fsl_romapi_iap.h>
#include <fsl_cache.h>
#include "flash_config.h"

#include <el2go_claimcode_encryption.h>
#include <el2go_rtp_claimcode.h>
#include "osal.h"

#include "el2go_flash_config.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define FLASH_ADDRESS (0x08000000U)
#define FCB_ADDRESS (FLASH_ADDRESS + 0x00000400U)
#ifndef CLAIM_CODE_INFO_ADDRESS
#define CLAIM_CODE_INFO_ADDRESS (0x088A0000U)
#endif

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Code
 ******************************************************************************/

static const char *plain_claimcode = EL2GO_CLAIMCODE_STRING;

__attribute__((aligned(
    4))) static const uint8_t el2go_claimcode_ecdh_pub_key[64] = { EL2GO_RTP_CLAIMCODE_PUBLIC_KEY };

/* 
 * An indicator to be able to make a fast and easy decision whether there is
 * a claimcode blob at a particular address in Flash
 */
static const uint8_t claimcode_blob_indicator[4] = { 'E', '2', 'G', 'C' };

typedef struct _flexspi_cache_status {
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
    if (cacheStatus.CacheEnableFlag) {
        /* Enable cache. */
        CACHE64_EnableCache(CACHE64_CTRL0);
    }
}

static status_t program_memory(api_core_context_t *context, uint32_t address, uint32_t length,
                               const void *data)
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

static el2go_status_t write_claimcode_blob_to_flash(uint32_t address, uint8_t *claimcode_blob,
                                                    size_t claimcode_blob_length)
{
    api_core_context_t context = { 0 };

    /* Note, 4096 is not enough for sbloader API, but sufficient for Flash driver API. */
    uint8_t iap_api_arena[4096] = { 0 };

    kp_api_init_param_t params = { 0 };
    params.allocStart = (uint32_t)&iap_api_arena;
    params.allocSize = sizeof(iap_api_arena);

    status_t status = iap_api_init(&context, &params);
    if (kStatus_Success != status) {
        return EL2GO_STATUS_FAILURE;
    }

    flexspi_nor_config_t flashConfig = { 0 };
    el2go_flash_get_config(&flashConfig, FCB_ADDRESS);

    status = iap_mem_config(&context, (uint32_t *)&flashConfig, kMemoryID_FlexspiNor);
    if (kStatus_Success != status) {
        osal_printf_always("iap_mem_config returned with code [%d]\r\n", status);
        return EL2GO_STATUS_FAILURE;
    }

    status = erase_memory(&context, address, flashConfig.sectorSize);
    if (kStatus_Success != status) {
        osal_printf_always("iap_mem_erase returned with code [%d]\r\n", status);
        return EL2GO_STATUS_FAILURE;
    }

    status = program_memory(&context, address, sizeof(claimcode_blob_indicator),
                            claimcode_blob_indicator);
    if (kStatus_Success != status) {
        osal_printf_always("iap_mem_write returned with code [%d]\r\n", status);
        return EL2GO_STATUS_FAILURE;
    }

    if (address > UINT32_MAX - sizeof(claimcode_blob_indicator)) {
        osal_printf_always("Address out of the range\r\n");
        return EL2GO_STATUS_FAILURE;
    }
    status = program_memory(&context, address + sizeof(claimcode_blob_indicator), sizeof(uint32_t),
                            (uint8_t *)&claimcode_blob_length);
    if (kStatus_Success != status) {
        osal_printf_always("iap_mem_write returned with code [%d]\r\n", status);
        return EL2GO_STATUS_FAILURE;
    }

    if ((address > UINT32_MAX - sizeof(claimcode_blob_indicator)) ||
        (address > UINT32_MAX - sizeof(claimcode_blob_indicator) - sizeof(uint32_t))) {
        osal_printf_always("Address out of the range\r\n");
        return EL2GO_STATUS_FAILURE;
    }
    status = program_memory(&context, address + sizeof(claimcode_blob_indicator) + sizeof(uint32_t),
                            claimcode_blob_length, claimcode_blob);
    if (kStatus_Success != status) {
        osal_printf_always("iap_mem_write returned with code [%d]\r\n", status);
        return EL2GO_STATUS_FAILURE;
    }

    status = flush_memory(&context);
    if (kStatus_Success != status) {
        osal_printf_always("iap_mem_flush returned with code [%d]\r\n", status);
        return EL2GO_STATUS_FAILURE;
    }

    return EL2GO_STATUS_SUCCESS;
}

/*!
 * @brief Main function
 */
int main(void)
{
    uint8_t claimcode_blob[512];
    size_t claimcode_blob_length = sizeof(claimcode_blob);

    el2go_status_t agent_status = el2go_claimcode_encrypt(
        plain_claimcode, el2go_claimcode_ecdh_pub_key, sizeof(el2go_claimcode_ecdh_pub_key),
        &claimcode_blob[0], &claimcode_blob_length);

    if (EL2GO_STATUS_SUCCESS != agent_status) {
        osal_printf_always("el2go_claimcode_encrypt failed: 0x%08x", agent_status);
        while (true)
            ;
    }

    agent_status = write_claimcode_blob_to_flash(CLAIM_CODE_INFO_ADDRESS, &claimcode_blob[0],
                                                 claimcode_blob_length);
    if (EL2GO_STATUS_SUCCESS != agent_status) {
        osal_printf_always("write_claimcode_blob_to_flash failed: 0x%08x", agent_status);
        while (true)
            ;
    }

    if (memcmp((uint8_t *)CLAIM_CODE_INFO_ADDRESS, claimcode_blob_indicator,
               sizeof(claimcode_blob_indicator)) != 0) {
        osal_printf_always("claimcode indicator was not found in flash");
        while (true)
            ;
    }

    osal_printf_always("\r\nclaimcode information written to flash at address 0x%08x\r\n",
                       CLAIM_CODE_INFO_ADDRESS);

    while (true) {
        osal_sleep_ms(UINT32_MAX);
    }
}
