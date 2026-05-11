/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "el2go_csr_memory.h"

/* RAM storage for EL2GO CSR data */
#ifndef EL2GO_CSR_CONF_SIZE
#define EL2GO_CSR_CONF_SIZE  (124U)
#endif

#ifndef EL2GO_CSR_MEM_SIZE
#define EL2GO_CSR_MEM_SIZE   (4096U)
#endif

/* Static RAM buffers */
static uint8_t s_ramStorage[EL2GO_CSR_MEM_SIZE];
static uint8_t s_memInitialized = 0U;

/* Configuration data and status code */
uint8_t el2go_csr_conf_data[EL2GO_CSR_CONF_SIZE];
uint32_t el2go_spsdk_status = 0U;

/* Base address of RAM storage */
#define RAM_STORAGE_BASE    ((uint32_t)&s_ramStorage[0])
#define RAM_STORAGE_END     (RAM_STORAGE_BASE + EL2GO_CSR_MEM_SIZE)

/**
 * @brief Initialize memory
 */
static csr_mem_status_t mem_init(void)
{
    uint32_t i;
    
    if (s_memInitialized != 0U)
    {
        return kStatus_CSR_MEM_SUCCESS;
    }

    for (i = 0U; i < EL2GO_CSR_MEM_SIZE; i++)
    {
        s_ramStorage[i] = 0x42U; // For debugging reasons, not needed otherwise.
    }
    s_memInitialized = 1U;
    
    return kStatus_CSR_MEM_SUCCESS;
}

/**
 * @brief Validate address is within RAM storage range
 */
static uint8_t validate_address(uint32_t addr, uint32_t size)
{
    return ((addr >= RAM_STORAGE_BASE) && ((addr + size) <= RAM_STORAGE_END)) ? 1U : 0U;
}

csr_mem_status_t mem_read(uint32_t addr, uint8_t *buffer, uint32_t size)
{
    uint32_t i;
    const uint8_t *src;
    
    if ((buffer == NULL) || (size == 0U))
    {
        return kStatus_CSR_MEM_INVALID_ARG;
    }

    if (s_memInitialized == 0U)
    {
        if (mem_init() != kStatus_CSR_MEM_SUCCESS)
        {
            return kStatus_CSR_MEM_FAILED;
        }
    }

    if (validate_address(addr, size) == 0U)
    {
        return kStatus_CSR_MEM_INVALID_ARG;
    }

    src = (const uint8_t *)addr;
    for (i = 0U; i < size; i++)
    {
        buffer[i] = src[i];
    }
    
    return kStatus_CSR_MEM_SUCCESS;
}

csr_mem_status_t mem_write(uint32_t addr, const uint8_t *buffer, uint32_t size)
{
    uint32_t i;
    uint8_t *dst;
    
    if ((buffer == NULL) || (size == 0U))
    {
        return kStatus_CSR_MEM_INVALID_ARG;
    }

    if (s_memInitialized == 0U)
    {
        if (mem_init() != kStatus_CSR_MEM_SUCCESS)
        {
            return kStatus_CSR_MEM_FAILED;
        }
    }

    if (validate_address(addr, size) == 0U)
    {
        return kStatus_CSR_MEM_INVALID_ARG;
    }

    dst = (uint8_t *)addr;
    for (i = 0U; i < size; i++)
    {
        dst[i] = buffer[i];
    }
    
    return kStatus_CSR_MEM_SUCCESS;
}
