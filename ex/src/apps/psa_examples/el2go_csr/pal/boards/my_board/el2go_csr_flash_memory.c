/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "el2go_csr_memory.h"
#include "el2go_csr_bsp.h"

static uint8_t s_memInitialized = 0U;
                              
#define FLASH_STORAGE_BASE 	 (0xBADC0DE)
#define FLASH_STORAGE_END    (FLASH_STORAGE_BASE + 4096U) 
#define FLASH_PAGE_SIZE      (0x1000U) 

uint8_t* const el2go_csr_conf_data = (uint8_t*)(FLASH_STORAGE_END - 128U);
uint32_t* const el2go_spsdk_status = (uint32_t*)(FLASH_STORAGE_END - 4U);

static csr_mem_status_t flash_init(void)
{
    if (s_memInitialized != 0U)
    {
        return kStatus_CSR_MEM_SUCCESS;
    }

    // Add here your Flash API for initializing the driver .
    // ...

    s_memInitialized = 1U;

    return kStatus_CSR_MEM_SUCCESS;
}

static csr_mem_status_t flash_read(uint32_t addr, uint8_t *buffer, uint32_t size)
{
    // Assuming memory-mapped address space for reading
    // Call the appropiate Flash API for reading, if this 
    // is not the case!

    (void)memcpy(buffer, (const void *)addr, size); 
    return kStatus_CSR_MEM_SUCCESS;
}

static csr_mem_status_t flash_erase_page(uint32_t addr)
{
    // Implement this helper function for erasing a page, 
    // for using a read-modify-write program pattern.

    return kStatus_CSR_MEM_SUCCESS;
}

static csr_mem_status_t flash_program(uint32_t addr, const uint8_t *data)
{
    // Call here the FLASH_PROGRAM API to write the data at the provided
    // address.

    return kStatus_CSR_MEM_SUCCESS;
}

static csr_mem_status_t program_page_rmw(uint32_t page_addr,
                                         uint32_t offset,
                                         const uint8_t *data,
                                         uint32_t size)
{
    uint8_t buffer[FLASH_PAGE_SIZE];

    if (flash_read(page_addr, buffer, FLASH_PAGE_SIZE) != kStatus_CSR_MEM_SUCCESS)
    {
        return kStatus_CSR_MEM_FAILED;
    }

    (void)memcpy(&buffer[offset], data, size);

    if (flash_erase_page(page_addr) != kStatus_CSR_MEM_SUCCESS)
    {
        return kStatus_CSR_MEM_FAILED;
    }

    if (flash_program(page_addr, buffer) != kStatus_CSR_MEM_SUCCESS)
    {
        return kStatus_CSR_MEM_FAILED;
    }

    return kStatus_CSR_MEM_SUCCESS;
}

static uint8_t validate_flash_address(uint32_t addr, uint32_t size)
{
    return !((addr < FLASH_STORAGE_BASE) || ((addr + size) > FLASH_STORAGE_END));
}

csr_mem_status_t mem_read(uint32_t addr, uint8_t *buffer, uint32_t size)
{
    if ((buffer == NULL) || (size == 0U))
    {
        return kStatus_CSR_MEM_INVALID_ARG;
    }

    if (s_memInitialized == 0U)
    {
        if (flash_init() != kStatus_CSR_MEM_SUCCESS)
        {
            return kStatus_CSR_MEM_FAILED;
        }
    }

    if (!validate_flash_address(addr, size))
    {
        return kStatus_CSR_MEM_INVALID_ARG;
    }

    if (flash_read(addr, buffer, size) != kStatus_CSR_MEM_SUCCESS)
    {
        return kStatus_CSR_MEM_FAILED;
    }

    return kStatus_CSR_MEM_SUCCESS;
}

csr_mem_status_t mem_write(uint32_t addr, const uint8_t *buffer, uint32_t size)
{
    uint32_t current_addr = addr;
    uint32_t remaining_size = size;
    const uint8_t *data_ptr = buffer;

    if ((buffer == NULL) || (size == 0U))
    {
        return kStatus_CSR_MEM_INVALID_ARG;
    }

    if (s_memInitialized == 0U)
    {
        if (flash_init() != kStatus_CSR_MEM_SUCCESS)
        {
            return kStatus_CSR_MEM_FAILED;
        }
    }

    if (!validate_flash_address(addr, size))
    {
        return kStatus_CSR_MEM_INVALID_ARG;
    }

    while (remaining_size > 0U)
    {
        uint32_t page_addr = current_addr & ~(FLASH_PAGE_SIZE - 1U);
        uint32_t offset = current_addr - page_addr;
        uint32_t chunk = FLASH_PAGE_SIZE - offset;

        if (chunk > remaining_size)
        {
            chunk = remaining_size;
        }

        if (program_page_rmw(page_addr, offset, data_ptr, chunk) != kStatus_CSR_MEM_SUCCESS)
        {
            return kStatus_CSR_MEM_FAILED;
        }

        current_addr += chunk;
        data_ptr += chunk;
        remaining_size -= chunk;
    }

    return kStatus_CSR_MEM_SUCCESS;
}