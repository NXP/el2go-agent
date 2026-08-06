/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
*/

#include "el2go_csr_memory.h"

uint8_t* const el2go_csr_conf_data = (uint8_t*)0;
uint32_t* const el2go_spsdk_status = (uint32_t*)0;
const uint32_t el2go_csr_conf_data_size = (uint32_t)0;

/**
 * @brief Initialize flash driver.
 *
 * @retval kStatus_CSR_MEM_SUCCESS PFlash driver initialized successfully
 */
static csr_mem_status_t flash_init(void)
{
    return kStatus_CSR_MEM_SUCCESS;
}

/**
 * @brief Read data directly from flash memory.
 *
 * @param addr Flash address to read from
 * @param buffer Pointer to destination buffer
 * @param size Number of bytes to read
 * @retval kStatus_CSR_MEM_SUCCESS on success
 */
static csr_mem_status_t flash_read(uint32_t addr, uint8_t *buffer, uint32_t size)
{
    return kStatus_CSR_MEM_SUCCESS;
}

/**
 * @brief Erase a flash sector.
 *
 * @param sector_addr Sector-aligned address
 * @retval kStatus_CSR_MEM_SUCCESS Flash operation status
 */
static csr_mem_status_t flash_erase_sector(uint32_t sector_addr)
{
    return kStatus_CSR_MEM_SUCCESS;
}

/**
 * @brief Program data to flash.
 *
 * @param addr Flash address (must be phrase-aligned)
 * @param data Pointer to data buffer
 * @param size Number of bytes to program (must be phrase-aligned)
 * @retval kStatus_CSR_MEM_SUCCESS Flash operation status
 */
static csr_mem_status_t flash_program(uint32_t addr, const uint8_t *data, uint32_t size)
{
    return kStatus_CSR_MEM_SUCCESS;
}

/**
 * @brief Program a single sector with a read-modify-write pattern.
 *
 * @param sector_addr Sector-aligned address
 * @param data_offset Offset within sector where data starts
 * @param data Pointer to data to write
 * @param data_size Size of data to write (in bytes)
 * @retval kStatus_CSR_MEM_SUCCESS on success, error code otherwise
 */
static csr_mem_status_t program_sector_rmw(uint32_t sector_addr,
                                   uint32_t data_offset,
                                   const uint8_t *data,
                                   uint32_t data_size)
{
    return kStatus_CSR_MEM_SUCCESS;
}

/**
 * @brief Validate flash address is within valid range.
 *
 * @param addr Address to validate
 * @param size Size of access
 * @retval true Address is valid
 * @retval false Address is out of range
 */
static bool validate_flash_address(uint32_t addr, uint32_t size)
{
    return true;
}


csr_mem_status_t mem_read(uint32_t addr, uint8_t *buffer, uint32_t size)
{
    return kStatus_CSR_MEM_SUCCESS;
}

csr_mem_status_t mem_write(uint32_t addr, const uint8_t *buffer, uint32_t size)
{
    return kStatus_CSR_MEM_SUCCESS;
}
