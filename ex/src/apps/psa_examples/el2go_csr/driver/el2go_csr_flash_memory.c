/*
 * Copyright 2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
*/

#include "el2go_csr_memory.h"
#include "fsl_c40_flash.h" 

// Flash sector size for C40 flash 
#define FLASH_SECTOR_SIZE       (8U * 1024U)

// Flash phrase size (minimum program unit) for C40 flash on FRDMMCXE31B 
#define FLASH_PHRASE_SIZE       (16U)

// Singleton to track init status of memory device 
static uint8_t s_memInitialized = 0U;

// Flash driver configuration structure 
static flash_config_t s_flashConfig;

// Sector buffer for read-modify-write operations - ensure 4-byte alignment 
static uint32_t s_sectorBufferAligned[FLASH_SECTOR_SIZE / sizeof(uint32_t)];
#define s_sectorBuffer ((uint8_t *)s_sectorBufferAligned)

// 8kB reserved section for EL2GO CSR configuration 
#define EL2GO_CSR_CONF_SIZE  0x2000
__attribute__((section(".el2go_csr_conf")))
uint8_t el2go_csr_conf_data[EL2GO_CSR_CONF_SIZE];

/**
 * @brief Initialize flash driver
 * 
 * @retval kStatus_CSR_MEM_SUCCESS PFlash driver initialized successfully
 */
static csr_mem_status_t flash_init(void)
{
    status_t result;
    
    if (s_memInitialized != 0U)
    {
        return kStatus_CSR_MEM_SUCCESS;
    }

    result = FLASH_Init(&s_flashConfig);
    if (result != kStatus_FLASH_Success)
    {
        return kStatus_CSR_MEM_INIT_FAILED;
    }

    s_memInitialized = 1U;
    return kStatus_CSR_MEM_SUCCESS;
}

/**
 * @brief Read data directly from flash memory
 * 
 * @param addr Flash address to read from
 * @param buffer Pointer to destination buffer
 * @param size Number of bytes to read
 * @retval kStatus_CSR_MEM_SUCCESS on success
 */
static csr_mem_status_t flash_read(uint32_t addr, uint8_t *buffer, uint32_t size)
{
    (void)memcpy(buffer, (const void *)addr, size);
    return kStatus_CSR_MEM_SUCCESS;
}

/**
 * @brief Erase a flash sector
 * 
 * @param sector_addr Sector-aligned address
 * @retval kStatus_CSR_MEM_SUCCESS Flash operation status
 */
static csr_mem_status_t flash_erase_sector(uint32_t sector_addr)
{
    if (FLASH_GetSectorProtection(&s_flashConfig, sector_addr) == kStatus_FLASH_SectorLocked)
    {
        if (FLASH_SetSectorProtection(&s_flashConfig, sector_addr, false) != kStatus_FLASH_Success)
        {
            return kStatus_CSR_MEM_SECTOR_LOCK_FAILED;
        }
    }

    if (FLASH_Erase(&s_flashConfig, sector_addr, FLASH_SECTOR_SIZE, kFLASH_ApiEraseKey) != kStatus_FLASH_Success)
    {
        return kStatus_CSR_MEM_ERASE_FAILED;
    }
    
    return kStatus_CSR_MEM_SUCCESS;
}

/**
 * @brief Program data to flash
 * 
 * @param addr Flash address (must be phrase-aligned)
 * @param data Pointer to data buffer
 * @param size Number of bytes to program (must be phrase-aligned)
 * @retval status_t Flash operation status
 */
static csr_mem_status_t flash_program(uint32_t addr, const uint8_t *data, uint32_t size)
{
    if (FLASH_Program(&s_flashConfig, addr, (uint32_t *)data, size) != kStatus_FLASH_Success)
    {
        return kStatus_CSR_MEM_PROGRAM_FAILED;
    }
    
    return kStatus_CSR_MEM_SUCCESS;
}

/**
 * @brief Program a single sector with read-modify-write pattern
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
    uint32_t actual_sector_size;

    // Use actual sector size from flash config if available 
    actual_sector_size = (s_flashConfig.PFlashSectorSize != 0U) ? 
                          s_flashConfig.PFlashSectorSize : FLASH_SECTOR_SIZE;

    // Step 1: Read entire sector into buffer 
    if (flash_read(sector_addr, s_sectorBuffer, actual_sector_size) != kStatus_CSR_MEM_SUCCESS)
    {
        return kStatus_CSR_MEM_FAILED;
    }

    // Step 2: Modify buffer with new data 
    (void)memcpy(&s_sectorBuffer[data_offset], data, data_size);

    // Step 3: Erase sector 
    if (flash_erase_sector(sector_addr) != kStatus_CSR_MEM_SUCCESS)
    {
        return kStatus_CSR_MEM_FAILED;
    }

    // Step 4: Program entire sector 
    if (flash_program(sector_addr, s_sectorBuffer, actual_sector_size) != kStatus_CSR_MEM_SUCCESS)
    {
        return kStatus_CSR_MEM_FAILED;
    }

    return kStatus_CSR_MEM_SUCCESS;
}

/**
 * @brief Validate flash address is within valid range
 * 
 * @param addr Address to validate
 * @param size Size of access
 * @retval true Address is valid
 * @retval false Address is out of range
 */
static bool validate_flash_address(uint32_t addr, uint32_t size)
{
    uint32_t flash_start = s_flashConfig.PFlashBlockBase;
    uint32_t flash_end = flash_start + s_flashConfig.PFlashTotalSize;
    
    return !((addr < flash_start) || ((addr + size) > flash_end));
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
    uint32_t sector_addr;
    uint32_t offset_in_sector;
    uint32_t bytes_to_write;
    const uint8_t *data_ptr = buffer;
    uint32_t current_addr = addr;
    uint32_t remaining_size = size;
    uint32_t actual_sector_size;
    
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

    // Use actual sector size from flash config 
    actual_sector_size = (s_flashConfig.PFlashSectorSize != 0U) ? 
                          s_flashConfig.PFlashSectorSize : FLASH_SECTOR_SIZE;

    // Process each affected sector 
    while (remaining_size > 0U)
    {
        sector_addr = current_addr & ~(actual_sector_size - 1U);
        offset_in_sector = current_addr - sector_addr;

        bytes_to_write = actual_sector_size - offset_in_sector;
        if (bytes_to_write > remaining_size)
        {
            bytes_to_write = remaining_size;
        }

        // Perform read-modify-write for this sector 
        if (program_sector_rmw(sector_addr, offset_in_sector, data_ptr, bytes_to_write) != kStatus_CSR_MEM_SUCCESS)
        {
            return kStatus_CSR_MEM_FAILED;
        }

        // Move to next sector 
        current_addr += bytes_to_write;
        data_ptr += bytes_to_write;
        remaining_size -= bytes_to_write;
    }

    return kStatus_CSR_MEM_SUCCESS;
}
