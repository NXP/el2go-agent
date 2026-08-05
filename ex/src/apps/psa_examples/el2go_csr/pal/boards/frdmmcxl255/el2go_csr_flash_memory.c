/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
*/

#include "el2go_csr_memory.h"
#include "flash_layout.h"
#include "fsl_romapi.h"
#include "fsl_common.h"

/* Dummy ROM API flash driver configuration structure. */
/* Will not be used, since this is done in SPE! */
static flash_config_t s_flashConfig;

#define FLASH_SECTOR_SIZE               (0x2000U)   /* 8 KB sector size */

/* = NSC flash region */
#define FLASH_STORAGE_END               (FLASH_TOTAL_SIZE)  
#define FLASH_STORAGE_BASE              (NXP_FLASH_NS_STORAGE_OFFSET)                 

/* configuration block is written to this address by the Host Tool (default).
 * Please refer to the README.md for further information. */
#define EL2GO_CSR_CONF_DATA_ADDR        (FLASH_STORAGE_END - 128U) 
#define EL2GO_CSR_APP_STATUSCODE_ADDR   (FLASH_STORAGE_END - 4U)   
#define EL2GO_CSR_CONF_DATA_SIZE        (124U)

uint8_t* const el2go_csr_conf_data      = (uint8_t*)EL2GO_CSR_CONF_DATA_ADDR;
uint32_t* const el2go_spsdk_status      = (uint32_t*)EL2GO_CSR_APP_STATUSCODE_ADDR;
const uint32_t el2go_csr_conf_data_size = (uint32_t)EL2GO_CSR_CONF_DATA_SIZE;

/**
 * @brief Invalidate CPU code cache / speculation buffer.
 *
 * On MCXL255 flash reads are served through the LPCAC / speculation buffer.
 * After an erase or program the caches must be cleared so subsequent reads
 * return the freshly written flash content instead of stale cached data.
 */
static void speculation_buffer_clear(void)
{
    /* Clear Flash/Flash data speculation. */
    if(((SYSCON->NVM_CTRL & SYSCON_NVM_CTRL_DIS_MBECC_ERR_INST_MASK) == 0U) 
        && ((SYSCON->NVM_CTRL & SYSCON_NVM_CTRL_DIS_MBECC_ERR_DATA_MASK) == 0U))
    {
        if((SYSCON->NVM_CTRL & SYSCON_NVM_CTRL_DIS_FLASH_SPEC_MASK) == 0U)
        {
            /* Disable flash speculation first. */
            SYSCON->NVM_CTRL |= SYSCON_NVM_CTRL_DIS_FLASH_SPEC_MASK;          
            /* Re-enable flash speculation. */
            SYSCON->NVM_CTRL &= ~SYSCON_NVM_CTRL_DIS_FLASH_SPEC_MASK;
        }
        if((SYSCON->NVM_CTRL & SYSCON_NVM_CTRL_DIS_DATA_SPEC_MASK) == 0U)
        {
            /* Disable flash data speculation first. */
            SYSCON->NVM_CTRL |= SYSCON_NVM_CTRL_DIS_DATA_SPEC_MASK;          
            /* Re-enable flash data speculation. */
            SYSCON->NVM_CTRL &= ~SYSCON_NVM_CTRL_DIS_DATA_SPEC_MASK;
        }
    }
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
    (void)memcpy(buffer, (const void *)addr, size);
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
    if (FLASH_EraseSector(&s_flashConfig, sector_addr, FLASH_SECTOR_SIZE, kFLASH_ApiEraseKey) != kStatus_Success)
    {
        return kStatus_CSR_MEM_ERASE_FAILED;
    }

    speculation_buffer_clear();

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
    if (FLASH_ProgramPage(&s_flashConfig, addr, (uint8_t *)data, size) != kStatus_Success)
    {
        return kStatus_CSR_MEM_PROGRAM_FAILED;
    }

    speculation_buffer_clear();

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
    /* Sector buffer for read-modify-write operations. */
    uint8_t* s_sectorBuffer = (uint8_t*)malloc(FLASH_SECTOR_SIZE);

    if (s_sectorBuffer == NULL)
    {
        return kStatus_CSR_MEM_OUT_OF_MEM;
    }

    /* Step 1: Read entire sector into buffer. */
    if (flash_read(sector_addr, s_sectorBuffer, FLASH_SECTOR_SIZE) != kStatus_CSR_MEM_SUCCESS)
    {
        free(s_sectorBuffer);
        return kStatus_CSR_MEM_FAILED;
    }

    /* Step 2: Modify buffer with new data. */
    (void)memcpy(&s_sectorBuffer[data_offset], data, data_size);

    /* Step 3: Erase sector. */
    if (flash_erase_sector(sector_addr) != kStatus_CSR_MEM_SUCCESS)
    {
        free(s_sectorBuffer);
        return kStatus_CSR_MEM_FAILED;
    }

    /* Step 4: Program entire sector. */
    if (flash_program(sector_addr, s_sectorBuffer, FLASH_SECTOR_SIZE) != kStatus_CSR_MEM_SUCCESS)
    {
        free(s_sectorBuffer);
        return kStatus_CSR_MEM_FAILED;
    }

    free(s_sectorBuffer);
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
    return !((addr < FLASH_STORAGE_BASE) || ((addr + size) > (uint32_t)FLASH_STORAGE_END));
}


csr_mem_status_t mem_read(uint32_t addr, uint8_t *buffer, uint32_t size)
{

    if ((buffer == NULL) || (size == 0U))
    {
        return kStatus_CSR_MEM_INVALID_ARG;
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

    if ((buffer == NULL) || (size == 0U))
    {
        return kStatus_CSR_MEM_INVALID_ARG;
    }

    if (!validate_flash_address(addr, size))
    {
        return kStatus_CSR_MEM_INVALID_ARG;
    }

    /* Process each affected sector. */
    while (remaining_size > 0U)
    {
        sector_addr = current_addr & ~(FLASH_SECTOR_SIZE - 1U);
        offset_in_sector = current_addr - sector_addr;

        bytes_to_write = FLASH_SECTOR_SIZE - offset_in_sector;
        if (bytes_to_write > remaining_size)
        {
            bytes_to_write = remaining_size;
        }

        /* Perform read-modify-write for this sector. */
        if (program_sector_rmw(sector_addr, offset_in_sector, data_ptr, bytes_to_write) != kStatus_CSR_MEM_SUCCESS)
        {
            return kStatus_CSR_MEM_FAILED;
        }

        /* Move to next sector. */
        current_addr += bytes_to_write;
        data_ptr += bytes_to_write;
        remaining_size -= bytes_to_write;
    }

    return kStatus_CSR_MEM_SUCCESS;
}