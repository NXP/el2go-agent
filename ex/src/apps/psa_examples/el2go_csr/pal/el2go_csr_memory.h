/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
/** @file */
#ifndef _EL2GO_CSR_MEMORY_H_
#define _EL2GO_CSR_MEMORY_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __ZEPHYR__
#include <stdint.h>
#else
#include "app.h"
#include "board.h"
#endif

typedef enum _csr_mem_status
{
    kStatus_CSR_MEM_SUCCESS             = 0x5A5A5A5AU,
    kStatus_CSR_MEM_INVALID_ARG         = 0x9DD210C5U,
    kStatus_CSR_MEM_INIT_FAILED         = 0x7B2E4F91U,
    kStatus_CSR_MEM_SECTOR_LOCK_FAILED  = 0x3A1C6D47U,
    kStatus_CSR_MEM_ERASE_FAILED        = 0x8F5B2A3CU,
    kStatus_CSR_MEM_PROGRAM_FAILED      = 0x6E7D1B9AU,
    kStatus_CSR_MEM_OUT_OF_MEM          = 0xC4A92F5EU,
    kStatus_CSR_MEM_FAILED              = 0x10F3DEABU,
} csr_mem_status_t; 

/*! @brief Read data from memory at specified address.
 * 
 * @param[in] addr: Memory address to read from.
 * @param[out] buffer: Pointer to buffer where read data will be stored.
 * @param[in] size: Number of bytes to read.
 * @retval kStatus_CSR_MEM_SUCCESS: Memory read operation successful.
*/
csr_mem_status_t mem_read(uint32_t addr, uint8_t *buffer, uint32_t size);

/*! @brief Write data to memory at specified address.
 * 
 * @param[in] addr: Memory address to write to.
 * @param[in] buffer: Pointer to buffer containing data to be written.
 * @param[in] size: Number of bytes to write.
 * @retval kStatus_CSR_MEM_SUCCESS: Memory write operation successful.
*/
csr_mem_status_t mem_write(uint32_t addr, const uint8_t *buffer, uint32_t size);

#ifdef __cplusplus
}
#endif

#endif /* _EL2GO_CSR_MEMORY_H_ */
