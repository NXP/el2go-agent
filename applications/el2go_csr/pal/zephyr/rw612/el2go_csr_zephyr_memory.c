/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/*
 * Zephyr flash driver implementation of the el2go_csr memory PAL for RW6xx.
 *
 * The RW612 QSPI flash is memory-mapped (XIP) at QSPI_XIP_BASE (0x08000000).
 * el2go_csr_conf_data and el2go_spsdk_status are exported as XIP pointers so
 * callers can read through them directly without any flash driver involvement.
 *
 * Reads  (mem_read)  use memcpy from the XIP address - no flash driver needed.
 * Writes (mem_write) convert the XIP address to a raw flash offset and perform
 * a read-modify-write using the Zephyr flash driver API directly.
 *
 * The flash device is obtained via DT_CHOSEN(zephyr_flash_controller) which
 * resolves to the FlexSPI controller on RW612 boards.
 *
 * Sector layout (4 kB, EL2GO_CSR_FLASH_SECTOR_SIZE bytes):
 *   [+0x000 .. +0x07B]  configuration block  (124 bytes)
 *   [+0x07C .. +0xFFB]  reserved
 *   [+0xFFC .. +0xFFF]  SPSDK status code    (4 bytes)
 */

#include <string.h>
#include <stdlib.h>
#include <zephyr/devicetree.h>
#include <zephyr/drivers/flash.h>

#include "el2go_csr_memory.h"
#include "builtin_macros.h"

/* Base address of the QSPI XIP window on RW612. */
#define QSPI_XIP_BASE (0x08000000U)

/* Absolute flash offset of the 4 kB sector used for CSR config block and
 * status code.  This matches the value programmed by SPSDK. */
#define EL2GO_CSR_FLASH_SECTOR_OFFSET (0x8B0000U)
#define EL2GO_CSR_FLASH_SECTOR_SIZE (0x1000U)

#define EL2GO_CSR_CONF_DATA_SIZE (124U)

/* XIP addresses for the two exported symbols. */
#define EL2GO_CSR_CONF_DATA_XIP_ADDR (QSPI_XIP_BASE + EL2GO_CSR_FLASH_SECTOR_OFFSET + 0x000U)
#define EL2GO_CSR_STATUSCODE_XIP_ADDR \
    (QSPI_XIP_BASE + EL2GO_CSR_FLASH_SECTOR_OFFSET + EL2GO_CSR_FLASH_SECTOR_SIZE - sizeof(uint32_t))

/* Exported XIP pointers and size used by el2go_csr.c */
uint8_t *const el2go_csr_conf_data = (uint8_t *)(EL2GO_CSR_CONF_DATA_XIP_ADDR);
uint32_t *const el2go_spsdk_status = (uint32_t *)(EL2GO_CSR_STATUSCODE_XIP_ADDR);
const uint32_t el2go_csr_conf_data_size = (uint32_t)EL2GO_CSR_CONF_DATA_SIZE;

/* ---------------------------------------------------------------------------
 * Internal helpers
 * ---------------------------------------------------------------------------*/

/*
 * Sector-level read-modify-write using the Zephyr flash driver API.
 * flash_offset - absolute flash offset (not XIP address) of the byte range
 * data         - data to write
 * size         - number of bytes to write
 */
static csr_mem_status_t flash_rmw(uint32_t flash_offset, const uint8_t *data, uint32_t size)
{
    const struct device *flash_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_flash_controller));
    csr_mem_status_t status = kStatus_CSR_MEM_SUCCESS;

    /* Validate the range falls within our CSR sector. */
    uint32_t end_offset = 0U;
    if ((flash_offset < EL2GO_CSR_FLASH_SECTOR_OFFSET) ||
        ADD_OVERFLOW(flash_offset, size, &end_offset) ||
        (end_offset > (EL2GO_CSR_FLASH_SECTOR_OFFSET + EL2GO_CSR_FLASH_SECTOR_SIZE))) {
        return kStatus_CSR_MEM_INVALID_ARG;
    }

    if (!device_is_ready(flash_dev)) {
        return kStatus_CSR_MEM_INIT_FAILED;
    }

    uint8_t *sector_buf = (uint8_t *)malloc(EL2GO_CSR_FLASH_SECTOR_SIZE);
    if (sector_buf == NULL) {
        return kStatus_CSR_MEM_OUT_OF_MEM;
    }

    /* Step 1: Read the whole sector at its absolute flash offset. */
    if (flash_read(flash_dev, EL2GO_CSR_FLASH_SECTOR_OFFSET, sector_buf,
                   EL2GO_CSR_FLASH_SECTOR_SIZE) != 0) {
        status = kStatus_CSR_MEM_FAILED;
        goto cleanup;
    }

    /* Step 2: Patch in the new data. */
    uint32_t offset_in_sector = flash_offset - EL2GO_CSR_FLASH_SECTOR_OFFSET;
    (void)memcpy(&sector_buf[offset_in_sector], data, size);

    /* Step 3: Erase the sector. */
    if (flash_erase(flash_dev, EL2GO_CSR_FLASH_SECTOR_OFFSET, EL2GO_CSR_FLASH_SECTOR_SIZE) != 0) {
        status = kStatus_CSR_MEM_ERASE_FAILED;
        goto cleanup;
    }

    /* Step 4: Write back the full sector. */
    if (flash_write(flash_dev, EL2GO_CSR_FLASH_SECTOR_OFFSET, sector_buf,
                    EL2GO_CSR_FLASH_SECTOR_SIZE) != 0) {
        status = kStatus_CSR_MEM_PROGRAM_FAILED;
        goto cleanup;
    }

cleanup:
    free(sector_buf);
    return status;
}

/* ---------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------------*/

/*
 * mem_read: Copy bytes from the XIP-mapped flash address into buffer.
 * addr is an XIP address (e.g. el2go_csr_conf_data cast to uint32_t).
 * No flash driver involvement; the QSPI window is directly readable.
 */
csr_mem_status_t mem_read(uint32_t addr, uint8_t *buffer, uint32_t size)
{
    if (buffer == NULL || size == 0U) {
        return kStatus_CSR_MEM_INVALID_ARG;
    }

    (void)memcpy(buffer, (const void *)(uintptr_t)addr, size);
    return kStatus_CSR_MEM_SUCCESS;
}

/*
 * mem_write: Write bytes to flash using a read-modify-write cycle.
 * addr is an XIP address; it is converted to a raw flash offset by
 * subtracting QSPI_XIP_BASE before being passed to flash_rmw.
 */
csr_mem_status_t mem_write(uint32_t addr, const uint8_t *buffer, uint32_t size)
{
    if (buffer == NULL || size == 0U) {
        return kStatus_CSR_MEM_INVALID_ARG;
    }

    if (addr < QSPI_XIP_BASE) {
        return kStatus_CSR_MEM_INVALID_ARG;
    }

    uint32_t flash_offset = addr - QSPI_XIP_BASE;
    return flash_rmw(flash_offset, buffer, size);
}
