/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <stddef.h>
#include <inttypes.h>

#include "psa/internal_trusted_storage.h"

#include "debug.h"
#include "builtin_macros.h"

#include "common/el2go_keystore.h"
#include "keystore_priv.h"
#include "plat_keys.h"

/*
 * Claimcode blob layout at CONFIG_EL2GO_RTP_CLAIMCODE_FLASH_ADDRESS:
 *   uint8_t  indicator[4] = {'E','2','G','C'}
 *   uint32_t size          (little-endian)
 *   uint8_t  data[size]
 */
#define EL2GO_CLAIMCODE_MAGIC_0 'E'
#define EL2GO_CLAIMCODE_MAGIC_1 '2'
#define EL2GO_CLAIMCODE_MAGIC_2 'G'
#define EL2GO_CLAIMCODE_MAGIC_3 'C'

el2go_status_t el2go_keystore_import_claimcode_from_flash(el2go_keystore_t *keystore)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    psa_status_t psa_status = PSA_SUCCESS;
    struct psa_storage_info_t info = { 0 };
    const uint8_t *flash_ptr = (const uint8_t *)(uintptr_t)CONFIG_EL2GO_RTP_CLAIMCODE_FLASH_ADDRESS;
    uint32_t claimcode_size = 0U;
    const uint8_t *claimcode_data = NULL;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    (void)keystore;

    /* Validate magic indicator bytes. */
    if (flash_ptr[0] != EL2GO_CLAIMCODE_MAGIC_0 || flash_ptr[1] != EL2GO_CLAIMCODE_MAGIC_1 ||
        flash_ptr[2] != EL2GO_CLAIMCODE_MAGIC_2 || flash_ptr[3] != EL2GO_CLAIMCODE_MAGIC_3) {
        EL2GO_DBG_PRINTF(ERROR, "Claimcode magic bytes invalid at 0x%08x\n",
                         CONFIG_EL2GO_RTP_CLAIMCODE_FLASH_ADDRESS);
        status = EL2GO_STATUS_INVALID_PARAMETER;
        goto exit;
    }

    /* Read size (little-endian 32-bit, immediately after indicator). */
    claimcode_size = (uint32_t)(flash_ptr[4]) | ((uint32_t)(flash_ptr[5]) << 8U) |
                     ((uint32_t)(flash_ptr[6]) << 16U) | ((uint32_t)(flash_ptr[7]) << 24U);
    claimcode_data = flash_ptr + 8U;

    /* Check whether claimcode is already stored in PSA ITS. */
    psa_status = psa_its_get_info(EDGELOCK2GO_CLAIMCODE_DATA_ID, &info);
    if (psa_status == PSA_SUCCESS) {
        EL2GO_DBG_PRINTF(VERBOSE, "Claimcode already stored in PSA ITS, skipping import\n");
        status = EL2GO_STATUS_SUCCESS;
        goto exit;
    }

    /* Write claimcode into PSA ITS. */
    psa_status = psa_its_set(EDGELOCK2GO_CLAIMCODE_DATA_ID, claimcode_size, claimcode_data,
                             PSA_STORAGE_FLAG_NONE);
    if (psa_status != PSA_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "psa_its_set claimcode failed: %d\n", (int)psa_status);
        status = EL2GO_STATUS_PSA_ERROR;
        goto exit;
    }

    EL2GO_DBG_PRINTF(VERBOSE, "Claimcode imported from flash (size: %" PRIu32 ")\n",
                     claimcode_size);

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}
