/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "el2go_csr_integrity_verifier.h"
#include "el2go_csr_console.h"
#include "byte_utils.h"
#include "crc_sw_util.h"


csr_integrity_verifier_t 
verify_integrity(uint8_t *data, size_t size, const uint8_t *checksum, integrity_algorithms_t algo)
{
    switch (algo)
    {
        case CRC_32:
            LOG(LOG_TRACE, "Verifying data integrity using CRC-32 algorithm\r\n");
            return crc32_calculate_sw(data, size, checksum);
        break; 

        default:
            LOG(LOG_TRACE, "Unsupported integrity algorithm: %d\r\n", algo);
        break;
    }

    return kStatus_CSR_INT_VERIFY_FAILED;
}

