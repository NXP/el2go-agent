/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "el2go_csr_integrity_verifier.h"
#include "el2go_csr_console.h"
#include "el2go_app_byte_utils.h"
#include "fsl_crc.h"

#include <stdint.h>
#include <stddef.h>

/*
 * Hardware CRC-32 using the RW61x CRC peripheral.
 * Configured for the standard Ethernet polynomial (0x04C11DB7),
 * reflected input/output, initial seed 0xFFFFFFFF, final XOR 0xFFFFFFFF.
 */

static csr_integrity_verifier_t crc32_verify(uint8_t *data, size_t size,
                                             const uint8_t *expected_crc)
{
    if (data == NULL || expected_crc == NULL || size == 0U) {
        return kStatus_CSR_INT_VERIFY_INVALID_ARG;
    }

    crc_config_t config;
    CRC_GetDefaultConfig(&config);
    /* Standard CRC-32 (IEEE 802.3): reflected I/O, seed and final XOR 0xFFFFFFFF */
    config.polynomial = kCRC_Polynomial_CRC_32;
    config.reverseIn = true;
    config.complementIn = false;
    config.reverseOut = true;
    config.complementOut = true;
    config.seed = 0xFFFFFFFFU;

    CRC_Init(CRC, &config);
    CRC_WriteData(CRC, data, size);
    uint32_t calculated = CRC_Get32bitResult(CRC);

    uint32_t expected = get_uint32_val(expected_crc);

    LOG(LOG_DEBUG, "Computed CRC32: 0x%08X, Expected CRC32: 0x%08X\r\n", calculated, expected);

    return (calculated == expected) ? kStatus_CSR_INT_VERIFY_SUCCESS :
                                      kStatus_CSR_INT_VERIFY_FAILED;
}

csr_integrity_verifier_t verify_integrity(uint8_t *data, size_t size, const uint8_t *checksum,
                                          integrity_algorithms_t algo)
{
    switch (algo) {
    case CRC_32:
        LOG(LOG_TRACE, "Verifying data integrity using CRC-32 algorithm\r\n");
        return crc32_verify(data, size, checksum);

    default:
        LOG(LOG_TRACE, "Unsupported integrity algorithm: %d\r\n", algo);
        break;
    }

    return kStatus_CSR_INT_VERIFY_FAILED;
}
