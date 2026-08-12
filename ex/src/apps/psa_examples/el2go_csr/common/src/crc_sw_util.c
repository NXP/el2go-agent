/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "crc_sw_util.h"
#include "el2go_csr_console.h"

#define CRC32_POLYNOMIAL_REFLECTED  0xEDB88320U
#define CRC32_INITIAL_VALUE         0xFFFFFFFFU
#define CRC32_FINAL_XOR             0xFFFFFFFFU

csr_integrity_verifier_t crc32_calculate_sw(uint8_t *data, size_t size, const uint8_t* expected_crc)
{
    uint32_t calculated_crc = 0U;
    uint32_t expected_crc_value = 0U;
    size_t i = 0U;
    uint8_t j = 0U;

    if (!data || !expected_crc || !size)
    {
        return kStatus_CSR_INT_VERIFY_INVALID_ARG;
    }

    calculated_crc = CRC32_INITIAL_VALUE;

    for (i = 0U; i < size; i++)
    {
        calculated_crc ^= data[i];

        for (j = 0U; j < 8U; j++)
        {
            if ((calculated_crc & 1U) != 0U)
            {
                calculated_crc = (calculated_crc >> 1U) ^ CRC32_POLYNOMIAL_REFLECTED;
            }
            else
            {
                calculated_crc = calculated_crc >> 1U;
            }
        }
    }

    calculated_crc ^= CRC32_FINAL_XOR;
    expected_crc_value = get_uint32_val(expected_crc);

    LOG(LOG_DEBUG, "Computed CRC32: 0x%08X, Expected CRC32: 0x%08X\r\n", calculated_crc, expected_crc_value);
    if (calculated_crc == expected_crc_value)
    {
        return kStatus_CSR_INT_VERIFY_SUCCESS;
    }
    
    return kStatus_CSR_INT_VERIFY_FAILED;
}
