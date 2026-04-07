/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "integrity_verifier.h"
#include "byte_utils.h"

// CRC-32 IEEE 802.3 polynomial 
#define CRC32_POLYNOMIAL_REFLECTED  0xEDB88320U
#define CRC32_INITIAL_VALUE         0xFFFFFFFFU
#define CRC32_FINAL_XOR             0xFFFFFFFFU

static csr_integrity_verifier_t crc32_calculate(const uint8_t *data, size_t size, uint32_t *crc)
{
    uint32_t crc_value = 0U;
    size_t i = 0U;
    uint8_t j = 0U;

    if (!data || !crc || !size)
    {
        return kStatus_CSR_INT_VERIFY_INVALID_ARG;
    }

    crc_value = CRC32_INITIAL_VALUE;

    for (i = 0U; i < size; i++)
    {
        crc_value ^= data[i];

        for (j = 0U; j < 8U; j++)
        {
            if ((crc_value & 1U) != 0U)
            {
                crc_value = (crc_value >> 1U) ^ CRC32_POLYNOMIAL_REFLECTED;
            }
            else
            {
                crc_value = crc_value >> 1U;
            }
        }
    }

    *crc = crc_value ^ CRC32_FINAL_XOR;

    return kStatus_CSR_INT_VERIFY_SUCCESS;
}

csr_integrity_verifier_t crc32_verify(const uint8_t *data, size_t size, const uint8_t* expected_crc)
{
    csr_integrity_verifier_t status = kStatus_CSR_INT_VERIFY_SUCCESS;
    uint32_t calculated_crc = 0U;
    uint32_t expected_crc_value = 0U;

    if (data == NULL || size == 0U || expected_crc == NULL)
    {
        status = kStatus_CSR_INT_VERIFY_INVALID_ARG;
        goto exit;
    }

    status = crc32_calculate(data, size, &calculated_crc);
    if (status != kStatus_CSR_INT_VERIFY_SUCCESS)
    {
         goto exit;
    }
    
    expected_crc_value = get_uint32_val(expected_crc);

    if (calculated_crc != expected_crc_value)
    {
        status = kStatus_CSR_INT_VERIFY_FAILED;
        goto exit;
    }

exit:
    return status;
}
