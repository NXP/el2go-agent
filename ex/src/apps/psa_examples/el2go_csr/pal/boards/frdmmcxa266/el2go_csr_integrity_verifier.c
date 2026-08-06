/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "el2go_csr_integrity_verifier.h"
#include "el2go_csr_console.h"
#include "fsl_crc.h"
#include "byte_utils.h"

#define CRC32_POLYNOMIAL    (0x04C11DB7U) 
#define CRC32_SEED_VALUE    (0xFFFFFFFFU)

// The MCXA266 supports only one instance of CRC module.
// See the CRC chapter of the Reference Manual, linked
// in the board specific README.md
#define CRC_INSTANCE_NR     (0U) 

static csr_integrity_verifier_t crc32_verify_builtin(uint8_t *data, size_t size, const uint8_t* expected_crc)
{
    uint32_t calculated_crc = 0U;
	uint32_t expected_crc_value = 0U;
	
    CRC_Type *crc_module = (CRC_Type*)((uint32_t)CRC0_BASE + (sizeof(CRC_Type)*CRC_INSTANCE_NR)); 
    crc_config_t config = {
		.polynomial         = CRC32_POLYNOMIAL,
		.seed               = CRC32_SEED_VALUE,
		.reflectIn          = true,
		.reflectOut         = true,
		.complementChecksum = true,
		.crcBits            = kCrcBits32,
		.crcResult          = kCrcFinalChecksum
	};
		
    if (!data || !expected_crc || !size)
    {
        return kStatus_CSR_INT_VERIFY_INVALID_ARG;
    }

    CRC_Init(crc_module, &config);
	CRC_WriteData(crc_module, data, size); 
	
    calculated_crc = CRC_Get32bitResult(crc_module);
	expected_crc_value = get_uint32_val(expected_crc); 
		
	LOG(LOG_DEBUG, "Computed CRC32: 0x%08X, Expected CRC32: 0x%08X\r\n", calculated_crc, expected_crc_value);
    if (calculated_crc == expected_crc_value)
    {
        return kStatus_CSR_INT_VERIFY_SUCCESS;
    }
    
    return kStatus_CSR_INT_VERIFY_FAILED;
}

csr_integrity_verifier_t 
verify_integrity(uint8_t *data, size_t size, const uint8_t *checksum, integrity_algorithms_t algo)
{
    switch (algo)
    {
        case CRC_32:
			LOG(LOG_TRACE, "Verifying data integrity using CRC-32 algorithm\r\n");
            return crc32_verify_builtin(data, size, checksum);
        break; 

        default:
            LOG(LOG_TRACE, "Unsupported integrity algorithm: %d\r\n", algo);
        break;
    }

    return kStatus_CSR_INT_VERIFY_FAILED;
}

