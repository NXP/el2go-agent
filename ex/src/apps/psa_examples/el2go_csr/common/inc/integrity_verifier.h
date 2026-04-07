/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef _INTEGRITY_VERIFIER_H_
#define _INTEGRITY_VERIFIER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "el2go_csr_osal_types.h"

typedef enum _csr_integrity_verifier
{
    kStatus_CSR_INT_VERIFY_SUCCESS             = 0x100A23BEU,
    kStatus_CSR_INT_VERIFY_INVALID_ARG         = 0x187B33BFU,
    kStatus_CSR_INT_VERIFY_FAILED              = 0xFDD7653AU,
} csr_integrity_verifier_t; 

/*! @brief Verify data integrity using CRC32 checksum.
 * 
 * @param[in] data Pointer to the data buffer to be verified.
 * @param[in] size Size of the data buffer in bytes.
 * @param[in] expected_crc Pointer to the expected CRC32 value for verification.
 * @retval kStatus_CSR_INT_VERIFY_SUCCESS: Memory read operation successful.
*/
csr_integrity_verifier_t 
crc32_verify(const uint8_t *data, size_t size, const uint8_t* expected_crc);

#ifdef __cplusplus
}
#endif

#endif /* _INTEGRITY_VERIFIER_H_ */
