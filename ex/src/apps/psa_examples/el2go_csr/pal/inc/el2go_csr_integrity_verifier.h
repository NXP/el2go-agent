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

typedef enum _integrity_algorithms
{
    INIT = 0x0,
    CRC_32 = 0x1,
    // Add here further algo's if needed. 
    // e.g. HMAC_SHA256 = 0x2, <-- count chronologically up!
    
    NR_OF_ALGOS // DO NOT insert any new entry below this line!
} integrity_algorithms_t;

/*! @brief Calculate data integrity checksum using specified algorithm.
 *  
 * @param[in] data Pointer to the data buffer to be verified.
 * @param[in] size Size of the data buffer in bytes.
 * @param[in] checksum Pointer to the expected checksum value for verification.
 * @param[in] algo Integrity algorithm to use for verification.
 * @retval kStatus_CSR_INT_VERIFY_SUCCESS: Data integrity verification successful.
*/
csr_integrity_verifier_t 
verify_integrity(uint8_t *data, size_t size, const uint8_t *checksum, integrity_algorithms_t algo);

#ifdef __cplusplus
}
#endif

#endif /* _INTEGRITY_VERIFIER_H_ */
