/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef _CRC_SW_UTIL_H_
#define _CRC_SW_UTIL_H_

#include "el2go_csr_integrity_verifier.h"
#include "byte_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

/*! @brief Calculat CRC32 checksum of data using software implementation.
 * 
 * @param[in] data: Pointer to data buffer for which CRC32 checksum will be calculated.
 * @param[in] size: Size of the data buffer in bytes.
 * @param[in] expected_crc: Pointer to buffer containing expected CRC32 value (4 bytes in big-endian order).
 * @retval kStatus_CSR_INT_VERIFY_SUCCESS: CRC32 checksum matches expected value.
*/
csr_integrity_verifier_t 
crc32_calculate_sw(uint8_t *data, size_t size, const uint8_t* expected_crc);


#ifdef __cplusplus
}
#endif

#endif /* _CRC_SW_UTIL_H_ */