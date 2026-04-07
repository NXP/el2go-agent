/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef _EL2GO_BYTE_UTILS_H_
#define _EL2GO_BYTE_UTILS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "el2go_csr_osal_types.h"

/*! @brief Extract 16-bit big-endian value from byte buffer.
 * 
 * @param[in] input Pointer to buffer containing 2 bytes in big-endian order.
 * @return 16-bit unsigned integer value.
 */
static inline uint16_t get_uint16_val(const uint8_t *input)
{
    return (uint16_t)((input[0] << 8U) | input[1]);
}

/*! @brief Extract 32-bit big-endian value from byte buffer.
 * 
 * @param[in] input Pointer to buffer containing 4 bytes in big-endian order.
 * @return 32-bit unsigned integer value.
 */
static inline uint32_t get_uint32_val(const uint8_t *input)
{
    return ((uint32_t)input[0] << 24U) |
           ((uint32_t)input[1] << 16U) |
           ((uint32_t)input[2] << 8U)  |
           ((uint32_t)input[3]);
}

/*! @brief Store 16-bit value to byte buffer in big-endian order.
 * 
 * @param[out] output Pointer to destination buffer (minimum 2 bytes).
 * @param[in] value 16-bit value to store.
 */
static inline void put_uint16_val(uint8_t *output, uint16_t value)
{
    output[0] = (uint8_t)(value >> 8U);
    output[1] = (uint8_t)(value);
}

/*! @brief Store 32-bit value to byte buffer in big-endian order.
 * 
 * @param[out] output Pointer to destination buffer (minimum 4 bytes).
 * @param[in] value 32-bit value to store.
 */
static inline void put_uint32_val(uint8_t *output, uint32_t value)
{
    output[0] = (uint8_t)(value >> 24U);
    output[1] = (uint8_t)(value >> 16U);
    output[2] = (uint8_t)(value >> 8U);
    output[3] = (uint8_t)(value);
}

#ifdef __cplusplus
}
#endif

#endif /* _EL2GO_BYTE_UTILS_H_ */
