/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __MBEDTLS_MAPPING_H__
#define __MBEDTLS_MAPPING_H__

/** @defgroup mbedtls_mapping mbedTLS Cipher and Curve Mapping
 * @brief Internal helpers for converting platform crypto parameter lists to mbedTLS types.
 * @{
 */

#include <stddef.h>

#include "plat_crypto_params.h"

/**
 * @brief Convert a platform cipher suite list to an array of mbedTLS cipher IDs.
 *
 * The output array is NULL-terminated (0 appended after the last entry).
 *
 * @param[in]  platform_list   Platform cipher suite list.
 * @param[out] mbedtls_ciphers Output array of mbedTLS cipher IDs.
 * @param[in]  max_ciphers     Size of output array (must include room for NULL terminator).
 *
 * @return Number of entries written (excluding terminator), or -1 on error.
 */
int cipher_list_to_mbedtls(const el2go_cipher_list_t *platform_list, int *mbedtls_ciphers,
                           size_t max_ciphers);

/**
 * @brief Convert a platform curve list to an array of mbedTLS group IDs.
 *
 * The output array is sentinel-terminated (MBEDTLS_COMPAT_CURVE_SENTINEL appended).
 * The element type is version-specific (mbedtls_compat_group_id_t); the caller
 * passes a void pointer to avoid pulling in the compat TLS header here.
 *
 * @param[in]  curve_list    Platform curve list.
 * @param[out] mbedtls_curves Output array (mbedtls_compat_group_id_t[]).
 * @param[in]  max_curves    Size of output array (must include room for sentinel).
 *
 * @return Number of entries written (excluding sentinel), or -1 on error.
 */
int curves_to_mbedtls(const el2go_curve_list_t *curve_list, void *mbedtls_curves,
                      size_t max_curves);

/** @} */ /* end of mbedtls_mapping */

#endif /* __MBEDTLS_MAPPING_H__ */
