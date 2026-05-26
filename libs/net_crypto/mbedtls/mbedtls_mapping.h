/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2026 NXP
 */

#ifndef __MBEDTLS_MAPPING_H__
#define __MBEDTLS_MAPPING_H__

#include <mbedtls/ssl.h>
#include "plat_crypto_params.h"
#include "builtin_macros.h"

/**
 * @defgroup mbedtls_int mbedTLS Internal API
 * @brief Internal mbedTLS interface for use within the net_crypto module.
 * @{
 */

/**
 * @brief Convert platform cipher suite list to mbedTLS format.
 *
 * Fills a caller-allocated array of mbedTLS cipher suite IDs terminated by 0.
 * Cipher suites not supported by the current mbedTLS version are skipped.
 *
 * @param[in]  platform_list    Platform cipher suite list.
 * @param[out] mbedtls_ciphers  Output array for mbedTLS cipher suite IDs (caller allocated).
 * @param[in]  max_ciphers      Maximum number of cipher suites in output array.
 *
 * @return Number of cipher suites converted on success, negative error code on failure.
 */
int cipher_list_to_mbedtls(const el2go_cipher_list_t *platform_list,
			   int *mbedtls_ciphers, size_t max_ciphers);

/**
 * @brief Convert platform curve list to mbedTLS curve array.
 *
 * @param[in]  curve_list     Platform curve list.
 * @param[out] mbedtls_curves Output array for mbedTLS curves (caller allocated).
 * @param[in]  max_curves     Maximum number of curves the output array can hold.
 *
 * @return Number of curves converted on success, negative error code on failure.
 */
int curves_to_mbedtls(const el2go_curve_list_t *curve_list,
		      void *mbedtls_curves, size_t max_curves);

/** @} */ /* end of mbedtls_int */

#endif /* __MBEDTLS_MAPPING_H__ */
