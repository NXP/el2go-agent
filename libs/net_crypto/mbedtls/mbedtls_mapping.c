/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <mbedtls/ssl_ciphersuites.h>

#include "builtin_macros.h"
#include "debug.h"
#include "compiler.h"

#include "mbedtls_mapping.h"
#include "mbedtls_compat.h"

/* ========================================================================== */
/* Cipher suite mapping                                                       */
/* ========================================================================== */

int cipher_list_to_mbedtls(const el2go_cipher_list_t *platform_list, int *mbedtls_ciphers,
                           size_t max_ciphers)
{
    size_t i = 0;
    int output_count = 0;
    size_t required_size = 0;
    int __maybe_unused mbedtls_id = 0;

    if (!platform_list || !mbedtls_ciphers || max_ciphers == 0 || !platform_list->suites)
        return -1;

    /* Verify compat mapping is in sync with el2go_cipher_suite_t enum */
    if (mbedtls_compat_cipher_suite_map_size() != EL2GO_CIPHER_MAX) {
        EL2GO_DBG_PRINTF(ERROR, "cipher_suite_map (%zu) does not match (%d)\n",
                         mbedtls_compat_cipher_suite_map_size(), EL2GO_CIPHER_MAX);
        EL2GO_DBG_PRINTF(ERROR, "Arrays are out of sync\n");
        return -1;
    }

    if (ADD_OVERFLOW(platform_list->count, 1, &required_size)) {
        EL2GO_DBG_PRINTF(ERROR, "platform_list->count (%zu) too large\n", platform_list->count);
        return -1;
    }

    if (required_size > max_ciphers) {
        EL2GO_DBG_PRINTF(ERROR, "max_ciphers (%zu) too small for %zu\n", max_ciphers,
                         platform_list->count);
        return -1;
    }

    for (i = 0; i < platform_list->count; i++) {
        mbedtls_id = mbedtls_compat_cipher_suite_to_id(platform_list->suites[i]);

        if (mbedtls_id == 0) {
            EL2GO_DBG_PRINTF(DEBUG, "Cipher suite %d not supported, skipping\n",
                             platform_list->suites[i]);
            continue;
        }

        mbedtls_ciphers[output_count] = mbedtls_id;
        if (INC_OVERFLOW(output_count, 1))
            return -1;
    }

    /* Terminate the list with 0 (required by mbedTLS) */
    mbedtls_ciphers[output_count] = 0;

    return output_count;
}

int curves_to_mbedtls(const el2go_curve_list_t *curve_list, void *mbedtls_curves, size_t max_curves)
{
    size_t i = 0;
    int output_count = 0;
    const size_t map_size = mbedtls_compat_curve_map_size();
    size_t required_size = 0;
    mbedtls_compat_group_id_t *curves = (mbedtls_compat_group_id_t *)mbedtls_curves;
    el2go_curve_id_t __maybe_unused platform_curve = 0;

    if (!curve_list || !curve_list->curves || curve_list->count == 0 || !mbedtls_curves ||
        max_curves == 0)
        return -1;

    /* Verify curve_map is in sync with el2go_curve_id_t enum */
    if (map_size != EL2GO_CURVE_MAX) {
        EL2GO_DBG_PRINTF(ERROR, "curve_map (%zu) does not match (%d)\n", map_size, EL2GO_CURVE_MAX);
        EL2GO_DBG_PRINTF(ERROR, "Arrays are out of sync\n");
        return -1;
    }

    if (ADD_OVERFLOW(curve_list->count, 1, &required_size)) {
        EL2GO_DBG_PRINTF(ERROR, "curve_list->count (%zu) too large\n", curve_list->count);
        return -1;
    }

    if (required_size > max_curves) {
        EL2GO_DBG_PRINTF(ERROR, "max_curves (%zu) too small for %zu\n", max_curves,
                         curve_list->count);
        return -1;
    }

    /* Convert each platform curve to mbedTLS format */
    for (i = 0; i < curve_list->count; i++) {
        platform_curve = curve_list->curves[i];

        /* Validate curve ID is within range */
        if (platform_curve >= map_size) {
            EL2GO_DBG_PRINTF(ERROR, "Curve ID %d out of range (%zu) - ", platform_curve, map_size);
            EL2GO_DBG_PRINTF(ERROR, "Arrays are out of sync\n");
            return -1;
        }

        mbedtls_compat_group_id_t group_id = mbedtls_compat_curve_to_id(platform_curve);

        /* Skip curves not supported by this mbedTLS version */
        if (group_id == MBEDTLS_COMPAT_CURVE_SENTINEL) {
            EL2GO_DBG_PRINTF(INFO, "Curve ID %d not supported by this mbedTLS version, skipping\n",
                             platform_curve);
            continue;
        }

        /* Direct lookup via compat layer - no search needed */
        curves[output_count] = group_id;
        if (INC_OVERFLOW(output_count, 1))
            return -1;
    }

    /* Terminate the list with sentinel value */
    curves[output_count] = MBEDTLS_COMPAT_CURVE_SENTINEL;

    return output_count;
}
