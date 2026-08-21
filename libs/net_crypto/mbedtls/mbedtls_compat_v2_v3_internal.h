/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef _MBEDTLS_COMPAT_V2_V3_INTERNAL_H
#define _MBEDTLS_COMPAT_V2_V3_INTERNAL_H

#include <mbedtls/version.h>

#if MBEDTLS_VERSION_MAJOR < 4

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

/**
 * @brief RNG context for mbedTLS 2.x and 3.x (internal definition).
 *
 * Shared between mbedtls_compat_v2_v3_common.c and mbedtls_compat_v2_v3_csr.c.
 * Not part of the public mbedtls_compat.h API.
 */
struct mbedtls_compat_rng_context {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
};

#endif /* MBEDTLS_VERSION_MAJOR < 4 */

#endif /* _MBEDTLS_COMPAT_V2_V3_INTERNAL_H */
