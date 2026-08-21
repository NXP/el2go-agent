/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __MBEDTLS_MAPPING_MD_H__
#define __MBEDTLS_MAPPING_MD_H__

#include <mbedtls/md.h>
#include "net_crypto.h"

/**
 * @brief Map platform message-digest algorithm to mbedTLS md_type_t.
 *
 * @param[in] alg  Platform-agnostic hash algorithm identifier.
 *
 * @return Corresponding mbedtls_md_type_t value.
 */
static inline mbedtls_md_type_t map_md_alg(net_crypto_md_alg_t alg)
{
    switch (alg) {
    case NET_CRYPTO_MD_SHA384:
        return MBEDTLS_MD_SHA384;
    case NET_CRYPTO_MD_SHA512:
        return MBEDTLS_MD_SHA512;
    case NET_CRYPTO_MD_SHA256:
    default:
        return MBEDTLS_MD_SHA256;
    }
}

#endif /* __MBEDTLS_MAPPING_MD_H__ */
