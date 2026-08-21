/*
 * Copyright 2026 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _NET_CRYPTO_MBEDTLS_CRYPTO_PRIV_H
#define _NET_CRYPTO_MBEDTLS_CRYPTO_PRIV_H

#include <mbedtls/md.h>
#include "net_crypto.h"

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

#endif /* _NET_CRYPTO_MBEDTLS_CRYPTO_PRIV_H */
