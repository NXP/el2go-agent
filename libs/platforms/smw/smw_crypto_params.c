/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "builtin_macros.h"

#include "plat_crypto_params.h"

/* ========================================================================== */
/* Cipher suites                                                               */
/* ========================================================================== */

/**
 * @brief Cipher suites supported by the SMW platform in preferred order.
 *
 * @note TODO: Read these capabilities from a configuration file.
 */
static const el2go_cipher_suite_t cipher_suites[] = {
    /* TLS 1.3 - cipher suites first */
    EL2GO_CIPHER_TLS1_3_CHACHA20_POLY1305_SHA256,
    EL2GO_CIPHER_TLS1_3_AES_256_GCM_SHA384,
    EL2GO_CIPHER_TLS1_3_AES_128_GCM_SHA256,

    /* TLS 1.2 - GCM cipher suites */
    EL2GO_CIPHER_ECDHE_ECDSA_AES256_GCM_SHA384,
    EL2GO_CIPHER_ECDH_ECDSA_AES256_GCM_SHA384,
    EL2GO_CIPHER_ECDHE_RSA_AES256_GCM_SHA384,
    EL2GO_CIPHER_ECDH_RSA_AES256_GCM_SHA384,

    /* TLS 1.2 - CBC cipher suites last */
    EL2GO_CIPHER_ECDHE_ECDSA_AES256_CBC_SHA384,
    EL2GO_CIPHER_ECDH_ECDSA_AES256_CBC_SHA384,
    EL2GO_CIPHER_ECDHE_RSA_AES256_CBC_SHA384,
    EL2GO_CIPHER_ECDH_RSA_AES256_CBC_SHA384,
};

el2go_cipher_list_t el2go_platform_get_cipher_suites(void)
{
    el2go_cipher_list_t list = { 0 };

    list.suites = cipher_suites;
    list.count = ARRAY_SIZE(cipher_suites);

    return list;
}

/* ========================================================================== */
/* Curves                                                                      */
/* ========================================================================== */

/**
 * @brief Curves supported by the SMW platform.
 *
 * @note TODO: Read these capabilities from a configuration file.
 */
static const el2go_curve_id_t curves[] = {
    EL2GO_CURVE_SECP256R1,
    EL2GO_CURVE_SECP384R1,
    EL2GO_CURVE_SECP521R1,
};

el2go_curve_list_t el2go_platform_get_curves(void)
{
    el2go_curve_list_t list = { 0 };

    list.curves = curves;
    list.count = ARRAY_SIZE(curves);

    return list;
}
