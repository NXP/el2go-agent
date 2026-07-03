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
 * @brief Cipher suites supported by the ELS PKC platform in preferred order.
 *
 * @note TODO: Read these capabilities from a configuration file.
 */
static const el2go_cipher_suite_t cipher_suites[] = {
    /* P-256 key — CBC then GCM, SHA-256 */
    EL2GO_CIPHER_ECDHE_ECDSA_AES128_CBC_SHA256,
    EL2GO_CIPHER_ECDHE_RSA_AES128_CBC_SHA256,
    EL2GO_CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256,
    EL2GO_CIPHER_ECDHE_RSA_AES128_GCM_SHA256,

    /* P-384 key — CBC then GCM, SHA-384 */
    EL2GO_CIPHER_ECDHE_ECDSA_AES256_CBC_SHA384,
    EL2GO_CIPHER_ECDHE_RSA_AES256_CBC_SHA384,
    EL2GO_CIPHER_ECDHE_ECDSA_AES256_GCM_SHA384,
    EL2GO_CIPHER_ECDHE_RSA_AES256_GCM_SHA384,
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
 * @brief Elliptic curves supported by the ELS PKC platform on RW61x.
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
