/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "plat_crypto_params.h"
#include "compiler.h"

__weak el2go_cipher_list_t el2go_platform_get_cipher_suites(void)
{
    el2go_cipher_list_t list = { .suites = NULL, .count = 0 };

    return list;
}

__weak el2go_curve_list_t el2go_platform_get_curves(void)
{
    el2go_curve_list_t list = { .curves = NULL, .count = 0 };

    return list;
}
