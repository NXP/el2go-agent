/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
*/

#include "el2go_csr_pal_util.h"

mbedtls_md_type_t get_msg_digest_algo(void)
{
    return MBEDTLS_MD_SHA256;
}