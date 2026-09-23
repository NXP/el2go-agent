/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <stddef.h>
#include <stdint.h>

#include "common/el2go_platform.h"
#include "common/el2go_status.h"
#include "plat_crypto_params.h"

struct el2go_platform_ctx {
    int dummy;
};

static struct el2go_platform_ctx g_stub_platform_ctx;

el2go_status_t el2go_platform_init(el2go_platform_ctx_t **platform_ctx)
{
    if (platform_ctx != NULL) {
        *platform_ctx = &g_stub_platform_ctx;
    }
    return EL2GO_STATUS_SUCCESS;
}

el2go_status_t el2go_platform_free(el2go_platform_ctx_t **platform_ctx)
{
    if (platform_ctx != NULL) {
        *platform_ctx = NULL;
    }
    return EL2GO_STATUS_SUCCESS;
}

el2go_status_t el2go_platform_get_uuid(el2go_platform_ctx_t *platform_ctx, uint8_t *buf,
                                       size_t buf_len, size_t *uuid_len)
{
    (void)platform_ctx;
    (void)buf;
    (void)buf_len;
    if (uuid_len != NULL) {
        *uuid_len = 0U;
    }
    return EL2GO_STATUS_SUCCESS;
}

el2go_cipher_list_t el2go_platform_get_cipher_suites(void)
{
    el2go_cipher_list_t empty = { NULL, 0U };
    return empty;
}

el2go_curve_list_t el2go_platform_get_curves(void)
{
    el2go_curve_list_t empty = { NULL, 0U };
    return empty;
}
