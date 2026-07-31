/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "compiler.h"
#include "el2go_ota_transport.h"

__weak el2go_ota_status_t el2go_ota_transport_init(el2go_ota_transport_t *t,
                                                   el2go_ota_tls_ctx_t *tls_ctx,
                                                   const char *hostname)
{
    (void)t;
    (void)tls_ctx;
    (void)hostname;
    return EL2GO_OTA_ERROR_INTERNAL;
}
