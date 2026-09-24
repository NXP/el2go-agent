/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <stddef.h>
#include <stdint.h>

#include "common/el2go_status.h"
#include "common/el2go_platform.h"
#include "ota/el2go_ota_config.h"
#include "el2go_ota_tls.h"
#include "el2go_ota_transport.h"
#include "mock_transport.h"

/* Stable non-NULL sentinel; never dereferenced while the wraps are active. */
static uint8_t s_tls_stub_sentinel;

el2go_status_t __wrap_el2go_ota_tls_init(el2go_ota_tls_ctx_t **out_ctx,
                                         el2go_platform_ctx_t *platform_ctx,
                                         const el2go_ota_mtls_config_t *config)
{
    (void)platform_ctx;
    (void)config;

    if (out_ctx == NULL) {
        return EL2GO_STATUS_INVALID_PARAMETER;
    }

    *out_ctx = (el2go_ota_tls_ctx_t *)(void *)&s_tls_stub_sentinel;
    return EL2GO_STATUS_SUCCESS;
}

el2go_status_t __wrap_el2go_ota_tls_connect(el2go_ota_tls_ctx_t *ctx)
{
    (void)ctx;
    return EL2GO_STATUS_SUCCESS;
}

void __wrap_el2go_ota_tls_disconnect(el2go_ota_tls_ctx_t *ctx)
{
    (void)ctx;
}

void __wrap_el2go_ota_tls_deinit(el2go_ota_tls_ctx_t *ctx)
{
    (void)ctx;
}

/* Replaces both the weak stub and the strong gRPC definition via --wrap. */
el2go_ota_status_t __wrap_el2go_ota_transport_init(el2go_ota_transport_t *t,
                                                   el2go_ota_tls_ctx_t *tls_ctx,
                                                   const char *hostname)
{
    (void)tls_ctx;
    (void)hostname;

    return mock_transport_init(t);
}
