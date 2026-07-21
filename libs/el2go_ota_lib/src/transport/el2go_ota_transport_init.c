/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "transport/el2go_ota_transport.h"
#include "transport/grpc/el2go_ota_grpc.h"

el2go_ota_status_t el2go_ota_transport_init(el2go_ota_transport_t *t, el2go_ota_tls_ctx_t *tls_ctx,
                                            const char *hostname)
{
    return el2go_ota_transport_grpc_init(t, tls_ctx, hostname);
}
