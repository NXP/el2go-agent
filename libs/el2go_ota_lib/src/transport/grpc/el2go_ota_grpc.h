/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/*
 *  EL2GO OTA Library -- gRPC/HTTP2 transport backend
 *
 * Implements el2go_ota_transport_t using gRPC over HTTP/2 over TLS.
 * The factory allocates a grpc_ctx_t as impl_ctx and sets up the
 * HTTP/2 connection preface + SETTINGS exchange on the first send().
 */

#ifndef EL2GO_OTA_GRPC_H
#define EL2GO_OTA_GRPC_H

#include "transport/el2go_ota_transport.h"
#include "el2go_ota_tls.h"

/**
 * @brief Initialise a transport instance backed by gRPC over HTTP/2 over TLS.
 *
 * Allocates a grpc_ctx_t as impl_ctx and fills t->send, t->recv, t->deinit.
 * The caller is responsible for keeping tls_ctx alive for the lifetime of t.
 * Call t->deinit(&t) (or el2go_ota_disconnect()) to free the context.
 *
 * @param[out] t         Transport instance to initialise. Must not be NULL.
 * @param[in]  tls_ctx   Connected TLS context. Must not be NULL.
 * @param[in]  hostname  Server hostname for the HTTP/2 :authority header.
 *                       Must not be NULL. Pointer must remain valid for
 *                       the lifetime of the transport.
 * @return EL2GO_OTA_SUCCESS on success.
 * @return EL2GO_OTA_ERROR_INVALID_PARAM if any argument is NULL.
 * @return EL2GO_OTA_ERROR_INTERNAL if context allocation fails.
 */
el2go_ota_status_t el2go_ota_transport_grpc_init(el2go_ota_transport_t *t,
                                                 el2go_ota_tls_ctx_t *tls_ctx,
                                                 const char *hostname);

#endif /* EL2GO_OTA_GRPC_H */
