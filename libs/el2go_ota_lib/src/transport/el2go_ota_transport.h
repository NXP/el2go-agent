/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef EL2GO_OTA_TRANSPORT_H
#define EL2GO_OTA_TRANSPORT_H

#include <stdint.h>
#include <stddef.h>

#include "ota/el2go_ota_lib.h"

/** Forward declaration -- defined below. */
typedef struct el2go_ota_transport el2go_ota_transport_t;

/**
 * @brief Send one framed message over the transport.
 *
 * @param[in] t            Transport instance (contains impl_ctx).
 * @param[in] method_path  RPC method path (e.g. "/pkg.Svc/Method"). Must not be
 *                         NULL. Ignored by backends that do not use HTTP/2 routing.
 * @param[in] msg          Serialized protobuf payload. Must not be NULL.
 * @param[in] msg_len      Length of msg in bytes. Must be > 0.
 * @return EL2GO_OTA_SUCCESS on success.
 * @return EL2GO_OTA_ERROR_INVALID_PARAM on bad arguments.
 * @return EL2GO_OTA_ERROR_NETWORK on I/O failure.
 */
typedef el2go_ota_status_t (*el2go_ota_transport_send_fn)(el2go_ota_transport_t *t,
                                                          const char *method_path,
                                                          const uint8_t *msg, size_t msg_len);

/**
 * @brief Receive one framed message from the transport.
 *
 * @param[in]  t        Transport instance (contains impl_ctx).
 * @param[out] buf      Output buffer. Must not be NULL.
 * @param[in]  buf_len  Size of buf in bytes.
 * @param[out] out_len  Number of payload bytes written. Must not be NULL.
 * @return EL2GO_OTA_SUCCESS on success.
 * @return EL2GO_OTA_ERROR_INVALID_PARAM on bad arguments.
 * @return EL2GO_OTA_ERROR_NETWORK on I/O failure or connection closed.
 * @return EL2GO_OTA_ERROR_INTERNAL if payload exceeds buf_len.
 */
typedef el2go_ota_status_t (*el2go_ota_transport_recv_fn)(el2go_ota_transport_t *t, uint8_t *buf,
                                                          size_t buf_len, size_t *out_len);

/**
 * @brief Release all resources owned by the transport impl_ctx.
 *
 * Called once by el2go_ota_disconnect(). May be NULL if the backend has no
 * heap-allocated state.
 *
 * @param[in] t  Transport instance. Must not be NULL.
 */
typedef void (*el2go_ota_transport_deinit_fn)(el2go_ota_transport_t *t);

/**
 * @brief Abstract transport instance.
 *
 * Initialised by a backend-specific factory via el2go_ota_transport_init().
 * The download engine calls send/recv through the function pointers and never
 * references any backend-specific header.
 */
struct el2go_ota_transport {
    el2go_ota_transport_send_fn send;     /**< Send one framed request. */
    el2go_ota_transport_recv_fn recv;     /**< Receive one framed response. */
    el2go_ota_transport_deinit_fn deinit; /**< Free backend state. May be NULL. */
    void *impl_ctx;                       /**< Opaque backend context. */
};

/** Forward declaration of the TLS context type (defined in el2go_ota_tls.h). */
typedef struct el2go_ota_tls_ctx el2go_ota_tls_ctx_t;

/**
 * @brief Initialize the transport vtable for the compiled-in backend.
 *
 * This function is provided by the backend-specific translation unit selected
 * by EL2GO_OTA_TRANSPORT_BACKEND (e.g. src/transport/el2go_ota_transport_init.c
 * for the grpc backend). Callers never need to include a backend-specific header.
 *
 * @param[out] t         Transport struct to initialise. Must not be NULL.
 * @param[in]  tls_ctx   Connected TLS context. Must not be NULL.
 * @param[in]  hostname  Server hostname used in the HTTP/2 :authority header.
 *                       Pointer must remain valid for the transport lifetime.
 *                       May be NULL for backends that do not need it.
 * @return EL2GO_OTA_SUCCESS on success.
 */
el2go_ota_status_t el2go_ota_transport_init(el2go_ota_transport_t *t, el2go_ota_tls_ctx_t *tls_ctx,
                                            const char *hostname);

#endif /* EL2GO_OTA_TRANSPORT_H */
