/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __EL2GO_OTA_LIB_H__
#define __EL2GO_OTA_LIB_H__

#include <stdbool.h>

#include "ota/el2go_ota_config.h"

/**
 * @brief Status codes returned by EL2GO OTA Library functions.
 */
typedef enum {
    EL2GO_OTA_SUCCESS = 0,             /**< Operation succeeded. */
    EL2GO_OTA_ERROR_INVALID_PARAM = 1, /**< NULL or invalid parameter. */
    EL2GO_OTA_ERROR_MEMORY = 2,        /**< Heap allocation failed. */
    EL2GO_OTA_ERROR_AUTH = 3,          /**< Client authentication failed. */
    EL2GO_OTA_ERROR_NETWORK = 4,       /**< TCP connection failed. */
    EL2GO_OTA_ERROR_TLS_HANDSHAKE = 5, /**< TLS handshake failed. */
    EL2GO_OTA_ERROR_CERT_VERIFY = 6,   /**< Server certificate verification failed. */
} el2go_ota_status_t;

/**
 * @brief Opaque EL2GO OTA Library context.
 *
 * Allocated by el2go_ota_init(), freed by el2go_ota_cleanup().
 * Callers must not inspect or modify the internals.
 */
typedef struct el2go_ota_ctx el2go_ota_ctx_t;

/**
 * @brief Allocate a context and prepare the mTLS security layer.
 *
 * Retrieves client credentials from the platform keystore using the object
 * IDs in config, configures the TLS context via the net_crypto abstraction
 * layer, and validates that credentials are present and well-formed.
 *
 * Does NOT open a network connection — call el2go_ota_connect() for that.
 *
 * @param[out] ctx     Receives the allocated context pointer. Must not be NULL.
 *                     On failure *ctx is set to NULL.
 * @param[in]  config  mTLS configuration. Must not be NULL.
 *                     config->hostname must not be NULL.
 *                     config->port must not be 0.
 *                     config->server_ca_chain must not be NULL and
 *                     config->server_ca_chain_size must be > 0.
 *
 * @retval EL2GO_OTA_SUCCESS on success.
 * @retval EL2GO_OTA_ERROR_INVALID_PARAM if ctx or config is NULL, or any
 *         required config field is missing or invalid (including port == 0).
 * @retval EL2GO_OTA_ERROR_MEMORY if context allocation fails.
 * @retval EL2GO_OTA_ERROR_TLS_HANDSHAKE if TLS context configuration fails.
 * @retval EL2GO_OTA_ERROR_CERT_VERIFY if client credentials cannot be
 *         loaded from the keystore.
 * @retval EL2GO_OTA_ERROR_AUTH if the client private key cannot be
 *         associated.
 */
el2go_ota_status_t el2go_ota_init(el2go_ota_ctx_t **ctx, const el2go_ota_mtls_config_t *config);

/**
 * @brief Open an mTLS connection to the OTA server.
 *
 * Performs the full TLS handshake:
 * -# TCP connect to hostname:port (respects connection_timeout_ms).
 * -# Server presents certificate, verified against server_ca_chain
 * -# Server requests client certificate (CertificateRequest).
 * -# Client presents certificate (from client_cert_object_id).
 * -# Client signs CertificateVerify using private key — signing happens
 *    inside the secure element; the key never leaves the keystore.
 * -# Server verifies signature — mTLS connection established.
 *
 * @param[in] ctx  Initialised context from el2go_ota_init(). Must not be NULL.
 *
 * If the context is already connected this function is a no-op and returns
 * EL2GO_OTA_SUCCESS immediately without performing a second handshake.
 *
 * @retval EL2GO_OTA_SUCCESS on success (including when already connected).
 * @retval EL2GO_OTA_ERROR_INVALID_PARAM if ctx is NULL.
 * @retval EL2GO_OTA_ERROR_NETWORK if TCP connection fails.
 * @retval EL2GO_OTA_ERROR_TLS_HANDSHAKE if TLS handshake fails.
 * @retval EL2GO_OTA_ERROR_CERT_VERIFY if server certificate verification
 *         fails.
 * @retval EL2GO_OTA_ERROR_AUTH if client authentication fails.
 */
el2go_ota_status_t el2go_ota_connect(el2go_ota_ctx_t *ctx);

/**
 * @brief Close the mTLS connection gracefully.
 *
 * Sends a TLS close_notify alert and closes the TCP socket. The context
 * remains valid — call el2go_ota_connect() to reconnect. Safe to call when
 * not connected (no-op).
 *
 * @param[in] ctx  Context. Must not be NULL.
 *
 * @retval EL2GO_OTA_SUCCESS on success.
 * @retval EL2GO_OTA_ERROR_INVALID_PARAM if ctx is NULL.
 */
el2go_ota_status_t el2go_ota_disconnect(el2go_ota_ctx_t *ctx);

/**
 * @brief Disconnect and free all resources held by the context.
 *
 * Disconnects if connected, releases the TLS context and all heap
 * allocations, then sets *ctx to NULL. Safe to call with *ctx == NULL (no-op).
 *
 * @param[in,out] ctx  Pointer to context pointer. Must not be NULL.
 */
void el2go_ota_cleanup(el2go_ota_ctx_t **ctx);

/**
 * @brief Query whether an mTLS connection is currently open.
 *
 * @param[in] ctx  Context. May be NULL (returns false).
 *
 * @retval true  if connected.
 * @retval false if not connected, not initialised, or ctx is NULL.
 */
bool el2go_ota_is_connected(const el2go_ota_ctx_t *ctx);

/**
 * @brief Retrieve a human-readable description of the last error.
 *
 * The returned string is owned by the library and remains valid until the
 * next API call on the same context.
 *
 * @param[in] ctx  Context. May be NULL (returns a generic message).
 *
 * @retval Null-terminated error string. Never returns NULL.
 */
const char *el2go_ota_get_last_error(const el2go_ota_ctx_t *ctx);

#endif /* __EL2GO_OTA_LIB_H__ */
