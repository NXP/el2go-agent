/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __EL2GO_OTA_TLS_H__
#define __EL2GO_OTA_TLS_H__

#include "common/el2go_status.h"
#include "common/el2go_platform.h"
#include "ota/el2go_ota_config.h"

/** @brief Forward declaration — defined only in el2go_ota_tls.c. */
typedef struct el2go_ota_tls_ctx el2go_ota_tls_ctx_t;

/**
 * @brief Allocate and configure a TLS context for mutual TLS.
 *
 * Uses the net_crypto abstraction layer to:
 *   1. Acquire client certificate and key ID via the credential provider
 *      selected at build time (EL2GO_OTA_CRED_PROVIDER).
 *   2. Allocate a new net_crypto context.
 *   3. Configure it with server hostname and port.
 *   4. Set the CA certificate chain for server verification.
 *   5. Set the client certificate for mutual TLS.
 *   6. Associate the device private key (key never leaves the keystore).
 *   7. Configure platform cipher suites and curves.
 *
 * Does NOT initialise the platform context — the caller (el2go_ota_init())
 * is responsible for calling el2go_platform_init() before this function and
 * el2go_platform_free() after el2go_ota_tls_deinit().
 *
 * Does NOT open a network connection — call el2go_ota_tls_connect() for that.
 *
 * @param[out] out_ctx       Receives allocated context pointer. Must not be NULL.
 * @param[in]  platform_ctx  Initialised platform context. Must not be NULL.
 * @param[in]  config        mTLS configuration.
 *
 * @retval EL2GO_STATUS_SUCCESS on success.
 * @retval EL2GO_STATUS_ALLOCATION_ERROR if context allocation fails.
 * @retval EL2GO_STATUS_NET_CRYPTO_CONFIG_FAILED if TLS configuration fails.
 * @retval EL2GO_STATUS_NET_CRYPTO_INVALID_CERT if certificate setup fails.
 * @retval EL2GO_STATUS_NET_CRYPTO_INVALID_KEY if key association fails.
 */
el2go_status_t el2go_ota_tls_init(el2go_ota_tls_ctx_t **out_ctx, el2go_platform_ctx_t *platform_ctx,
                                  const el2go_ota_mtls_config_t *config);

/**
 * @brief Open the mTLS connection to the OTA server.
 *
 * Calls net_crypto_connect() to perform the TLS handshake.
 * el2go_ota_tls_init() must have been called successfully first.
 *
 * @param[in] ctx  TLS context. Must not be NULL.
 *
 * @retval  EL2GO_STATUS_SUCCESS on success.
 * @retval  EL2GO_STATUS_NET_CRYPTO_HANDSHAKE_FAILED if handshake fails.
 * @retval  EL2GO_STATUS_NET_CRYPTO_INVALID_CERT if server cert verify fails.
 * @retval  EL2GO_STATUS_NET_CRYPTO_INVALID_KEY if client auth fails.
 */
el2go_status_t el2go_ota_tls_connect(el2go_ota_tls_ctx_t *ctx);

/**
 * @brief Close the mTLS connection gracefully.
 *
 * Calls net_crypto_disconnect() to send TLS close_notify and close the socket.
 * Safe to call when not connected (no-op).
 *
 * @param[in] ctx  TLS context. Must not be NULL.
 */
void el2go_ota_tls_disconnect(el2go_ota_tls_ctx_t *ctx);

/**
 * @brief Free all resources held by a TLS context.
 *
 * Calls net_crypto_free() to release the underlying context.
 * Safe to call with ctx == NULL (no-op).
 *
 * @param[in] ctx  Context to free.
 */
void el2go_ota_tls_deinit(el2go_ota_tls_ctx_t *ctx);

/**
 * @brief Write data over the TLS connection.
 *
 * Calls net_crypto_write() and retries on partial writes until all bytes
 * are sent or an unrecoverable error occurs.
 *
 * @param[in] ctx  TLS context. Must not be NULL.
 * @param[in] buf  Data to write. Must not be NULL.
 * @param[in] len  Number of bytes to write. Must be > 0.
 *
 * @retval EL2GO_STATUS_SUCCESS on success.
 * @retval EL2GO_STATUS_INVALID_PARAMETER if ctx, buf is NULL or len is 0.
 * @retval EL2GO_STATUS_FAILURE if the TLS send fails.
 */
el2go_status_t el2go_ota_tls_write(el2go_ota_tls_ctx_t *ctx, const uint8_t *buf, size_t len);

/**
 * @brief Read exactly len bytes over the TLS connection.
 *
 * Calls net_crypto_read() in a loop until exactly len bytes have been
 * received or an error/EOF occurs.
 *
 * @param[in]  ctx      TLS context. Must not be NULL.
 * @param[out] buf      Output buffer. Must not be NULL.
 * @param[in]  len      Exact number of bytes to read.
 * @param[out] out_len  Number of bytes actually read. Must not be NULL.
 *
 * @retval EL2GO_STATUS_SUCCESS on success (out_len == len).
 * @retval EL2GO_STATUS_INVALID_PARAMETER if ctx, buf, or out_len is NULL.
 * @retval EL2GO_STATUS_FAILURE if the connection is closed or read fails.
 */
el2go_status_t el2go_ota_tls_read(el2go_ota_tls_ctx_t *ctx, uint8_t *buf, size_t len,
                                  size_t *out_len);

#endif /* __EL2GO_OTA_TLS_H__ */
