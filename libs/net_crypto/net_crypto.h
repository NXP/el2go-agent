/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2026 NXP
 */

#ifndef __NET_CRYPTO_H__
#define __NET_CRYPTO_H__

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "common/el2go_status.h"
#include "plat_crypto_params.h"

/**
 * @defgroup net_crypto Network Crypto
 * @brief Network crypto interface for SSL/TLS connections.
 * @{
 */

/** @brief Opaque network crypto connection context. */
typedef struct net_crypto_ctx net_crypto_ctx_t;

/**
 * @brief Network crypto connection configuration.
 */
typedef struct {
	const char *hostname; /**< Server hostname or IP address. */
	uint16_t port; /**< Server port number. */
} net_crypto_config_t;

/**
 * @brief Initialize the network crypto library.
 *
 * Performs any high-level initialization (like OpenSSL provider setup).
 *
 * @return @ref el2go_status_t value, @ref EL2GO_STATUS_SUCCESS on success.
 */
el2go_status_t net_crypto_init(void);

/**
 * @brief Parse and set CA certificates for server verification.
 *
 * @param[in] ctx          Network crypto context.
 * @param[in] ca_cert_pem  DER-encoded CA certificate(s).
 * @param[in] ca_cert_len  Length of CA certificate data.
 *
 * @return @ref el2go_status_t value, @ref EL2GO_STATUS_SUCCESS on success.
 */
el2go_status_t net_crypto_set_server_cert(net_crypto_ctx_t *ctx,
					  const uint8_t *ca_cert_pem,
					  size_t ca_cert_len);

/**
 * @brief Parse and set client certificate for TLS authentication.
 *
 * @param[in] ctx       Network crypto context.
 * @param[in] cert_pem  DER-encoded client certificate.
 * @param[in] cert_len  Length of client certificate data.
 *
 * @return @ref el2go_status_t value, @ref EL2GO_STATUS_SUCCESS on success.
 */
el2go_status_t net_crypto_set_cli_cert(net_crypto_ctx_t *ctx,
				       const uint8_t *cert_pem,
				       size_t cert_len);

/**
 * @brief Set cipher suites for TLS connection.
 *
 * @param[in] ctx            Network crypto context.
 * @param[in] cipher_suites  Platform cipher suite list.
 *
 * @return @ref el2go_status_t value, @ref EL2GO_STATUS_SUCCESS on success.
 */
el2go_status_t
net_crypto_set_cipher_suites(net_crypto_ctx_t *ctx,
			     const el2go_cipher_list_t *cipher_suites);

/**
 * @brief Set curves for TLS connection.
 *
 * If NULL or empty list is provided, mbedTLS default curves are used.
 *
 * @param[in] ctx         Network crypto context.
 * @param[in] curve_list  Platform curve list.
 *
 * @return @ref el2go_status_t value, @ref EL2GO_STATUS_SUCCESS on success.
 */
el2go_status_t net_crypto_set_curves(net_crypto_ctx_t *ctx,
				     const el2go_curve_list_t *curve_list);

/**
 * @brief Associate a private key from HSM for TLS handshake.
 *
 * @param[in] ctx        Network crypto context.
 * @param[in] object_id  HSM object ID for the private key.
 *
 * @return @ref el2go_status_t value, @ref EL2GO_STATUS_SUCCESS on success.
 */
el2go_status_t net_crypto_associate_key(net_crypto_ctx_t *ctx,
					uint32_t object_id);

/**
 * @brief Generate a self-signed certificate.
 *
 * This function is independent of any network connection.
 *
 * @param[in]     subject          Certificate subject name (e.g., "CN=Device,O=Company").
 * @param[in]     key_id           Platform-specific key identifier.
 * @param[in]     device_uuid      Device UUID to include in certificate serial number.
 * @param[in]     device_uuid_len  Length of device UUID.
 * @param[out]    cert_out         Output buffer for DER-encoded certificate.
 * @param[in,out] cert_out_len     Buffer size on input, actual certificate size on output.
 *
 * @return @ref el2go_status_t value, @ref EL2GO_STATUS_SUCCESS on success.
 */
el2go_status_t net_crypto_self_signed_cert(const char *subject, uint32_t key_id,
					   const uint8_t *device_uuid,
					   size_t device_uuid_len,
					   uint8_t *cert_out,
					   size_t *cert_out_len);

/**
 * @brief Create a new network crypto connection context.
 *
 * Just initializes the context, does not establish a connection.
 *
 * @param[out] ctx  Pointer to receive the new context.
 *
 * @return @ref el2go_status_t value, @ref EL2GO_STATUS_SUCCESS on success.
 */
el2go_status_t net_crypto_new(net_crypto_ctx_t **ctx);

/**
 * @brief Configure the network crypto connection.
 *
 * @param[in] ctx     Network crypto context.
 * @param[in] config  Configuration parameters.
 *
 * @return @ref el2go_status_t value, @ref EL2GO_STATUS_SUCCESS on success.
 */
el2go_status_t net_crypto_configure(net_crypto_ctx_t *ctx,
				    const net_crypto_config_t *config);

/**
 * @brief Establish SSL/TLS connection.
 *
 * @param[in] ctx  Network crypto context.
 *
 * @return @ref el2go_status_t value, @ref EL2GO_STATUS_SUCCESS on success.
 */
el2go_status_t net_crypto_connect(net_crypto_ctx_t *ctx);

/**
 * @brief Verify server certificate against CRL.
 *
 * @param[in] ctx      Network crypto context.
 * @param[in] crl_pem  DER-encoded Certificate Revocation List.
 * @param[in] crl_len  Length of CRL data.
 *
 * @return @ref el2go_status_t value, @ref EL2GO_STATUS_SUCCESS on success.
 */
el2go_status_t net_crypto_verify_cert(net_crypto_ctx_t *ctx,
				      const uint8_t *crl_pem, size_t crl_len);

/**
 * @brief Read data from the SSL/TLS connection.
 *
 * @param[in]  ctx     Network crypto context.
 * @param[out] buffer  Buffer to receive data.
 * @param[in]  len     Maximum number of bytes to read.
 *
 * @return Number of bytes read on success, negative error code on failure.
 */
int net_crypto_read(net_crypto_ctx_t *ctx, uint8_t *buffer, size_t len);

/**
 * @brief Write data to the SSL/TLS connection.
 *
 * @param[in] ctx     Network crypto context.
 * @param[in] buffer  Data to write.
 * @param[in] len     Number of bytes to write.
 *
 * @return Number of bytes written on success, negative error code on failure.
 */
int net_crypto_write(net_crypto_ctx_t *ctx, const uint8_t *buffer, size_t len);

/**
 * @brief Free the network crypto context and all resources.
 *
 * @param[in,out] ctx  Pointer to network crypto context pointer (will be set to NULL).
 */
void net_crypto_free(net_crypto_ctx_t **ctx);

/**
 * @brief Cleanup the network crypto library.
 *
 * Performs any high-level cleanup.
 */
void net_crypto_cleanup(void);

/**
 * @brief Disconnect the SSL/TLS connection.
 *
 * @param[in] ctx  Network crypto context.
 *
 * @return @ref el2go_status_t value, @ref EL2GO_STATUS_SUCCESS on success.
 */
el2go_status_t net_crypto_disconnect(net_crypto_ctx_t *ctx);

/** @} */ /* end of net_crypto */

#endif /* __NET_CRYPTO_H__ */
