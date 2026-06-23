/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __KEYSTORE_PRIV_H__
#define __KEYSTORE_PRIV_H__

#include "common/el2go_keystore.h"
#include "common/el2go_status.h"

/**
 * @defgroup el2go_keystore_int Keystore Internal API
 * @brief Keystore interface for internal module use.
 * @{
 */

/**
 * @brief Handle a keystore request
 *
 * Processes incoming keystore requests by decoding the request, executing
 * the appropriate command, and encoding the response.
 *
 * @param[in]  keystore      Pointer to keystore structure.
 * @param[in]  message_type  Message type fields.
 * @param[in]  istream       Input stream with request data.
 * @param[out] ostream       Output stream for response data.
 *
 * @return @ref el2go_status_t value, @ref EL2GO_STATUS_SUCCESS on success.
 */
el2go_status_t el2go_keystore_handle_request(el2go_keystore_t *keystore, const void *message_type,
                                             void *istream, void *ostream);

/**
 * el2go_keystore_get_el2go_key_id - Get the ECC key ID for EdgeLock 2GO server connection
 * @keystore: Keystore structure
 * @key_id: Pointer to store the key ID
 *
 * Return:
 * EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
el2go_status_t el2go_keystore_get_el2go_key_id(el2go_keystore_t *keystore, uint32_t *key_id);

/**
 * el2go_keystore_get_el2go_cert - Get client certificate for EdgeLock 2GO connection
 * @keystore: Keystore structure
 * @cert: Pointer to buffer where certificate will be stored
 * @cert_len: On input, size of buffer; on output, actual certificate length
 *
 * Retrieves the client certificate used for mutual TLS authentication with
 * the EdgeLock 2GO server. Delegates to the platform-specific implementation.
 * If the platform returns EL2GO_STATUS_CERT_NOT_AVAILABLE, the caller should fall
 * back to generating a self-signed certificate.
 *
 * Return:
 * EL2GO_STATUS_SUCCESS on success
 * EL2GO_STATUS_CERT_NOT_AVAILABLE if no certificate is available
 * error code otherwise
 */
el2go_status_t el2go_keystore_get_el2go_cert(el2go_keystore_t *keystore, uint8_t *cert,
                                             size_t *cert_len);

/** @} */ /* end of el2go_keystore_int */

#endif /* __KEYSTORE_PRIV_H__ */
