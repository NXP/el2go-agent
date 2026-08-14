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

#include <stdbool.h>

#include "pb.h"
#include "pb_encode.h"
#include "Dispatcher.pb.h"
#include "ServiceDescriptor.pb.h"

/**
 * @defgroup el2go_keystore_int Keystore Internal API
 * @brief Keystore interface for internal module use.
 * @{
 */

/**
 * @brief Handle a keystore provisioning request.
 *
 * Processes an incoming keystore request by decoding it, executing the
 * appropriate command, and encoding the response into ostream.
 * Conforms to endpoint_handle_request_t so it can be registered directly
 * in the dispatcher endpoint table without a wrapper.
 *
 * @param[in]  ctx          Pointer to the el2go_keystore_t (void * for callback compatibility).
 * @param[in]  message_type nanopb fields descriptor identifying the request type.
 * @param[in]  istream      Input stream positioned at the start of the request.
 * @param[out] ostream      Output stream for the encoded response payload.
 *
 * @retval EL2GO_STATUS_SUCCESS on success.
 * @retval el2go_status_t error code on decode or provisioning failure.
 */
el2go_status_t el2go_keystore_handle_request(void *ctx, const pb_field_t *message_type,
                                             pb_istream_t *istream, pb_ostream_t *ostream);

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

/**
 * @brief Set the client certificate in a service descriptor.
 *
 * Stores the provided client certificate into the service descriptor.
 *
 * @param keystore            Keystore structure containing the platform context.
 * @param client_cert         Client certificate to use.
 * @param service_descriptor  Service descriptor in which to store the certificate.
 *
 * @return EL2GO_STATUS_SUCCESS on success, error code otherwise.
 */
el2go_status_t el2go_keystore_set_cert_in_srv_desc(el2go_keystore_t *keystore,
                                                   const pb_bytes_array_t *client_cert,
                                                   nxp_iot_ServiceDescriptor *service_descriptor);
/**
 * el2go_keystore_get_cert_from_srv_desc - Get client certificate from service descriptor
 * @keystore: Keystore structure
 * @service_descriptor: Service descriptor containing the client certificate
 * @client_cert: Output pointer to client certificate buffer
 * @client_cert_len: Output pointer to client certificate length
 *
 * Return:
 * EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
el2go_status_t
el2go_keystore_get_cert_from_srv_desc(el2go_keystore_t *keystore,
                                      const nxp_iot_ServiceDescriptor *service_descriptor,
                                      const uint8_t **client_cert, size_t *client_cert_len);

/**
 * @brief Return the nxp_iot_EndpointType corresponding to a keystore's type.
 *
 * Maps the el2go_keystore_type_t stored in the keystore to the protobuf
 * EndpointType value used in the dispatcher endpoint table and HelloResponse.
 *
 * @param[in] keystore  Keystore to query.
 *
 * @retval nxp_iot_EndpointType for the keystore, or nxp_iot_EndpointType_INVALID
 *         if the type is not recognized.
 */
nxp_iot_EndpointType el2go_keystore_get_endpoint_type(const el2go_keystore_t *keystore);

/**
 * @brief Populate endpoint information for a keystore endpoint.
 *
 * Endpoint get_info callback for the dispatcher endpoint table.
 * The type and endpointId fields are pre-filled by the dispatcher before this
 * function is called; this function marks them as present in the message.
 *
 * @param[in]  ctx   Pointer to the el2go_keystore_t (void * for callback compatibility).
 * @param[out] info  Endpoint information structure to populate.
 *
 * @retval true always.
 */
el2go_status_t el2go_keystore_get_endpoint_info(void *ctx, nxp_iot_EndpointInformation *info);

/**
 * @brief Import claimcode blob from a fixed flash address into PSA ITS.
 *
 * Reads the claimcode blob from CONFIG_EL2GO_RTP_CLAIMCODE_FLASH_ADDRESS,
 * validates the magic indicator {'E','2','G','C'}, and writes it into PSA ITS
 * under EDGELOCK2GO_CLAIMCODE_DATA_ID. No-op if already stored.
 *
 * A weak no-op default is provided in el2go_keystore.c; the real PSA
 * implementation in libs/keystores/psa/ overrides it when linked.
 *
 * @param[in] keystore  Initialized keystore (used for context only).
 *
 * @return EL2GO_STATUS_SUCCESS on success or if already stored.
 * @return EL2GO_STATUS_INVALID_PARAMETER if the magic bytes do not match.
 * @return EL2GO_STATUS_PSA_ERROR on PSA ITS write failure.
 */
el2go_status_t el2go_keystore_import_claimcode_from_flash(el2go_keystore_t *keystore);

/** @} */ /* end of el2go_keystore_int */

#endif /* __KEYSTORE_PRIV_H__ */
