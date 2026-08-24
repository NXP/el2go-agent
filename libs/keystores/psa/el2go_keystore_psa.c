/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <stddef.h>
#include <inttypes.h>

#include "psa/crypto.h"
#include "psa/internal_trusted_storage.h"

#include "compiler.h"
#include "debug.h"
#include "builtin_macros.h"

#include "pb.h"
#include "pb_encode.h"
#include "pb_decode.h"

#include "Dispatcher.pb.h"
#include "Agent.pb.h"
#include "PSA.pb.h"
#include "ServiceDescriptor.pb.h"
#include "pb_utils.h"

#include "common/el2go_keystore.h"
#include "keystore_priv.h"
#include "platform_priv.h"
#include "plat_keys.h"

#define EL2GO_MAX_KEY_DATA_SIZE (10 * 1024)

/* Map the server-canonical claimcode UID to the locally valid ITS UID.
 * The server always sends 0xF00000E0 (the TF-M ITS range). On non-TF-M
 * platforms EDGELOCK2GO_CLAIMCODE_DATA_ID is already defined to the
 * platform-valid UID, so the remap resolves at compile time. On TF-M
 * builds both sides are identical and the function is a no-op. */
static inline psa_storage_uid_t psa_its_uid_remap(psa_storage_uid_t uid)
{
    if (uid == 0xF00000E0U)
        return (psa_storage_uid_t)EDGELOCK2GO_CLAIMCODE_DATA_ID;
    return uid;
}

static el2go_status_t handle_get_version(el2go_keystore_t *keystore, nxp_iot_PsaRequest *request,
                                         nxp_iot_ResponsePayload *response)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    nxp_iot_GetVersionResponse *get_version_resp = NULL;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    (void)keystore;
    (void)request;

    if (!response) {
        status = EL2GO_STATUS_INVALID_PARAMETER;
        goto exit;
    }

    response->which_message = nxp_iot_ResponsePayload_psa_tag;
    response->message.psa.which_response = nxp_iot_PsaResponse_get_version_tag;

    get_version_resp = &response->message.psa.response.get_version;
    *get_version_resp = (nxp_iot_GetVersionResponse)nxp_iot_GetVersionResponse_init_default;
    get_version_resp->has_crypto_api_version = true;
    get_version_resp->crypto_api_version = (PSA_CRYPTO_API_VERSION_MAJOR << 16) |
                                           (PSA_CRYPTO_API_VERSION_MINOR << 8);
    get_version_resp->supported_key_data_formats_count = 1;
    get_version_resp->supported_key_data_formats[0] = nxp_iot_KeyDataFormat_S50;
    get_version_resp->has_max_raw_key_size = true;
    get_version_resp->max_raw_key_size = EL2GO_MAX_KEY_DATA_SIZE;

    EL2GO_DBG_PRINTF(VERBOSE, "PSA get version request handled\n");

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

static el2go_status_t handle_destroy_key(el2go_keystore_t *keystore, nxp_iot_PsaRequest *request,
                                         nxp_iot_ResponsePayload *response)
{
    el2go_status_t el2go_status = EL2GO_STATUS_SUCCESS;
    psa_status_t psa_status = PSA_SUCCESS;
    psa_key_id_t id = 0U;
    nxp_iot_DestroyKeyRequest *destroy_key_req = NULL;
    nxp_iot_DestroyKeyResponse *destroy_key_resp = NULL;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!keystore || !request || !response) {
        el2go_status = EL2GO_STATUS_INVALID_PARAMETER;
        goto exit;
    }

    destroy_key_req = &request->command.destroy_key;
    if (!destroy_key_req->has_identifier) {
        el2go_status = EL2GO_STATUS_INVALID_REQUEST;
        goto exit;
    }

    response->which_message = nxp_iot_ResponsePayload_psa_tag;
    response->message.psa.which_response = nxp_iot_PsaResponse_destroy_key_tag;

    destroy_key_resp = &response->message.psa.response.destroy_key;
    *destroy_key_resp = (nxp_iot_DestroyKeyResponse)nxp_iot_DestroyKeyResponse_init_default;
    destroy_key_resp->has_status = true;

    id = destroy_key_req->identifier;
    psa_status = psa_destroy_key(id);

    /* Try platform-specific fallback if standard destroy failed */
    if (psa_status == PSA_ERROR_INVALID_HANDLE && keystore->platform_ctx) {
        el2go_status = el2go_platform_destroy_key(keystore->platform_ctx, &id);
        if (el2go_status == EL2GO_STATUS_SUCCESS) {
            psa_status = PSA_SUCCESS;
        } else if (el2go_status == EL2GO_STATUS_NOT_FOUND) {
            psa_status = PSA_ERROR_DOES_NOT_EXIST;
        }
    }

    destroy_key_resp->status = (nxp_iot_StatusCode)psa_status;
    el2go_status = EL2GO_STATUS_SUCCESS;

    EL2GO_DBG_PRINTF(VERBOSE, "PSA destroy key request handled (id: 0x%08" PRIx32 ", status: %d)\n",
                     id, (int)psa_status);

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, el2go_status);
    return el2go_status;
}

static el2go_status_t handle_import_key(el2go_keystore_t *keystore, nxp_iot_PsaRequest *request,
                                        nxp_iot_ResponsePayload *response)
{
    el2go_status_t el2go_status = EL2GO_STATUS_SUCCESS;
    psa_status_t psa_status = PSA_SUCCESS;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t id = 0U;
    psa_key_type_t type = 0U;
    nxp_iot_ImportKeyRequest *import_key_req = NULL;
    nxp_iot_ImportKeyResponse *import_key_resp = NULL;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    (void)keystore;

    if (!request || !response) {
        el2go_status = EL2GO_STATUS_INVALID_PARAMETER;
        goto exit;
    }

    import_key_req = &request->command.import_key;

    if (!import_key_req->has_identifier || !import_key_req->has_type ||
        !import_key_req->has_usage || !import_key_req->has_algorithm ||
        !import_key_req->has_key_data_format || !import_key_req->has_lifetime ||
        !import_key_req->data) {
        el2go_status = EL2GO_STATUS_INVALID_REQUEST;
        goto exit;
    }

    if (import_key_req->data->size == 0U || import_key_req->data->size > EL2GO_MAX_KEY_DATA_SIZE) {
        EL2GO_DBG_PRINTF(ERROR, "Key data size out of range: %u (valid range: 1-%d)\n",
                         (unsigned int)import_key_req->data->size, EL2GO_MAX_KEY_DATA_SIZE);
        el2go_status = EL2GO_STATUS_INVALID_REQUEST;
        goto exit;
    }

    if (import_key_req->key_data_format != nxp_iot_KeyDataFormat_S50) {
        EL2GO_DBG_PRINTF(ERROR, "Unsupported key data format: %d\n",
                         (int)import_key_req->key_data_format);
        el2go_status = EL2GO_STATUS_INVALID_REQUEST;
        goto exit;
    }

    response->which_message = nxp_iot_ResponsePayload_psa_tag;
    response->message.psa.which_response = nxp_iot_PsaResponse_import_key_tag;

    import_key_resp = &response->message.psa.response.import_key;
    *import_key_resp = (nxp_iot_ImportKeyResponse)nxp_iot_ImportKeyResponse_init_default;
    import_key_resp->has_status = true;

    if (SET_OVERFLOW(import_key_req->type, type)) {
        import_key_resp->status = (nxp_iot_StatusCode)PSA_ERROR_INVALID_ARGUMENT;
        EL2GO_DBG_PRINTF(ERROR, "Invalid key type: 0x%08" PRIx32 " (overflow)\n",
                         import_key_req->type);
        goto exit;
    }

    /* Set key attributes */
    psa_set_key_usage_flags(&attributes, import_key_req->usage);
    psa_set_key_algorithm(&attributes, import_key_req->algorithm);
    psa_set_key_type(&attributes, type);
    psa_set_key_id(&attributes, import_key_req->identifier);
    psa_set_key_lifetime(&attributes, import_key_req->lifetime);
    psa_set_key_bits(&attributes, import_key_req->key_bits);

    /* Import the key */
    psa_status =
        psa_import_key(&attributes, import_key_req->data->bytes, import_key_req->data->size, &id);

    import_key_resp->status = (nxp_iot_StatusCode)psa_status;

    EL2GO_DBG_PRINTF(VERBOSE, "PSA import key request handled (id: 0x%08" PRIx32 ", status: %d)\n",
                     import_key_req->identifier, (int)psa_status);

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, el2go_status);
    return el2go_status;
}

static el2go_status_t handle_read_object(el2go_keystore_t *keystore, nxp_iot_PsaRequest *request,
                                         nxp_iot_ResponsePayload *response)
{
    el2go_status_t el2go_status = EL2GO_STATUS_SUCCESS;
    psa_status_t psa_status = PSA_SUCCESS;
    psa_storage_uid_t uid = 0U;
    struct psa_storage_info_t info = { 0 };
    size_t chunk_size = 0U;
    size_t read_length = 0U;
    size_t remaining = 0U;
    nxp_iot_ReadObjectRequest *read_object_req = NULL;
    nxp_iot_ReadObjectResponse *read_object_resp = NULL;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    (void)keystore;

    if (!request || !response) {
        el2go_status = EL2GO_STATUS_INVALID_PARAMETER;
        goto exit;
    }

    read_object_req = &request->command.read_object;
    if (!read_object_req->has_identifier) {
        el2go_status = EL2GO_STATUS_INVALID_REQUEST;
        goto exit;
    }

    uid = read_object_req->identifier;

    response->which_message = nxp_iot_ResponsePayload_psa_tag;
    response->message.psa.which_response = nxp_iot_PsaResponse_read_object_tag;

    read_object_resp = &response->message.psa.response.read_object;
    /* Explicitly zero the response struct: nxp_iot_ResponsePayload_init_default does not
     * guarantee the full union is zeroed, so data (FT_POINTER) could be a garbage stack
     * value if we take an error path without setting it. */
    *read_object_resp = (nxp_iot_ReadObjectResponse)nxp_iot_ReadObjectResponse_init_default;
    read_object_resp->has_status = true;

    uid = psa_its_uid_remap(uid);
    psa_status = psa_its_get_info(uid, &info);
    if (psa_status != PSA_SUCCESS) {
        read_object_resp->status = (nxp_iot_StatusCode)psa_status;
        EL2GO_DBG_PRINTF(ERROR, "Failed to get object info (uid: 0x%016" PRIx64 ", status: %d)\n",
                         uid, (int)psa_status);
        read_object_resp->data = osal_calloc(1, PB_BYTES_ARRAY_T_ALLOCSIZE(0));
        goto exit;
    }

    chunk_size = info.size;
    if (read_object_req->has_length) {
        if (SUB_OVERFLOW(info.size, read_object_req->offset, &remaining)) {
            read_object_resp->status = (nxp_iot_StatusCode)PSA_ERROR_INVALID_ARGUMENT;
            EL2GO_DBG_PRINTF(ERROR, "Invalid offset (offset: %" PRIu32 ", size: %zu)\n",
                             read_object_req->offset, info.size);
            goto exit;
        }

        chunk_size = MIN(remaining, read_object_req->length);
    }

    if (chunk_size > EL2GO_MAX_KEY_DATA_SIZE) {
        read_object_resp->status = (nxp_iot_StatusCode)PSA_ERROR_INVALID_ARGUMENT;
        EL2GO_DBG_PRINTF(ERROR, "Object size exceeds maximum allowed size (size: %zu, max: %d)\n",
                         chunk_size, EL2GO_MAX_KEY_DATA_SIZE);
        goto exit;
    }

    read_object_resp->data = osal_calloc(1, PB_BYTES_ARRAY_T_ALLOCSIZE(chunk_size));
    if (!read_object_resp->data) {
        read_object_resp->status = (nxp_iot_StatusCode)PSA_ERROR_INSUFFICIENT_MEMORY;
        EL2GO_DBG_PRINTF(ERROR, "Failed to allocate memory for read object\n");
        goto exit;
    }

    read_object_resp->data->size = chunk_size;

    psa_status = psa_its_get(uid, read_object_req->offset, chunk_size,
                             read_object_resp->data->bytes, &read_length);
    read_object_resp->data->size = read_length;
    read_object_resp->status = (nxp_iot_StatusCode)psa_status;

    EL2GO_DBG_PRINTF(VERBOSE,
                     "PSA read object request handled (uid: 0x%016" PRIx64
                     ", size: %zu, status: %d)\n",
                     uid, read_length, (int)psa_status);

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, el2go_status);
    return el2go_status;
}

static el2go_status_t handle_remove_object(el2go_keystore_t *keystore, nxp_iot_PsaRequest *request,
                                           nxp_iot_ResponsePayload *response)
{
    el2go_status_t el2go_status = EL2GO_STATUS_SUCCESS;
    psa_status_t psa_status = PSA_SUCCESS;
    psa_storage_uid_t uid = 0U;
    nxp_iot_RemoveObjectRequest *remove_object_req = NULL;
    nxp_iot_RemoveObjectResponse *remove_object_resp = NULL;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    (void)keystore;

    if (!request || !response) {
        el2go_status = EL2GO_STATUS_INVALID_PARAMETER;
        goto exit;
    }

    remove_object_req = &request->command.remove_object;

    if (!remove_object_req->has_identifier) {
        el2go_status = EL2GO_STATUS_INVALID_REQUEST;
        goto exit;
    }

    response->which_message = nxp_iot_ResponsePayload_psa_tag;
    response->message.psa.which_response = nxp_iot_PsaResponse_remove_object_tag;

    remove_object_resp = &response->message.psa.response.remove_object;
    *remove_object_resp = (nxp_iot_RemoveObjectResponse)nxp_iot_RemoveObjectResponse_init_default;
    remove_object_resp->has_status = true;

    uid = psa_its_uid_remap(remove_object_req->identifier);
    psa_status = psa_its_remove(uid);

    remove_object_resp->status = (nxp_iot_StatusCode)psa_status;

    EL2GO_DBG_PRINTF(VERBOSE,
                     "PSA remove object request handled (uid: 0x%016" PRIx64 ", status: %d)\n", uid,
                     (int)psa_status);

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, el2go_status);
    return el2go_status;
}

__export el2go_status_t el2go_keystore_init(uint32_t id, el2go_platform_ctx_t *platform_ctx,
                                            el2go_keystore_t *keystore)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    psa_status_t psa_status = PSA_SUCCESS;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!keystore) {
        status = EL2GO_STATUS_INVALID_PARAMETER;
        goto exit;
    }

    /* Initialize PSA crypto subsystem */
    psa_status = psa_crypto_init();
    if (psa_status != PSA_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "psa_crypto_init failed: 0x%08" PRIx32 "\n", (int)psa_status);
        status = EL2GO_STATUS_PSA_ERROR;
        goto exit;
    }

    keystore->id = id;
    keystore->type = EL2GO_KEYSTORE_PSA;
    keystore->context = NULL;
    keystore->priv = NULL;
    keystore->platform_ctx = platform_ctx;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

el2go_status_t el2go_keystore_handle_request(void *ctx, const pb_field_t *message_type,
                                             pb_istream_t *istream, pb_ostream_t *ostream)
{
    el2go_keystore_t *keystore = (el2go_keystore_t *)ctx;
    el2go_status_t status = EL2GO_STATUS_RTP_DECODE_ERROR;
    nxp_iot_PsaRequest request = nxp_iot_PsaRequest_init_default;
    nxp_iot_ResponsePayload response = nxp_iot_ResponsePayload_init_default;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!keystore || !istream || !ostream || !message_type) {
        status = EL2GO_STATUS_INVALID_PARAMETER;
        goto exit;
    }

    if (message_type != nxp_iot_PsaRequest_fields) {
        EL2GO_DBG_PRINTF(ERROR, "Unsupported message type: tag: %u\n",
                         (unsigned int)message_type->tag);
        goto exit;
    }

    /* Decode the incoming request */
    if (!pb_decode_delimited(istream, nxp_iot_PsaRequest_fields, &request)) {
        EL2GO_DBG_PRINTF(ERROR, "Decoding of server message failed: %s\n", PB_GET_ERROR(istream));
        goto exit;
    }

    /* Handle the request based on command type */
    switch (request.which_command) {
    case nxp_iot_PsaRequest_get_version_tag:
        status = handle_get_version(keystore, &request, &response);
        break;

    case nxp_iot_PsaRequest_destroy_key_tag:
        status = handle_destroy_key(keystore, &request, &response);
        break;

    case nxp_iot_PsaRequest_import_key_tag:
        status = handle_import_key(keystore, &request, &response);
        break;

    case nxp_iot_PsaRequest_read_object_tag:
        status = handle_read_object(keystore, &request, &response);
        break;

    case nxp_iot_PsaRequest_remove_object_tag:
        status = handle_remove_object(keystore, &request, &response);
        break;

    default:
        EL2GO_DBG_PRINTF(ERROR, "Unknown command: %d\n", (int)request.which_command);
        goto exit;
    }

    if (status != EL2GO_STATUS_SUCCESS)
        goto exit;

    /* Encode the response wrapped in nxp_iot_Responses */
    if (!encode_responses_from_payload(ostream, &response)) {
        EL2GO_DBG_PRINTF(ERROR, "encode_responses_from_payload failed\n");
        status = EL2GO_STATUS_RTP_ENCODE_ERROR;
        goto exit;
    }

    status = EL2GO_STATUS_SUCCESS;

exit:
    pb_release(nxp_iot_PsaRequest_fields, &request);
    pb_release(nxp_iot_ResponsePayload_fields, &response);

    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

el2go_status_t el2go_keystore_get_el2go_key_id(el2go_keystore_t *keystore, uint32_t *key_id)
{
    if (!keystore || !key_id)
        return EL2GO_STATUS_INVALID_PARAMETER;

    return el2go_platform_get_el2go_key_id(keystore->platform_ctx, key_id);
}

el2go_status_t el2go_keystore_get_el2go_cert(el2go_keystore_t *keystore, uint8_t *cert,
                                             size_t *cert_len)
{
    if (!keystore || !cert || !cert_len)
        return EL2GO_STATUS_INVALID_PARAMETER;

    return el2go_platform_get_el2go_cert(keystore->platform_ctx, cert, cert_len);
}

el2go_status_t
el2go_keystore_get_cert_from_srv_desc(el2go_keystore_t *keystore,
                                      const nxp_iot_ServiceDescriptor *service_descriptor,
                                      const uint8_t **client_cert, size_t *client_cert_len)
{
    if (!keystore || !service_descriptor || !client_cert || !client_cert_len)
        return EL2GO_STATUS_INVALID_PARAMETER;

    if (!service_descriptor->client_certificate ||
        service_descriptor->client_certificate->size == 0) {
        EL2GO_DBG_PRINTF(ERROR, "EL2GOSERVICE descriptor has no client certificate\n");
        return EL2GO_STATUS_INVALID_DATASTORE;
    }

    /* PSA keystore: certificate is stored in service descriptor
     * point directly into it - no copy needed */
    *client_cert = service_descriptor->client_certificate->bytes;
    *client_cert_len = service_descriptor->client_certificate->size;

    return EL2GO_STATUS_SUCCESS;
}

el2go_status_t el2go_keystore_set_cert_in_srv_desc(el2go_keystore_t *keystore,
                                                   const pb_bytes_array_t *client_cert,
                                                   nxp_iot_ServiceDescriptor *service_descriptor)
{
    if (!keystore || !client_cert || !service_descriptor)
        return EL2GO_STATUS_INVALID_PARAMETER;

    /* PSA keystore: point directly into the pb_bytes_array_t - no copy needed */
    service_descriptor->client_certificate = (pb_bytes_array_t *)client_cert;

    return EL2GO_STATUS_SUCCESS;
}

el2go_status_t el2go_keystore_import_claimcode(el2go_keystore_t *keystore, const char *claimcode,
                                               size_t claimcode_len)
{
    if (!keystore || !claimcode || claimcode_len == 0U)
        return EL2GO_STATUS_INVALID_PARAMETER;

    /* Delegate to the platform-specific implementation.
     * If no platform support is available (EL2GO_STATUS_NOT_IMPLEMENTED), a generic
     * PSA ITS fallback can be added here in the future. */
    return el2go_platform_import_claimcode(keystore->platform_ctx, claimcode, claimcode_len);
}
