/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <string.h>

#include "compiler.h"
#include "osal.h"
#include "debug.h"
#include "builtin_macros.h"

#include "pb.h"
#include "pb_encode.h"
#include "pb_decode.h"
#include "ServiceDescriptor.pb.h"

#include "common/el2go_datastore.h"
#include "common/el2go_keystore.h"
#include "common/el2go_status.h"

#include "el2go_service.h"
#include "el2go_server_connection.h"
#include "net_crypto.h"

#include "keystore_priv.h"

bool el2go_conn_datastore_needs_update(el2go_datastore_t *datastore, const char *hostname,
                                       uint16_t port, const el2go_buffer_t *certificate)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    nxp_iot_ServiceDescriptor svc_desc = nxp_iot_ServiceDescriptor_init_default;
    size_t num_services = 0;
    size_t offset = 0;
    bool needs_update = true;
    size_t i = 0;

    if (srv_validate_configuration_data(datastore) != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(VERBOSE, "Datastore configuration is not valid, "
                                  "update required\n");
        goto exit;
    }

    num_services = srv_get_number_of_services(datastore);

    for (i = 0; i < num_services; i++) {
        status = srv_get_service_by_index(datastore, i, &offset, &svc_desc);
        if (status != EL2GO_STATUS_SUCCESS)
            goto exit;

        /* Only interested in EdgeLock 2GO service descriptors */
        if (svc_desc.has_service_type && svc_desc.service_type != nxp_iot_ServiceType_EL2GOSERVICE)
            continue;

        /* Skip update if hostname and port match and no new
         * certificate is provided by the user */
        if (svc_desc.hostname && strcmp(svc_desc.hostname, hostname) == 0 && svc_desc.has_port &&
            svc_desc.port == port && certificate == NULL) {
            EL2GO_DBG_PRINTF(INFO, "EdgeLock 2GO hostname and port match, "
                                   "update of datastore not required\n");
            needs_update = false;
            goto exit;
        }
    }

exit:
    pb_release(nxp_iot_ServiceDescriptor_fields, &svc_desc);
    return needs_update;
}

el2go_status_t el2go_conn_write_datastore(el2go_datastore_t *datastore,
                                          el2go_keystore_t *keystore_ctx, const char *hostname,
                                          uint16_t port, const pb_bytes_array_t *server_cert,
                                          uint32_t object_id, const pb_bytes_array_t *client_cert)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    nxp_iot_ServiceDescriptor svc_desc = nxp_iot_ServiceDescriptor_init_default;
    pb_ostream_t stream = PB_OSTREAM_SIZING;
    pb_ostream_t ostream = { 0 };
    bool pb_status = false;
    size_t encoded_size = 0;
    size_t total_size = 0;
    uint8_t *buffer = NULL;
    config_data_hdr_t *header = NULL;
    size_t bytes_written = 0;

    /* Validate input parameters - server_cert is the only optional parameter */
    if (!datastore || !keystore_ctx || !hostname || !client_cert) {
        EL2GO_DBG_PRINTF(ERROR, "Invalid input parameter\n");
        status = EL2GO_STATUS_INVALID_PARAMETER;
        goto exit;
    }

    /* Build service descriptor */
    svc_desc.hostname = (char *)hostname;
    svc_desc.has_port = true;
    svc_desc.port = port;
    svc_desc.has_service_type = true;
    svc_desc.service_type = nxp_iot_ServiceType_EL2GOSERVICE;

    /* Set server certificate (optional, can be NULL) */
    svc_desc.server_certificate = (pb_bytes_array_t *)server_cert;

    /* Set client key reference from keystore */
    svc_desc.has_client_key_sss_ref = true;
    svc_desc.client_key_sss_ref.has_type = true;
    svc_desc.client_key_sss_ref.type = (nxp_iot_EndpointType)keystore_ctx->type;
    svc_desc.client_key_sss_ref.has_endpoint_id = true;
    svc_desc.client_key_sss_ref.endpoint_id = keystore_ctx->id;
    svc_desc.client_key_sss_ref.has_object_id = true;
    svc_desc.client_key_sss_ref.object_id = object_id;

    /* Setup client certificate in service descriptor */
    status = el2go_keystore_set_cert_in_srv_desc(keystore_ctx, client_cert, &svc_desc);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR,
                         "Failed to set client certificate in service "
                         "descriptor: 0x%04x\n",
                         status);
        goto exit;
    }

    EL2GO_DBG_PRINTF(EXTRA, "client_cert size=%u\n", (unsigned)client_cert->size);
    if (server_cert != NULL) {
        EL2GO_DBG_PRINTF(EXTRA, "server_cert size=%u\n", (unsigned)server_cert->size);
    }

    pb_status = pb_encode_delimited(&stream, nxp_iot_ServiceDescriptor_fields, &svc_desc);
    if (!pb_status) {
        EL2GO_DBG_PRINTF(ERROR, "pb_encode_delimited sizing failed\n");
        status = EL2GO_STATUS_FAILURE;
        goto exit;
    }

    encoded_size = stream.bytes_written;
    EL2GO_DBG_PRINTF(EXTRA, "Encoded service descriptor size: %zu bytes\n", encoded_size);

    if (ADD_OVERFLOW(sizeof(config_data_hdr_t), encoded_size, &total_size)) {
        EL2GO_DBG_PRINTF(ERROR, "Overflow in total size calculation\n");
        status = EL2GO_STATUS_ARITHMETIC_OVERFLOW;
        goto exit;
    }

    buffer = (uint8_t *)osal_calloc(1, total_size);
    if (!buffer) {
        status = EL2GO_STATUS_ALLOCATION_ERROR;
        goto exit;
    }

    ostream = pb_ostream_from_buffer(buffer + sizeof(config_data_hdr_t), encoded_size);
    pb_status = pb_encode_delimited(&ostream, nxp_iot_ServiceDescriptor_fields, &svc_desc);
    if (!pb_status) {
        EL2GO_DBG_PRINTF(ERROR, "pb_encode_delimited failed\n");
        status = EL2GO_STATUS_FAILURE;
        goto exit;
    }

    /* Build header */
    header = (config_data_hdr_t *)buffer;
    header->length = (uint32_t)total_size;
    header->number_of_services = 1U;
    header->version = EL2GO_CONFIGURATION_DATA_VERSION;

    EL2GO_DBG_PRINTF(EXTRA, "config_data_hdr total_size=%zu\n", total_size);

    /* Calculate SHA-256 checksum over everything after the checksum field */
    status = net_crypto_sha256(buffer + sizeof(header->checksum),
                               total_size - sizeof(header->checksum), header->checksum);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "Checksum calculation failed: 0x%04x\n", status);
        goto exit;
    }

    /* Write to datastore */
    status = el2go_datastore_allocate(datastore, total_size);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "Datastore allocate failed: 0x%04x\n", status);
        goto exit;
    }

    status = el2go_datastore_write(datastore, buffer, 0U, total_size, &bytes_written);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "Datastore write failed: 0x%04x\n", status);
        goto exit;
    }

    status = el2go_datastore_commit(datastore);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "Datastore commit failed: 0x%04x\n", status);
        goto exit;
    }

    EL2GO_DBG_PRINTF(INFO, "EdgeLock 2GO datastore written successfully\n");

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    osal_free(buffer);
    return status;
}