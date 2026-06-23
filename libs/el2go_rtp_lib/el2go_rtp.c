/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "rtp/el2go_rtp.h"
#include "rtp/el2go_rtp_config.h"
#include "common/el2go_status.h"

#include "compiler.h"
#include "osal.h"
#include "debug.h"
#include "builtin_macros.h"

#include "net_crypto.h"
#include "el2go_server_certificates.h"
#include "el2go_server_connection.h"

#include "keystore_priv.h"
#include "platform_priv.h"

#include "pb.h"

#include "el2go_rtp_internal.h"

__export el2go_status_t el2go_rtp_datastore_el2go(el2go_datastore_t *datastore,
                                                  el2go_keystore_t *keystore_ctx,
                                                  const el2go_rtp_datastore_config_t *config)
{
    el2go_status_t status = EL2GO_STATUS_INVALID_PARAMETER;
    const char *hostname = NULL;
    uint16_t port = 0;
    pb_bytes_array_t *cert_array = NULL;
    const pb_bytes_array_t *cert = NULL;
    bool user_provided = false;
    uint32_t key_id = 0;
    uint8_t *device_uuid = NULL;
    size_t device_uuid_len = 0;
    PB_BYTES_ARRAY_T(EL2GO_RTP_CLIENT_CERT_MAX_SIZE) client_cert_buf = { 0 };
    pb_bytes_array_t *client_cert_array = (pb_bytes_array_t *)&client_cert_buf;
    size_t client_cert_len = EL2GO_RTP_CLIENT_CERT_MAX_SIZE;

    EL2GO_DBG_TRACE_API_CALL;

    if (!datastore || !keystore_ctx || !config)
        goto exit;

    /* Use hostname and port from config if both are set,
     * otherwise fall back to defaults for both.
     * Hostname and port must be provided together. */
    if (config->hostname && config->hostname[0] != '\0' && config->port != 0) {
        hostname = config->hostname;
        port = config->port;
        user_provided = true;
        EL2GO_DBG_PRINTF(VERBOSE, "Using hostname and port from config\n");
    } else {
        hostname = EL2GO_RTP_EDGELOCK2GO_HOSTNAME;
        port = EL2GO_RTP_EDGELOCK2GO_PORT;
        EL2GO_DBG_PRINTF(VERBOSE,
                         "No hostname/port in config, "
                         "using defaults: %s:%u\n",
                         hostname, port);
    }

    EL2GO_DBG_PRINTF(INFO, "Using EdgeLock 2GO server: %s:%u\n", hostname, port);

    if (user_provided &&
        !el2go_conn_datastore_needs_update(datastore, hostname, port, config->certificate)) {
        status = EL2GO_STATUS_SUCCESS;
        goto exit;
    }

    /* Get the ECC key ID from the keystore */
    status = el2go_keystore_get_el2go_key_id(keystore_ctx, &key_id);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to get EL2GO key ID: 0x%04x\n", status);
        goto exit;
    }

    /* Try to get client certificate from keystore/platform first */
    status = el2go_keystore_get_el2go_cert(keystore_ctx, client_cert_buf.bytes, &client_cert_len);
    if (status == EL2GO_STATUS_CERT_NOT_AVAILABLE) {
        EL2GO_DBG_PRINTF(VERBOSE, "No platform certificate, generating self-signed\n");

        /* Get device UUID from platform */
        status =
            el2go_platform_get_uuid(keystore_ctx->platform_ctx, &device_uuid, &device_uuid_len);
        if (status != EL2GO_STATUS_SUCCESS) {
            EL2GO_DBG_PRINTF(ERROR, "Failed to get device UUID: 0x%04x\n", status);
            goto exit;
        }

        /* Generate self-signed client certificate */
        status = net_crypto_self_signed_cert(EL2GO_RTP_SUBJECT, key_id, device_uuid,
                                             device_uuid_len, client_cert_buf.bytes,
                                             &client_cert_len);
        if (status != EL2GO_STATUS_SUCCESS) {
            EL2GO_DBG_PRINTF(ERROR, "Failed to generate self-signed certificate: 0x%04x\n", status);
            goto exit;
        }

        EL2GO_DBG_PRINTF(VERBOSE, "Generated self-signed client certificate (%zu bytes)\n",
                         client_cert_len);
    } else if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to get client certificate from keystore: 0x%04x\n", status);
        goto exit;
    } else {
        EL2GO_DBG_PRINTF(VERBOSE, "Using keystore client certificate (%zu bytes)\n",
                         client_cert_len);
    }

    client_cert_buf.size = (pb_size_t)client_cert_len;

    /* Build pb_bytes_array_t for the certificate.
     * Certificate is independent of hostname/port -
     * can be provided in any situation. */
    if (config->certificate && config->certificate->data && config->certificate->len > 0) {
        cert_array = (pb_bytes_array_t *)osal_calloc(
            1, PB_BYTES_ARRAY_T_ALLOCSIZE(config->certificate->len));
        if (!cert_array) {
            status = EL2GO_STATUS_ALLOCATION_ERROR;
            goto exit;
        }
        cert_array->size = (pb_size_t)config->certificate->len;
        memcpy(cert_array->bytes, config->certificate->data, config->certificate->len);
        cert = cert_array;
        user_provided = true;
        EL2GO_DBG_PRINTF(VERBOSE, "Using certificate from config (%zu bytes)\n",
                         config->certificate->len);
    } else {
        cert = el2go_get_default_certs();
        EL2GO_DBG_PRINTF(VERBOSE, "No certificate in config, using default\n");
    }

    if (user_provided &&
        !el2go_conn_datastore_needs_update(datastore, hostname, port, config->certificate)) {
        status = EL2GO_STATUS_SUCCESS;
        goto exit;
    }

    EL2GO_DBG_PRINTF(INFO, "Updating EdgeLock 2GO datastore with %s:%u\n", hostname, port);

    status = el2go_conn_write_datastore(datastore, keystore_ctx, hostname, port, cert, key_id,
                                        client_cert_array);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR,
                         "Failed to write EdgeLock 2GO datastore: "
                         "0x%04x\n",
                         status);
        goto exit;
    }

exit:
    if (cert_array)
        osal_free(cert_array);
    if (device_uuid)
        osal_free(device_uuid);

    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}
/**
 * get_datastore_index_by_id - Get datastore index by identifier
 * @ctx: RTP agent context
 * @id: Datastore identifier to search for
 * @index: Pointer to store the found index
 *
 * This function searches through the registered datastores in the agent context
 * to find a datastore with the specified identifier. If found, the index of the
 * datastore in the internal array is returned through the index parameter.
 *
 * Return:
 * EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
static el2go_status_t get_datastore_index_by_id(const el2go_rtp_ctx_t *ctx, uint32_t id,
                                                size_t *index)
{
    el2go_status_t status = EL2GO_STATUS_INVALID_PARAMETER;
    size_t i = 0;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!ctx || !index)
        goto exit;

    status = EL2GO_STATUS_NOT_FOUND;

    for (; i < ctx->num_datastores; i++) {
        if (ctx->datastores[i]->id == id) {
            *index = i;
            status = EL2GO_STATUS_SUCCESS;
            goto exit;
        }
    }

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

/**
 * get_keystore_index_by_id - Get keystore index by identifier
 * @ctx: RTP agent context
 * @id: Keystore identifier to search for
 * @index: Pointer to store the found index
 *
 * This function searches through the registered keystores in the agent context
 * to find a keystore with the specified identifier. If found, the index of the
 * keystore in the internal array is returned through the index parameter.
 *
 * Return:
 * EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
static el2go_status_t get_keystore_index_by_id(const el2go_rtp_ctx_t *ctx, uint32_t id,
                                               size_t *index)
{
    el2go_status_t status = EL2GO_STATUS_INVALID_PARAMETER;
    size_t i = 0;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!ctx || !index)
        goto exit;

    status = EL2GO_STATUS_NOT_FOUND;

    for (; i < ctx->num_keystores; i++) {
        if (ctx->keystores[i]->id == id) {
            *index = i;
            status = EL2GO_STATUS_SUCCESS;
            goto exit;
        }
    }

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

__export el2go_status_t el2go_rtp_get_version(unsigned int *major, unsigned int *minor)
{
    el2go_status_t status = EL2GO_STATUS_INVALID_PARAMETER;

    EL2GO_DBG_TRACE_API_CALL;

    if (!major || !minor)
        goto exit;

    *major = 0;
    *minor = 0;

    status = EL2GO_STATUS_SUCCESS;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

__export el2go_status_t el2go_rtp_init(el2go_rtp_ctx_t **ctx)
{
    el2go_status_t status = EL2GO_STATUS_INVALID_PARAMETER;
    el2go_rtp_ctx_t *agent_ctx = NULL;

    if (!ctx)
        goto exit;

    /* Initialize OSAL subsystem */
    osal_lib_init();

    /* Allocate memory for RTP agent context */
    agent_ctx = (el2go_rtp_ctx_t *)osal_calloc(1, sizeof(el2go_rtp_ctx_t));
    if (!agent_ctx) {
        status = EL2GO_STATUS_ALLOCATION_ERROR;
        goto exit;
    }

    *ctx = agent_ctx;

    status = EL2GO_STATUS_SUCCESS;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

__export el2go_status_t el2go_rtp_free(el2go_rtp_ctx_t **ctx)
{
    el2go_status_t status = EL2GO_STATUS_INVALID_PARAMETER;

    EL2GO_DBG_TRACE_API_CALL;

    if (!ctx || !*ctx)
        goto exit;

    /* Free the allocated context */
    osal_free(*ctx);
    *ctx = NULL;

    status = EL2GO_STATUS_SUCCESS;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

__export el2go_status_t el2go_rtp_add_datastore(el2go_rtp_ctx_t *ctx, el2go_datastore_t *datastore)
{
    el2go_status_t status = EL2GO_STATUS_INVALID_PARAMETER;
    size_t index = 0;

    EL2GO_DBG_TRACE_API_CALL;

    if (!ctx || !datastore)
        goto exit;

    if (ctx->num_datastores >= EL2GO_RTP_MAX_DATASTORES) {
        EL2GO_DBG_PRINTF(ERROR, "Unable to register datastore, maximum number reached\n");
        status = EL2GO_STATUS_RESOURCE_LIMIT;
        goto exit;
    }

    /* Check for identifier uniqueness against existing datastores */
    status = get_datastore_index_by_id(ctx, datastore->id, &index);
    if (status == EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR,
                         "Unable to register datastore with id 0x%08" PRIx32
                         ", a datastore with that id is already registered\n",
                         datastore->id);
        status = EL2GO_STATUS_ALREADY_EXISTS;
        goto exit;
    }

    /* Check for identifier uniqueness against existing keystores */
    status = get_keystore_index_by_id(ctx, datastore->id, &index);
    if (status == EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR,
                         "Unable to register datastore with id 0x%08" PRIx32
                         ", a keystore with that id is already registered\n",
                         datastore->id);
        status = EL2GO_STATUS_ALREADY_EXISTS;
        goto exit;
    }

    /* Register the datastore */
    ctx->datastores[ctx->num_datastores] = datastore;
    ctx->num_datastores++;

    status = EL2GO_STATUS_SUCCESS;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

__export el2go_status_t el2go_rtp_remove_datastore(el2go_rtp_ctx_t *ctx,
                                                   el2go_datastore_t *datastore)
{
    el2go_status_t status = EL2GO_STATUS_INVALID_PARAMETER;
    size_t index = 0;

    EL2GO_DBG_TRACE_API_CALL;

    if (!ctx || !datastore)
        goto exit;

    if (ctx->num_datastores == 0) {
        status = EL2GO_STATUS_INVALID_STATE;
        goto exit;
    }

    status = get_datastore_index_by_id(ctx, datastore->id, &index);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "Datastore with id 0x%08" PRIx32 " not found\n", datastore->id);
        goto exit;
    }

    /*
	 * Shift remaining datastores to fill the gap.
	 * Note: Using a simple array with memmove is acceptable here since
	 * the number of datastores is expected to be low (limited by
	 * EL2GO_RTP_MAX_DATASTORES) and does not justify the overhead of
	 * a linked list implementation.
	 */
    if (index < ctx->num_datastores - 1)
        memmove(&ctx->datastores[index], &ctx->datastores[index + 1],
                (ctx->num_datastores - index - 1) * sizeof(el2go_datastore_t *));

    ctx->num_datastores--;
    ctx->datastores[ctx->num_datastores] = NULL;

    status = EL2GO_STATUS_SUCCESS;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

__export el2go_status_t el2go_rtp_get_datastore_by_id(el2go_rtp_ctx_t *ctx, uint32_t id,
                                                      el2go_datastore_t **datastore)
{
    el2go_status_t status = EL2GO_STATUS_INVALID_PARAMETER;
    size_t index = 0;

    EL2GO_DBG_TRACE_API_CALL;

    if (!ctx || !datastore)
        goto exit;

    status = get_datastore_index_by_id(ctx, id, &index);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "Datastore with id 0x%08" PRIx32 " not found\n", id);
        goto exit;
    }

    *datastore = ctx->datastores[index];

    status = EL2GO_STATUS_SUCCESS;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

__export el2go_status_t el2go_rtp_provision(el2go_rtp_ctx_t *ctx, el2go_verbosity_t verbosity)
{
    el2go_status_t status = EL2GO_STATUS_INVALID_PARAMETER;

    EL2GO_DBG_TRACE_API_CALL;

    (void)verbosity;

    if (!ctx)
        goto exit;

    /* TODO: Connect to EdgeLock 2GO server */
    /* TODO: Provision keys and certificates */
    /* TODO: Populate status_report from server response */
    /* TODO: Set result based on provisioning outcome */

    status = EL2GO_STATUS_SUCCESS;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

__export el2go_status_t el2go_rtp_add_keystore(el2go_rtp_ctx_t *ctx, el2go_keystore_t *keystore)
{
    el2go_status_t status = EL2GO_STATUS_INVALID_PARAMETER;
    size_t index = 0;

    EL2GO_DBG_TRACE_API_CALL;

    if (!ctx || !keystore)
        goto exit;

    if (ctx->num_keystores >= EL2GO_RTP_MAX_KEYSTORES) {
        EL2GO_DBG_PRINTF(ERROR, "Unable to register keystore, maximum number reached\n");
        status = EL2GO_STATUS_RESOURCE_LIMIT;
        goto exit;
    }

    /* Check for identifier uniqueness against existing keystores */
    status = get_keystore_index_by_id(ctx, keystore->id, &index);
    if (status == EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR,
                         "Unable to register keystore with id 0x%08" PRIx32
                         ", a keystore with that id is already registered\n",
                         keystore->id);
        status = EL2GO_STATUS_ALREADY_EXISTS;
        goto exit;
    }

    /* Check for identifier uniqueness against existing datastores */
    status = get_datastore_index_by_id(ctx, keystore->id, &index);
    if (status == EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR,
                         "Unable to register keystore with id 0x%08" PRIx32
                         ", a datastore with that id is already registered\n",
                         keystore->id);
        status = EL2GO_STATUS_ALREADY_EXISTS;
        goto exit;
    }

    /* Register the keystore */
    ctx->keystores[ctx->num_keystores] = keystore;
    ctx->num_keystores++;

    status = EL2GO_STATUS_SUCCESS;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

__export el2go_status_t el2go_rtp_remove_keystore(el2go_rtp_ctx_t *ctx, el2go_keystore_t *keystore)
{
    el2go_status_t status = EL2GO_STATUS_INVALID_PARAMETER;
    size_t index = 0;

    EL2GO_DBG_TRACE_API_CALL;

    if (!ctx || !keystore)
        goto exit;

    if (ctx->num_keystores == 0) {
        status = EL2GO_STATUS_INVALID_STATE;
        goto exit;
    }

    status = get_keystore_index_by_id(ctx, keystore->id, &index);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "Keystore with id 0x%08" PRIx32 " not found\n", keystore->id);
        goto exit;
    }

    /*
     * Shift remaining keystores to fill the gap.
     * Note: Using a simple array with memmove is acceptable here since
     * the number of keystores is expected to be low (limited by
     * EL2GO_RTP_MAX_KEYSTORES) and does not justify the overhead of
     * a linked list implementation.
     */
    if (index < ctx->num_keystores - 1)
        memmove(&ctx->keystores[index], &ctx->keystores[index + 1],
                (ctx->num_keystores - index - 1) * sizeof(el2go_keystore_t *));

    ctx->num_keystores--;
    ctx->keystores[ctx->num_keystores] = NULL;

    status = EL2GO_STATUS_SUCCESS;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

__export el2go_status_t el2go_rtp_get_keystore_by_id(el2go_rtp_ctx_t *ctx, uint32_t id,
                                                     el2go_keystore_t **keystore)
{
    el2go_status_t status = EL2GO_STATUS_INVALID_PARAMETER;
    size_t index = 0;

    EL2GO_DBG_TRACE_API_CALL;

    if (!ctx || !keystore)
        goto exit;

    status = get_keystore_index_by_id(ctx, id, &index);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "Keystore with id 0x%08" PRIx32 " not found\n", id);
        goto exit;
    }

    *keystore = ctx->keystores[index];

    status = EL2GO_STATUS_SUCCESS;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

__export el2go_status_t el2go_rtp_get_device_uuid(el2go_rtp_ctx_t *ctx, char *uuid_buffer,
                                                  size_t *buffer_size)
{
    el2go_status_t status = EL2GO_STATUS_INVALID_PARAMETER;

    EL2GO_DBG_TRACE_API_CALL;

    if (!ctx || !uuid_buffer || !buffer_size)
        goto exit;

    status = EL2GO_STATUS_SUCCESS;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}
