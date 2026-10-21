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
#include "common/el2go_version.h"

#include "compiler.h"
#include "osal.h"
#include "debug.h"
#include "builtin_macros.h"

#include "net_crypto.h"
#include "el2go_server_certificates.h"
#include "el2go_server_connection.h"
#include "el2go_service.h"

#include "keystore_priv.h"
#include "platform_priv.h"

#include "pb.h"
#include "pb_decode.h"
#include "Agent.pb.h"
#include "ServiceDescriptor.pb.h"

#include "el2go_rtp_internal.h"
#include "el2go_dispatcher_priv.h"
#include "rtp/el2go_rtp_timing.h"
#include "el2go_rtp_timing_priv.h"

/* ========================================================================== */
/* nanopb network stream adaptors                                               */
/* ========================================================================== */

/**
 * @brief nanopb ostream write callback - forwards encoded bytes to the TLS layer.
 */
static bool net_write_callback(pb_ostream_t *stream, const pb_byte_t *buf, size_t count)
{
    net_crypto_ctx_t *net_ctx = (net_crypto_ctx_t *)stream->state;
    int written = net_crypto_write(net_ctx, buf, count);
    if (written < 0)
        return false;
    return (size_t)written == count;
}

/**
 * @brief nanopb istream read callback - receives bytes from the TLS layer.
 */
static bool net_read_callback(pb_istream_t *stream, pb_byte_t *buf, size_t count)
{
    net_crypto_ctx_t *net_ctx = (net_crypto_ctx_t *)stream->state;
    int rd = 0;

    while (count > 0U) {
        rd = net_crypto_read(net_ctx, buf, count);
        if (rd <= 0) {
            stream->bytes_left = 0U;
            break;
        }
        buf += rd;
        count -= (size_t)rd;
    }
    return (count == 0U);
}

/**
 * @brief Construct a nanopb output stream backed by a TLS connection.
 */
static pb_ostream_t ostream_from_net(net_crypto_ctx_t *net_ctx)
{
    pb_ostream_t s = { &net_write_callback, net_ctx, SIZE_MAX, 0U, NULL };
    return s;
}

/**
 * @brief Construct a nanopb input stream backed by a TLS connection.
 */
static pb_istream_t istream_from_net(net_crypto_ctx_t *net_ctx)
{
    pb_istream_t s = { &net_read_callback, net_ctx, SIZE_MAX, NULL };
    return s;
}

/**
 * @brief Get or generate the client certificate for EL2GO connection
 *
 * Tries to get the client certificate from the keystore/platform first.
 * If not available, generates a self-signed certificate using the key ID
 * and device UUID from the platform.
 *
 * @param[in] keystore_ctx Keystore context
 * @param[in] key_id ECC key ID to use for self-signed certificate generation
 * @param[out] client_cert_buf Buffer to store the certificate
 * @param[in,out] client_cert_len On input, size of buffer; on output, actual certificate length
 *
 * @return EL2GO_STATUS_SUCCESS on success, error code otherwise
 */

static el2go_status_t get_el2go_client_cert(el2go_keystore_t *keystore_ctx, uint32_t key_id,
                                            uint8_t *client_cert_buf, size_t *client_cert_len)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    uint8_t device_uuid[EL2GO_UUID_MAX_LEN];
    size_t device_uuid_len = 0;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    /* Try to get client certificate from keystore/platform first */
    status = el2go_keystore_get_el2go_cert(keystore_ctx, client_cert_buf, client_cert_len);
    if (status == EL2GO_STATUS_CERT_NOT_AVAILABLE) {
        EL2GO_DBG_PRINTF(VERBOSE, "No platform certificate, generating self-signed\n");

        /* Get device UUID from platform into stack buffer */
        status = el2go_platform_get_uuid(keystore_ctx->platform_ctx, device_uuid,
                                         sizeof(device_uuid), &device_uuid_len);
        if (status != EL2GO_STATUS_SUCCESS) {
            EL2GO_DBG_PRINTF(ERROR, "Failed to get device UUID: 0x%04x\n", status);
            goto exit;
        }

        /* Generate self-signed client certificate */
        status = net_crypto_self_signed_cert(EL2GO_RTP_SUBJECT, key_id, device_uuid,
                                             device_uuid_len, client_cert_buf, client_cert_len);
        if (status != EL2GO_STATUS_SUCCESS) {
            EL2GO_DBG_PRINTF(ERROR,
                             "Failed to generate self-signed certificate: "
                             "0x%04x\n",
                             status);
            goto exit;
        }

        EL2GO_DBG_PRINTF(VERBOSE, "Generated self-signed client certificate (%zu bytes)\n",
                         *client_cert_len);
    } else if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR,
                         "Failed to get client certificate from keystore: "
                         "0x%04x\n",
                         status);
        goto exit;
    } else {
        EL2GO_DBG_PRINTF(VERBOSE, "Using keystore client certificate (%zu bytes)\n",
                         *client_cert_len);
    }

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

__export el2go_status_t el2go_rtp_datastore_el2go(el2go_datastore_t *datastore,
                                                  el2go_keystore_t *keystore_ctx,
                                                  const el2go_rtp_datastore_config_t *config)
{
    el2go_status_t status = EL2GO_STATUS_INVALID_PARAMETER;
    const char *hostname = NULL;
    uint16_t port = 0;
    pb_bytes_array_t *cert_array = NULL;
    const pb_bytes_array_t *cert = NULL;
    bool user_provided_host = false;
    bool user_provided_cert = false;

    uint32_t key_id = 0;
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
        user_provided_host = true;
        EL2GO_DBG_PRINTF(VERBOSE, "Using hostname and port from config\n");
    } else {
        hostname = EL2GO_RTP_EDGELOCK2GO_HOSTNAME;
        port = EL2GO_RTP_EDGELOCK2GO_PORT;
        EL2GO_DBG_PRINTF(VERBOSE,
                         "No hostname/port in config, "
                         "using defaults: %s:%u\n",
                         hostname, port);
    }

    EL2GO_DBG_PRINTF(VERBOSE, "Using EdgeLock 2GO server: %s:%u\n", hostname, port);

    if (user_provided_host &&
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
    status = get_el2go_client_cert(keystore_ctx, key_id, client_cert_buf.bytes, &client_cert_len);
    if (status != EL2GO_STATUS_SUCCESS) {
        goto exit;
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
        user_provided_cert = true;
        EL2GO_DBG_PRINTF(VERBOSE, "Using certificate from config (%zu bytes)\n",
                         config->certificate->len);
    } else {
        cert = el2go_get_default_certs();
        EL2GO_DBG_PRINTF(VERBOSE, "No certificate in config, using default\n");
    }

    if (user_provided_cert &&
        !el2go_conn_datastore_needs_update(datastore, hostname, port, config->certificate)) {
        status = EL2GO_STATUS_SUCCESS;
        goto exit;
    }

    EL2GO_DBG_PRINTF(VERBOSE, "Updating EdgeLock 2GO datastore with %s:%u\n", hostname, port);

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

    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}
/**
 * @brief Get datastore index by identifier.
 *
 * Searches through the registered datastores in the agent context to find a
 * datastore with the specified identifier. If found, the index of the datastore
 * in the internal array is returned through @p index.
 *
 * @param[in]  ctx   RTP agent context
 * @param[in]  id    Datastore identifier to search for
 * @param[out] index Pointer to store the found index
 *
 * @return EL2GO_STATUS_SUCCESS on success, error code otherwise
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
 * @brief Get keystore index by identifier.
 *
 * Searches through the registered keystores in the agent context to find a
 * keystore with the specified identifier. If found, the index of the keystore
 * in the internal array is returned through @p index.
 *
 * @param[in]  ctx   RTP agent context
 * @param[in]  id    Keystore identifier to search for
 * @param[out] index Pointer to store the found index
 *
 * @return EL2GO_STATUS_SUCCESS on success, error code otherwise
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

__export el2go_status_t el2go_rtp_get_version(unsigned int *major, unsigned int *minor,
                                              unsigned int *patch)
{
    el2go_status_t status = EL2GO_STATUS_INVALID_PARAMETER;

    EL2GO_DBG_TRACE_API_CALL;

    if (major == NULL || minor == NULL || patch == NULL)
        goto exit;

    *major = EL2GO_LIB_VERSION_MAJOR;
    *minor = EL2GO_LIB_VERSION_MINOR;
    *patch = EL2GO_LIB_VERSION_PATCH;

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

    /* EL2GO datastore is treated specially - stored in dedicated pointer */
    if (datastore->id == EL2GO_RTP_DATASTORE_EDGELOCK_ID) {
        if (ctx->el2go_datastore) {
            EL2GO_DBG_PRINTF(ERROR, "EL2GO datastore already set\n");
            status = EL2GO_STATUS_ALREADY_EXISTS;
            goto exit;
        }

        ctx->el2go_datastore = datastore;
        EL2GO_DBG_PRINTF(VERBOSE, "EL2GO datastore added\n");
        status = EL2GO_STATUS_SUCCESS;
        goto exit;
    }

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

    /* Handle special EL2GO datastore */
    if (datastore->id == EL2GO_RTP_DATASTORE_EDGELOCK_ID) {
        if (!ctx->el2go_datastore) {
            EL2GO_DBG_PRINTF(ERROR, "EL2GO datastore not set\n");
            status = EL2GO_STATUS_INVALID_STATE;
            goto exit;
        }

        ctx->el2go_datastore = NULL;
        EL2GO_DBG_PRINTF(VERBOSE, "EL2GO datastore removed\n");
        status = EL2GO_STATUS_SUCCESS;
        goto exit;
    }

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

    /* Handle special EL2GO datastore */
    if (id == EL2GO_RTP_DATASTORE_EDGELOCK_ID) {
        if (!ctx->el2go_datastore) {
            EL2GO_DBG_PRINTF(ERROR, "EL2GO datastore not set\n");
            status = EL2GO_STATUS_NOT_FOUND;
            goto exit;
        }

        *datastore = ctx->el2go_datastore;
        status = EL2GO_STATUS_SUCCESS;
        goto exit;
    }

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

/**
 * @brief Find and return the EL2GOSERVICE descriptor from a datastore.
 *
 * Searches the datastore for a service descriptor of type EL2GOSERVICE and
 * populates the caller-provided descriptor with the found data.
 *
 * @param[in]  datastore          EL2GO datastore containing the service descriptor
 * @param[out] service_descriptor Caller-owned descriptor to populate; must be released by caller
 *
 * @return EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
static el2go_status_t get_el2go_service_descriptor(el2go_datastore_t *datastore,
                                                   nxp_iot_ServiceDescriptor *service_descriptor)
{
    el2go_status_t status = EL2GO_STATUS_INVALID_PARAMETER;
    size_t num_services = 0;
    size_t offset = 0;
    size_t i = 0;
    bool found = false;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!datastore || !service_descriptor)
        goto exit;

    num_services = srv_get_number_of_services(datastore);
    if (num_services == 0) {
        EL2GO_DBG_PRINTF(ERROR, "No services in EL2GO datastore\n");
        status = EL2GO_STATUS_NOT_FOUND;
        goto exit;
    }

    /* Search for EL2GOSERVICE type service descriptor */
    for (i = 0; i < num_services; i++) {
        offset = 0;
        pb_release(nxp_iot_ServiceDescriptor_fields, service_descriptor);
        *service_descriptor = (nxp_iot_ServiceDescriptor)nxp_iot_ServiceDescriptor_init_default;

        status = srv_get_service_by_index(datastore, i, &offset, service_descriptor);
        if (status != EL2GO_STATUS_SUCCESS) {
            EL2GO_DBG_PRINTF(ERROR,
                             "Failed to read service descriptor %zu: "
                             "0x%04x\n",
                             i, status);
            goto exit;
        }

        if (service_descriptor->has_service_type &&
            service_descriptor->service_type == nxp_iot_ServiceType_EL2GOSERVICE) {
            found = true;
            break;
        }
    }

    if (!found) {
        EL2GO_DBG_PRINTF(ERROR, "No EL2GOSERVICE descriptor found in datastore\n");
        status = EL2GO_STATUS_NOT_FOUND;
        goto exit;
    }

    EL2GO_DBG_PRINTF(VERBOSE, "Found EL2GOSERVICE descriptor\n");

    status = EL2GO_STATUS_SUCCESS;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

__export el2go_status_t el2go_rtp_provision(el2go_rtp_ctx_t *ctx, void **status_report)
{
    el2go_status_t status = EL2GO_STATUS_INVALID_PARAMETER;
    const char *hostname = NULL;
    uint16_t port = 0;
    uint32_t key_id = 0;
    el2go_keystore_t *keystore = NULL;
    uint8_t *client_cert_buf = NULL;
    size_t client_cert_buf_len = EL2GO_RTP_CLIENT_CERT_MAX_SIZE;
    const uint8_t *client_cert = NULL;
    size_t client_cert_len = 0;
    const uint8_t *server_cert = NULL;
    size_t server_cert_len = 0;
    bool use_compile_time_config = false;
    nxp_iot_ServiceDescriptor service_descriptor = nxp_iot_ServiceDescriptor_init_default;
    const pb_bytes_array_t *default_certs = NULL;
    net_crypto_ctx_t *net_ctx = NULL;
    net_crypto_config_t net_config = { 0 };
    el2go_cipher_list_t cipher_list = { 0 };
    el2go_curve_list_t curve_list = { 0 };
    nxp_iot_UpdateStatusReport *report = NULL;

    EL2GO_DBG_TRACE_API_CALL;

    if (!ctx)
        goto exit;

    /* Find the keystore registered with EL2GO keystore ID */
    status = el2go_rtp_get_keystore_by_id(ctx, EL2GO_RTP_EDGELOCK2GO_KEYSTORE_ID, &keystore);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "EL2GO keystore not found\n");
        goto exit;
    }

    /* Check if EL2GO datastore is set and valid */
    if (!ctx->el2go_datastore) {
        EL2GO_DBG_PRINTF(VERBOSE, "EL2GO datastore not set, using compile-time constants\n");
        use_compile_time_config = true;
    } else {
        status = srv_validate_configuration_data(ctx->el2go_datastore);
        if (status != EL2GO_STATUS_SUCCESS) {
            EL2GO_DBG_PRINTF(VERBOSE,
                             "EL2GO datastore invalid (0x%04x), "
                             "using compile-time constants\n",
                             status);
            use_compile_time_config = true;
        }
    }

    if (use_compile_time_config) {
        /* Use compile-time constants for connection parameters */
        hostname = EL2GO_RTP_EDGELOCK2GO_HOSTNAME;
        port = EL2GO_RTP_EDGELOCK2GO_PORT;

        /* Get default server certificates */
        default_certs = el2go_get_default_certs();
        if (!default_certs) {
            EL2GO_DBG_PRINTF(ERROR, "Failed to get default server certificates\n");
            status = EL2GO_STATUS_FAILURE;
            goto exit;
        }
        server_cert = default_certs->bytes;
        server_cert_len = default_certs->size;

        /* Get key ID from keystore */
        status = el2go_keystore_get_el2go_key_id(keystore, &key_id);
        if (status != EL2GO_STATUS_SUCCESS) {
            EL2GO_DBG_PRINTF(ERROR, "Failed to get EL2GO key ID: 0x%04x\n", status);
            goto exit;
        }

        /* Allocate and zero client certificate buffer - mbedtls_x509write_crt_der
         * uses the entire buffer as scratch space; uninitialized bytes cause
         * Valgrind errors and a stack-smash abort during ECDSA/ECP parsing. */
        client_cert_buf = osal_calloc(1, EL2GO_RTP_CLIENT_CERT_MAX_SIZE);
        if (!client_cert_buf) {
            EL2GO_DBG_PRINTF(ERROR, "Failed to allocate client certificate buffer\n");
            status = EL2GO_STATUS_ALLOCATION_ERROR;
            goto exit;
        }

        /* Get or generate client certificate */
        status = get_el2go_client_cert(keystore, key_id, client_cert_buf, &client_cert_buf_len);
        if (status != EL2GO_STATUS_SUCCESS) {
            EL2GO_DBG_PRINTF(ERROR, "Failed to get client certificate: 0x%04x\n", status);
            goto exit;
        }

        /* Point client_cert to the allocated buffer */
        client_cert = client_cert_buf;
        client_cert_len = client_cert_buf_len;

        EL2GO_DBG_PRINTF(VERBOSE, "Using compile-time config: %s:%u\n", hostname, port);
    } else {
        EL2GO_DBG_PRINTF(VERBOSE, "EL2GO datastore is valid, reading config\n");

        status = get_el2go_service_descriptor(ctx->el2go_datastore, &service_descriptor);
        if (status != EL2GO_STATUS_SUCCESS) {
            EL2GO_DBG_PRINTF(ERROR,
                             "Failed to get EL2GO service descriptor: "
                             "0x%04x\n",
                             status);
            goto exit;
        }

        /* Extract connection parameters from service descriptor */
        hostname = service_descriptor.hostname;
        port = (uint16_t)service_descriptor.port;
        key_id = service_descriptor.client_key_sss_ref.object_id;
        server_cert = service_descriptor.server_certificate->bytes;
        server_cert_len = service_descriptor.server_certificate->size;

        /* Get client certificate from service descriptor - no allocation */
        status = el2go_keystore_get_cert_from_srv_desc(keystore, &service_descriptor, &client_cert,
                                                       &client_cert_len);
        if (status != EL2GO_STATUS_SUCCESS) {
            EL2GO_DBG_PRINTF(ERROR,
                             "Failed to get client certificate from service "
                             "descriptor: 0x%04x\n",
                             status);
            goto exit;
        }

        EL2GO_DBG_PRINTF(VERBOSE,
                         "Using datastore config: %s:%u key_id: 0x%08" PRIx32
                         " client_cert: %zu bytes "
                         "server_cert: %zu bytes\n",
                         hostname, port, key_id, client_cert_len, server_cert_len);
    }

    /* 1. Create network crypto context */
    EL2GO_TIMING_START(ctx, tls_prep);
    status = net_crypto_new(&net_ctx);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to create net crypto context: 0x%04x\n", status);
        goto exit;
    }

    /* 2. Configure connection (hostname, port) */
    net_config.hostname = hostname;
    net_config.port = port;
    status = net_crypto_configure(net_ctx, &net_config);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to configure net crypto context: 0x%04x\n", status);
        goto exit;
    }

    /* 3. Set trusted root CA certificates for server verification */
    status = net_crypto_set_server_cert(net_ctx, server_cert, server_cert_len);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to set server certificate: 0x%04x\n", status);
        goto exit;
    }

    /* 4. Set client certificate for mutual TLS authentication */
    status = net_crypto_set_cli_cert(net_ctx, client_cert, client_cert_len);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to set client certificate: 0x%04x\n", status);
        goto exit;
    }

    /* 5. Associate the private key from HSM */
    status = net_crypto_associate_key(net_ctx, key_id);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to associate private key: 0x%04x\n", status);
        goto exit;
    }

    /* 6. Configure platform cipher suites */
    cipher_list = el2go_platform_get_cipher_suites();
    status = net_crypto_set_cipher_suites(net_ctx, &cipher_list);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to set cipher suites: 0x%04x\n", status);
        goto exit;
    }

    /* 7. Configure platform curves */
    curve_list = el2go_platform_get_curves();
    status = net_crypto_set_curves(net_ctx, &curve_list);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to set curves: 0x%04x\n", status);
        goto exit;
    }

    EL2GO_TIMING_STOP(ctx, tls_prep);

    /* 8. Connect to EdgeLock 2GO server */
    EL2GO_TIMING_START(ctx, network_connect);
    status = net_crypto_connect(net_ctx);
    EL2GO_TIMING_STOP(ctx, network_connect);

    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to connect to EL2GO server: 0x%04x\n", status);
        goto exit;
    }

    EL2GO_DBG_PRINTF(VERBOSE, "Connected to EL2GO server successfully\n");

    /* 9. Allocate status report buffer unconditionally so that dispatch always
     * has a place to write the provisioning outcome.  If the caller did not
     * request the report it will be freed in the exit block. */
    report = (nxp_iot_UpdateStatusReport *)osal_calloc(1, sizeof(nxp_iot_UpdateStatusReport));
    if (!report) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to allocate status report buffer\n");
        status = EL2GO_STATUS_ALLOCATION_ERROR;
        goto exit;
    }

    /* 10. Run the provisioning dispatch loop */
    pb_istream_t istream = istream_from_net(net_ctx);
    pb_ostream_t ostream = ostream_from_net(net_ctx);
    status = el2go_rtp_dispatch(ctx, &istream, &ostream, report);
    if (status == EL2GO_STATUS_RTP_PROVISIONING_FAILED) {
        /* Provisioning completed but one or more objects failed - outcome
         * is captured in the status report, so this is not an unexpected
         * error and does not warrant an ERROR log. */
        EL2GO_DBG_PRINTF(INFO, "Provisioning completed with failures, see status report\n");
        goto exit;
    } else if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "Provisioning dispatch failed: 0x%04x\n", status);
        goto exit;
    }

    EL2GO_DBG_PRINTF(VERBOSE, "Provisioning completed successfully\n");

exit:
    if (net_ctx) {
        net_crypto_disconnect(net_ctx);
        net_crypto_free(&net_ctx);
    }
    /* Only free the heap allocated buffer - datastore path points into service_descriptor */
    if (client_cert_buf)
        osal_free(client_cert_buf);
    pb_release(nxp_iot_ServiceDescriptor_fields, &service_descriptor);

    /* Transfer report ownership to the caller unconditionally.
     * The report is valid whenever dispatch ran (including server-side failures).
     * If the caller did not request a report, free any allocated buffer. */
    if (status_report != NULL) {
        *status_report = report;
    } else if (report) {
        pb_release(nxp_iot_UpdateStatusReport_fields, report);
        osal_free(report);
    }

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

__export const char *el2go_rtp_get_error_string(el2go_status_t status)
{
    switch (status) {
    case EL2GO_STATUS_SUCCESS:
        return "Success";
    case EL2GO_STATUS_FAILURE:
        return "Generic failure";
    case EL2GO_STATUS_FILE_OPEN_ERROR:
        return "Failed to open file";
    case EL2GO_STATUS_FILE_CLOSE_ERROR:
        return "Failed to close file";
    case EL2GO_STATUS_FILE_WRITE_ERROR:
        return "Failed to write/flush file";
    case EL2GO_STATUS_FILE_SEEK_ERROR:
        return "Failed to seek in file";
    case EL2GO_STATUS_FILE_TELL_ERROR:
        return "Failed to query file position";
    case EL2GO_STATUS_INVALID_PARAMETER:
        return "Invalid parameter";
    case EL2GO_STATUS_INVALID_POINTER:
        return "Invalid pointer";
    case EL2GO_STATUS_INVALID_STATE:
        return "Invalid state";
    case EL2GO_STATUS_INVALID_DATA:
        return "Invalid or malformed data";
    case EL2GO_STATUS_ALLOCATION_ERROR:
        return "Memory allocation failed";
    case EL2GO_STATUS_BUFFER_TOO_SMALL:
        return "Buffer too small";
    case EL2GO_STATUS_NOT_FOUND:
        return "Resource not found";
    case EL2GO_STATUS_ALREADY_EXISTS:
        return "Resource already exists";
    case EL2GO_STATUS_RESOURCE_LIMIT:
        return "Resource limit reached";
    case EL2GO_STATUS_ARITHMETIC_OVERFLOW:
        return "Arithmetic overflow detected";
    case EL2GO_STATUS_NOT_IMPLEMENTED:
        return "Not implemented";
    case EL2GO_STATUS_UNSUPPORTED_OPERATION:
        return "Unsupported operation";
    case EL2GO_STATUS_PLATFORM_INIT_FAILED:
        return "Platform initialisation failed";
    case EL2GO_STATUS_PLATFORM_SMW_ERROR:
        return "SMW platform operation failed";
    case EL2GO_STATUS_NET_CRYPTO_CONFIG_FAILED:
        return "Network crypto configuration failed";
    case EL2GO_STATUS_NET_CRYPTO_INVALID_KEY:
        return "Invalid or unavailable key for network crypto";
    case EL2GO_STATUS_NET_CRYPTO_CONNECT_FAILED:
        return "TCP connection to server failed";
    case EL2GO_STATUS_NET_CRYPTO_SSL_CONFIG_FAILED:
        return "SSL/TLS configuration failed";
    case EL2GO_STATUS_NET_CRYPTO_SSL_SETUP_FAILED:
        return "SSL/TLS context setup failed";
    case EL2GO_STATUS_NET_CRYPTO_HANDSHAKE_FAILED:
        return "TLS handshake failed";
    case EL2GO_STATUS_NET_CRYPTO_CERT_VERIFY_FAILED:
        return "Server certificate verification failed";
    case EL2GO_STATUS_NET_CRYPTO_HOSTNAME_FAILED:
        return "Failed to set SNI hostname";
    case EL2GO_STATUS_NET_CRYPTO_INVALID_CERT:
        return "Certificate invalid or could not be parsed";
    case EL2GO_STATUS_NET_CRYPTO_SHA_ERROR:
        return "SHA hashing operation failed";
    case EL2GO_STATUS_NET_CRYPTO_NOT_CONNECTED:
        return "Network crypto connection not established";
    case EL2GO_STATUS_CERT_NOT_AVAILABLE:
        return "Certificate not available";
    case EL2GO_STATUS_INVALID_DATASTORE:
        return "Datastore invalid or corrupted";
    case EL2GO_STATUS_INCOMPLETE_DATA:
        return "Incomplete data";
    case EL2GO_STATUS_INCOMPLETE_READ:
        return "Read operation incomplete";
    case EL2GO_STATUS_INCOMPLETE_WRITE:
        return "Write operation incomplete";
    case EL2GO_STATUS_CHECKSUM_MISMATCH:
        return "Checksum verification failed";
    case EL2GO_STATUS_INVALID_REQUEST:
        return "Invalid request";
    case EL2GO_STATUS_PSA_ERROR:
        return "PSA API returned an error";
    case EL2GO_STATUS_RTP_DECODE_ERROR:
        return "Failed to decode RTP protobuf message";
    case EL2GO_STATUS_RTP_ENCODE_ERROR:
        return "Failed to encode RTP protobuf response";
    case EL2GO_STATUS_RTP_ENDPOINT_NOT_FOUND:
        return "No registered endpoint matches the request";
    case EL2GO_STATUS_RTP_CRL_NOT_VERIFIED:
        return "Non-CRL message received before CRL verification";
    case EL2GO_STATUS_RTP_PROVISIONING_FAILED:
        return "Server reported provisioning failure";
    default:
        return "Unknown error";
    }
}
