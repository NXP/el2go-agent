/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <stddef.h>

#include "compiler.h"
#include "debug.h"
#include "builtin_macros.h"

#include "pb.h"
#include "pb_decode.h"
#include "ServiceDescriptor.pb.h"

#include "common/el2go_datastore.h"
#include "el2go_service.h"

#include "net_crypto.h"

/**
 * @brief Context for streaming checksum calculation from a datastore.
 */
typedef struct {
    el2go_datastore_t *datastore; /**< Pointer to the datastore. */
    size_t offset;                /**< Current read offset in the datastore. */
    size_t remaining;             /**< Number of bytes remaining to read. */
} checksum_fetch_context_t;

/**
 * @brief Context for streaming protobuf decoding from a datastore.
 */
typedef struct ds_stream_ctx_t {
    el2go_datastore_t *datastore; /**< Pointer to the datastore. */
    size_t offset;                /**< Current read offset in the datastore. */
} ds_stream_ctx_t;

/**
 * @brief Service search type selector.
 */
typedef enum { SRV_SEARCH_BY_INDEX, SRV_SEARCH_BY_ID } srv_search_type_t;

/**
 * @brief Criteria used to search for a service descriptor.
 */
typedef struct {
    srv_search_type_t type; /**< Type of search to perform. */
    union {
        size_t index;        /**< Index of the service (used with @ref SRV_SEARCH_BY_INDEX). */
        uint64_t service_id; /**< Service ID to search for (used with @ref SRV_SEARCH_BY_ID). */
    } value;
} srv_search_criteria_t;

/**
 * @brief Protobuf input stream callback to read data from a datastore.
 *
 * @param stream Pointer to the protobuf input stream.
 * @param buf    Buffer to fill with data.
 * @param count  Number of bytes to read.
 * @return @c true on success, @c false on error.
 */
static bool datastore_read_callback(pb_istream_t *stream, uint8_t *buf, size_t count)
{
    ds_stream_ctx_t *ctx = NULL;
    el2go_status_t ret = EL2GO_STATUS_SUCCESS;
    size_t bytes_read = 0;

    if (!stream || !stream->state)
        return false;

    ctx = (ds_stream_ctx_t *)stream->state;

    if (!ctx->datastore)
        return false;

    ret = el2go_datastore_read(ctx->datastore, buf, ctx->offset, count, &bytes_read);

    if (ret != EL2GO_STATUS_SUCCESS && ret != EL2GO_STATUS_INCOMPLETE_READ) {
        EL2GO_DBG_PRINTF(ERROR, "Datastore read failed: 0x%04x\n", ret);
        return false;
    }

    /* Update offset for next read */
    if (ADD_OVERFLOW(ctx->offset, bytes_read, &ctx->offset))
        return false;

    return true;
}
/**
 * @brief Search for a service descriptor in the datastore by index or service ID.
 *
 * Iterates over all service descriptors stored in the datastore and returns
 * the offset and decoded descriptor of the matching service.
 *
 * @param datastore          Pointer to the datastore.
 * @param criteria           Search criteria (by index or by service ID).
 * @param offset             Pointer to store the offset of the matching service descriptor.
 * @param service_descriptor Pointer to store the decoded service descriptor.
 * @return @ref el2go_status_t value, @ref EL2GO_STATUS_SUCCESS on success.
 */
static el2go_status_t srv_get_service_offset(el2go_datastore_t *datastore,
                                             srv_search_criteria_t *criteria, size_t *offset,
                                             nxp_iot_ServiceDescriptor *service_descriptor)
{
    el2go_status_t status = EL2GO_STATUS_INVALID_PARAMETER;
    size_t number_of_services = 0;
    bool pb_status = false;
    bool found = false;
    ds_stream_ctx_t ds_stream_ctx = { 0 };
    pb_istream_t stream = { 0 };
    size_t i = 0;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!datastore || !criteria || !offset || !service_descriptor) {
        EL2GO_DBG_PRINTF(ERROR, "Invalid parameter\n");
        goto exit;
    }

    *offset = sizeof(config_data_hdr_t);
    number_of_services = srv_get_number_of_services(datastore);

    status = EL2GO_STATUS_NOT_FOUND;

    for (i = 0; i < number_of_services; i++) {
        ds_stream_ctx = (ds_stream_ctx_t){ datastore, *offset };
        stream = (pb_istream_t){ &datastore_read_callback, &ds_stream_ctx, EL2GO_PB_SIZE_MAX, 0 };

        pb_release(nxp_iot_ServiceDescriptor_fields, service_descriptor);
        pb_status =
            pb_decode_delimited(&stream, nxp_iot_ServiceDescriptor_fields, service_descriptor);

        if (!pb_status) {
            status = EL2GO_STATUS_INVALID_DATASTORE;
            goto exit;
        }

        /* Check if we found the service we're looking for */
        if (criteria->type == SRV_SEARCH_BY_INDEX) {
            found = (i == criteria->value.index);
        } else {
            found = (service_descriptor->identifier == criteria->value.service_id);
        }

        if (found) {
            status = EL2GO_STATUS_SUCCESS;
            goto exit;
        }

        *offset = ds_stream_ctx.offset;
    }

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

/**
 * @brief Callback to fetch data chunks from the datastore for checksum calculation.
 *
 * This callback is used by @ref net_crypto_sha256_stream to fetch data chunks
 * from the datastore for incremental hash calculation. It is called repeatedly
 * until all remaining bytes have been read, at which point @p bytes_read is set to 0.
 *
 * @param context     Pointer to a @ref checksum_fetch_context_t structure.
 * @param buffer      Buffer to fill with data.
 * @param buffer_size Size of the buffer in bytes.
 * @param bytes_read  Output: number of bytes actually read (0 = end of data).
 * @return @ref el2go_status_t value, @ref EL2GO_STATUS_SUCCESS on success.
 */
static el2go_status_t checksum_fetch_callback(void *context, uint8_t *buffer, size_t buffer_size,
                                              size_t *bytes_read)
{
    checksum_fetch_context_t *ctx = (checksum_fetch_context_t *)context;
    el2go_status_t status = EL2GO_STATUS_INVALID_PARAMETER;
    size_t chunk_size = 0;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!ctx || !buffer || !bytes_read)
        goto exit;

    /* No more data to read */
    if (ctx->remaining == 0) {
        *bytes_read = 0;
        status = EL2GO_STATUS_SUCCESS;
        goto exit;
    }

    /* Calculate chunk size */
    chunk_size = ctx->remaining < buffer_size ? ctx->remaining : buffer_size;

    /* Read from datastore */
    status = el2go_datastore_read(ctx->datastore, buffer, ctx->offset, chunk_size, bytes_read);
    if (status != EL2GO_STATUS_SUCCESS && status != EL2GO_STATUS_INCOMPLETE_READ) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to read from datastore: 0x%04x\n", status);
        goto exit;
    }

    /* Update context */
    if (ADD_OVERFLOW(ctx->offset, *bytes_read, &ctx->offset)) {
        EL2GO_DBG_PRINTF(ERROR, "Offset overflow\n");
        status = EL2GO_STATUS_ARITHMETIC_OVERFLOW;
        goto exit;
    }

    if (SUB_OVERFLOW(ctx->remaining, *bytes_read, &ctx->remaining)) {
        EL2GO_DBG_PRINTF(ERROR, "Remaining underflow\n");
        status = EL2GO_STATUS_ARITHMETIC_OVERFLOW;
        goto exit;
    }

    status = EL2GO_STATUS_SUCCESS;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

/**
 * @brief Calculate SHA-256 checksum of configuration data.
 *
 * Calculates SHA-256 hash of all configuration data following the checksum
 * field in the header. Uses streaming API to process data in chunks.
 *
 * @param datastore           Pointer to the datastore containing configuration data.
 * @param header              Pointer to the configuration data header.
 * @param calculated_checksum Output buffer for the calculated checksum (must be 32 bytes).
 * @return @ref el2go_status_t value, @ref EL2GO_STATUS_SUCCESS on success.
 */
static el2go_status_t calculate_configuration_checksum(el2go_datastore_t *datastore,
                                                       const config_data_hdr_t *header,
                                                       uint8_t *calculated_checksum)
{
    checksum_fetch_context_t ctx = { 0 };
    size_t remaining = 0;

    if (header->length < sizeof(header->checksum)) {
        EL2GO_DBG_PRINTF(ERROR, "Invalid header length: %u\n", header->length);
        return EL2GO_STATUS_INVALID_PARAMETER;
    }

    if (SUB_OVERFLOW(header->length, sizeof(header->checksum), &remaining)) {
        EL2GO_DBG_PRINTF(ERROR, "Arithmetic overflow in remaining length calculation\n");
        return EL2GO_STATUS_ARITHMETIC_OVERFLOW;
    }

    ctx.datastore = datastore;
    ctx.offset = sizeof(header->checksum);
    ctx.remaining = remaining;

    return net_crypto_sha256_stream(checksum_fetch_callback, &ctx, calculated_checksum);
}

/**
 * @brief Validate configuration data checksum.
 *
 * Reads the configuration data header from the datastore, calculates the
 * SHA-256 checksum of all data following the checksum field, and compares
 * it against the stored checksum in the header.
 *
 * @param datastore Pointer to the datastore.
 * @return @ref el2go_status_t value, @ref EL2GO_STATUS_SUCCESS on success.
 */
el2go_status_t srv_validate_configuration_data(el2go_datastore_t *datastore)
{
    config_data_hdr_t header = { 0 };
    uint8_t calculated_checksum[EL2GO_SHA256_CHECKSUM_SIZE] = { 0 };
    el2go_status_t status = EL2GO_STATUS_INVALID_PARAMETER;
    size_t bytes_read = 0;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!datastore) {
        EL2GO_DBG_PRINTF(ERROR, "Invalid datastore parameter\n");
        goto exit;
    }

    /* Read the header from the datastore at offset 0 */
    status = el2go_datastore_read(datastore, &header, 0, sizeof(header), &bytes_read);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to read header: 0x%04x\n", status);
        goto exit;
    }

    /* Validate header length */
    if (header.length < sizeof(header)) {
        EL2GO_DBG_PRINTF(ERROR, "Header length too small: %u\n", header.length);
        status = EL2GO_STATUS_INVALID_DATA;
        goto exit;
    }

    /* Calculate checksum */
    status = calculate_configuration_checksum(datastore, &header, calculated_checksum);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to calculate checksum: 0x%04x\n", status);
        goto exit;
    }

    /* Compare checksums */
    if (memcmp(header.checksum, calculated_checksum, EL2GO_SHA256_CHECKSUM_SIZE) != 0) {
        EL2GO_DBG_PRINTF(ERROR, "Checksum mismatch\n");
        status = EL2GO_STATUS_CHECKSUM_MISMATCH;
        goto exit;
    }

    EL2GO_DBG_PRINTF(VERBOSE, "Configuration data validated successfully\n");
    status = EL2GO_STATUS_SUCCESS;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

size_t srv_get_number_of_services(el2go_datastore_t *datastore)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    config_data_hdr_t header = { 0 };
    size_t bytes_read = 0;

    if (!datastore) {
        EL2GO_DBG_PRINTF(ERROR, "Invalid datastore parameter\n");
        return 0;
    }

    /* Read the header from the datastore at offset 0 */
    status = el2go_datastore_read(datastore, &header, 0, sizeof(header), &bytes_read);

    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to read header: 0x%04x\n", status);
        return 0;
    }

    return (size_t)header.number_of_services;
}

el2go_status_t srv_get_service_by_index(el2go_datastore_t *datastore, size_t index, size_t *offset,
                                        nxp_iot_ServiceDescriptor *service_descriptor)
{
    srv_search_criteria_t criteria = { .type = SRV_SEARCH_BY_INDEX, .value.index = index };

    return srv_get_service_offset(datastore, &criteria, offset, service_descriptor);
}

el2go_status_t srv_get_service_by_id(el2go_datastore_t *datastore, uint64_t service_id,
                                     size_t *offset, nxp_iot_ServiceDescriptor *service_descriptor)
{
    srv_search_criteria_t criteria = { .type = SRV_SEARCH_BY_ID, .value.service_id = service_id };

    return srv_get_service_offset(datastore, &criteria, offset, service_descriptor);
}
