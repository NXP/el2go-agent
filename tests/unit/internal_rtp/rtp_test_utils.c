/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2026 NXP
 */

#include <string.h>

#include "osal.h"
#include "debug.h"
#include "net_crypto.h"

#include "pb.h"
#include "pb_encode.h"

#include "el2go_service.h"
#include "rtp_test_utils.h"

/* ========================================================================== */
/* Internal types                                                             */
/* ========================================================================== */

/**
 * @brief Context for buffer-based checksum calculation.
 */
typedef struct {
    const uint8_t *buffer; /**< Pointer to the buffer. */
    size_t offset;         /**< Current read offset. */
    size_t remaining;      /**< Number of bytes remaining. */
} buffer_fetch_context_t;

/* ========================================================================== */
/* Internal functions                                                         */
/* ========================================================================== */

/**
 * @brief Callback to fetch data chunks from a buffer for checksum calculation.
 */
static el2go_status_t buffer_fetch_callback(void *context, uint8_t *buffer, size_t buffer_size,
                                            size_t *bytes_read)
{
    buffer_fetch_context_t *ctx = (buffer_fetch_context_t *)context;

    if (!ctx || !buffer || !bytes_read)
        return EL2GO_STATUS_INVALID_PARAMETER;

    if (ctx->remaining == 0) {
        *bytes_read = 0;
        return EL2GO_STATUS_SUCCESS;
    }

    size_t chunk_size = ctx->remaining < buffer_size ? ctx->remaining : buffer_size;

    memcpy(buffer, ctx->buffer + ctx->offset, chunk_size);

    *bytes_read = chunk_size;
    ctx->offset += chunk_size;
    ctx->remaining -= chunk_size;

    return EL2GO_STATUS_SUCCESS;
}

/* ========================================================================== */
/* Public functions                                                           */
/* ========================================================================== */

el2go_status_t srv_add_service(el2go_datastore_t *datastore,
                               const nxp_iot_ServiceDescriptor *service_descriptor)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    config_data_hdr_t header = { 0 };
    pb_ostream_t sizing_stream = PB_OSTREAM_SIZING;
    pb_ostream_t ostream = { 0 };
    bool pb_status = false;
    size_t encoded_size = 0;
    size_t total_size = 0;
    size_t write_offset = 0;
    uint8_t *buffer = NULL;
    size_t bytes_read = 0;
    size_t bytes_written = 0;

    if (!datastore || !service_descriptor) {
        status = EL2GO_STATUS_INVALID_PARAMETER;
        goto exit;
    }

    /* First pass: calculate encoded size of service descriptor */
    pb_status =
        pb_encode_delimited(&sizing_stream, nxp_iot_ServiceDescriptor_fields, service_descriptor);
    if (!pb_status) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to calculate service descriptor size\n");
        status = EL2GO_STATUS_FAILURE;
        goto exit;
    }

    encoded_size = sizing_stream.bytes_written;

    /* Try to read existing header */
    status = el2go_datastore_read(datastore, &header, 0, sizeof(header), &bytes_read);
    if (status != EL2GO_STATUS_SUCCESS) {
        /* No existing header - initialize a new one */
        memset(&header, 0, sizeof(header));
        header.number_of_services = 0;
        header.version = EL2GO_CONFIGURATION_DATA_VERSION;
        header.length = sizeof(header);
    }

    /* Calculate total size including new service descriptor */
    total_size = header.length + encoded_size;

    /* Allocate buffer for the entire datastore content */
    buffer = osal_malloc(total_size);
    if (!buffer) {
        status = EL2GO_STATUS_ALLOCATION_ERROR;
        goto exit;
    }

    /* Read existing content if any services exist */
    if (header.number_of_services > 0) {
        status = el2go_datastore_read(datastore, buffer, 0, header.length, &bytes_read);
        if (status != EL2GO_STATUS_SUCCESS) {
            EL2GO_DBG_PRINTF(ERROR, "Failed to read existing datastore content\n");
            goto exit;
        }
    } else {
        /* Initialize buffer with zeroed header */
        memset(buffer, 0, sizeof(header));
    }

    /* Encode new service descriptor at the end */
    write_offset = header.length;
    ostream = pb_ostream_from_buffer(buffer + write_offset, encoded_size);
    pb_status = pb_encode_delimited(&ostream, nxp_iot_ServiceDescriptor_fields, service_descriptor);
    if (!pb_status) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to encode service descriptor\n");
        status = EL2GO_STATUS_FAILURE;
        goto exit;
    }

    /* Update header fields */
    header.number_of_services++;
    header.length = (uint32_t)total_size;
    header.version = EL2GO_CONFIGURATION_DATA_VERSION;

    /* Write updated header into buffer FIRST before calculating checksum */
    memcpy(buffer, &header, sizeof(header));

    /* Calculate checksum over everything after the checksum field */
    buffer_fetch_context_t fetch_ctx = { .buffer = buffer + sizeof(header.checksum),
                                         .offset = 0,
                                         .remaining = total_size - sizeof(header.checksum) };

    status = net_crypto_sha256_stream(buffer_fetch_callback, &fetch_ctx, header.checksum);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to calculate checksum\n");
        goto exit;
    }

    /* Write checksum back into buffer */
    memcpy(buffer, &header, sizeof(header));

    /* Allocate and write to datastore */
    status = el2go_datastore_allocate(datastore, total_size);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to allocate datastore\n");
        goto exit;
    }

    status = el2go_datastore_write(datastore, buffer, 0, total_size, &bytes_written);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to write datastore\n");
        goto exit;
    }

    status = el2go_datastore_commit(datastore);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to commit datastore\n");
        goto exit;
    }

exit:
    if (buffer)
        osal_free(buffer);

    return status;
}