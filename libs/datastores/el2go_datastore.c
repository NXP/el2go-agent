/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <stddef.h>
#include <string.h>
#include <stdbool.h>

#include "compiler.h"
#include "debug.h"
#include "builtin_macros.h"
#include "osal.h"

#include "common/el2go_datastore.h"
#include "el2go_datastore_plain.h"
#include "el2go_datastore_fs.h"

#include "pb.h"
#include "pb_encode.h"
#include "pb_decode.h"

#include "Dispatcher.pb.h"
#include "Agent.pb.h"
#include "Datastore.pb.h"

#include "datastore_priv.h"

typedef el2go_status_t (*datastore_create_fn_t)(el2go_datastore_t *datastore, const char *basename);

static const datastore_create_fn_t datastore_create_functions[] = {
    [EL2GO_DATASTORE_TYPE_FS] = el2go_datastore_fs_create,
    [EL2GO_DATASTORE_TYPE_PLAIN] = el2go_datastore_plain_create,
    [EL2GO_DATASTORE_TYPE_CUSTOM] = NULL,
};

__export el2go_status_t el2go_datastore_init(uint32_t id, const char *name,
                                             el2go_datastore_type_t type,
                                             el2go_datastore_t *datastore,
                                             el2go_datastore_validator_t validator)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    size_t name_len = 0;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!datastore || !name) {
        status = EL2GO_STATUS_INVALID_PARAMETER;
        goto exit;
    }

    name_len = strlen(name);
    if (INC_OVERFLOW(name_len, 1)) {
        status = EL2GO_STATUS_ARITHMETIC_OVERFLOW;
        goto exit;
    }

    datastore->name = (char *)osal_calloc(name_len, sizeof(char));
    if (!datastore->name) {
        status = EL2GO_STATUS_ALLOCATION_ERROR;
        goto exit;
    }

    memcpy(datastore->name, name, name_len - 1);

    datastore->id = id;
    datastore->type = type;
    datastore->priv = NULL;

    if (type >= ARRAY_SIZE(datastore_create_functions)) {
        status = EL2GO_STATUS_INVALID_PARAMETER;
        goto cleanup;
    }

    if (datastore_create_functions[type]) {
        status = datastore_create_functions[type](datastore, name);
        if (status != EL2GO_STATUS_SUCCESS) {
            goto cleanup;
        }
    }

    if (!datastore->ops || !datastore->ops->init) {
        status = EL2GO_STATUS_INVALID_POINTER;
        goto cleanup;
    }

    status = datastore->ops->init(datastore->context, validator);
    if (status == EL2GO_STATUS_SUCCESS) {
        goto exit;
    }

cleanup:
    if (datastore->name) {
        osal_free(datastore->name);
        datastore->name = NULL;
    }

    (void)el2go_datastore_free(datastore);

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

__export el2go_status_t el2go_datastore_allocate(el2go_datastore_t *datastore, size_t len)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (len == 0 || !datastore || !datastore->ops || !datastore->ops->allocate) {
        status = EL2GO_STATUS_INVALID_PARAMETER;
        goto exit;
    }

    status = datastore->ops->allocate(datastore->context, len);

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

__export el2go_status_t el2go_datastore_read(el2go_datastore_t *datastore, void *dest,
                                             size_t offset, size_t len, size_t *bytes_read)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (len == 0 || !dest || !datastore || !datastore->ops || !datastore->ops->read ||
        !bytes_read) {
        status = EL2GO_STATUS_INVALID_PARAMETER;
        goto exit;
    }

    *bytes_read = 0;

    status = datastore->ops->read(datastore->context, dest, offset, len, bytes_read);

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

__export el2go_status_t el2go_datastore_write(el2go_datastore_t *datastore, const void *src,
                                              size_t offset, size_t len, size_t *bytes_written)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (len == 0 || !src || !datastore || !datastore->ops || !datastore->ops->write ||
        !bytes_written) {
        status = EL2GO_STATUS_INVALID_PARAMETER;
        goto exit;
    }

    *bytes_written = 0;

    status = datastore->ops->write(datastore->context, src, offset, len, bytes_written);

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

el2go_status_t el2go_datastore_get_size(el2go_datastore_t *datastore, size_t *size)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!size || !datastore || !datastore->ops || !datastore->ops->get_size) {
        status = EL2GO_STATUS_INVALID_PARAMETER;
        goto exit;
    }

    *size = 0;

    status = datastore->ops->get_size(datastore->context, size);

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

__export el2go_status_t el2go_datastore_commit(el2go_datastore_t *datastore)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!datastore || !datastore->ops || !datastore->ops->commit) {
        status = EL2GO_STATUS_INVALID_PARAMETER;
        goto exit;
    }

    status = datastore->ops->commit(datastore->context);

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

__export el2go_status_t el2go_datastore_free(el2go_datastore_t *datastore)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!datastore) {
        status = EL2GO_STATUS_INVALID_PARAMETER;
        goto exit;
    }

    if (datastore->context && datastore->ops && datastore->ops->free)
        status = datastore->ops->free(datastore->context);

    if (datastore->name) {
        osal_free(datastore->name);
        datastore->name = NULL;
    }

    datastore->context = NULL;
    datastore->ops = NULL;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

nxp_iot_EndpointType el2go_datastore_get_endpoint_type(const el2go_datastore_t *datastore)
{
    if (!datastore)
        return nxp_iot_EndpointType_INVALID;

    switch (datastore->type) {
    case EL2GO_DATASTORE_TYPE_FS:
        return nxp_iot_EndpointType_DS_FS;
    case EL2GO_DATASTORE_TYPE_PLAIN:
        return nxp_iot_EndpointType_DS_PLAIN;
    case EL2GO_DATASTORE_TYPE_CUSTOM:
    default:
        /* The server does not support custom datastore endpoints. */
        return nxp_iot_EndpointType_INVALID;
    }
}

el2go_status_t el2go_datastore_get_endpoint_info(void *ctx, nxp_iot_EndpointInformation *info)
{
    (void)ctx;

    if (!info) {
        return EL2GO_STATUS_INVALID_PARAMETER;
    }

    /* Generic fallback: mark type and endpointId as present. */
    info->has_type = true;
    info->has_endpointId = true;

    return EL2GO_STATUS_SUCCESS;
}

/* ========================================================================== */
/* Datastore request handler - default implementation                          */
/* ========================================================================== */

/*
 * Context for the WRITE decode callback.
 * Holds a pointer back to the DatastoreRequest being decoded so that when
 * the 'data' bytes callback fires, req->offset is already populated.
 * (offset is field 2, data is field 10 - nanopb decodes in field number order.)
 */
typedef struct {
    el2go_datastore_t *ds;
    nxp_iot_DatastoreRequest *req;
    bool write_failed; /* set on any write error so the WRITE response returns ERROR */
} ds_write_decode_ctx_t;

/*
 * @brief Nanopb decode callback for the DatastoreRequest 'data' bytes field.
 *
 * Called by nanopb only when a 'data' field is present in the stream, which
 * is only the case for WRITE requests. By the time this fires, req->offset has
 * already been decoded (field 2 precedes field 10). Bytes are streamed
 * directly into the datastore in 64-byte chunks.
 *
 * On any write error (including an incomplete write) the callback sets
 * wctx->write_failed and keeps draining the input stream so that
 * pb_decode_delimited succeeds and the caller can still send an error
 * response back to the server.
 */
static bool ds_write_data_decode_cb(pb_istream_t *stream, const pb_field_t *field, void **arg)
{
    ds_write_decode_ctx_t *wctx = NULL;
    el2go_datastore_t *ds = NULL;
    nxp_iot_DatastoreRequest *req = NULL;
    size_t offset = 0U;
    size_t available = 0U;
    size_t chunk_len = 0U;
    size_t bytes_written = 0U;
    el2go_status_t st = EL2GO_STATUS_SUCCESS;
    uint8_t chunk[EL2GO_DATASTORE_CHUNK_SIZE] = { 0 };

    (void)field;

    if (!stream || !arg || !(*arg))
        return false;

    wctx = (ds_write_decode_ctx_t *)(*arg);
    ds = wctx->ds;
    req = wctx->req;

    if (!ds || !req)
        return false;

    offset = (req->has_offset && req->offset >= 0) ? (size_t)req->offset : 0U;
    available = stream->bytes_left;

    while (available > 0U) {
        chunk_len = (available < sizeof(chunk)) ? available : sizeof(chunk);
        if (!pb_read(stream, chunk, chunk_len))
            return false;

        if (!wctx->write_failed) {
            st = el2go_datastore_write(ds, chunk, offset, chunk_len, &bytes_written);
            if (st != EL2GO_STATUS_SUCCESS) {
                EL2GO_DBG_PRINTF(ERROR,
                                 "ds_write_data_decode_cb: write error at offset=%zu "
                                 "status=0x%04x\n",
                                 offset, st);
                wctx->write_failed = true;
                /*
                 * Do not return false here: keep draining the stream so
                 * pb_decode_delimited completes cleanly and the caller can
                 * encode a proper error response for the server.
                 */
            } else {
                if (ADD_OVERFLOW(offset, bytes_written, &offset))
                    return false;
            }
        }
        /* Always advance the available counter to fully drain the stream. */
        if (SUB_OVERFLOW(available, chunk_len, &available))
            return false;
    }
    return true;
}

/*
 * Context for the READ encode callback.
 */
typedef struct {
    el2go_datastore_t *ds;
    int32_t offset;
    int32_t length;
} ds_read_encode_ctx_t;

/*
 * @brief Nanopb encode callback for the DatastoreResponse 'data' bytes field.
 *
 * Called by nanopb during encode_responses_from_payload() when it serializes
 * the 'data' field of nxp_iot_DatastoreResponse. Streams datastore bytes into
 * the output in 64-byte chunks.
 *
 * The varint length written before the bytes must match the actual data
 * delivered. If the datastore returns fewer bytes than requested (short read),
 * the callback returns false to surface an error: the server receives a failed
 * encode rather than a malformed/truncated protobuf response.
 */
static bool ds_read_data_encode_cb(pb_ostream_t *stream, const pb_field_t *field, void *const *arg)
{
    ds_read_encode_ctx_t *rctx = NULL;
    size_t declared_len = 0U;
    size_t offset = 0U;
    size_t bytes_read = 0U;
    size_t total_read = 0U;
    size_t remaining = 0U;
    size_t chunk_len = 0U;
    el2go_status_t st = EL2GO_STATUS_SUCCESS;
    uint8_t chunk[EL2GO_DATASTORE_CHUNK_SIZE] = { 0 };

    if (!stream || !field || !arg || !(*arg))
        return false;

    rctx = (ds_read_encode_ctx_t *)(*arg);

    if (!rctx->ds)
        return false;

    declared_len = (rctx->length > 0) ? (size_t)rctx->length : 0U;
    offset = (rctx->offset >= 0) ? (size_t)rctx->offset : 0U;
    remaining = declared_len;

    if (declared_len == 0U) {
        EL2GO_DBG_PRINTF(DEBUG, "ds_read_data_encode_cb: declared_len=0, skipping\n");
        return true;
    }

    EL2GO_DBG_PRINTF(VERBOSE, "ds_read_data_encode_cb: declared_len=%zu offset=%zu\n", declared_len,
                     offset);

    /*
     * Write the bytes field tag and the declared length varint first.
     * The actual bytes written into the stream must equal declared_len;
     * a short read returns false so the caller sees an encode failure.
     */
    if (!pb_encode_tag_for_field(stream, field))
        return false;
    if (!pb_encode_varint(stream, (uint64_t)declared_len))
        return false;

    while (remaining > 0U) {
        chunk_len = (remaining < sizeof(chunk)) ? remaining : sizeof(chunk);
        bytes_read = 0U;

        st = el2go_datastore_read(rctx->ds, chunk, offset, chunk_len, &bytes_read);
        if (st != EL2GO_STATUS_SUCCESS && st != EL2GO_STATUS_INCOMPLETE_READ) {
            EL2GO_DBG_PRINTF(ERROR,
                             "ds_read_data_encode_cb: read error at offset=%zu status=0x%04x\n",
                             offset, st);
            return false;
        }
        if (bytes_read == 0U) {
            /* Datastore has less data than declared - signal encode error. */
            EL2GO_DBG_PRINTF(ERROR, "Short read: declared %zu bytes, got %zu so far\n",
                             declared_len, total_read);
            return false;
        }

        if (!pb_write(stream, chunk, bytes_read))
            return false;
        if (ADD_OVERFLOW(offset, bytes_read, &offset))
            return false;
        if (ADD_OVERFLOW(total_read, bytes_read, &total_read))
            return false;
        if (SUB_OVERFLOW(remaining, bytes_read, &remaining))
            return false;
        EL2GO_DBG_PRINTF(EXTRA, "ds_read_data_encode_cb: wrote %zu bytes, total=%zu/%zu\n",
                         bytes_read, total_read, declared_len);
    }

    EL2GO_DBG_PRINTF(VERBOSE, "ds_read_data_encode_cb: done, total_read=%zu\n", total_read);
    return true;
}

/*
 * @brief Default handle_request implementation for datastore endpoints.
 *
 * Installs ds_write_data_decode_cb on the DatastoreRequest 'data' field before
 * calling pb_decode_delimited. The callback fires only for WRITE requests (when
 * 'data' is present in the stream) and writes bytes directly into the datastore.
 * After decoding, dispatches on req.operation for ALLOCATE, READ, WRITE, COMMIT.
 *
 * For READ, the response 'data' field uses ds_read_data_encode_cb, which is
 * invoked by nanopb inside encode_responses_from_payload(). A short read returns
 * false, propagating the error to the dispatcher.
 *
 * Custom datastores may override the entire handler by setting ops->handle_request.
 */
el2go_status_t el2go_datastore_handle_request(void *ctx, const pb_field_t *message_type,
                                              pb_istream_t *istream, pb_ostream_t *ostream)
{
    el2go_datastore_t *ds = NULL;
    nxp_iot_DatastoreRequest req = nxp_iot_DatastoreRequest_init_default;
    nxp_iot_DatastoreResponse resp = nxp_iot_DatastoreResponse_init_default;
    nxp_iot_ResponsePayload response = nxp_iot_ResponsePayload_init_default;
    ds_write_decode_ctx_t wctx = { NULL, &req, false };
    ds_read_encode_ctx_t rctx = { 0 };
    el2go_status_t st = EL2GO_STATUS_SUCCESS;
    size_t len = 0U;
    size_t ds_size = 0U;
    size_t requested = 0U;
    size_t rd_offset = 0U;
    size_t actual = 0U;
    size_t available = 0U;
    el2go_status_t result = EL2GO_STATUS_RTP_DECODE_ERROR;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!ctx || !istream || !ostream) {
        result = EL2GO_STATUS_INVALID_PARAMETER;
        goto exit;
    }

    ds = (el2go_datastore_t *)ctx;
    wctx.ds = ds;

    (void)message_type;

    /*
     * Install the write decode callback before decoding.
     * nanopb calls it only when 'data' (field 10) is present in the stream.
     * At that point req.offset (field 2) is already populated.
     */
    req.data.funcs.decode = ds_write_data_decode_cb;
    req.data.arg = &wctx;

    if (!pb_decode_delimited(istream, nxp_iot_DatastoreRequest_fields, &req)) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to decode DatastoreRequest: %s\n", PB_GET_ERROR(istream));
        goto exit;
    }

    resp.has_status = true;

    EL2GO_DBG_PRINTF(EXTRA,
                     "DatastoreRequest operation=%d has_operation=%d has_offset=%d "
                     "offset=%d has_length=%d length=%d\n",
                     (int)req.operation, (int)req.has_operation, (int)req.has_offset,
                     (int)req.offset, (int)req.has_length, (int)req.length);

    if (!req.has_operation) {
        EL2GO_DBG_PRINTF(ERROR, "DatastoreRequest missing operation field\n");
        resp.status = nxp_iot_DatastoreStatus_ERROR;
        goto encode;
    }

    switch (req.operation) {
    case nxp_iot_DatastoreOperation_ALLOCATE: {
        len = (req.has_length && req.length > 0) ? (size_t)req.length : 0U;
        st = el2go_datastore_allocate(ds, len);
        resp.status = (st == EL2GO_STATUS_SUCCESS) ? nxp_iot_DatastoreStatus_OK :
                                                     nxp_iot_DatastoreStatus_ERROR;
        EL2GO_DBG_PRINTF(VERBOSE, "Datastore ALLOCATE %zu bytes: 0x%04x\n", len, st);
        break;
    }

    case nxp_iot_DatastoreOperation_READ:
        /*
         * Determine how many bytes are actually available from the current
         * read slot before setting up the encode callback. This ensures the
         * protobuf varint length written to the wire always matches the actual
         * data delivered, even when the server requests more than is stored.
         */
        requested = (req.has_length && req.length > 0) ? (size_t)req.length : 0U;
        rd_offset = req.has_offset ? (size_t)req.offset : 0U;
        actual = requested;

        if (el2go_datastore_get_size(ds, &ds_size) == EL2GO_STATUS_SUCCESS) {
            available = (ds_size > rd_offset) ? (ds_size - rd_offset) : 0U;
            if (actual > available)
                actual = available;
        }
        rctx.ds = ds;
        rctx.offset = (int32_t)rd_offset;
        rctx.length = (int32_t)actual;
        resp.has_length = true;
        resp.length = (int32_t)actual;
        resp.data.funcs.encode = ds_read_data_encode_cb;
        resp.data.arg = &rctx;
        resp.status = nxp_iot_DatastoreStatus_OK;
        EL2GO_DBG_PRINTF(VERBOSE, "Datastore READ offset=%zu requested=%zu actual=%zu\n", rd_offset,
                         requested, actual);
        break;

    case nxp_iot_DatastoreOperation_WRITE:
        /*
         * Data was written to the datastore by ds_write_data_decode_cb during
         * pb_decode_delimited above. If the callback recorded a write failure
         * (incomplete or error), report it back to the server as an error.
         */
        if (wctx.write_failed) {
            EL2GO_DBG_PRINTF(ERROR, "Datastore WRITE failed (incomplete or error)\n");
            resp.status = nxp_iot_DatastoreStatus_ERROR;
        } else {
            resp.status = nxp_iot_DatastoreStatus_OK;
            EL2GO_DBG_PRINTF(VERBOSE, "Datastore WRITE done\n");
        }
        break;

    case nxp_iot_DatastoreOperation_COMMIT: {
        st = el2go_datastore_commit(ds);
        resp.status = (st == EL2GO_STATUS_SUCCESS) ? nxp_iot_DatastoreStatus_OK :
                                                     nxp_iot_DatastoreStatus_ERROR;
        EL2GO_DBG_PRINTF(VERBOSE, "Datastore COMMIT: 0x%04x\n", st);
        break;
    }

    default:
        EL2GO_DBG_PRINTF(ERROR, "Unknown datastore operation: %d\n", req.operation);
        resp.status = nxp_iot_DatastoreStatus_ERROR;
        break;
    }

encode:
    response.which_message = nxp_iot_ResponsePayload_datastore_tag;
    response.message.datastore = resp;

    if (!encode_responses_from_payload(ostream, &response)) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to encode DatastoreResponse\n");
        goto exit;
    }
    result = EL2GO_STATUS_SUCCESS;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, (int)result);
    return result;
}
