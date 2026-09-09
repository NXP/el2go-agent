/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/**
 * @file test_el2go_datastore_handle_request.c
 * @brief Unit tests for el2go_datastore_handle_request().
 *
 * Tests cover:
 *   - NULL argument guards
 *   - Malformed protobuf input
 *   - Missing operation field
 *   - ALLOCATE, READ, WRITE, COMMIT happy paths
 *   - WRITE with a failing underlying write (incomplete write -> ERROR status)
 *   - Unknown operation -> ERROR status in response
 */

#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "test_framework.h"

#include "osal.h"

#include "common/el2go_datastore.h"
#include "datastore_priv.h"

#include "pb.h"
#include "pb_encode.h"
#include "pb_decode.h"
#include "Dispatcher.pb.h"
#include "Datastore.pb.h"
#include "ServiceDescriptor.pb.h"

/* ========================================================================== */
/* Local helpers                                                               */
/* ========================================================================== */

/*
 * Build and init a datastore of the given type ready for use.
 * Caller must call cleanup_ds() when done.
 */
static bool setup_ds(el2go_datastore_t *ds, el2go_datastore_type_t type)
{
    return el2go_datastore_init(0, "test", type, ds, NULL) == EL2GO_STATUS_SUCCESS;
}

static void cleanup_ds(el2go_datastore_t *ds)
{
    (void)el2go_datastore_free(ds);
}

/*
 * Encode a DatastoreRequest into buf[].
 * Returns the number of bytes written, or 0 on failure.
 */
static size_t encode_request(const nxp_iot_DatastoreRequest *req, uint8_t *buf, size_t buf_sz)
{
    pb_ostream_t ostream = pb_ostream_from_buffer(buf, buf_sz);

    if (!pb_encode_delimited(&ostream, nxp_iot_DatastoreRequest_fields, req))
        return 0;
    return ostream.bytes_written;
}

/*
 * Context used when extracting the data bytes out of a DatastoreResponse.
 */
typedef struct {
    uint8_t *buf;      /* Destination buffer supplied by the caller */
    size_t buf_sz;     /* Capacity of buf */
    size_t bytes_read; /* Number of bytes actually written into buf */
} ds_data_decode_ctx_t;

/*
 * Nanopb decode callback for the DatastoreResponse 'data' bytes field.
 * Copies the raw bytes into the caller-supplied buffer.
 */
static bool ds_data_field_decode_cb(pb_istream_t *stream, const pb_field_t *field, void **arg)
{
    ds_data_decode_ctx_t *ctx = (ds_data_decode_ctx_t *)(*arg);
    size_t avail = stream->bytes_left;

    (void)field;

    if (avail > ctx->buf_sz)
        avail = ctx->buf_sz;

    if (!pb_read(stream, ctx->buf, avail))
        return false;

    /* Drain any remaining bytes that did not fit. */
    if (stream->bytes_left > 0U) {
        if (!pb_read(stream, NULL, stream->bytes_left))
            return false;
    }

    ctx->bytes_read = avail;
    return true;
}

/*
 * Accumulates the DatastoreResponse found inside the first
 * nxp_iot_ResponsePayload of an nxp_iot_Responses message.
 */
typedef struct {
    nxp_iot_DatastoreStatus *status_out;
    ds_data_decode_ctx_t *data_ctx;
    bool found;
} ds_response_decode_ctx_t;

/*
 * Nanopb repeated-field callback for nxp_iot_Responses.responses.
 *
 * nanopb zeroes the oneof union inside nxp_iot_ResponsePayload before
 * filling it in, which would wipe any callback pre-registered in the
 * datastore sub-message.  To avoid that, this callback manually scans
 * the ResponsePayload fields looking for tag 30 (datastore), then decodes
 * nxp_iot_DatastoreResponse directly - that struct has no oneof so no
 * zeroing occurs and the data callback survives.
 */
static bool decode_response_payload_cb(pb_istream_t *stream, const pb_field_t *field, void **arg)
{
    ds_response_decode_ctx_t *ctx = (ds_response_decode_ctx_t *)(*arg);
    pb_wire_type_t wt;
    uint32_t tag;
    bool eof;
    nxp_iot_DatastoreResponse ds_resp = nxp_iot_DatastoreResponse_init_default;

    (void)field;

    /* Process only the first matching entry. */
    if (ctx->found)
        return pb_read(stream, NULL, stream->bytes_left);

    /* Walk the ResponsePayload fields looking for the datastore oneof tag. */
    while (pb_decode_tag(stream, &wt, &tag, &eof)) {
        if (tag == (uint32_t)nxp_iot_ResponsePayload_datastore_tag && wt == PB_WT_STRING) {
            pb_istream_t sub;
            bool ok;

            if (!pb_make_string_substream(stream, &sub))
                return false;

            /* Set the data callback before decoding - DatastoreResponse has
             * no oneof so these pointers are not zeroed during decode. */
            if (ctx->data_ctx != NULL) {
                ds_resp.data.funcs.decode = ds_data_field_decode_cb;
                ds_resp.data.arg = ctx->data_ctx;
            }

            ok = pb_decode(&sub, nxp_iot_DatastoreResponse_fields, &ds_resp);
            ok = pb_close_string_substream(stream, &sub) && ok;

            if (!ok)
                return false;

            if (ds_resp.has_status) {
                *ctx->status_out = ds_resp.status;
                ctx->found = true;
            }
            return true;
        }

        if (!pb_skip_field(stream, wt))
            return false;
    }

    /* eof with no matching field means this payload had no datastore tag. */
    return eof;
}

/*
 * Decode-response helper that captures both status and data bytes.
 * data_ctx->buf / buf_sz must be set by the caller before calling this
 * function; data_ctx->bytes_read is filled on success.
 * Pass data_ctx == NULL if only the status is needed.
 */
static bool decode_ds_response(const uint8_t *buf, size_t len, nxp_iot_DatastoreStatus *status_out,
                               ds_data_decode_ctx_t *data_ctx)
{
    nxp_iot_Responses responses = nxp_iot_Responses_init_default;
    ds_response_decode_ctx_t ctx = { status_out, data_ctx, false };
    pb_istream_t istream = pb_istream_from_buffer(buf, len);

    responses.responses.funcs.decode = decode_response_payload_cb;
    responses.responses.arg = &ctx;

    if (!pb_decode(&istream, nxp_iot_Responses_fields, &responses))
        return false;

    return ctx.found;
}

/*
 * Convenience wrapper: decode only the status (no data extraction).
 */
static bool decode_ds_status(const uint8_t *buf, size_t len, nxp_iot_DatastoreStatus *status_out)
{
    return decode_ds_response(buf, len, status_out, NULL);
}

/* ========================================================================== */
/* NULL / invalid parameter tests                                              */
/* ========================================================================== */

/**
 * @brief NULL ctx must return EL2GO_STATUS_RTP_DECODE_ERROR immediately.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_handle_request_null_ctx(void *params)
{
    pb_istream_t istream = { 0 };
    pb_ostream_t ostream = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    (void)params;

    status =
        el2go_datastore_handle_request(NULL, nxp_iot_DatastoreRequest_fields, &istream, &ostream);
    TEST_ASSERT_EQUAL(EL2GO_STATUS_INVALID_PARAMETER, status);
    return true;
}

/**
 * @brief NULL istream must return EL2GO_STATUS_RTP_DECODE_ERROR.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_handle_request_null_istream(void *params)
{
    el2go_datastore_t ds = { 0 };
    el2go_datastore_type_t type = *(const el2go_datastore_type_t *)params;
    uint8_t out_buf[256] = { 0 };
    pb_ostream_t ostream = pb_ostream_from_buffer(out_buf, sizeof(out_buf));
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    TEST_ASSERT_GOTO(setup_ds(&ds, type), exit);

    status = el2go_datastore_handle_request(&ds, nxp_iot_DatastoreRequest_fields, NULL, &ostream);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

exit:
    cleanup_ds(&ds);
    return test_status;
}

/**
 * @brief NULL ostream must return EL2GO_STATUS_RTP_DECODE_ERROR.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_handle_request_null_ostream(void *params)
{
    el2go_datastore_t ds = { 0 };
    el2go_datastore_type_t type = *(const el2go_datastore_type_t *)params;
    uint8_t in_buf[64] = { 0 };
    pb_istream_t istream = pb_istream_from_buffer(in_buf, sizeof(in_buf));
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    TEST_ASSERT_GOTO(setup_ds(&ds, type), exit);

    status = el2go_datastore_handle_request(&ds, nxp_iot_DatastoreRequest_fields, &istream, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

exit:
    cleanup_ds(&ds);
    return test_status;
}

/**
 * @brief Malformed (garbage) protobuf input must return EL2GO_STATUS_RTP_DECODE_ERROR.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_handle_request_malformed_protobuf(void *params)
{
    el2go_datastore_t ds = { 0 };
    el2go_datastore_type_t type = *(const el2go_datastore_type_t *)params;
    /* A length-delimited field announces length 0x7f but stream is only 4 bytes. */
    uint8_t bad_data[] = { 0x0a, 0x7f, 0xff, 0xff };
    pb_istream_t istream = pb_istream_from_buffer(bad_data, sizeof(bad_data));
    uint8_t out_buf[256] = { 0 };
    pb_ostream_t ostream = pb_ostream_from_buffer(out_buf, sizeof(out_buf));
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    TEST_ASSERT_GOTO(setup_ds(&ds, type), exit);

    status =
        el2go_datastore_handle_request(&ds, nxp_iot_DatastoreRequest_fields, &istream, &ostream);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_RTP_DECODE_ERROR, status, exit);

exit:
    cleanup_ds(&ds);
    return test_status;
}

/* ========================================================================== */
/* Missing operation field                                                     */
/* ========================================================================== */

/**
 * @brief Request with has_operation == false -> response status ERROR,
 *        but function still returns EL2GO_STATUS_SUCCESS (encode succeeds).
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_handle_request_missing_operation(void *params)
{
    el2go_datastore_t ds = { 0 };
    nxp_iot_DatastoreRequest req = nxp_iot_DatastoreRequest_init_default;
    uint8_t enc_buf[64] = { 0 };
    size_t enc_len = 0;
    pb_istream_t istream = { 0 };
    uint8_t out_buf[512] = { 0 };
    pb_ostream_t ostream = pb_ostream_from_buffer(out_buf, sizeof(out_buf));
    el2go_datastore_type_t type = *(const el2go_datastore_type_t *)params;
    nxp_iot_DatastoreStatus st = (nxp_iot_DatastoreStatus)0;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool decoded = false;
    bool test_status = true;

    TEST_ASSERT_GOTO(setup_ds(&ds, type), exit);

    req.has_operation = false;
    enc_len = encode_request(&req, enc_buf, sizeof(enc_buf));
    TEST_ASSERT_NOT_EQUAL_GOTO(0, enc_len, exit);

    istream = pb_istream_from_buffer(enc_buf, enc_len);

    status =
        el2go_datastore_handle_request(&ds, nxp_iot_DatastoreRequest_fields, &istream, &ostream);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    decoded = decode_ds_status(out_buf, ostream.bytes_written, &st);
    TEST_ASSERT_GOTO(decoded, exit);
    TEST_ASSERT_EQUAL_GOTO(nxp_iot_DatastoreStatus_ERROR, st, exit);

exit:
    cleanup_ds(&ds);
    return test_status;
}

/* ========================================================================== */
/* Unknown operation                                                           */
/* ========================================================================== */

/**
 * @brief Unknown operation value -> response status ERROR, function returns EL2GO_STATUS_SUCCESS.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_handle_request_unknown_operation(void *params)
{
    el2go_datastore_t ds = { 0 };
    nxp_iot_DatastoreRequest req = nxp_iot_DatastoreRequest_init_default;
    uint8_t enc_buf[64] = { 0 };
    size_t enc_len = 0;
    pb_istream_t istream = { 0 };
    uint8_t out_buf[512] = { 0 };
    pb_ostream_t ostream = pb_ostream_from_buffer(out_buf, sizeof(out_buf));
    el2go_datastore_type_t type = *(const el2go_datastore_type_t *)params;
    nxp_iot_DatastoreStatus st = (nxp_iot_DatastoreStatus)0;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool decoded = false;
    bool test_status = true;

    TEST_ASSERT_GOTO(setup_ds(&ds, type), exit);

    req.has_operation = true;
    req.operation = (nxp_iot_DatastoreOperation)99;
    enc_len = encode_request(&req, enc_buf, sizeof(enc_buf));
    TEST_ASSERT_NOT_EQUAL_GOTO(0, enc_len, exit);

    istream = pb_istream_from_buffer(enc_buf, enc_len);

    status =
        el2go_datastore_handle_request(&ds, nxp_iot_DatastoreRequest_fields, &istream, &ostream);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    decoded = decode_ds_status(out_buf, ostream.bytes_written, &st);
    TEST_ASSERT_GOTO(decoded, exit);
    TEST_ASSERT_EQUAL_GOTO(nxp_iot_DatastoreStatus_ERROR, st, exit);

exit:
    cleanup_ds(&ds);
    return test_status;
}

/* ========================================================================== */
/* ALLOCATE                                                                    */
/* ========================================================================== */

/**
 * @brief ALLOCATE with a valid length -> OK status.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_handle_request_allocate_success(void *params)
{
    el2go_datastore_t ds = { 0 };
    nxp_iot_DatastoreRequest req = nxp_iot_DatastoreRequest_init_default;
    uint8_t enc_buf[64] = { 0 };
    size_t enc_len = 0;
    pb_istream_t istream = { 0 };
    uint8_t out_buf[512] = { 0 };
    pb_ostream_t ostream = pb_ostream_from_buffer(out_buf, sizeof(out_buf));
    el2go_datastore_type_t type = *(const el2go_datastore_type_t *)params;
    nxp_iot_DatastoreStatus st = (nxp_iot_DatastoreStatus)0;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool decoded = false;
    bool test_status = true;

    TEST_ASSERT_GOTO(setup_ds(&ds, type), exit);

    req.has_operation = true;
    req.operation = nxp_iot_DatastoreOperation_ALLOCATE;
    req.has_length = true;
    req.length = 128;
    enc_len = encode_request(&req, enc_buf, sizeof(enc_buf));
    TEST_ASSERT_NOT_EQUAL_GOTO(0, enc_len, exit);

    istream = pb_istream_from_buffer(enc_buf, enc_len);

    status =
        el2go_datastore_handle_request(&ds, nxp_iot_DatastoreRequest_fields, &istream, &ostream);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    decoded = decode_ds_status(out_buf, ostream.bytes_written, &st);
    TEST_ASSERT_GOTO(decoded, exit);
    TEST_ASSERT_EQUAL_GOTO(nxp_iot_DatastoreStatus_OK, st, exit);

exit:
    cleanup_ds(&ds);
    return test_status;
}

/**
 * @brief ALLOCATE with zero length -> ERROR status (invalid parameter).
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_handle_request_allocate_zero_length(void *params)
{
    el2go_datastore_t ds = { 0 };
    nxp_iot_DatastoreRequest req = nxp_iot_DatastoreRequest_init_default;
    uint8_t enc_buf[64] = { 0 };
    size_t enc_len = 0;
    pb_istream_t istream = { 0 };
    uint8_t out_buf[512] = { 0 };
    pb_ostream_t ostream = pb_ostream_from_buffer(out_buf, sizeof(out_buf));
    el2go_datastore_type_t type = *(const el2go_datastore_type_t *)params;
    nxp_iot_DatastoreStatus st = (nxp_iot_DatastoreStatus)0;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool decoded = false;
    bool test_status = true;

    TEST_ASSERT_GOTO(setup_ds(&ds, type), exit);

    req.has_operation = true;
    req.operation = nxp_iot_DatastoreOperation_ALLOCATE;
    req.has_length = true;
    req.length = 0;
    enc_len = encode_request(&req, enc_buf, sizeof(enc_buf));
    TEST_ASSERT_NOT_EQUAL_GOTO(0, enc_len, exit);

    istream = pb_istream_from_buffer(enc_buf, enc_len);

    status =
        el2go_datastore_handle_request(&ds, nxp_iot_DatastoreRequest_fields, &istream, &ostream);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    decoded = decode_ds_status(out_buf, ostream.bytes_written, &st);
    TEST_ASSERT_GOTO(decoded, exit);
    TEST_ASSERT_EQUAL_GOTO(nxp_iot_DatastoreStatus_ERROR, st, exit);

exit:
    cleanup_ds(&ds);
    return test_status;
}

/* ========================================================================== */
/* WRITE                                                                       */
/* ========================================================================== */

/*
 * Nanopb encode callback that writes a fixed pattern into the DatastoreRequest
 * 'data' bytes field.
 */
typedef struct {
    const uint8_t *data;
    size_t len;
} write_cb_arg_t;

static bool write_data_cb(pb_ostream_t *stream, const pb_field_t *field, void *const *arg)
{
    const write_cb_arg_t *a = (const write_cb_arg_t *)(*arg);

    if (!pb_encode_tag_for_field(stream, field))
        return false;
    return pb_encode_string(stream, a->data, a->len);
}

/**
 * @brief WRITE happy path: allocate then write; expect OK status.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_handle_request_write_success(void *params)
{
    el2go_datastore_t ds = { 0 };
    const uint8_t pattern[32] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                                  0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                                  0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
    write_cb_arg_t cb_arg = { pattern, sizeof(pattern) };
    nxp_iot_DatastoreRequest req = nxp_iot_DatastoreRequest_init_default;
    uint8_t enc_buf[128] = { 0 };
    size_t enc_len = 0;
    pb_istream_t istream = { 0 };
    uint8_t out_buf[512] = { 0 };
    pb_ostream_t ostream = pb_ostream_from_buffer(out_buf, sizeof(out_buf));
    el2go_datastore_type_t type = *(const el2go_datastore_type_t *)params;
    nxp_iot_DatastoreStatus st = (nxp_iot_DatastoreStatus)0;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool decoded = false;
    bool test_status = true;

    TEST_ASSERT_GOTO(setup_ds(&ds, type), exit);

    /* First allocate space. */
    status = el2go_datastore_allocate(&ds, sizeof(pattern));
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Build WRITE request. */
    req.has_operation = true;
    req.operation = nxp_iot_DatastoreOperation_WRITE;
    req.has_offset = true;
    req.offset = 0;
    req.data.funcs.encode = write_data_cb;
    req.data.arg = &cb_arg;

    enc_len = encode_request(&req, enc_buf, sizeof(enc_buf));
    TEST_ASSERT_NOT_EQUAL_GOTO(0, enc_len, exit);

    istream = pb_istream_from_buffer(enc_buf, enc_len);

    status =
        el2go_datastore_handle_request(&ds, nxp_iot_DatastoreRequest_fields, &istream, &ostream);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    decoded = decode_ds_status(out_buf, ostream.bytes_written, &st);
    TEST_ASSERT_GOTO(decoded, exit);
    TEST_ASSERT_EQUAL_GOTO(nxp_iot_DatastoreStatus_OK, st, exit);

exit:
    cleanup_ds(&ds);
    return test_status;
}

/**
 * @brief WRITE without prior ALLOCATE -> underlying write fails ->
 *        function returns EL2GO_STATUS_SUCCESS but response status is ERROR.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_handle_request_write_no_alloc(void *params)
{
    el2go_datastore_t ds = { 0 };
    const uint8_t data[16] = { 0xAB };
    write_cb_arg_t cb_arg = { data, sizeof(data) };
    nxp_iot_DatastoreRequest req = nxp_iot_DatastoreRequest_init_default;
    uint8_t enc_buf[128] = { 0 };
    size_t enc_len = 0;
    pb_istream_t istream = { 0 };
    uint8_t out_buf[512] = { 0 };
    pb_ostream_t ostream = pb_ostream_from_buffer(out_buf, sizeof(out_buf));
    el2go_datastore_type_t type = *(const el2go_datastore_type_t *)params;
    nxp_iot_DatastoreStatus st = (nxp_iot_DatastoreStatus)0;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool decoded = false;
    bool test_status = true;

    TEST_ASSERT_GOTO(setup_ds(&ds, type), exit);

    /* No allocate - write must fail internally. */
    req.has_operation = true;
    req.operation = nxp_iot_DatastoreOperation_WRITE;
    req.has_offset = true;
    req.offset = 0;
    req.data.funcs.encode = write_data_cb;
    req.data.arg = &cb_arg;

    enc_len = encode_request(&req, enc_buf, sizeof(enc_buf));
    TEST_ASSERT_NOT_EQUAL_GOTO(0, enc_len, exit);

    istream = pb_istream_from_buffer(enc_buf, enc_len);

    /*
     * The handler must still return EL2GO_STATUS_SUCCESS (encode succeeds);
     * the failure is reported in the response status field as ERROR.
     */
    status =
        el2go_datastore_handle_request(&ds, nxp_iot_DatastoreRequest_fields, &istream, &ostream);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    decoded = decode_ds_status(out_buf, ostream.bytes_written, &st);
    TEST_ASSERT_GOTO(decoded, exit);
    TEST_ASSERT_EQUAL_GOTO(nxp_iot_DatastoreStatus_ERROR, st, exit);

exit:
    cleanup_ds(&ds);
    return test_status;
}

/* ========================================================================== */
/* READ                                                                        */
/* ========================================================================== */

/**
 * @brief Verify the READ happy path: write data, read it back via
 *        handle_request, and verify the response status and returned data.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_handle_request_read_success(void *params)
{
    el2go_datastore_t ds = { 0 };
    const size_t data_len = 32;
    uint8_t pattern[32];
    uint8_t read_back[32] = { 0 };
    ds_data_decode_ctx_t data_ctx = { read_back, sizeof(read_back), 0 };
    size_t i = 0;
    size_t bytes_written = 0;
    nxp_iot_DatastoreRequest req = nxp_iot_DatastoreRequest_init_default;
    uint8_t enc_buf[64] = { 0 };
    size_t enc_len = 0;
    pb_istream_t istream = { 0 };
    uint8_t out_buf[1024] = { 0 };
    pb_ostream_t ostream = pb_ostream_from_buffer(out_buf, sizeof(out_buf));
    el2go_datastore_type_t type = *(const el2go_datastore_type_t *)params;
    nxp_iot_DatastoreStatus st = (nxp_iot_DatastoreStatus)0;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool decoded = false;
    bool test_status = true;

    /* Fill the pattern. */
    for (i = 0; i < data_len; i++)
        pattern[i] = (uint8_t)(i * 3u);

    TEST_ASSERT_GOTO(setup_ds(&ds, type), exit);

    status = el2go_datastore_allocate(&ds, data_len);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    status = el2go_datastore_write(&ds, pattern, 0, data_len, &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(data_len, bytes_written, exit);
    /* Commit so the data is visible on the read slot. */
    status = el2go_datastore_commit(&ds);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Issue READ request for offset=0, length=32. */
    req.has_operation = true;
    req.operation = nxp_iot_DatastoreOperation_READ;
    req.has_offset = true;
    req.offset = 0;
    req.has_length = true;
    req.length = (int32_t)data_len;
    enc_len = encode_request(&req, enc_buf, sizeof(enc_buf));
    TEST_ASSERT_NOT_EQUAL_GOTO(0, enc_len, exit);

    istream = pb_istream_from_buffer(enc_buf, enc_len);

    status =
        el2go_datastore_handle_request(&ds, nxp_iot_DatastoreRequest_fields, &istream, &ostream);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Decode the response and capture the data field. */
    decoded = decode_ds_response(out_buf, ostream.bytes_written, &st, &data_ctx);
    TEST_ASSERT_GOTO(decoded, exit);
    TEST_ASSERT_EQUAL_GOTO(nxp_iot_DatastoreStatus_OK, st, exit);

    /* Verify the returned bytes match the original pattern. */
    TEST_ASSERT_EQUAL_GOTO(data_len, data_ctx.bytes_read, exit);
    TEST_ASSERT_GOTO(memcmp(read_back, pattern, data_len) == 0, exit);

exit:
    cleanup_ds(&ds);
    return test_status;
}

/**
 * @brief Verify that a READ request whose length exceeds the stored data
 *        is clamped to the available size and returns a successful status.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_handle_request_read_clamp_to_size(void *params)
{
    el2go_datastore_t ds = { 0 };
    const size_t stored_len = 16;
    uint8_t pattern[16] = { 0xCC };
    size_t bytes_written = 0;
    nxp_iot_DatastoreRequest req = nxp_iot_DatastoreRequest_init_default;
    uint8_t enc_buf[64] = { 0 };
    size_t enc_len = 0;
    pb_istream_t istream = { 0 };
    uint8_t out_buf[1024] = { 0 };
    pb_ostream_t ostream = pb_ostream_from_buffer(out_buf, sizeof(out_buf));
    el2go_datastore_type_t type = *(const el2go_datastore_type_t *)params;
    nxp_iot_DatastoreStatus st = (nxp_iot_DatastoreStatus)0;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool decoded = false;
    bool test_status = true;

    TEST_ASSERT_GOTO(setup_ds(&ds, type), exit);

    status = el2go_datastore_allocate(&ds, stored_len);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    status = el2go_datastore_write(&ds, pattern, 0, stored_len, &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    /* Commit so the data is visible on the read slot. */
    status = el2go_datastore_commit(&ds);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Request 256 bytes but only 16 are stored. */
    req.has_operation = true;
    req.operation = nxp_iot_DatastoreOperation_READ;
    req.has_offset = true;
    req.offset = 0;
    req.has_length = true;
    req.length = 256;
    enc_len = encode_request(&req, enc_buf, sizeof(enc_buf));
    TEST_ASSERT_NOT_EQUAL_GOTO(0, enc_len, exit);

    istream = pb_istream_from_buffer(enc_buf, enc_len);

    status =
        el2go_datastore_handle_request(&ds, nxp_iot_DatastoreRequest_fields, &istream, &ostream);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    decoded = decode_ds_status(out_buf, ostream.bytes_written, &st);
    TEST_ASSERT_GOTO(decoded, exit);
    TEST_ASSERT_EQUAL_GOTO(nxp_iot_DatastoreStatus_OK, st, exit);

exit:
    cleanup_ds(&ds);
    return test_status;
}

/* ========================================================================== */
/* COMMIT                                                                      */
/* ========================================================================== */

/**
 * @brief COMMIT after ALLOCATE + WRITE -> OK status.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_handle_request_commit_success(void *params)
{
    el2go_datastore_t ds = { 0 };
    nxp_iot_DatastoreRequest req = nxp_iot_DatastoreRequest_init_default;
    uint8_t enc_buf[64] = { 0 };
    size_t enc_len = 0;
    pb_istream_t istream = { 0 };
    uint8_t out_buf[512] = { 0 };
    pb_ostream_t ostream = pb_ostream_from_buffer(out_buf, sizeof(out_buf));
    el2go_datastore_type_t type = *(const el2go_datastore_type_t *)params;
    nxp_iot_DatastoreStatus st = (nxp_iot_DatastoreStatus)0;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool decoded = false;
    bool test_status = true;

    TEST_ASSERT_GOTO(setup_ds(&ds, type), exit);

    /* Allocate some space first so COMMIT has something to finalise. */
    status = el2go_datastore_allocate(&ds, 64);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    req.has_operation = true;
    req.operation = nxp_iot_DatastoreOperation_COMMIT;
    enc_len = encode_request(&req, enc_buf, sizeof(enc_buf));
    TEST_ASSERT_NOT_EQUAL_GOTO(0, enc_len, exit);

    istream = pb_istream_from_buffer(enc_buf, enc_len);

    status =
        el2go_datastore_handle_request(&ds, nxp_iot_DatastoreRequest_fields, &istream, &ostream);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    decoded = decode_ds_status(out_buf, ostream.bytes_written, &st);
    TEST_ASSERT_GOTO(decoded, exit);
    TEST_ASSERT_EQUAL_GOTO(nxp_iot_DatastoreStatus_OK, st, exit);

exit:
    cleanup_ds(&ds);
    return test_status;
}

/* ========================================================================== */
/* READ service descriptor (EL2GO connection datastore style)                 */
/* ========================================================================== */

/**
 * @brief Write a delimited nxp_iot_ServiceDescriptor via ALLOCATE/WRITE/COMMIT
 *        handle_request calls, then READ it back and verify the decoded fields
 *        match the original values.
 *
 * This mirrors exactly what the EdgeLock 2GO connection datastore
 * (el2go_rtp_datastore_el2go) stores: a delimited protobuf-encoded
 * nxp_iot_ServiceDescriptor with a service type, hostname, and port.
 * The test exercises the full round-trip entirely through
 * el2go_datastore_handle_request.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_handle_request_read_service_descriptor(void *params)
{
    el2go_datastore_t ds = { 0 };
    el2go_datastore_type_t type = *(const el2go_datastore_type_t *)params;

    /* Service descriptor to persist */
    nxp_iot_ServiceDescriptor sd_in = nxp_iot_ServiceDescriptor_init_default;
    const char *hostname = "agent.edgelock2go.com";
    const uint32_t port = 443U;
    uint8_t sd_enc[512] = { 0 };
    size_t sd_enc_len = 0;

    /* Buffers for the three handle_request calls */
    nxp_iot_DatastoreRequest req = nxp_iot_DatastoreRequest_init_default;
    uint8_t req_buf[640] = { 0 };
    size_t req_len = 0;
    uint8_t resp_buf[1024] = { 0 };
    pb_istream_t istream = { 0 };
    pb_ostream_t ostream = { 0 };
    nxp_iot_DatastoreStatus st = (nxp_iot_DatastoreStatus)0;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool decoded = false;

    /* Read-back buffers */
    uint8_t sd_read[512] = { 0 };
    ds_data_decode_ctx_t data_ctx = { sd_read, sizeof(sd_read), 0 };
    nxp_iot_ServiceDescriptor sd_out = nxp_iot_ServiceDescriptor_init_default;
    pb_istream_t sd_istream = { 0 };

    pb_ostream_t sd_enc_ostream = { 0 };
    write_cb_arg_t write_arg = { 0 };
    bool test_status = true;

    TEST_ASSERT_GOTO(setup_ds(&ds, type), exit);

    /* ------------------------------------------------------------------ */
    /* 1. Encode the service descriptor (delimited, as the real code does) */
    /* ------------------------------------------------------------------ */
    sd_in.has_service_type = true;
    sd_in.service_type = nxp_iot_ServiceType_EL2GOSERVICE;
    sd_in.hostname = (char *)hostname;
    sd_in.has_port = true;
    sd_in.port = port;

    sd_enc_ostream = pb_ostream_from_buffer(sd_enc, sizeof(sd_enc));
    TEST_ASSERT_GOTO(pb_encode_delimited(&sd_enc_ostream, nxp_iot_ServiceDescriptor_fields, &sd_in),
                     exit);
    sd_enc_len = sd_enc_ostream.bytes_written;

    /* ------------------------------------------------------------------ */
    /* 2. ALLOCATE via handle_request                                      */
    /* ------------------------------------------------------------------ */
    req = (nxp_iot_DatastoreRequest)nxp_iot_DatastoreRequest_init_default;
    req.has_operation = true;
    req.operation = nxp_iot_DatastoreOperation_ALLOCATE;
    req.has_length = true;
    req.length = (int32_t)sd_enc_len;

    req_len = encode_request(&req, req_buf, sizeof(req_buf));
    TEST_ASSERT_NOT_EQUAL_GOTO(0, req_len, exit);

    istream = pb_istream_from_buffer(req_buf, req_len);
    ostream = pb_ostream_from_buffer(resp_buf, sizeof(resp_buf));
    status =
        el2go_datastore_handle_request(&ds, nxp_iot_DatastoreRequest_fields, &istream, &ostream);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    decoded = decode_ds_status(resp_buf, ostream.bytes_written, &st);
    TEST_ASSERT_GOTO(decoded, exit);
    TEST_ASSERT_EQUAL_GOTO(nxp_iot_DatastoreStatus_OK, st, exit);

    /* ------------------------------------------------------------------ */
    /* 3. WRITE the encoded service descriptor via handle_request          */
    /* ------------------------------------------------------------------ */
    write_arg.data = sd_enc;
    write_arg.len = sd_enc_len;

    req = (nxp_iot_DatastoreRequest)nxp_iot_DatastoreRequest_init_default;
    req.has_operation = true;
    req.operation = nxp_iot_DatastoreOperation_WRITE;
    req.has_offset = true;
    req.offset = 0;
    req.data.funcs.encode = write_data_cb;
    req.data.arg = &write_arg;

    req_len = encode_request(&req, req_buf, sizeof(req_buf));
    TEST_ASSERT_NOT_EQUAL_GOTO(0, req_len, exit);

    istream = pb_istream_from_buffer(req_buf, req_len);
    ostream = pb_ostream_from_buffer(resp_buf, sizeof(resp_buf));
    status =
        el2go_datastore_handle_request(&ds, nxp_iot_DatastoreRequest_fields, &istream, &ostream);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    decoded = decode_ds_status(resp_buf, ostream.bytes_written, &st);
    TEST_ASSERT_GOTO(decoded, exit);
    TEST_ASSERT_EQUAL_GOTO(nxp_iot_DatastoreStatus_OK, st, exit);

    /* ------------------------------------------------------------------ */
    /* 4. COMMIT via handle_request                                        */
    /* ------------------------------------------------------------------ */
    req = (nxp_iot_DatastoreRequest)nxp_iot_DatastoreRequest_init_default;
    req.has_operation = true;
    req.operation = nxp_iot_DatastoreOperation_COMMIT;

    req_len = encode_request(&req, req_buf, sizeof(req_buf));
    TEST_ASSERT_NOT_EQUAL_GOTO(0, req_len, exit);

    istream = pb_istream_from_buffer(req_buf, req_len);
    ostream = pb_ostream_from_buffer(resp_buf, sizeof(resp_buf));
    status =
        el2go_datastore_handle_request(&ds, nxp_iot_DatastoreRequest_fields, &istream, &ostream);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    decoded = decode_ds_status(resp_buf, ostream.bytes_written, &st);
    TEST_ASSERT_GOTO(decoded, exit);
    TEST_ASSERT_EQUAL_GOTO(nxp_iot_DatastoreStatus_OK, st, exit);

    /* ------------------------------------------------------------------ */
    /* 5. READ back via handle_request                                     */
    /* ------------------------------------------------------------------ */
    req = (nxp_iot_DatastoreRequest)nxp_iot_DatastoreRequest_init_default;
    req.has_operation = true;
    req.operation = nxp_iot_DatastoreOperation_READ;
    req.has_offset = true;
    req.offset = 0;
    req.has_length = true;
    req.length = (int32_t)sd_enc_len;

    req_len = encode_request(&req, req_buf, sizeof(req_buf));
    TEST_ASSERT_NOT_EQUAL_GOTO(0, req_len, exit);

    istream = pb_istream_from_buffer(req_buf, req_len);
    ostream = pb_ostream_from_buffer(resp_buf, sizeof(resp_buf));
    status =
        el2go_datastore_handle_request(&ds, nxp_iot_DatastoreRequest_fields, &istream, &ostream);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    decoded = decode_ds_response(resp_buf, ostream.bytes_written, &st, &data_ctx);
    TEST_ASSERT_GOTO(decoded, exit);
    TEST_ASSERT_EQUAL_GOTO(nxp_iot_DatastoreStatus_OK, st, exit);
    TEST_ASSERT_EQUAL_GOTO(sd_enc_len, data_ctx.bytes_read, exit);

    /* ------------------------------------------------------------------ */
    /* 6. Decode the read-back bytes as a ServiceDescriptor and verify     */
    /* ------------------------------------------------------------------ */
    sd_istream = pb_istream_from_buffer(sd_read, data_ctx.bytes_read);
    TEST_ASSERT_GOTO(pb_decode_delimited(&sd_istream, nxp_iot_ServiceDescriptor_fields, &sd_out),
                     exit);

    TEST_ASSERT_EQUAL_GOTO(true, sd_out.has_service_type, exit);
    TEST_ASSERT_EQUAL_GOTO(nxp_iot_ServiceType_EL2GOSERVICE, sd_out.service_type, exit);

    TEST_ASSERT_NOT_NULL_GOTO(sd_out.hostname, exit);
    TEST_ASSERT_EQUAL_GOTO(0, strcmp(sd_out.hostname, hostname), exit);

    TEST_ASSERT_EQUAL_GOTO(true, sd_out.has_port, exit);
    TEST_ASSERT_EQUAL_GOTO(port, sd_out.port, exit);

exit:
    pb_release(nxp_iot_ServiceDescriptor_fields, &sd_out);
    cleanup_ds(&ds);
    return test_status;
}

/* ========================================================================== */
/* Test registration                                                           */
/* ========================================================================== */

void register_datastore_handle_request_tests(bool include_fs_tests)
{
    static el2go_datastore_type_t s_plain = EL2GO_DATASTORE_TYPE_PLAIN;
    static el2go_datastore_type_t s_fs = EL2GO_DATASTORE_TYPE_FS;

    /* NULL ctx test is type-independent - no datastore is created */
    TEST_REGISTER(test_handle_request_null_ctx);

    /* PLAIN variants - always registered */
    TEST_REGISTER_WITH_PARAMS(test_handle_request_null_istream, &s_plain);
    TEST_REGISTER_WITH_PARAMS(test_handle_request_null_ostream, &s_plain);
    TEST_REGISTER_WITH_PARAMS(test_handle_request_malformed_protobuf, &s_plain);
    TEST_REGISTER_WITH_PARAMS(test_handle_request_missing_operation, &s_plain);
    TEST_REGISTER_WITH_PARAMS(test_handle_request_unknown_operation, &s_plain);
    TEST_REGISTER_WITH_PARAMS(test_handle_request_allocate_success, &s_plain);
    TEST_REGISTER_WITH_PARAMS(test_handle_request_allocate_zero_length, &s_plain);
    TEST_REGISTER_WITH_PARAMS(test_handle_request_write_success, &s_plain);
    TEST_REGISTER_WITH_PARAMS(test_handle_request_write_no_alloc, &s_plain);
    TEST_REGISTER_WITH_PARAMS(test_handle_request_read_success, &s_plain);
    TEST_REGISTER_WITH_PARAMS(test_handle_request_read_clamp_to_size, &s_plain);
    TEST_REGISTER_WITH_PARAMS(test_handle_request_commit_success, &s_plain);
    TEST_REGISTER_WITH_PARAMS(test_handle_request_read_service_descriptor, &s_plain);

    /* FS variants - only on platforms that support a filesystem datastore */
    if (include_fs_tests) {
        TEST_REGISTER_WITH_PARAMS(test_handle_request_null_istream, &s_fs);
        TEST_REGISTER_WITH_PARAMS(test_handle_request_null_ostream, &s_fs);
        TEST_REGISTER_WITH_PARAMS(test_handle_request_malformed_protobuf, &s_fs);
        TEST_REGISTER_WITH_PARAMS(test_handle_request_missing_operation, &s_fs);
        TEST_REGISTER_WITH_PARAMS(test_handle_request_unknown_operation, &s_fs);
        TEST_REGISTER_WITH_PARAMS(test_handle_request_allocate_success, &s_fs);
        TEST_REGISTER_WITH_PARAMS(test_handle_request_allocate_zero_length, &s_fs);
        TEST_REGISTER_WITH_PARAMS(test_handle_request_write_success, &s_fs);
        TEST_REGISTER_WITH_PARAMS(test_handle_request_write_no_alloc, &s_fs);
        TEST_REGISTER_WITH_PARAMS(test_handle_request_read_success, &s_fs);
        TEST_REGISTER_WITH_PARAMS(test_handle_request_read_clamp_to_size, &s_fs);
        TEST_REGISTER_WITH_PARAMS(test_handle_request_commit_success, &s_fs);
        TEST_REGISTER_WITH_PARAMS(test_handle_request_read_service_descriptor, &s_fs);
    }
}
