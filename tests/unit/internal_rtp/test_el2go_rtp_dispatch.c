/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/**
 * @defgroup test_el2go_rtp_dispatch Dispatcher Unit Tests
 * @brief Unit tests for el2go_rtp_dispatch() covering both failure paths and
 *        complete dispatch sessions driven by hand-crafted nanopb byte buffers.
 *
 * Because el2go_rtp_dispatch() now accepts pb_istream_t * / pb_ostream_t *
 * instead of a live TLS context, all protobuf traffic can be injected and
 * captured with memory-backed streams.  No network connection is required.
 *
 * Hand-crafted protobuf byte arrays used in session tests
 * -------------------------------------------------------
 *
 * The wire encoding follows protobuf serialization rules and is documented
 * inline next to each array definition.
 *
 * Null/invalid argument tests
 * ---------------------------
 *  - NULL ctx, NULL istream, NULL ostream  -> INVALID_PARAMETER
 *  - Empty input stream                    -> RTP_DECODE_ERROR
 *
 * Decode-error tests
 * ------------------
 *  - Truncated varint length prefix        -> RTP_DECODE_ERROR
 *  - Request for an unregistered endpoint  -> RTP_ENDPOINT_NOT_FOUND
 *  - Malformed HelloRequest body           -> RTP_DECODE_ERROR
 *
 * Encode-error test
 * -----------------
 *  - HelloRequest decoded but ostream full -> RTP_ENCODE_ERROR
 *
 * Session (full round-trip) tests
 * --------------------------------
 *  - Goodbye with no status field          -> RTP_PROVISIONING_FAILED
 *  - Goodbye with failure status           -> RTP_PROVISIONING_FAILED
 *  - Hello + Goodbye with SUCCESS status   -> SUCCESS
 *  - Hello only (no Goodbye)               -> RTP_DECODE_ERROR
 *
 * @{
 */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "osal.h"

#include "pb.h"
#include "pb_decode.h"
#include "pb_encode.h"

#include "rtp/el2go_rtp.h"
#include "common/el2go_status.h"

#include "el2go_rtp_internal.h"
#include "el2go_dispatcher_priv.h"

#include "test_framework.h"

/* ========================================================================== */
/* Hand-crafted protobuf byte arrays                                           */
/* ========================================================================== */

/*
 * HELLO_BYTES - one length-delimited EndpointRequests message carrying an
 *               AgentHelloRequest directed at the AGENT endpoint (type=1, id=0).
 *
 * Encoding breakdown:
 *   pb_decode_delimited length prefix: varint 11 = 0x0B
 *   EndpointRequests.requests (field 1, LEN, len=9):
 *     0x0A 0x09
 *     EndpointRequest (9 bytes):
 *       .type = AGENT(1)        : 0x08 0x01
 *       .endpointId = 0         : 0x10 0x00
 *       .payload (field 100, LEN, len=2):
 *         tag = (100<<3)|2=802  : 0xA2 0x06
 *         length                : 0x02
 *         RequestPayload.hello (field 1, LEN, len=0):
 *           0x0A 0x00
 */
static const uint8_t HELLO_BYTES[] = {
    0x0B,             /* outer length prefix = 11  */
    0x0A, 0x09,       /* requests: field 1, len=9  */
    0x08, 0x01,       /* type = AGENT = 1          */
    0x10, 0x00,       /* endpointId = 0            */
    0xA2, 0x06, 0x02, /* payload field 100, len=2  */
    0x0A, 0x00        /* hello: field 1, len=0     */
};

/*
 * GOODBYE_SUCCESS_BYTES - one length-delimited EndpointRequests message
 *   carrying AgentGoodbyeRequest { status { status = SUCCESS(1) } }
 *
 * Encoding breakdown:
 *   pb_decode_delimited length prefix: varint 15 = 0x0F
 *   EndpointRequests.requests (field 1, LEN, len=13): 0x0A 0x0D
 *     EndpointRequest (13 bytes):
 *       .type = AGENT(1)        : 0x08 0x01
 *       .endpointId = 0         : 0x10 0x00
 *       .payload (field 100, LEN, len=6): 0xA2 0x06 0x06
 *         RequestPayload.goodbye (field 2, LEN, len=4): 0x12 0x04
 *           AgentGoodbyeRequest.status (field 1, LEN, len=2): 0x0A 0x02
 *             UpdateStatusReport.status = SUCCESS(1): 0x08 0x01
 */
static const uint8_t GOODBYE_SUCCESS_BYTES[] = {
    0x0F,             /* outer length prefix = 15     */
    0x0A, 0x0D,       /* requests: field 1, len=13    */
    0x08, 0x01,       /* type = AGENT = 1             */
    0x10, 0x00,       /* endpointId = 0               */
    0xA2, 0x06, 0x06, /* payload field 100, len=6     */
    0x12, 0x04,       /* goodbye: field 2, len=4      */
    0x0A, 0x02,       /* GoodbyeRequest.status len=2  */
    0x08, 0x01        /* UpdateStatusReport.status=1  */
};

/*
 * GOODBYE_FAILURE_BYTES - GoodbyeRequest with status=ERR_UPDATE_FAILED(64=0x40).
 *
 * Same layout as GOODBYE_SUCCESS_BYTES but the last byte is 0x40.
 */
static const uint8_t GOODBYE_FAILURE_BYTES[] = {
    0x0F, 0x0A, 0x0D, 0x08, 0x01, 0x10, 0x00, 0xA2,
    0x06, 0x06, 0x12, 0x04, 0x0A, 0x02, 0x08, 0x40 /* ERR_UPDATE_FAILED = 64       */
};

/*
 * GOODBYE_NO_STATUS_BYTES - GoodbyeRequest with no status field at all.
 *
 * Encoding breakdown:
 *   pb_decode_delimited length prefix: varint 11 = 0x0B
 *   EndpointRequests.requests (field 1, LEN, len=9): 0x0A 0x09
 *     EndpointRequest (9 bytes):
 *       .type = AGENT(1)        : 0x08 0x01
 *       .endpointId = 0         : 0x10 0x00
 *       .payload (field 100, LEN, len=2): 0xA2 0x06 0x02
 *         RequestPayload.goodbye (field 2, LEN, len=0): 0x12 0x00
 */
static const uint8_t GOODBYE_NO_STATUS_BYTES[] = { 0x0B, 0x0A, 0x09, 0x08, 0x01, 0x10,
                                                   0x00, 0xA2, 0x06, 0x02, 0x12, 0x00 };

/*
 * UNKNOWN_ENDPOINT_BYTES - EndpointRequest targeting type=KS_PSA(21), id=0x1234
 *   with a CrlRequest payload.
 *
 * A CrlRequest payload is used here so the message passes the CRL gate (only
 * Goodbye and CRL messages are allowed before crl_verified becomes true).
 * After the gate, find_endpoint() returns NULL because no keystore with
 * type=KS_PSA(21)/id=0x1234 is registered.  The callback then sets
 * pending_error=RTP_ENDPOINT_NOT_FOUND and returns false.
 *
 * Encoding breakdown:
 *   pb_decode_delimited length prefix: varint 12 = 0x0C
 *   EndpointRequests.requests (field 1, LEN, len=10): 0x0A 0x0A
 *     EndpointRequest (10 bytes):
 *       .type = KS_PSA(21)      : 0x08 0x15
 *       .endpointId = 0x1234    : 0x10 0xB4 0x24 (varint 4660)
 *       .payload (field 100, LEN, len=2): 0xA2 0x06 0x02
 *         RequestPayload.crl (field 3, LEN, len=0):
 *           tag = (3<<3)|2 = 0x1A, length = 0x00
 */
static const uint8_t UNKNOWN_ENDPOINT_BYTES[] = {
    0x0C, 0x0A, 0x0A, 0x08, 0x15, /* type = KS_PSA = 21           */
    0x10, 0xB4, 0x24,             /* endpointId = 4660 = 0x1234   */
    0xA2, 0x06, 0x02,             /* payload field 100, len=2     */
    0x1A, 0x00                    /* crl: field 3, len=0          */
};

/*
 * HELLO_MALFORMED_BODY_BYTES - EndpointRequests carrying an AgentHelloRequest
 *   whose inner body is corrupted: the hello LEN field declares 4 bytes but
 *   only 1 byte follows before the stream ends.
 *
 * pb_decode_unionmessage_type() succeeds (it recognises field 1 = hello).
 * The subsequent pb_decode_delimited() call fails with "end-of-stream" ->
 * pending_error is set to RTP_DECODE_ERROR and the dispatcher returns that.
 *
 * Encoding breakdown:
 *   outer length prefix = 11 : 0x0B
 *   EndpointRequests.requests (field 1, LEN, len=9): 0x0A 0x09
 *     EndpointRequest (9 bytes):
 *       .type = AGENT(1)  : 0x08 0x01
 *       .endpointId = 0   : 0x10 0x00
 *       .payload (field 100, LEN, len=4): 0xA2 0x06 0x04
 *         hello: field 1 tag = 0x0A, declared length = 0x04
 *         only 1 byte of payload follows: 0xFF
 */
static const uint8_t HELLO_MALFORMED_BODY_BYTES[] = {
    0x0B,             /* outer length prefix = 11             */
    0x0A, 0x09,       /* requests: field 1, len=9             */
    0x08, 0x01,       /* type = AGENT = 1                     */
    0x10, 0x00,       /* endpointId = 0                       */
    0xA2, 0x06, 0x04, /* payload field 100, len=4             */
    0x0A, 0x04, 0xFF  /* hello tag, declared len=4, 1 byte    */
};

/*
 * APDU_BEFORE_CRL_BYTES - EndpointRequest targeting the AGENT endpoint (type=1,
 *   id=0) but carrying an APDU payload (tag 20) instead of a CRL or Goodbye.
 *
 * When EL2GO_RTP_REQUEST_CRL==1 (the default), the dispatcher sets
 * crl_required=true at session start.  Only GoodbyeRequest and CrlRequest are
 * permitted before crl_verified becomes true.  An APDU message triggers the
 * gate: the callback sets pending_error=RTP_CRL_NOT_VERIFIED and returns false,
 * and the dispatch loop propagates that specific error code.
 *
 * Encoding breakdown:
 *   pb_decode_delimited length prefix: varint 12 = 0x0C
 *   EndpointRequests.requests (field 1, LEN, len=10): 0x0A 0x0A
 *     EndpointRequest (10 bytes):
 *       .type = AGENT(1)        : 0x08 0x01
 *       .endpointId = 0         : 0x10 0x00
 *       .payload (field 100, LEN, len=3): 0xA2 0x06 0x03
 *         RequestPayload.apdu (field 20, LEN, len=0):
 *           tag = (20<<3)|2 = 0xA2 0x01, length = 0x00
 */
static const uint8_t APDU_BEFORE_CRL_BYTES[] = {
    0x0C,             /* outer length prefix = 12     */
    0x0A, 0x0A,       /* requests: field 1, len=10    */
    0x08, 0x01,       /* type = AGENT = 1             */
    0x10, 0x00,       /* endpointId = 0               */
    0xA2, 0x06, 0x03, /* payload field 100, len=3     */
    0xA2, 0x01, 0x00  /* apdu: field 20, len=0        */
};

/* ========================================================================== */
/* NULL parameter tests                                                        */
/* ========================================================================== */

/**
 * @brief Passing NULL as the RTP context must return INVALID_PARAMETER.
 *
 * @param params Unused.
 * @return true if the assertion passes, false otherwise.
 */
static bool test_dispatch_null_ctx(void *params)
{
    uint8_t dummy = 0;
    pb_istream_t istream = pb_istream_from_buffer(&dummy, 0);
    pb_ostream_t ostream = PB_OSTREAM_SIZING;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    (void)params;

    status = el2go_rtp_dispatch(NULL, &istream, &ostream, NULL);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_INVALID_PARAMETER, status);

    return test_status;
}

/**
 * @brief Passing NULL as the istream must return INVALID_PARAMETER.
 *
 * @param params Unused.
 * @return true if the assertion passes, false otherwise.
 */
static bool test_dispatch_null_istream(void *params)
{
    el2go_rtp_ctx_t *ctx = NULL;
    pb_ostream_t ostream = PB_OSTREAM_SIZING;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    (void)params;

    status = el2go_rtp_init(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_NOT_NULL_GOTO(ctx, exit);

    status = el2go_rtp_dispatch(ctx, NULL, &ostream, NULL);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_INVALID_PARAMETER, status);

    status = el2go_rtp_free(&ctx);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

exit:
    return test_status;
}

/**
 * @brief Passing NULL as the ostream must return INVALID_PARAMETER.
 *
 * @param params Unused.
 * @return true if the assertion passes, false otherwise.
 */
static bool test_dispatch_null_ostream(void *params)
{
    el2go_rtp_ctx_t *ctx = NULL;
    uint8_t dummy = 0;
    pb_istream_t istream = pb_istream_from_buffer(&dummy, 0);
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    (void)params;

    status = el2go_rtp_init(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_NOT_NULL_GOTO(ctx, exit);

    status = el2go_rtp_dispatch(ctx, &istream, NULL, NULL);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_INVALID_PARAMETER, status);

    status = el2go_rtp_free(&ctx);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

exit:
    return test_status;
}

/* ========================================================================== */
/* Decode-error tests                                                          */
/* ========================================================================== */

/**
 * @brief An empty input buffer must cause a decode error.
 *
 * Passing a zero-length buffer stream means pb_decode_delimited() receives
 * EOF immediately on the first byte, returning false.  The dispatcher
 * translates this into EL2GO_STATUS_RTP_DECODE_ERROR.
 *
 * @param params Unused.
 * @return true if the assertion passes, false otherwise.
 */
static bool test_dispatch_empty_input_stream(void *params)
{
    el2go_rtp_ctx_t *ctx = NULL;
    uint8_t dummy = 0;
    pb_istream_t istream = pb_istream_from_buffer(&dummy, 0);
    pb_ostream_t ostream = PB_OSTREAM_SIZING;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    (void)params;

    status = el2go_rtp_init(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_NOT_NULL_GOTO(ctx, exit);

    status = el2go_rtp_dispatch(ctx, &istream, &ostream, NULL);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_RTP_DECODE_ERROR, status);

    status = el2go_rtp_free(&ctx);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

exit:
    return test_status;
}

/**
 * @brief A truncated varint length prefix must cause a decode error.
 *
 * A byte with the MSB set (0xFF) starts a multi-byte varint but is not
 * followed by a continuation byte.  pb_decode_delimited() cannot read the
 * full message length and returns false -> RTP_DECODE_ERROR.
 *
 * @param params Unused.
 * @return true if the assertion passes, false otherwise.
 */
static bool test_dispatch_corrupted_input(void *params)
{
    el2go_rtp_ctx_t *ctx = NULL;
    /* 0xFF starts a varint but has no continuation byte -> truncated */
    static const uint8_t garbage[] = { 0xFF, 0xFF };
    pb_istream_t istream = pb_istream_from_buffer(garbage, sizeof(garbage));
    pb_ostream_t ostream = PB_OSTREAM_SIZING;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    (void)params;

    status = el2go_rtp_init(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_NOT_NULL_GOTO(ctx, exit);

    status = el2go_rtp_dispatch(ctx, &istream, &ostream, NULL);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_RTP_DECODE_ERROR, status);

    status = el2go_rtp_free(&ctx);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

exit:
    return test_status;
}

/**
 * @brief A request targeting an unregistered endpoint must return ENDPOINT_NOT_FOUND.
 *
 * UNKNOWN_ENDPOINT_BYTES carries a CRL request for endpoint type KS_PSA(21)
 * with id=0x1234.  No keystore is registered in the empty RTP context, so
 * find_endpoint() returns NULL.  The callback sets pending_error to
 * RTP_ENDPOINT_NOT_FOUND, and the dispatcher propagates that specific code.
 *
 * @param params Unused.
 * @return true if the assertion passes, false otherwise.
 */
static bool test_dispatch_unknown_endpoint(void *params)
{
    el2go_rtp_ctx_t *ctx = NULL;
    pb_istream_t istream =
        pb_istream_from_buffer(UNKNOWN_ENDPOINT_BYTES, sizeof(UNKNOWN_ENDPOINT_BYTES));
    pb_ostream_t ostream = PB_OSTREAM_SIZING;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    (void)params;

    status = el2go_rtp_init(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_NOT_NULL_GOTO(ctx, exit);

    status = el2go_rtp_dispatch(ctx, &istream, &ostream, NULL);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_RTP_ENDPOINT_NOT_FOUND, status);

    status = el2go_rtp_free(&ctx);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

exit:
    return test_status;
}

/**
 * @brief A well-formed HelloRequest tag followed by a truncated body must
 *        return RTP_DECODE_ERROR.
 *
 * HELLO_MALFORMED_BODY_BYTES passes pb_decode_unionmessage_type() (field 1 tag
 * is present) but the declared inner body length (4) exceeds the available
 * stream bytes (1).  The pb_decode_delimited() call inside the Hello branch
 * fails, and pending_error is set to RTP_DECODE_ERROR.
 *
 * @param params Unused.
 * @return true if the assertion passes, false otherwise.
 */
static bool test_dispatch_hello_malformed_body(void *params)
{
    el2go_rtp_ctx_t *ctx = NULL;
    pb_istream_t istream =
        pb_istream_from_buffer(HELLO_MALFORMED_BODY_BYTES, sizeof(HELLO_MALFORMED_BODY_BYTES));
    pb_ostream_t ostream = PB_OSTREAM_SIZING;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    (void)params;

    status = el2go_rtp_init(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_NOT_NULL_GOTO(ctx, exit);

    status = el2go_rtp_dispatch(ctx, &istream, &ostream, NULL);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_RTP_DECODE_ERROR, status);

    status = el2go_rtp_free(&ctx);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

exit:
    return test_status;
}

/**
 * @brief A non-CRL message received before CRL verification must return CRL_NOT_VERIFIED.
 *
 * When EL2GO_RTP_REQUEST_CRL==1 (the default), crl_required is set to true at
 * session start and the gate in handle_request_payload() blocks any payload
 * that is neither GoodbyeRequest nor CrlRequest.
 *
 * APDU_BEFORE_CRL_BYTES carries an APDU message (tag 20) directed at the AGENT
 * endpoint before any CRL has been received.  The callback sets
 * pending_error=RTP_CRL_NOT_VERIFIED before returning false, and the dispatch
 * loop propagates that specific code.
 *
 * @param params Unused.
 * @return true if the assertion passes, false otherwise.
 */
static bool test_dispatch_crl_not_verified(void *params)
{
    el2go_rtp_ctx_t *ctx = NULL;
    pb_istream_t istream =
        pb_istream_from_buffer(APDU_BEFORE_CRL_BYTES, sizeof(APDU_BEFORE_CRL_BYTES));
    pb_ostream_t ostream = PB_OSTREAM_SIZING;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    (void)params;

    status = el2go_rtp_init(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_NOT_NULL_GOTO(ctx, exit);

    status = el2go_rtp_dispatch(ctx, &istream, &ostream, NULL);
#if defined(EL2GO_RTP_REQUEST_CRL) && (EL2GO_RTP_REQUEST_CRL == 1)
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_RTP_CRL_NOT_VERIFIED, status);
#else
    /* When CRL is not required the gate is not active; the AGENT endpoint
     * does not handle APDU messages, so the handler returns false and the
     * status code is RTP_DECODE_ERROR. */
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_RTP_DECODE_ERROR, status);
#endif

    status = el2go_rtp_free(&ctx);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

exit:
    return test_status;
}

/* ========================================================================== */
/* Encode-error test                                                           */
/* ========================================================================== */

/**
 * @brief A valid HelloRequest with a full ostream must cause an encode error.
 *
 * HELLO_BYTES is a well-formed EndpointRequests message containing an
 * AgentHelloRequest.  The dispatcher decodes it successfully and produces a
 * non-empty HelloResponse payload.  Writing that payload to a zero-byte
 * ostream causes pb_encode_string() to fail -> RTP_ENCODE_ERROR.
 *
 * @param params Unused.
 * @return true if the assertion passes, false otherwise.
 */
static bool test_dispatch_ostream_full(void *params)
{
    el2go_rtp_ctx_t *ctx = NULL;
    pb_istream_t istream = pb_istream_from_buffer(HELLO_BYTES, sizeof(HELLO_BYTES));
    uint8_t tiny_buf[1];
    /* max_size=0: any write immediately returns "stream full" */
    pb_ostream_t ostream = pb_ostream_from_buffer(tiny_buf, 0);
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    (void)params;

    status = el2go_rtp_init(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_NOT_NULL_GOTO(ctx, exit);

    status = el2go_rtp_dispatch(ctx, &istream, &ostream, NULL);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_RTP_ENCODE_ERROR, status);

    status = el2go_rtp_free(&ctx);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

exit:
    return test_status;
}

/* ========================================================================== */
/* Session (round-trip) tests                                                  */
/* ========================================================================== */

/**
 * @brief A GoodbyeRequest with no status field must report provisioning failed.
 *
 * GOODBYE_NO_STATUS_BYTES is a well-formed GoodbyeRequest that carries no
 * UpdateStatusReport.  The dispatcher sets closed=true but update_success
 * stays false -> EL2GO_STATUS_RTP_PROVISIONING_FAILED.
 *
 * @param params Unused.
 * @return true if the assertion passes, false otherwise.
 */
static bool test_dispatch_goodbye_no_status_field(void *params)
{
    el2go_rtp_ctx_t *ctx = NULL;
    pb_istream_t istream =
        pb_istream_from_buffer(GOODBYE_NO_STATUS_BYTES, sizeof(GOODBYE_NO_STATUS_BYTES));
    pb_ostream_t ostream = PB_OSTREAM_SIZING;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    (void)params;

    status = el2go_rtp_init(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_NOT_NULL_GOTO(ctx, exit);

    status = el2go_rtp_dispatch(ctx, &istream, &ostream, NULL);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_RTP_PROVISIONING_FAILED, status);

    status = el2go_rtp_free(&ctx);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

exit:
    return test_status;
}

/**
 * @brief A GoodbyeRequest with a failure status must report provisioning failed.
 *
 * GOODBYE_FAILURE_BYTES carries UpdateStatusReport.status=ERR_UPDATE_FAILED.
 * update_success is set only when status==SUCCESS, so the dispatcher returns
 * EL2GO_STATUS_RTP_PROVISIONING_FAILED.
 *
 * @param params Unused.
 * @return true if the assertion passes, false otherwise.
 */
static bool test_dispatch_goodbye_failure_status(void *params)
{
    el2go_rtp_ctx_t *ctx = NULL;
    pb_istream_t istream =
        pb_istream_from_buffer(GOODBYE_FAILURE_BYTES, sizeof(GOODBYE_FAILURE_BYTES));
    pb_ostream_t ostream = PB_OSTREAM_SIZING;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    (void)params;

    status = el2go_rtp_init(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_NOT_NULL_GOTO(ctx, exit);

    status = el2go_rtp_dispatch(ctx, &istream, &ostream, NULL);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_RTP_PROVISIONING_FAILED, status);

    status = el2go_rtp_free(&ctx);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

exit:
    return test_status;
}

/**
 * @brief A complete Hello + Goodbye(SUCCESS) session must return SUCCESS.
 *
 * The input stream carries two consecutive length-delimited EndpointRequests
 * messages:
 *   1. AgentHelloRequest  - dispatcher replies with HelloResponse (into ostream)
 *   2. AgentGoodbyeRequest{ status = SUCCESS } - sets update_success=true, closed=true
 *
 * Expected result: EL2GO_STATUS_SUCCESS.
 *
 * The output uses PB_OSTREAM_SIZING so the HelloResponse bytes are discarded
 * but all internal encoding succeeds (sizing stream never returns "full").
 *
 * @param params Unused.
 * @return true if the assertion passes, false otherwise.
 */
static bool test_dispatch_hello_goodbye_success(void *params)
{
    el2go_rtp_ctx_t *ctx = NULL;
    /* Concatenate Hello and Goodbye(SUCCESS) into a single input buffer */
    uint8_t session_buf[sizeof(HELLO_BYTES) + sizeof(GOODBYE_SUCCESS_BYTES)];
    pb_istream_t istream;
    pb_ostream_t ostream = PB_OSTREAM_SIZING;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    (void)params;

    memcpy(session_buf, HELLO_BYTES, sizeof(HELLO_BYTES));
    memcpy(session_buf + sizeof(HELLO_BYTES), GOODBYE_SUCCESS_BYTES, sizeof(GOODBYE_SUCCESS_BYTES));

    istream = pb_istream_from_buffer(session_buf, sizeof(session_buf));

    status = el2go_rtp_init(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_NOT_NULL_GOTO(ctx, exit);

    status = el2go_rtp_dispatch(ctx, &istream, &ostream, NULL);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

    status = el2go_rtp_free(&ctx);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

exit:
    return test_status;
}

/**
 * @brief A Hello message with no following Goodbye must return a decode error.
 *
 * After sending the HelloResponse the dispatcher loops back to wait for the
 * next message.  The input stream is exhausted (EOF), so pb_decode_delimited()
 * returns false on the second iteration -> RTP_DECODE_ERROR.
 *
 * @param params Unused.
 * @return true if the assertion passes, false otherwise.
 */
static bool test_dispatch_hello_no_goodbye(void *params)
{
    el2go_rtp_ctx_t *ctx = NULL;
    pb_istream_t istream = pb_istream_from_buffer(HELLO_BYTES, sizeof(HELLO_BYTES));
    pb_ostream_t ostream = PB_OSTREAM_SIZING;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    (void)params;

    status = el2go_rtp_init(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_NOT_NULL_GOTO(ctx, exit);

    status = el2go_rtp_dispatch(ctx, &istream, &ostream, NULL);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_RTP_DECODE_ERROR, status);

    status = el2go_rtp_free(&ctx);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

exit:
    return test_status;
}

/* ========================================================================== */
/* Test registration                                                            */
/* ========================================================================== */

/**
 * @brief Register all el2go_rtp_dispatch() unit tests.
 */
void register_el2go_rtp_dispatch_tests(void)
{
    /* NULL argument tests */
    TEST_REGISTER(test_dispatch_null_ctx);
    TEST_REGISTER(test_dispatch_null_istream);
    TEST_REGISTER(test_dispatch_null_ostream);

    /* Decode-error tests */
    TEST_REGISTER(test_dispatch_empty_input_stream);
    TEST_REGISTER(test_dispatch_corrupted_input);
    TEST_REGISTER(test_dispatch_unknown_endpoint);
    TEST_REGISTER(test_dispatch_hello_malformed_body);

    /* CRL gate test */
    TEST_REGISTER(test_dispatch_crl_not_verified);

    /* Encode-error test */
    TEST_REGISTER(test_dispatch_ostream_full);

    /* Session (round-trip) tests */
    TEST_REGISTER(test_dispatch_goodbye_no_status_field);
    TEST_REGISTER(test_dispatch_goodbye_failure_status);
    TEST_REGISTER(test_dispatch_hello_goodbye_success);
    TEST_REGISTER(test_dispatch_hello_no_goodbye);
}

/** @} */ /* end of test_el2go_rtp_dispatch */
