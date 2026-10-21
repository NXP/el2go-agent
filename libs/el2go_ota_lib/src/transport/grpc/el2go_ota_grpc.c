/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/*
 * EL2GO OTA Library -- gRPC/HTTP/2 transport backend
 *
 * Implements the el2go_ota_transport_t vtable using a minimal HTTP/2 client
 * layered on top of the el2go_ota_tls abstraction.  ALPN negotiation for "h2"
 * is performed by el2go_ota_tls_connect() before this layer is used.
 *
 * HTTP/2 frame layout (RFC 7540 section 4.1):
 *   Bytes 0-2  : payload length (24-bit big-endian)
 *   Byte  3    : type
 *   Byte  4    : flags
 *   Bytes 5-8  : stream identifier (31-bit big-endian, R bit = 0)
 *
 * gRPC message framing (gRPC-over-HTTP/2 spec):
 *   Byte  0    : compressed-flag (0x00 -- no compression)
 *   Bytes 1-4  : message length (32-bit big-endian)
 *   Bytes 5+   : protobuf payload
 *
 * HPACK encoding uses static table entries only (RFC 7541 Appendix A):
 *   index 1  :authority        (name only, literal value)
 *   index 3  :method POST      (indexed)
 *   index 4  :path /           (name only, literal value)
 *   index 7  :scheme https     (indexed)
 *   content-type / te          (new-name literals)
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include "debug.h"
#include "osal.h"
#include "el2go_ota_transport.h"
#include "el2go_ota_tls.h"
#include "builtin_macros.h"

/* Constants */

/* HTTP/2 connection preface (RFC 7540 section 3.5). */
static const uint8_t HTTP2_PREFACE[24] = {
    0x50, 0x52, 0x49, 0x20, 0x2A, 0x20, 0x48, 0x54, /* PRI * HT */
    0x54, 0x50, 0x2F, 0x32, 0x2E, 0x30, 0x0D, 0x0A, /* TP/2.0\r\n */
    0x0D, 0x0A, 0x53, 0x4D, 0x0D, 0x0A, 0x0D, 0x0A  /* \r\nSM\r\n\r\n */
};

/* HTTP/2 frame type codes (RFC 7540 section 11.2). */
#define H2_TYPE_DATA 0x00U
#define H2_TYPE_HEADERS 0x01U
#define H2_TYPE_SETTINGS 0x04U
#define H2_TYPE_PING 0x06U
#define H2_TYPE_GOAWAY 0x07U
#define H2_TYPE_WINDOW_UPDATE 0x08U
#define H2_TYPE_RST_STREAM 0x03U

/* HTTP/2 flag bits. */
#define H2_FLAG_END_STREAM 0x01U
#define H2_FLAG_END_HEADERS 0x04U
#define H2_FLAG_ACK 0x01U

/* HTTP/2 wire sizes. */
#define H2_FRAME_HDR_LEN 9U /* bytes in every frame header */
#define H2_SETTINGS_LEN 0U  /* empty SETTINGS payload */
#define H2_PING_PAYLOAD_LEN 8U
#define H2_WINDOW_UPDATE_LEN 4U
#define H2_INITIAL_WINDOW_SIZE 65535U /* RFC 7540 s6.9.2: default flow-control window */
#define H2_BYTE_MASK 0xFFU            /* extract the low 8 bits of a multi-byte field */
#define H2_MSB_RESERVED_MASK \
    0x7FU /* mask off the reserved MSB of a 32-bit stream/increment field (RFC 7540 s4.1) */

/* gRPC message prefix. */
#define GRPC_MSG_HDR_LEN 5U

/* Maximum frames to drain while waiting for a response DATA frame. */
#define GRPC_RECV_MAX_FRAMES 64U

/* Size of the HPACK block scratch buffer (stack-allocated). */
#define HPACK_BUF_SIZE 256U

#define HPACK_HUFFMAN_NUM_SYMBOLS 257U
#define HPACK_HUFFMAN_EOS_SYMBOL 256U
#define HPACK_HUFFMAN_MAX_CODE_LEN 30U

/* Caps for decoding header names/values we actually care about. */
#define HPACK_NAME_BUF_CAP 32U
#define HPACK_VALUE_BUF_CAP 16U

/* HPACK static table indices that carry a non-200 :status pseudo-header
 * (RFC 7541 Appendix A, entries 9-14). Any one of these indexed (fully-
 * indexed, 0x80 | index) in a Response-Headers block means the server did
 * not return HTTP 200 at the HTTP/2 layer -- below the gRPC application
 * layer entirely, so grpc-status in the eventual Trailers cannot be
 * trusted (there may not even be a valid Trailers block). Index 8 is
 * :status 200 and is the only "good" indexed value checked for below. */
#define HPACK_STATIC_IDX_STATUS_200 8U

/* Context */

typedef struct {
    el2go_ota_tls_ctx_t *tls_ctx;
    const char *hostname; /* not owned; points into user config */
    uint32_t next_stream_id;
    uint32_t active_stream_id; /* stream opened by the most recent send(); the only
                                * stream grpc_recv() expects to receive a response on. */
    bool http2_ready;          /* preface + SETTINGS exchanged */
} grpc_ctx_t;

/* Internal helpers -- HTTP/2 frame building */

/*
 * Write a 9-byte HTTP/2 frame header into dst[0..8].
 * payload_len must fit in 24 bits.
 */
static void h2_build_frame_hdr(uint8_t *dst, uint32_t payload_len, uint8_t type, uint8_t flags,
                               uint32_t stream_id)
{
    dst[0] = (uint8_t)((payload_len >> 16U) & H2_BYTE_MASK);
    dst[1] = (uint8_t)((payload_len >> 8U) & H2_BYTE_MASK);
    dst[2] = (uint8_t)(payload_len & H2_BYTE_MASK);
    dst[3] = type;
    dst[4] = flags;
    /* Stream identifier: MSB (reserved) = 0, then 31-bit stream ID. */
    dst[5] = (uint8_t)((stream_id >> 24U) & H2_MSB_RESERVED_MASK);
    dst[6] = (uint8_t)((stream_id >> 16U) & H2_BYTE_MASK);
    dst[7] = (uint8_t)((stream_id >> 8U) & H2_BYTE_MASK);
    dst[8] = (uint8_t)(stream_id & H2_BYTE_MASK);
}

/*
 * Send an HTTP/2 SETTINGS frame with empty payload (used for both initial
 * SETTINGS and SETTINGS ACK, differentiated by flags).
 */
static el2go_ota_status_t h2_send_settings(grpc_ctx_t *ctx, uint8_t flags)
{
    uint8_t frame[H2_FRAME_HDR_LEN] = { 0U };
    el2go_status_t s = EL2GO_STATUS_FAILURE;

    h2_build_frame_hdr(frame, 0U, H2_TYPE_SETTINGS, flags, 0U);
    s = el2go_ota_tls_write(ctx->tls_ctx, frame, sizeof(frame));
    return (s == EL2GO_STATUS_SUCCESS) ? EL2GO_OTA_SUCCESS : EL2GO_OTA_ERROR_NETWORK;
}

/*
 * Send an HTTP/2 WINDOW_UPDATE frame on stream_id with the given increment.
 */
static el2go_ota_status_t h2_send_window_update(grpc_ctx_t *ctx, uint32_t stream_id,
                                                uint32_t increment)
{
    uint8_t frame[H2_FRAME_HDR_LEN + H2_WINDOW_UPDATE_LEN] = { 0U };
    el2go_status_t s = EL2GO_STATUS_FAILURE;

    h2_build_frame_hdr(frame, H2_WINDOW_UPDATE_LEN, H2_TYPE_WINDOW_UPDATE, 0x00U, stream_id);
    frame[9] = (uint8_t)((increment >> 24U) & H2_MSB_RESERVED_MASK);
    frame[10] = (uint8_t)((increment >> 16U) & H2_BYTE_MASK);
    frame[11] = (uint8_t)((increment >> 8U) & H2_BYTE_MASK);
    frame[12] = (uint8_t)(increment & H2_BYTE_MASK);
    s = el2go_ota_tls_write(ctx->tls_ctx, frame, sizeof(frame));
    return (s == EL2GO_STATUS_SUCCESS) ? EL2GO_OTA_SUCCESS : EL2GO_OTA_ERROR_NETWORK;
}

/*
 * Send an HTTP/2 PING ACK carrying the same 8-byte opaque payload as the
 * incoming PING.
 */
static el2go_ota_status_t h2_send_ping_ack(grpc_ctx_t *ctx, const uint8_t *ping_data)
{
    uint8_t frame[H2_FRAME_HDR_LEN + H2_PING_PAYLOAD_LEN] = { 0U };
    el2go_status_t s = EL2GO_STATUS_FAILURE;

    h2_build_frame_hdr(frame, H2_PING_PAYLOAD_LEN, H2_TYPE_PING, H2_FLAG_ACK, 0U);
    (void)memcpy(frame + H2_FRAME_HDR_LEN, ping_data, H2_PING_PAYLOAD_LEN);
    s = el2go_ota_tls_write(ctx->tls_ctx, frame, sizeof(frame));
    return (s == EL2GO_STATUS_SUCCESS) ? EL2GO_OTA_SUCCESS : EL2GO_OTA_ERROR_NETWORK;
}

/* Internal helpers -- HPACK encoding (static table only, no Huffman) */

/*
 * Append one byte to buf[*pos], growing pos.  Returns false if buf is full.
 */
static bool hpack_put_byte(uint8_t *buf, size_t buf_size, size_t *pos, uint8_t b)
{
    if (*pos >= buf_size) {
        return false;
    }
    buf[(*pos)++] = b;
    return true;
}

/*
 * Encode a length-prefixed string (H=0, no Huffman) into buf at *pos.
 * len must be < 128 so it fits in a single HPACK integer byte.
 */
static bool hpack_put_string(uint8_t *buf, size_t buf_size, size_t *pos, const char *str,
                             size_t len)
{
    size_t i = 0U;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (len >= 128U) {
        return false; /* multi-byte integer not needed for our use case */
    }
    if (!hpack_put_byte(buf, buf_size, pos, (uint8_t)len)) {
        return false;
    }
    for (i = 0U; i < len; i++) {
        if (!hpack_put_byte(buf, buf_size, pos, (uint8_t)str[i])) {
            return false;
        }
    }
    return true;
}

/*
 * Build the HPACK header block for a gRPC request into buf[0..buf_size-1].
 * Returns the number of bytes written, or 0 on error.
 *
 * Headers emitted:
 *   :method: POST                     (indexed, static #3)
 *   :scheme: https                    (indexed, static #7)
 *   :path:   <method_path>            (literal, name from static #4)
 *   :authority: <hostname>            (literal, name from static #1)
 *   content-type: application/grpc    (literal, new name, never-indexed)
 *   te: trailers                      (literal, new name, never-indexed)
 */
static size_t hpack_encode_grpc_request(uint8_t *buf, size_t buf_size, const char *method_path,
                                        const char *hostname)
{
    size_t pos = 0U;
    size_t method_path_len = 0U;
    size_t hostname_len = 0U;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    /* :method POST -- static index 3, fully indexed. */
    if (!hpack_put_byte(buf, buf_size, &pos, 0x80U | 3U)) {
        return 0U;
    }

    /* :scheme https -- static index 7, fully indexed. */
    if (!hpack_put_byte(buf, buf_size, &pos, 0x80U | 7U)) {
        return 0U;
    }

    /*
     * :path <method_path>
     * Literal with incremental indexing (0x40), name from static index 4.
     * Encoding: 0x44 | value string.
     */
    if (!hpack_put_byte(buf, buf_size, &pos, 0x40U | 4U)) {
        return 0U;
    }
    method_path_len = strlen(method_path);
    if (!hpack_put_string(buf, buf_size, &pos, method_path, method_path_len)) {
        return 0U;
    }

    /*
     * :authority <hostname>
     * Literal with incremental indexing, name from static index 1.
     * Encoding: 0x41 | value string.
     */
    if (!hpack_put_byte(buf, buf_size, &pos, 0x40U | 1U)) {
        return 0U;
    }
    hostname_len = strlen(hostname);
    if (!hpack_put_string(buf, buf_size, &pos, hostname, hostname_len)) {
        return 0U;
    }

    /*
     * content-type: application/grpc
     * Literal never-indexed (0x10), new name (name index = 0).
     */
    if (!hpack_put_byte(buf, buf_size, &pos, 0x10U)) {
        return 0U;
    }
    if (!hpack_put_string(buf, buf_size, &pos, "content-type", 12U)) {
        return 0U;
    }
    if (!hpack_put_string(buf, buf_size, &pos, "application/grpc", 16U)) {
        return 0U;
    }

    /*
     * te: trailers
     * Literal never-indexed, new name.
     */
    if (!hpack_put_byte(buf, buf_size, &pos, 0x10U)) {
        return 0U;
    }
    if (!hpack_put_string(buf, buf_size, &pos, "te", 2U)) {
        return 0U;
    }
    if (!hpack_put_string(buf, buf_size, &pos, "trailers", 8U)) {
        return 0U;
    }

    return pos;
}

/* Internal helpers -- gRPC status parsing */

/*
 * Standard gRPC status code names (indices 0-16, RFC: https://grpc.github.io/grpc/core/md_doc_statuscodes.html).
 */
static __attribute__((unused)) const char *grpc_status_name(uint32_t code)
{
    switch (code) {
    case 0U:
        return "OK";
    case 1U:
        return "CANCELLED";
    case 2U:
        return "UNKNOWN";
    case 3U:
        return "INVALID_ARGUMENT";
    case 4U:
        return "DEADLINE_EXCEEDED";
    case 5U:
        return "NOT_FOUND";
    case 6U:
        return "ALREADY_EXISTS";
    case 7U:
        return "PERMISSION_DENIED";
    case 8U:
        return "RESOURCE_EXHAUSTED";
    case 9U:
        return "FAILED_PRECONDITION";
    case 10U:
        return "ABORTED";
    case 11U:
        return "OUT_OF_RANGE";
    case 12U:
        return "UNIMPLEMENTED";
    case 13U:
        return "INTERNAL";
    case 14U:
        return "UNAVAILABLE";
    case 15U:
        return "DATA_LOSS";
    case 16U:
        return "UNAUTHENTICATED";
    default:
        return "UNKNOWN_CODE";
    }
}

/*
 * HTTP/2 error codes carried by RST_STREAM/GOAWAY frames (RFC 7540 S7,
 * "Error Codes" table). Decoded purely for diagnostics -- this client
 * still reports EL2GO_OTA_ERROR_NETWORK for both frame types regardless of
 * the specific code; only the log message gains detail.
 */
static __attribute__((unused)) const char *h2_error_code_name(uint32_t code)
{
    switch (code) {
    case 0x0U:
        return "NO_ERROR";
    case 0x1U:
        return "PROTOCOL_ERROR";
    case 0x2U:
        return "INTERNAL_ERROR";
    case 0x3U:
        return "FLOW_CONTROL_ERROR";
    case 0x4U:
        return "SETTINGS_TIMEOUT";
    case 0x5U:
        return "STREAM_CLOSED";
    case 0x6U:
        return "FRAME_SIZE_ERROR";
    case 0x7U:
        return "REFUSED_STREAM";
    case 0x8U:
        return "CANCEL";
    case 0x9U:
        return "COMPRESSION_ERROR";
    case 0xAU:
        return "CONNECT_ERROR";
    case 0xBU:
        return "ENHANCE_YOUR_CALM";
    case 0xCU:
        return "INADEQUATE_SECURITY";
    case 0xDU:
        return "HTTP_1_1_REQUIRED";
    default:
        return "UNKNOWN_ERROR_CODE";
    }
}

/* Internal helpers -- HPACK Huffman decoding (RFC 7541 Appendix B) */

/*
 * One entry of the canonical HPACK Huffman code table (RFC 7541 Appendix B).
 * code is the Huffman codeword, left-justified in the low `length` bits.
 * Table has 257 entries: symbols 0-255 plus the EOS symbol (index 256).
 * Values transcribed verbatim from the RFC and cross-checked against the
 * grpc-core reference implementation (src/core/.../huffsyms.cc).
 */
typedef struct {
    uint32_t code;
    uint8_t length;
} hpack_huffman_sym_t;

static const hpack_huffman_sym_t HPACK_HUFFMAN_TABLE[HPACK_HUFFMAN_NUM_SYMBOLS] = {
    { 0x1ff8U, 13U },     { 0x7fffd8U, 23U },   { 0xfffffe2U, 28U },  { 0xfffffe3U, 28U },
    { 0xfffffe4U, 28U },  { 0xfffffe5U, 28U },  { 0xfffffe6U, 28U },  { 0xfffffe7U, 28U },
    { 0xfffffe8U, 28U },  { 0xffffeaU, 24U },   { 0x3ffffffcU, 30U }, { 0xfffffe9U, 28U },
    { 0xfffffeaU, 28U },  { 0x3ffffffdU, 30U }, { 0xfffffebU, 28U },  { 0xfffffecU, 28U },
    { 0xfffffedU, 28U },  { 0xfffffeeU, 28U },  { 0xfffffefU, 28U },  { 0xffffff0U, 28U },
    { 0xffffff1U, 28U },  { 0xffffff2U, 28U },  { 0x3ffffffeU, 30U }, { 0xffffff3U, 28U },
    { 0xffffff4U, 28U },  { 0xffffff5U, 28U },  { 0xffffff6U, 28U },  { 0xffffff7U, 28U },
    { 0xffffff8U, 28U },  { 0xffffff9U, 28U },  { 0xffffffaU, 28U },  { 0xffffffbU, 28U },
    { 0x14U, 6U },        { 0x3f8U, 10U },      { 0x3f9U, 10U },      { 0xffaU, 12U },
    { 0x1ff9U, 13U },     { 0x15U, 6U },        { 0xf8U, 8U },        { 0x7faU, 11U },
    { 0x3faU, 10U },      { 0x3fbU, 10U },      { 0xf9U, 8U },        { 0x7fbU, 11U },
    { 0xfaU, 8U },        { 0x16U, 6U },        { 0x17U, 6U },        { 0x18U, 6U },
    { 0x0U, 5U },         { 0x1U, 5U },         { 0x2U, 5U },         { 0x19U, 6U },
    { 0x1aU, 6U },        { 0x1bU, 6U },        { 0x1cU, 6U },        { 0x1dU, 6U },
    { 0x1eU, 6U },        { 0x1fU, 6U },        { 0x5cU, 7U },        { 0xfbU, 8U },
    { 0x7ffcU, 15U },     { 0x20U, 6U },        { 0xffbU, 12U },      { 0x3fcU, 10U },
    { 0x1ffaU, 13U },     { 0x21U, 6U },        { 0x5dU, 7U },        { 0x5eU, 7U },
    { 0x5fU, 7U },        { 0x60U, 7U },        { 0x61U, 7U },        { 0x62U, 7U },
    { 0x63U, 7U },        { 0x64U, 7U },        { 0x65U, 7U },        { 0x66U, 7U },
    { 0x67U, 7U },        { 0x68U, 7U },        { 0x69U, 7U },        { 0x6aU, 7U },
    { 0x6bU, 7U },        { 0x6cU, 7U },        { 0x6dU, 7U },        { 0x6eU, 7U },
    { 0x6fU, 7U },        { 0x70U, 7U },        { 0x71U, 7U },        { 0x72U, 7U },
    { 0xfcU, 8U },        { 0x73U, 7U },        { 0xfdU, 8U },        { 0x1ffbU, 13U },
    { 0x7fff0U, 19U },    { 0x1ffcU, 13U },     { 0x3ffcU, 14U },     { 0x22U, 6U },
    { 0x7ffdU, 15U },     { 0x3U, 5U },         { 0x23U, 6U },        { 0x4U, 5U },
    { 0x24U, 6U },        { 0x5U, 5U },         { 0x25U, 6U },        { 0x26U, 6U },
    { 0x27U, 6U },        { 0x6U, 5U },         { 0x74U, 7U },        { 0x75U, 7U },
    { 0x28U, 6U },        { 0x29U, 6U },        { 0x2aU, 6U },        { 0x7U, 5U },
    { 0x2bU, 6U },        { 0x76U, 7U },        { 0x2cU, 6U },        { 0x8U, 5U },
    { 0x9U, 5U },         { 0x2dU, 6U },        { 0x77U, 7U },        { 0x78U, 7U },
    { 0x79U, 7U },        { 0x7aU, 7U },        { 0x7bU, 7U },        { 0x7ffeU, 15U },
    { 0x7fcU, 11U },      { 0x3ffdU, 14U },     { 0x1ffdU, 13U },     { 0xffffffcU, 28U },
    { 0xfffe6U, 20U },    { 0x3fffd2U, 22U },   { 0xfffe7U, 20U },    { 0xfffe8U, 20U },
    { 0x3fffd3U, 22U },   { 0x3fffd4U, 22U },   { 0x3fffd5U, 22U },   { 0x7fffd9U, 23U },
    { 0x3fffd6U, 22U },   { 0x7fffdaU, 23U },   { 0x7fffdbU, 23U },   { 0x7fffdcU, 23U },
    { 0x7fffddU, 23U },   { 0x7fffdeU, 23U },   { 0xffffebU, 24U },   { 0x7fffdfU, 23U },
    { 0xffffecU, 24U },   { 0xffffedU, 24U },   { 0x3fffd7U, 22U },   { 0x7fffe0U, 23U },
    { 0xffffeeU, 24U },   { 0x7fffe1U, 23U },   { 0x7fffe2U, 23U },   { 0x7fffe3U, 23U },
    { 0x7fffe4U, 23U },   { 0x1fffdcU, 21U },   { 0x3fffd8U, 22U },   { 0x7fffe5U, 23U },
    { 0x3fffd9U, 22U },   { 0x7fffe6U, 23U },   { 0x7fffe7U, 23U },   { 0xffffefU, 24U },
    { 0x3fffdaU, 22U },   { 0x1fffddU, 21U },   { 0xfffe9U, 20U },    { 0x3fffdbU, 22U },
    { 0x3fffdcU, 22U },   { 0x7fffe8U, 23U },   { 0x7fffe9U, 23U },   { 0x1fffdeU, 21U },
    { 0x7fffeaU, 23U },   { 0x3fffddU, 22U },   { 0x3fffdeU, 22U },   { 0xfffff0U, 24U },
    { 0x1fffdfU, 21U },   { 0x3fffdfU, 22U },   { 0x7fffebU, 23U },   { 0x7fffecU, 23U },
    { 0x1fffe0U, 21U },   { 0x1fffe1U, 21U },   { 0x3fffe0U, 22U },   { 0x1fffe2U, 21U },
    { 0x7fffedU, 23U },   { 0x3fffe1U, 22U },   { 0x7fffeeU, 23U },   { 0x7fffefU, 23U },
    { 0xfffeaU, 20U },    { 0x3fffe2U, 22U },   { 0x3fffe3U, 22U },   { 0x3fffe4U, 22U },
    { 0x7ffff0U, 23U },   { 0x3fffe5U, 22U },   { 0x3fffe6U, 22U },   { 0x7ffff1U, 23U },
    { 0x3ffffe0U, 26U },  { 0x3ffffe1U, 26U },  { 0xfffebU, 20U },    { 0x7fff1U, 19U },
    { 0x3fffe7U, 22U },   { 0x7ffff2U, 23U },   { 0x3fffe8U, 22U },   { 0x1ffffecU, 25U },
    { 0x3ffffe2U, 26U },  { 0x3ffffe3U, 26U },  { 0x3ffffe4U, 26U },  { 0x7ffffdeU, 27U },
    { 0x7ffffdfU, 27U },  { 0x3ffffe5U, 26U },  { 0xfffff1U, 24U },   { 0x1ffffedU, 25U },
    { 0x7fff2U, 19U },    { 0x1fffe3U, 21U },   { 0x3ffffe6U, 26U },  { 0x7ffffe0U, 27U },
    { 0x7ffffe1U, 27U },  { 0x3ffffe7U, 26U },  { 0x7ffffe2U, 27U },  { 0xfffff2U, 24U },
    { 0x1fffe4U, 21U },   { 0x1fffe5U, 21U },   { 0x3ffffe8U, 26U },  { 0x3ffffe9U, 26U },
    { 0xffffffdU, 28U },  { 0x7ffffe3U, 27U },  { 0x7ffffe4U, 27U },  { 0x7ffffe5U, 27U },
    { 0xfffecU, 20U },    { 0xfffff3U, 24U },   { 0xfffedU, 20U },    { 0x1fffe6U, 21U },
    { 0x3fffe9U, 22U },   { 0x1fffe7U, 21U },   { 0x1fffe8U, 21U },   { 0x7ffff3U, 23U },
    { 0x3fffeaU, 22U },   { 0x3fffebU, 22U },   { 0x1ffffeeU, 25U },  { 0x1ffffefU, 25U },
    { 0xfffff4U, 24U },   { 0xfffff5U, 24U },   { 0x3ffffeaU, 26U },  { 0x7ffff4U, 23U },
    { 0x3ffffebU, 26U },  { 0x7ffffe6U, 27U },  { 0x3ffffecU, 26U },  { 0x3ffffedU, 26U },
    { 0x7ffffe7U, 27U },  { 0x7ffffe8U, 27U },  { 0x7ffffe9U, 27U },  { 0x7ffffeaU, 27U },
    { 0x7ffffebU, 27U },  { 0xffffffeU, 28U },  { 0x7ffffecU, 27U },  { 0x7ffffedU, 27U },
    { 0x7ffffeeU, 27U },  { 0x7ffffefU, 27U },  { 0x7fffff0U, 27U },  { 0x3ffffeeU, 26U },
    { 0x3fffffffU, 30U },
};

/**
 * @brief Decode a Huffman-encoded byte string into out[0..out_cap-1].
 *
 * Walks @p data bit by bit (MSB first within each byte, matching RFC 7541
 * S5.2), accumulating a candidate code and comparing it against every table
 * entry of the same bit length. This is a reference-style linear-scan
 * decoder: simple and easy to verify, at the cost of O(symbols) per bit --
 * acceptable here because trailer blocks are tiny (<128 bytes).
 *
 * @param[in]  data     Input buffer containing the Huffman-encoded bit stream.
 * @param[in]  data_len Number of bytes in @p data.
 * @param[out] out      Output buffer to write decoded bytes into.
 * @param[in]  out_cap  Capacity of @p out in bytes.
 *
 * @return Number of decoded bytes written to @p out, or SIZE_MAX if the
 *         input does not decode to a valid Huffman sequence, decodes to more
 *         than @p out_cap bytes, or the trailing padding bits are not all 1s
 *         as required by the spec.
 */
static size_t hpack_huffman_decode(const uint8_t *data, size_t data_len, uint8_t *out,
                                   size_t out_cap)
{
    size_t total_bits = data_len * 8U;
    size_t bit_pos = 0U;
    uint32_t code = 0U;
    uint8_t code_len = 0U;
    size_t written = 0U;

    while (bit_pos < total_bits) {
        size_t byte_idx = bit_pos / 8U;
        uint8_t bit_idx = (uint8_t)(7U - (bit_pos % 8U));
        uint8_t bit = (uint8_t)((data[byte_idx] >> bit_idx) & 0x01U);
        bool found = false;
        uint32_t sym = 0U;

        code = (code << 1U) | bit;
        code_len++;
        bit_pos++;

        for (sym = 0U; sym < HPACK_HUFFMAN_NUM_SYMBOLS; sym++) {
            if (HPACK_HUFFMAN_TABLE[sym].length == code_len &&
                HPACK_HUFFMAN_TABLE[sym].code == code) {
                found = true;
                break;
            }
        }

        if (found) {
            if (sym == HPACK_HUFFMAN_EOS_SYMBOL) {
                break; /* EOS -- stop; remaining bits (if any) are padding */
            }
            if (written >= out_cap) {
                return SIZE_MAX; /* decoded output does not fit -- caller's buffer too small */
            }
            out[written] = (uint8_t)sym;
            written++;
            code = 0U;
            code_len = 0U;
        } else if (code_len > (uint8_t)HPACK_HUFFMAN_MAX_CODE_LEN) {
            return SIZE_MAX; /* no symbol has a code this long -- malformed input */
        } else {
            /* keep accumulating bits */
        }
    }

    /* Any leftover bits must be the all-1s EOS padding (RFC 7541 S5.2). */
    if (code_len > 0U) {
        uint32_t all_ones = (1UL << code_len) - 1UL;
        if (code != all_ones) {
            return SIZE_MAX;
        }
    }

    return written;
}

/**
 * @brief Decode an HPACK integer (RFC 7541 S5.1) starting at block[*pos].
 *
 * The first byte of the integer uses @p prefix_bits low bits for the initial
 * value. Advances @p pos past the consumed bytes on success.
 *
 * @param[in]     block       Input HPACK header block.
 * @param[in]     block_len   Length of @p block in bytes.
 * @param[in,out] pos         Byte offset into @p block; advanced on success.
 * @param[in]     prefix_bits Number of low bits in the first byte used for
 *                            the integer prefix (1-8).
 * @param[out]    out_value   Decoded integer value on success.
 *
 * @return true on success, false if the block is truncated or the value
 *         overflows the supported range.
 */
static bool hpack_decode_integer(const uint8_t *block, size_t block_len, size_t *pos,
                                 uint8_t prefix_bits, uint32_t *out_value)
{
    uint32_t mask = (uint32_t)((1UL << prefix_bits) - 1UL);
    uint32_t value = 0U;
    uint8_t shift = 0U;

    if (*pos >= block_len) {
        return false;
    }
    value = (uint32_t)(block[*pos] & mask);
    (*pos)++;

    if (value < mask) {
        *out_value = value;
        return true;
    }

    for (;;) {
        uint8_t b = 0U;
        uint32_t add_result = 0U;

        if (*pos >= block_len || shift >= 28U) {
            return false; /* truncated or integer too large for this use case */
        }
        b = block[*pos];
        (*pos)++;

        if (ADD_OVERFLOW(value, ((uint32_t)(b & 0x7FU) << shift), &add_result)) {
            return false;
        }
        value = add_result;
        shift += 7U;

        if ((b & 0x80U) == 0U) {
            break;
        }
    }

    *out_value = value;
    return true;
}

/**
 * @brief Skip over one HPACK string at block[*pos] without decoding it.
 *
 * Used to skip header field values that are not of interest (e.g. values of
 * headers other than grpc-status). Advances @p pos past the string on
 * success.
 *
 * @param[in]     block      Input HPACK header block.
 * @param[in]     block_len  Length of @p block in bytes.
 * @param[in,out] pos        Byte offset into @p block; advanced on success.
 *
 * @return true on success, false if the block is truncated or malformed.
 */
static bool hpack_skip_string(const uint8_t *block, size_t block_len, size_t *pos)
{
    uint32_t str_len = 0U;

    if (!hpack_decode_integer(block, block_len, pos, 7U, &str_len)) {
        return false;
    }
    if ((size_t)str_len > block_len - *pos) {
        return false;
    }
    *pos += (size_t)str_len;
    return true;
}

/**
 * @brief Decode one HPACK string at block[*pos] into @p out[0..out_cap-1].
 *
 * Applies Huffman decoding when the string's H-bit is set. Advances @p pos
 * past the string on success.
 *
 * Returns false without decoding if the string does not fit in @p out_cap;
 * the caller should treat that as "not the header we are looking for" rather
 * than aborting the whole trailer scan.
 *
 * @param[in]     block      Input HPACK header block.
 * @param[in]     block_len  Length of @p block in bytes.
 * @param[in,out] pos        Byte offset into @p block; advanced on success.
 * @param[out]    out        Buffer to write the decoded string into.
 * @param[in]     out_cap    Capacity of @p out in bytes.
 * @param[out]    out_len    Number of bytes written to @p out on success.
 *
 * @return true on success, false if the block is truncated, Huffman-decoding
 *         fails, or the decoded string does not fit in @p out_cap.
 */
static bool hpack_decode_string_bounded(const uint8_t *block, size_t block_len, size_t *pos,
                                        uint8_t *out, size_t out_cap, size_t *out_len)
{
    bool huffman = false;
    uint32_t str_len = 0U;
    size_t start = 0U;

    if (*pos >= block_len) {
        return false;
    }
    huffman = ((block[*pos] & 0x80U) != 0U);

    if (!hpack_decode_integer(block, block_len, pos, 7U, &str_len)) {
        return false;
    }
    if ((size_t)str_len > block_len - *pos) {
        return false;
    }
    start = *pos;
    *pos += (size_t)str_len;

    if (huffman) {
        size_t decoded_len = hpack_huffman_decode(&block[start], (size_t)str_len, out, out_cap);
        if (decoded_len == SIZE_MAX) {
            return false;
        }
        *out_len = decoded_len;
    } else {
        if ((size_t)str_len > out_cap) {
            return false;
        }
        (void)memcpy(out, &block[start], (size_t)str_len);
        *out_len = (size_t)str_len;
    }
    return true;
}

/**
 * @brief Walk an HPACK block looking for a "grpc-status" header.
 *
 * Walks the HPACK header-list representations in @p block (RFC 7541 S6)
 * looking for a literal header named "grpc-status" and decodes its value.
 *
 * This is a fallback used by grpc_parse_trailers() when the fast
 * plain-literal byte scan finds nothing -- i.e. when grpc-status is present
 * but Huffman-encoded (the common case for most production gRPC server
 * stacks). Indexed header fields and dynamic-table-size-update entries are
 * skipped without tracking HPACK dynamic-table state. Header values other
 * than grpc-status's own value are skipped undecoded, so an oversized
 * unrelated field cannot prevent grpc-status from being found.
 *
 * @param[in]  block      Input HPACK trailer block.
 * @param[in]  block_len  Length of @p block in bytes.
 * @param[out] out_code   Decoded grpc-status value on success.
 *
 * @return true and sets @p out_code if grpc-status was found and decoded.
 *         false if grpc-status was not found or the block could not be walked
 *         (malformed/truncated); both cases are treated as "not found" by the
 *         caller.
 */
static bool hpack_find_grpc_status_fallback(const uint8_t *block, size_t block_len,
                                            uint32_t *out_code)
{
    size_t pos = 0U;
    uint32_t iterations = 0U;

    while (pos < block_len && iterations < GRPC_RECV_MAX_FRAMES) {
        uint8_t first = block[pos];
        uint8_t prefix_bits = 0U;
        uint32_t idx_val = 0U;
        uint32_t name_idx = 0U;
        uint8_t name_buf[HPACK_NAME_BUF_CAP];
        size_t name_len = 0U;
        bool has_literal_name = false;
        bool is_grpc_status = false;

        iterations++;

        if ((first & 0x80U) != 0U) {
            /* Indexed header field -- fully self-contained, just skip it. */
            if (!hpack_decode_integer(block, block_len, &pos, 7U, &idx_val)) {
                return false;
            }
            continue;
        }

        if ((first & 0x40U) != 0U) {
            prefix_bits = 6U; /* literal with incremental indexing */
        } else if ((first & 0x20U) != 0U) {
            /* Dynamic table size update -- self-contained, skip it. */
            if (!hpack_decode_integer(block, block_len, &pos, 5U, &idx_val)) {
                return false;
            }
            continue;
        } else {
            prefix_bits = 4U; /* literal without indexing, or never indexed */
        }

        if (!hpack_decode_integer(block, block_len, &pos, prefix_bits, &name_idx)) {
            return false;
        }
        has_literal_name = (name_idx == 0U);

        if (has_literal_name) {
            if (!hpack_decode_string_bounded(block, block_len, &pos, name_buf, sizeof(name_buf),
                                             &name_len)) {
                /*
                 * Name present but too large for name_buf, or malformed.
                 * grpc-status's name is always short ("grpc-status", 11
                 * bytes) and well within HPACK_NAME_BUF_CAP, so a name that
                 * does not fit cannot be grpc-status -- but we cannot skip
                 * it either without having consumed it, so bail out and let
                 * the caller fail open (same as "not found").
                 */
                return false;
            }
            is_grpc_status = (name_len == (sizeof("grpc-status") - 1U)) &&
                             (memcmp(name_buf, "grpc-status", sizeof("grpc-status") - 1U) == 0);
        }

        if (is_grpc_status) {
            uint8_t value_buf[HPACK_VALUE_BUF_CAP];
            size_t value_len = 0U;
            uint32_t code = 0U;
            size_t j = 0U;
            uint32_t mul_result = 0U;
            uint32_t add_result = 0U;

            if (!hpack_decode_string_bounded(block, block_len, &pos, value_buf, sizeof(value_buf),
                                             &value_len)) {
                return false;
            }
            for (j = 0U; j < value_len; j++) {
                uint8_t c = value_buf[j];
                if (c < (uint8_t)'0' || c > (uint8_t)'9') {
                    break;
                }
                if (MUL_OVERFLOW(code, 10U, &mul_result) ||
                    ADD_OVERFLOW(mul_result, (uint32_t)(c - (uint8_t)'0'), &add_result)) {
                    return false; /* overflow -- malformed status code */
                }
                code = add_result;
            }
            *out_code = code;
            return true;
        }

        /* Not grpc-status -- skip its value without decoding. */
        if (!hpack_skip_string(block, block_len, &pos)) {
            return false;
        }
    }

    return false;
}

/**
 * @brief Validate the `:status` pseudo-header (and note `content-type`) in
 * a Response-Headers block.
 *
 * Walks the HPACK header-list representations in @p block (RFC 7541 S6)
 * looking for `:status` and `content-type`. This defends against a
 * misbehaving intermediary (e.g. a proxy/load balancer returning an HTTP-
 * level error or a non-gRPC response) being blindly parsed downstream as if
 * it were a valid gRPC response.
 *
 * `:status`: per RFC 7540 S8.1.2.4 every HTTP/2 response carries this
 * pseudo-header, and a gRPC server normally always returns 200 at the
 * HTTP/2 layer (errors are signalled via grpc-status in Trailers, not via
 * `:status`). An explicit, successfully-decoded non-200 `:status` is
 * therefore treated as a hard failure -- this function returns false.
 *
 * `content-type`: per the gRPC-over-HTTP2 spec this SHOULD be
 * "application/grpc" (optionally with a "+proto"/"+json" suffix). This is
 * only logged (VERBOSE/ERROR) if a mismatch is found, never a hard
 * failure -- unlike `:status`, this is a SHOULD, not a MUST, and failing
 * the call outright here would be riskier than it's worth for a mismatch
 * that is very unlikely to ever actually occur against this specific
 * server.
 *
 * Like hpack_find_grpc_status_fallback(), if `:status` cannot be
 * determined at all (e.g. because of an index this client cannot resolve
 * without tracking HPACK dynamic-table state, or because the headers do
 * not fit in @p block), this fails open -- consistent with the rest of
 * this file's generic "could not determine -> do not block" trailer/status
 * decoding philosophy. It is still presence-of-explicit-bad-status that
 * matters, not presence-of-good-status.
 *
 * @param[in] block      Input HPACK Response-Headers block.
 * @param[in] block_len  Length of @p block in bytes.
 *
 * @return true if `:status` is 200 or could not be determined; false if an
 *         explicit, successfully-decoded non-200 `:status` was found.
 */
static bool hpack_validate_response_headers(const uint8_t *block, size_t block_len)
{
    size_t pos = 0U;
    uint32_t iterations = 0U;

    while (pos < block_len && iterations < GRPC_RECV_MAX_FRAMES) {
        uint8_t first = block[pos];
        uint8_t prefix_bits = 0U;
        uint32_t idx_val = 0U;
        uint32_t name_idx = 0U;
        uint8_t name_buf[HPACK_NAME_BUF_CAP];
        size_t name_len = 0U;
        bool has_literal_name = false;
        bool is_status = false;
        bool is_content_type = false;

        iterations++;

        if ((first & 0x80U) != 0U) {
            /* Indexed header field -- fully self-contained. */
            if (!hpack_decode_integer(block, block_len, &pos, 7U, &idx_val)) {
                return true; /* malformed -- fail open */
            }
            /* Static table indices 9-14 (RFC 7541 Appendix A) are the
             * non-200 :status values (204, 206, 304, 400, 404, 500). Index
             * 8 is :status 200 and needs no special handling (it is the
             * success case already assumed by returning true below). */
            if (idx_val > HPACK_STATIC_IDX_STATUS_200 && idx_val <= 14U) {
                EL2GO_DBG_PRINTF(ERROR,
                                 "gRPC recv: Response-Headers :status is non-200 "
                                 "(HPACK static index %u)\n",
                                 (unsigned int)idx_val);
                return false;
            }
            continue;
        }

        if ((first & 0x40U) != 0U) {
            prefix_bits = 6U; /* literal with incremental indexing */
        } else if ((first & 0x20U) != 0U) {
            /* Dynamic table size update -- self-contained, skip it. */
            if (!hpack_decode_integer(block, block_len, &pos, 5U, &idx_val)) {
                return true; /* malformed -- fail open */
            }
            continue;
        } else {
            prefix_bits = 4U; /* literal without indexing, or never indexed */
        }

        if (!hpack_decode_integer(block, block_len, &pos, prefix_bits, &name_idx)) {
            return true; /* malformed -- fail open */
        }
        has_literal_name = (name_idx == 0U);

        if (has_literal_name) {
            if (!hpack_decode_string_bounded(block, block_len, &pos, name_buf, sizeof(name_buf),
                                             &name_len)) {
                return true; /* name too large/malformed -- fail open, cannot skip safely */
            }
            is_status = (name_len == (sizeof(":status") - 1U)) &&
                        (memcmp(name_buf, ":status", sizeof(":status") - 1U) == 0);
            is_content_type = (name_len == (sizeof("content-type") - 1U)) &&
                              (memcmp(name_buf, "content-type", sizeof("content-type") - 1U) == 0);
        }

        if (is_status) {
            uint8_t value_buf[HPACK_VALUE_BUF_CAP];
            size_t value_len = 0U;
            uint32_t code = 0U;
            size_t j = 0U;
            uint32_t mul_result = 0U;
            uint32_t add_result = 0U;
            bool decoded_ok = true;

            if (!hpack_decode_string_bounded(block, block_len, &pos, value_buf, sizeof(value_buf),
                                             &value_len)) {
                continue; /* value too large/malformed -- cannot determine, keep scanning */
            }
            for (j = 0U; j < value_len; j++) {
                uint8_t c = value_buf[j];
                if (c < (uint8_t)'0' || c > (uint8_t)'9') {
                    decoded_ok = false;
                    break;
                }
                if (MUL_OVERFLOW(code, 10U, &mul_result) ||
                    ADD_OVERFLOW(mul_result, (uint32_t)(c - (uint8_t)'0'), &add_result)) {
                    decoded_ok = false;
                    break;
                }
                code = add_result;
            }
            if (decoded_ok && code != 200U) {
                EL2GO_DBG_PRINTF(ERROR, "gRPC recv: Response-Headers :status is %u (not 200)\n",
                                 (unsigned int)code);
                return false;
            }
            continue;
        }

        if (is_content_type) {
            uint8_t value_buf[32U];
            size_t value_len = 0U;
            static const char expected_prefix[] = "application/grpc";

            if (!hpack_decode_string_bounded(block, block_len, &pos, value_buf, sizeof(value_buf),
                                             &value_len)) {
                continue; /* value too large/malformed -- just skip the diagnostic */
            }
            if (value_len < sizeof(expected_prefix) - 1U ||
                memcmp(value_buf, expected_prefix, sizeof(expected_prefix) - 1U) != 0) {
                EL2GO_DBG_PRINTF(VERBOSE,
                                 "gRPC recv: Response-Headers content-type is \"%.*s\", "
                                 "expected prefix \"%s\" (diagnostic only, not treated as "
                                 "an error)\n",
                                 (int)value_len, (const char *)value_buf, expected_prefix);
            }
            continue;
        }

        /* Not :status or content-type -- skip its value without decoding. */
        if (!hpack_skip_string(block, block_len, &pos)) {
            return true; /* malformed -- fail open */
        }
    }

    return true; /* no explicit non-200 :status found -- treat as OK */
}

/**
 * @brief Scan an HPACK trailer block for "grpc-status" and decode its value.
 *
 * Fast path: a linear byte search for the plain literal string "grpc-status"
 * (11 bytes) preceded by its HPACK length byte (0x0B). This matches when
 * grpc-status is sent as a non-Huffman literal, which is common for simple
 * server implementations.
 *
 * Fallback: if the fast path finds nothing, the block is walked generically
 * via hpack_find_grpc_status_fallback(), which also handles Huffman-encoded
 * header names -- the encoding used by the EL2GO OTA server. Without this
 * fallback a Huffman-encoded grpc-status would be silently treated as
 * "not found -> OK", masking real server-side errors.
 *
 * @param[in] block      Input HPACK trailer block (may be NULL).
 * @param[in] block_len  Length of @p block in bytes.
 *
 * @return EL2GO_OTA_SUCCESS      if grpc-status is 0 (OK) or not found.
 * @return EL2GO_OTA_ERROR_SERVER if grpc-status is non-zero.
 */
static el2go_ota_status_t grpc_parse_trailers(const uint8_t *block, size_t block_len)
{
    static const uint8_t NAME_PREFIX[12] = {
        0x0BU, /* HPACK string length = 11 */
        'g',   'r', 'p', 'c', '-', 's', 't', 'a', 't', 'u', 's'
    };
    size_t i = 0U;
    uint32_t code = 0U;
    uint8_t val_len = 0U;
    size_t val_start = 0U;
    size_t j = 0U;
    uint32_t mul_result = 0U;
    uint32_t add_result = 0U;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (block == NULL || block_len == 0U) {
        return EL2GO_OTA_SUCCESS; /* no trailers to parse -- treat as OK */
    }

    /*
     * Fast path: search for the 12-byte plain-literal pattern anywhere in
     * the block. Note this loop's bound naturally skips the fast path
     * (never executes) when block_len is too short to contain it -- that
     * does NOT mean grpc-status cannot be present: a Huffman-encoded
     * "grpc-status" name is itself shorter than its 11-byte plain-text
     * form, so a short block must still be given to the HPACK fallback
     * below rather than being short-circuited to "not found" here.
     */
    for (i = 0U; i + sizeof(NAME_PREFIX) + 2U <= block_len; i++) {
        bool match = true;
        size_t k;

        for (k = 0U; k < sizeof(NAME_PREFIX); k++) {
            if (block[i + k] != NAME_PREFIX[k]) {
                match = false;
                break;
            }
        }

        if (!match) {
            continue;
        }

        /* Found "grpc-status" name.  Next byte is the value string length. */
        val_len = block[i + sizeof(NAME_PREFIX)];
        val_start = i + sizeof(NAME_PREFIX) + 1U;

        if (val_start >= block_len || (size_t)val_len > block_len - val_start) {
            break; /* truncated -- bail out */
        }

        /* Parse decimal ASCII value (1-2 digits for codes 0-16). */
        code = 0U;
        for (j = 0U; j < (size_t)val_len; j++) {
            uint8_t c = block[val_start + j];
            if (c < (uint8_t)'0' || c > (uint8_t)'9') {
                break; /* non-digit -- stop */
            }
            if (MUL_OVERFLOW(code, 10U, &mul_result) ||
                ADD_OVERFLOW(mul_result, (uint32_t)(c - (uint8_t)'0'), &add_result)) {
                break; /* overflow -- malformed status code, bail out */
            }
            code = add_result;
        }

        if (code != 0U) {
            EL2GO_DBG_PRINTF(ERROR, "gRPC recv: server returned grpc-status %u (%s)\n",
                             (unsigned int)code, grpc_status_name(code));
            return EL2GO_OTA_ERROR_SERVER;
        }

        EL2GO_DBG_PRINTF(VERBOSE, "gRPC recv: grpc-status OK (0)\n");
        return EL2GO_OTA_SUCCESS;
    }

    /* grpc-status not found via the fast path -- try the HPACK fallback,
     * which also understands Huffman-encoded header names. */
    {
        uint32_t fallback_code = 0U;

        if (hpack_find_grpc_status_fallback(block, block_len, &fallback_code)) {
            if (fallback_code != 0U) {
                EL2GO_DBG_PRINTF(ERROR, "gRPC recv: server returned grpc-status %u (%s)\n",
                                 (unsigned int)fallback_code, grpc_status_name(fallback_code));
                return EL2GO_OTA_ERROR_SERVER;
            }
            EL2GO_DBG_PRINTF(VERBOSE, "gRPC recv: grpc-status OK (0) [HPACK fallback]\n");
            return EL2GO_OTA_SUCCESS;
        }
    }

    /* grpc-status not found in trailer block -- treat as OK. */
    return EL2GO_OTA_SUCCESS;
}

/* HTTP/2 connection setup */

/*
 * Read and drain frame bodies during the initial SETTINGS exchange.
 * Sends SETTINGS ACK once the server SETTINGS frame is received.
 * Also handles PING and ignores WINDOW_UPDATE on stream 0.
 * Returns EL2GO_OTA_SUCCESS once the server SETTINGS has been acknowledged.
 */
static el2go_ota_status_t h2_do_settings_exchange(grpc_ctx_t *ctx)
{
    uint8_t hdr[H2_FRAME_HDR_LEN] = { 0U };
    uint8_t tmp[H2_PING_PAYLOAD_LEN] = { 0U }; /* largest frame body we need to read here */
    uint32_t pay_len = 0U;
    uint8_t frame_type = 0U;
    uint8_t flags = 0U;
    size_t n_read = 0U;
    el2go_status_t s = EL2GO_STATUS_FAILURE;
    bool server_settings_acked = false;
    uint32_t iterations = 0U;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    while (!server_settings_acked && iterations < 16U) {
        iterations++;

        s = el2go_ota_tls_read(ctx->tls_ctx, hdr, H2_FRAME_HDR_LEN, &n_read);
        if (s != EL2GO_STATUS_SUCCESS || n_read < H2_FRAME_HDR_LEN) {
            EL2GO_DBG_PRINTF(ERROR, "h2 settings: frame header read failed\n");
            return EL2GO_OTA_ERROR_NETWORK;
        }

        pay_len = ((uint32_t)hdr[0] << 16U) | ((uint32_t)hdr[1] << 8U) | (uint32_t)hdr[2];
        frame_type = hdr[3];
        flags = hdr[4];
        /* stream_id bytes hdr[5..8] ignored for these connection-level frames */

        if (frame_type == H2_TYPE_SETTINGS) {
            if ((flags & H2_FLAG_ACK) != 0U) {
                /* Server ACK for our SETTINGS -- drain (empty payload). */
            } else {
                /*
                 * Server SETTINGS -- drain the payload (settings params we
                 * do not act on for this simple client), then send ACK.
                 */
                size_t remaining = pay_len;
                while (remaining > 0U) {
                    size_t to_read = (remaining > sizeof(tmp)) ? sizeof(tmp) : remaining;
                    s = el2go_ota_tls_read(ctx->tls_ctx, tmp, to_read, &n_read);
                    if (s != EL2GO_STATUS_SUCCESS || n_read < to_read) {
                        return EL2GO_OTA_ERROR_NETWORK;
                    }
                    remaining -= n_read;
                }
                /* Send SETTINGS ACK (empty SETTINGS with ACK flag). */
                el2go_ota_status_t ack_status = h2_send_settings(ctx, H2_FLAG_ACK);
                if (ack_status != EL2GO_OTA_SUCCESS) {
                    return ack_status;
                }
                server_settings_acked = true;
            }
        } else if (frame_type == H2_TYPE_PING) {
            /* Must read 8-byte payload and send PONG. */
            if (pay_len == H2_PING_PAYLOAD_LEN) {
                s = el2go_ota_tls_read(ctx->tls_ctx, tmp, H2_PING_PAYLOAD_LEN, &n_read);
                if (s != EL2GO_STATUS_SUCCESS || n_read < H2_PING_PAYLOAD_LEN) {
                    return EL2GO_OTA_ERROR_NETWORK;
                }
                (void)h2_send_ping_ack(ctx, tmp);
            }
        } else {
            /* Unknown / connection-level frame -- drain payload. */
            size_t remaining = pay_len;
            while (remaining > 0U) {
                size_t to_read = (remaining > sizeof(tmp)) ? sizeof(tmp) : remaining;
                s = el2go_ota_tls_read(ctx->tls_ctx, tmp, to_read, &n_read);
                if (s != EL2GO_STATUS_SUCCESS || n_read < to_read) {
                    return EL2GO_OTA_ERROR_NETWORK;
                }
                remaining -= n_read;
            }
        }
    }

    if (!server_settings_acked) {
        EL2GO_DBG_PRINTF(ERROR, "h2 settings: did not receive server SETTINGS\n");
        return EL2GO_OTA_ERROR_NETWORK;
    }

    return EL2GO_OTA_SUCCESS;
}

/*
 * Perform the HTTP/2 connection preface:
 *   1. Send the 24-byte client connection preface.
 *   2. Send an empty SETTINGS frame.
 *   3. Wait for the server SETTINGS and send the ACK.
 */
static el2go_ota_status_t h2_init_connection(grpc_ctx_t *ctx)
{
    el2go_status_t s = EL2GO_STATUS_FAILURE;
    el2go_ota_status_t status = EL2GO_OTA_ERROR_INTERNAL;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    s = el2go_ota_tls_write(ctx->tls_ctx, HTTP2_PREFACE, sizeof(HTTP2_PREFACE));
    if (s != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "h2 init: preface write failed\n");
        return EL2GO_OTA_ERROR_NETWORK;
    }

    status = h2_send_settings(ctx, 0x00U);
    if (status != EL2GO_OTA_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "h2 init: SETTINGS send failed\n");
        return status;
    }

    status = h2_do_settings_exchange(ctx);
    if (status != EL2GO_OTA_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "h2 init: SETTINGS exchange failed\n");
        return status;
    }

    EL2GO_DBG_PRINTF(VERBOSE, "h2 init: connection ready\n");
    return EL2GO_OTA_SUCCESS;
}

/* vtable -- send */

static el2go_ota_status_t grpc_send(el2go_ota_transport_t *t, const char *method_path,
                                    const uint8_t *msg, size_t msg_len)
{
    grpc_ctx_t *ctx = NULL;
    uint8_t hpack_buf[HPACK_BUF_SIZE] = { 0U };
    uint8_t frame_hdr[H2_FRAME_HDR_LEN] = { 0U };
    uint8_t grpc_prefix[GRPC_MSG_HDR_LEN] = { 0U };
    size_t hpack_len = 0U;
    uint32_t stream_id = 0U;
    uint32_t data_payload_len = 0U;
    el2go_status_t s = EL2GO_STATUS_FAILURE;
    el2go_ota_status_t status = EL2GO_OTA_ERROR_INTERNAL;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (t == NULL || method_path == NULL || msg == NULL || msg_len == 0U) {
        return EL2GO_OTA_ERROR_INVALID_PARAM;
    }

    ctx = (grpc_ctx_t *)t->impl_ctx;
    if (ctx == NULL) {
        return EL2GO_OTA_ERROR_INVALID_PARAM;
    }

    /* Step 1: one-time HTTP/2 connection preface + SETTINGS exchange. */
    if (!ctx->http2_ready) {
        status = h2_init_connection(ctx);
        if (status != EL2GO_OTA_SUCCESS) {
            return status;
        }
        ctx->http2_ready = true;
    }

    /* Step 2: allocate a new odd stream ID. grpc_recv() will only accept
     * stream-specific frames (DATA/HEADERS/RST_STREAM) carrying this id as
     * the response to this call; frames for any other stream id are stray
     * (e.g. left over from a prior call) and are drained without being
     * mistaken for this call's response. */
    stream_id = ctx->next_stream_id;
    ctx->next_stream_id += 2U;
    ctx->active_stream_id = stream_id;

    /* Step 3: HEADERS frame (request headers, END_HEADERS). */
    hpack_len = hpack_encode_grpc_request(hpack_buf, sizeof(hpack_buf), method_path, ctx->hostname);
    if (hpack_len == 0U) {
        EL2GO_DBG_PRINTF(ERROR, "gRPC send: HPACK encoding failed\n");
        return EL2GO_OTA_ERROR_INTERNAL;
    }

    h2_build_frame_hdr(frame_hdr, (uint32_t)hpack_len, H2_TYPE_HEADERS, H2_FLAG_END_HEADERS,
                       stream_id);
    s = el2go_ota_tls_write(ctx->tls_ctx, frame_hdr, H2_FRAME_HDR_LEN);
    if (s != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "gRPC send: HEADERS frame header write failed\n");
        return EL2GO_OTA_ERROR_NETWORK;
    }
    s = el2go_ota_tls_write(ctx->tls_ctx, hpack_buf, hpack_len);
    if (s != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "gRPC send: HEADERS frame payload write failed\n");
        return EL2GO_OTA_ERROR_NETWORK;
    }

    /*
     * Step 4: DATA frame (gRPC message, END_STREAM).
     *   DATA payload = 5-byte gRPC prefix + protobuf message.
     */
    if (msg_len > (size_t)(UINT32_MAX - GRPC_MSG_HDR_LEN)) {
        EL2GO_DBG_PRINTF(ERROR, "gRPC send: message too large\n");
        return EL2GO_OTA_ERROR_INVALID_PARAM;
    }
    data_payload_len = (uint32_t)(GRPC_MSG_HDR_LEN + msg_len);

    h2_build_frame_hdr(frame_hdr, data_payload_len, H2_TYPE_DATA, H2_FLAG_END_STREAM, stream_id);
    s = el2go_ota_tls_write(ctx->tls_ctx, frame_hdr, H2_FRAME_HDR_LEN);
    if (s != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "gRPC send: DATA frame header write failed\n");
        return EL2GO_OTA_ERROR_NETWORK;
    }

    /* gRPC message prefix: compressed=0, big-endian length. */
    grpc_prefix[0] = 0x00U;
    grpc_prefix[1] = (uint8_t)((msg_len >> 24U) & H2_BYTE_MASK);
    grpc_prefix[2] = (uint8_t)((msg_len >> 16U) & H2_BYTE_MASK);
    grpc_prefix[3] = (uint8_t)((msg_len >> 8U) & H2_BYTE_MASK);
    grpc_prefix[4] = (uint8_t)(msg_len & H2_BYTE_MASK);

    s = el2go_ota_tls_write(ctx->tls_ctx, grpc_prefix, GRPC_MSG_HDR_LEN);
    if (s != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "gRPC send: DATA gRPC prefix write failed\n");
        return EL2GO_OTA_ERROR_NETWORK;
    }
    s = el2go_ota_tls_write(ctx->tls_ctx, msg, msg_len);
    if (s != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "gRPC send: DATA payload write failed\n");
        return EL2GO_OTA_ERROR_NETWORK;
    }

    /*
     * Step 5: WINDOW_UPDATE on stream 0 and on this stream so the server
     * can send the response without being flow-controlled.
     */
    status = h2_send_window_update(ctx, 0U, H2_INITIAL_WINDOW_SIZE);
    if (status != EL2GO_OTA_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "gRPC send: WINDOW_UPDATE(conn) failed\n");
        return status;
    }
    status = h2_send_window_update(ctx, stream_id, H2_INITIAL_WINDOW_SIZE);
    if (status != EL2GO_OTA_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "gRPC send: WINDOW_UPDATE(stream) failed\n");
        return status;
    }

    EL2GO_DBG_PRINTF(VERBOSE, "gRPC send: stream %u, %zu byte(s) sent\n", (unsigned int)stream_id,
                     msg_len);
    return EL2GO_OTA_SUCCESS;
}

/* vtable -- recv */

static el2go_ota_status_t grpc_recv(el2go_ota_transport_t *t, uint8_t *buf, size_t buf_len,
                                    size_t *out_len)
{
    grpc_ctx_t *ctx = NULL;
    uint8_t hdr[H2_FRAME_HDR_LEN] = { 0U };
    uint8_t tmp[H2_PING_PAYLOAD_LEN] = { 0U };
    uint32_t pay_len = 0U;
    uint8_t frame_type = 0U;
    uint8_t flags = 0U;
    size_t n_read = 0U;
    el2go_status_t s = EL2GO_STATUS_FAILURE;
    uint32_t iterations = 0U;
    bool data_received = false;
    uint32_t stream_id = 0U;
    bool is_active_stream = false;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (t == NULL || buf == NULL || out_len == NULL) {
        return EL2GO_OTA_ERROR_INVALID_PARAM;
    }

    ctx = (grpc_ctx_t *)t->impl_ctx;
    if (ctx == NULL) {
        return EL2GO_OTA_ERROR_INVALID_PARAM;
    }
    *out_len = 0U;
    data_received = false;
    iterations = 0U;

    while (iterations < GRPC_RECV_MAX_FRAMES) {
        iterations++;

        /* Read the 9-byte HTTP/2 frame header. */
        s = el2go_ota_tls_read(ctx->tls_ctx, hdr, H2_FRAME_HDR_LEN, &n_read);
        if (s != EL2GO_STATUS_SUCCESS || n_read < H2_FRAME_HDR_LEN) {
            EL2GO_DBG_PRINTF(ERROR, "gRPC recv: frame header read failed\n");
            return EL2GO_OTA_ERROR_NETWORK;
        }

        pay_len = ((uint32_t)hdr[0] << 16U) | ((uint32_t)hdr[1] << 8U) | (uint32_t)hdr[2];
        frame_type = hdr[3];
        flags = hdr[4];
        /*
         * Stream identifier (RFC 7540 S4.1): 31 bits, MSB (reserved) masked
         * off. Needed to detect stray frames left over from a prior call on
         * this connection (e.g. a late DATA/HEADERS/RST_STREAM for a stream
         * this grpc_recv() call did not open) so they are drained instead of
         * being mistaken for the current call's response.
         */
        stream_id = (((uint32_t)hdr[5] & H2_MSB_RESERVED_MASK) << 24U) | ((uint32_t)hdr[6] << 16U) |
                    ((uint32_t)hdr[7] << 8U) | (uint32_t)hdr[8];
        is_active_stream = (stream_id == ctx->active_stream_id);

        switch (frame_type) {
        /* DATA frame: contains the gRPC response message. */
        case H2_TYPE_DATA:
            if (!is_active_stream) {
                /*
                 * Stray DATA frame for a stream other than the one this
                 * call opened (e.g. late-arriving data for a previous
                 * call). Drain and ignore -- do not treat it as this
                 * call's response.
                 */
                EL2GO_DBG_PRINTF(VERBOSE, "gRPC recv: ignoring DATA for stream %u (active=%u)\n",
                                 (unsigned int)stream_id, (unsigned int)ctx->active_stream_id);
                {
                    size_t remaining = pay_len;
                    while (remaining > 0U) {
                        size_t to_drain = (remaining > sizeof(tmp)) ? sizeof(tmp) : remaining;
                        s = el2go_ota_tls_read(ctx->tls_ctx, tmp, to_drain, &n_read);
                        if (s != EL2GO_STATUS_SUCCESS || n_read < to_drain) {
                            return EL2GO_OTA_ERROR_NETWORK;
                        }
                        remaining -= n_read;
                    }
                }
                break;
            }
            if (pay_len < GRPC_MSG_HDR_LEN) {
                EL2GO_DBG_PRINTF(ERROR, "gRPC recv: DATA payload too short (%u bytes)\n",
                                 (unsigned int)pay_len);
                return EL2GO_OTA_ERROR_NETWORK;
            }
            {
                uint8_t grpc_prefix[GRPC_MSG_HDR_LEN] = { 0U };
                uint32_t grpc_msg_len = 0U;
                size_t body_len = 0U;

                /* Read the 5-byte gRPC message prefix. */
                s = el2go_ota_tls_read(ctx->tls_ctx, grpc_prefix, GRPC_MSG_HDR_LEN, &n_read);
                if (s != EL2GO_STATUS_SUCCESS || n_read < GRPC_MSG_HDR_LEN) {
                    EL2GO_DBG_PRINTF(ERROR, "gRPC recv: gRPC prefix read failed\n");
                    return EL2GO_OTA_ERROR_NETWORK;
                }

                if (grpc_prefix[0] != 0x00U) {
                    EL2GO_DBG_PRINTF(ERROR, "gRPC recv: compressed flag 0x%02X not supported\n",
                                     (unsigned int)grpc_prefix[0]);
                    return EL2GO_OTA_ERROR_NETWORK;
                }

                grpc_msg_len = ((uint32_t)grpc_prefix[1] << 24U) |
                               ((uint32_t)grpc_prefix[2] << 16U) |
                               ((uint32_t)grpc_prefix[3] << 8U) | (uint32_t)grpc_prefix[4];

                body_len = (size_t)grpc_msg_len;

                /*
                 * Diagnostic only (no behaviour change): per the gRPC-over-HTTP2
                 * spec, "DATA frame boundaries have no relation to
                 * Length-Prefixed-Message boundaries" -- a server is always
                 * legally allowed to split a single gRPC message across
                 * multiple DATA frames, regardless of message size. This
                 * client does not implement reassembly across frames (an
                 * accepted MVP limitation; see ota/el2go_ota_config.h), so if
                 * that ever happens the subsequent reads below will desync
                 * and this call will fail with EL2GO_OTA_ERROR_NETWORK (safe:
                 * the download engine already retries on network errors).
                 * This log line exists purely so that failure mode is
                 * instantly recognizable in the field instead of looking like
                 * a generic/unexplained network error.
                 */
                if ((size_t)pay_len < GRPC_MSG_HDR_LEN + body_len) {
                    EL2GO_DBG_PRINTF(ERROR,
                                     "gRPC recv: message (%zu bytes) split across multiple "
                                     "DATA frames (this frame only has %u byte(s) after the "
                                     "gRPC prefix) -- reassembly not implemented, call will "
                                     "likely fail with a network error\n",
                                     body_len,
                                     (unsigned int)((size_t)pay_len > GRPC_MSG_HDR_LEN ?
                                                        (size_t)pay_len - GRPC_MSG_HDR_LEN :
                                                        0U));
                }

                if (body_len > buf_len) {
                    EL2GO_DBG_PRINTF(ERROR,
                                     "gRPC recv: gRPC message %zu bytes exceeds buffer %zu\n",
                                     body_len, buf_len);
                    return EL2GO_OTA_ERROR_INTERNAL;
                }

                if (body_len > 0U) {
                    s = el2go_ota_tls_read(ctx->tls_ctx, buf, body_len, &n_read);
                    if (s != EL2GO_STATUS_SUCCESS || n_read < body_len) {
                        EL2GO_DBG_PRINTF(ERROR,
                                         "gRPC recv: data body read failed "
                                         "(got %zu/%zu)\n",
                                         n_read, body_len);
                        return EL2GO_OTA_ERROR_NETWORK;
                    }
                    *out_len = n_read;
                }

                data_received = true;
                EL2GO_DBG_PRINTF(VERBOSE, "gRPC recv: %zu byte(s) received\n", *out_len);

                /* Drain any padding bytes (pay_len - GRPC_MSG_HDR_LEN - body_len). */
                {
                    size_t padding = (size_t)(pay_len - GRPC_MSG_HDR_LEN) - body_len;
                    while (padding > 0U) {
                        size_t to_drain = (padding > sizeof(tmp)) ? sizeof(tmp) : padding;
                        s = el2go_ota_tls_read(ctx->tls_ctx, tmp, to_drain, &n_read);
                        if (s != EL2GO_STATUS_SUCCESS || n_read < to_drain) {
                            return EL2GO_OTA_ERROR_NETWORK;
                        }
                        padding -= n_read;
                    }
                }

                /* If END_STREAM set on DATA, the response is complete. */
                if ((flags & H2_FLAG_END_STREAM) != 0U) {
                    return EL2GO_OTA_SUCCESS;
                }
            }
            break;

        /*
         * HEADERS frame: either
         *   - Response-Headers (no END_STREAM): precedes zero or more DATA
         *     frames, drained here (no grpc-status; status is only ever
         *     sent in Trailers), or
         *   - Trailers (END_STREAM set): the final HEADERS block of the
         *     response, carrying grpc-status/grpc-message. Per the gRPC/
         *     HTTP2 spec, this is true regardless of whether any DATA frame
         *     preceded it:
         *       Response -> (Response-Headers *Length-Prefixed-Message Trailers)
         *                 / Trailers-Only
         *     Trailers-Only (no preceding DATA frame, data_received == false)
         *     is explicitly permitted for calls that fail immediately, so
         *     END_STREAM alone -- not data_received -- is what marks a
         *     HEADERS frame as Trailers.
         */
        case H2_TYPE_HEADERS:
            if (!is_active_stream) {
                /*
                 * Stray HEADERS frame (response headers or trailers) for a
                 * stream other than the one this call opened. Drain and
                 * ignore -- do not treat it as this call's response or
                 * trailers.
                 */
                EL2GO_DBG_PRINTF(VERBOSE, "gRPC recv: ignoring HEADERS for stream %u (active=%u)\n",
                                 (unsigned int)stream_id, (unsigned int)ctx->active_stream_id);
                {
                    size_t remaining = pay_len;
                    while (remaining > 0U) {
                        size_t to_drain = (remaining > sizeof(tmp)) ? sizeof(tmp) : remaining;
                        s = el2go_ota_tls_read(ctx->tls_ctx, tmp, to_drain, &n_read);
                        if (s != EL2GO_STATUS_SUCCESS || n_read < to_drain) {
                            return EL2GO_OTA_ERROR_NETWORK;
                        }
                        remaining -= n_read;
                    }
                }
            } else if ((flags & H2_FLAG_END_STREAM) != 0U) {
                /*
                 * Trailers (Trailers-Only if !data_received): read the block
                 * into a stack buffer so grpc_parse_trailers() can scan it
                 * for grpc-status. Trailer blocks are typically < 64 bytes;
                 * use 128 bytes to be safe. Any overflow is drained and
                 * ignored.
                 */
                uint8_t trailer_buf[128U] = { 0U };
                size_t to_read = 0U;
                size_t overflow = 0U;
                el2go_ota_status_t grpc_status = EL2GO_OTA_ERROR_INTERNAL;

                if (!data_received) {
                    EL2GO_DBG_PRINTF(VERBOSE,
                                     "gRPC recv: Trailers-Only response (no DATA frame)\n");
                }

                to_read = (pay_len <= sizeof(trailer_buf)) ? pay_len : sizeof(trailer_buf);
                if (to_read > 0U) {
                    s = el2go_ota_tls_read(ctx->tls_ctx, trailer_buf, to_read, &n_read);
                    if (s != EL2GO_STATUS_SUCCESS || n_read < to_read) {
                        return EL2GO_OTA_ERROR_NETWORK;
                    }
                }
                /* Drain any overflow bytes that did not fit in trailer_buf. */
                overflow = (pay_len > sizeof(trailer_buf)) ? (pay_len - sizeof(trailer_buf)) : 0U;
                while (overflow > 0U) {
                    size_t to_drain = (overflow > sizeof(tmp)) ? sizeof(tmp) : overflow;
                    s = el2go_ota_tls_read(ctx->tls_ctx, tmp, to_drain, &n_read);
                    if (s != EL2GO_STATUS_SUCCESS || n_read < to_drain) {
                        return EL2GO_OTA_ERROR_NETWORK;
                    }
                    overflow -= n_read;
                }
                grpc_status = grpc_parse_trailers(trailer_buf, to_read);
                return grpc_status;
            } else {
                /*
                 * Response-Headers (no END_STREAM): validate :status (and
                 * diagnose content-type) before continuing. Per RFC 7540
                 * S8.1.2.4 every HTTP/2 response carries :status; a gRPC
                 * server normally always returns 200 here (application-
                 * level errors go through grpc-status in Trailers, not
                 * :status). A non-200 :status means something below the
                 * gRPC layer went wrong -- e.g. a misbehaving proxy/load
                 * balancer -- and the eventual Trailers (if any even
                 * follow) should not be trusted as a real gRPC response.
                 *
                 * Read the block into a stack buffer (same 128-byte budget
                 * and overflow-drain pattern already used for Trailers --
                 * Response-Headers for this client's small, fixed request
                 * set are not expected to exceed this).
                 */
                uint8_t headers_buf[128U] = { 0U };
                size_t to_read_h = 0U;
                size_t overflow_h = 0U;

                to_read_h = (pay_len <= sizeof(headers_buf)) ? pay_len : sizeof(headers_buf);
                if (to_read_h > 0U) {
                    s = el2go_ota_tls_read(ctx->tls_ctx, headers_buf, to_read_h, &n_read);
                    if (s != EL2GO_STATUS_SUCCESS || n_read < to_read_h) {
                        return EL2GO_OTA_ERROR_NETWORK;
                    }
                }
                overflow_h = (pay_len > sizeof(headers_buf)) ? (pay_len - sizeof(headers_buf)) : 0U;
                while (overflow_h > 0U) {
                    size_t to_drain = (overflow_h > sizeof(tmp)) ? sizeof(tmp) : overflow_h;
                    s = el2go_ota_tls_read(ctx->tls_ctx, tmp, to_drain, &n_read);
                    if (s != EL2GO_STATUS_SUCCESS || n_read < to_drain) {
                        return EL2GO_OTA_ERROR_NETWORK;
                    }
                    overflow_h -= n_read;
                }
                if (!hpack_validate_response_headers(headers_buf, to_read_h)) {
                    return EL2GO_OTA_ERROR_NETWORK;
                }
            }
            break;

        /*
         * SETTINGS: either server-initiated (send ACK) or ACK (ignore).
         */
        case H2_TYPE_SETTINGS:
            if ((flags & H2_FLAG_ACK) == 0U) {
                /* Drain settings parameters and send ACK. */
                size_t remaining = pay_len;
                while (remaining > 0U) {
                    size_t to_drain = (remaining > sizeof(tmp)) ? sizeof(tmp) : remaining;
                    s = el2go_ota_tls_read(ctx->tls_ctx, tmp, to_drain, &n_read);
                    if (s != EL2GO_STATUS_SUCCESS || n_read < to_drain) {
                        return EL2GO_OTA_ERROR_NETWORK;
                    }
                    remaining -= n_read;
                }
                (void)h2_send_settings(ctx, H2_FLAG_ACK);
            }
            /* ACK: no payload, nothing to drain. */
            break;

        /*
         * PING: must be answered with PONG.
         */
        case H2_TYPE_PING:
            if (pay_len == H2_PING_PAYLOAD_LEN && (flags & H2_FLAG_ACK) == 0U) {
                s = el2go_ota_tls_read(ctx->tls_ctx, tmp, H2_PING_PAYLOAD_LEN, &n_read);
                if (s != EL2GO_STATUS_SUCCESS || n_read < H2_PING_PAYLOAD_LEN) {
                    return EL2GO_OTA_ERROR_NETWORK;
                }
                (void)h2_send_ping_ack(ctx, tmp);
            } else {
                /* Drain unexpected PING payload. */
                size_t remaining = pay_len;
                while (remaining > 0U) {
                    size_t to_drain = (remaining > sizeof(tmp)) ? sizeof(tmp) : remaining;
                    s = el2go_ota_tls_read(ctx->tls_ctx, tmp, to_drain, &n_read);
                    if (s != EL2GO_STATUS_SUCCESS || n_read < to_drain) {
                        return EL2GO_OTA_ERROR_NETWORK;
                    }
                    remaining -= n_read;
                }
            }
            break;

        /*
         * RST_STREAM: server terminated one stream. Stream-specific (RFC
         * 7540 S6.4): a stray RST_STREAM for a stream other than the one
         * this call opened (e.g. a late RST for a prior call that this
         * client already finished processing) does not affect the current
         * call and must not abort it -- drain and ignore. An RST_STREAM for
         * the active stream is treated as before (reported as a network
         * error).
         */
        case H2_TYPE_RST_STREAM:
            if (!is_active_stream) {
                EL2GO_DBG_PRINTF(VERBOSE,
                                 "gRPC recv: ignoring RST_STREAM for stream %u (active=%u)\n",
                                 (unsigned int)stream_id, (unsigned int)ctx->active_stream_id);
                {
                    size_t remaining = pay_len;
                    while (remaining > 0U) {
                        size_t to_drain = (remaining > sizeof(tmp)) ? sizeof(tmp) : remaining;
                        s = el2go_ota_tls_read(ctx->tls_ctx, tmp, to_drain, &n_read);
                        if (s != EL2GO_STATUS_SUCCESS || n_read < to_drain) {
                            return EL2GO_OTA_ERROR_NETWORK;
                        }
                        remaining -= n_read;
                    }
                }
                break;
            }
            /*
             * RST_STREAM on the active stream: read its Error Code (RFC
             * 7540 S6.4 -- a 4-byte field, the frame's entire payload in a
             * conformant implementation) for diagnostics, then drain any
             * remaining bytes before returning. The HTTP/2 connection
             * (ctx->tls_ctx) is reused across send()/recv() calls on
             * subsequent downloads, so leaving any of this frame's bytes
             * unread would desync the next frame header read on the very
             * next call -- unread bytes would be misinterpreted as (part
             * of) the next frame header.
             */
            {
                uint8_t err_code_buf[4] = { 0U };
                uint32_t h2_err_code = 0U;
                bool have_err_code = false;
                size_t remaining = pay_len;

                if (remaining >= sizeof(err_code_buf)) {
                    s = el2go_ota_tls_read(ctx->tls_ctx, err_code_buf, sizeof(err_code_buf),
                                           &n_read);
                    if (s != EL2GO_STATUS_SUCCESS || n_read < sizeof(err_code_buf)) {
                        return EL2GO_OTA_ERROR_NETWORK;
                    }
                    remaining -= n_read;
                    h2_err_code = ((uint32_t)err_code_buf[0] << 24U) |
                                  ((uint32_t)err_code_buf[1] << 16U) |
                                  ((uint32_t)err_code_buf[2] << 8U) | (uint32_t)err_code_buf[3];
                    have_err_code = true;
                }
                while (remaining > 0U) {
                    size_t to_drain = (remaining > sizeof(tmp)) ? sizeof(tmp) : remaining;
                    s = el2go_ota_tls_read(ctx->tls_ctx, tmp, to_drain, &n_read);
                    if (s != EL2GO_STATUS_SUCCESS || n_read < to_drain) {
                        return EL2GO_OTA_ERROR_NETWORK;
                    }
                    remaining -= n_read;
                }
                if (have_err_code) {
                    EL2GO_DBG_PRINTF(ERROR,
                                     "gRPC recv: server sent RST_STREAM (stream %u): "
                                     "%s (0x%x)\n",
                                     (unsigned int)stream_id, h2_error_code_name(h2_err_code),
                                     (unsigned int)h2_err_code);
                } else {
                    EL2GO_DBG_PRINTF(ERROR,
                                     "gRPC recv: server sent RST_STREAM (stream %u), "
                                     "payload too short to decode error code (%u byte(s))\n",
                                     (unsigned int)stream_id, (unsigned int)pay_len);
                }
            }
            return EL2GO_OTA_ERROR_NETWORK;

        /*
         * GOAWAY: server terminated the whole connection. Always
         * connection-level (stream_id 0, RFC 7540 S6.8) regardless of which
         * stream is active, so it is never ignored based on stream_id.
         *
         * Payload layout (RFC 7540 S6.8): 4-byte Last-Stream-ID, 4-byte
         * Error Code, then optional Additional Debug Data. Read the Error
         * Code for diagnostics and drain the rest (including any debug
         * data) before returning -- this connection is about to be torn
         * down by the caller on a NETWORK error, but draining here is kept
         * for consistency with every other frame type in this function
         * and to avoid ever leaving unread bytes on the wire.
         */
        case H2_TYPE_GOAWAY: {
            uint8_t goaway_hdr[8] = { 0U };
            uint32_t h2_err_code = 0U;
            bool have_err_code = false;
            size_t remaining = pay_len;

            if (remaining >= sizeof(goaway_hdr)) {
                s = el2go_ota_tls_read(ctx->tls_ctx, goaway_hdr, sizeof(goaway_hdr), &n_read);
                if (s != EL2GO_STATUS_SUCCESS || n_read < sizeof(goaway_hdr)) {
                    return EL2GO_OTA_ERROR_NETWORK;
                }
                remaining -= n_read;
                /* goaway_hdr[0..3] = Last-Stream-ID (not needed here). */
                h2_err_code = ((uint32_t)goaway_hdr[4] << 24U) | ((uint32_t)goaway_hdr[5] << 16U) |
                              ((uint32_t)goaway_hdr[6] << 8U) | (uint32_t)goaway_hdr[7];
                have_err_code = true;
            }
            while (remaining > 0U) {
                size_t to_drain = (remaining > sizeof(tmp)) ? sizeof(tmp) : remaining;
                s = el2go_ota_tls_read(ctx->tls_ctx, tmp, to_drain, &n_read);
                if (s != EL2GO_STATUS_SUCCESS || n_read < to_drain) {
                    return EL2GO_OTA_ERROR_NETWORK;
                }
                remaining -= n_read;
            }
            if (have_err_code) {
                EL2GO_DBG_PRINTF(ERROR, "gRPC recv: server sent GOAWAY: %s (0x%x)\n",
                                 h2_error_code_name(h2_err_code), (unsigned int)h2_err_code);
            } else {
                EL2GO_DBG_PRINTF(ERROR,
                                 "gRPC recv: server sent GOAWAY, payload too short to "
                                 "decode error code (%u byte(s))\n",
                                 (unsigned int)pay_len);
            }
            return EL2GO_OTA_ERROR_NETWORK;
        }

        /*
         * All other frame types: drain payload and continue.
         */
        default: {
            size_t remaining = pay_len;
            while (remaining > 0U) {
                size_t to_drain = (remaining > sizeof(tmp)) ? sizeof(tmp) : remaining;
                s = el2go_ota_tls_read(ctx->tls_ctx, tmp, to_drain, &n_read);
                if (s != EL2GO_STATUS_SUCCESS || n_read < to_drain) {
                    return EL2GO_OTA_ERROR_NETWORK;
                }
                remaining -= n_read;
            }
        } break;
        }
    }

    EL2GO_DBG_PRINTF(ERROR, "gRPC recv: exceeded max frame iterations\n");
    return EL2GO_OTA_ERROR_NETWORK;
}

/* vtable -- deinit */

static void grpc_deinit(el2go_ota_transport_t *t)
{
    if (t != NULL && t->impl_ctx != NULL) {
        osal_free(t->impl_ctx);
        t->impl_ctx = NULL;
    }
}

el2go_ota_status_t el2go_ota_transport_init(el2go_ota_transport_t *t, el2go_ota_tls_ctx_t *tls_ctx,
                                            const char *hostname)
{
    grpc_ctx_t *ctx = NULL;

    EL2GO_DBG_TRACE_API_CALL;

    if (t == NULL || tls_ctx == NULL || hostname == NULL) {
        return EL2GO_OTA_ERROR_INVALID_PARAM;
    }

    ctx = (grpc_ctx_t *)osal_calloc(1U, sizeof(grpc_ctx_t));
    if (ctx == NULL) {
        EL2GO_DBG_PRINTF(ERROR, "gRPC init: context allocation failed\n");
        return EL2GO_OTA_ERROR_INTERNAL;
    }

    ctx->tls_ctx = tls_ctx;
    ctx->hostname = hostname;
    ctx->next_stream_id = 1U;   /* HTTP/2: client streams start at 1, odd numbers */
    ctx->active_stream_id = 0U; /* 0 is never a valid client stream id, so no DATA/HEADERS/
                                 * RST_STREAM frame can match it before the first send(). */
    ctx->http2_ready = false;

    t->send = grpc_send;
    t->recv = grpc_recv;
    t->deinit = grpc_deinit;
    t->impl_ctx = ctx;

    EL2GO_DBG_PRINTF(VERBOSE, "gRPC init: transport ready (host=%s)\n", hostname);
    return EL2GO_OTA_SUCCESS;
}
