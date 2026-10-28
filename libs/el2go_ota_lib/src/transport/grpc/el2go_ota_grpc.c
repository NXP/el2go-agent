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
#define H2_TYPE_CONTINUATION 0x09U

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

/* HPACK static table index 8 = :status 200; indices 9-14 = non-200 :status values. */
#define HPACK_STATIC_IDX_STATUS_200 8U

/* First HPACK dynamic-table index (RFC 7541 S2.3.3): newest entry = 62. */
#define HPACK_DYN_TABLE_FIRST_IDX 62U

/* SETTINGS parameter id for HEADER_TABLE_SIZE (RFC 7540 S6.5.2) and the
 * byte length of one settings parameter (2-byte id + 4-byte value). */
#define H2_SETTINGS_PARAM_HDR_TABLE_SIZE 0x0001U
#define H2_SETTINGS_PARAM_LEN 6U

/* SETTINGS parameter id for MAX_FRAME_SIZE (RFC 7540 S6.5.2) and the
 * protocol-default value a server may never advertise below. */
#define H2_SETTINGS_PARAM_MAX_FRAME_SIZE 0x0005U
#define H2_SETTINGS_DEFAULT_MAX_FRAME_SIZE 16384U

/* Context */

typedef struct {
    el2go_ota_tls_ctx_t *tls_ctx;
    const char *hostname; /* not owned; points into user config */
    uint32_t next_stream_id;
    uint32_t active_stream_id;          /* stream opened by the most recent send(); the only
                                * stream grpc_recv() expects to receive a response on. */
    bool http2_ready;                   /* preface + SETTINGS exchanged */
    uint32_t grpc_status_insert_serial; /* hpack_dyn_entries value at insertion time; 0 = not seen */
    uint32_t grpc_status_dyn_value;     /* cached numeric grpc-status code */
    uint32_t hpack_dyn_entries;         /* best-effort count of dynamic-table insertions seen */
    uint32_t
        server_max_frame_size; /* server-advertised MAX_FRAME_SIZE (RFC 7540 S6.5.2); diagnostic only; 0 = not yet seen */
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
 * Send an HTTP/2 SETTINGS ACK frame (empty payload, ACK flag set).
 */
static el2go_ota_status_t h2_send_settings_ack(grpc_ctx_t *ctx)
{
    uint8_t frame[H2_FRAME_HDR_LEN] = { 0U };
    el2go_status_t s = EL2GO_STATUS_FAILURE;

    h2_build_frame_hdr(frame, 0U, H2_TYPE_SETTINGS, H2_FLAG_ACK, 0U);
    s = el2go_ota_tls_write(ctx->tls_ctx, frame, sizeof(frame));
    return (s == EL2GO_STATUS_SUCCESS) ? EL2GO_OTA_SUCCESS : EL2GO_OTA_ERROR_NETWORK;
}

/**
 * @brief Send an HTTP/2 SETTINGS frame advertising HEADER_TABLE_SIZE=0
 *        (RFC 7540 S6.5.2, RFC 7541 S4.2).
 *
 * Instructs the server to evict its HPACK dynamic table and forbids it from
 * re-populating it, so every response header is sent as a decodable literal.
 * This avoids the need to track which dynamic-table index the server assigns
 * to grpc-status (the indexed-reference fallback handles the case where the
 * server ignores this setting).
 *
 * @param[in,out] ctx  Transport context owning the TLS connection.
 *
 * @return EL2GO_OTA_SUCCESS or EL2GO_OTA_ERROR_NETWORK.
 */
static el2go_ota_status_t h2_send_settings_hdr_table_zero(grpc_ctx_t *ctx)
{
    /* 9-byte frame header + one 6-byte setting parameter. */
    uint8_t frame[H2_FRAME_HDR_LEN + H2_SETTINGS_PARAM_LEN] = { 0U };
    el2go_status_t s = EL2GO_STATUS_FAILURE;

    h2_build_frame_hdr(frame, H2_SETTINGS_PARAM_LEN, H2_TYPE_SETTINGS, 0x00U, 0U);
    /* Parameter: HEADER_TABLE_SIZE (0x0001), value 0x00000000. */
    frame[H2_FRAME_HDR_LEN + 0U] =
        (uint8_t)((H2_SETTINGS_PARAM_HDR_TABLE_SIZE >> 8U) & H2_BYTE_MASK);
    frame[H2_FRAME_HDR_LEN + 1U] = (uint8_t)(H2_SETTINGS_PARAM_HDR_TABLE_SIZE & H2_BYTE_MASK);
    frame[H2_FRAME_HDR_LEN + 2U] = 0x00U;
    frame[H2_FRAME_HDR_LEN + 3U] = 0x00U;
    frame[H2_FRAME_HDR_LEN + 4U] = 0x00U;
    frame[H2_FRAME_HDR_LEN + 5U] = 0x00U;

    s = el2go_ota_tls_write(ctx->tls_ctx, frame, sizeof(frame));
    return (s == EL2GO_STATUS_SUCCESS) ? EL2GO_OTA_SUCCESS : EL2GO_OTA_ERROR_NETWORK;
}

/**
 * @brief Send an HTTP/2 SETTINGS frame (ACK or initial empty SETTINGS).
 *
 * When @p flags has H2_FLAG_ACK set, sends a SETTINGS ACK with no payload.
 * Otherwise sends the initial client SETTINGS (HEADER_TABLE_SIZE=0) via
 * h2_send_settings_hdr_table_zero().
 *
 * @param[in,out] ctx    Transport context owning the TLS connection.
 * @param[in]     flags  H2_FLAG_ACK to send an ACK; 0 for initial SETTINGS.
 *
 * @return EL2GO_OTA_SUCCESS or EL2GO_OTA_ERROR_NETWORK.
 */
static el2go_ota_status_t h2_send_settings(grpc_ctx_t *ctx, uint8_t flags)
{
    if ((flags & H2_FLAG_ACK) != 0U) {
        return h2_send_settings_ack(ctx);
    }
    /* Non-ACK initial SETTINGS: advertise HEADER_TABLE_SIZE=0. */
    return h2_send_settings_hdr_table_zero(ctx);
}

/**
 * @brief Send an HTTP/2 WINDOW_UPDATE frame (RFC 7540 S6.9).
 *
 * @param[in,out] ctx        Transport context owning the TLS connection.
 * @param[in]     stream_id  Stream to update (0 for the connection level).
 * @param[in]     increment  Flow-control window increment in bytes.
 *
 * @return EL2GO_OTA_SUCCESS or EL2GO_OTA_ERROR_NETWORK.
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

/**
 * @brief Send an HTTP/2 PING ACK (RFC 7540 S6.7).
 *
 * Echoes the 8-byte opaque payload received in the peer's PING frame.
 *
 * @param[in,out] ctx        Transport context owning the TLS connection.
 * @param[in]     ping_data  8-byte opaque payload from the incoming PING.
 *
 * @return EL2GO_OTA_SUCCESS or EL2GO_OTA_ERROR_NETWORK.
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

/**
 * @brief Append one byte to buf[*pos], advancing @p pos.
 *
 * @return true on success, false if the buffer is full.
 */
static bool hpack_put_byte(uint8_t *buf, size_t buf_size, size_t *pos, uint8_t b)
{
    if (*pos >= buf_size) {
        return false;
    }
    buf[(*pos)++] = b;
    return true;
}

/**
 * @brief Encode a plain (non-Huffman) HPACK length-prefixed string.
 *
 * @p len must be less than 128 so it fits in a single HPACK integer byte.
 *
 * @return true on success, false if the buffer is full or @p len >= 128.
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

/**
 * @brief Build the HPACK header block for a gRPC request.
 *
 * Emits: :method POST (indexed #3), :scheme https (indexed #7),
 * :path (literal, name from #4), :authority (literal, name from #1),
 * content-type: application/grpc (never-indexed literal),
 * te: trailers (never-indexed literal).
 *
 * @param[out] buf          Output buffer.
 * @param[in]  buf_size     Capacity of @p buf in bytes.
 * @param[in]  method_path  gRPC method path (e.g. "/pkg.Svc/Method").
 * @param[in]  hostname     Server hostname for the :authority header.
 *
 * @return Number of bytes written, or 0 on encoding error.
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

/* HTTP/2 error code name for RST_STREAM/GOAWAY diagnostics (RFC 7540 S7). */
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
 * Also tracks dynamic-table insertions for the secondary HPACK
 * indexed-reference defence. @p ctx may be NULL (unit-test / no-context
 * callers), in which case the indexed-reference check is skipped.
 *
 * Best-effort only. The reliable protection is the SETTINGS_HEADER_TABLE_SIZE=0
 * advertised at connection setup, which a compliant server must honour
 * (RFC 7540 S6.5.2): it then never inserts into the dynamic table and never sends
 * an indexed grpc-status. This secondary defence only covers a server that
 * ignores that setting, and only partially: insertions made by Response-Headers
 * or by the plain-literal fast path in grpc_parse_trailers() are not counted, and
 * a repeated error sent as a literal with a dynamic-table name index is not
 * resolved. Failure mode is fail-open (the status is read as OK).
 *
 * @param[in]     block      Input HPACK trailer block.
 * @param[in]     block_len  Length of @p block in bytes.
 * @param[in,out] ctx        Per-connection HPACK state; may be NULL.
 * @param[out]    out_code   Decoded grpc-status value on success.
 *
 * @return true and sets @p out_code if grpc-status was found and decoded.
 *         false if grpc-status was not found or the block could not be walked
 *         (malformed/truncated); both cases are treated as "not found" by the
 *         caller.
 */
static bool hpack_find_grpc_status_fallback(const uint8_t *block, size_t block_len, grpc_ctx_t *ctx,
                                            uint32_t *out_code)
{
    size_t pos = 0U;
    uint32_t iterations = 0U;
    /* Local shadow of ctx->hpack_dyn_entries; tracks insertions in this block. */
    uint32_t local_entries = (ctx != NULL) ? ctx->hpack_dyn_entries : 0U;
    /* Keep walking even after finding grpc-status to count all incremental-indexing
     * insertions (e.g. grpc-message) so ctx->hpack_dyn_entries stays in sync. */
    bool found = false;
    uint32_t found_code = 0U;

    while (pos < block_len && iterations < GRPC_RECV_MAX_FRAMES) {
        uint8_t first = block[pos];
        uint8_t prefix_bits = 0U;
        uint32_t idx_val = 0U;
        uint32_t name_idx = 0U;
        uint8_t name_buf[HPACK_NAME_BUF_CAP];
        size_t name_len = 0U;
        bool has_literal_name = false;
        bool is_grpc_status = false;
        bool inserts_into_dyn_table = false;

        iterations++;

        if ((first & 0x80U) != 0U) {
            /* Indexed header field (RFC 7541 S6.1). Secondary defence: resolve
             * grpc-status by its stored insertion serial if the server ignored
             * HEADER_TABLE_SIZE=0. abs_idx = FIRST_IDX + (local - insert_serial). */
            if (!hpack_decode_integer(block, block_len, &pos, 7U, &idx_val)) {
                if (found) {
                    *out_code = found_code;
                    return true;
                }
                return false;
            }
            if (!found && ctx != NULL && ctx->grpc_status_insert_serial != 0U) {
                uint32_t expected_idx =
                    HPACK_DYN_TABLE_FIRST_IDX + (local_entries - ctx->grpc_status_insert_serial);
                if (idx_val == expected_idx) {
                    EL2GO_DBG_PRINTF(VERBOSE,
                                     "gRPC recv: grpc-status via HPACK indexed ref "
                                     "(idx=%u, cached code=%u)\n",
                                     (unsigned int)idx_val,
                                     (unsigned int)ctx->grpc_status_dyn_value);
                    found = true;
                    found_code = ctx->grpc_status_dyn_value;
                }
            }
            continue;
        }

        if ((first & 0x40U) != 0U) {
            prefix_bits = 6U; /* literal with incremental indexing */
            inserts_into_dyn_table = true;
        } else if ((first & 0x20U) != 0U) {
            /* Dynamic table size update -- self-contained, skip it. */
            if (!hpack_decode_integer(block, block_len, &pos, 5U, &idx_val)) {
                if (found) {
                    *out_code = found_code;
                    return true;
                }
                return false;
            }
            continue;
        } else {
            prefix_bits = 4U; /* literal without indexing, or never indexed */
        }

        if (!hpack_decode_integer(block, block_len, &pos, prefix_bits, &name_idx)) {
            if (found) {
                *out_code = found_code;
                return true;
            }
            return false;
        }
        has_literal_name = (name_idx == 0U);

        if (has_literal_name) {
            if (!hpack_decode_string_bounded(block, block_len, &pos, name_buf, sizeof(name_buf),
                                             &name_len)) {
                /* Name decode failed; cannot skip the field without consuming
                 * it, so bail out. Return true if grpc-status was found earlier. */
                if (found) {
                    *out_code = found_code;
                    return true;
                }
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
                if (found) {
                    *out_code = found_code;
                    return true;
                }
                return false;
            }
            for (j = 0U; j < value_len; j++) {
                uint8_t c = value_buf[j];
                if (c < (uint8_t)'0' || c > (uint8_t)'9') {
                    break;
                }
                if (MUL_OVERFLOW(code, 10U, &mul_result) ||
                    ADD_OVERFLOW(mul_result, (uint32_t)(c - (uint8_t)'0'), &add_result)) {
                    /* overflow -- malformed status code */
                    if (found) {
                        *out_code = found_code;
                        return true;
                    }
                    return false;
                }
                code = add_result;
            }
            /* Incremental indexing: record insertion serial so indexed refs can
             * be resolved on subsequent responses on this connection. */
            if (inserts_into_dyn_table && ctx != NULL) {
                local_entries++;
                ctx->hpack_dyn_entries = local_entries;
                ctx->grpc_status_insert_serial = local_entries;
                ctx->grpc_status_dyn_value = code;
            }
            /* Do not return yet -- keep walking to count further insertions. */
            found = true;
            found_code = code;
            continue;
        }

        /* Not grpc-status -- still count incremental-indexing insertions. */
        if (inserts_into_dyn_table && ctx != NULL) {
            local_entries++;
            ctx->hpack_dyn_entries = local_entries;
        }

        /* Skip its value without decoding. */
        if (!hpack_skip_string(block, block_len, &pos)) {
            if (found) {
                *out_code = found_code;
                return true;
            }
            return false;
        }
    }

    if (found) {
        *out_code = found_code;
        return true;
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
            /* HPACK static indices 9-14 = non-200 :status; 8 = :status 200 (OK). */
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
static el2go_ota_status_t grpc_parse_trailers(const uint8_t *block, size_t block_len,
                                              grpc_ctx_t *ctx)
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

    /* Fast path: scan for the plain-literal "grpc-status" pattern.
     * Short blocks are still passed to the HPACK fallback below --
     * a Huffman-encoded name is shorter than the 11-byte plain form. */
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

        if (hpack_find_grpc_status_fallback(block, block_len, ctx, &fallback_code)) {
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

/**
 * Read exactly @p pay_len bytes of a SETTINGS frame payload off the wire,
 * parsing each 6-byte (2-byte id, 4-byte value) parameter as it goes, and
 * updating @p ctx->server_max_frame_size if a MAX_FRAME_SIZE parameter is
 * found. Any other parameter (including HEADER_TABLE_SIZE, which this
 * client does not need to read back since it only cares about its own
 * outgoing SETTINGS HEADER_TABLE_SIZE=0 request) is parsed but ignored.
 *
 * This replaces a blind byte-for-byte drain with a parsing drain -- the
 * exact same number of bytes is read off the wire either way, so this
 * cannot desync the next frame-header read even if pay_len is not a
 * multiple of 6 (a malformed/non-compliant SETTINGS frame per RFC 7540
 * S6.5, which requires pay_len to be a multiple of 6): any trailing
 * partial parameter is drained as plain bytes without being parsed as a
 * fresh (id, value) pair.
 *
 * Diagnostic-only: per RFC 7540 S6.5.2 a server must never advertise
 * MAX_FRAME_SIZE below the protocol default (16384) -- if one is seen
 * advertising a smaller value anyway (a non-compliant server), this is
 * logged but never treated as an error; this client's own frame sizing
 * is governed entirely by its own compile-time EL2GO_OTA_CHUNK_SIZE
 * budget (see el2go_ota_download_engine.c), not by anything learned here.
 *
 * @param[in,out] ctx      Transport context; server_max_frame_size is
 *                          updated in place if MAX_FRAME_SIZE is found.
 * @param[in]     pay_len  Number of SETTINGS payload bytes to read and
 *                          drain from the wire.
 *
 * @return EL2GO_OTA_SUCCESS on success, EL2GO_OTA_ERROR_NETWORK if the
 *         underlying read fails.
 */
static el2go_ota_status_t h2_parse_and_drain_settings_payload(grpc_ctx_t *ctx, uint32_t pay_len)
{
    uint8_t param[H2_SETTINGS_PARAM_LEN] = { 0U };
    uint8_t trailing[H2_SETTINGS_PARAM_LEN] = { 0U };
    uint32_t remaining = pay_len;
    el2go_status_t s = EL2GO_STATUS_FAILURE;
    size_t n_read = 0U;

    while (remaining >= H2_SETTINGS_PARAM_LEN) {
        uint16_t param_id = 0U;
        uint32_t param_value = 0U;

        s = el2go_ota_tls_read(ctx->tls_ctx, param, sizeof(param), &n_read);
        if (s != EL2GO_STATUS_SUCCESS || n_read < sizeof(param)) {
            return EL2GO_OTA_ERROR_NETWORK;
        }
        remaining -= (uint32_t)n_read;

        param_id = (uint16_t)(((uint16_t)param[0] << 8U) | (uint16_t)param[1]);
        param_value = ((uint32_t)param[2] << 24U) | ((uint32_t)param[3] << 16U) |
                      ((uint32_t)param[4] << 8U) | (uint32_t)param[5];

        if (param_id == H2_SETTINGS_PARAM_MAX_FRAME_SIZE) {
            ctx->server_max_frame_size = param_value;
            if (param_value < H2_SETTINGS_DEFAULT_MAX_FRAME_SIZE) {
                /* Non-compliant server (RFC 7540 S6.5.2 forbids this) --
                 * diagnostic only, this client's own frame sizing is
                 * unaffected and already stays within the default. */
                EL2GO_DBG_PRINTF(ERROR,
                                 "gRPC: server advertised non-compliant "
                                 "SETTINGS_MAX_FRAME_SIZE=%u (below the "
                                 "RFC 7540 S6.5.2 floor of %u) -- ignored, "
                                 "this client's frame sizing is unaffected\n",
                                 (unsigned int)param_value,
                                 (unsigned int)H2_SETTINGS_DEFAULT_MAX_FRAME_SIZE);
            } else {
                EL2GO_DBG_PRINTF(VERBOSE, "gRPC: server SETTINGS_MAX_FRAME_SIZE=%u\n",
                                 (unsigned int)param_value);
            }
        }
    }

    /* Drain any trailing partial parameter (malformed, pay_len not a
     * multiple of 6) without attempting to parse it. */
    if (remaining > 0U) {
        s = el2go_ota_tls_read(ctx->tls_ctx, trailing, (size_t)remaining, &n_read);
        if (s != EL2GO_STATUS_SUCCESS || n_read < (size_t)remaining) {
            return EL2GO_OTA_ERROR_NETWORK;
        }
    }

    return EL2GO_OTA_SUCCESS;
}

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
                 * Server SETTINGS -- parse MAX_FRAME_SIZE (diagnostic
                 * only, see h2_parse_and_drain_settings_payload()) while
                 * draining the payload, then send ACK.
                 */
                el2go_ota_status_t parse_status = h2_parse_and_drain_settings_payload(ctx, pay_len);
                if (parse_status != EL2GO_OTA_SUCCESS) {
                    return parse_status;
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

/**
 * @brief Read and reassemble a Response-Headers or Trailers block that may be
 *        split across one HEADERS frame and zero or more CONTINUATION frames
 *        (RFC 7540 S6.10).
 *
 * Raw HPACK bytes are reassembled into @p out_buf (up to @p out_cap bytes).
 * Any overflow across however many frames the block spans is drained and
 * discarded, matching this file's existing fixed-size stack buffer pattern
 * for Trailers/Response-Headers.
 *
 * The caller has already read the frame header of the initiating HEADERS
 * frame (its stream_id, flags, and pay_len) before calling this function;
 * this function does not re-read it.
 *
 * Per RFC 7540 S6.10: once a HEADERS frame without END_HEADERS has been
 * received, the only frame type permitted to arrive next, before END_HEADERS,
 * is a CONTINUATION frame for the same stream_id.  Any other frame type, or a
 * CONTINUATION for a different stream, is a connection-level PROTOCOL_ERROR;
 * this is reported as EL2GO_OTA_ERROR_NETWORK (consistent with every other
 * fatal transport error in this file) rather than silently drained and
 * ignored.
 *
 * @note Only the active stream's header/trailer block is reassembled here
 *       (the only case grpc_recv() ever calls this for).  A stray or
 *       inactive-stream HEADERS frame that happens to be split across
 *       CONTINUATION frames is not handled by this helper and is out of scope
 *       for this client's single-in-flight-call request pattern.  Such a
 *       stray CONTINUATION, if ever seen outside of this helper's reassembly
 *       loop, continues to fall through to grpc_recv()'s existing default:
 *       case, which already drains it safely by its declared length.
 *
 * @param[in,out] ctx                 Transport context.
 * @param[in]     stream_id           Stream ID the HEADERS frame opened on.
 * @param[in]     first_pay_len       Payload length of the initiating HEADERS
 *                                    frame.
 * @param[in]     initial_end_headers Whether END_HEADERS was already set on
 *                                    the initiating HEADERS frame.
 * @param[out]    out_buf             Buffer to reassemble the raw HPACK bytes
 *                                    into.
 * @param[in]     out_cap             Capacity of @p out_buf in bytes.
 * @param[out]    out_len             Number of bytes written to @p out_buf
 *                                    (capped at @p out_cap; matches this
 *                                    file's existing overflow-drain semantics
 *                                    for an oversized block).
 *
 * @retval EL2GO_OTA_SUCCESS       Full block reassembled successfully.
 * @retval EL2GO_OTA_ERROR_NETWORK I/O failure, frame-iteration budget
 *                                 exceeded, or an RFC 7540 S6.10
 *                                 PROTOCOL_ERROR.
 */
static el2go_ota_status_t grpc_read_header_block(grpc_ctx_t *ctx, uint32_t stream_id,
                                                 uint32_t first_pay_len, bool initial_end_headers,
                                                 uint8_t *out_buf, size_t out_cap, size_t *out_len)
{
    uint8_t tmp[H2_PING_PAYLOAD_LEN] = { 0U };
    el2go_status_t s = EL2GO_STATUS_FAILURE;
    size_t n_read = 0U;
    size_t written = 0U;
    uint32_t pay_len = first_pay_len;
    bool end_headers = initial_end_headers;
    uint32_t iterations = 0U;

    *out_len = 0U;

    for (;;) {
        size_t to_read = 0U;
        size_t overflow = 0U;

        to_read =
            (written < out_cap) ?
                (((size_t)pay_len <= (out_cap - written)) ? (size_t)pay_len : (out_cap - written)) :
                0U;
        if (to_read > 0U) {
            s = el2go_ota_tls_read(ctx->tls_ctx, &out_buf[written], to_read, &n_read);
            if (s != EL2GO_STATUS_SUCCESS || n_read < to_read) {
                return EL2GO_OTA_ERROR_NETWORK;
            }
            written += n_read;
        }
        overflow = (size_t)pay_len - to_read;
        while (overflow > 0U) {
            size_t to_drain = (overflow > sizeof(tmp)) ? sizeof(tmp) : overflow;
            s = el2go_ota_tls_read(ctx->tls_ctx, tmp, to_drain, &n_read);
            if (s != EL2GO_STATUS_SUCCESS || n_read < to_drain) {
                return EL2GO_OTA_ERROR_NETWORK;
            }
            overflow -= n_read;
        }

        if (end_headers) {
            *out_len = written;
            return EL2GO_OTA_SUCCESS;
        }

        /* Block not yet complete -- the next frame on the wire MUST be a
         * CONTINUATION frame for this same stream_id (RFC 7540 S6.10).
         * Anything else is a connection-level PROTOCOL_ERROR. */
        {
            uint8_t hdr[H2_FRAME_HDR_LEN] = { 0U };
            uint8_t next_type = 0U;
            uint8_t next_flags = 0U;
            uint32_t next_stream = 0U;

            iterations++;
            if (iterations >= GRPC_RECV_MAX_FRAMES) {
                EL2GO_DBG_PRINTF(ERROR,
                                 "gRPC recv: exceeded max frame iterations while "
                                 "awaiting CONTINUATION (stream %u)\n",
                                 (unsigned int)stream_id);
                return EL2GO_OTA_ERROR_NETWORK;
            }

            s = el2go_ota_tls_read(ctx->tls_ctx, hdr, H2_FRAME_HDR_LEN, &n_read);
            if (s != EL2GO_STATUS_SUCCESS || n_read < H2_FRAME_HDR_LEN) {
                return EL2GO_OTA_ERROR_NETWORK;
            }
            pay_len = ((uint32_t)hdr[0] << 16U) | ((uint32_t)hdr[1] << 8U) | (uint32_t)hdr[2];
            next_type = hdr[3];
            next_flags = hdr[4];
            next_stream = (((uint32_t)hdr[5] & H2_MSB_RESERVED_MASK) << 24U) |
                          ((uint32_t)hdr[6] << 16U) | ((uint32_t)hdr[7] << 8U) | (uint32_t)hdr[8];

            if (next_type != H2_TYPE_CONTINUATION || next_stream != stream_id) {
                EL2GO_DBG_PRINTF(ERROR,
                                 "gRPC recv: PROTOCOL_ERROR -- expected CONTINUATION "
                                 "for stream %u (RFC 7540 S6.10), got frame type "
                                 "0x%02x for stream %u\n",
                                 (unsigned int)stream_id, (unsigned int)next_type,
                                 (unsigned int)next_stream);
                return EL2GO_OTA_ERROR_NETWORK;
            }

            end_headers = (next_flags & H2_FLAG_END_HEADERS) != 0U;
        }
    }
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
    /* LPM reassembly state; lives across iterations (message may span multiple DATA frames). */
    uint8_t grpc_prefix[GRPC_MSG_HDR_LEN] = { 0U };
    size_t prefix_have = 0U;
    bool prefix_parsed = false;
    size_t body_len = 0U;
    size_t body_have = 0U;
    bool msg_complete = false;
    /* Messages that started after a complete one (a unary call carries just one). */
    uint32_t extra_msgs = 0U;

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
        /* Stream id (RFC 7540 S4.1): used to detect and drain stray frames
         * from prior calls on this connection. */
        stream_id = (((uint32_t)hdr[5] & H2_MSB_RESERVED_MASK) << 24U) | ((uint32_t)hdr[6] << 16U) |
                    ((uint32_t)hdr[7] << 8U) | (uint32_t)hdr[8];
        is_active_stream = (stream_id == ctx->active_stream_id);

        switch (frame_type) {
        /* DATA frame: contains the gRPC response message. */
        case H2_TYPE_DATA:
            if (!is_active_stream) {
                /* Stray DATA frame from a prior call -- drain and ignore. */
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
            {
                /* LPM boundaries and DATA frame boundaries are independent (gRPC-over-HTTP2
                 * spec); consume this frame's payload into the prefix, then the body. */
                size_t frame_left = (size_t)pay_len;
                size_t progress = 0U;
                size_t take = 0U;

                data_received = true;

                /* Non-empty frame after a complete message starts a new message; empty
                 * frames (e.g. bare END_STREAM) must not discard a completed message. */
                if (msg_complete && pay_len > 0U) {
                    /* Tolerated (the later message overwrites the earlier one), but bounded:
                     * otherwise a peer sending small complete messages without END_STREAM
                     * would keep this loop running, as progress resets the idle-frame budget. */
                    extra_msgs++;
                    if (extra_msgs > GRPC_RECV_MAX_FRAMES) {
                        EL2GO_DBG_PRINTF(ERROR, "gRPC recv: too many messages on a unary call\n");
                        return EL2GO_OTA_ERROR_NETWORK;
                    }
                    prefix_have = 0U;
                    prefix_parsed = false;
                    body_len = 0U;
                    body_have = 0U;
                    msg_complete = false;
                }

                /* Step 1: gRPC message prefix (may be split). */
                if (prefix_have < GRPC_MSG_HDR_LEN && frame_left > 0U) {
                    take = GRPC_MSG_HDR_LEN - prefix_have;
                    if (take > frame_left) {
                        take = frame_left;
                    }
                    s = el2go_ota_tls_read(ctx->tls_ctx, &grpc_prefix[prefix_have], take, &n_read);
                    if (s != EL2GO_STATUS_SUCCESS || n_read < take) {
                        EL2GO_DBG_PRINTF(ERROR, "gRPC recv: gRPC prefix read failed\n");
                        return EL2GO_OTA_ERROR_NETWORK;
                    }
                    prefix_have += take;
                    frame_left -= take;
                    progress += take;
                }

                if (prefix_have == GRPC_MSG_HDR_LEN && !prefix_parsed) {
                    uint32_t grpc_msg_len = 0U;

                    if (grpc_prefix[0] != 0x00U) {
                        EL2GO_DBG_PRINTF(ERROR, "gRPC recv: compressed flag 0x%02X not supported\n",
                                         (unsigned int)grpc_prefix[0]);
                        return EL2GO_OTA_ERROR_NETWORK;
                    }

                    grpc_msg_len = ((uint32_t)grpc_prefix[1] << 24U) |
                                   ((uint32_t)grpc_prefix[2] << 16U) |
                                   ((uint32_t)grpc_prefix[3] << 8U) | (uint32_t)grpc_prefix[4];
                    body_len = (size_t)grpc_msg_len;

                    if (body_len > buf_len) {
                        EL2GO_DBG_PRINTF(ERROR,
                                         "gRPC recv: gRPC message %zu bytes exceeds buffer %zu\n",
                                         body_len, buf_len);
                        return EL2GO_OTA_ERROR_INTERNAL;
                    }
                    prefix_parsed = true;
                    if (body_len == 0U) {
                        msg_complete = true;
                    }
                }

                /* Step 2: message body (may be split). */
                if (prefix_parsed && body_have < body_len && frame_left > 0U) {
                    take = body_len - body_have;
                    if (take > frame_left) {
                        take = frame_left;
                    }
                    s = el2go_ota_tls_read(ctx->tls_ctx, &buf[body_have], take, &n_read);
                    if (s != EL2GO_STATUS_SUCCESS || n_read < take) {
                        EL2GO_DBG_PRINTF(ERROR,
                                         "gRPC recv: data body read failed "
                                         "(got %zu/%zu)\n",
                                         n_read, take);
                        return EL2GO_OTA_ERROR_NETWORK;
                    }
                    body_have += take;
                    frame_left -= take;
                    progress += take;
                    if (body_have == body_len) {
                        msg_complete = true;
                        *out_len = body_len;
                        EL2GO_DBG_PRINTF(VERBOSE, "gRPC recv: %zu byte(s) received\n", *out_len);
                    }
                }

                /* Step 3: drain whatever is left of this frame (padding, or
                 * bytes beyond the single message a unary call carries). */
                while (frame_left > 0U) {
                    size_t to_drain = (frame_left > sizeof(tmp)) ? sizeof(tmp) : frame_left;
                    s = el2go_ota_tls_read(ctx->tls_ctx, tmp, to_drain, &n_read);
                    if (s != EL2GO_STATUS_SUCCESS || n_read < to_drain) {
                        return EL2GO_OTA_ERROR_NETWORK;
                    }
                    frame_left -= n_read;
                }

                if (!msg_complete && (flags & H2_FLAG_END_STREAM) == 0U) {
                    EL2GO_DBG_PRINTF(VERBOSE,
                                     "gRPC recv: message continues in next DATA frame "
                                     "(prefix %zu/%u, body %zu/%zu)\n",
                                     prefix_have, (unsigned int)GRPC_MSG_HDR_LEN, body_have,
                                     body_len);
                }

                /* Reset idle-frame budget on progress; GRPC_RECV_MAX_FRAMES bounds
                 * no-progress frames (PING storms etc.), not message fragments. */
                if (progress > 0U) {
                    iterations = 0U;
                }

                /* END_STREAM on DATA: the response is complete only if the
                 * whole message arrived. */
                if ((flags & H2_FLAG_END_STREAM) != 0U) {
                    if (msg_complete) {
                        return EL2GO_OTA_SUCCESS;
                    }
                    EL2GO_DBG_PRINTF(ERROR,
                                     "gRPC recv: stream ended with a truncated message "
                                     "(prefix %zu/%u, body %zu/%zu)\n",
                                     prefix_have, (unsigned int)GRPC_MSG_HDR_LEN, body_have,
                                     body_len);
                    return EL2GO_OTA_ERROR_NETWORK;
                }
            }
            break;

        /* HEADERS frame: Response-Headers (no END_STREAM) or Trailers (END_STREAM set).
         * Trailers-Only (no prior DATA) is also valid -- END_STREAM is what matters. */
        case H2_TYPE_HEADERS:
            if (!is_active_stream) {
                /* Stray HEADERS frame from a prior call -- drain and ignore. */
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
                /* Trailers: reassemble the HPACK block and scan for grpc-status. */
                uint8_t trailer_buf[128U] = { 0U };
                size_t to_read = 0U;
                el2go_ota_status_t grpc_status = EL2GO_OTA_ERROR_INTERNAL;
                el2go_ota_status_t block_status = EL2GO_OTA_ERROR_INTERNAL;

                if (!data_received) {
                    EL2GO_DBG_PRINTF(VERBOSE,
                                     "gRPC recv: Trailers-Only response (no DATA frame)\n");
                }

                block_status = grpc_read_header_block(ctx, stream_id, pay_len,
                                                      (flags & H2_FLAG_END_HEADERS) != 0U,
                                                      trailer_buf, sizeof(trailer_buf), &to_read);
                if (block_status != EL2GO_OTA_SUCCESS) {
                    return block_status;
                }
                grpc_status = grpc_parse_trailers(trailer_buf, to_read, ctx);
                if (grpc_status == EL2GO_OTA_SUCCESS && data_received && !msg_complete) {
                    EL2GO_DBG_PRINTF(ERROR,
                                     "gRPC recv: trailers arrived before the full message "
                                     "(prefix %zu/%u, body %zu/%zu)\n",
                                     prefix_have, (unsigned int)GRPC_MSG_HDR_LEN, body_have,
                                     body_len);
                    return EL2GO_OTA_ERROR_NETWORK;
                }
                return grpc_status;
            } else {
                /* Response-Headers (no END_STREAM): validate :status and
                 * diagnose content-type before continuing. */
                uint8_t headers_buf[128U] = { 0U };
                size_t to_read_h = 0U;
                el2go_ota_status_t block_status = EL2GO_OTA_ERROR_INTERNAL;

                block_status = grpc_read_header_block(ctx, stream_id, pay_len,
                                                      (flags & H2_FLAG_END_HEADERS) != 0U,
                                                      headers_buf, sizeof(headers_buf), &to_read_h);
                if (block_status != EL2GO_OTA_SUCCESS) {
                    return block_status;
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
                /* Parse MAX_FRAME_SIZE (diagnostic only) while draining
                 * settings parameters, then send ACK. */
                el2go_ota_status_t parse_status = h2_parse_and_drain_settings_payload(ctx, pay_len);
                if (parse_status != EL2GO_OTA_SUCCESS) {
                    return parse_status;
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

        /* RST_STREAM: stray (prior call) -- drain and ignore;
         * active stream -- report as a network error. */
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
            /* RST_STREAM on the active stream: read the Error Code for
             * diagnostics and drain any remaining bytes. The connection is
             * reused across calls -- leaving bytes unread would desync the
             * next frame-header read. */
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

        /* GOAWAY: server terminated the connection. Read the Error Code
         * for diagnostics and drain remaining bytes before returning. */
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
