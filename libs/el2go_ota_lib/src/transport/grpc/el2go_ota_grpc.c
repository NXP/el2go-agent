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

/* Context */

typedef struct {
    el2go_ota_tls_ctx_t *tls_ctx;
    const char *hostname; /* not owned; points into user config */
    uint32_t next_stream_id;
    bool http2_ready; /* preface + SETTINGS exchanged */
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
 * Scan an HPACK block for the "grpc-status" header and decode its value.
 *
 * The scan is a simple linear byte search for the literal string
 * "grpc-status" (11 bytes) preceded by its HPACK length byte (0x0B).
 * This is reliable because grpc-status is always sent as a literal header
 * (not in the static table) and its name is fixed.
 *
 * Returns EL2GO_OTA_SUCCESS   if grpc-status is 0 (OK) or not found.
 * Returns EL2GO_OTA_ERROR_SERVER if grpc-status is non-zero.
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

    if (block == NULL || block_len < sizeof(NAME_PREFIX) + 2U) {
        return EL2GO_OTA_SUCCESS; /* no trailers to parse -- treat as OK */
    }

    /* Search for the 12-byte pattern anywhere in the block. */
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

    /* Step 2: allocate a new odd stream ID. */
    stream_id = ctx->next_stream_id;
    ctx->next_stream_id += 2U;

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
        /* hdr[5..8] = stream_id; not needed for single-stream tracking here */

        switch (frame_type) {
        /* DATA frame: contains the gRPC response message. */
        case H2_TYPE_DATA:
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
         * HEADERS frame: response headers (no END_STREAM) or trailers
         * (END_STREAM set, after DATA).
         */
        case H2_TYPE_HEADERS:
            if ((flags & H2_FLAG_END_STREAM) != 0U && data_received) {
                /*
                 * Trailer HEADERS: read the block into a stack buffer so
                 * grpc_parse_trailers() can scan it for grpc-status.
                 * Trailer blocks are typically < 64 bytes; use 128 bytes
                 * to be safe.  Any overflow is drained and ignored.
                 */
                uint8_t trailer_buf[128U] = { 0U };
                size_t to_read = 0U;
                size_t overflow = 0U;
                el2go_ota_status_t grpc_status = EL2GO_OTA_ERROR_INTERNAL;

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
                /* Response HEADERS (before DATA): drain, no grpc-status here. */
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
         * RST_STREAM / GOAWAY: server terminated the stream or connection.
         */
        case H2_TYPE_RST_STREAM:
        case H2_TYPE_GOAWAY:
            EL2GO_DBG_PRINTF(ERROR, "gRPC recv: server sent RST_STREAM/GOAWAY (type=0x%02X)\n",
                             (unsigned int)frame_type);
            return EL2GO_OTA_ERROR_NETWORK;

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
    ctx->next_stream_id = 1U; /* HTTP/2: client streams start at 1, odd numbers */
    ctx->http2_ready = false;

    t->send = grpc_send;
    t->recv = grpc_recv;
    t->deinit = grpc_deinit;
    t->impl_ctx = ctx;

    EL2GO_DBG_PRINTF(VERBOSE, "gRPC init: transport ready (host=%s)\n", hostname);
    return EL2GO_OTA_SUCCESS;
}
