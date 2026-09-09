/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __EL2GO_DISPATCHER_PRIV_H__
#define __EL2GO_DISPATCHER_PRIV_H__

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "rtp/el2go_rtp.h"
#include "rtp/el2go_rtp_config.h"
#include "common/el2go_status.h"

#include "net_crypto.h"
#include "Agent.pb.h"

#include "pb.h"
#include "pb_encode.h"
#include "pb_decode.h"

#include "Dispatcher.pb.h"

/**
 * @defgroup el2go_dispatcher_int Dispatcher Internal API
 * @brief Internal interface for the RTP session dispatcher.
 * @{
 */

/* ========================================================================== */
/* Protocol constants                                                          */
/* ========================================================================== */

/**
 * @brief Size of the buffer for handling incoming request messages.
 *
 * Reported to the server in AgentHelloResponse so it knows the maximum
 * single-request payload size to send. Can be overridden at compile time.
 */
#ifndef EL2GO_RTP_REQUEST_BUFFER_SIZE
#define EL2GO_RTP_REQUEST_BUFFER_SIZE 4096U
#endif

/**
 * @brief Size of the per-iteration response accumulation buffer (bytes).
 *
 * All endpoint responses in one round-trip are collected here before being
 * sent as a single nxp_iot_Responses message. Reported in AgentHelloResponse
 * communicationBufferSizeResponses. Can be overridden at compile time.
 */
#ifndef EL2GO_RTP_RESPONSE_BUFFER_SIZE
#define EL2GO_RTP_RESPONSE_BUFFER_SIZE 4096U
#endif

/** @brief Dispatcher protocol version major component. */
#define DISPATCHER_VERSION_MAJOR 1U

/** @brief Dispatcher protocol version minor component. */
#define DISPATCHER_VERSION_MINOR 0U

/** @brief Dispatcher protocol version patch component. */
#define DISPATCHER_VERSION_PATCH 0U

/**
 * @brief Packed dispatcher protocol version sent in AgentHelloResponse.
 *
 * Encoded as ((major * 256) + minor) * 256 + patch.
 */
#define DISPATCHER_VERSION                                                              \
    ((uint32_t)(((DISPATCHER_VERSION_MAJOR * 256U) + DISPATCHER_VERSION_MINOR) * 256U + \
                DISPATCHER_VERSION_PATCH))

/** @brief Agent endpoint version major component. */
#define AGENT_VERSION_MAJOR 1U

/** @brief Agent endpoint version minor component. */
#define AGENT_VERSION_MINOR 0U

/** @brief Agent endpoint version patch component. */
#define AGENT_VERSION_PATCH 0U

/**
 * @brief Packed agent endpoint version sent in AgentHelloResponse endpoints[].
 *
 * Encoded as ((major * 256) + minor) * 256 + patch.
 */
#define AGENT_VERSION \
    ((uint32_t)(((AGENT_VERSION_MAJOR * 256U) + AGENT_VERSION_MINOR) * 256U + AGENT_VERSION_PATCH))

/**
 * @brief Fixed endpoint ID for the agent endpoint (type AGENT).
 *
 * The server uses this endpoint to send Hello, Goodbye, and CRL messages.
 */
#define DISPATCHER_AGENT_ENDPOINT_ID 0U

/**
 * @brief Maximum number of endpoints in the dispatcher routing table.
 *
 * One AGENT endpoint plus all registered keystores, datastores, and the
 * dedicated EL2GO connection datastore (registered separately).
 * Must fit within nxp_iot_AgentHelloResponse.endpoints[].
 */
#define DISPATCHER_MAX_ENDPOINTS (1U + EL2GO_RTP_MAX_KEYSTORES + EL2GO_RTP_MAX_DATASTORES + 1U)

/* ========================================================================== */
/* Endpoint table types                                                        */
/* ========================================================================== */

/**
 * @brief Per-endpoint get_info callback type.
 *
 * Fills an nxp_iot_EndpointInformation entry for the Hello response.
 *
 * @param[in]  ctx   Endpoint-specific context pointer.
 * @param[out] info  Endpoint information structure to populate.
 *
 * @retval EL2GO_STATUS_SUCCESS on success.
 * @retval el2go_status_t error code on failure.
 */
typedef el2go_status_t (*endpoint_get_info_t)(void *ctx, nxp_iot_EndpointInformation *info);

/**
 * @brief Per-endpoint request handler callback type.
 *
 * Decodes the incoming request and encodes a response.
 *
 * @param[in]  ctx          Endpoint-specific context pointer.
 * @param[in]  message_type nanopb fields descriptor identifying the request type.
 * @param[in]  istream      Input stream at the start of the request payload.
 * @param[out] ostream      Output stream for the encoded response.
 *
 * @retval EL2GO_STATUS_SUCCESS on success.
 * @retval el2go_status_t error code on failure.
 */
typedef el2go_status_t (*endpoint_handle_request_t)(void *ctx, const pb_field_t *message_type,
                                                    pb_istream_t *istream, pb_ostream_t *ostream);

/** @brief Single entry in the dispatcher endpoint routing table. */
typedef struct {
    nxp_iot_EndpointType type;                /**< Endpoint type. */
    uint32_t id;                              /**< Endpoint identifier. */
    endpoint_get_info_t get_info;             /**< HelloResponse info callback. */
    endpoint_handle_request_t handle_request; /**< Request handler callback. */
    void *ctx;                                /**< Endpoint-specific context pointer. */
} endpoint_entry_t;

/* ========================================================================== */
/* Dispatcher internal context                                                 */
/* ========================================================================== */

/** @brief Dispatcher runtime context. */
typedef struct {
    /** Agent context carrying the registered keystores and datastores. */
    el2go_rtp_ctx_t *agent_ctx;
    /** TLS network context for this session. */
    net_crypto_ctx_t *net_ctx;
    /** Endpoint routing table. */
    endpoint_entry_t endpoints[DISPATCHER_MAX_ENDPOINTS];
    /** Number of valid entries in endpoints[]. */
    size_t num_endpoints;
    /** EndpointRequest being decoded; valid only during nanopb decode callbacks. */
    nxp_iot_EndpointRequest *current_request;
    /** Set to true when a GoodbyeRequest has been received. */
    bool closed;
    /** True when EL2GO_RTP_REQUEST_CRL is enabled; drives the pre-CRL-verification gate. */
    bool crl_required;
    /** True once a CRL has been successfully received and verified. */
    bool crl_verified;
    /** Provisioning outcome reported by the server GoodbyeRequest. */
    bool update_success;
    /** Optional output buffer filled from the GoodbyeRequest status report. */
    nxp_iot_UpdateStatusReport *status_report;
} dispatcher_ctx_t;

/** @brief Per-iteration response accumulation buffer. */
typedef struct {
    uint8_t *start;   /**< Base of the allocated memory block. */
    uint8_t *pos;     /**< Next byte to write; advances with each write. */
    size_t remaining; /**< Bytes still available between pos and end of the block. */
} response_buffer_t;

/** @brief Arguments forwarded into the nanopb decode callbacks. */
typedef struct {
    dispatcher_ctx_t *disp;         /**< Dispatcher context for the current session. */
    response_buffer_t response_buf; /**< Response accumulation buffer for this round-trip. */
    el2go_status_t pending_error;   /**< Specific error set by a callback before returning false. */
} handle_request_args_t;

/* ========================================================================== */
/* Public API                                                                  */
/* ========================================================================== */

/**
 * @brief Run the RTP provisioning dispatch loop.
 *
 * Establishes the protocol with the EL2GO server and processes
 * nxp_iot_EndpointRequests messages until a GoodbyeRequest is received.
 * Each EndpointRequest is routed to the registered keystore or datastore
 * handler matching its (type, endpointId) pair. Agent-level messages
 * (HelloRequest, GoodbyeRequest, CrlRequest) are handled internally.
 * Responses are accumulated per iteration and sent back as a single
 * length-delimited nxp_iot_Responses message.
 *
 * @param[in]  ctx            RTP agent context with registered keystores and datastores.
 * @param[in]  istream        nanopb input stream to read EndpointRequests from.
 * @param[in]  ostream        nanopb output stream to write EndpointResponses to.
 * @param[out] status_report  Filled with the server status report on exit (may be NULL).
 *
 * @return @ref el2go_status_t value, @ref EL2GO_STATUS_SUCCESS on success.
 */
el2go_status_t el2go_rtp_dispatch(el2go_rtp_ctx_t *ctx, pb_istream_t *istream,
                                  pb_ostream_t *ostream, nxp_iot_UpdateStatusReport *status_report);

/** @} */ /* end of el2go_dispatcher_int */

#endif /* __EL2GO_DISPATCHER_PRIV_H__ */
