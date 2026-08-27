/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <stdbool.h>

#include "rtp/el2go_rtp.h"
#include "rtp/el2go_rtp_config.h"
#include "common/el2go_status.h"
#include "common/el2go_datastore.h"
#include "common/el2go_keystore.h"

#include "compiler.h"
#include "debug.h"
#include "osal.h"
#include "builtin_macros.h"

#include "pb.h"
#include "pb_encode.h"
#include "pb_decode.h"
#include "pb_utils.h"

#include "Dispatcher.pb.h"
#include "Agent.pb.h"
#include "Datastore.pb.h"

#include "keystore_priv.h"
#include "datastore_priv.h"
#include "el2go_rtp_internal.h"
#include "el2go_dispatcher_priv.h"
#include "el2go_agent_endpoint.h"

/* ========================================================================== */
/* Response buffer ostream adaptor                                              */
/* ========================================================================== */

/**
 * @brief nanopb ostream write callback - accumulates encoded bytes into a flat buffer.
 *
 * Used to stage per-iteration responses before sending them over the network
 * as a single write. Returns false if the buffer would overflow.
 *
 * @param[in] stream  nanopb output stream (state holds a response_buffer_t pointer).
 * @param[in] buf     Source bytes to append.
 * @param[in] count   Number of bytes to append.
 *
 * @retval true  on success.
 * @retval false if count exceeds the remaining buffer space.
 */
static bool response_buffer_write_callback(pb_ostream_t *stream, const pb_byte_t *buf, size_t count)
{
    response_buffer_t *rb = (response_buffer_t *)stream->state;
    if (count > rb->remaining)
        return false;
    memcpy(rb->pos, buf, count);
    rb->pos += count;
    rb->remaining -= count;
    return true;
}

/* ========================================================================== */
/* Endpoint lookup helper                                                       */
/* ========================================================================== */

/**
 * @brief Find the endpoint entry matching a given type and id.
 *
 * Walks the dispatcher endpoint table and returns a pointer to the first entry
 * whose type and id fields match.  Returns NULL if no match is found.
 *
 * @param[in] disp  Dispatcher context containing the endpoint table.
 * @param[in] type  Endpoint type to match.
 * @param[in] id    Endpoint identifier to match.
 *
 * @retval Pointer to the matching endpoint_entry_t on success.
 * @retval NULL if no matching entry exists.
 */
static endpoint_entry_t *find_endpoint(const dispatcher_ctx_t *disp, nxp_iot_EndpointType type,
                                       uint32_t id)
{
    size_t i = 0U;

    for (i = 0U; i < disp->num_endpoints; i++) {
        if (disp->endpoints[i].type == type && disp->endpoints[i].id == id)
            return (endpoint_entry_t *)&disp->endpoints[i];
    }
    return NULL;
}

/* ========================================================================== */
/* Nanopb callback: decode nxp_iot_RequestPayload (one endpoint request)       */
/* ========================================================================== */

/**
 * @brief nanopb decode callback for nxp_iot_RequestPayload - dispatches one request.
 *
 * Called by nanopb once per repeated payload field inside an EndpointRequest.
 * Determines the concrete message type using decode_unionmessage_type(), then
 * either handles the message inline (Hello / Goodbye / CRL) or routes it to
 * the matching keystore or datastore endpoint handler. The encoded response is
 * appended to the accumulation buffer referenced by hargs.
 *
 * @param[in] stream  nanopb input stream positioned at the start of the payload.
 * @param[in] field   Field descriptor for the payload field (unused).
 * @param[in] arg     Pointer to a handle_request_args_t carrying dispatcher state
 *                    and the response accumulation buffer.
 *
 * @retval true  on success.
 * @retval false if decoding or response encoding fails.
 */
static bool handle_request_payload(pb_istream_t *stream, const pb_field_t *field, void **arg)
{
    handle_request_args_t *hargs = NULL;
    dispatcher_ctx_t *disp = NULL;
    nxp_iot_EndpointRequest *req = NULL;
    const pb_field_t *message_type = NULL;
    pb_ostream_t ostream = { 0 };
    endpoint_entry_t *ep = NULL;
    nxp_iot_AgentHelloRequest hello_req = nxp_iot_AgentHelloRequest_init_default;
    nxp_iot_ResponsePayload hello_response = nxp_iot_ResponsePayload_init_default;
    nxp_iot_AgentHelloResponse *hello_resp = NULL;
    nxp_iot_EndpointInformation *ep_info = NULL;
    el2go_status_t gi_status = EL2GO_STATUS_SUCCESS;
    el2go_status_t ep_status = EL2GO_STATUS_SUCCESS;
    size_t i = 0U;
    bool result = true;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    (void)field;

    if (!stream || !arg || !(*arg)) {
        result = false;
        goto exit;
    }

    hargs = (handle_request_args_t *)(*arg);
    disp = hargs->disp;
    req = disp->current_request;

    /* Identify the active oneof member. */
    message_type = pb_decode_unionmessage_type(stream, nxp_iot_RequestPayload_fields);
    if (message_type == NULL) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to identify RequestPayload message type\n");
        hargs->pending_error = EL2GO_STATUS_RTP_DECODE_ERROR;
        result = false;
        goto exit;
    }

    /* Build an ostream backed directly by the embedded response_buffer_t. */
    ostream.callback = &response_buffer_write_callback;
    ostream.state = &hargs->response_buf;
    ostream.max_size = hargs->response_buf.remaining;
    ostream.bytes_written = 0U;
    ostream.errmsg = NULL;

    if (message_type == nxp_iot_AgentHelloRequest_fields) {
        /*
         * HelloRequest is the first message exchanged, before the endpoint
         * list has been sent to the server.  It is handled here directly
         * rather than through the endpoint table so the dispatcher can
         * populate the HelloResponse with the full endpoint list.
         */
        hello_req = (nxp_iot_AgentHelloRequest)nxp_iot_AgentHelloRequest_init_default;
        if (!pb_decode_delimited(stream, nxp_iot_AgentHelloRequest_fields, &hello_req)) {
            EL2GO_DBG_PRINTF(ERROR, "Failed to decode AgentHelloRequest: %s\n",
                             PB_GET_ERROR(stream));
            hargs->pending_error = EL2GO_STATUS_RTP_DECODE_ERROR;
            result = false;
            goto exit;
        }

        hello_response = (nxp_iot_ResponsePayload)nxp_iot_ResponsePayload_init_default;
        hello_response.which_message = nxp_iot_ResponsePayload_hello_tag;
        hello_resp = &hello_response.message.hello;

        hello_resp->has_version = true;
        hello_resp->version = DISPATCHER_VERSION;

        hello_resp->has_communicationBufferSizeRequests = true;
        hello_resp->communicationBufferSizeRequests = (int32_t)EL2GO_RTP_REQUEST_BUFFER_SIZE;

        hello_resp->has_communicationBufferSizeResponses = true;
        hello_resp->communicationBufferSizeResponses = (int32_t)EL2GO_RTP_RESPONSE_BUFFER_SIZE;

        hello_resp->has_useMultipleRequestsPerMessage = true;
        hello_resp->useMultipleRequestsPerMessage = true;

        for (i = 0U; i < disp->num_endpoints; i++) {
            ep = &disp->endpoints[i];
            ep_info = &hello_resp->endpoints[hello_resp->endpoints_count];
            ep_info->has_type = true;
            ep_info->type = ep->type;
            ep_info->has_endpointId = true;
            ep_info->endpointId = ep->id;

            gi_status = ep->get_info(ep->ctx, ep_info);
            if (gi_status != EL2GO_STATUS_SUCCESS) {
                EL2GO_DBG_PRINTF(ERROR, "get_endpoint_info failed for endpoint %zu\n", i);
                hargs->pending_error = gi_status;
                result = false;
                goto exit;
            }
            if (INC_OVERFLOW(hello_resp->endpoints_count, 1)) {
                hargs->pending_error = EL2GO_STATUS_RESOURCE_LIMIT;
                result = false;
                goto exit;
            }
        }

        if (!encode_responses_from_payload(&ostream, &hello_response)) {
            EL2GO_DBG_PRINTF(ERROR, "Failed to encode AgentHelloResponse\n");
            hargs->pending_error = EL2GO_STATUS_RTP_ENCODE_ERROR;
            result = false;
            goto exit;
        }

        EL2GO_DBG_PRINTF(VERBOSE, "HelloRequest handled, sending HelloResponse\n");

    } else {
        /*
         * All other messages are routed to the endpoint that owns them.
         * The AGENT endpoint handles Goodbye and CRL via el2go_agent_handle_request.
         * Keystore and datastore endpoints are looked up by type and id from
         * the EndpointRequest header.
         *
         * When CRL verification is required, only Hello, Goodbye, and CRL
         * messages are permitted until a successful CRL verification has been
         * completed.  Reject any other message type before that point.
         */
        if (disp->crl_required && !disp->crl_verified &&
            message_type != nxp_iot_AgentGoodbyeRequest_fields &&
            message_type != nxp_iot_AgentCrlRequest_fields) {
            EL2GO_DBG_PRINTF(ERROR, "Unexpected message received before CRL verification, "
                                    "stopping processing\n");
            hargs->pending_error = EL2GO_STATUS_RTP_CRL_NOT_VERIFIED;
            result = false;
            goto exit;
        }

        if (!req || !req->has_type || !req->has_endpointId) {
            EL2GO_DBG_PRINTF(ERROR, "EndpointRequest missing type or endpointId\n");
            hargs->pending_error = EL2GO_STATUS_RTP_DECODE_ERROR;
            result = false;
            goto exit;
        }

        ep = find_endpoint(disp, req->type, req->endpointId);
        if (ep == NULL) {
            EL2GO_DBG_PRINTF(ERROR, "No endpoint found for type=%d id=0x%08" PRIx32 "\n",
                             (int)req->type, req->endpointId);
            hargs->pending_error = EL2GO_STATUS_RTP_ENDPOINT_NOT_FOUND;
            result = false;
            goto exit;
        }

        ep_status = ep->handle_request(ep->ctx, message_type, stream, &ostream);
        if (ep_status != EL2GO_STATUS_SUCCESS) {
            EL2GO_DBG_PRINTF(ERROR, "Endpoint handler failed for type=%d id=0x%08" PRIx32 "\n",
                             (int)req->type, req->endpointId);
            hargs->pending_error = ep_status;
            result = false;
            goto exit;
        }
    }

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, result);
    return result;
}

/* ========================================================================== */
/* Nanopb callback: decode nxp_iot_EndpointRequest                             */
/* ========================================================================== */

/**
 * @brief nanopb decode callback for nxp_iot_EndpointRequests.requests - handles one request.
 *
 * Called by nanopb for each entry in the repeated requests field of an
 * nxp_iot_EndpointRequests message. Decodes the nxp_iot_EndpointRequest header
 * (type, endpointId) and installs handle_request_payload() as the nested
 * callback for the payload oneof field.
 *
 * @param[in] stream  nanopb input stream positioned at the start of the EndpointRequest.
 * @param[in] field   Field descriptor for the requests field (unused).
 * @param[in] arg     Pointer to a handle_request_args_t carrying dispatcher state
 *                    and the response accumulation buffer.
 *
 * @retval true  on success.
 * @retval false if EndpointRequest decoding fails.
 */
static bool handle_request(pb_istream_t *stream, const pb_field_t *field, void **arg)
{
    handle_request_args_t *hargs = (handle_request_args_t *)(*arg);
    dispatcher_ctx_t *disp = hargs->disp;
    nxp_iot_EndpointRequest req = nxp_iot_EndpointRequest_init_default;

    (void)field;

    req.payload.funcs.decode = handle_request_payload;
    req.payload.arg = hargs;

    disp->current_request = &req;

    if (!pb_decode(stream, nxp_iot_EndpointRequest_fields, &req)) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to decode EndpointRequest: %s\n", PB_GET_ERROR(stream));
        disp->current_request = NULL;
        if (hargs->pending_error == EL2GO_STATUS_SUCCESS)
            hargs->pending_error = EL2GO_STATUS_RTP_DECODE_ERROR;
        return false;
    }

    disp->current_request = NULL;
    return true;
}

/* ========================================================================== */
/* Endpoint table build                                                         */
/* ========================================================================== */

/**
 * @brief Build the dispatcher endpoint routing table from the agent context.
 *
 * Registers the AGENT endpoint (id 0) first, then all keystores, then all
 * datastores. Each entry stores the endpoint type, id, get_info callback,
 * request handler callback, and a context pointer.
 *
 * @param[in]  ctx   Agent context carrying the registered keystores and datastores.
 * @param[out] disp  Dispatcher context whose endpoint table will be populated.
 *
 * @retval EL2GO_STATUS_SUCCESS       upon success.
 * @retval EL2GO_STATUS_RESOURCE_LIMIT if the number of endpoints exceeds
 *                                     DISPATCHER_MAX_ENDPOINTS.
 */
static el2go_status_t build_endpoint_table(el2go_rtp_ctx_t *ctx, dispatcher_ctx_t *disp)
{
    size_t n = 0U;
    size_t i = 0U;
    el2go_keystore_t *ks = NULL;
    el2go_datastore_t *ds = NULL;

    /* Register the agent endpoint (type AGENT, id 0).
     * HelloRequest is intercepted in handle_request_payload before endpoint
     * lookup, so it never reaches this handler.  Goodbye and CRL are routed
     * here via el2go_agent_handle_request using the dispatcher context as ctx. */
    disp->endpoints[n].type = nxp_iot_EndpointType_AGENT;
    disp->endpoints[n].id = DISPATCHER_AGENT_ENDPOINT_ID;
    disp->endpoints[n].get_info = el2go_agent_get_info;
    disp->endpoints[n].handle_request = el2go_agent_handle_request;
    disp->endpoints[n].ctx = disp;
    n++;

    /* Register keystores */
    for (i = 0U; i < ctx->num_keystores; i++) {
        if (n >= DISPATCHER_MAX_ENDPOINTS || i >= EL2GO_RTP_MAX_KEYSTORES) {
            EL2GO_DBG_PRINTF(ERROR,
                             "Too many keystores (i=%zu, max=%u) or endpoint table full (n=%zu)\n",
                             i, EL2GO_RTP_MAX_KEYSTORES, n);
            return EL2GO_STATUS_RESOURCE_LIMIT;
        }
        ks = ctx->keystores[i];
        disp->endpoints[n].type = el2go_keystore_get_endpoint_type(ks);
        disp->endpoints[n].id = ks->id;
        disp->endpoints[n].get_info = el2go_keystore_get_endpoint_info;
        disp->endpoints[n].handle_request = el2go_keystore_handle_request;
        disp->endpoints[n].ctx = ks;
        EL2GO_DBG_PRINTF(VERBOSE, "Registered keystore endpoint: id=0x%08" PRIx32 "\n", ks->id);
        n++;
    }

    /* Register all datastores from the regular array. */
    for (i = 0U; i < ctx->num_datastores; i++) {
        if (n >= DISPATCHER_MAX_ENDPOINTS || i >= EL2GO_RTP_MAX_DATASTORES) {
            EL2GO_DBG_PRINTF(ERROR,
                             "Too many datastores (i=%zu, max=%u) or endpoint table full (n=%zu)\n",
                             i, EL2GO_RTP_MAX_DATASTORES, n);
            return EL2GO_STATUS_RESOURCE_LIMIT;
        }
        ds = ctx->datastores[i];
        disp->endpoints[n].type = el2go_datastore_get_endpoint_type(ds);
        if (disp->endpoints[n].type == nxp_iot_EndpointType_INVALID) {
            EL2GO_DBG_PRINTF(VERBOSE, "Skipping datastore id=0x%08" PRIx32 ": unsupported type\n",
                             ds->id);
            continue;
        }
        disp->endpoints[n].id = ds->id;
        disp->endpoints[n].get_info = el2go_datastore_get_endpoint_info;
        disp->endpoints[n].handle_request = el2go_datastore_handle_request;
        disp->endpoints[n].ctx = ds;
        EL2GO_DBG_PRINTF(VERBOSE, "Registered datastore endpoint: id=0x%08" PRIx32 "\n", ds->id);
        n++;
    }

    /* Register the EL2GO connection datastore if present; it is stored separately
     * from datastores[] and must be added explicitly. */
    if (ctx->el2go_datastore != NULL) {
        if (n >= DISPATCHER_MAX_ENDPOINTS) {
            EL2GO_DBG_PRINTF(ERROR, "Too many endpoints, increase DISPATCHER_MAX_ENDPOINTS\n");
            return EL2GO_STATUS_RESOURCE_LIMIT;
        }
        ds = ctx->el2go_datastore;
        disp->endpoints[n].type = el2go_datastore_get_endpoint_type(ds);
        if (disp->endpoints[n].type == nxp_iot_EndpointType_INVALID) {
            EL2GO_DBG_PRINTF(
                VERBOSE, "Skipping EL2GO datastore id=0x%08" PRIx32 ": unsupported type\n", ds->id);
        } else {
            disp->endpoints[n].id = ds->id;
            disp->endpoints[n].get_info = el2go_datastore_get_endpoint_info;
            disp->endpoints[n].handle_request = el2go_datastore_handle_request;
            disp->endpoints[n].ctx = ds;
            EL2GO_DBG_PRINTF(VERBOSE,
                             "Registered EL2GO connection datastore endpoint: "
                             "id=0x%08" PRIx32 "\n",
                             ds->id);
            n++;
        }
    }

    disp->num_endpoints = n;
    EL2GO_DBG_PRINTF(VERBOSE, "Dispatcher endpoint table: %zu entries\n", n);
    return EL2GO_STATUS_SUCCESS;
}

el2go_status_t el2go_rtp_dispatch(el2go_rtp_ctx_t *ctx, pb_istream_t *istream,
                                  pb_ostream_t *ostream, nxp_iot_UpdateStatusReport *status_report)
{
    el2go_status_t status = EL2GO_STATUS_INVALID_PARAMETER;
    dispatcher_ctx_t disp = { 0 };
    uint8_t *mem = NULL;
    handle_request_args_t hargs = { 0 };
    nxp_iot_EndpointRequests ep_requests;
    size_t response_len = 0U;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!ctx || !istream || !ostream)
        goto exit;

    disp.agent_ctx = ctx;
    disp.net_ctx = (istream->state != NULL) ? (net_crypto_ctx_t *)istream->state : NULL;
    disp.status_report = status_report;

    /* Capture the CRL requirement once so the dispatch callbacks need no ifdefs. */
#if defined(EL2GO_RTP_REQUEST_CRL) && (EL2GO_RTP_REQUEST_CRL == 1)
    disp.crl_required = true;
#endif
    EL2GO_DBG_PRINTF(INFO, "CRL verification %s\n", disp.crl_required ? "enabled" : "disabled");

    /* Build the endpoint routing table from registered keystores/datastores */
    status = build_endpoint_table(ctx, &disp);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to build endpoint table: 0x%04x\n", status);
        goto exit;
    }

    /* Allocate and zero-initialize the response accumulation buffer */
    mem = (uint8_t *)osal_calloc(1U, EL2GO_RTP_RESPONSE_BUFFER_SIZE);
    if (mem == NULL) {
        status = EL2GO_STATUS_ALLOCATION_ERROR;
        EL2GO_DBG_PRINTF(ERROR, "Failed to allocate response buffer\n");
        goto exit;
    }

    hargs.disp = &disp;
    hargs.response_buf.start = mem;
    hargs.response_buf.remaining = EL2GO_RTP_RESPONSE_BUFFER_SIZE;

    EL2GO_DBG_PRINTF(VERBOSE, "Starting RTP dispatch loop\n");

    while (!disp.closed) {
        /* Reset per-iteration state: response buffer position and pending error. */
        hargs.response_buf.pos = hargs.response_buf.start;
        hargs.response_buf.remaining = EL2GO_RTP_RESPONSE_BUFFER_SIZE;
        hargs.pending_error = EL2GO_STATUS_SUCCESS;

        ep_requests = (nxp_iot_EndpointRequests)nxp_iot_EndpointRequests_init_default;

        /* Decode one nxp_iot_EndpointRequests message (length-delimited) */
        ep_requests.requests.funcs.decode = handle_request;
        ep_requests.requests.arg = &hargs;

        if (!pb_decode_delimited(istream, nxp_iot_EndpointRequests_fields, &ep_requests)) {
            EL2GO_DBG_PRINTF(ERROR, "Failed to decode EndpointRequests: %s\n",
                             PB_GET_ERROR(istream));
            /* If a callback set a specific error, propagate it; otherwise generic decode error. */
            status = (hargs.pending_error != EL2GO_STATUS_SUCCESS) ? hargs.pending_error :
                                                                     EL2GO_STATUS_RTP_DECODE_ERROR;
            goto cleanup;
        }

        /* Send accumulated responses back to server */
        response_len = (size_t)(hargs.response_buf.pos - hargs.response_buf.start);
        if (response_len > 0U) {
            if (!pb_encode_string(ostream, hargs.response_buf.start, response_len)) {
                EL2GO_DBG_PRINTF(ERROR, "Failed to write Responses to network: %s\n",
                                 PB_GET_ERROR(ostream));
                status = EL2GO_STATUS_RTP_ENCODE_ERROR;
                goto cleanup;
            }
        }
    }

    status = disp.update_success ? EL2GO_STATUS_SUCCESS : EL2GO_STATUS_RTP_PROVISIONING_FAILED;
    EL2GO_DBG_PRINTF(VERBOSE, "RTP dispatch loop finished, status=0x%04x\n", status);

cleanup:
    osal_free(mem);

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}
