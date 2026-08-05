/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <stdbool.h>

#include "debug.h"

#include "pb.h"
#include "pb_encode.h"
#include "pb_decode.h"
#include "pb_utils.h"

#include "Dispatcher.pb.h"
#include "Agent.pb.h"

#include "net_crypto.h"

#include "el2go_dispatcher_priv.h"
#include "el2go_agent_endpoint.h"

/* ========================================================================== */
/* Agent endpoint - get_info                                                   */
/* ========================================================================== */

el2go_status_t el2go_agent_get_info(void *ctx, nxp_iot_EndpointInformation *info)
{
    nxp_iot_AgentAdditionalData additional_data = nxp_iot_AgentAdditionalData_init_default;
    pb_ostream_t ostream = { 0 };

    (void)ctx;

    if (info == NULL) {
        return EL2GO_STATUS_INVALID_PARAMETER;
    }

    /* type and endpointId already filled by the dispatcher build step */
    info->has_type = true;
    info->has_endpointId = true;

    info->has_version = true;
    info->version = AGENT_VERSION;

    additional_data.has_serviceDescriptorVersion = true;
    additional_data.serviceDescriptorVersion = nxp_iot_ServiceDescriptorVersion_PROTOBUF;

#if defined(EL2GO_RTP_REQUEST_CRL) && (EL2GO_RTP_REQUEST_CRL == 1)
    additional_data.has_requestCrl = true;
    additional_data.requestCrl = true;
#endif

    info->has_additionalData = true;
    ostream =
        pb_ostream_from_buffer(info->additionalData.bytes, sizeof(info->additionalData.bytes));
    if (!pb_encode_delimited(&ostream, nxp_iot_AgentAdditionalData_fields, &additional_data)) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to encode AgentAdditionalData: %s\n",
                         PB_GET_ERROR(&ostream));
        return EL2GO_STATUS_RTP_ENCODE_ERROR;
    }

    info->additionalData.size = (pb_size_t)ostream.bytes_written;
    return EL2GO_STATUS_SUCCESS;
}

/* ========================================================================== */
/* Agent endpoint - handle_request                                            */
/* ========================================================================== */

el2go_status_t el2go_agent_handle_request(void *ctx, const pb_field_t *message_type,
                                          pb_istream_t *istream, pb_ostream_t *ostream)
{
    dispatcher_ctx_t *disp = (dispatcher_ctx_t *)ctx;
    nxp_iot_AgentGoodbyeRequest goodbye = nxp_iot_AgentGoodbyeRequest_init_default;
    el2go_status_t result = EL2GO_STATUS_RTP_DECODE_ERROR;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (ctx == NULL || message_type == NULL || istream == NULL || ostream == NULL) {
        return EL2GO_STATUS_INVALID_PARAMETER;
    }

    if (message_type == nxp_iot_AgentGoodbyeRequest_fields) {
        EL2GO_DBG_PRINTF(VERBOSE, "el2go_agent_handle_request: GoodbyeRequest\n");

        if (!pb_decode_delimited(istream, nxp_iot_AgentGoodbyeRequest_fields, &goodbye)) {
            EL2GO_DBG_PRINTF(ERROR, "Failed to decode AgentGoodbyeRequest: %s\n",
                             PB_GET_ERROR(istream));
            goto exit;
        }

        if (goodbye.has_status) {
            disp->update_success =
                (goodbye.status.has_status &&
                 goodbye.status.status == nxp_iot_UpdateStatusReport_UpdateStatus_SUCCESS);

            if (disp->status_report != NULL) {
                /* Transfer ownership of goodbye.status to the caller's buffer.
                 * Zero out goodbye.status before pb_release so that any
                 * dynamically-allocated sub-fields are not freed here -
                 * the caller is responsible for releasing *disp->status_report. */
                *disp->status_report = goodbye.status;
                goodbye.status =
                    (nxp_iot_UpdateStatusReport)nxp_iot_UpdateStatusReport_init_default;
            }
        } else {
            /* No status field present - outcome unknown, leave update_success as false. */
            EL2GO_DBG_PRINTF(DEBUG, "GoodbyeRequest received without status field\n");
        }

        disp->closed = true;
        pb_release(nxp_iot_AgentGoodbyeRequest_fields, &goodbye);
        EL2GO_DBG_PRINTF(VERBOSE, "GoodbyeRequest received, closing dispatch loop\n");
        result = EL2GO_STATUS_SUCCESS;

    } else if (disp->crl_required && message_type == nxp_iot_AgentCrlRequest_fields) {
        nxp_iot_AgentCrlRequest crl_req = nxp_iot_AgentCrlRequest_init_default;
        nxp_iot_AgentCrlResponse response_crl = nxp_iot_AgentCrlResponse_init_default;
        nxp_iot_ResponsePayload response = nxp_iot_ResponsePayload_init_default;
        el2go_status_t crl_st = EL2GO_STATUS_SUCCESS;

        EL2GO_DBG_PRINTF(VERBOSE, "el2go_agent_handle_request: CrlRequest\n");

        if (!pb_decode_delimited(istream, nxp_iot_AgentCrlRequest_fields, &crl_req)) {
            EL2GO_DBG_PRINTF(ERROR, "Failed to decode AgentCrlRequest: %s\n",
                             PB_GET_ERROR(istream));
            goto exit;
        }

        if (crl_req.crl != NULL && crl_req.crl->size > 0U) {
            crl_st = net_crypto_verify_cert(disp->net_ctx, crl_req.crl->bytes,
                                            (size_t)crl_req.crl->size);
            if (crl_st != EL2GO_STATUS_SUCCESS) {
                EL2GO_DBG_PRINTF(ERROR, "CRL verification failed: 0x%04x\n", crl_st);
                response_crl.has_error = true;
                response_crl.error = (uint32_t)crl_st;
                disp->closed = true;
            } else {
                disp->crl_verified = true;
            }
        }

        pb_release(nxp_iot_AgentCrlRequest_fields, &crl_req);

        response.which_message = nxp_iot_ResponsePayload_crl_tag;
        response.message.crl = response_crl;

        if (!encode_responses_from_payload(ostream, &response)) {
            EL2GO_DBG_PRINTF(ERROR, "Failed to encode CrlResponse\n");
            result = EL2GO_STATUS_RTP_ENCODE_ERROR;
            goto exit;
        }

        EL2GO_DBG_PRINTF(VERBOSE, "CrlRequest handled\n");
        result = EL2GO_STATUS_SUCCESS;

    } else {
        EL2GO_DBG_PRINTF(ERROR, "Unknown agent message type\n");
    }

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, (int)result);
    return result;
}
