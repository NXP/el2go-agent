/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __EL2GO_AGENT_ENDPOINT_H__
#define __EL2GO_AGENT_ENDPOINT_H__

#include <stdbool.h>
#include "pb.h"
#include "pb_encode.h"
#include "pb_decode.h"
#include "Dispatcher.pb.h"

/**
 * @defgroup el2go_agent_endpoint Agent Endpoint Internal API
 * @brief Internal interface for the AGENT endpoint handler.
 * @{
 */

/**
 * @brief Populate endpoint information for the AGENT endpoint.
 *
 * Sets the dispatcher protocol version and encodes nxp_iot_AgentAdditionalData
 * into info->additionalData. The additional data advertises the service
 * descriptor version (PROTOBUF) and, if EL2GO_RTP_REQUEST_CRL is set,
 * requests the server to push a CRL via AgentCrlRequest.
 *
 * @param[in]  ctx   Unused (no per-agent context).
 * @param[out] info  Endpoint information structure to populate.
 *
 * @retval EL2GO_STATUS_SUCCESS on success.
 * @retval EL2GO_STATUS_RTP_ENCODE_ERROR if encoding the additional data fails.
 */
el2go_status_t el2go_agent_get_info(void *ctx, nxp_iot_EndpointInformation *info);

/**
 * @brief Handle agent-level requests (Goodbye and CRL) routed via the endpoint table.
 *
 * Dispatches on message_type and handles nxp_iot_AgentGoodbyeRequest and
 * nxp_iot_AgentCrlRequest. The ctx parameter must point to a dispatcher_ctx_t
 * so the function can update the closed/update_success flags and the status report.
 *
 * @param[in]  ctx          Pointer to the dispatcher_ctx_t for this session.
 * @param[in]  message_type nanopb fields descriptor identifying the message type.
 * @param[in]  istream      Input stream positioned at the start of the request payload.
 * @param[out] ostream      Output stream for any encoded response (Goodbye has none).
 *
 * @retval EL2GO_STATUS_SUCCESS on success.
 * @retval el2go_status_t error code on decode failure or unknown message type.
 */
el2go_status_t el2go_agent_handle_request(void *ctx, const pb_field_t *message_type,
                                          pb_istream_t *istream, pb_ostream_t *ostream);

/** @} */ /* end of el2go_agent_endpoint */

#endif /* __EL2GO_AGENT_ENDPOINT_H__ */
