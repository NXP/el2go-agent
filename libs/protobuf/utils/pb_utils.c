/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "pb_utils.h"
#include "pb_encode.h"
#include "Dispatcher.pb.h"

/* ========================================================================== */
/* nxp_iot_Responses encoding helper                                           */
/* ========================================================================== */

/**
 * @brief nanopb encode callback for nxp_iot_Responses.responses.
 *
 * Writes the wire-format entry for one nxp_iot_ResponsePayload item in the
 * repeated responses[] field.
 */
static bool encode_responses_callback(pb_ostream_t *stream, const pb_field_t *field,
                                      void *const *arg)
{
    const nxp_iot_ResponsePayload *response = (const nxp_iot_ResponsePayload *)(*arg);
    bool result = false;

    (void)field;

    result = pb_encode_tag(stream, PB_WT_STRING, nxp_iot_Responses_responses_tag);
    if (!result)
        return false;

    return pb_encode_delimited(stream, nxp_iot_ResponsePayload_fields, response);
}

bool encode_responses_from_payload(pb_ostream_t *ostream, nxp_iot_ResponsePayload *response)
{
    nxp_iot_Responses responses = nxp_iot_Responses_init_default;
    responses.responses.arg = response;
    responses.responses.funcs.encode = encode_responses_callback;

    if (!pb_encode(ostream, nxp_iot_Responses_fields, &responses)) {
        /* Caller can retrieve the error string via PB_GET_ERROR(ostream). */
        return false;
    }
    return true;
}
