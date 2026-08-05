/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "pb_utils.h"
#include "pb_encode.h"
#include "pb_decode.h"
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

/* ========================================================================== */
/* Union message type detection helper                                         */
/* ========================================================================== */

const pb_field_t *pb_decode_unionmessage_type(pb_istream_t *stream, const pb_field_t *fields)
{
    pb_wire_type_t wire_type = (pb_wire_type_t)0;
    uint32_t tag = 0U;
    bool eof = false;
    const pb_field_t *f = NULL;

    while (pb_decode_tag(stream, &wire_type, &tag, &eof)) {
        if (wire_type == PB_WT_STRING) {
            /* Walk the fields table looking for a tag match. */
            for (f = fields; f->tag != 0; f++) {
                if (f->tag == (pb_size_t)tag && PB_LTYPE(f->type) == PB_LTYPE_SUBMESSAGE) {
                    /* Return the sub-message's own fields descriptor. */
                    return (const pb_field_t *)f->ptr;
                }
            }
        }

        /* Unknown tag or non-submessage wire type - skip the field and keep looking. */
        if (!pb_skip_field(stream, wire_type))
            break;
    }

    return NULL;
}
