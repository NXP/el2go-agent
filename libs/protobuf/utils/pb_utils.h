/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __PB_UTILS_H__
#define __PB_UTILS_H__

#include <stdbool.h>
#include "pb.h"
#include "Dispatcher.pb.h"

/**
 * @brief Encode one ResponsePayload into the ostream as an nxp_iot_Responses wire fragment.
 *
 * Wraps response in nxp_iot_Responses and calls pb_encode() so the resulting
 * bytes form a valid repeated responses[] field entry.  Endpoint handlers
 * (keystore, datastore, dispatcher) use this to write responses into the
 * per-iteration accumulation buffer.
 *
 * @param[in] ostream   Output stream receiving the encoded bytes.
 * @param[in] response  ResponsePayload to encode.
 *
 * @retval true  on success.
 * @retval false on encode failure.
 */
bool encode_responses_from_payload(pb_ostream_t *ostream, nxp_iot_ResponsePayload *response);

/**
 * @brief Peek at the next tag in a nanopb stream and identify the active oneof member.
 *
 * Reads one tag from the stream (without consuming the payload), then walks
 * the fields array to find the entry whose tag matches. Returns the
 * sub-message field descriptor pointer (field->ptr) so the caller can
 * dispatch to the correct pb_decode call.
 *
 * This mirrors the decode_unionmessage_type() helper from the nanopb examples.
 *
 * @param[in] stream  nanopb input stream positioned before the first field tag.
 * @param[in] fields  The pb_field_t array for the oneof/union message.
 *
 * @retval Pointer to the matching sub-message fields descriptor on success.
 * @retval NULL if no matching field is found or a stream error occurs.
 */
const pb_field_t *pb_decode_unionmessage_type(pb_istream_t *stream, const pb_field_t *fields);

#endif /* __PB_UTILS_H__ */
