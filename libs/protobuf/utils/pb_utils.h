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

#endif /* __PB_UTILS_H__ */
