/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __DATASTORE_PRIV_H__
#define __DATASTORE_PRIV_H__

#include <stdbool.h>

#include "common/el2go_datastore.h"
#include "Dispatcher.pb.h"
#include "Agent.pb.h"
#include "Datastore.pb.h"
#include "pb_encode.h"
#include "pb_decode.h"
#include "pb_utils.h"

/**
 * @brief Return the nxp_iot_EndpointType for a datastore.
 *
 * Maps the el2go_datastore_type_t stored in the datastore to the protobuf
 * EndpointType value used in the dispatcher endpoint table and HelloResponse.
 * Specific datastore implementations may override this via the ops table.
 *
 * @param[in] datastore  Datastore to query.
 *
 * @retval nxp_iot_EndpointType for the datastore.
 */
nxp_iot_EndpointType el2go_datastore_get_endpoint_type(const el2go_datastore_t *datastore);

/**
 * @brief Populate endpoint information for a datastore endpoint.
 *
 * Endpoint get_info callback for the dispatcher endpoint table.
 * Delegates to ops->get_endpoint_info if provided; otherwise marks
 * has_type and has_endpointId as present with a minimal response.
 *
 * @param[in]  ctx   Pointer to the el2go_datastore_t (void * for callback compatibility).
 * @param[out] info  Pointer to nxp_iot_EndpointInformation to populate.
 *
 * @retval true always.
 */
el2go_status_t el2go_datastore_get_endpoint_info(void *ctx, nxp_iot_EndpointInformation *info);

/**
 * @brief Handle a provisioning request for a datastore endpoint.
 *
 * Dispatcher-facing handle_request callback. Conforms to endpoint_handle_request_t
 * so it can be registered directly in the dispatcher endpoint table.
 * If ops->handle_request is set, delegates to it (passing ds->context).
 * Otherwise runs the built-in default that handles ALLOCATE / READ / WRITE / COMMIT
 * via the standard ops callbacks.
 *
 * @param[in]  ctx          Pointer to el2go_datastore_t.
 * @param[in]  message_type pb_field_t descriptor (unused by the default impl).
 * @param[in]  istream      pb_istream_t positioned at the start of the request.
 * @param[out] ostream      pb_ostream_t for the encoded response payload.
 *
 * @retval EL2GO_STATUS_SUCCESS on success.
 * @retval el2go_status_t error code on decode or encode failure.
 */
el2go_status_t el2go_datastore_handle_request(void *ctx, const pb_field_t *message_type,
                                              pb_istream_t *istream, pb_ostream_t *ostream);

#endif /* __DATASTORE_PRIV_H__ */
