/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __EL2GO_SERVER_CONNECTION_H__
#define __EL2GO_SERVER_CONNECTION_H__

#include <stdint.h>
#include <stdbool.h>

#include "pb.h"
#include "common/el2go_datastore.h"
#include "common/el2go_keystore.h"
#include "common/el2go_status.h"
#include "rtp/el2go_rtp.h"

/**
 * @defgroup el2go_server_conn Server Connection Internal API
 * @brief Internal interface for managing EdgeLock 2GO server connections.
 * @{
 */

/**
 * @brief Check if the EdgeLock 2GO datastore needs update
 *
 * If no user provided values, always update from constants.
 * If user provided values, check if datastore already has matching values
 * and skip update if they match.
 *
 * @param[in] datastore Datastore to check
 * @param[in] hostname Hostname to compare against
 * @param[in] port Port to compare against
 * @param[in] certificate User provided certificate, or NULL if not provided
 *
 * @return true if the datastore needs to be updated, false otherwise
 */
bool el2go_conn_datastore_needs_update(el2go_datastore_t *datastore, const char *hostname,
                                       uint16_t port, const el2go_buffer_t *certificate);

/**
 * @brief Write EdgeLock 2GO connection data to datastore
 *
 * Builds a ServiceDescriptor protobuf message with the provided connection
 * data, wraps it in a configuration data header with SHA-256 checksum,
 * and writes everything to the datastore.
 *
 * All parameters must be non-NULL except @p server_cert which is optional.
 *
 * @param[in] datastore Datastore to write to
 * @param[in] keystore_ctx Keystore context for key references
 * @param[in] hostname Hostname to write
 * @param[in] port Port to write
 * @param[in] server_cert Server certificate to write (optional, can be NULL)
 * @param[in] object_id Key object ID to use for the client key reference
 * @param[in] client_cert Client certificate to write
 *
 * @return EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
el2go_status_t el2go_conn_write_datastore(el2go_datastore_t *datastore,
                                          el2go_keystore_t *keystore_ctx, const char *hostname,
                                          uint16_t port, const pb_bytes_array_t *server_cert,
                                          uint32_t object_id, const pb_bytes_array_t *client_cert);

/** @} */ /* end of el2go_server_conn */

#endif /* __EL2GO_SERVER_CONNECTION_H__ */
