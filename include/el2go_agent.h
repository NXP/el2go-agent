/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2018-2026 NXP
 */

#ifndef __EL2GO_AGENT_H__
#define __EL2GO_AGENT_H__

#include <stdint.h>
#include <stdbool.h>
#include "el2go_agent_status.h"
#include "el2go_agent_datastore.h"
#include "el2go_agent_keystore.h"
#include "el2go_agent_platform.h"

/*
 * IoT Agent context
 *
 * This is an opaque structure. Users should not access its members directly.
 * The actual definition is in the implementation files.
 */
typedef struct el2go_agent_ctx el2go_agent_ctx_t;

/**
 * el2go_agent_get_version - Get IoT Agent version information
 * @major: Pointer to store major version number
 * @minor: Pointer to store minor version number
 *
 * Return:
 * EL2GO_AGENT_SUCCESS on success, EL2GO_AGENT_FAILURE otherwise
 */
el2go_agent_t el2go_agent_get_version(unsigned int *major, unsigned int *minor);

/**
 * el2go_agent_init - Initialize and allocate IoT Agent context
 * @ctx: Pointer to store allocated context
 *
 * Return:
 * EL2GO_AGENT_SUCCESS on success, EL2GO_AGENT_FAILURE otherwise
 */
el2go_agent_t el2go_agent_init(el2go_agent_ctx_t **ctx);

/**
 * el2go_agent_free - Cleanup and free IoT Agent context
 * @ctx: Pointer to context (will be set to NULL)
 *
 * Return:
 * EL2GO_AGENT_SUCCESS on success, EL2GO_AGENT_FAILURE otherwise
 */
el2go_agent_t el2go_agent_free(el2go_agent_ctx_t **ctx);

/**
 * el2go_agent_keystore_add - Add a keystore to the agent
 * @ctx: IoT Agent context
 * @keystore_ctx: Keystore context to add
 *
 * Adds an initialized keystore to the agent's list of keystores.
 * The keystore must be initialized with el2go_agent_keystore_init() first.
 *
 * Return:
 * EL2GO_AGENT_SUCCESS on success, error code otherwise
 */
el2go_agent_t el2go_agent_keystore_add(el2go_agent_ctx_t *ctx,
				       el2go_agent_keystore_t *keystore_ctx);

/**
 * el2go_agent_keystore_remove - Remove a keystore from the agent
 * @ctx: IoT Agent context
 * @keystore_ctx: Keystore context to remove
 *
 * Removes the keystore from the agent's list. The keystore context itself
 * should be freed separately using el2go_agent_keystore_free().
 *
 * Return:
 * EL2GO_AGENT_SUCCESS on success, error code otherwise
 */
el2go_agent_t el2go_agent_keystore_remove(el2go_agent_ctx_t *ctx,
					  el2go_agent_keystore_t *keystore_ctx);

/**
 * el2go_agent_datastore_add - Add a datastore to the agent
 * @ctx: IoT Agent context
 * @datastore: Datastore context to add
 *
 * Adds an initialized datastore to the agent's list of datastores.
 * The datastore must be initialized with el2go_agent_datastore_init() first.
 *
 * Return:
 * EL2GO_AGENT_SUCCESS on success, error code otherwise
 */
el2go_agent_t el2go_agent_datastore_add(el2go_agent_ctx_t *ctx,
					el2go_agent_datastore_t *datastore);

/**
 * el2go_agent_datastore_remove - Remove a datastore from the agent
 * @ctx: IoT Agent context
 * @datastore: Pointer to datastore context (will be set to NULL)
 *
 * Removes the datastore from the agent's list and frees all resources.
 *
 * Return:
 * EL2GO_AGENT_SUCCESS on success, error code otherwise
 */
el2go_agent_t el2go_agent_datastore_remove(el2go_agent_ctx_t *ctx,
					   el2go_agent_datastore_t *datastore);
/**
  * el2go_agent_provision - Provision keys and certificates from server
  * @ctx: IoT Agent context
  * @verbosity: Status report verbosity level
  *
  * Connects to the EdgeLock 2GO server and provisions device keys and certificates.
  *
  * The function can optionally print the provisioning report received from the server.
  * Note: The report data is not currently exposed to the caller as it uses internal
  * protobuf structures. The API can be modified to provide a simplified or abstracted report
  * structure to avoid exposing protobuf implementation details to users.
  *
  * Return:
  * EL2GO_AGENT_SUCCESS on success, error code otherwise
  */
el2go_agent_t el2go_agent_provision(el2go_agent_ctx_t *ctx,
				    el2go_agent_verbosity_t verbosity);
/**
 * el2go_agent_get_device_uuid - Get device UUID in hexadecimal format
 * @ctx: IoT Agent context
 * @uuid_buffer: Buffer to store UUID hex string
 * @buffer_size: Input: Size of the provided buffer, Output: Actual size written (including null terminator)
 *
 * Retrieves the device's unique identifier (UUID) and formats it as a
 * hexadecimal string. The UUID is typically derived from the device's
 * hardware security module or platform-specific identifier.
 *
 * Return:
 * EL2GO_AGENT_SUCCESS on success, error code otherwise
 */
el2go_agent_t el2go_agent_get_device_uuid(el2go_agent_ctx_t *ctx,
					  char *uuid_buffer,
					  size_t *buffer_size);

#endif /* __EL2GO_AGENT_H__ */