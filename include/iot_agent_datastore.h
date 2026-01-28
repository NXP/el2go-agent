/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __IOT_AGENT_DATASTORE_H__
#define __IOT_AGENT_DATASTORE_H__

#include <stdint.h>
#include <stddef.h>
#include "iot_agent_status.h"
#include "iot_agent_keystore.h"

typedef struct iot_agent_ctx iot_agent_ctx_t;

/*
 * IoT Agent datastore context
 *
 * This is an opaque structure. Users should not access its members directly.
 * The actual definition is in the implementation files.
 */
typedef struct iot_agent_datastore_ctx iot_agent_datastore_ctx_t;

/*
 * Datastore types
 */
typedef enum {
	IOT_AGENT_DATASTORE_TYPE_FS,    /* Filesystem-based datastore */
	IOT_AGENT_DATASTORE_TYPE_PLAIN  /* Plain memory datastore */
} iot_agent_datastore_type_t;

/*
 * Binary data buffer
 */
typedef struct {
	const uint8_t *data;  /* Pointer to data */
	size_t len;           /* Length in bytes */
} iot_agent_buffer_t;

/**
 * iot_agent_datastore_add - Add a datastore to the agent
 * @agent_ctx: IoT Agent context
 * @id: Datastore identifier
 * @name: Datastore name
 * @type: Datastore type (FS or PLAIN)
 * @datastore_ctx: Pointer to store the created datastore context
 *
 * Return:
 * IOT_AGENT_SUCCESS on success, error code otherwise
 */
iot_agent_t
iot_agent_datastore_add(iot_agent_ctx_t *agent_ctx, uint32_t id,
			const char *name, iot_agent_datastore_type_t type,
			iot_agent_datastore_ctx_t **datastore_ctx);

/*
 * EdgeLock 2GO datastore configuration
 */
typedef struct {
	const char *hostname;                   /* Server hostname */
	uint16_t port;                          /* Server port */
	const iot_agent_buffer_t *certificate;  /* Server certificate */
} iot_agent_el2go_config_t;

/**
 * iot_agent_datastore_el2go - Configure EdgeLock 2GO datastore
 * @datastore_ctx: Datastore context
 * @keystore_ctx: Keystore context for secure operations
 * @config: EdgeLock 2GO configuration
 *
 * Configures the EdgeLock 2GO datastore with connection parameters.
 * If certificate is NULL or certificate->data is NULL, compile-time defaults
 * will be used. Missing hostname or port will also use defaults.
 *
 * Return:
 * IOT_AGENT_SUCCESS on success, error code otherwise
 */
iot_agent_t
iot_agent_datastore_el2go(iot_agent_datastore_ctx_t *datastore_ctx,
			  iot_agent_keystore_ctx_t *keystore_ctx,
			  const iot_agent_el2go_config_t *config);

/**
 * iot_agent_datastore_remove - Remove and free a datastore
 * @agent_ctx: IoT Agent context
 * @datastore_ctx: Pointer to datastore context (will be set to NULL)
 *
 * This function removes the datastore from the agent and frees all resources.
 *
 * Return:
 * IOT_AGENT_SUCCESS on success, error code otherwise
 */
iot_agent_t
iot_agent_datastore_remove(iot_agent_ctx_t *agent_ctx,
			   iot_agent_datastore_ctx_t **datastore_ctx);

#endif /* __IOT_AGENT_DATASTORE_H__ */