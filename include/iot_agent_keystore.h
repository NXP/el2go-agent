/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __IOT_AGENT_KEYSTORE_H__
#define __IOT_AGENT_KEYSTORE_H__

#include <stdint.h>
#include "iot_agent_status.h"

typedef struct iot_agent_ctx iot_agent_ctx_t;

/*
  * IoT Agent keystore context
  *
  * This is an opaque structure. Users should not access its members directly.
  * The actual definition is in the implementation files.
  */
typedef struct iot_agent_keystore_ctx iot_agent_keystore_ctx_t;

/*
 * Keystore types - the types might not be needed if the keystore implementation
 * is selected at compile time.
 */
typedef enum {
	IOT_AGENT_KEYSTORE_SSS, /* SSS (Secure Subsystem) keystore */
	IOT_AGENT_KEYSTORE_PSA  /* PSA (Platform Security Architecture) keystore */
} iot_agent_keystore_type_t;

/**
 * iot_agent_keystore_add - Add a keystore to the agent
 * @agent_ctx: IoT Agent context
 * @id: Keystore identifier
 * @type: Keystore type (SSS or PSA)
 * @keystore_ctx: Pointer to store the created keystore context
 *
 * This function allocates a keystore and adds it to the Agent. The allocation and
 * register is done in a single step.
 *
 * Return:
 * IOT_AGENT_SUCCESS on success, error code otherwise
 */
iot_agent_t iot_agent_keystore_add(iot_agent_ctx_t *agent_ctx, uint32_t id,
				   iot_agent_keystore_type_t type,
				   iot_agent_keystore_ctx_t **keystore_ctx);

/**
 * iot_agent_keystore_remove - Remove and free a keystore
 * @agent_ctx: IoT Agent context
 * @keystore_ctx: Pointer to keystore context (will be set to NULL)
 *
 * This function removes the keystore from the agent and frees all resources.
 *
 * Return:
 * IOT_AGENT_SUCCESS on success, error code otherwise
 */
iot_agent_t
iot_agent_keystore_remove(iot_agent_ctx_t *agent_ctx,
			  iot_agent_keystore_ctx_t **keystore_ctx);
#endif /* __IOT_AGENT_KEYSTORE_H__ */