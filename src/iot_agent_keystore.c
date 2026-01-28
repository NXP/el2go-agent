/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* TODO: Add visibility attribute to public API functions when defining OSAL layer */

#include <stddef.h>
#include "iot_agent_keystore.h"

iot_agent_t iot_agent_keystore_add(iot_agent_ctx_t *agent_ctx, uint32_t id,
				   iot_agent_keystore_type_t type,
				   iot_agent_keystore_ctx_t **keystore_ctx)
{
	(void)id;
	(void)type;

	if (!agent_ctx || !keystore_ctx) {
		return IOT_AGENT_FAILURE;
	}

	/* TODO: Validate keystore type (SSS or PSA) */
	/* TODO: Allocate keystore context */
	/* TODO: Initialize keystore based on type */
	/* TODO: Add keystore to agent context */

	return IOT_AGENT_SUCCESS;
}

iot_agent_t
iot_agent_keystore_remove(iot_agent_ctx_t *agent_ctx,
			  iot_agent_keystore_ctx_t **keystore_ctx)
{
	if (!agent_ctx || !keystore_ctx || !*keystore_ctx) {
		return IOT_AGENT_FAILURE;
	}

	/* TODO: Remove from agent context */
	/* TODO: Free keystore resources */

	*keystore_ctx = NULL;

	return IOT_AGENT_SUCCESS;
}