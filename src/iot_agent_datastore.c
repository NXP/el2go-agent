/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* TODO: Add visibility attribute to public API functions when defining OSAL layer */

#include <stddef.h>
#include "iot_agent_datastore.h"

iot_agent_t iot_agent_datastore_add(iot_agent_ctx_t *agent_ctx,
				    uint32_t id,
				    const char *name,
				    iot_agent_datastore_type_t type,
				    iot_agent_datastore_ctx_t **datastore_ctx)
{
	(void)id;
	(void)name;
	(void)type;

	if (!agent_ctx || !name || !datastore_ctx) {
		return IOT_AGENT_FAILURE;
	}

	/* TODO: Implement datastore add */

	return IOT_AGENT_SUCCESS;
}

iot_agent_t iot_agent_datastore_el2go(iot_agent_datastore_ctx_t *datastore_ctx,
				      iot_agent_keystore_ctx_t *keystore_ctx,
				      const iot_agent_el2go_config_t *config)
{
	if (!datastore_ctx || !keystore_ctx || !config)
	{
		return IOT_AGENT_FAILURE;
	}

	/* TODO: Implement EdgeLock 2GO configuration */

	return IOT_AGENT_SUCCESS;
}

iot_agent_t iot_agent_datastore_remove(iot_agent_ctx_t *agent_ctx,
				       iot_agent_datastore_ctx_t **datastore_ctx)
{
	if (!agent_ctx || !datastore_ctx || !*datastore_ctx)
	{
		return IOT_AGENT_FAILURE;
	}

	/* TODO: Remove from agent context */
	/* TODO: Free datastore resources */

	*datastore_ctx = NULL;

	return IOT_AGENT_SUCCESS;
}