/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* TODO: Add visibility attribute to public API functions when defining OSAL layer */

#include <stddef.h>
#include <stdio.h>

#include "iot_agent.h"
#include "iot_agent_status.h"

iot_agent_t iot_agent_get_version(unsigned int *major, unsigned int *minor)
{
	if (!major || !minor) {
		return IOT_AGENT_FAILURE;
	}

	*major = 0;
	*minor = 0;

	return IOT_AGENT_SUCCESS;
}

iot_agent_t iot_agent_init(iot_agent_ctx_t **ctx)
{
	if (!ctx) {
		return IOT_AGENT_FAILURE;
	}

	/* TODO: Implement initialization */

	return IOT_AGENT_SUCCESS;
}

iot_agent_t iot_agent_cleanup(iot_agent_ctx_t **ctx)
{
	if (!ctx || !*ctx) {
		return IOT_AGENT_FAILURE;
	}

	/* TODO: Implement cleanup */

	*ctx = NULL;

	return IOT_AGENT_SUCCESS;
}

iot_agent_t iot_agent_platform_init(iot_agent_ctx_t *ctx,
				    const iot_agent_platform_config_t *config,
				    iot_agent_keystore_ctx_t **platform_ctx)
{
	if (!ctx || !config || !platform_ctx) {
		return IOT_AGENT_FAILURE;
	}

	/* TODO: Implement platform initialization */
	/* TODO: Initialize HSM hardware */
	/* TODO: Store platform context in agent context */

	return IOT_AGENT_SUCCESS;
}

iot_agent_t
iot_agent_platform_cleanup(iot_agent_ctx_t *ctx,
			   iot_agent_keystore_ctx_t **platform_ctx)
{
	if (!ctx || !platform_ctx || !*platform_ctx) {
		return IOT_AGENT_FAILURE;
	}

	/* TODO: Cleanup HSM hardware */
	/* TODO: Remove platform context from agent context */
	/* TODO: Free platform resources */

	*platform_ctx = NULL;

	return IOT_AGENT_SUCCESS;
}

iot_agent_t
iot_agent_claimcode_import(iot_agent_keystore_ctx_t *platform_ctx,
			   const char *claimcode)
{
	if (!platform_ctx || !claimcode) {
		return IOT_AGENT_FAILURE;
	}

	/* TODO: Validate claim code format */
	/* TODO: Store claim code in platform-specific secure storage */

	return IOT_AGENT_SUCCESS;
}
iot_agent_t
iot_agent_update_device_configuration(iot_agent_ctx_t *ctx,
				      iot_agent_status_verbosity_t verbosity)
{
	iot_agent_t result = IOT_AGENT_SUCCESS;

	(void)verbosity;

	if (!ctx) {
		return IOT_AGENT_FAILURE;
	}

	/* TODO: Connect to EdgeLock 2GO server */
	/* TODO: Provision keys and certificates */
	/* TODO: Populate status_report from server response */
	/* TODO: Set result based on provisioning outcome */

	return result;
}
