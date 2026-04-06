// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2018-2026 NXP
 */

#include <stddef.h>
#include <stdio.h>

#include "el2go_agent.h"
#include "el2go_agent_internal.h"
#include "el2go_agent_status.h"
#include "compiler.h"
#include "osal.h"

__export el2go_agent_t el2go_agent_get_version(unsigned int *major,
					       unsigned int *minor)
{
	if (!major || !minor)
		return EL2GO_AGENT_FAILURE;

	*major = 0;
	*minor = 0;

	return EL2GO_AGENT_SUCCESS;
}

__export el2go_agent_t el2go_agent_init(el2go_agent_ctx_t **ctx)
{
	el2go_agent_ctx_t *agent_ctx = NULL;
	el2go_agent_t status = EL2GO_AGENT_SUCCESS;

	if (!ctx)
		return EL2GO_AGENT_INVALID_POINTER;

	/* Initialize OSAL subsystem */
	osal_lib_init();

	/* Allocate memory for agent context */
	agent_ctx =
		(el2go_agent_ctx_t *)osal_calloc(1, sizeof(el2go_agent_ctx_t));
	if (!agent_ctx)
		return EL2GO_AGENT_ALLOCATION_ERROR;

	*ctx = agent_ctx;

	return status;
}

__export el2go_agent_t el2go_agent_free(el2go_agent_ctx_t **ctx)
{
	if (!ctx || !*ctx)
		return EL2GO_AGENT_INVALID_POINTER;

	/* Free the allocated context */
	osal_free(*ctx);
	*ctx = NULL;

	return EL2GO_AGENT_SUCCESS;
}

__export el2go_agent_t
el2go_agent_datastore_add(el2go_agent_ctx_t *ctx,
			  el2go_agent_datastore_t *datastore)
{
	if (!ctx || !datastore)
		return EL2GO_AGENT_FAILURE;

	/* TODO: Add datastore to agent's datastore list */

	return EL2GO_AGENT_SUCCESS;
}

__export el2go_agent_t
el2go_agent_datastore_remove(el2go_agent_ctx_t *ctx,
			     el2go_agent_datastore_t *datastore)
{
	if (!ctx || !datastore)
		return EL2GO_AGENT_FAILURE;

	/* TODO: Remove datastore from agent's list */

	return EL2GO_AGENT_SUCCESS;
}

__export el2go_agent_t el2go_agent_provision(el2go_agent_ctx_t *ctx,
					     el2go_agent_verbosity_t verbosity)
{
	el2go_agent_t result = EL2GO_AGENT_SUCCESS;

	(void)verbosity;

	if (!ctx)
		return EL2GO_AGENT_FAILURE;

	/* TODO: Connect to EdgeLock 2GO server */
	/* TODO: Provision keys and certificates */
	/* TODO: Populate status_report from server response */
	/* TODO: Set result based on provisioning outcome */

	return result;
}
__export el2go_agent_t
el2go_agent_keystore_add(el2go_agent_ctx_t *ctx,
			 el2go_agent_keystore_t *keystore_ctx)
{
	if (!ctx || !keystore_ctx)
		return EL2GO_AGENT_FAILURE;

	/* TODO: Add keystore to agent's internal list */
	printf("Adding keystore to agent (stub implementation)\n");

	return EL2GO_AGENT_SUCCESS;
}

__export el2go_agent_t
el2go_agent_keystore_remove(el2go_agent_ctx_t *ctx,
			    el2go_agent_keystore_t *keystore_ctx)
{
	if (!ctx || !keystore_ctx)
		return EL2GO_AGENT_FAILURE;

	/* TODO: Remove keystore from agent's internal list */
	printf("Removing keystore from agent (stub implementation)\n");

	return EL2GO_AGENT_SUCCESS;
}

__export el2go_agent_t el2go_agent_get_device_uuid(el2go_agent_ctx_t *ctx,
						   char *uuid_buffer,
						   size_t *buffer_size)
{
	if (!ctx || !uuid_buffer || !buffer_size)
		return EL2GO_AGENT_FAILURE;

	return EL2GO_AGENT_SUCCESS;
}