// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2018-2026 NXP
 */

#include <stddef.h>
#include "common/el2go_datastore.h"
#include "compiler.h"

__export el2go_agent_t
el2go_agent_datastore_init(uint32_t id,
			   const char *name,
			   el2go_agent_datastore_type_t type,
			   el2go_agent_datastore_t *datastore,
			   el2go_agent_datastore_validator_t validator)
{
	(void)id;
	(void)name;
	(void)type;
	(void)validator;

	if (!name || !datastore)
		return EL2GO_AGENT_FAILURE;

	/* TODO: Allocate datastore context */
	/* TODO: Initialize datastore with id, name, type */
	/* TODO: Store validator function pointer */
	/* TODO: Call validator if provided */

	return EL2GO_AGENT_SUCCESS;
}

__export el2go_agent_t
el2go_agent_datastore_el2go(el2go_agent_datastore_t *datastore,
			    el2go_agent_keystore_t *keystore_ctx,
			    const el2go_agent_el2go_config_t *config)
{
	if (!datastore || !keystore_ctx || !config)
		return EL2GO_AGENT_FAILURE;

	/* TODO: Implement EdgeLock 2GO configuration */

	return EL2GO_AGENT_SUCCESS;
}

__export void *
el2go_agent_datastore_allocate(el2go_agent_datastore_t *datastore,
			       size_t len)
{
	(void)len;

	if (!datastore || len == 0)
		return NULL;

	/* TODO: Allocate len bytes in the datastore */
	/* TODO: Handle allocation based on datastore type (FS or PLAIN) */

	return NULL;
}

__export el2go_agent_t
el2go_agent_datastore_read(el2go_agent_datastore_t *datastore,
			   void *dest, size_t offset, size_t len)
{
	(void)offset;
	(void)len;

	if (!datastore || !dest || len == 0)
		return EL2GO_AGENT_FAILURE;

	/* TODO: Read len bytes from datastore at offset into dest */
	/* TODO: Handle read based on datastore type (FS or PLAIN) */

	return EL2GO_AGENT_SUCCESS;
}

__export el2go_agent_t
el2go_agent_datastore_write(el2go_agent_datastore_t *datastore,
			    const void *src, size_t offset, size_t len)
{
	(void)offset;
	(void)len;

	if (!datastore || !src || len == 0)
		return EL2GO_AGENT_FAILURE;

	/* TODO: Write len bytes from src to datastore at offset */
	/* TODO: Handle write based on datastore type (FS or PLAIN) */

	return EL2GO_AGENT_SUCCESS;
}

__export el2go_agent_t
el2go_agent_datastore_commit(el2go_agent_datastore_t *datastore)
{
	if (!datastore)
		return EL2GO_AGENT_FAILURE;

	/* TODO: Commit pending changes to datastore */
	/* TODO: For FS type, flush buffers to disk */
	/* TODO: For PLAIN type, finalize in-memory structures */

	return EL2GO_AGENT_SUCCESS;
}

__export el2go_agent_t
el2go_agent_datastore_free(el2go_agent_datastore_t *datastore)
{
	if (!datastore || !datastore)
		return EL2GO_AGENT_FAILURE;

	/* TODO: Free datastore resources */

	return EL2GO_AGENT_SUCCESS;
}
