/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* TODO: Add visibility attribute to public API functions when defining OSAL layer */

#include <stdio.h>
#include <string.h>
#include "iot_agent_utils.h"

iot_agent_t
iot_agent_get_device_uuid(iot_agent_ctx_t *ctx,
			  char *uuid_buffer,
			  size_t *buffer_size)
{

	if (!ctx || !uuid_buffer || !buffer_size) {
		return IOT_AGENT_FAILURE;
	}

	return IOT_AGENT_SUCCESS;
}