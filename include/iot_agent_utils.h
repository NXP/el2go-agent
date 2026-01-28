/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __IOT_AGENT_UTILS_H__
#define __IOT_AGENT_UTILS_H__

#include <stddef.h>
#include "iot_agent_status.h"
#include "iot_agent.h"

/**
 * iot_agent_get_device_uuid - Get device UUID in hexadecimal format
 * @ctx: IoT Agent context
 * @uuid_buffer: Buffer to store UUID hex string (must be at least 33 bytes for 16-byte UUID + null terminator)
 * @buffer_size: Input: Size of the provided buffer, Output: Actual size written (including null terminator)
 *
 * Retrieves the device's unique identifier (UUID) and formats it as a
 * hexadecimal string. The UUID is typically derived from the device's
 * hardware security module or platform-specific identifier.
 *
 * Return:
 * IOT_AGENT_SUCCESS on success, error code otherwise
 */
iot_agent_t
iot_agent_get_device_uuid(iot_agent_ctx_t *ctx,
			  char *uuid_buffer,
			  size_t *buffer_size);
#endif /* __IOT_AGENT_UTILS_H__ */