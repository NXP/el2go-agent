// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2026 NXP
 */
#include <string.h>
#include "builtin_macros.h"
#include "test_utils.h"

void fill_buffer(uint8_t *buffer, size_t size, size_t seed)
{
	size_t i = 0, sum = 0;

	if (!buffer)
		return;

	for (; i < size; i++) {
		if (ADD_OVERFLOW(i, seed, &sum))
			sum = 0;

		buffer[i] = (uint8_t)(sum & 0xFF);
	}
}

void init_datastores(el2go_datastore_t *datastores, size_t count,
		     uint32_t base_id)
{
	size_t i = 0, total_size = 0;
	uint32_t id = 0;

	if (!datastores)
		return;

	if (MUL_OVERFLOW(count, sizeof(el2go_datastore_t), &total_size))
		return;

	memset(datastores, 0, total_size);

	for (; i < count; i++) {
		if (ADD_OVERFLOW(base_id, (uint32_t)i, &id))
			id = base_id;

		datastores[i].id = id;
	}
}
