// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2026 NXP
 */
#include "test_utils.h"

void fill_buffer(uint8_t *buffer, size_t size, size_t seed)
{
	size_t i = 0;

	if (!buffer)
		return;

	for (; i < size; i++)
		buffer[i] = (uint8_t)((i + seed) & 0xFF);
}
