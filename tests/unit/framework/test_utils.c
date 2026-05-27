// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2026 NXP
 */
#include "test_utils.h"
#include "builtin_macros.h"

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
