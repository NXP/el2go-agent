/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
#include "test_utils.h"
#include "test_framework.h"
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

void test_dump_hex(const char *label, const uint8_t *buf, size_t len)
{
	size_t i = 0;

	TEST_PRINT_INFO("%s (%zu bytes):", label, len);
	for (i = 0; i < len; i += 16) {
		char hex_line[64] = { 0 };
		char asc_line[20] = { 0 };
		char *ph = hex_line;
		char *pa = asc_line;
		size_t j = 0;

		for (j = i; j < len && j < i + 16; j++) {
			uint8_t byte = buf[j];
			char c = '.';

			ph += sprintf(ph, "%02x ", byte);

			/* Only printable ASCII characters (0x20-0x7E) */
			if (byte >= 0x20 && byte < 0x7f)
				c = (char)byte;
			*pa++ = c;
		}
		*pa = '\0';
		TEST_PRINT_INFO("  %04zx: %-48s %s", i, hex_line, asc_line);
	}
}
