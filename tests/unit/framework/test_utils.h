/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2026 NXP
 */
#ifndef __TEST_UTILS_H__
#define __TEST_UTILS_H__

#include <stddef.h>
#include <stdint.h>
#include "common/el2go_datastore.h"

/**
 * fill_buffer - Fill buffer with generated data pattern
 * @buffer: Buffer to fill
 * @size: Size of buffer
 * @seed: Seed value for pattern generation
 *
 * Fills the buffer with a predictable pattern based on index and seed.
 */
void fill_buffer(uint8_t *buffer, size_t size, size_t seed);

/**
 * init_datastores - Initialize array of datastores with unique IDs
 * @datastores: Array of datastores to initialize
 * @count: Number of datastores in the array
 * @base_id: Base ID for the first datastore
 *
 * Initializes all datastores in the array with zero values and assigns
 * unique IDs starting from base_id.
 */
void init_datastores(el2go_datastore_t *datastores, size_t count,
		     uint32_t base_id);

#endif /* __TEST_UTILS_H__ */
