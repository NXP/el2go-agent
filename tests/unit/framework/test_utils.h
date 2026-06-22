/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
#ifndef __TEST_UTILS_H__
#define __TEST_UTILS_H__

#include <stddef.h>
#include <stdint.h>
#include "common/el2go_datastore.h"

/**
 * @defgroup test_utils Test Utilities
 * @brief Utility functions for EL2GO device link reference tests.
 * @{
 */

/**
 * @brief Fill a buffer with a generated data pattern.
 *
 * Fills the buffer with a predictable pattern based on index and seed.
 *
 * @param buffer Buffer to fill.
 * @param size   Size of the buffer in bytes.
 * @param seed   Seed value for pattern generation.
 */
void fill_buffer(uint8_t *buffer, size_t size, size_t seed);

/**
 * @brief Initialize array of datastores with unique IDs.
 *
 * Initializes all datastores in the array with zero values and assigns
 * unique IDs starting from base_id.
 *
 * @param datastores Array of datastores to initialize.
 * @param count      Number of datastores in the array.
 * @param base_id    Base ID for the first datastore.
 */
void init_datastores(el2go_datastore_t *datastores, size_t count,
		     uint32_t base_id);
/**
 * @brief Dump buffer contents in hexadecimal format.
 *
 * Prints buffer contents in a formatted hex dump with ASCII representation.
 * Format: offset: hex bytes (16 per line) ASCII representation.
 *
 * @param label Label to print before the hex dump.
 * @param buf   Buffer to dump.
 * @param len   Length of the buffer in bytes.
 */
void test_dump_hex(const char *label, const uint8_t *buf, size_t len);

/** @} */ /* end of test_utils */

#endif /* __TEST_UTILS_H__ */
