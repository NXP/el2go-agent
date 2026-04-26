/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2026 NXP
 */
#ifndef __TEST_UTILS_H__
#define __TEST_UTILS_H__

#include <stddef.h>
#include <stdint.h>

/**
 * fill_buffer - Fill buffer with generated data pattern
 * @buffer: Buffer to fill
 * @size: Size of buffer
 * @seed: Seed value for pattern generation
 *
 * Fills the buffer with a predictable pattern based on index and seed.
 */
void fill_buffer(uint8_t *buffer, size_t size, size_t seed);

#endif /* __TEST_UTILS_H__ */
