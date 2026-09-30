/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __EL2GO_BLOB_TEST_PLATFORM_H__
#define __EL2GO_BLOB_TEST_PLATFORM_H__

#include <stdint.h>
#include <psa/crypto_types.h>

#include "el2go_blob_test_console.h"

/**
 * @brief Perform platform-specific initialization before the test runs.
 *
 */
void el2go_blob_test_platform_init(void);

/**
 * @brief Return the current system uptime in milliseconds.
 *
 * @return Current uptime in milliseconds.
 */
int64_t el2go_blob_test_uptime_ms(void);

/**
 * @brief Return elapsed time in milliseconds since a reference time and update it.
 *
 * Reads the current uptime, computes the delta relative to *reftime, stores
 * the current uptime back into *reftime, and returns the delta.
 *
 * @param[in,out] reftime  Pointer to the reference timestamp (milliseconds).
 *                         Updated to the current uptime on return.
 * @return Elapsed time in milliseconds since *reftime was last set.
 */
int64_t el2go_blob_test_uptime_delta(int64_t *reftime);

/**
 * @brief Initialize the secure storage backend before running tests.
 *
 * On platforms that require explicit secure storage initialization
 * (e.g. Zephyr with CONFIG_SECURE_STORAGE), this function calls the
 * backend init routine and halts on failure. The default implementation
 * is a no-op for platforms that do not require it.
 *
 * @return PSA_SUCCESS on success, or a PSA error code on failure.
 */
psa_status_t el2go_blob_test_secure_storage_init(void);

#endif /* __EL2GO_BLOB_TEST_PLATFORM_H__ */
