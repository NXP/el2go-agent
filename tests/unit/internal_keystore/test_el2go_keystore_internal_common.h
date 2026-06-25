/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef TEST_EL2GO_KEYSTORE_INTERNAL_COMMON_H
#define TEST_EL2GO_KEYSTORE_INTERNAL_COMMON_H

#include "common/el2go_keystore.h"
#include "test_framework.h"

/**
 * @brief Helper function to cleanup a keystore instance.
 *
 * Frees all resources associated with the given keystore.
 *
 * @param keystore Pointer to the keystore to cleanup.
 * @return @c EL2GO_STATUS_SUCCESS on success, error code otherwise.
 */
el2go_status_t cleanup_keystore(el2go_keystore_t *keystore);

/**
 * @brief Common test for keystore initialization with a specific ID.
 *
 * Verifies that a keystore can be successfully initialized with a given ID,
 * that the keystore type matches the expected type, and that the ID
 * matches the initialization value. Also verifies proper cleanup.
 *
 * @param keystore_id The ID to use for keystore initialization.
 * @param expected_type The expected keystore type (EL2GO_KEYSTORE_SSS or EL2GO_KEYSTORE_PSA).
 * @return @c true if all assertions pass, @c false otherwise.
 */
bool common_test_keystore_init_with_id(uint32_t keystore_id, el2go_keystore_type_t expected_type);

/**
 * @brief Register keystore-specific tests.
 *
 * This function is implemented in the keystore-specific subdirectory
 * and registers tests specific to that keystore type.
 * It is called from register_keystore_tests() in the common module.
 */
void register_keystore_specific_tests(void);

#endif /* TEST_EL2GO_KEYSTORE_INTERNAL_COMMON_H */